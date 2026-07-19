//! Shared node-config builder for the HTTP poll path (`get_config`) and the
//! WebSocket push path (`build_config_snapshot`).
//!
//! **Why this exists (v0.3.6 fix):** v0.3.5 had TWO copies of "turn a device
//! group into a NodeConfigResponse". They drifted — the HTTP path JOINed
//! `users` (to drop banned / over-quota rules) but the WS path did NOT, so a
//! freshly-(re)connected node could be handed a banned user's rules until the
//! next HTTP poll corrected it. There was also duplicated target resolution +
//! `build_listeners_for_rule` wiring in both files.
//!
//! This module is the single source of truth. Both callers go through
//! [`build_node_config`], so the filter, target resolution, protocol expansion,
//! transport derivation and ws_path passthrough are identical by construction.
//!
//! Error policy: a DB failure is surfaced as `Err(DbError)` instead of
//! silently returning an empty config. An empty result that came from a real
//! "no rules" state is indistinguishable from a DB failure under the old
//! `unwrap_or_default()` — that masked real errors as "no rules", which is
//! dangerous for quota enforcement. Callers decide how to render the error
//! (HTTP returns an empty config + logs; WS skips the snapshot push + logs).

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, ProfileScope, ResourceScope, TunnelProfileRepository};
use crate::db::Repository;
use relay_shared::models::{DeviceGroup, ForwardRule};
use relay_shared::protocol::{NodeConfigResponse, Protocol, UotRole};
use sha2::{Digest, Sha256};

struct ResolvedTargets {
    addrs: Vec<String>,
    weights: Vec<u16>,
}

/// Build the full [`NodeConfigResponse`] for a device group.
///
/// This is the ONE function both `get_config` (HTTP) and `build_config_snapshot`
/// (WS) call. It performs, in order:
///
/// 1. Group lookup — `monitor` groups never forward; `in`/`out`/`both` groups
///    can receive listeners.
/// 2. Direct rules + chain **entry** hops via `device_group_in` match.
/// 3. Chain intermediate/exit hops via `forward_rule_hops` for this group.
/// 4. Target resolution (final targets or next-hop connect_host:port).
/// 5. [`relay_shared::protocol::build_listeners_for_rule_with`] for protocol
///    expansion; intermediate hops set `count_traffic=false`.
///
/// Returns `Ok(empty)` only for a legitimate empty state. A DB error is `Err`.
pub async fn build_node_config(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigResponse, DbError> {
    build_node_config_inner(
        db,
        group_id,
        uot_ingress_enabled(),
        tcp_zero_rtt_ingress_enabled(),
    )
    .await
}

fn uot_ingress_enabled() -> bool {
    env_flag("RELAY_ENABLE_UOT")
}

fn tcp_zero_rtt_ingress_enabled() -> bool {
    env_flag("RELAY_ENABLE_TCP_0RTT")
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        // UOT/TFO are active by default. Operators can still force the native
        // path during a mixed-version rollout or emergency rollback.
        Err(std::env::VarError::NotPresent) => parse_env_flag_value(None).unwrap_or(false),
        Err(std::env::VarError::NotUnicode(_)) => false,
        Ok(value) => match parse_env_flag_value(Some(&value)) {
            Some(enabled) => enabled,
            None => {
                tracing::warn!(
                    "{} has invalid boolean value {:?}; disabling the feature",
                    name,
                    value
                );
                false
            }
        },
    }
}

fn parse_env_flag_value(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("1" | "true" | "yes" | "on") => Some(true),
        Some("0" | "false" | "no" | "off") => Some(false),
        Some(_) => None,
    }
}

async fn build_node_config_inner(
    db: &dyn Repository,
    group_id: i64,
    enable_uot_ingress: bool,
    enable_tcp_zero_rtt_ingress: bool,
) -> Result<NodeConfigResponse, DbError> {
    // 1. Group gate. `monitor` groups never forward. `in` groups get direct +
    //    chain-entry listeners; `out` (and any other non-monitor) groups get
    //    chain intermediate/exit hop listeners when referenced by hops.
    let group = match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(g) if g.group_type != "monitor" => g,
        _ => return Ok(NodeConfigResponse { listeners: vec![] }),
    };

    // 2. Filtered rule query. The JOIN on users is the fix for the v0.3.5 WS
    //    drift: without it a banned / over-quota user's rules would still be
    //    pushed to a reconnecting node. Both paths now share this exact query.
    //
    //    Quota note (unchanged from v0.3.0, documented): there is a leak window
    //    of up to one poll cycle (default 10s) because quota is re-checked only
    //    when the node fetches config, not per-packet. Offline nodes serve an
    //    unfiltered cached config ("forward over bill" trade-off). Do not change
    //    without a product decision.
    let rules: Vec<ForwardRule> = db.list_active_for_config(group.id).await?;

    // 3 + 4. Resolve targets and build listener configs. Target resolution needs
    //    a DB lookup (outbound group's connect_host), so it stays async and lives
    //    here; the pure ListenerConfig assembly (transport/ws_path/protocol) is
    //    delegated to the shared `build_listeners_for_rule` so that part can never
    //    drift between paths.
    let mut listeners = Vec::new();
    for rule in &rules {
        let Some(effective_rule) = apply_tunnel_profile(db, rule).await? else {
            continue;
        };

        if rule.route_mode == "chain" {
            // Entry hop (position 0) for chain rules whose device_group_in is
            // this group. Intermediate/exit hops are emitted below via
            // list_active_chain_hops_for_group (position > 0 only here).
            let mut hops = db.list_rule_hops(rule.id).await?;
            if hops.is_empty() {
                tracing::warn!("chain rule {} has no hops; skipping listeners", rule.id);
                continue;
            }
            let mut uot_ready = false;
            if matches!(rule.protocol.as_str(), "udp" | "tcp_udp") {
                if let Some(prepared) = prepare_tunnel_ports(db, rule.id, hops.clone()).await? {
                    hops = prepared;
                    uot_ready = true;
                } else {
                    tracing::warn!(
                        "chain rule {}: no safe dedicated tunnel port; keeping native UDP",
                        rule.id
                    );
                }
            }
            let entry = &hops[0];
            if entry.device_group_id != group.id {
                // Stale device_group_in vs hops[0] — skip rather than misroute.
                continue;
            }
            let targets = match chain_hop_targets(db, rule, &hops, 0).await? {
                Some(t) => t,
                None => continue,
            };
            let mut hop_listeners = relay_shared::protocol::build_listeners_for_rule_with(
                &effective_rule,
                targets.addrs,
                entry.listen_port as u16,
                true, // entry bills traffic
            );
            set_target_weights(&mut hop_listeners, targets.weights);
            if uot_ready {
                apply_uot_role(db, rule, &hops, 0, &mut hop_listeners, enable_uot_ingress).await?;
            }
            apply_tcp_fast_open_role(rule, 0, &mut hop_listeners, enable_tcp_zero_rtt_ingress);
            listeners.extend(hop_listeners);
            continue;
        }

        let targets = resolve_targets(db, rule).await?;
        let mut direct_listeners =
            relay_shared::protocol::build_listeners_for_rule(&effective_rule, targets.addrs);
        set_target_weights(&mut direct_listeners, targets.weights);
        listeners.extend(direct_listeners);
    }

    // 5. Chain intermediate / exit hops on this group (position > 0).
    // Entry is already handled above via list_active_for_config.
    let chain_hops = db.list_active_chain_hops_for_group(group.id).await?;
    for hop in chain_hops {
        if hop.position <= 0 {
            continue; // entry emitted via device_group_in path
        }
        let Some(rule) = db.find_rule_by_id(hop.rule_id, &ResourceScope::All).await? else {
            continue;
        };
        // find_rule_by_id does not re-check user gating; hop query already did.
        if rule.paused || rule.route_mode != "chain" {
            continue;
        }
        let Some(effective_rule) = apply_tunnel_profile(db, &rule).await? else {
            continue;
        };
        let mut hops = db.list_rule_hops(rule.id).await?;
        let mut uot_ready = false;
        if matches!(rule.protocol.as_str(), "udp" | "tcp_udp") {
            if let Some(prepared) = prepare_tunnel_ports(db, rule.id, hops.clone()).await? {
                hops = prepared;
                uot_ready = true;
            } else {
                tracing::warn!(
                    "chain rule {}: no safe dedicated tunnel port; keeping native UDP",
                    rule.id
                );
            }
        }
        let targets = match chain_hop_targets(db, &rule, &hops, hop.position).await? {
            Some(t) => t,
            None => continue,
        };
        let mut hop_listeners = relay_shared::protocol::build_listeners_for_rule_with(
            &effective_rule,
            targets.addrs,
            hop.listen_port as u16,
            false, // only entry bills
        );
        set_target_weights(&mut hop_listeners, targets.weights);
        if uot_ready {
            apply_uot_role(
                db,
                &rule,
                &hops,
                hop.position,
                &mut hop_listeners,
                enable_uot_ingress,
            )
            .await?;
        }
        apply_tcp_fast_open_role(
            &rule,
            hop.position,
            &mut hop_listeners,
            enable_tcp_zero_rtt_ingress,
        );
        listeners.extend(hop_listeners);
    }

    Ok(NodeConfigResponse { listeners })
}

fn set_target_weights(listeners: &mut [relay_shared::protocol::ListenerConfig], weights: Vec<u16>) {
    for listener in listeners {
        listener.target_weights = weights.clone();
    }
}

/// Turn the UDP component of an udp/tcp_udp chain into the authenticated UOT
/// data path. The public entry remains a UDP socket; every later hop listens on
/// its dedicated TCP/UOT tunnel port. Link tokens
/// are SHA-256 digests over both adjacent group secrets plus rule/position, so
/// a data-plane node never receives a reusable control-plane credential.
async fn apply_uot_role(
    db: &dyn Repository,
    rule: &ForwardRule,
    hops: &[relay_shared::models::ForwardRuleHop],
    position: i32,
    listeners: &mut Vec<relay_shared::protocol::ListenerConfig>,
    enable_ingress: bool,
) -> Result<(), DbError> {
    let pos = position as usize;
    if hops.len() < 2 || pos >= hops.len() {
        return Ok(());
    }
    // Rollout stage 1: every later v7 hop prepares both legacy UDP and UOT,
    // while the entry keeps using native UDP. Stage 2 explicitly enables the
    // entry only after all downstream nodes have upgraded.
    if pos == 0 && !enable_ingress {
        return Ok(());
    }
    let inbound_token = if pos > 0 {
        Some(uot_link_token(db, rule.id, &hops[pos - 1], &hops[pos], pos - 1).await?)
    } else {
        None
    };
    let outbound_token = if pos + 1 < hops.len() {
        Some(uot_link_token(db, rule.id, &hops[pos], &hops[pos + 1], pos).await?)
    } else {
        None
    };

    let Some(udp_index) = listeners
        .iter()
        .position(|listener| listener.protocol == Protocol::Udp)
    else {
        return Ok(());
    };

    if pos == 0 {
        let Some(target) = tunnel_next_target(db, rule.id, hops, pos).await? else {
            return Ok(());
        };
        let listener = &mut listeners[udp_index];
        listener.targets = vec![target];
        listener.target_weights = vec![1];
        listener.zero_rtt = true;
        listener.uot_role = UotRole::Ingress;
        listener.uot_token = outbound_token;
    } else {
        let Some(tunnel_port) = hops[pos].tunnel_port else {
            return Ok(());
        };
        let mut tunnel_listener = listeners[udp_index].clone();
        tunnel_listener.port = tunnel_port as u16;
        tunnel_listener.protocol = Protocol::Uot;
        tunnel_listener.zero_rtt = true;
        if pos + 1 == hops.len() {
            tunnel_listener.uot_role = UotRole::Egress;
            tunnel_listener.uot_token = inbound_token;
        } else {
            let Some(target) = tunnel_next_target(db, rule.id, hops, pos).await? else {
                return Ok(());
            };
            tunnel_listener.targets = vec![target];
            tunnel_listener.target_weights = vec![1];
            tunnel_listener.uot_role = UotRole::Relay;
            tunnel_listener.uot_token = inbound_token;
            tunnel_listener.uot_next_token = outbound_token;
        }
        listeners.push(tunnel_listener);
    }
    Ok(())
}

/// Claim one dedicated TCP tunnel port for every non-entry hop. The claim is
/// persisted so all nodes/config paths converge on the same address. Existing
/// listen ports remain untouched and keep carrying native TCP/UDP during the
/// staged rollout.
async fn prepare_tunnel_ports(
    db: &dyn Repository,
    rule_id: i64,
    mut hops: Vec<relay_shared::models::ForwardRuleHop>,
) -> Result<Option<Vec<relay_shared::models::ForwardRuleHop>>, DbError> {
    for hop in hops.iter_mut().skip(1) {
        if hop.tunnel_port.is_none() {
            let mut claimed = None;
            for _ in 0..8 {
                let candidate =
                    match crate::service::rules::auto_assign_port(db, hop.device_group_id, "tcp")
                        .await
                    {
                        Ok(port) => port,
                        Err(error) => {
                            tracing::warn!(
                                "chain rule {} hop {}: cannot allocate tunnel port: {}",
                                rule_id,
                                hop.position,
                                error
                            );
                            return Ok(None);
                        }
                    };
                match db
                    .claim_rule_hop_tunnel_port(hop.id, candidate as i32)
                    .await
                {
                    Ok(Some(port)) => {
                        claimed = Some(port);
                        break;
                    }
                    Ok(None) => return Ok(None),
                    Err(DbError::UniqueViolation) => continue,
                    Err(error) => return Err(error),
                }
            }
            let Some(port) = claimed else {
                return Ok(None);
            };
            hop.tunnel_port = Some(port);
        }

        let tunnel_port = hop.tunnel_port.expect("tunnel port claimed above");
        let occupants = db.list_group_port_protocols(hop.device_group_id).await?;
        let tcp_occupants = occupants
            .iter()
            .filter(|(port, protocol)| {
                *port == tunnel_port && matches!(protocol.as_str(), "tcp" | "tcp_udp")
            })
            .count();
        if tcp_occupants != 1 {
            tracing::warn!(
                "chain rule {}: hop group {} tunnel port {} has {} TCP occupants; keeping native UDP",
                rule_id,
                hop.device_group_id,
                tunnel_port,
                tcp_occupants,
            );
            return Ok(None);
        }
    }
    Ok(Some(hops))
}

async fn tunnel_next_target(
    db: &dyn Repository,
    rule_id: i64,
    hops: &[relay_shared::models::ForwardRuleHop],
    pos: usize,
) -> Result<Option<String>, DbError> {
    let Some(next) = hops.get(pos + 1) else {
        return Ok(None);
    };
    let Some(port) = next.tunnel_port else {
        return Ok(None);
    };
    let next_group =
        GroupRepository::find_by_id(db, next.device_group_id, &ResourceScope::All).await?;
    let Some(group) = next_group.filter(|group| !group.connect_host.trim().is_empty()) else {
        tracing::warn!(
            "chain rule {}: next group {} has no connect_host",
            rule_id,
            next.device_group_id
        );
        return Ok(None);
    };
    Ok(Some(format!("{}:{}", group.connect_host, port)))
}

fn apply_tcp_fast_open_role(
    rule: &ForwardRule,
    position: i32,
    listeners: &mut [relay_shared::protocol::ListenerConfig],
    enable_ingress: bool,
) {
    if !matches!(rule.protocol.as_str(), "tcp" | "tcp_udp") {
        return;
    }
    let enabled = position > 0 || enable_ingress;
    for listener in listeners {
        if listener.protocol == Protocol::Tcp {
            listener.tcp_fast_open = enabled;
        }
    }
}

async fn uot_link_token(
    db: &dyn Repository,
    rule_id: i64,
    from: &relay_shared::models::ForwardRuleHop,
    to: &relay_shared::models::ForwardRuleHop,
    position: usize,
) -> Result<String, DbError> {
    let from_group = GroupRepository::find_by_id(db, from.device_group_id, &ResourceScope::All)
        .await?
        .ok_or(DbError::NotFound)?;
    let to_group = GroupRepository::find_by_id(db, to.device_group_id, &ResourceScope::All)
        .await?
        .ok_or(DbError::NotFound)?;
    let mut hasher = Sha256::new();
    hasher.update(b"relay-panel-uot-v1\0");
    hasher.update(rule_id.to_be_bytes());
    hasher.update((position as u64).to_be_bytes());
    hasher.update(from_group.token.as_bytes());
    hasher.update([0]);
    hasher.update(to_group.token.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Apply tunnel profile overrides onto a cloned rule, or None to skip the rule.
async fn apply_tunnel_profile(
    db: &dyn Repository,
    rule: &ForwardRule,
) -> Result<Option<ForwardRule>, DbError> {
    let mut effective_rule = rule.clone();
    if let Some(pid) = rule.tunnel_profile_id {
        match TunnelProfileRepository::find_profile_by_id(db, pid, &ProfileScope::All).await? {
            Some(profile) => {
                let node_transport = match profile.transport.as_str() {
                    "direct" => "raw",
                    "ws" => "ws",
                    "tls_simple" => "tls_simple",
                    other => other,
                };
                effective_rule.node_transport = node_transport.to_string();
                effective_rule.ws_path = if profile.transport == "ws" {
                    Some(profile.ws_path.clone())
                } else {
                    None
                };
            }
            None => {
                tracing::warn!(
                    "rule {} bound to missing tunnel_profile_id {}; skipping (rebind or pause the rule)",
                    rule.id,
                    pid
                );
                return Ok(None);
            }
        }
    }
    Ok(Some(effective_rule))
}

/// Resolve dial targets for a chain hop at `position`.
/// Non-last → next hop's connect_host:listen_port.
/// Last → final rule targets.
async fn chain_hop_targets(
    db: &dyn Repository,
    rule: &ForwardRule,
    hops: &[relay_shared::models::ForwardRuleHop],
    position: i32,
) -> Result<Option<ResolvedTargets>, DbError> {
    let pos = position as usize;
    if pos >= hops.len() {
        return Ok(None);
    }
    if pos + 1 < hops.len() {
        let next = &hops[pos + 1];
        let next_group =
            GroupRepository::find_by_id(db, next.device_group_id, &ResourceScope::All).await?;
        let host = match next_group {
            Some(g) if !g.connect_host.is_empty() => g.connect_host,
            _ => {
                tracing::warn!(
                    "chain rule {} hop {} next group {} missing connect_host; skipping",
                    rule.id,
                    position,
                    next.device_group_id
                );
                return Ok(None);
            }
        };
        Ok(Some(ResolvedTargets {
            addrs: vec![format!("{}:{}", host, next.listen_port)],
            weights: vec![1],
        }))
    } else {
        // Exit hop → final targets.
        Ok(Some(resolve_final_targets(db, rule).await?))
    }
}

async fn resolve_final_targets(
    db: &dyn Repository,
    rule: &ForwardRule,
) -> Result<ResolvedTargets, DbError> {
    let mut targets = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await?;
    if targets.is_empty() {
        targets.push(relay_shared::models::ForwardRuleTarget {
            id: 0,
            rule_id: rule.id,
            host: rule.target_addr.clone(),
            port: rule.target_port,
            position: 1,
            enabled: true,
            weight: 1,
            created_at: String::new(),
        });
    }
    Ok(ResolvedTargets {
        addrs: targets
            .iter()
            .map(|t| format!("{}:{}", t.host, t.port))
            .collect(),
        weights: targets
            .iter()
            .map(|t| t.weight.clamp(1, 100) as u16)
            .collect(),
    })
}

/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own
///   `target_addr:target_port`.
/// - otherwise → the outbound group's `connect_host:target_port`, falling back
///   to the rule's own `target_addr` when the outbound group is missing or has
///   no `connect_host` configured.
///
/// `targets` is the single place target resolution happens — both config paths
/// used to duplicate this `match` block.
async fn resolve_targets(
    db: &dyn Repository,
    rule: &ForwardRule,
) -> Result<ResolvedTargets, DbError> {
    let mut targets = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await?;
    if targets.is_empty() {
        targets.push(relay_shared::models::ForwardRuleTarget {
            id: 0,
            rule_id: rule.id,
            host: rule.target_addr.clone(),
            port: rule.target_port,
            position: 1,
            enabled: true,
            weight: 1,
            created_at: String::new(),
        });
    }

    let weights: Vec<u16> = targets
        .iter()
        .map(|t| t.weight.clamp(1, 100) as u16)
        .collect();

    match (rule.forward_mode.as_str(), rule.device_group_out) {
        ("direct", _) | (_, None) => Ok(ResolvedTargets {
            addrs: targets
                .into_iter()
                .map(|t| format!("{}:{}", t.host, t.port))
                .collect(),
            weights,
        }),
        (_, Some(out_id)) => {
            // Qualify: find_by_id is on both UserRepository and GroupRepository.
            let og = GroupRepository::find_by_id(db, out_id, &ResourceScope::All).await?;
            let addrs = match og {
                Some(DeviceGroup { connect_host, .. }) if !connect_host.is_empty() => targets
                    .into_iter()
                    .map(|t| format!("{}:{}", connect_host, t.port))
                    .collect(),
                _ => targets
                    .into_iter()
                    .map(|t| format!("{}:{}", t.host, t.port))
                    .collect(),
            };
            Ok(ResolvedTargets { addrs, weights })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::RuleRepository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;

    #[test]
    fn transport_features_default_on_and_allow_explicit_opt_out() {
        assert_eq!(parse_env_flag_value(None), Some(true));
        for value in ["1", "true", "yes", "on", " TRUE "] {
            assert_eq!(parse_env_flag_value(Some(value)), Some(true), "{value}");
        }
        for value in ["0", "false", "no", "off", " OFF "] {
            assert_eq!(parse_env_flag_value(Some(value)), Some(false), "{value}");
        }
        assert_eq!(parse_env_flag_value(Some("enabled")), None);
        assert_eq!(parse_env_flag_value(Some("")), None);
    }

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        pool
    }

    /// Wrap the pool in a SqliteRepository so build_node_config can be invoked
    /// the same way the real callers (get_config, build_config_snapshot) do.
    fn repo(pool: &SqlitePool) -> SqliteRepository {
        SqliteRepository::new(pool.clone())
    }

    async fn add_user(pool: &SqlitePool, id: i64) {
        let hash = bcrypt::hash(format!("pw-{id}"), 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(format!("u{id}"))
            .bind(&hash)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_group(pool: &SqlitePool, id: i64, gtype: &str, uid: i64) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(format!("g{id}"))
        .bind(gtype)
        .bind(format!("tok-{id}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_rule(pool: &SqlitePool, id: i64, uid: i64, in_group: i64, port: i64) {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80)",
        )
        .bind(id)
        .bind(format!("r{id}"))
        .bind(uid)
        .bind(port)
        .bind(in_group)
        .execute(pool)
        .await
        .unwrap();
    }

    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]
    async fn active_rule_produces_listener() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].port, 20000);
    }

    /// A banned user's rule must NOT appear — this is the regression the WS path
    /// was missing (v0.3.5 drift). Both paths now share this query, so the test
    /// pins the filter itself.
    #[tokio::test]
    async fn banned_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET banned = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "banned user rule must be filtered"
        );
    }

    /// An over-quota user's rule must be filtered.
    #[tokio::test]
    async fn over_quota_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 100, traffic_used = 100 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "over-quota rule must be filtered");
    }

    /// A paused rule must be filtered.
    #[tokio::test]
    async fn paused_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET paused = 1 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "paused rule must be filtered");
    }

    /// Monitor groups never receive listeners (observation only).
    #[tokio::test]
    async fn monitor_group_yields_no_listeners() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "monitor", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty());
    }

    /// Multi-hop chain: entry emits next-hop target; exit emits final targets;
    /// only entry has count_traffic=true.
    #[tokio::test]
    async fn chain_rule_entry_and_exit_listeners() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        // Entry + exit groups; exit needs connect_host for previous hop to dial.
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'entry', 'in', 'tok-10', 2, '1.1.1.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (20, 'exit', 'out', 'tok-20', 2, '2.2.2.2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, device_group_out, forward_mode, \
              route_mode, target_addr, target_port) \
             VALUES (100, 'chain', 2, 20000, 10, 20, 'chain', 'chain', '9.9.9.9', 443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops (rule_id, position, device_group_id, listen_port) \
             VALUES (100, 0, 10, 20000), (100, 1, 20, 30000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let entry_cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(entry_cfg.listeners.len(), 1);
        assert_eq!(entry_cfg.listeners[0].port, 20000);
        assert_eq!(
            entry_cfg.listeners[0].targets,
            vec!["2.2.2.2:30000".to_string()]
        );
        assert!(entry_cfg.listeners[0].count_traffic);

        let exit_cfg = build_node_config(&repo(&pool), 20).await.unwrap();
        assert_eq!(exit_cfg.listeners.len(), 1);
        assert_eq!(exit_cfg.listeners[0].port, 30000);
        assert_eq!(
            exit_cfg.listeners[0].targets,
            vec!["9.9.9.9:443".to_string()]
        );
        assert!(!exit_cfg.listeners[0].count_traffic);
    }

    #[tokio::test]
    async fn pure_udp_chain_uses_authenticated_uot_and_warm_zero_rtt() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'entry', 'in', 'entry-secret', 2, '1.1.1.1'), \
                    (20, 'exit', 'out', 'exit-secret', 2, '2.2.2.2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, device_group_in, device_group_out, \
              forward_mode, route_mode, target_addr, target_port) \
             VALUES (101, 'udp-chain', 2, 20001, 'udp', 10, 20, 'chain', 'chain', \
                     '9.9.9.9', 53)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops (rule_id, position, device_group_id, listen_port) \
             VALUES (101, 0, 10, 20001), (101, 1, 20, 30001)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Stage 1 is the safe upgrade default: entry remains native UDP, while
        // later hops prepare both native UDP and UOT listeners.
        let staged_entry = build_node_config_inner(&repo(&pool), 10, false, false)
            .await
            .unwrap();
        let staged_exit = build_node_config_inner(&repo(&pool), 20, false, false)
            .await
            .unwrap();
        assert_eq!(staged_entry.listeners.len(), 1);
        assert_eq!(staged_entry.listeners[0].uot_role, UotRole::Disabled);
        assert!(staged_exit
            .listeners
            .iter()
            .any(|listener| listener.protocol == Protocol::Udp));
        assert!(staged_exit
            .listeners
            .iter()
            .any(|listener| listener.protocol == Protocol::Uot));

        // Stage 2 switches only the entry after every downstream v7 node has
        // already prepared its compatibility listeners.
        let entry = build_node_config_inner(&repo(&pool), 10, true, false)
            .await
            .unwrap();
        let exit = build_node_config_inner(&repo(&pool), 20, true, false)
            .await
            .unwrap();
        assert_eq!(entry.listeners[0].protocol, Protocol::Udp);
        assert_eq!(entry.listeners[0].uot_role, UotRole::Ingress);
        assert!(entry.listeners[0].zero_rtt);
        let exit_uot = exit
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Uot)
            .unwrap();
        assert_eq!(exit_uot.uot_role, UotRole::Egress);
        assert_eq!(entry.listeners[0].uot_token, exit_uot.uot_token);
        assert_eq!(
            entry.listeners[0].uot_token.as_deref().map(str::len),
            Some(64)
        );
        assert_ne!(
            entry.listeners[0].uot_token.as_deref(),
            Some("entry-secret")
        );
        assert_ne!(entry.listeners[0].uot_token.as_deref(), Some("exit-secret"));
        let occupied = repo(&pool).list_group_port_protocols(20).await.unwrap();
        assert!(occupied.contains(&(30001, "udp".to_string())));
        let tunnel_port: i64 = sqlx::query_scalar(
            "SELECT tunnel_port FROM forward_rule_hops WHERE rule_id = 101 AND position = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(exit_uot.port, tunnel_port as u16);
        assert_eq!(
            entry.listeners[0].targets,
            vec![format!("2.2.2.2:{tunnel_port}")]
        );
        assert!(occupied.contains(&(tunnel_port as i32, "tcp".to_string())));
    }

    #[tokio::test]
    async fn existing_tcp_port_collision_gets_a_dedicated_uot_port() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'entry', 'in', 'entry-secret', 2, '1.1.1.1'), \
                    (20, 'exit', 'out', 'exit-secret', 2, '2.2.2.2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, device_group_in, device_group_out, \
              forward_mode, route_mode, target_addr, target_port) VALUES \
             (101, 'udp-chain', 2, 20001, 'udp', 10, 20, 'chain', 'chain', '9.9.9.9', 53), \
             (102, 'existing-tcp', 2, 30001, 'tcp', 20, NULL, 'direct', 'direct', '8.8.8.8', 443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops (rule_id, position, device_group_id, listen_port) \
             VALUES (101, 0, 10, 20001), (101, 1, 20, 30001)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let entry = build_node_config_inner(&repo(&pool), 10, true, false)
            .await
            .unwrap();
        assert_eq!(entry.listeners[0].uot_role, UotRole::Ingress);
        let exit = build_node_config_inner(&repo(&pool), 20, true, false)
            .await
            .unwrap();
        let chain_listeners: Vec<_> = exit
            .listeners
            .iter()
            .filter(|listener| listener.rule_id == 101)
            .collect();
        assert_eq!(chain_listeners.len(), 2);
        let uot = chain_listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Uot)
            .unwrap();
        assert_ne!(uot.port, 30001);
        assert_eq!(uot.uot_role, UotRole::Egress);
    }

    #[tokio::test]
    async fn tcp_udp_chain_stages_uot_and_tcp_fast_open_independently() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups \
             (id, name, group_type, token, uid, connect_host, port_range) VALUES \
             (10, 'entry', 'in', 'entry-secret', 2, '1.1.1.1', '20000-20010'), \
             (20, 'exit', 'out', 'exit-secret', 2, '2.2.2.2', '30000-30010')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, device_group_in, device_group_out, \
              forward_mode, route_mode, target_addr, target_port) \
             VALUES (103, 'both-chain', 2, 20003, 'tcp_udp', 10, 20, 'chain', 'chain', \
                     '9.9.9.9', 443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops \
             (rule_id, position, device_group_id, listen_port) \
             VALUES (103, 0, 10, 20003), (103, 1, 20, 30003)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Stage 1: public entry remains native. The upgraded exit prepares
        // raw TCP+UDP on the legacy port, UOT on a distinct TCP port, and TFO
        // on its raw TCP listener for upgraded upstream hops.
        let entry_stage1 = build_node_config_inner(&repo(&pool), 10, false, false)
            .await
            .unwrap();
        let exit_stage1 = build_node_config_inner(&repo(&pool), 20, false, false)
            .await
            .unwrap();
        assert_eq!(entry_stage1.listeners.len(), 2);
        assert!(entry_stage1
            .listeners
            .iter()
            .all(|listener| listener.uot_role == UotRole::Disabled));
        assert!(!entry_stage1
            .listeners
            .iter()
            .any(|listener| listener.tcp_fast_open));
        let exit_tcp = exit_stage1
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Tcp)
            .unwrap();
        let exit_udp = exit_stage1
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Udp)
            .unwrap();
        let exit_uot = exit_stage1
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Uot)
            .unwrap();
        assert_eq!(exit_tcp.port, 30003);
        assert_eq!(exit_udp.port, 30003);
        assert!(exit_tcp.tcp_fast_open);
        assert_ne!(exit_uot.port, 30003);

        // Stage 2 independently enables the UDP ingress tunnel and entry-side
        // TFO. TCP still targets the native hop port; only UDP targets UOT.
        let entry = build_node_config_inner(&repo(&pool), 10, true, true)
            .await
            .unwrap();
        let entry_tcp = entry
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Tcp)
            .unwrap();
        let entry_udp = entry
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Udp)
            .unwrap();
        assert!(entry_tcp.tcp_fast_open);
        assert_eq!(entry_tcp.targets, vec!["2.2.2.2:30003".to_string()]);
        assert_eq!(entry_udp.uot_role, UotRole::Ingress);
        assert_eq!(
            entry_udp.targets,
            vec![format!("2.2.2.2:{}", exit_uot.port)]
        );
        assert_eq!(entry_udp.uot_token, exit_uot.uot_token);
    }

    #[tokio::test]
    async fn exhausted_tunnel_pool_keeps_tcp_udp_chain_native() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups \
             (id, name, group_type, token, uid, connect_host, port_range) VALUES \
             (10, 'entry', 'in', 'entry-secret', 2, '1.1.1.1', '20000-20010'), \
             (20, 'exit', 'out', 'exit-secret', 2, '2.2.2.2', '30001-30001')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, device_group_in, device_group_out, \
              forward_mode, route_mode, target_addr, target_port) \
             VALUES (104, 'full-pool', 2, 20004, 'tcp_udp', 10, 20, 'chain', 'chain', \
                     '9.9.9.9', 443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops \
             (rule_id, position, device_group_id, listen_port) \
             VALUES (104, 0, 10, 20004), (104, 1, 20, 30001)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // The only port in the exit pool is already occupied by the raw TCP
        // component. Even with both feature flags enabled, UOT must fail closed
        // to the native UDP path instead of removing or half-switching it.
        let entry = build_node_config_inner(&repo(&pool), 10, true, true)
            .await
            .unwrap();
        let entry_udp = entry
            .listeners
            .iter()
            .find(|listener| listener.protocol == Protocol::Udp)
            .unwrap();
        assert_eq!(entry_udp.uot_role, UotRole::Disabled);
        assert_eq!(entry_udp.targets, vec!["2.2.2.2:30001".to_string()]);

        let exit = build_node_config_inner(&repo(&pool), 20, true, true)
            .await
            .unwrap();
        assert!(exit
            .listeners
            .iter()
            .all(|listener| listener.protocol != Protocol::Uot));
        assert!(exit
            .listeners
            .iter()
            .any(|listener| listener.protocol == Protocol::Udp));
        let tunnel_port: Option<i64> = sqlx::query_scalar(
            "SELECT tunnel_port FROM forward_rule_hops WHERE rule_id = 104 AND position = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tunnel_port, None);
    }

    /// One `both` group represents one relay-node registration that can serve
    /// its own entry rules and another chain's exit hop at the same time. The
    /// node must receive both listeners in one config snapshot; otherwise an
    /// operator would still need two groups/processes on the same server.
    #[tokio::test]
    async fn dual_role_group_combines_entry_and_exit_listeners() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'entry', 'in', 'tok-10', 2, '1.1.1.1'), \
                    (20, 'dual', 'both', 'tok-20', 2, '2.2.2.2')",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Rule 100 uses the dual-role node as its exit.
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, device_group_out, forward_mode, \
              route_mode, target_addr, target_port) \
             VALUES (100, 'chain-to-dual', 2, 20000, 10, 20, 'chain', 'chain', '9.9.9.9', 443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops (rule_id, position, device_group_id, listen_port) \
             VALUES (100, 0, 10, 20000), (100, 1, 20, 30000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Rule 200 uses that same node as a normal entry.
        add_rule(&pool, 200, 2, 20, 40000).await;

        let cfg = build_node_config(&repo(&pool), 20).await.unwrap();
        assert_eq!(cfg.listeners.len(), 2);
        let by_port: std::collections::HashMap<_, _> =
            cfg.listeners.iter().map(|l| (l.port, l)).collect();

        let exit = by_port.get(&30000).expect("chain exit listener");
        assert_eq!(exit.targets, vec!["9.9.9.9:443".to_string()]);
        assert!(
            !exit.count_traffic,
            "exit hop must not double-count traffic"
        );

        let entry = by_port.get(&40000).expect("direct entry listener");
        assert_eq!(entry.targets, vec!["127.0.0.1:80".to_string()]);
        assert!(
            entry.count_traffic,
            "entry listener owns traffic accounting"
        );
    }

    /// traffic_limit = 0 means unlimited — never filtered by quota even if
    /// traffic_used is huge.
    #[tokio::test]
    async fn unlimited_quota_never_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 0, traffic_used = 999999999 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
    }

    /// v0.4.7: a rule bound to a WS tunnel profile must take its node_transport
    /// and ws_path FROM the profile (the rule's own columns are ignored).
    #[tokio::test]
    async fn profile_overrides_transport_and_ws_path() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // The test pool only runs SCHEMA_SQL (no builtin seeds), so insert a ws
        // profile explicitly rather than rely on the Migration 6 seed.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (50, 'ws-relay', 'ws', 'none', '/relay', '', '', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 50 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Ws,
            "profile transport must override the rule's stored raw transport"
        );
        assert_eq!(
            cfg.listeners[0].ws_path.as_deref(),
            Some("/relay"),
            "ws_path must come from the profile"
        );
    }

    /// v0.4.7: a rule with NO profile (tunnel_profile_id NULL) keeps using its
    /// own stored public_transport/ws_path — legacy behavior, zero break.
    #[tokio::test]
    async fn null_profile_falls_back_to_rule_transport() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // A raw rule, no profile binding.
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Raw
        );
        assert!(cfg.listeners[0].ws_path.is_none());
    }

    /// v0.4.7: a rule bound to a DELETED profile is skipped (no listener), not
    /// silently downgraded to raw.
    #[tokio::test]
    async fn missing_profile_skips_rule() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        // Point at a profile id that doesn't exist. Disable FK enforcement for
        // this insert so SQLite accepts the dangling reference (production code
        // prevents this via Migration 22's NULL-out + delete usage count, but
        // we want to pin the builder's defensive skip behavior).
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 99999 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "a rule bound to a missing profile must be skipped, not downgraded"
        );
    }
}
