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
use relay_shared::protocol::{
    GroupCredentialRevision, LoadBalanceStrategy, NodeConfigResponse, Protocol, TunnelClientConfig,
    TunnelListenerConfig, TunnelNextConfig, TunnelRouteConfig, UotRole,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

struct ResolvedTargets {
    addrs: Vec<String>,
    weights: Vec<u16>,
}

fn empty_node_config(credential_revisions: Vec<GroupCredentialRevision>) -> NodeConfigResponse {
    NodeConfigResponse {
        listeners: vec![],
        tunnels: vec![],
        credential_revisions,
        terminate_tunnel_ids: vec![],
        drain_rule_ids: vec![],
        route_transition_rule_ids: vec![],
        route_staging_rule_ids: vec![],
        route_drain_rule_ids: vec![],
    }
}

async fn group_is_administrator_managed(
    db: &dyn Repository,
    group_id: i64,
    cache: &mut HashMap<i64, bool>,
) -> Result<bool, DbError> {
    if let Some(managed) = cache.get(&group_id) {
        return Ok(*managed);
    }
    let managed = match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(group) => db.is_admin(group.uid).await?,
        None => false,
    };
    cache.insert(group_id, managed);
    Ok(managed)
}

async fn all_rule_hops_are_administrator_managed(
    db: &dyn Repository,
    hops: &[relay_shared::models::ForwardRuleHop],
    cache: &mut HashMap<i64, bool>,
) -> Result<bool, DbError> {
    for hop in hops {
        if !group_is_administrator_managed(db, hop.device_group_id, cache).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Render a dial address without producing ambiguous raw-IPv6 `host:port`
/// strings. Device-group connect_host and rule targets are stored separately
/// from their port, so bracket normalization belongs at this boundary.
fn format_host_port(host: &str, port: i32) -> String {
    let host = host.trim();
    if host.starts_with('[') && host.ends_with(']') {
        return format!("{host}:{port}");
    }
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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
    let Some(group) = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? else {
        return Ok(empty_node_config(Vec::new()));
    };
    if !db.is_admin(group.uid).await? {
        tracing::warn!(
            group_id,
            owner_id = group.uid,
            "refusing runtime config for a historical non-admin-owned device group"
        );
        return Ok(empty_node_config(Vec::new()));
    }

    let credential_revisions = db
        .list_group_credential_revisions()
        .await?
        .into_iter()
        .map(|(group_id, revision)| GroupCredentialRevision { group_id, revision })
        .collect::<Vec<_>>();
    if group.group_type == "monitor" {
        return Ok(empty_node_config(credential_revisions));
    }
    let mut admin_group_cache = HashMap::from([(group.id, true)]);

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
    // Load the reusable topology once per node snapshot. Besides avoiding one
    // lookup per bound rule, this guarantees entry clients and shared
    // listeners are built from the same topology snapshot.
    let loaded_group_tunnels = db.list_enabled_tunnels_for_group(group.id).await?;
    let mut group_tunnels = Vec::with_capacity(loaded_group_tunnels.len());
    'tunnels: for tunnel in loaded_group_tunnels {
        for hop in &tunnel.hops {
            if !group_is_administrator_managed(db, hop.device_group_id, &mut admin_group_cache)
                .await?
            {
                tracing::warn!(
                    tunnel_id = tunnel.id,
                    group_id = hop.device_group_id,
                    "skipping historical tunnel with a non-admin-owned hop"
                );
                continue 'tunnels;
            }
        }
        group_tunnels.push(tunnel);
    }
    let preset_tunnels: HashMap<i64, &relay_shared::models::Tunnel> = group_tunnels
        .iter()
        .map(|tunnel| (tunnel.id, tunnel))
        .collect();
    let tunnel_group_tokens: HashMap<i64, String> = if group_tunnels.is_empty() {
        HashMap::new()
    } else {
        let mut group_ids: Vec<i64> = group_tunnels
            .iter()
            .flat_map(|tunnel| tunnel.hops.iter().map(|hop| hop.device_group_id))
            .collect();
        group_ids.sort_unstable();
        group_ids.dedup();
        db.list_group_tokens(&group_ids)
            .await?
            .into_iter()
            .collect()
    };

    // 3 + 4. Resolve targets and build listener configs. Target resolution needs
    //    a DB lookup (outbound group's connect_host), so it stays async and lives
    //    here; the pure ListenerConfig assembly (transport/ws_path/protocol) is
    //    delegated to the shared `build_listeners_for_rule` so that part can never
    //    drift between paths.
    let mut listeners = Vec::new();
    let mut entry_tunnel_configs = Vec::new();
    for rule in &rules {
        let Some(effective_rule) = apply_tunnel_profile(db, rule).await? else {
            continue;
        };

        if let Some(tunnel_id) = rule.tunnel_id {
            let Some(tunnel) = preset_tunnels.get(&tunnel_id) else {
                tracing::warn!(
                    "rule {} references missing tunnel {}; skipping",
                    rule.id,
                    tunnel_id
                );
                continue;
            };
            if !tunnel.enabled || tunnel.hops.len() < 2 {
                continue;
            }
            // An unshared preset is administrator-only. This is a second
            // defense behind the repository query so a future query refactor
            // cannot accidentally publish an ordinary user's bound rule.
            if !tunnel.shared && !db.is_admin(rule.uid).await? {
                continue;
            }
            let entry = &tunnel.hops[0];
            let next = &tunnel.hops[1];
            if entry.device_group_id != group.id {
                continue;
            }
            let Some(next_port) = next.listen_port else {
                continue;
            };
            let Some(next_host) = next.connect_host.as_deref() else {
                continue;
            };
            if next_host.trim().is_empty() {
                continue;
            }
            let address = format_host_port(next_host, next_port);
            let auth_token =
                preset_tunnel_link_token(&tunnel_group_tokens, tunnel.id, &tunnel.hops, 0)?;
            let route_revision = preset_rule_route_revision(rule, tunnel);
            let mut entry_listeners = relay_shared::protocol::build_listeners_for_rule(
                &effective_rule,
                vec![address.clone()],
            );
            let client_config = TunnelClientConfig {
                tunnel_id: tunnel.id,
                rule_id: rule.id,
                hop_position: 0,
                address: address.clone(),
                auth_token: auth_token.clone(),
                link_scope: preset_tunnel_link_scope(tunnel.id, &tunnel.hops, 0)?,
            };
            for listener in &mut entry_listeners {
                listener.target_weights = vec![1];
                if listener.protocol == Protocol::Udp {
                    listener.zero_rtt = true;
                }
                // Reuse an existing fingerprinted secret field so token
                // rotation restarts the entry listener even though the v8
                // client metadata lives in NodeConfigResponse.tunnels.
                listener.uot_token = Some(auth_token.clone());
                // The entry does not dial final targets directly, so those
                // addresses cannot live in `targets`. Carry a one-way revision
                // in another fingerprinted field: target/weight edits restart
                // the UDP ingress task (closing its warm channel) while active
                // TCP connections still drain under the existing runtime.
                listener.uot_next_token = Some(route_revision.clone());
            }
            entry_tunnel_configs.push(TunnelListenerConfig {
                tunnel_id: tunnel.id,
                port: 0,
                hop_position: 0,
                auth_token: String::new(),
                link_scope: String::new(),
                next: None,
                routes: Vec::new(),
                handshake_timeout_ms: 3_000,
                max_unauthenticated: 0,
                clients: vec![client_config],
            });
            listeners.extend(entry_listeners);
            continue;
        }

        if rule.route_mode == "chain" {
            // Entry hop (position 0) for chain rules whose device_group_in is
            // this group. Intermediate/exit hops are emitted below via
            // list_active_chain_hops_for_group (position > 0 only here).
            let mut hops = db.list_rule_hops(rule.id).await?;
            if hops.is_empty() {
                tracing::warn!("chain rule {} has no hops; skipping listeners", rule.id);
                continue;
            }
            if !all_rule_hops_are_administrator_managed(db, &hops, &mut admin_group_cache).await? {
                tracing::warn!(
                    rule_id = rule.id,
                    "skipping historical chain with a non-admin-owned hop"
                );
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
    let chain_rules: HashMap<i64, ForwardRule> = db
        .list_active_chain_rules_for_group(group.id)
        .await?
        .into_iter()
        .map(|rule| (rule.id, rule))
        .collect();
    for hop in chain_hops {
        if hop.position <= 0 {
            continue; // entry emitted via device_group_in path
        }
        let Some(rule) = chain_rules.get(&hop.rule_id) else {
            continue;
        };
        if rule.paused || rule.route_mode != "chain" {
            continue;
        }
        let Some(effective_rule) = apply_tunnel_profile(db, rule).await? else {
            continue;
        };
        let mut hops = db.list_rule_hops(rule.id).await?;
        if !all_rule_hops_are_administrator_managed(db, &hops, &mut admin_group_cache).await? {
            tracing::warn!(
                rule_id = rule.id,
                "skipping historical chain with a non-admin-owned hop"
            );
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
        let targets = match chain_hop_targets(db, rule, &hops, hop.position).await? {
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
                rule,
                &hops,
                hop.position,
                &mut hop_listeners,
                enable_uot_ingress,
            )
            .await?;
        }
        apply_tcp_fast_open_role(
            rule,
            hop.position,
            &mut hop_listeners,
            enable_tcp_zero_rtt_ingress,
        );
        listeners.extend(hop_listeners);
    }

    let mut tunnels =
        build_preset_tunnel_configs(db, group.id, &group_tunnels, &tunnel_group_tokens).await?;
    tunnels.extend(entry_tunnel_configs);
    let terminate_tunnel_ids = db.list_disabled_bound_tunnel_ids().await?;
    let drain_rule_ids = db.list_draining_tunnel_rule_ids_for_group(group.id).await?;
    let route_transition_rule_ids = db
        .list_route_transition_rule_ids_for_group(group.id)
        .await?;
    let route_staging_rule_ids = db.list_route_staging_rule_ids_for_group(group.id).await?;
    let route_drain_rule_ids = db.list_route_drain_rule_ids_for_group(group.id).await?;
    Ok(NodeConfigResponse {
        listeners,
        tunnels,
        credential_revisions,
        terminate_tunnel_ids,
        drain_rule_ids,
        route_transition_rule_ids,
        route_staging_rule_ids,
        route_drain_rule_ids,
    })
}

async fn build_preset_tunnel_configs(
    db: &dyn Repository,
    group_id: i64,
    tunnels: &[relay_shared::models::Tunnel],
    group_tokens: &HashMap<i64, String>,
) -> Result<Vec<TunnelListenerConfig>, DbError> {
    let mut rules_by_tunnel: HashMap<i64, Vec<ForwardRule>> = HashMap::new();
    for rule in db.list_active_tunnel_rules_for_group(group_id).await? {
        if let Some(tunnel_id) = rule.tunnel_id {
            rules_by_tunnel.entry(tunnel_id).or_default().push(rule);
        }
    }
    let mut configs = Vec::new();
    for tunnel in tunnels {
        let Some((position, hop)) = tunnel
            .hops
            .iter()
            .enumerate()
            .find(|(_, hop)| hop.device_group_id == group_id)
        else {
            continue;
        };
        if position == 0 {
            continue;
        }
        let rules = rules_by_tunnel.remove(&tunnel.id).unwrap_or_default();
        if rules.is_empty() {
            continue;
        }
        let Some(port) = hop.listen_port else {
            continue;
        };
        let auth_token =
            preset_tunnel_link_token(group_tokens, tunnel.id, &tunnel.hops, position - 1)?;
        let next = if position + 1 < tunnel.hops.len() {
            let next_hop = &tunnel.hops[position + 1];
            let Some(next_port) = next_hop.listen_port else {
                continue;
            };
            let Some(next_host) = next_hop.connect_host.as_deref() else {
                continue;
            };
            if next_host.trim().is_empty() {
                continue;
            }
            Some(TunnelNextConfig {
                hop_position: position as u8,
                address: format_host_port(next_host, next_port),
                auth_token: preset_tunnel_link_token(
                    group_tokens,
                    tunnel.id,
                    &tunnel.hops,
                    position,
                )?,
                link_scope: preset_tunnel_link_scope(tunnel.id, &tunnel.hops, position)?,
            })
        } else {
            None
        };

        let mut routes = Vec::with_capacity(rules.len());
        for rule in rules {
            let (targets, weights, strategy) = if next.is_none() {
                let resolved = resolve_preloaded_final_targets(&rule);
                (
                    resolved.addrs,
                    resolved.weights,
                    LoadBalanceStrategy::from_db_str(&rule.load_balance_strategy),
                )
            } else {
                (Vec::new(), Vec::new(), LoadBalanceStrategy::First)
            };
            routes.push(TunnelRouteConfig {
                rule_id: rule.id,
                protocol: rule.protocol,
                targets,
                target_weights: weights,
                load_balance_strategy: strategy,
            });
        }
        configs.push(TunnelListenerConfig {
            tunnel_id: tunnel.id,
            port: port as u16,
            hop_position: position as u8,
            auth_token,
            link_scope: preset_tunnel_link_scope(tunnel.id, &tunnel.hops, position - 1)?,
            next,
            routes,
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 128,
            clients: Vec::new(),
        });
    }
    Ok(configs)
}

fn preset_tunnel_link_scope(
    tunnel_id: i64,
    hops: &[relay_shared::models::TunnelHop],
    position: usize,
) -> Result<String, DbError> {
    let from = hops.get(position).ok_or(DbError::NotFound)?;
    let to = hops.get(position + 1).ok_or(DbError::NotFound)?;
    Ok(format!(
        "{tunnel_id}:{position}:{}:{}",
        from.device_group_id, to.device_group_id
    ))
}

fn preset_tunnel_link_token(
    group_tokens: &HashMap<i64, String>,
    tunnel_id: i64,
    hops: &[relay_shared::models::TunnelHop],
    position: usize,
) -> Result<String, DbError> {
    let from = hops.get(position).ok_or(DbError::NotFound)?;
    let to = hops.get(position + 1).ok_or(DbError::NotFound)?;
    let from_token = group_tokens
        .get(&from.device_group_id)
        .ok_or(DbError::NotFound)?;
    let to_token = group_tokens
        .get(&to.device_group_id)
        .ok_or(DbError::NotFound)?;
    let mut hasher = Sha256::new();
    hasher.update(b"relay-panel-preset-tunnel-v1\0");
    hasher.update(tunnel_id.to_be_bytes());
    hasher.update((position as u64).to_be_bytes());
    hasher.update(from_token.as_bytes());
    hasher.update([0]);
    hasher.update(to_token.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn preset_rule_route_revision(rule: &ForwardRule, tunnel: &relay_shared::models::Tunnel) -> String {
    let resolved = resolve_preloaded_final_targets(rule);
    let mut hasher = Sha256::new();
    hasher.update(b"relay-panel-preset-route-revision-v1\0");
    hasher.update(tunnel.id.to_be_bytes());
    for hop in &tunnel.hops {
        hasher.update([0]);
        hasher.update(hop.position.to_be_bytes());
        hasher.update(hop.device_group_id.to_be_bytes());
        hasher.update(hop.listen_port.unwrap_or_default().to_be_bytes());
        hasher.update([0]);
        hasher.update(hop.connect_host.as_deref().unwrap_or_default().as_bytes());
    }
    hasher.update(rule.protocol.as_bytes());
    hasher.update([0]);
    hasher.update(rule.load_balance_strategy.as_bytes());
    for (index, address) in resolved.addrs.iter().enumerate() {
        hasher.update([0]);
        hasher.update(address.as_bytes());
        hasher.update(
            resolved
                .weights
                .get(index)
                .copied()
                .unwrap_or(1)
                .to_be_bytes(),
        );
    }
    format!("{:x}", hasher.finalize())
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
    Ok(Some(format_host_port(&group.connect_host, port)))
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
            addrs: vec![format_host_port(&host, next.listen_port)],
            weights: vec![1],
        }))
    } else {
        // Exit hop → final targets.
        Ok(Some(resolve_preloaded_final_targets(rule)))
    }
}

fn resolve_preloaded_final_targets(rule: &ForwardRule) -> ResolvedTargets {
    let mut targets: Vec<_> = rule
        .targets
        .iter()
        .filter(|target| target.enabled)
        .collect();
    if targets.is_empty() {
        return ResolvedTargets {
            addrs: vec![format_host_port(&rule.target_addr, rule.target_port)],
            weights: vec![1],
        };
    }
    ResolvedTargets {
        addrs: targets
            .iter()
            .map(|target| format_host_port(&target.host, target.port))
            .collect(),
        weights: targets
            .drain(..)
            .map(|target| target.weight.clamp(1, 100) as u16)
            .collect(),
    }
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
    let targets: Vec<(&str, i32, i32)> = if rule.targets.iter().any(|target| target.enabled) {
        rule.targets
            .iter()
            .filter(|target| target.enabled)
            .map(|target| (target.host.as_str(), target.port, target.weight))
            .collect()
    } else {
        vec![(rule.target_addr.as_str(), rule.target_port, 1)]
    };
    let weights: Vec<u16> = targets
        .iter()
        .map(|(_, _, weight)| (*weight).clamp(1, 100) as u16)
        .collect();

    match (rule.forward_mode.as_str(), rule.device_group_out) {
        ("direct", _) | (_, None) => Ok(ResolvedTargets {
            addrs: targets
                .into_iter()
                .map(|(host, port, _)| format_host_port(host, port))
                .collect(),
            weights,
        }),
        (_, Some(out_id)) => {
            // Qualify: find_by_id is on both UserRepository and GroupRepository.
            let og = GroupRepository::find_by_id(db, out_id, &ResourceScope::All).await?;
            let addrs = match og {
                Some(DeviceGroup { connect_host, .. }) if !connect_host.is_empty() => targets
                    .into_iter()
                    .map(|(_, port, _)| format_host_port(&connect_host, port))
                    .collect(),
                _ => targets
                    .into_iter()
                    .map(|(host, port, _)| format_host_port(host, port))
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
    fn host_port_formatter_brackets_ipv6_once() {
        assert_eq!(format_host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(format_host_port("[2001:db8::1]", 443), "[2001:db8::1]:443");
        assert_eq!(format_host_port(" example.com ", 443), "example.com:443");
        assert_eq!(format_host_port("192.0.2.1", 443), "192.0.2.1:443");
    }

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
        // These tests exercise runtime/config behavior other than entitlement.
        // Make that entitlement explicit so a successful fixture does not rely
        // on the obsolete "group owner implies access" behavior.
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, all_device_groups) \
             VALUES (?, ?, ?, 0, 1)",
        )
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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
             VALUES (10, 'entry', 'in', 'tok-10', 1, '1.1.1.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (20, 'exit', 'out', 'tok-20', 1, '2.2.2.2')",
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
        sqlx::query(
            "INSERT INTO forward_rule_targets \
             (rule_id,host,port,position,enabled,weight) VALUES \
             (100,'9.9.9.9',443,1,1,30),(100,'8.8.8.8',8443,2,1,70)",
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
            vec!["9.9.9.9:443".to_string(), "8.8.8.8:8443".to_string()]
        );
        assert_eq!(exit_cfg.listeners[0].target_weights, vec![30, 70]);
        assert!(!exit_cfg.listeners[0].count_traffic);
    }

    #[tokio::test]
    async fn historical_regular_owned_chain_hops_fail_closed() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups (id,name,group_type,token,uid,connect_host) VALUES \
             (10,'entry','in','entry-token',1,'192.0.2.10'), \
             (20,'legacy-exit','out','legacy-token',2,'192.0.2.20')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id,name,uid,listen_port,device_group_in,device_group_out,forward_mode,route_mode,target_addr,target_port) \
             VALUES(100,'legacy-chain',2,20000,10,20,'chain','chain','203.0.113.10',443)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops(rule_id,position,device_group_id,listen_port) \
             VALUES(100,0,10,20000),(100,1,20,30000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(build_node_config(&repo(&pool), 10)
            .await
            .unwrap()
            .listeners
            .is_empty());
        let legacy = build_node_config(&repo(&pool), 20).await.unwrap();
        assert!(legacy.listeners.is_empty());
        assert!(legacy.credential_revisions.is_empty());
    }

    #[tokio::test]
    async fn pure_udp_chain_uses_authenticated_uot_and_warm_zero_rtt() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'entry', 'in', 'entry-secret', 1, '1.1.1.1'), \
                    (20, 'exit', 'out', 'exit-secret', 1, '2.2.2.2')",
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
             VALUES (10, 'entry', 'in', 'entry-secret', 1, '1.1.1.1'), \
                    (20, 'exit', 'out', 'exit-secret', 1, '2.2.2.2')",
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
             (10, 'entry', 'in', 'entry-secret', 1, '1.1.1.1', '20000-20010'), \
             (20, 'exit', 'out', 'exit-secret', 1, '2.2.2.2', '30000-30010')",
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
             (10, 'entry', 'in', 'entry-secret', 1, '1.1.1.1', '20000-20010'), \
             (20, 'exit', 'out', 'exit-secret', 1, '2.2.2.2', '30001-30001')",
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
             VALUES (10, 'entry', 'in', 'tok-10', 1, '1.1.1.1'), \
                    (20, 'dual', 'both', 'tok-20', 1, '2.2.2.2')",
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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
        add_group(&pool, 10, "in", 1).await;
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

    #[tokio::test]
    async fn preset_route_revision_covers_later_hops_ports_and_addresses() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query("UPDATE users SET all_device_groups=1 WHERE id=2")
            .execute(&pool)
            .await
            .unwrap();
        add_group(&pool, 10, "in", 1).await;
        add_group(&pool, 20, "out", 1).await;
        add_group(&pool, 30, "out", 1).await;
        sqlx::query(
            "UPDATE device_groups SET connect_host=CASE id \
             WHEN 20 THEN '127.0.0.20' ELSE '127.0.0.30' END WHERE id IN (20,30)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tunnels (id,name,enabled,shared,uid) VALUES (40,'three-hop',1,1,2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tunnel_hops (tunnel_id,position,device_group_id,listen_port) \
             VALUES (40,0,10,NULL),(40,1,20,36100),(40,2,30,36101)",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 110, 2, 10, 20110).await;
        sqlx::query(
            "UPDATE forward_rules SET protocol='udp',route_mode='chain',forward_mode='chain', \
             device_group_out=30,tunnel_id=40 WHERE id=110",
        )
        .execute(&pool)
        .await
        .unwrap();

        let revision = |config: &NodeConfigResponse| {
            config.listeners[0]
                .uot_next_token
                .as_deref()
                .expect("preset route revision")
                .to_owned()
        };
        let first = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(first.listeners[0].targets, vec!["127.0.0.20:36100"]);

        sqlx::query("UPDATE tunnel_hops SET listen_port=36102 WHERE tunnel_id=40 AND position=2")
            .execute(&pool)
            .await
            .unwrap();
        let port_changed = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_ne!(
            revision(&first),
            revision(&port_changed),
            "a later-hop port edit must rebuild the entry UDP warm channel"
        );
        assert_eq!(
            first.listeners[0].targets, port_changed.listeners[0].targets,
            "the first link intentionally stays unchanged in this regression"
        );

        sqlx::query("UPDATE device_groups SET connect_host='127.0.0.31' WHERE id=30")
            .execute(&pool)
            .await
            .unwrap();
        let address_changed = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_ne!(
            revision(&port_changed),
            revision(&address_changed),
            "a later-hop dial-address edit must rebuild the entry UDP warm channel"
        );
    }

    #[tokio::test]
    async fn preset_tunnel_two_rules_share_one_downstream_listener_and_route_table() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        sqlx::query("UPDATE users SET all_device_groups=1 WHERE id=2")
            .execute(&pool)
            .await
            .unwrap();
        add_group(&pool, 10, "in", 1).await;
        add_group(&pool, 20, "out", 1).await;
        sqlx::query("UPDATE device_groups SET connect_host='127.0.0.1' WHERE id=20")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tunnels (id,name,enabled,shared,uid) VALUES (30,'shared',1,1,2)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tunnel_hops (tunnel_id,position,device_group_id,listen_port) \
             VALUES (30,0,10,NULL),(30,1,20,36000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (id, port, target_port) in [(100, 20000, 8001), (101, 20001, 8002)] {
            add_rule(&pool, id, 2, 10, port).await;
            sqlx::query(
                "UPDATE forward_rules SET route_mode='chain',forward_mode='chain', \
                 device_group_out=20,tunnel_id=30,target_port=? WHERE id=?",
            )
            .bind(target_port)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        }

        let entry = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(
            entry.listeners.len(),
            2,
            "public entry remains rule-specific"
        );
        assert_eq!(
            entry.tunnels.len(),
            2,
            "entry metadata carries one client per rule"
        );
        assert!(entry.tunnels.iter().all(|config| config.port == 0));

        sqlx::query("UPDATE tunnels SET name='display-only-change' WHERE id=30")
            .execute(&pool)
            .await
            .unwrap();
        let renamed = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            serde_json::to_value(&renamed).unwrap(),
            "a tunnel name change must not restart the data plane"
        );

        let old_revision = entry
            .listeners
            .iter()
            .find(|listener| listener.rule_id == 101)
            .and_then(|listener| listener.uot_next_token.clone());
        sqlx::query("UPDATE forward_rules SET target_port=8999 WHERE id=101")
            .execute(&pool)
            .await
            .unwrap();
        let retargeted_entry = build_node_config(&repo(&pool), 10).await.unwrap();
        let new_revision = retargeted_entry
            .listeners
            .iter()
            .find(|listener| listener.rule_id == 101)
            .and_then(|listener| listener.uot_next_token.clone());
        assert_ne!(
            old_revision, new_revision,
            "target edits must rebuild UDP warm channels"
        );

        let exit = build_node_config(&repo(&pool), 20).await.unwrap();
        assert!(exit.listeners.is_empty());
        assert_eq!(
            exit.tunnels.len(),
            1,
            "the exit binds one shared TCP listener"
        );
        assert_eq!(exit.tunnels[0].port, 36000);
        assert_eq!(exit.tunnels[0].routes.len(), 2);
        assert_eq!(
            exit.tunnels[0]
                .routes
                .iter()
                .map(|route| route.rule_id)
                .collect::<Vec<_>>(),
            vec![100, 101]
        );
        assert_ne!(
            exit.tunnels[0].routes[0].targets, exit.tunnels[0].routes[1].targets,
            "rule ids must route to their own configured targets"
        );

        sqlx::query("UPDATE tunnels SET shared=0 WHERE id=30")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            build_node_config(&repo(&pool), 10)
                .await
                .unwrap()
                .listeners
                .is_empty(),
            "取消共享必须撤下普通用户的公网入口 listener"
        );
        assert!(
            build_node_config(&repo(&pool), 20)
                .await
                .unwrap()
                .tunnels
                .is_empty(),
            "取消共享必须同步撤下普通用户的共享隧道路由"
        );
        sqlx::query("UPDATE tunnels SET shared=1 WHERE id=30")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            build_node_config(&repo(&pool), 20).await.unwrap().tunnels[0]
                .routes
                .len(),
            2,
            "重新共享后未暂停规则应自动恢复"
        );

        sqlx::query("UPDATE users SET all_device_groups=0 WHERE id=2")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            build_node_config(&repo(&pool), 10)
                .await
                .unwrap()
                .listeners
                .is_empty(),
            "撤销入口授权必须撤下入口规则"
        );
        assert!(
            build_node_config(&repo(&pool), 20)
                .await
                .unwrap()
                .tunnels
                .is_empty(),
            "撤销入口授权也必须撤下下游共享路由"
        );
        sqlx::query("UPDATE users SET all_device_groups=1 WHERE id=2")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query("UPDATE forward_rules SET paused=1 WHERE id=100")
            .execute(&pool)
            .await
            .unwrap();
        let paused = build_node_config(&repo(&pool), 20).await.unwrap();
        assert_eq!(paused.tunnels[0].routes.len(), 1);
        assert_eq!(paused.tunnels[0].routes[0].rule_id, 101);

        sqlx::query("UPDATE tunnels SET enabled=0 WHERE id=30")
            .execute(&pool)
            .await
            .unwrap();
        let disabled_entry = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(disabled_entry.listeners.is_empty());
        assert_eq!(disabled_entry.terminate_tunnel_ids, vec![30]);
        let disabled_exit = build_node_config(&repo(&pool), 20).await.unwrap();
        assert!(disabled_exit.tunnels.is_empty());
        assert_eq!(disabled_exit.terminate_tunnel_ids, vec![30]);

        // A node can miss the disable push while offline. If the administrator
        // then edits the disabled path, the removed historical hop must still
        // receive the id-only kill set when it reconnects with its old cache.
        add_group(&pool, 40, "out", 1).await;
        sqlx::query("UPDATE device_groups SET connect_host='127.0.0.1' WHERE id=40")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE tunnel_hops SET device_group_id=40 WHERE tunnel_id=30 AND position=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET device_group_out=40 WHERE tunnel_id=30")
            .execute(&pool)
            .await
            .unwrap();
        let removed_hop = build_node_config(&repo(&pool), 20).await.unwrap();
        assert!(removed_hop.tunnels.is_empty());
        assert_eq!(removed_hop.terminate_tunnel_ids, vec![30]);
    }
}
