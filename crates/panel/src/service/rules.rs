//! Rule + shared rule/group/profile validation service.
//!
//! Houses the pure, DB-agnostic validators shared by the rule, group and
//! profile handlers (protocol/transport rules, target normalization, port
//! auto-assignment) plus the `create_rule` / `update_rule` business flows.
//! Extracted from `api/admin` so the validation lives behind the `Repository`
//! trait and is unit-testable without the HTTP layer.

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, ProfileScope, Repository, ResourceScope, RuleUpdateData};
use relay_shared::protocol::{
    CreateRuleRequest, GroupType, Protocol, PublicTransport, RouteMode, RuleTargetRequest,
    UpdateRuleRequest, CHAIN_HOPS_MAX, CHAIN_HOPS_MIN,
};
use std::net::{IpAddr, Ipv6Addr};

/// Accepted forward_mode values for create/update.
pub fn validate_forward_mode(mode: &str) -> bool {
    matches!(mode, "direct" | "chain")
}

/// Is `transport` accepted by the admin API in the current release?
///
/// v0.4.1: `Raw` + `Ws` + `TlsSimple` (node terminates TLS via rustls).
/// `Wss` is deprecated — existing wss rules are migrated to ws by Migration 18,
/// and the admin API no longer accepts creating new wss rules.
///
/// Single source of truth for "what public_transport values may a rule store" —
/// both create_rule and update_rule call this so they can't drift.
pub fn is_public_transport_accepted(transport: PublicTransport) -> bool {
    matches!(
        transport,
        PublicTransport::Raw | PublicTransport::Ws | PublicTransport::TlsSimple
    )
}

/// Validate the protocol × public_transport combination for v0.4.0.
///
/// Two symmetric constraints (a rule must satisfy BOTH):
///   (a) any UDP-bearing protocol (udp OR tcp_udp) ⇒ transport must be Raw
///       (WS/WSS are TCP-only).
///   (b) WS/WSS transport ⇒ protocol must be TCP (WS carries TCP only).
///
/// Pure function (no DB) so create_rule and update_rule can both resolve their
/// EFFECTIVE protocol/transport strings and call this. Returns Some(error_msg)
/// when the combination is invalid.
///
/// `protocol` / `transport` are the stable DB strings ("tcp"|"udp"|"tcp_udp" and
/// "raw"|"ws"|"wss"|"tls_simple"). Unknown values are not rejected here —
/// they're handled by their own field validation.
pub fn validate_protocol_transport(protocol: &str, transport: &str) -> Option<&'static str> {
    // WS and TLS Simple are TCP-only transports.
    if (transport == "ws" || transport == "tls_simple") && protocol != "tcp" {
        return Some(
            "This transport (ws/tls_simple) currently carries TCP forwarding only; \
             UDP / TCP+UDP are not supported.",
        );
    }
    // any UDP-bearing protocol (udp OR tcp_udp) ⇒ transport must be Raw.
    let is_udp_bearing = matches!(protocol, "udp" | "tcp_udp");
    if is_udp_bearing && transport != "raw" {
        return Some("UDP rules only support 'raw' transport");
    }
    None
}

/// Map Protocol enum to stable DB string.
pub fn protocol_to_str(p: &Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Uot => "uot",
        Protocol::TcpUdp => "tcp_udp",
    }
}

pub fn is_plausible_target_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.contains("://") || h.contains('/') || h.chars().any(char::is_whitespace) {
        return false;
    }

    // Accept both raw and bracketed IP literals. Brackets are useful in forms
    // copied from host:port notation; node_config::format_host_port preserves
    // them without producing a double-bracketed address.
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some(inner) = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().is_ok();
    }

    // A remaining colon is neither a valid DNS hostname nor an IP literal.
    // Validate labels so punctuation-only inputs such as ":", "..." and "-"
    // do not survive until the relay node fails DNS resolution at runtime.
    if h.contains(':') {
        return false;
    }
    let dns_name = h.strip_suffix('.').unwrap_or(h);
    !dns_name.is_empty()
        && dns_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().any(|c| c.is_ascii_alphanumeric())
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        })
}

pub fn normalize_rule_targets(
    targets: Option<Vec<RuleTargetRequest>>,
    legacy_host: &str,
    legacy_port: u16,
) -> Result<Vec<RuleTargetRequest>, &'static str> {
    let mut out = targets.unwrap_or_else(|| {
        vec![RuleTargetRequest {
            host: legacy_host.to_string(),
            port: legacy_port,
            enabled: true,
            weight: 1,
        }]
    });
    if out.is_empty() {
        return Err("At least one target is required");
    }
    if out.len() > 32 {
        return Err("A rule can have at most 32 targets");
    }
    let mut enabled = 0usize;
    for target in &mut out {
        target.host = target.host.trim().to_string();
        if !is_plausible_target_host(&target.host) {
            return Err("Target host must be an IP address or domain without scheme/path/spaces");
        }
        if target.port == 0 {
            return Err("Target port must be between 1 and 65535");
        }
        if !(1..=100).contains(&target.weight) {
            return Err("Target weight must be between 1 and 100");
        }
        if target.enabled {
            enabled += 1;
        }
    }
    if enabled == 0 {
        return Err("At least one target must be enabled");
    }
    Ok(out)
}

/// Map GroupType enum to stable DB string.
pub fn group_type_to_str(gt: &GroupType) -> &'static str {
    match gt {
        GroupType::In => "in",
        GroupType::Out => "out",
        GroupType::Both => "both",
        GroupType::Monitor => "monitor",
    }
}

/// Whether a device group can be used as the first hop of a rule.
/// `both` deliberately shares all inbound behavior while remaining available
/// as a later chain hop, so one relay-node registration can serve both roles.
pub fn group_type_supports_inbound(group_type: &str) -> bool {
    matches!(group_type, "in" | "both")
}

/// The default auto-assign pool used when a group's `port_range` is unset, is
/// the "全可转发" sentinel `1-65535`, or is unparseable. Deliberately excludes
/// system ports (<10000) — matching the historical hardcoded behavior — so a
/// brand-new / never-customized group never auto-assigns 22/80/443 etc.
const DEFAULT_AUTO_PORT_LO: u16 = 10000;
const DEFAULT_AUTO_PORT_HI: u16 = 65535;

/// Resolve a group's stored `port_range` string into the inclusive `[lo, hi]`
/// pool that auto-assignment draws from.
///
/// * empty / `"1-65535"` (the schema default, i.e. "全可转发" — nobody narrowed
///   it) / unparseable → the default 10000-65535 pool (never system ports);
/// * an explicit `"start-end"` with `1 <= start <= end <= 65535` → used
///   verbatim, INCLUDING sub-10000 ports when the admin asked for them
///   (`"5000-65535"` really does hand out 5000-9999 — an explicit choice wins
///   over the default-avoidance). Only the exact `1-65535` string is treated as
///   the sentinel, so `2-65535` or `1-65534` are honored as narrowings.
pub fn resolve_auto_port_range(raw: &str) -> (u16, u16) {
    const DEFAULT: (u16, u16) = (DEFAULT_AUTO_PORT_LO, DEFAULT_AUTO_PORT_HI);
    let s = raw.trim();
    if s.is_empty() || s == "1-65535" {
        return DEFAULT;
    }
    let Some((a, b)) = s.split_once('-') else {
        return DEFAULT;
    };
    let (Ok(start), Ok(end)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) else {
        return DEFAULT;
    };
    if start < 1 || end > 65535 || start > end {
        return DEFAULT;
    }
    (start as u16, end as u16)
}

/// A cheap, dependency-free pseudo-random offset in `[0, span)`, seeded from the
/// wall clock so successive auto-assignments on the same group spread across the
/// pool instead of clustering at its low end. `span` is always `>= 1`.
fn pseudo_random_offset(span: u32) -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % span
}

/// Auto-assign a free listen port from the rule's inbound group's configured
/// `port_range`, scoped to that group and socket type.
///
/// v1.2.x: the search pool is the group's `port_range` (resolved via
/// [`resolve_auto_port_range`]) instead of a hardcoded 10000-65535. When the
/// pool is exhausted this returns an error naming the real range so the panel
/// can tell the operator the range is full — it never silently spills outside
/// the configured range.
///
/// v0.4.11 PR4: port occupancy is per (device_group_in, port, socket type).
/// We only need to avoid ports already used ON THIS GROUP that conflict with
/// the candidate's socket type: a TCP-bearing candidate (tcp / tcp_udp) avoids
/// this group's tcp / tcp_udp ports, and a UDP-bearing candidate (udp /
/// tcp_udp) avoids its udp / tcp_udp ports. A pure-TCP candidate may reuse a
/// port held by a pure-UDP rule, and vice versa. Different groups have
/// independent pools.
pub async fn auto_assign_port(
    db: &dyn Repository,
    device_group_in: i64,
    protocol: &str,
) -> Result<u16, String> {
    let needs_tcp = matches!(protocol, "tcp" | "tcp_udp");
    let needs_udp = matches!(protocol, "udp" | "tcp_udp");

    // The pool to draw from = this group's configured port_range, with the
    // unset / "1-65535" sentinel mapped to the safe 10000-65535 default. A
    // missing group (None) also falls back to the default pool.
    let range_raw = db
        .group_port_range(device_group_in)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let (lo, hi) = resolve_auto_port_range(&range_raw);

    // (port, protocol) pairs already in use on this group.
    let group_ports: Vec<(i32, String)> = db
        .list_group_port_protocols(device_group_in)
        .await
        .map_err(|e| e.to_string())?;

    // Build the occupied set: only ports whose socket type overlaps the
    // candidate's.
    let used: std::collections::HashSet<u16> = group_ports
        .into_iter()
        .filter_map(|(p, proto)| {
            let occupies_tcp = matches!(proto.as_str(), "tcp" | "tcp_udp");
            let occupies_udp = matches!(proto.as_str(), "udp" | "tcp_udp");
            let conflicts = (needs_tcp && occupies_tcp) || (needs_udp && occupies_udp);
            if conflicts {
                u16::try_from(p).ok()
            } else {
                None
            }
        })
        .collect();

    // Ring scan over [lo, hi] starting from a pseudo-random offset: visits every
    // port in the pool exactly once, returning the first that doesn't conflict.
    // The random start spreads assignments across the range rather than always
    // taking the lowest free port. If every port is taken, the range is full.
    let span = (hi as u32) - (lo as u32) + 1;
    let start_offset = pseudo_random_offset(span);
    for i in 0..span {
        // lo + offset <= hi <= 65535, so the u16 cast never truncates.
        let candidate = (lo as u32 + (start_offset + i) % span) as u16;
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    // Actionable, user-facing: this surfaces as a 400 (CreateRuleError::BadRequest)
    // so the operator knows to widen the group's port range or free a rule —
    // NOT a generic 500 "数据库错误".
    Err(format!(
        "设备组端口范围 {}-{} 已全部占用,请扩大该组端口范围或删除已有规则后重试",
        lo, hi
    ))
}

#[derive(Debug)]
pub enum CreateRuleError {
    BadRequest(String),
    Forbidden(String),
    PortConflict(u16),
    Database(DbError),
}

#[derive(Debug)]
pub enum UpdateRuleError {
    BadRequest(String),
    Forbidden(String),
    NotFound,
    PortConflict,
    Internal(String),
    Database(DbError),
}

async fn user_can_bind_preset_tunnel(
    db: &dyn Repository,
    user_id: i64,
    tunnel: &relay_shared::models::Tunnel,
) -> Result<bool, DbError> {
    if db.is_admin(user_id).await? {
        return Ok(true);
    }
    if !tunnel.shared {
        return Ok(false);
    }
    let Some(entry) = tunnel.hops.first() else {
        return Ok(false);
    };
    Ok(db
        .authorized_device_group_ids(user_id)
        .await?
        .contains(&entry.device_group_id))
}

async fn validate_admin_owned_inbound_group(
    db: &dyn Repository,
    gid: i64,
    context: &str,
) -> Result<(), CreateRuleError> {
    match GroupRepository::find_by_id(db, gid, &ResourceScope::All).await {
        Ok(Some(g)) => {
            let owner_is_admin = match db.is_admin(g.uid).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("{}: group_in is_admin failed: {}", context, e);
                    return Err(CreateRuleError::Database(e));
                }
            };
            if !group_type_supports_inbound(&g.group_type) || !owner_is_admin {
                return Err(CreateRuleError::BadRequest(
                    "device_group_in not found".into(),
                ));
            }
            Ok(())
        }
        Ok(None) => Err(CreateRuleError::BadRequest(
            "device_group_in not found".into(),
        )),
        Err(e) => {
            tracing::error!("{}: group_in find_by_id failed: {}", context, e);
            Err(CreateRuleError::Database(e))
        }
    }
}

#[allow(dead_code)] // retained for possible per-owner out-group checks later
async fn validate_owner_outbound_group(
    db: &dyn Repository,
    gid_out: i64,
    owner_scope: &ResourceScope,
    context: &str,
) -> Result<(), CreateRuleError> {
    match GroupRepository::find_by_id(db, gid_out, owner_scope).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(CreateRuleError::BadRequest(
            "device_group_out does not belong to the rule owner".into(),
        )),
        Err(e) => {
            tracing::error!("{}: group_out find_by_id failed: {}", context, e);
            Err(CreateRuleError::Database(e))
        }
    }
}

/// Validate chain hop group list. Returns normalized (entry, exit, hop ids).
/// - length 2..=8, no duplicates
/// - entry (first) must be admin-owned inbound
/// - every hop after entry must exist, not monitor, non-empty connect_host
async fn validate_chain_hops(
    db: &dyn Repository,
    hop_group_ids: &[i64],
    context: &str,
) -> Result<(), CreateRuleError> {
    if hop_group_ids.len() < CHAIN_HOPS_MIN {
        return Err(CreateRuleError::BadRequest(format!(
            "hops: chain requires at least {} hops (entry + exit)",
            CHAIN_HOPS_MIN
        )));
    }
    if hop_group_ids.len() > CHAIN_HOPS_MAX {
        return Err(CreateRuleError::BadRequest(format!(
            "hops: at most {} hops allowed",
            CHAIN_HOPS_MAX
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for (i, &gid) in hop_group_ids.iter().enumerate() {
        if !seen.insert(gid) {
            return Err(CreateRuleError::BadRequest(format!(
                "hops: duplicate device_group_id {} at position {}",
                gid, i
            )));
        }
        if i == 0 {
            validate_admin_owned_inbound_group(db, gid, context).await?;
            continue;
        }
        match GroupRepository::find_by_id(db, gid, &ResourceScope::All).await {
            Ok(Some(g)) => {
                let owner_is_admin = db.is_admin(g.uid).await.map_err(|e| {
                    tracing::error!("{}: hop owner lookup failed: {}", context, e);
                    CreateRuleError::Database(e)
                })?;
                if !owner_is_admin {
                    return Err(CreateRuleError::BadRequest(format!(
                        "hops[{}]: device group {} is not administrator-managed",
                        i, gid
                    )));
                }
                if g.group_type == "monitor" {
                    return Err(CreateRuleError::BadRequest(format!(
                        "hops[{}]: monitor groups cannot be used as chain hops",
                        i
                    )));
                }
                if g.connect_host.trim().is_empty() {
                    return Err(CreateRuleError::BadRequest(format!(
                        "hops[{}]: group {} must have a non-empty connect_host (previous hop dials it)",
                        i, gid
                    )));
                }
            }
            Ok(None) => {
                return Err(CreateRuleError::BadRequest(format!(
                    "hops[{}]: device group {} not found",
                    i, gid
                )));
            }
            Err(e) => {
                tracing::error!("{}: hop find_by_id failed: {}", context, e);
                return Err(CreateRuleError::Database(e));
            }
        }
    }
    Ok(())
}

/// Allocate listen ports for each hop. Entry uses `entry_listen_port`; later
/// hops auto-assign from that group's free pool.
async fn allocate_chain_hop_ports(
    db: &dyn Repository,
    hop_group_ids: &[i64],
    entry_listen_port: u16,
    protocol: &str,
) -> Result<Vec<(i64, i32)>, CreateRuleError> {
    let mut out = Vec::with_capacity(hop_group_ids.len());
    for (i, &gid) in hop_group_ids.iter().enumerate() {
        let port = if i == 0 {
            entry_listen_port
        } else {
            // The native hop keeps the rule's protocol. UOT uses a separate,
            // persisted TCP tunnel port that node_config claims lazily after
            // all nodes understand config protocol v7. Keeping these
            // allocations separate avoids wasting a TCP port for native UDP
            // and lets tcp_udp carry raw TCP alongside UOT without ambiguity.
            match auto_assign_port(db, gid, protocol).await {
                Ok(p) => p,
                Err(e) => {
                    return Err(CreateRuleError::BadRequest(format!(
                        "hops[{}]: cannot allocate listen port on group {}: {}",
                        i, gid, e
                    )));
                }
            }
        };
        out.push((gid, port as i32));
    }
    Ok(out)
}

pub async fn create_rule(
    db: &dyn Repository,
    caller_user_id: i64,
    caller_admin: bool,
    req: &CreateRuleRequest,
) -> Result<(), CreateRuleError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(CreateRuleError::BadRequest("规则名称不能为空".into()));
    }
    if req.protocol == Protocol::Uot {
        return Err(CreateRuleError::BadRequest(
            "protocol 'uot' is internal-only; create an UDP or TCP+UDP chain instead".into(),
        ));
    }
    // v0.4.10: resolve the rule's owner. An admin may specify owner_uid to
    // create on behalf of another user; a non-admin's owner_uid is IGNORED and
    // the rule is attributed to themselves (defense against forgery).
    let owner_uid = if caller_admin {
        req.owner_uid.unwrap_or(caller_user_id)
    } else {
        caller_user_id
    };

    // If the admin is creating on behalf of another user, validate that user
    // exists and is not banned (a banned/deleted owner can't own new rules).
    if owner_uid != caller_user_id {
        match db.find_banned_by_id(owner_uid).await {
            Ok(Some(false)) => {}
            Ok(Some(true)) => return Err(CreateRuleError::BadRequest("owner is banned".into())),
            Ok(None) => return Err(CreateRuleError::BadRequest("owner does not exist".into())),
            Err(e) => {
                tracing::error!("create_rule: owner find_banned_by_id failed: {}", e);
                return Err(CreateRuleError::Database(e));
            }
        }
    }

    // The scope for validating referenced groups = the FINAL owner.
    let _owner_scope = ResourceScope::Owner(owner_uid);

    if req.tunnel_id.is_some() && req.hops.is_some() {
        return Err(CreateRuleError::BadRequest(
            "tunnel_id and hops are mutually exclusive".into(),
        ));
    }
    if req.forward_mode == "direct" && (req.tunnel_id.is_some() || req.hops.is_some()) {
        return Err(CreateRuleError::BadRequest(
            "direct mode cannot include tunnel_id or hops".into(),
        ));
    }

    // Resolve effective topology: a preset tunnel is persisted as chain but
    // deliberately has no rule-level hop rows.
    let preset_tunnel = if let Some(tunnel_id) = req.tunnel_id {
        let tunnel = db
            .find_tunnel_by_id(tunnel_id)
            .await
            .map_err(CreateRuleError::Database)?
            .ok_or_else(|| CreateRuleError::BadRequest("tunnel_id: no such tunnel".into()))?;
        if !tunnel.enabled {
            return Err(CreateRuleError::BadRequest(
                "tunnel_id: disabled tunnels cannot accept new rules".into(),
            ));
        }
        if !user_can_bind_preset_tunnel(db, owner_uid, &tunnel)
            .await
            .map_err(CreateRuleError::Database)?
        {
            return Err(CreateRuleError::Forbidden(
                "该隧道未共享给您，或您的套餐未授权其入口线路".into(),
            ));
        }
        if tunnel.hops.len() < CHAIN_HOPS_MIN {
            return Err(CreateRuleError::BadRequest(
                "tunnel_id: tunnel path is incomplete".into(),
            ));
        }
        let tunnel_hop_ids: Vec<i64> = tunnel.hops.iter().map(|hop| hop.device_group_id).collect();
        validate_chain_hops(db, &tunnel_hop_ids, "create_rule preset tunnel").await?;
        Some(tunnel)
    } else {
        None
    };

    // Resolve effective topology: chain via route_mode, forward_mode, hops or
    // an administrator-managed preset tunnel.
    let is_chain = matches!(req.route_mode, RouteMode::Chain)
        || req.forward_mode == "chain"
        || req.hops.as_ref().map(|h| !h.is_empty()).unwrap_or(false)
        || preset_tunnel.is_some();

    let (
        effective_device_group_in,
        effective_device_group_out,
        hop_group_ids,
        forward_mode,
        route_str,
    ) = if let Some(tunnel) = &preset_tunnel {
        let entry = tunnel.hops.first().unwrap().device_group_id;
        let exit = tunnel.hops.last().unwrap().device_group_id;
        if req.device_group_in != 0 && req.device_group_in != entry {
            return Err(CreateRuleError::BadRequest(
                "device_group_in must equal the preset tunnel entry group".into(),
            ));
        }
        if req.device_group_out.is_some_and(|value| value != exit) {
            return Err(CreateRuleError::BadRequest(
                "device_group_out must equal the preset tunnel exit group".into(),
            ));
        }
        (
            entry,
            Some(exit),
            Vec::new(),
            "chain".to_string(),
            RouteMode::Chain.to_db_str(),
        )
    } else if is_chain {
        let hops = req.hops.clone().unwrap_or_default();
        if hops.is_empty() {
            return Err(CreateRuleError::BadRequest(
                "hops: required for chain mode (ordered device_group ids, entry first)".into(),
            ));
        }
        validate_chain_hops(db, &hops, "create_rule").await?;
        // Allow device_group_in to be omitted/wrong if hops provided — hops[0] wins.
        let entry = hops[0];
        let exit = *hops.last().unwrap();
        if req.device_group_in != 0 && req.device_group_in != entry {
            // If client sent device_group_in, it must match hops[0].
            return Err(CreateRuleError::BadRequest(
                "device_group_in must equal hops[0] (entry group) for chain rules".into(),
            ));
        }
        (
            entry,
            Some(exit),
            hops,
            "chain".to_string(),
            RouteMode::Chain.to_db_str(),
        )
    } else {
        if !validate_forward_mode(&req.forward_mode) && req.forward_mode != "direct" {
            // Accept default/group legacy by forcing direct.
        }
        if req.forward_mode == "group" {
            return Err(CreateRuleError::BadRequest(
                "forward_mode 'group' is no longer supported; use 'direct' or 'chain'".into(),
            ));
        }
        if req.device_group_out.is_some() {
            return Err(CreateRuleError::BadRequest(
                "device_group_out: only used with chain mode (set via hops); omit for direct"
                    .into(),
            ));
        }
        validate_admin_owned_inbound_group(db, req.device_group_in, "create_rule").await?;
        (
            req.device_group_in,
            None,
            Vec::new(),
            "direct".to_string(),
            RouteMode::Direct.to_db_str(),
        )
    };

    if !is_public_transport_accepted(req.public_transport) {
        return Err(CreateRuleError::BadRequest(
            "public_transport: only 'raw', 'ws' and 'tls_simple' are supported".into(),
        ));
    }

    if let Some(msg) = validate_protocol_transport(
        protocol_to_str(&req.protocol),
        req.public_transport.to_db_str(),
    ) {
        return Err(CreateRuleError::BadRequest(msg.into()));
    }

    let targets = normalize_rule_targets(req.targets.clone(), &req.target_addr, req.target_port)
        .map_err(|msg| CreateRuleError::BadRequest(msg.into()))?;
    let primary_target = &targets[0];

    // v0.4.11 PR1: strong validation for transport/profile binding:
    // - Raw: tunnel_profile_id must be NULL
    // - WS: must bind a ws transport template
    // - TLS Simple: must bind a tls_simple transport template
    let public_transport = &req.public_transport;
    if let Some(pid) = req.tunnel_profile_id {
        if public_transport == &PublicTransport::Raw {
            return Err(CreateRuleError::BadRequest(
                "tunnel_profile_id must be null for Raw transport".into(),
            ));
        }
        match db
            .find_profile_by_id(pid, &ProfileScope::AvailableTemplates)
            .await
        {
            Ok(None) => {
                return Err(CreateRuleError::BadRequest(
                    "tunnel_profile_id: no such profile".into(),
                ));
            }
            Ok(Some(profile)) => {
                let expected_transport = match public_transport {
                    PublicTransport::Ws => "ws",
                    PublicTransport::TlsSimple => "tls_simple",
                    PublicTransport::Raw => {
                        return Err(CreateRuleError::BadRequest(
                            "tunnel_profile_id must be null for Raw transport".into(),
                        ));
                    }
                };
                if profile.transport != expected_transport {
                    return Err(CreateRuleError::BadRequest(format!(
                        "tunnel_profile_id: profile transport '{}' does not match '{}' transport",
                        profile.transport, expected_transport
                    )));
                }
                if let Some(msg) = validate_protocol_transport(
                    protocol_to_str(&req.protocol),
                    profile.transport.as_str(),
                ) {
                    return Err(CreateRuleError::BadRequest(msg.into()));
                }
            }
            Err(e) => {
                tracing::error!("create_rule: find_profile_by_id failed: {}", e);
                return Err(CreateRuleError::Database(e));
            }
        }
    } else {
        if public_transport == &PublicTransport::Ws {
            return Err(CreateRuleError::BadRequest(
                "tunnel_profile_id is required for WebSocket transport".into(),
            ));
        }
        if public_transport == &PublicTransport::TlsSimple {
            return Err(CreateRuleError::BadRequest(
                "tunnel_profile_id is required for TLS Simple transport".into(),
            ));
        }
    }

    let protocol_str = protocol_to_str(&req.protocol);
    let public_str = req.public_transport.to_db_str();
    let node_str = req.public_transport.derive_node_transport().to_db_str();
    // route_str / forward_mode already resolved above for chain vs direct.
    let ws_path: Option<String> = if req.public_transport == PublicTransport::Ws {
        req.ws_path
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    } else {
        None
    };

    let lb_db = req.load_balance_strategy.to_db_str();
    let up_mbps = req.upload_limit_mbps.unwrap_or(0);
    let down_mbps = req.download_limit_mbps.unwrap_or(0);
    let max_connections = req.max_connections.unwrap_or(0);
    let auto_restart_minutes = req.auto_restart_minutes.unwrap_or(0);
    if up_mbps < 0 || down_mbps < 0 || max_connections < 0 || auto_restart_minutes < 0 {
        return Err(CreateRuleError::BadRequest(
            "速率、连接数上限和自动重启间隔不能为负数".into(),
        ));
    }
    if auto_restart_minutes != 0
        && auto_restart_minutes < relay_shared::models::MIN_AUTO_RESTART_MINUTES
    {
        return Err(CreateRuleError::BadRequest(format!(
            "自动重启间隔最小 {} 分钟（0 = 关闭）",
            relay_shared::models::MIN_AUTO_RESTART_MINUTES
        )));
    }

    let mut attempt = 0u32;
    let max_attempts = if req.listen_port.is_some() { 1 } else { 8 };
    let mut last_port: Option<u16> = req.listen_port;
    // v1.2: create_rule_full does the rule INSERT + targets + LB + rate limits
    // + tunnel profile in ONE transaction and returns the new rule's id
    // directly (SQLite last_insert_rowid / PG RETURNING id). This replaces the
    // old insert_quota_guarded-then-list_rules-by-(owner,listen_port)-lookup,
    // which wrote the side-tables to the WRONG rule when two inbound groups
    // reused the same listen_port (the per-group unique index makes that legal
    // but the lookup ignored device_group_in). Atomicity also guarantees a
    // mid-create failure leaves no half-rule.
    let result: Result<Option<i64>, DbError> = loop {
        let port = match last_port {
            Some(p) => p,
            None => match auto_assign_port(db, effective_device_group_in, protocol_str).await {
                Ok(p) => p,
                // A full/unassignable range is a client-fixable condition, not a
                // DB fault — surface the actionable message as a 400, not a
                // generic 500 "数据库错误".
                Err(e) => return Err(CreateRuleError::BadRequest(e)),
            },
        };
        last_port = Some(port);

        // Resolve chain ports before creating the rule, then hand them to the
        // repository so the rule, targets and hops are committed atomically.
        // A range-allocation failure therefore cannot leave a quota-consuming
        // chain rule without hop rows.
        let hop_ports = if hop_group_ids.is_empty() {
            Vec::new()
        } else {
            allocate_chain_hop_ports(db, &hop_group_ids, port, protocol_str).await?
        };

        match db
            .create_rule_full_with_tunnel(
                name,
                owner_uid,
                port as i32,
                protocol_str,
                public_str,
                node_str,
                route_str,
                public_str,
                ws_path.as_deref(),
                effective_device_group_in,
                effective_device_group_out,
                &forward_mode,
                &primary_target.host,
                primary_target.port as i32,
                &targets,
                &hop_ports,
                lb_db,
                up_mbps,
                down_mbps,
                req.tunnel_profile_id,
                req.tunnel_id,
                max_connections,
                auto_restart_minutes,
            )
            .await
        {
            Ok(opt) => break Ok(opt),
            Err(DbError::PortConflict | DbError::UniqueViolation)
                if req.listen_port.is_none() && attempt + 1 < max_attempts =>
            {
                attempt += 1;
                last_port = None;
                tracing::debug!(
                    "create_rule: listen_port {} taken on group {}; retry {}",
                    port,
                    effective_device_group_in,
                    attempt
                );
                continue;
            }
            Err(e) => break Err(e),
        }
    };

    match result {
        Ok(None) => {
            // Quota exhausted: the guarded INSERT matched 0 rows.
            let current_count = db.count_by_uid(owner_uid).await.map_err(|error| {
                tracing::error!(
                    "create_rule: count_by_uid({}) after quota rejection failed: {}",
                    owner_uid,
                    error
                );
                CreateRuleError::Database(error)
            })?;
            let max_rules = db.max_rules_for_uid(owner_uid).await.map_err(|error| {
                tracing::error!(
                    "create_rule: max_rules_for_uid({}) after quota rejection failed: {}",
                    owner_uid,
                    error
                );
                CreateRuleError::Database(error)
            })?;
            Err(CreateRuleError::BadRequest(format!(
                "Rule limit reached: you have {} rules, max is {}",
                current_count, max_rules
            )))
        }
        Ok(Some(_rule_id)) => Ok(()),
        Err(DbError::PortConflict | DbError::UniqueViolation) => {
            Err(CreateRuleError::PortConflict(last_port.unwrap_or(0)))
        }
        Err(DbError::TunnelUnavailable) => Err(CreateRuleError::BadRequest(
            "tunnel_id: tunnel was disabled or its path changed; refresh and retry".into(),
        )),
        Err(DbError::TunnelAccessDenied) => Err(CreateRuleError::Forbidden(
            "该隧道未共享给您，或您的套餐未授权其入口线路".into(),
        )),
        Err(DbError::ProfileUnavailable) => Err(CreateRuleError::BadRequest(
            "tunnel_profile_id: template changed or no longer matches the selected transport"
                .into(),
        )),
        Err(DbError::RuleGroupUnavailable) => Err(CreateRuleError::BadRequest(
            "device_group_in or a downstream hop is no longer available".into(),
        )),
        Err(DbError::RuleGroupAccessDenied) => Err(CreateRuleError::Forbidden(
            "device_group_in 不在规则所有者当前允许的分组列表中".into(),
        )),
        Err(e) => {
            tracing::error!("create_rule: create_rule_full failed: {}", e);
            Err(CreateRuleError::Database(e))
        }
    }
}

fn map_create_rule_validation_error(err: CreateRuleError) -> UpdateRuleError {
    match err {
        CreateRuleError::BadRequest(msg) => UpdateRuleError::BadRequest(msg),
        CreateRuleError::Forbidden(msg) => UpdateRuleError::Forbidden(msg),
        CreateRuleError::PortConflict(_) => UpdateRuleError::PortConflict,
        CreateRuleError::Database(e) => UpdateRuleError::Database(e),
    }
}

pub async fn update_rule(
    db: &dyn Repository,
    id: i64,
    scope: &ResourceScope,
    req: &UpdateRuleRequest,
) -> Result<(), UpdateRuleError> {
    if matches!(req.protocol, Some(Protocol::Uot)) {
        return Err(UpdateRuleError::BadRequest(
            "protocol 'uot' is internal-only; use an UDP or TCP+UDP chain".into(),
        ));
    }
    if let Some(ref mode) = req.forward_mode {
        if mode == "group" {
            return Err(UpdateRuleError::BadRequest(
                "forward_mode 'group' is no longer supported; use 'direct' or 'chain'".into(),
            ));
        }
        if !validate_forward_mode(mode) {
            return Err(UpdateRuleError::BadRequest(
                "forward_mode: only 'direct' or 'chain' is supported".into(),
            ));
        }
    }

    if let Some(ref transport) = req.public_transport {
        if !is_public_transport_accepted(*transport) {
            return Err(UpdateRuleError::BadRequest(
                "public_transport: only 'raw', 'ws' and 'tls_simple' are supported".into(),
            ));
        }
    }

    // Load the existing rule once and reuse it for stored protocol/profile/owner.
    let existing = match db.find_rule_by_id(id, scope).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(UpdateRuleError::NotFound),
        Err(e) => {
            tracing::error!("update_rule {}: find_rule_by_id failed: {}", id, e);
            return Err(UpdateRuleError::Database(e));
        }
    };
    let name = match req.name.as_deref() {
        Some(name) => {
            let name = name.trim();
            if name.is_empty() {
                return Err(UpdateRuleError::BadRequest("规则名称不能为空".into()));
            }
            Some(name.to_owned())
        }
        None => None,
    };
    let _owner_scope = ResourceScope::Owner(existing.uid);

    // A pure pause is always a safe operation.  Do it before validating the
    // currently stored route/profile so operators can stop legacy rows that
    // have become invalid.  Resume and every other edit still take the normal
    // validation path below.
    let pause_only = req.paused == Some(true)
        && req.name.is_none()
        && req.listen_port.is_none()
        && req.protocol.is_none()
        && req.device_group_in.is_none()
        && req.device_group_out.is_none()
        && req.forward_mode.is_none()
        && req.route_mode.is_none()
        && req.hops.is_none()
        && req.tunnel_id.is_none()
        && req.public_transport.is_none()
        && req.ws_path.is_none()
        && req.target_addr.is_none()
        && req.target_port.is_none()
        && req.targets.is_none()
        && req.load_balance_strategy.is_none()
        && req.upload_limit_mbps.is_none()
        && req.download_limit_mbps.is_none()
        && req.tunnel_profile_id.is_none()
        && req.max_connections.is_none()
        && req.auto_restart_minutes.is_none();
    if pause_only {
        let update = RuleUpdateData {
            id,
            owner_uid: scope.owner_id(),
            effective_device_group_in: existing.device_group_in,
            paused: Some(true),
            ..Default::default()
        };
        return match db.update_rule_full(&update).await {
            Ok(0) => Err(UpdateRuleError::NotFound),
            Ok(_) => Ok(()),
            Err(error) => {
                tracing::error!("update_rule {}: pause failed: {}", id, error);
                Err(UpdateRuleError::Database(error))
            }
        };
    }

    if req.hops.is_some()
        && (matches!(req.tunnel_id, Some(Some(_)))
            || (req.tunnel_id.is_none() && existing.tunnel_id.is_some()))
    {
        return Err(UpdateRuleError::BadRequest(
            "hops cannot be submitted while a preset tunnel remains bound; set tunnel_id to null to switch to a custom chain"
                .into(),
        ));
    }

    // `route_mode` and the legacy `forward_mode` describe the same topology.
    // Reject contradictions rather than silently giving one field precedence.
    let route_requests_chain = matches!(req.route_mode, Some(RouteMode::Chain));
    let route_requests_direct = matches!(req.route_mode, Some(RouteMode::Direct));
    let forward_requests_chain = req.forward_mode.as_deref() == Some("chain");
    let forward_requests_direct = req.forward_mode.as_deref() == Some("direct");
    if (route_requests_chain && forward_requests_direct)
        || (route_requests_direct && forward_requests_chain)
    {
        return Err(UpdateRuleError::BadRequest(
            "route_mode and forward_mode describe conflicting topologies".into(),
        ));
    }

    let explicitly_chain = route_requests_chain || forward_requests_chain;
    let explicitly_direct = route_requests_direct || forward_requests_direct;
    if req.hops.is_some() && explicitly_direct {
        return Err(UpdateRuleError::BadRequest(
            "hops are only valid for chain mode".into(),
        ));
    }

    let becoming_direct = explicitly_direct;
    if becoming_direct && matches!(req.tunnel_id, Some(Some(_))) {
        return Err(UpdateRuleError::BadRequest(
            "direct mode cannot bind a preset tunnel".into(),
        ));
    }
    let effective_tunnel_id = if becoming_direct {
        None
    } else {
        req.tunnel_id.unwrap_or(existing.tunnel_id)
    };
    let preset_tunnel = if let Some(tunnel_id) = effective_tunnel_id {
        let tunnel = db
            .find_tunnel_by_id(tunnel_id)
            .await
            .map_err(UpdateRuleError::Database)?
            .ok_or_else(|| UpdateRuleError::BadRequest("tunnel_id: no such tunnel".into()))?;
        let newly_binding = existing.tunnel_id != Some(tunnel_id);
        if newly_binding && !tunnel.enabled {
            return Err(UpdateRuleError::BadRequest(
                "tunnel_id: disabled tunnels cannot accept new rules".into(),
            ));
        }
        if (newly_binding || req.paused == Some(false))
            && !user_can_bind_preset_tunnel(db, existing.uid, &tunnel)
                .await
                .map_err(UpdateRuleError::Database)?
        {
            return Err(UpdateRuleError::Forbidden(
                "该隧道未共享给您，或您的套餐未授权其入口线路".into(),
            ));
        }
        if tunnel.hops.len() < CHAIN_HOPS_MIN {
            return Err(UpdateRuleError::BadRequest(
                "tunnel_id: tunnel path is incomplete".into(),
            ));
        }
        let tunnel_hop_ids: Vec<i64> = tunnel.hops.iter().map(|hop| hop.device_group_id).collect();
        validate_chain_hops(db, &tunnel_hop_ids, "update_rule preset tunnel")
            .await
            .map_err(map_create_rule_validation_error)?;
        Some(tunnel)
    } else {
        None
    };
    if preset_tunnel.is_some() && explicitly_direct {
        return Err(UpdateRuleError::BadRequest(
            "preset tunnels require chain mode".into(),
        ));
    }

    let becoming_chain = preset_tunnel.is_some()
        || explicitly_chain
        || req.hops.is_some()
        || (!becoming_direct && existing.route_mode == "chain");

    if existing.tunnel_id.is_some()
        && matches!(req.tunnel_id, Some(None))
        && !becoming_direct
        && req.hops.is_none()
    {
        return Err(UpdateRuleError::BadRequest(
            "unbind a preset tunnel by switching to direct mode or providing custom hops".into(),
        ));
    }

    // device_group_out is derived from hops in chain mode — never set raw on
    // direct rules (would hit FK or silently change topology).
    if req.device_group_out.is_some()
        && req.hops.is_none()
        && preset_tunnel.is_none()
        && !becoming_chain
    {
        return Err(UpdateRuleError::BadRequest(
            "device_group_out: only used with chain mode (set via hops); omit for direct".into(),
        ));
    }

    if becoming_chain && !becoming_direct && preset_tunnel.is_none() {
        if let Some(ref hops) = req.hops {
            validate_chain_hops(db, hops, "update_rule")
                .await
                .map_err(map_create_rule_validation_error)?;
        } else if existing.route_mode != "chain" {
            return Err(UpdateRuleError::BadRequest(
                "hops: required when switching a rule to chain mode".into(),
            ));
        }
    }

    if let Some(tunnel) = &preset_tunnel {
        let entry = tunnel.hops.first().unwrap().device_group_id;
        let exit = tunnel.hops.last().unwrap().device_group_id;
        if req.device_group_in.is_some_and(|value| value != entry) {
            return Err(UpdateRuleError::BadRequest(
                "device_group_in must equal the preset tunnel entry group".into(),
            ));
        }
        if req.device_group_out.is_some_and(|value| value != exit) {
            return Err(UpdateRuleError::BadRequest(
                "device_group_out must equal the preset tunnel exit group".into(),
            ));
        }
    }

    if let Some(gid_in) = req.device_group_in {
        validate_admin_owned_inbound_group(db, gid_in, "update_rule")
            .await
            .map_err(map_create_rule_validation_error)?;
    }

    // Effective protocol×transport cross-check.
    let stored: Option<(String, String)> = match db.find_transport_by_id(id, scope).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("update_rule {}: find_transport_by_id failed: {}", id, e);
            return Err(UpdateRuleError::Database(e));
        }
    };
    let effective_protocol = req
        .protocol
        .as_ref()
        .map(protocol_to_str)
        .map(str::to_string)
        .or_else(|| stored.as_ref().map(|(p, _)| p.clone()));
    let effective_transport = req
        .public_transport
        .map(|t| t.to_db_str().to_string())
        .or_else(|| stored.as_ref().map(|(_, t)| t.clone()));
    if let (Some(proto), Some(transport)) = (effective_protocol, effective_transport) {
        if let Some(msg) = validate_protocol_transport(&proto, &transport) {
            return Err(UpdateRuleError::BadRequest(msg.into()));
        }
    }

    let switching_to_direct = becoming_direct;
    let device_group_out_arg: Option<Option<i64>> = if switching_to_direct {
        Some(None)
    } else if let Some(tunnel) = &preset_tunnel {
        Some(Some(tunnel.hops.last().unwrap().device_group_id))
    } else if let Some(ref hops) = req.hops {
        hops.last().copied().map(Some)
    } else {
        req.device_group_out.map(Some)
    };

    // When hops are provided, entry group comes from hops[0].
    let device_group_in_arg: Option<i64> = if let Some(tunnel) = &preset_tunnel {
        Some(tunnel.hops.first().unwrap().device_group_id)
    } else if let Some(ref hops) = req.hops {
        hops.first().copied()
    } else {
        req.device_group_in
    };

    let route_mode_arg: Option<&str> = if becoming_chain && !switching_to_direct {
        Some(RouteMode::Chain.to_db_str())
    } else if switching_to_direct {
        Some(RouteMode::Direct.to_db_str())
    } else {
        req.route_mode.as_ref().map(|r| r.to_db_str())
    };
    let forward_mode_arg: Option<&str> = if becoming_chain && !switching_to_direct {
        Some("chain")
    } else if switching_to_direct {
        Some("direct")
    } else {
        req.forward_mode.as_deref()
    };

    let has_field = req.name.is_some()
        || req.listen_port.is_some()
        || req.protocol.is_some()
        || req.public_transport.is_some()
        || req.route_mode.is_some()
        || req.ws_path.is_some()
        || req.device_group_in.is_some()
        || req.device_group_out.is_some()
        || req.forward_mode.is_some()
        || req.hops.is_some()
        || req.target_addr.is_some()
        || req.target_port.is_some()
        || req.targets.is_some()
        || req.load_balance_strategy.is_some()
        || req.upload_limit_mbps.is_some()
        || req.download_limit_mbps.is_some()
        // v1.2.0: these are written by set_rule_connection_controls, not by the
        // main UPDATE, so they belong in has_field but NOT in has_scalar_field
        // (same category as the rate limits and targets above).
        || req.max_connections.is_some()
        || req.auto_restart_minutes.is_some()
        || req.tunnel_profile_id.is_some()
        || req.tunnel_id.is_some()
        || req.paused.is_some();
    if !has_field {
        return Err(UpdateRuleError::BadRequest("No fields to update".into()));
    }

    // Prefer an explicit `targets` list. If the client only updates the legacy
    // target_addr/target_port pair, ALSO rewrite the targets table — otherwise
    // node_config's resolve_final_targets keeps serving the stale multi-target
    // rows and the scalar columns change is a silent no-op for forwarding.
    let normalized_targets = if let Some(targets) = req.targets.clone() {
        let legacy_host = req
            .target_addr
            .as_deref()
            .unwrap_or(existing.target_addr.as_str());
        let legacy_port = req.target_port.unwrap_or(existing.target_port as u16);
        Some(
            normalize_rule_targets(Some(targets), legacy_host, legacy_port)
                .map_err(|msg| UpdateRuleError::BadRequest(msg.into()))?,
        )
    } else if req.target_addr.is_some() || req.target_port.is_some() {
        let host = req
            .target_addr
            .as_deref()
            .unwrap_or(existing.target_addr.as_str());
        let port = req.target_port.unwrap_or(existing.target_port as u16);
        Some(
            normalize_rule_targets(None, host, port)
                .map_err(|msg| UpdateRuleError::BadRequest(msg.into()))?,
        )
    } else {
        None
    };

    let existing_transport = match existing.public_transport.as_str() {
        "raw" => PublicTransport::Raw,
        "ws" => PublicTransport::Ws,
        "tls_simple" => PublicTransport::TlsSimple,
        _ => {
            tracing::error!(
                "update_rule {}: unknown existing public_transport '{}'",
                id,
                existing.public_transport
            );
            return Err(UpdateRuleError::Internal(
                "internal error: unknown transport".into(),
            ));
        }
    };
    let effective_transport = req
        .public_transport
        .as_ref()
        .copied()
        .unwrap_or(existing_transport);
    let effective_pid = match req.tunnel_profile_id {
        Some(pid_opt) => pid_opt,
        None => existing.tunnel_profile_id,
    };

    match (effective_transport, effective_pid) {
        (PublicTransport::Raw, Some(_)) => {
            return Err(UpdateRuleError::BadRequest(
                "tunnel_profile_id must be null for Raw transport".into(),
            ));
        }
        (PublicTransport::Ws, None) | (PublicTransport::TlsSimple, None) => {
            let transport_name = match effective_transport {
                PublicTransport::Ws => "WebSocket",
                PublicTransport::TlsSimple => "TLS Simple",
                PublicTransport::Raw => unreachable!(),
            };
            return Err(UpdateRuleError::BadRequest(format!(
                "tunnel_profile_id is required for {} transport",
                transport_name
            )));
        }
        (PublicTransport::Ws | PublicTransport::TlsSimple, Some(pid)) => {
            let expected_transport = match effective_transport {
                PublicTransport::Ws => "ws",
                PublicTransport::TlsSimple => "tls_simple",
                PublicTransport::Raw => unreachable!(),
            };
            match db
                .find_profile_by_id(pid, &ProfileScope::AvailableTemplates)
                .await
            {
                Ok(None) => {
                    return Err(UpdateRuleError::BadRequest(
                        "tunnel_profile_id: no such profile".into(),
                    ));
                }
                Ok(Some(profile)) => {
                    if profile.transport != expected_transport {
                        return Err(UpdateRuleError::BadRequest(format!(
                            "tunnel_profile_id: profile transport '{}' does not match '{}' transport",
                            profile.transport, expected_transport
                        )));
                    }
                    let proto_to_check = match req.protocol.as_ref() {
                        Some(p) => protocol_to_str(p),
                        None => existing.protocol.as_str(),
                    };
                    if let Some(msg) =
                        validate_protocol_transport(proto_to_check, profile.transport.as_str())
                    {
                        return Err(UpdateRuleError::BadRequest(msg.into()));
                    }
                }
                Err(e) => {
                    tracing::error!("update_rule {}: find_profile_by_id failed: {}", id, e);
                    return Err(UpdateRuleError::Database(e));
                }
            }
        }
        (PublicTransport::Raw, None) => {}
    }

    if let Some(new_proto) = req.protocol.as_ref() {
        let effective_pid = match req.tunnel_profile_id {
            Some(pid_opt) => pid_opt,
            None => existing.tunnel_profile_id,
        };
        if let Some(pid) = effective_pid {
            match db.find_profile_by_id(pid, &ProfileScope::All).await {
                Ok(Some(profile)) => {
                    if validate_protocol_transport(
                        protocol_to_str(new_proto),
                        profile.transport.as_str(),
                    )
                    .is_some()
                    {
                        return Err(UpdateRuleError::BadRequest(
                            "the existing tunnel profile is incompatible with the requested protocol"
                                .into(),
                        ));
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("update_rule {}: find_profile_by_id failed: {}", id, e);
                    return Err(UpdateRuleError::Database(e));
                }
            }
        }
    }

    let (public, node, entry) = match req.public_transport {
        Some(v) => {
            let p = v.to_db_str();
            let n = v.derive_node_transport().to_db_str();
            (Some(p), Some(n), Some(p))
        }
        None => (None, None, None),
    };
    let ws_path: Option<Option<&str>> = req.ws_path.as_ref().map(|v| {
        v.as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s as &str)
    });

    // Plan chain placement BEFORE writing scalar rule fields. Port allocation
    // can fail for a full group range; doing it first prevents a half-applied
    // topology where route_mode/group ids changed but the old hop rows remain.
    // Existing chain clients may omit `hops` when the group order is unchanged;
    // protocol and entry-port changes must still rewrite the hop rows. In
    // particular, a TCP->UDP change cannot safely reuse a numeric hop port that
    // may already be occupied by an unrelated UDP listener in the same group.
    let protocol_str = req
        .protocol
        .as_ref()
        .map(protocol_to_str)
        .unwrap_or(existing.protocol.as_str());
    let protocol_unchanged = req
        .protocol
        .as_ref()
        .is_none_or(|p| protocol_to_str(p) == existing.protocol);
    let needs_existing_chain_replan =
        existing.route_mode == "chain" && (!protocol_unchanged || req.listen_port.is_some());
    let existing_hops = if req.hops.is_some() || needs_existing_chain_replan {
        db.list_rule_hops(id)
            .await
            .map_err(UpdateRuleError::Database)?
    } else {
        Vec::new()
    };
    let hop_gids_to_plan = req.hops.clone().or_else(|| {
        needs_existing_chain_replan.then(|| {
            existing_hops
                .iter()
                .map(|hop| hop.device_group_id)
                .collect()
        })
    });
    let planned_hop_ports: Option<Vec<(i64, i32)>> =
        if switching_to_direct || preset_tunnel.is_some() {
            Some(Vec::new())
        } else if let Some(ref hop_gids) = hop_gids_to_plan {
            let entry_port = req.listen_port.unwrap_or(existing.listen_port as u16);
            let mut planned = Vec::with_capacity(hop_gids.len());
            for (position, gid) in hop_gids.iter().copied().enumerate() {
                let port = if position == 0 {
                    entry_port
                } else if protocol_unchanged {
                    let suffix_unchanged = existing_hops.len() == hop_gids.len()
                        && existing_hops[position..]
                            .iter()
                            .map(|hop| hop.device_group_id)
                            .eq(hop_gids[position..].iter().copied());
                    let incoming_unchanged = existing_hops
                        .get(position - 1)
                        .is_some_and(|old| old.device_group_id == hop_gids[position - 1]);
                    if suffix_unchanged
                        && incoming_unchanged
                        && existing_hops
                            .get(position)
                            .is_some_and(|old| old.device_group_id == gid)
                    {
                        existing_hops[position].listen_port as u16
                    } else {
                        allocate_chain_hop_ports(db, &[hop_gids[0], gid], entry_port, protocol_str)
                            .await
                            .map_err(map_create_rule_validation_error)?[1]
                            .1 as u16
                    }
                } else {
                    allocate_chain_hop_ports(db, &[hop_gids[0], gid], entry_port, protocol_str)
                        .await
                        .map_err(map_create_rule_validation_error)?[1]
                        .1 as u16
                };
                planned.push((gid, port as i32));
            }
            Some(planned)
        } else {
            None
        };

    let rate_limits = if req.upload_limit_mbps.is_some() || req.download_limit_mbps.is_some() {
        let upload_limit_mbps = req.upload_limit_mbps.unwrap_or(existing.upload_limit_mbps);
        let download_limit_mbps = req
            .download_limit_mbps
            .unwrap_or(existing.download_limit_mbps);
        if upload_limit_mbps < 0 || download_limit_mbps < 0 {
            return Err(UpdateRuleError::BadRequest(
                "上传和下载速率不能为负数".into(),
            ));
        }
        Some((upload_limit_mbps, download_limit_mbps))
    } else {
        None
    };

    // Resolve and validate connection controls before opening the repository
    // transaction.  Falling back to the already-loaded row preserves omitted
    // counterparts without a second post-update read.
    let connection_controls = if req.max_connections.is_some() || req.auto_restart_minutes.is_some()
    {
        let max_connections = req.max_connections.unwrap_or(existing.max_connections);
        let auto_restart_minutes = req
            .auto_restart_minutes
            .unwrap_or(existing.auto_restart_minutes);
        if max_connections < 0 || auto_restart_minutes < 0 {
            return Err(UpdateRuleError::BadRequest(
                "连接数上限和自动重启间隔不能为负数".into(),
            ));
        }
        if auto_restart_minutes != 0
            && auto_restart_minutes < relay_shared::models::MIN_AUTO_RESTART_MINUTES
        {
            return Err(UpdateRuleError::BadRequest(format!(
                "自动重启间隔最小 {} 分钟（0 = 关闭）",
                relay_shared::models::MIN_AUTO_RESTART_MINUTES
            )));
        }
        Some((max_connections, auto_restart_minutes))
    } else {
        None
    };

    let update = RuleUpdateData {
        id,
        owner_uid: scope.owner_id(),
        effective_device_group_in: device_group_in_arg.unwrap_or(existing.device_group_in),
        name,
        listen_port: req.listen_port.map(|port| port as i32),
        protocol: req
            .protocol
            .as_ref()
            .map(protocol_to_str)
            .map(str::to_owned),
        public_transport: public.map(str::to_owned),
        node_transport: node.map(str::to_owned),
        entry_transport: entry.map(str::to_owned),
        route_mode: route_mode_arg.map(str::to_owned),
        ws_path: ws_path.map(|value| value.map(str::to_owned)),
        device_group_in: device_group_in_arg,
        device_group_out: device_group_out_arg,
        forward_mode: forward_mode_arg.map(str::to_owned),
        target_addr: req.target_addr.clone(),
        target_port: req.target_port.map(|port| port as i32),
        paused: req.paused,
        targets: normalized_targets,
        hops: planned_hop_ports,
        load_balance_strategy: req
            .load_balance_strategy
            .map(|strategy| strategy.to_db_str().to_owned()),
        rate_limits,
        connection_controls,
        tunnel_profile_id: req.tunnel_profile_id,
        tunnel_id: if switching_to_direct {
            Some(None)
        } else {
            req.tunnel_id
        },
    };

    match db.update_rule_full(&update).await {
        Ok(0) => Err(UpdateRuleError::NotFound),
        Ok(_) => Ok(()),
        Err(DbError::UniqueViolation | DbError::PortConflict) => Err(UpdateRuleError::PortConflict),
        Err(DbError::TunnelUnavailable) => Err(UpdateRuleError::BadRequest(
            "tunnel_id: tunnel was disabled or its path changed; refresh and retry".into(),
        )),
        Err(DbError::TunnelAccessDenied) => Err(UpdateRuleError::Forbidden(
            "该隧道未共享给您，或您的套餐未授权其入口线路".into(),
        )),
        Err(DbError::ProfileUnavailable) => Err(UpdateRuleError::BadRequest(
            "tunnel_profile_id: template changed or no longer matches the selected transport"
                .into(),
        )),
        Err(DbError::RuleGroupUnavailable) => Err(UpdateRuleError::BadRequest(
            "device_group_in or a downstream hop is no longer available".into(),
        )),
        Err(DbError::RuleGroupAccessDenied) => Err(UpdateRuleError::Forbidden(
            "device_group_in 不在规则所有者当前允许的分组列表中".into(),
        )),
        Err(e) => {
            tracing::error!("update_rule {}: update_rule_fields failed: {}", id, e);
            Err(UpdateRuleError::Database(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_group_type_maps_and_supports_inbound() {
        assert_eq!(group_type_to_str(&GroupType::Both), "both");
        assert!(group_type_supports_inbound("both"));
        assert!(group_type_supports_inbound("in"));
        assert!(!group_type_supports_inbound("out"));
        assert!(!group_type_supports_inbound("monitor"));
    }

    /// The valid combinations must all pass (return None). These are the ones
    /// the UI and the node actually support in v0.3.0-alpha.
    #[test]
    fn valid_combinations_pass() {
        // The overwhelmingly common case: raw TCP.
        assert!(validate_protocol_transport("tcp", "raw").is_none());
        // raw UDP — the only valid UDP combination.
        assert!(validate_protocol_transport("udp", "raw").is_none());
        // raw TCP+UDP — both listeners, raw transport.
        assert!(validate_protocol_transport("tcp_udp", "raw").is_none());
        // v0.3.0-alpha headline: WS over TCP.
        assert!(validate_protocol_transport("tcp", "ws").is_none());
    }

    /// UDP / TCP+UDP over WS must be rejected (WS carries TCP only in alpha).
    /// This is the constraint the frontend enforces by disabling the protocol
    /// picker — the API must reject it independently for direct/import callers.
    #[test]
    fn ws_rejects_udp_and_tcp_udp() {
        assert!(validate_protocol_transport("udp", "ws").is_some());
        assert!(validate_protocol_transport("tcp_udp", "ws").is_some());
        // And the error message mentions TCP-only so the caller knows why.
        let msg = validate_protocol_transport("udp", "ws").unwrap();
        assert!(
            msg.contains("TCP forwarding only"),
            "error should explain TCP-only: got {:?}",
            msg
        );
    }

    /// UDP-bearing protocols (udp OR tcp_udp) are rejected for ANY non-raw
    /// transport, not just ws. tls_simple would also be caught here (though
    /// that transport is rejected earlier by is_public_transport_accepted).
    #[test]
    fn udp_bearing_requires_raw_transport() {
        // tcp_udp includes a UDP listener → same rule as pure udp.
        assert!(validate_protocol_transport("tcp_udp", "ws").is_some());
        assert!(validate_protocol_transport("tcp_udp", "tls").is_some());
        assert!(validate_protocol_transport("udp", "wss").is_some());
        // But tcp_udp + raw is fine (both listeners, raw ingress).
        assert!(validate_protocol_transport("tcp_udp", "raw").is_none());
    }

    /// WS over TCP is the ONLY valid ws combination. Make sure the boundary is
    /// exactly at protocol=tcp — anything else is rejected, tcp passes.
    #[test]
    fn ws_accepts_only_tcp() {
        assert!(validate_protocol_transport("tcp", "ws").is_none());
        // Every other protocol string with ws is rejected.
        for proto in ["udp", "tcp_udp", "quic", ""] {
            assert!(
                validate_protocol_transport(proto, "ws").is_some(),
                "ws + {:?} should be rejected",
                proto,
            );
        }
    }

    /// Target normalization: a missing targets list falls back to the legacy
    /// host:port; an empty list is rejected; >32 is rejected; all-disabled is
    /// rejected; a bad host is rejected.
    #[test]
    fn target_normalization_rules() {
        // Fallback to legacy single target.
        let out = normalize_rule_targets(None, "1.2.3.4", 80).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].host, "1.2.3.4");
        assert_eq!(out[0].port, 80);

        // Empty explicit list → rejected.
        assert!(normalize_rule_targets(Some(vec![]), "1.2.3.4", 80).is_err());

        // >32 targets → rejected.
        let many: Vec<RuleTargetRequest> = (0..33)
            .map(|_| RuleTargetRequest {
                host: "1.2.3.4".into(),
                port: 80,
                enabled: true,
                weight: 1,
            })
            .collect();
        assert!(normalize_rule_targets(Some(many), "x", 1).is_err());

        // All-disabled → rejected.
        let disabled = vec![RuleTargetRequest {
            host: "1.2.3.4".into(),
            port: 80,
            enabled: false,
            weight: 1,
        }];
        assert!(normalize_rule_targets(Some(disabled), "x", 1).is_err());

        // Bad host (has scheme) → rejected.
        let bad = vec![RuleTargetRequest {
            host: "http://x".into(),
            port: 80,
            enabled: true,
            weight: 1,
        }];
        assert!(normalize_rule_targets(Some(bad), "x", 1).is_err());
    }

    #[test]
    fn target_host_validation_accepts_addresses_and_rejects_punctuation() {
        for valid in [
            "example.com",
            "example.com.",
            "localhost",
            "service_name",
            "192.0.2.1",
            "2001:db8::1",
            "[2001:db8::1]",
        ] {
            assert!(is_plausible_target_host(valid), "{valid} should be valid");
        }

        for invalid in [
            "",
            ":",
            "...",
            "-",
            "_",
            "a..example",
            "-example.com",
            "example-.com",
            "example.com:443",
            "[192.0.2.1]",
            "[not-an-ip]",
        ] {
            assert!(
                !is_plausible_target_host(invalid),
                "{invalid} should be invalid"
            );
        }
    }

    /// v1.2.x: the unset / "全可转发" sentinel and any garbage fall back to the
    /// default 10000-65535 pool, so a never-customized group never auto-assigns
    /// a system port.
    #[test]
    fn resolve_auto_port_range_sentinel_and_default() {
        let def = (DEFAULT_AUTO_PORT_LO, DEFAULT_AUTO_PORT_HI);
        assert_eq!(resolve_auto_port_range("1-65535"), def, "全可转发 sentinel");
        assert_eq!(resolve_auto_port_range(""), def, "empty");
        assert_eq!(resolve_auto_port_range("   "), def, "whitespace");
        assert_eq!(resolve_auto_port_range("garbage"), def, "no dash");
        assert_eq!(resolve_auto_port_range("10000"), def, "single number");
        assert_eq!(resolve_auto_port_range("abc-def"), def, "non-numeric");
        assert_eq!(resolve_auto_port_range("65000-100"), def, "start > end");
        assert_eq!(resolve_auto_port_range("0-100"), def, "start < 1");
        assert_eq!(resolve_auto_port_range("1-70000"), def, "end > 65535");
    }

    /// An explicit narrowing is honored verbatim — including sub-10000 ports the
    /// admin deliberately opted into, and including exact-boundary narrowings
    /// that are NOT the `1-65535` sentinel.
    #[test]
    fn resolve_auto_port_range_explicit_is_honored() {
        assert_eq!(resolve_auto_port_range("65000-65100"), (65000, 65100));
        // "5000-65535" is an explicit choice → really hands out 5000-9999.
        assert_eq!(resolve_auto_port_range("5000-65535"), (5000, 65535));
        // A one-off narrowing of either bound is NOT the sentinel.
        assert_eq!(resolve_auto_port_range("2-65535"), (2, 65535));
        assert_eq!(resolve_auto_port_range("1-65534"), (1, 65534));
        // Single-port pool.
        assert_eq!(resolve_auto_port_range("40000-40000"), (40000, 40000));
        // Surrounding whitespace is trimmed on both the whole string and parts.
        assert_eq!(resolve_auto_port_range("  5000 - 6000  "), (5000, 6000));
    }

    /// The ring-scan offset is always inside the pool span, so `lo + offset`
    /// can never exceed `hi` (guards the u16 cast in auto_assign_port).
    #[test]
    fn pseudo_random_offset_within_span() {
        for span in [1u32, 2, 101, 55536, 65535] {
            let off = pseudo_random_offset(span);
            assert!(off < span, "offset {} must be < span {}", off, span);
        }
    }
}
