use serde::{Deserialize, Serialize};

/// Protocols that an inbound device group may reject before dialing the
/// configured target. The wire/storage vocabulary is deliberately extensible;
/// v1 exposes only TLS ClientHello detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockedProtocol {
    Tls,
}

pub fn normalize_blocked_protocols(protocols: &[BlockedProtocol]) -> Vec<BlockedProtocol> {
    let mut protocols = protocols.to_vec();
    protocols.sort_unstable();
    protocols.dedup();
    protocols
}

pub fn encode_blocked_protocols(protocols: &[BlockedProtocol]) -> String {
    serde_json::to_string(&normalize_blocked_protocols(protocols))
        .expect("BlockedProtocol is always JSON serializable")
}

pub fn decode_blocked_protocols(value: &str) -> Vec<BlockedProtocol> {
    serde_json::from_str::<Vec<BlockedProtocol>>(value)
        .map(|protocols| normalize_blocked_protocols(&protocols))
        .unwrap_or_default()
}

fn empty_json_array() -> String {
    "[]".to_string()
}

fn serialize_blocked_protocols<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    decode_blocked_protocols(value).serialize(serializer)
}

fn deserialize_blocked_protocols<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let protocols = Vec::<BlockedProtocol>::deserialize(deserializer)?;
    Ok(encode_blocked_protocols(&protocols))
}

fn default_load_balance_strategy() -> String {
    "first".to_string()
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub balance: String,
    pub plan_id: Option<i64>,
    /// v1.0.7: replaces the old `group_id` permission-group link. When true the
    /// user may use ALL device groups (admins are always treated as true). When
    /// false the user is limited to the device groups in `user_device_groups`;
    /// none assigned = cannot forward.
    #[serde(default)]
    pub all_device_groups: bool,
    pub max_rules: i32,
    pub speed_limit: i32,
    pub ip_limit: i32,
    pub traffic_used: i64,
    pub traffic_limit: i64,
    pub admin: bool,
    pub banned: bool,
    pub created_at: String,
    /// v0.4.10 PR4: force a password change on next login (admin reset).
    #[serde(default)]
    pub must_change_password: bool,
    /// v0.4.10 PR4: JWT session-version counter. Bumped on password change /
    /// admin reset / ban to instantly revoke previously-issued tokens.
    #[serde(default)]
    pub token_version: i64,
    /// v1.0.8: plan expiry (TEXT 'YYYY-MM-DD HH:MM:SS' UTC, NULL = no expiry).
    #[serde(default)]
    pub plan_expire_at: Option<String>,
    /// v1.0.8: admin suspension. true = forwarding gated off via
    /// list_active_for_config (login still allowed; no token_version bump).
    /// Admins can never be suspended.
    #[serde(default)]
    pub suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ForwardRuleTarget {
    pub id: i64,
    pub rule_id: i64,
    pub host: String,
    pub port: i32,
    pub position: i32,
    pub enabled: bool,
    #[serde(default = "default_target_weight_i32")]
    pub weight: i32,
    pub created_at: String,
}

fn default_target_weight_i32() -> i32 {
    1
}

/// One hop in a multi-hop chain rule (entry=position 0, exit=last).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ForwardRuleHop {
    pub id: i64,
    pub rule_id: i64,
    pub position: i32,
    pub device_group_id: i64,
    pub listen_port: i32,
    /// Dedicated authenticated inter-node tunnel port. `None` on pre-v7 rows;
    /// the panel claims one lazily before enabling UOT so tcp_udp chains never
    /// have to share their raw TCP socket with the UDP tunnel.
    #[serde(default)]
    pub tunnel_port: Option<i32>,
    pub created_at: String,
    /// Display-only: filled when listing rules, not stored on the hop row.
    #[serde(default)]
    #[sqlx(skip)]
    pub group_name: Option<String>,
    /// Display-only: next-hop dial address of this group.
    #[serde(default)]
    #[sqlx(skip)]
    pub connect_host: Option<String>,
}

/// An administrator-managed reusable route.  Unlike `TunnelProfile` (the
/// historical WS/TLS transport template), this owns an ordered device-group
/// path and one shared TCP listener on every non-entry hop.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tunnel {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    /// Whether ordinary users may bind this tunnel. This deliberately reuses
    /// the existing entry-group authorization model: shared is necessary but
    /// not sufficient; the rule owner must also be allowed to use hop 0.
    pub shared: bool,
    pub uid: i64,
    pub created_at: String,
    #[serde(default)]
    #[sqlx(skip)]
    pub hops: Vec<TunnelHop>,
    #[serde(default)]
    #[sqlx(skip)]
    pub bound_rule_count: i64,
}

/// One hop of a reusable tunnel. Position 0 is the public entry and therefore
/// has no shared listener port; positions 1..N each reserve one TCP port.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TunnelHop {
    pub id: i64,
    pub tunnel_id: i64,
    pub position: i32,
    pub device_group_id: i64,
    pub listen_port: Option<i32>,
    pub created_at: String,
    /// Display-only fields populated by the repository. Public APIs clear
    /// `connect_host`; the administrator API retains it for firewall output.
    #[serde(default)]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ForwardRule {
    pub id: i64,
    pub name: String,
    pub uid: i64,
    pub paused: bool,
    pub listen_port: i32,
    pub protocol: String,
    /// v0.4.0: user-facing ingress transport (what the user picks).
    /// "raw" | "ws" | "wss" | "tls_simple". Legacy "tls" is mapped to
    /// "tls_simple" on read. Replaces the v0.3.x `entry_transport` column.
    pub public_transport: String,
    /// v0.4.0: the transport the NODE actually listens on, derived from
    /// public_transport at write time. "raw" | "ws" | "tls_simple". The node
    /// receives this verbatim (never "wss" — that's proxy-terminated).
    pub node_transport: String,
    /// v0.4.0: forwarding topology. "direct" | "group" | "chain".
    pub route_mode: String,
    pub device_group_in: i64,
    pub device_group_out: Option<i64>,
    pub forward_mode: String,
    /// v0.3.0: chain-mode tunnel profile. NULL → fall back to builtin 'direct'
    /// at config-build time.
    pub tunnel_profile_id: Option<i64>,
    /// Reusable preset route. Tunnel-bound rules are deliberately persisted as
    /// route_mode=chain with no rule-level hop rows so an old panel fails
    /// closed rather than silently forwarding directly.
    #[serde(default)]
    pub tunnel_id: Option<i64>,
    #[serde(default)]
    #[sqlx(skip)]
    pub tunnel_name: Option<String>,
    #[serde(default)]
    #[sqlx(skip)]
    pub tunnel_enabled: Option<bool>,
    #[serde(default)]
    #[sqlx(skip)]
    pub tunnel_shared: Option<bool>,
    /// Safe display snapshot of the bound preset route. Unlike `hops`, these
    /// rows are not rule-owned and never affect old-panel fail-closed behavior.
    /// Public rule APIs clear every hop's internal connect_host.
    #[serde(default)]
    #[sqlx(skip)]
    pub tunnel_hops: Vec<TunnelHop>,
    /// v0.3.0: optional per-rule WS/TLS metadata. NULL = use profile default /
    /// not applicable for raw/tcp.
    pub domain: Option<String>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub sni: Option<String>,
    pub target_addr: String,
    pub target_port: i32,
    #[serde(default)]
    #[sqlx(skip)]
    pub targets: Vec<ForwardRuleTarget>,
    /// Multi-hop chain membership (ordered by position). Empty for direct rules.
    #[serde(default)]
    #[sqlx(skip)]
    pub hops: Vec<ForwardRuleHop>,
    /// v0.4.6: multi-target load-balancing strategy.
    /// "first" | "round_robin" | "failover" | "weighted" |
    /// "least_latency" | "least_connections". Defaults to "first".
    #[serde(default = "default_load_balance_strategy")]
    pub load_balance_strategy: String,
    /// v0.4.6: per-rule upload cap in decimal Mbps (1 Mbps = 1,000,000 bit/s).
    /// 0 = unlimited. Shared across all connections of the rule.
    #[serde(default)]
    pub upload_limit_mbps: i32,
    /// v0.4.6: per-rule download cap in decimal Mbps. 0 = unlimited.
    #[serde(default)]
    pub download_limit_mbps: i32,
    /// v1.2.0: cap on concurrent TCP connections, enforced PER NODE (see
    /// `ListenerConfig::max_connections` for why the scope is per-node, and why
    /// it is TCP-only). 0 = unlimited, which is the pre-v1.2 behaviour and
    /// stays the default so an upgrade changes nothing on its own.
    #[serde(default)]
    pub max_connections: i32,
    /// v1.2.0: restart this rule every N minutes to shed accumulated
    /// connections. 0 = off (the default). The panel rejects a non-zero value
    /// below `MIN_AUTO_RESTART_MINUTES` — a shorter interval would drop live
    /// connections faster than clients can reasonably reconnect, which turns
    /// the safety valve into an outage.
    #[serde(default)]
    pub auto_restart_minutes: i32,
    pub config: String,
    pub traffic_used: i64,
    pub status: String,
    pub created_at: String,
}

/// v1.2.0: floor for `auto_restart_minutes` when it is enabled (non-zero).
/// Lives in shared so the panel's validation and the frontend's form hint
/// cannot drift apart.
pub const MIN_AUTO_RESTART_MINUTES: i32 = 5;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeviceGroup {
    pub id: i64,
    pub name: String,
    pub group_type: String,
    pub token: String,
    pub uid: i64,
    pub connect_host: String,
    pub port_range: String,
    pub fallback_group: Option<i64>,
    pub config: String,
    /// Inbound protocol policy, stored as a canonical JSON array in both
    /// database backends but exposed as a real JSON array over the API.
    #[serde(
        default = "empty_json_array",
        serialize_with = "serialize_blocked_protocols",
        deserialize_with = "deserialize_blocked_protocols"
    )]
    pub blocked_protocols: String,
    /// v0.3.0: declared protocol capabilities (JSON array string). Used for
    /// pre-create validation only; e.g. `["tcp","udp"]`.
    pub capabilities: String,
    /// v0.3.0: descriptive metadata (nullable; "- " when absent).
    pub region: Option<String>,
    pub line_type: Option<String>,
    pub remark: Option<String>,
    /// v1.0.8: traffic billing multiplier for this line. Real bytes are stored
    /// on forward_rules / users; users are CHARGED `real * rate` (rounded) in
    /// apply_traffic_batch. 1.0 = bill what you use. Range 0.1..=100.
    pub rate: f64,
    /// v1.0.7: hidden from regular users' shared views (node status / available
    /// lines). Admins are unaffected. Default false.
    #[serde(default)]
    pub hidden: bool,
    pub created_at: String,
}

/// v0.4.11 PR3: summary of a device group visible to all authenticated users.
/// Does NOT include sensitive fields (token, uid, config, fallback_group).
/// Used by the shared-groups endpoint so regular users can select admin-provided
/// inbound/outbound groups when creating rules.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SharedGroupSummary {
    pub id: i64,
    pub name: String,
    pub group_type: String,
    pub connect_host: String,
    pub capabilities: String,
    pub region: Option<String>,
    pub line_type: Option<String>,
    /// Safe, user-visible ingress policy metadata. Stored as JSON text in the
    /// row model and serialized as an array in HTTP responses.
    #[serde(
        default = "empty_json_array",
        serialize_with = "serialize_blocked_protocols",
        deserialize_with = "deserialize_blocked_protocols"
    )]
    pub blocked_protocols: String,
    /// v1.0.7: admin "hidden" flag. Carried here so the node-status path can
    /// filter it out (regular users don't see hidden lines in node status),
    /// while the rule dropdown / shop still list it. Default false.
    #[serde(default)]
    pub hidden: bool,
}

/// v0.4.13 PR2 / v0.4.14 PR1: per-NODE availability + load metrics for a shared
/// (admin-owned) inbound group, visible to regular users. Built in the handler
/// layer by scanning the `node_status:*` kvs keys — it is NOT a DB row mapping.
///
/// One row PER NODE. A shared group with no reporting node still yields one
/// placeholder row (node_id empty, online=false, metrics None) so the line
/// never disappears. Group metadata (group_id/name/connect_host/region/
/// line_type) repeats on each of the group's node rows.
///
/// v0.4.14: `node_id` and `public_ip` ARE exposed to regular users (confirmed
/// product requirement — users need to see which server they're using). Still
/// NEVER exposed: NODE_TOKEN, config, listener_errors, internal DB fields,
/// install commands, certificate / private-key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedNodeSummary {
    pub group_id: i64,
    pub group_name: String,
    pub connect_host: String,
    pub capabilities: String,
    pub region: Option<String>,
    pub line_type: Option<String>,
    /// Safe shared-line policy metadata repeated on every node row (and the
    /// no-node placeholder) so regular-user status views do not lose the
    /// warning carried by `SharedGroupSummary`.
    #[serde(default)]
    pub blocked_protocols: Vec<BlockedProtocol>,
    /// Per-node identity (row key). Empty for a group's no-node placeholder row.
    pub node_id: String,
    /// This node's last_seen is within the online window (backend SoT).
    pub online: bool,
    /// v0.4.14: node public IP (exposed to regular users). v0.4.15: this is the
    /// legacy field (carries IPv4); prefer `public_ipv4` / `public_ipv6`.
    pub public_ip: Option<String>,
    /// v0.4.15: dual-stack public IPs. `public_ipv4` falls back to `public_ip`
    /// for older nodes. `public_ipv6` is None when the node has no IPv6.
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    /// v0.4.15: node-level GeoIP (resolved by the PANEL from the IP, not
    /// reported by the node). None = lookup disabled / pending / unknown.
    pub ipv4_country_code: Option<String>,
    pub ipv4_country_name: Option<String>,
    pub ipv6_country_code: Option<String>,
    pub ipv6_country_name: Option<String>,
    /// v0.4.14: relay-node binary version (e.g. "0.4.13").
    pub node_version: Option<String>,
    /// v0.4.14: config-protocol version the node speaks.
    pub config_protocol_version: Option<i64>,
    /// v0.4.14: active connection count.
    pub connections: i64,
    pub capacity_score: Option<f64>,
    pub predicted_spare_connections: Option<i64>,
    pub anomaly_detected: Option<bool>,
    /// v0.4.14: SYSTEM uptime (since OS boot), seconds.
    pub uptime: Option<i64>,
    /// v0.4.14: relay-node process uptime (since binary start), seconds.
    pub process_uptime: Option<i64>,
    /// v0.4.14: interface machine traffic is counted on (e.g. "eth0").
    pub network_interface: Option<String>,
    /// CPU usage percent (0-100). None on a placeholder / old node.
    pub cpu: Option<f64>,
    /// Memory usage percent (0-100).
    pub mem: Option<f64>,
    /// v0.4.14: primary-disk mount point (e.g. "/").
    pub disk_mount: Option<String>,
    /// Primary-disk usage percent (0-100).
    pub disk_usage_percent: Option<f64>,
    pub disk_used: Option<i64>,
    pub disk_total: Option<i64>,
    /// Realtime upload / download rate (bytes/sec).
    pub upload_bps: Option<i64>,
    pub download_bps: Option<i64>,
    /// Cumulative (since node boot) upload / download bytes.
    pub boot_upload_bytes: Option<i64>,
    pub boot_download_bytes: Option<i64>,
    /// This node's last_seen (RFC3339), if it has reported.
    pub last_seen: Option<String>,
}

/// v0.3.0: reusable tunnel profile describing the transport between an inbound
/// node and an outbound node (NOT the user-facing entry protocol). The six
/// builtin rows are seeded by Migration 6 and owned by the admin (uid=1).
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TunnelProfile {
    pub id: i64,
    pub name: String,
    /// ws | tls_simple
    pub transport: String,
    /// none | terminate | passthrough
    pub tls_mode: String,
    pub ws_path: String,
    pub host_header: String,
    pub sni: String,
    /// Reserved for a future certificates table; NULL until then.
    pub cert_id: Option<i64>,
    /// 1 = seeded builtin (not deletable).
    pub is_builtin: bool,
    pub uid: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Plan {
    pub id: i64,
    pub name: String,
    pub max_rules: i32,
    pub traffic: i64,
    pub speed_limit: i32,
    pub ip_limit: i32,
    pub price: String,
    /// v1.0.8: 'data' = traffic-quota plan, 'time' = time-limited plan.
    #[serde(default = "default_plan_type")]
    pub plan_type: String,
    /// v1.0.8: validity in days (0 = unlimited). Only meaningful for time plans.
    #[serde(default)]
    pub duration_days: i32,
    /// v1.0.8: hidden from the public plan list + not self-purchasable.
    #[serde(default)]
    pub hidden: bool,
    /// v1.0.8: buying resets traffic_used to 0.
    #[serde(default)]
    pub reset_traffic: bool,
    /// v1.0.8: free-form line shown under the plan name in the shop.
    #[serde(default)]
    pub description: String,
    /// v1.0.9: when true, buying this plan grants access to ALL inbound groups
    /// (sets the user's all_device_groups flag). When false, buying grants the
    /// groups in plan_device_groups (appended to the user's existing set).
    #[serde(default)]
    pub grant_all_groups: bool,
    pub created_at: String,
}

fn default_plan_type() -> String {
    "data".to_string()
}

/// v1.0.8: a purchase order. plan_name + price are SNAPSHOTS at buy time so
/// the history stays accurate after a plan is renamed/retired/deleted.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Order {
    pub id: i64,
    pub user_id: i64,
    pub plan_id: Option<i64>,
    pub plan_name: String,
    pub price: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Statistic {
    pub id: i64,
    pub stat_type: String,
    pub stat_key: String,
    pub time: String,
    pub number: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_protocol_storage_is_canonical_and_api_is_an_array() {
        assert_eq!(
            encode_blocked_protocols(&[BlockedProtocol::Tls, BlockedProtocol::Tls]),
            "[\"tls\"]"
        );
        let summary = SharedGroupSummary {
            id: 1,
            name: "entry".into(),
            group_type: "in".into(),
            connect_host: "192.0.2.1".into(),
            capabilities: "[\"tcp\"]".into(),
            region: None,
            line_type: None,
            blocked_protocols: "[\"tls\",\"tls\"]".into(),
            hidden: false,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["blocked_protocols"], serde_json::json!(["tls"]));

        let decoded: SharedGroupSummary = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.blocked_protocols, "[\"tls\"]");
    }
}
