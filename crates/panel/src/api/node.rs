use crate::api::AppState;
use axum::response::{IntoResponse, Response};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;
use std::net::{IpAddr, SocketAddr};

/// Extract the node token from the `Authorization: Bearer <NODE_TOKEN>` header.
/// The token is accepted ONLY from this header — never from the query string
/// (leaks into access/proxy logs) nor from the request body. All currently
/// shipped nodes send the header.
pub(crate) fn extract_node_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Canonicalize the stable node identity used by status KVS keys, URL path
/// segments and directed WebSocket control. Restricting it to the portable
/// filename/URL-safe alphabet keeps all three representations identical;
/// bounding it also prevents a valid group token from creating arbitrarily
/// large KVS keys.
pub(crate) fn normalize_node_id(raw: &str) -> Option<String> {
    let node_id = raw.trim();
    if node_id.is_empty()
        || node_id.len() > 128
        || !node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(node_id.to_string())
}

/// v0.4.0: read the node's config-protocol version from the
/// `X-Config-Protocol-Version` request header. Returns None if absent (treated
/// as incompatible — the node is too old to know about the gate).
pub(crate) fn extract_config_protocol_version(headers: &HeaderMap) -> Option<u32> {
    headers
        .get("X-Config-Protocol-Version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
}

/// Parse the address forms commonly emitted by reverse proxies:
///
/// - `203.0.113.7`
/// - `203.0.113.7:43210`
/// - `[2001:db8::7]:43210`
/// - `for="[2001:db8::7]:43210"` (RFC 7239 Forwarded)
fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let mut value = value.trim();
    if value
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("for="))
    {
        value = &value[4..];
    }
    value = value.trim().trim_matches('"');
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .and_then(|v| v.parse::<IpAddr>().ok())
        })
}

/// Resolve the IP used by the node's actual `report_status` path.
///
/// Reverse-proxy headers take precedence because the panel's TCP peer is then
/// the proxy/container address. The direct socket peer is the final fallback.
/// Only an authenticated node report is persisted, so accepting these headers
/// does not create an unauthenticated status-write path.
pub(crate) fn extract_report_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    // Cloudflare terminates the client connection before an origin proxy, so
    // this is the only header that still identifies the node in that topology.
    for value in headers.get_all("cf-connecting-ip") {
        if let Ok(value) = value.to_str() {
            if let Some(ip) = parse_forwarded_ip(value) {
                return Some(ip);
            }
        }
    }

    // RFC 7239: use the first valid `for=` hop (the original client).
    for value in headers.get_all("forwarded") {
        let Ok(value) = value.to_str() else { continue };
        for hop in value.split(',') {
            for parameter in hop.split(';') {
                if parameter
                    .trim()
                    .get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("for="))
                {
                    if let Some(ip) = parse_forwarded_ip(parameter) {
                        return Some(ip);
                    }
                }
            }
        }
    }

    // Nginx/Caddy convention. The left-most valid entry is the original
    // client; later entries are intermediary proxies.
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else { continue };
        for hop in value.split(',') {
            if let Some(ip) = parse_forwarded_ip(hop) {
                return Some(ip);
            }
        }
    }

    for value in headers.get_all("x-real-ip") {
        if let Ok(value) = value.to_str() {
            if let Some(ip) = parse_forwarded_ip(value) {
                return Some(ip);
            }
        }
    }

    peer.map(|addr| addr.ip())
}

/// v0.4.0: the config-protocol compatibility gate. Returns true if the node's
/// reported version matches the panel's `CONFIG_PROTOCOL_VERSION`. A missing
/// header (old node) is treated as incompatible. Used by HTTP to gate snapshots
/// and by WebSocket to select its protocol-incompatible control-only mode.
pub(crate) fn config_protocol_compatible(headers: &HeaderMap) -> bool {
    match extract_config_protocol_version(headers) {
        Some(v) => v == CONFIG_PROTOCOL_VERSION,
        None => false,
    }
}

/// Protocol v8 introduced authoritative 401/403 handling in relay-node's
/// config poller. v4-v7 treated every non-426 error as transient and retained
/// the disk cache, so a rotated/deleted token must receive a successful empty
/// snapshot to stop those historical nodes durably.
const CREDENTIAL_REJECTION_AWARE_PROTOCOL: u32 = 8;

fn rejected_node_credential_response(headers: &HeaderMap) -> Response {
    let received = extract_config_protocol_version(headers);
    if received.is_none_or(|version| version < CREDENTIAL_REJECTION_AWARE_PROTOCOL) {
        tracing::warn!(
            received = ?received,
            "sending legacy node with an invalid credential an empty fail-closed configuration"
        );
        return Json(crate::service::node_config::empty_node_config(Vec::new())).into_response();
    }
    (StatusCode::UNAUTHORIZED, "invalid node credential").into_response()
}

pub async fn get_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Authentication must run before the compatibility gate. Otherwise a
    // revoked node that also reports an old protocol receives 426 and keeps
    // forwarding from its cache. Rejection-aware nodes get 401 below; older
    // pollers get a wire-compatible empty snapshot instead.
    let Some(token) = extract_node_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "invalid node credential").into_response();
    };

    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("get_config: find_by_token failed: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "config unavailable: transient database error",
            )
                .into_response();
        }
    };

    let Some(group) = group else {
        return rejected_node_credential_response(&headers);
    };

    // v0.4.0: protocol-version gate. A node reporting a different
    // config_protocol_version (or none at all — pre-v0.4.0 node) must NOT
    // receive config it can't deserialize (e.g. the renamed node_transport
    // field). Return 426 (Upgrade Required) — NOT 503 — so the node treats it
    // as a permanent config error and backs off, not as a transient outage.
    // The structured JSON lets the node log "requires v1, has v0".
    if !config_protocol_compatible(&headers) {
        let received = extract_config_protocol_version(&headers);
        // A protocol mismatch normally preserves the old cached config to
        // avoid an outage during rolling upgrades. That is unsafe once an
        // ingress-blocking policy is active: a pre-v11 node would keep serving
        // its old unfiltered listener indefinitely. Return a wire-compatible
        // successful EMPTY snapshot so every historical poller follows its
        // normal save-and-apply path. Protocol v4-v7 treated 401/403 as a
        // transient error and retained their disk cache, so an error response
        // cannot provide durable fail-closed behavior across node restarts.
        if !decode_blocked_protocols(&group.blocked_protocols).is_empty() {
            tracing::warn!(
                group_id = group.id,
                received = ?received,
                required = CONFIG_PROTOCOL_VERSION,
                "sending protocol-incompatible node an empty fail-closed configuration"
            );
            return Json(crate::service::node_config::empty_node_config(Vec::new()))
                .into_response();
        }
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(serde_json::json!({
                "code": "CONFIG_PROTOCOL_MISMATCH",
                "required": CONFIG_PROTOCOL_VERSION,
                "received": received,
                "message": "relay-node configuration protocol is incompatible; \
                            upgrade relay-node to match the panel"
            })),
        )
            .into_response();
    }

    // v0.3.6: delegate to the shared `build_node_config`. This path and the WS
    // push path (ws.rs) now use the SAME function.
    //
    // An empty Ok result is a legitimate "no matching rules" state. A DB Err is
    // a transient backend failure → HTTP 503.
    match crate::service::node_config::build_node_config(state.db.as_ref(), group.id).await {
        Ok(cfg) => {
            // Building a snapshot performs several queries and may include
            // freshly derived inter-node credentials. Revalidate after all of
            // them: a token rotated during the build must not receive a
            // snapshot derived from the replacement credential.
            match state.db.find_by_token(&token).await {
                Ok(Some(current)) if current.id == group.id => Json(cfg).into_response(),
                // Keep credential-rejection behavior centralized. A token can
                // be rotated while the snapshot queries are running, so this
                // branch must never release the just-built snapshot.
                Ok(_) => rejected_node_credential_response(&headers),
                Err(e) => {
                    tracing::error!(
                        "get_config: post-build token revalidation failed for group {}: {}",
                        group.id,
                        e
                    );
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "config unavailable: transient database error",
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "get_config: build_node_config failed for group {}: {}",
                group.id,
                e
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "config unavailable: transient database error",
            )
                .into_response()
        }
    }
}

pub async fn report_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TrafficReport>,
) -> Json<ApiResponse<()>> {
    // Token comes ONLY from the Authorization header (v0.3.9: the body token
    // fallback was removed — nodes send the header and an empty body token).
    //
    // HTTP-status note: a missing/invalid token here returns HTTP 200 with a
    // business `code: 401` INSIDE the JSON body — NOT a real HTTP 401. This is
    // deliberate backward-compat: all shipped nodes read the JSON `code` field
    // and ignore the HTTP status on these reporting endpoints. The protocol-v8
    // config endpoint and WebSocket upgrade path are exceptions: both return a
    // real HTTP 401 so the node can immediately revoke cached tunnel
    // credentials. Do NOT "normalize" the remaining reporting endpoints
    // without a coordinated node upgrade; see the test module's
    // `node_http_status_compat_*` tests that pin the current behavior.
    let Some(token) = extract_node_token(&headers) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };

    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("report_traffic: find_by_token failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };

    let group = match group {
        Some(g) => g,
        None => {
            return Json(ApiResponse {
                code: 401,
                message: "Invalid token".into(),
                data: None,
            })
        }
    };

    // v0.4.9 SECURITY: the whole batch is one atomic transaction, and rule-id
    // existence is NO LONGER distinguishable from cross-group reporting. Both
    // "rule missing" and "rule belongs to another group" produce the SAME
    // external response (403 + a single generic message). The batch logic lives
    // in `service::traffic::apply_traffic_report` (overflow pre-check + atomic
    // apply + result interpretation) so it can be unit-tested without HTTP.
    //
    // HTTP-status note (preserved): a rejection returns HTTP 200 with a business
    // `code` (403/400/500) INSIDE the JSON body — NOT a real HTTP error. Nodes
    // read the JSON `code` and ignore the HTTP status on these endpoints.
    match crate::service::traffic::apply_traffic_report(state.db.as_ref(), group.id, &req.reports)
        .await
    {
        Ok(()) => Json(ApiResponse::success(())),
        Err(crate::service::traffic::TrafficReportError::Unavailable) => {
            // Uniform 403 — identical for "missing" and "foreign". Do NOT echo
            // which rule_id or why.
            Json(ApiResponse {
                code: 403,
                message: "one or more rules are unavailable for this node".into(),
                data: None,
            })
        }
        Err(crate::service::traffic::TrafficReportError::Overflow) => Json(ApiResponse {
            code: 400,
            message: "one or more traffic entries are out of range".into(),
            data: None,
        }),
        Err(crate::service::traffic::TrafficReportError::Database(e)) => {
            tracing::error!("report_traffic: apply_traffic_batch failed: {}", e);
            Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            })
        }
    }
}

pub async fn report_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<StatusReport>,
) -> Json<ApiResponse<()>> {
    // Token comes ONLY from the Authorization header (v0.3.9: body token
    // fallback removed).
    let Some(token) = extract_node_token(&headers) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };

    // Verify token before accepting status or renewing any drain lease. Keep
    // the reporting endpoint's HTTP-200 compatibility, but distinguish an
    // invalid credential from a transient backend failure in the business
    // response instead of acknowledging both as a successful report.
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) => group,
        Ok(None) => {
            return Json(ApiResponse {
                code: 401,
                message: "Invalid token".into(),
                data: None,
            });
        }
        Err(e) => {
            tracing::error!("report_status: find_by_token failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };

    let node_id = match req.node_id.as_deref() {
        Some(raw) => match normalize_node_id(raw) {
            Some(node_id) => Some(node_id),
            None => {
                return Json(ApiResponse {
                    code: 400,
                    message: "Invalid node_id".into(),
                    data: None,
                });
            }
        },
        None => None,
    };

    // This is the address family/path that actually delivered the heartbeat
    // to the panel. It is deliberately independent of the node's external
    // ipify-style self-detection fields.
    let report_ip = extract_report_ip(&headers, Some(peer)).map(|ip| ip.to_string());

    {
        let g = group;
        let mut draining_rule_ids: Vec<i64> = req
            .draining_rule_ids
            .iter()
            .copied()
            .filter(|rule_id| *rule_id > 0)
            .collect();
        draining_rule_ids.sort_unstable();
        draining_rule_ids.dedup();
        if !draining_rule_ids.is_empty() {
            // Bound each generated IN query without discarding legitimate
            // tails. A large shared tunnel can have more than 4096 rules
            // draining at once after an entry move.
            let mut renewed = 0u64;
            for rule_ids in draining_rule_ids.chunks(4096) {
                match state
                    .db
                    .renew_draining_tunnel_rule_ids_for_group(g.id, rule_ids)
                    .await
                {
                    Ok(count) => renewed = renewed.saturating_add(count),
                    Err(error) => {
                        tracing::error!(
                            group_id = g.id,
                            "failed to renew entry-drain leases: {error}"
                        );
                        return Json(ApiResponse {
                            code: 500,
                            message: "database error".into(),
                            data: None,
                        });
                    }
                }
            }
            if renewed < draining_rule_ids.len() as u64 {
                tracing::debug!(
                    group_id = g.id,
                    requested = draining_rule_ids.len(),
                    renewed,
                    "some reported drain leases were absent"
                );
            }
        }
        // v0.3.0: key node status by (group_id, node_id) so multiple nodes
        // sharing one group token no longer overwrite each other. The node_id
        // is a stable per-node identity generated on first start (see
        // poller::get_or_create_node_id). Older nodes that don't send node_id
        // fall back to the legacy per-group key (no regression — a single-node
        // group behaves exactly as before).
        let status_key = match &node_id {
            Some(nid) => format!("node_status:{}:{}", g.id, nid),
            _ => format!("node_status:{}", g.id), // legacy fallback
        };
        let node_id_for_json = node_id.clone();
        // Store every reported metric in the status JSON. New optional fields
        // are only included when the node actually reported them (older nodes
        // omit them and the panel renders "-" for missing values).
        let status = serde_json::json!({
            "node_id": node_id_for_json,
            "cpu": req.cpu_usage,
            "mem": req.mem_usage,
            "connections": req.active_connections,
            "capacity_score": req.capacity_score,
            "predicted_spare_connections": req.predicted_spare_connections,
            "anomaly_detected": req.anomaly_detected,
            // v0.3.2: "uptime" is SYSTEM uptime (since OS boot). process uptime
            // is separate below; older nodes don't send it and it renders as "-".
            "uptime": req.uptime_secs,
            "process_uptime": req.process_uptime_secs,
            // v0.3.4: the node binary's version (for the "stale node" upgrade
            // hint). Older nodes don't send it; the panel renders "-".
            "node_version": req.node_version,
            // v0.4.0: config-protocol version (mirrors the
            // X-Config-Protocol-Version header). The frontend uses this to show
            // "配置协议不兼容，请升级节点" when it doesn't match the panel's.
            "config_protocol_version": req.config_protocol_version,
            "last_seen": chrono::Utc::now().to_rfc3339(),
            "report_ip": report_ip,
            "public_ip": req.public_ip,
            // v0.4.15: dual-stack public IPs. Falls back to public_ip (legacy
            // IPv4) when the node hasn't upgraded yet.
            "public_ipv4": req.public_ipv4.clone().or(req.public_ip.clone()),
            "public_ipv6": req.public_ipv6,
            "disk_total": req.disk_total,
            "disk_used": req.disk_used,
            "disk_usage_percent": req.disk_usage_percent,
            "disk_mount": req.disk_mount,
            "upload_bps": req.upload_bps,
            "download_bps": req.download_bps,
            "boot_upload_bytes": req.boot_upload_bytes,
            "boot_download_bytes": req.boot_download_bytes,
            // v0.4.6: the interface machine traffic is counted on, so the panel
            // can show "统计网卡: eth0". Missing on older nodes → "-".
            "network_interface": req.network_interface,
            // v0.3.6: listener bind failures (port in use, permission denied,
            // etc.) so the operator can see WHY a rule isn't forwarding.
            // Missing on older nodes; the frontend renders "ok".
            "listener_errors": req.listener_errors,
            // v1.1.x: how the node is installed ("systemd" | "docker" | "manual").
            // The node reports this so the panel's node-status UI knows whether a
            // one-click self-upgrade is possible (only systemd can safely restart
            // after replacing its own binary). Without persisting it here the
            // frontend saw `undefined` and wrongly showed every node as "manual",
            // hiding the upgrade button on legitimately systemd-managed nodes.
            "install_method": req.install_method,
            // Cumulative protocol-policy rejects since node process start.
            // Additive optional metric: older nodes simply omit it.
            "blocked_protocol_connections": req.blocked_protocol_connections,
        });
        // Do not acknowledge a status report that was not persisted. Nodes
        // report periodically and may retry safely; returning success here
        // would instead hide the outage and leave the panel with stale state.
        if let Err(error) = state.db.set(&status_key, &status.to_string()).await {
            tracing::error!("report_status: kvs set failed: {}", error);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }

        // v0.4.19: async GeoIP enrichment — fire-and-forget, never blocks the
        // status report or node forwarding. Only runs when GEOIP_ENABLED=true.
        // Uses built-in primary + fallback providers (ipinfo.io → ipwho.is).
        // Each public IP is looked up independently; the geoip module handles
        // caching + concurrent de-duplication + private-IP rejection.
        if state.config.geoip_enabled {
            let db = state.db.clone();
            let ttl = state.config.geoip_cache_ttl as i64;
            let inflight = state.geoip_in_flight.clone();
            let report_ip = report_ip.clone();
            let v4 = req.public_ipv4.clone().or(req.public_ip.clone());
            let v6 = req.public_ipv6.clone();
            tokio::spawn(async move {
                if let Some(ip) = report_ip {
                    let _ = crate::api::geoip::lookup(db.as_ref(), ttl, &inflight, &ip).await;
                }
                if let Some(ip) = v4 {
                    let _ = crate::api::geoip::lookup(db.as_ref(), ttl, &inflight, &ip).await;
                }
                if let Some(ip) = v6 {
                    let _ = crate::api::geoip::lookup(db.as_ref(), ttl, &inflight, &ip).await;
                }
            });
        }

        // ── v0.3.2: legacy status cleanup ──
        // When a node upgraded to v0.3.1+ starts reporting with its new
        // node_id key, its OLD legacy entry ("node_status:{group_id}", no
        // node_id suffix) is left behind forever, showing as a permanently-
        // offline ghost node. We clean it up HERE: if this report has a
        // node_id AND a public_ip, delete the legacy key for the same group
        // IF AND ONLY IF its stored public_ip matches (so a different-IP node
        // sharing the group isn't wrongly deleted).
        if let (Some(_), Some(ref ip)) = (&node_id, &req.public_ip) {
            if !ip.is_empty() {
                crate::service::traffic::cleanup_legacy_status(state.db.as_ref(), g.id, ip).await;
            }
        }
    }

    // ── v0.3.2: stale status sweep ──
    // Also runs on READ (get_node_status), so ghost rows get cleaned even when
    // no node in the group is still reporting. Threshold is 2 min (frontend
    // marks offline at 30s; we keep the row a bit longer to ride out blips).
    let _ = crate::service::traffic::sweep_stale_status(state.db.as_ref()).await;

    Json(ApiResponse::success(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

    // ── report_traffic transactional correctness (v0.3.6) ──
    //
    // These exercise the atomicity contract: rule + user totals must move
    // together or not at all; an unauthorized rule must reject the whole batch;
    // a stale rule_id is skipped; overflow is rejected up front.

    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::api::AppState;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use relay_shared::protocol::{TrafficEntry, TrafficReport};
    use std::sync::Arc;

    #[test]
    fn node_id_normalization_is_bounded_and_key_safe() {
        assert_eq!(
            normalize_node_id("  node-a_1.2  ").as_deref(),
            Some("node-a_1.2")
        );
        assert!(normalize_node_id("").is_none());
        assert!(normalize_node_id("group:node").is_none());
        assert!(normalize_node_id("node id").is_none());
        assert!(normalize_node_id("node/path?query").is_none());
        assert!(normalize_node_id(&"a".repeat(129)).is_none());
    }

    #[test]
    fn report_ip_prefers_forwarded_client_over_proxy_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "2402:4e00:c013:8600::7, 172.18.0.4".parse().unwrap(),
        );
        let peer = "172.18.0.3:43210".parse().unwrap();
        assert_eq!(
            extract_report_ip(&headers, Some(peer)),
            Some("2402:4e00:c013:8600::7".parse().unwrap())
        );
    }

    #[test]
    fn report_ip_supports_standard_forwarded_and_socket_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            r#"for="[2001:db8::7]:4711";proto=https"#.parse().unwrap(),
        );
        assert_eq!(
            extract_report_ip(&headers, Some("10.0.0.2:80".parse().unwrap())),
            Some("2001:db8::7".parse().unwrap())
        );

        assert_eq!(
            extract_report_ip(
                &HeaderMap::new(),
                Some("203.0.113.9:43210".parse().unwrap())
            ),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn report_ip_uses_cloudflare_original_client_header_first() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "198.51.100.8".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
        assert_eq!(
            extract_report_ip(&headers, Some("10.0.0.2:80".parse().unwrap())),
            Some("198.51.100.8".parse().unwrap())
        );
    }

    async fn full_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        (state, pool)
    }

    /// Seed: administrator-owned inbound group 10 with token "tok-A", plus a
    /// rule owned by regular user 2 on that group. Returns AppState + pool.
    async fn seeded_state() -> (AppState, SqlitePool) {
        let (state, pool) = full_state().await;
        let hash = bcrypt::hash("pw-2", 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'alice', ?, 0)")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'gin', 'in', 'tok-A', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (100, 'r100', 2, 20000, 10, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();
        (state, pool)
    }

    fn report(_token: &str, entries: &[TrafficEntry]) -> TrafficReport {
        TrafficReport {
            reports: entries.to_vec(),
        }
    }

    fn auth_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    fn test_peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:43210".parse().unwrap())
    }

    fn empty_status_report() -> StatusReport {
        StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            capacity_score: None,
            predicted_spare_connections: None,
            anomaly_detected: None,
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: None,
            process_uptime_secs: None,
            node_version: None,
            config_protocol_version: None,
            listener_errors: None,
            install_method: None,
            draining_rule_ids: vec![],
            blocked_protocol_connections: None,
        }
    }

    async fn user_traffic(pool: &SqlitePool, uid: i64) -> i64 {
        let (v,): (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id=?")
            .bind(uid)
            .fetch_one(pool)
            .await
            .unwrap();
        v
    }

    async fn rule_traffic(pool: &SqlitePool, rid: i64) -> i64 {
        let (v,): (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id=?")
            .bind(rid)
            .fetch_one(pool)
            .await
            .unwrap();
        v
    }

    /// Normal batch: rule and user totals both move, atomically.
    #[tokio::test]
    async fn traffic_report_updates_rule_and_user() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[TrafficEntry {
                    rule_id: 100,
                    upload: 1000,
                    download: 2000,
                }],
            )),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        assert_eq!(rule_traffic(&pool, 100).await, 3000);
        assert_eq!(user_traffic(&pool, 2).await, 3000);
    }

    /// Multi-entry batch updates every rule and the shared user once each.
    #[tokio::test]
    async fn traffic_report_multi_entry_all_applied() {
        let (state, pool) = seeded_state().await;
        // second rule on the same group + user
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (101, 'r101', 2, 20001, 10, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 100,
                        upload: 100,
                        download: 0,
                    },
                    TrafficEntry {
                        rule_id: 101,
                        upload: 0,
                        download: 200,
                    },
                ],
            )),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        assert_eq!(rule_traffic(&pool, 100).await, 100);
        assert_eq!(rule_traffic(&pool, 101).await, 200);
        assert_eq!(user_traffic(&pool, 2).await, 300);
    }

    /// A rule belonging to ANOTHER group is unauthorized — the whole batch is
    /// rejected and rolled back, including the legitimate entry in the same batch.
    #[tokio::test]
    async fn traffic_report_other_group_rule_rejects_whole_batch() {
        let (state, pool) = seeded_state().await;
        // rule 200 belongs to group 20 (different group), same user
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (20, 'g20', 'in', 'tok-B', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (200, 'r200', 2, 20002, 20, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 100,
                        upload: 500,
                        download: 0,
                    },
                    TrafficEntry {
                        rule_id: 200,
                        upload: 0,
                        download: 999,
                    },
                ],
            )),
        )
        .await;
        assert_eq!(resp.code, 403, "unauthorized rule must reject batch");
        // Rollback: even the legitimate rule 100 entry must NOT have landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    /// v0.4.9: a rule_id that does NOT exist must be treated EXACTLY like a
    /// foreign rule (uniform 403 + whole-batch rollback) — it can no longer be
    /// told apart by the response. This closes the rule-id existence oracle.
    #[tokio::test]
    async fn traffic_report_unknown_rule_is_unavailable_not_skipped() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 99999, // does not exist
                        upload: 1,
                        download: 2,
                    },
                    TrafficEntry {
                        rule_id: 100,
                        upload: 10,
                        download: 20,
                    },
                ],
            )),
        )
        .await;
        // Same code + same generic message as the foreign-rule case.
        assert_eq!(
            resp.code, 403,
            "unknown rule must be rejected like a foreign rule"
        );
        assert_eq!(
            resp.message, "one or more rules are unavailable for this node",
            "message must be generic — no rule_id, no reason"
        );
        // Rollback: even rule 100 must NOT have landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    /// Overflow in upload+download is rejected up front with a 400 (no DB write).
    #[tokio::test]
    async fn traffic_report_overflow_rejected() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[TrafficEntry {
                    rule_id: 100,
                    upload: u64::MAX,
                    download: 1,
                }],
            )),
        )
        .await;
        assert_eq!(resp.code, 400);
        // Nothing landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    // ── node HTTP-status compatibility pins ──
    //
    // Node-facing endpoints deliberately have different auth-failure behavior:
    //   - report_traffic / report_status: missing token → HTTP 200, business
    //     code 401 INSIDE the JSON body (nodes read `code`, not the HTTP status).
    //   - get_config (config protocol v8): missing/invalid token → real HTTP
    //     401 so relay-node clears cached forwarding and revokes tunnel streams.
    //   - WebSocket upgrade: missing/invalid token → real HTTP 401 (WS upgrades
    //     must fail at the HTTP layer — the client never reads a JSON body).
    //
    // These tests PIN that behavior so a future "let's normalize to real HTTP
    // 401s" change can't land silently and break old nodes. The get_config
    // contract was introduced with protocol v8; any node that does not match
    // the current protocol is rejected with 426 before it can observe it.

    /// report_traffic with NO Authorization header → HTTP 200, JSON code 401.
    #[tokio::test]
    async fn node_http_status_compat_traffic_missing_token_is_http200_business401() {
        let (state, _pool) = seeded_state().await;
        let mut h = HeaderMap::new();
        // No Authorization header. (Also need the config-protocol header? No —
        // report_traffic doesn't gate on it, only get_config / WS do.)
        let _ = &mut h;
        let Json(resp) = report_traffic(State(state.clone()), h, Json(report("", &[]))).await;
        // The Json wrapper always serializes as HTTP 200; the business code is
        // the signal. Pin both: status is 200 (Implicit via Json), code is 401.
        assert_eq!(resp.code, 401, "missing token → business 401, not HTTP 401");
        assert_eq!(resp.message, "Invalid token");
    }

    /// report_status with NO Authorization header → HTTP 200, JSON code 401.
    #[tokio::test]
    async fn node_http_status_compat_status_missing_token_is_http200_business401() {
        let (state, _pool) = seeded_state().await;
        let h = HeaderMap::new(); // no Authorization
        let Json(resp) = report_status(
            State(state.clone()),
            h,
            test_peer(),
            Json(empty_status_report()),
        )
        .await;
        assert_eq!(resp.code, 401, "missing token → business 401, not HTTP 401");
    }

    #[tokio::test]
    async fn report_status_unknown_token_is_business401() {
        let (state, _pool) = seeded_state().await;
        let Json(resp) = report_status(
            State(state),
            auth_headers("rotated-or-unknown-token"),
            test_peer(),
            Json(empty_status_report()),
        )
        .await;
        assert_eq!(resp.code, 401);
        assert_eq!(resp.message, "Invalid token");
    }

    #[tokio::test]
    async fn report_status_lookup_failure_is_business500() {
        let (state, pool) = full_state().await;
        sqlx::query("DROP TABLE users")
            .execute(&pool)
            .await
            .unwrap();
        let Json(resp) = report_status(
            State(state),
            auth_headers("any-token"),
            test_peer(),
            Json(empty_status_report()),
        )
        .await;
        assert_eq!(resp.code, 500);
        assert_eq!(resp.message, "database error");
    }

    /// Config protocol v8 treats a missing credential as authoritative
    /// revocation so relay-node cannot keep retired authenticated streams.
    #[tokio::test]
    async fn node_config_missing_token_is_real_http401() {
        let (state, _pool) = seeded_state().await;
        let mut h = HeaderMap::new();
        // Supply a matching protocol too; authentication remains authoritative.
        h.insert(
            "X-Config-Protocol-Version",
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                .to_string()
                .parse()
                .unwrap(),
        );
        // No Authorization header.
        let resp = get_config(State(state.clone()), h).await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// A rejection-aware node receives an authoritative HTTP 401 for an
    /// explicitly supplied but unknown token.
    #[tokio::test]
    async fn node_config_unknown_token_is_real_http401() {
        let (state, _pool) = seeded_state().await;
        let mut headers = auth_headers("rotated-or-unknown-token");
        headers.insert(
            "X-Config-Protocol-Version",
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                .to_string()
                .parse()
                .unwrap(),
        );
        let response = get_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// During a panel-first rolling upgrade an old node must receive 426, never
    /// a v6 config it cannot understand. The node interprets 426 as "keep the
    /// cached forwarding config", which is the no-outage compatibility gate.
    #[tokio::test]
    async fn authenticated_config_protocol_mismatch_returns_426_before_config_build() {
        let (state, _pool) = seeded_state().await;
        let mut headers = auth_headers("tok-A");
        headers.insert(
            "X-Config-Protocol-Version",
            (relay_shared::protocol::CONFIG_PROTOCOL_VERSION - 1)
                .to_string()
                .parse()
                .unwrap(),
        );
        let response = get_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::UPGRADE_REQUIRED);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["required"],
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
        );
        assert_eq!(
            value["received"],
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION - 1
        );
    }

    #[tokio::test]
    async fn protocol_blocked_group_returns_persistable_empty_config_to_incompatible_node() {
        let (state, pool) = seeded_state().await;
        sqlx::query("UPDATE device_groups SET blocked_protocols='[\"tls\"]' WHERE token='tok-A'")
            .execute(&pool)
            .await
            .unwrap();
        let mut headers = auth_headers("tok-A");
        headers.insert(
            "X-Config-Protocol-Version",
            (relay_shared::protocol::CONFIG_PROTOCOL_VERSION - 1)
                .to_string()
                .parse()
                .unwrap(),
        );

        let response = get_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let current: relay_shared::protocol::NodeConfigResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(current.listeners.is_empty());
        assert!(current.tunnels.is_empty());

        // Protocol v4-v7 had only the required `listeners` top-level field and
        // persisted successful HTTP responses. Unknown additive fields are
        // ignored, so the v10 empty snapshot is deliberately compatible with
        // their normal save-and-apply path.
        #[derive(serde::Deserialize)]
        struct LegacyNodeConfigResponse {
            listeners: Vec<serde_json::Value>,
        }
        let legacy: LegacyNodeConfigResponse = serde_json::from_slice(&body).unwrap();
        assert!(legacy.listeners.is_empty());
    }

    #[tokio::test]
    async fn unknown_token_with_legacy_protocol_returns_persistable_empty_config() {
        let (state, _pool) = seeded_state().await;
        let mut headers = auth_headers("revoked-token");
        headers.insert(
            "X-Config-Protocol-Version",
            (CREDENTIAL_REJECTION_AWARE_PROTOCOL - 1)
                .to_string()
                .parse()
                .unwrap(),
        );
        let response = get_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let config: relay_shared::protocol::NodeConfigResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(config.listeners.is_empty());
        assert!(config.tunnels.is_empty());
    }

    #[tokio::test]
    async fn unknown_token_with_rejection_aware_protocol_returns_401() {
        let (state, _pool) = seeded_state().await;
        let mut headers = auth_headers("revoked-token");
        headers.insert(
            "X-Config-Protocol-Version",
            CREDENTIAL_REJECTION_AWARE_PROTOCOL
                .to_string()
                .parse()
                .unwrap(),
        );
        let response = get_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// WebSocket upgrade with NO Authorization header → real HTTP 401 (the one
    /// exception to the "business code in JSON" rule — WS upgrades must fail at
    /// the HTTP layer). We assert via node_ws_handler's IntoResponse output,
    /// WITHOUT performing a real WS upgrade (the handler returns 401 before
    /// touching the socket).
    #[tokio::test]
    async fn node_http_status_compat_ws_missing_token_is_real_http401() {
        // We can't easily build a WebSocketUpgrade in a unit test, so this pin
        // documents + guards the contract via the token-extraction primitive the
        // handler uses: no Authorization header → extract_node_token returns
        // None, and node_ws_handler returns StatusCode::UNAUTHORIZED on None.
        // (A full WS-upgrade integration test would need an HTTP server; the
        // primitive-level pin is sufficient to catch a regression here.)
        let h = HeaderMap::new(); // no Authorization
        assert!(
            extract_node_token(&h).is_none(),
            "no Authorization header → no token → WS handler returns real HTTP 401"
        );
        // And a malformed header (not "Bearer ...") also yields None.
        let mut h2 = HeaderMap::new();
        h2.insert("Authorization", "notabearer".parse().unwrap());
        assert!(extract_node_token(&h2).is_none());
    }

    /// Regression: report_status MUST persist `install_method` into the stored
    /// node-status JSON. It was dropped from the status builder, so the panel
    /// served `install_method: undefined` and the frontend wrongly resolved
    /// every node to the "manual" upgrade state ("手动运行：不支持一键升级"),
    /// hiding the one-click upgrade button on legitimately systemd-managed nodes.
    #[tokio::test]
    async fn report_status_persists_install_method() {
        use relay_shared::protocol::StatusReport;
        let (state, _pool) = seeded_state().await;
        let req = StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            capacity_score: None,
            predicted_spare_connections: None,
            anomaly_detected: None,
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: Some("n1".into()),
            process_uptime_secs: None,
            node_version: Some("1.1.1".into()),
            config_protocol_version: None,
            listener_errors: None,
            install_method: Some("systemd".into()),
            draining_rule_ids: vec![],
            blocked_protocol_connections: Some(std::collections::BTreeMap::from([(
                "tls".to_string(),
                7,
            )])),
        };
        let Json(resp) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            ConnectInfo("203.0.113.27:45678".parse().unwrap()),
            Json(req),
        )
        .await;
        assert_eq!(resp.code, 0, "valid report → success");

        // The per-node status key is node_status:{group_id}:{node_id}.
        let raw = state
            .db
            .get("node_status:10:n1")
            .await
            .expect("kvs get")
            .expect("status row must exist after a successful report");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("stored status is JSON");
        assert_eq!(
            v.get("install_method").and_then(|x| x.as_str()),
            Some("systemd"),
            "install_method must be persisted so the upgrade UI can offer a self-upgrade"
        );
        assert_eq!(
            v.get("report_ip").and_then(|x| x.as_str()),
            Some("203.0.113.27"),
            "status must persist the IP of the actual report path"
        );
        assert_eq!(
            v.pointer("/blocked_protocol_connections/tls")
                .and_then(|x| x.as_u64()),
            Some(7),
            "protocol reject counters must be persisted for the group UI"
        );
    }

    #[tokio::test]
    async fn report_status_rejects_node_id_that_cannot_round_trip_through_key() {
        use relay_shared::protocol::StatusReport;
        let (state, _pool) = seeded_state().await;
        let req = StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            capacity_score: None,
            predicted_spare_connections: None,
            anomaly_detected: None,
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: Some("forged:segment".into()),
            process_uptime_secs: None,
            node_version: None,
            config_protocol_version: None,
            listener_errors: None,
            install_method: None,
            draining_rule_ids: vec![],
            blocked_protocol_connections: None,
        };

        let Json(resp) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            test_peer(),
            Json(req),
        )
        .await;
        assert_eq!(resp.code, 400);
        assert!(state
            .db
            .scan_prefix("node_status:")
            .await
            .expect("scan status keys")
            .is_empty());
    }

    #[tokio::test]
    async fn report_status_does_not_acknowledge_failed_persistence() {
        use relay_shared::protocol::StatusReport;
        let (state, pool) = seeded_state().await;
        sqlx::query("DROP TABLE kvs").execute(&pool).await.unwrap();
        let req = StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            capacity_score: None,
            predicted_spare_connections: None,
            anomaly_detected: None,
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: Some("n1".into()),
            process_uptime_secs: None,
            node_version: None,
            config_protocol_version: None,
            listener_errors: None,
            install_method: None,
            draining_rule_ids: vec![],
            blocked_protocol_connections: None,
        };

        let Json(resp) =
            report_status(State(state), auth_headers("tok-A"), test_peer(), Json(req)).await;
        assert_eq!(resp.code, 500);
    }
}
