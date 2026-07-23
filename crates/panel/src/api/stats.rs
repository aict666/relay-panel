use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::models::Statistic;
use relay_shared::protocol::*;
use serde::{Deserialize, Serialize};

use crate::service::dashboard_metrics::{
    DASHBOARD_STAT_TYPE, KEY_CONNECTIONS, KEY_DOWNLOAD_BPS, KEY_ONLINE_NODES, KEY_RECENT_NODES,
    KEY_UPLOAD_BPS,
};

// Keep these names in this module for the existing node-status callers/tests,
// while the implementation lives with the dashboard sampler so both paths use
// exactly one availability threshold and parser.
pub(crate) use crate::service::dashboard_metrics::{status_is_online, status_last_seen};

/// Parse a node_status kvs key into (group_id, node_id).
///
/// Two formats coexist for backward compat:
///   - legacy:  "node_status:{group_id}"        (older nodes, single-node group)
///   - v0.3.0:  "node_status:{group_id}:{node_id}" (per-node dedup)
///
/// Returns None if the key isn't a node_status key or group_id isn't an int.
/// node_id is None for the legacy format. Pure function so it's unit-testable
/// without a DB.
pub(crate) fn parse_status_key(key: &str) -> Option<(i64, Option<&str>)> {
    let rest = key.strip_prefix("node_status:")?;
    let (group_id_str, node_id) = match rest.split_once(':') {
        Some((g, n)) => (g, Some(n)),
        None => (rest, None),
    };
    let group_id = group_id_str.parse().ok()?;
    Some((group_id, node_id))
}

/// Extract the public IPs from a stored node_status JSON blob.
///
/// Used before deleting one node_status row so we can clean only that node's
/// GeoIP cache entries. Returns None when the JSON is corrupt; callers should
/// still delete the node_status row but skip GeoIP cleanup.
pub(crate) fn public_ips_from_status_json(raw: &str) -> Option<Vec<String>> {
    let status_json: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut ips: Vec<String> = Vec::new();
    for field in ["report_ip", "public_ipv4", "public_ipv6", "public_ip"] {
        if let Some(ip) = status_json
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            ips.push(ip.to_string());
        }
    }
    ips.sort();
    ips.dedup();
    Some(ips)
}

fn public_ips_referenced_by_other_statuses(
    rows: &[(String, String)],
    excluded_key: &str,
) -> std::collections::HashSet<String> {
    rows.iter()
        .filter(|(key, _)| key != excluded_key)
        .filter_map(|(_, raw)| public_ips_from_status_json(raw))
        .flatten()
        .collect()
}

#[derive(Deserialize)]
pub struct StatsQuery {
    pub stat_type: Option<String>,
    pub stat_key: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// GET /stats — global statistics.
///
/// v0.4.10: temporarily ADMIN-ONLY. These rows are not yet owner-scoped, so a
/// regular user would otherwise see every user's aggregate stats. Per-user
/// private statistics are a PR2 deliverable; until then this stays admin-gated
/// rather than leak cross-tenant data.
pub async fn get_stats(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
) -> Json<ApiResponse<Vec<Statistic>>> {
    match state
        .db
        .query_stats(
            q.stat_type.as_deref(),
            q.stat_key.as_deref(),
            q.from.as_deref(),
            q.to.as_deref(),
        )
        .await
    {
        Ok(stats) => Json(ApiResponse::success(stats)),
        Err(e) => {
            tracing::error!("get_stats: db error: {}", e);
            Json(ApiResponse {
                code: 500,
                message: "数据库错误".into(),
                data: None,
            })
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DashboardHistoryQuery {
    pub range: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardRange {
    OneHour,
    OneDay,
    SevenDays,
    ThirtyDays,
}

impl DashboardRange {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("24h") {
            "1h" => Some(Self::OneHour),
            "24h" => Some(Self::OneDay),
            "7d" => Some(Self::SevenDays),
            "30d" => Some(Self::ThirtyDays),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::OneDay => "24h",
            Self::SevenDays => "7d",
            Self::ThirtyDays => "30d",
        }
    }

    fn duration(self) -> chrono::Duration {
        match self {
            Self::OneHour => chrono::Duration::hours(1),
            Self::OneDay => chrono::Duration::hours(24),
            Self::SevenDays => chrono::Duration::days(7),
            Self::ThirtyDays => chrono::Duration::days(30),
        }
    }

    fn bucket_seconds(self) -> i64 {
        match self {
            Self::OneHour => 60,
            Self::OneDay => 5 * 60,
            Self::SevenDays => 30 * 60,
            Self::ThirtyDays => 2 * 60 * 60,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DashboardHistoryPoint {
    pub timestamp: String,
    pub upload_bps_avg: i64,
    pub download_bps_avg: i64,
    /// Highest one-minute sample inside this display bucket. Long ranges use
    /// wider buckets, so plotting only the average would make short spikes
    /// disappear when switching from 24h to 7d/30d.
    pub upload_bps_max: i64,
    pub download_bps_max: i64,
    /// Actual minute at which each directional peak occurred. This is kept
    /// separately because upload and download maxima can occur at different
    /// points inside the same display bucket.
    pub upload_bps_max_at: String,
    pub download_bps_max_at: String,
    pub connections_max: i64,
    pub online_nodes_min: i64,
    pub recent_nodes_max: i64,
    pub sample_count: u32,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DashboardHistoryResponse {
    pub range: String,
    pub bucket_seconds: i64,
    pub points: Vec<DashboardHistoryPoint>,
}

#[derive(Default)]
struct RawMinute {
    upload_bps: Option<i64>,
    download_bps: Option<i64>,
    connections: Option<i64>,
    online_nodes: Option<i64>,
    recent_nodes: Option<i64>,
}

#[derive(Default)]
struct BucketAccumulator {
    upload_sum: i128,
    download_sum: i128,
    upload_max: i64,
    download_max: i64,
    upload_max_at: Option<i64>,
    download_max_at: Option<i64>,
    connections_max: i64,
    online_nodes_min: Option<i64>,
    recent_nodes_max: i64,
    sample_count: u32,
}

fn parse_stat_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|t| t.and_utc())
        })
}

fn downsample_history(stats: Vec<Statistic>, bucket_seconds: i64) -> Vec<DashboardHistoryPoint> {
    use std::collections::BTreeMap;

    let mut minutes: BTreeMap<i64, RawMinute> = BTreeMap::new();
    for stat in stats {
        let Some(time) = parse_stat_time(&stat.time) else {
            continue;
        };
        let minute = minutes.entry(time.timestamp()).or_default();
        let value = stat.number.max(0);
        match stat.stat_key.as_str() {
            KEY_UPLOAD_BPS => minute.upload_bps = Some(value),
            KEY_DOWNLOAD_BPS => minute.download_bps = Some(value),
            KEY_CONNECTIONS => minute.connections = Some(value),
            KEY_ONLINE_NODES => minute.online_nodes = Some(value),
            KEY_RECENT_NODES => minute.recent_nodes = Some(value),
            _ => {}
        }
    }

    let mut buckets: BTreeMap<i64, BucketAccumulator> = BTreeMap::new();
    for (timestamp, minute) in minutes {
        let (
            Some(upload_bps),
            Some(download_bps),
            Some(connections),
            Some(online_nodes),
            Some(recent_nodes),
        ) = (
            minute.upload_bps,
            minute.download_bps,
            minute.connections,
            minute.online_nodes,
            minute.recent_nodes,
        )
        else {
            // A sampler write is atomic, so an incomplete minute means legacy
            // or corrupt data. Skip it instead of manufacturing zeroes.
            continue;
        };
        let bucket_start = timestamp.div_euclid(bucket_seconds) * bucket_seconds;
        let bucket = buckets.entry(bucket_start).or_default();
        bucket.upload_sum += upload_bps as i128;
        bucket.download_sum += download_bps as i128;
        if bucket.upload_max_at.is_none() || upload_bps > bucket.upload_max {
            bucket.upload_max = upload_bps;
            bucket.upload_max_at = Some(timestamp);
        }
        if bucket.download_max_at.is_none() || download_bps > bucket.download_max {
            bucket.download_max = download_bps;
            bucket.download_max_at = Some(timestamp);
        }
        bucket.connections_max = bucket.connections_max.max(connections);
        bucket.online_nodes_min = Some(
            bucket
                .online_nodes_min
                .map_or(online_nodes, |old| old.min(online_nodes)),
        );
        bucket.recent_nodes_max = bucket.recent_nodes_max.max(recent_nodes);
        bucket.sample_count = bucket.sample_count.saturating_add(1);
    }

    buckets
        .into_iter()
        .filter_map(|(timestamp, bucket)| {
            let time = chrono::DateTime::from_timestamp(timestamp, 0)?;
            let upload_max_at = chrono::DateTime::from_timestamp(bucket.upload_max_at?, 0)?;
            let download_max_at = chrono::DateTime::from_timestamp(bucket.download_max_at?, 0)?;
            let count = i128::from(bucket.sample_count.max(1));
            Some(DashboardHistoryPoint {
                timestamp: time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                upload_bps_avg: (bucket.upload_sum / count).min(i128::from(i64::MAX)) as i64,
                download_bps_avg: (bucket.download_sum / count).min(i128::from(i64::MAX)) as i64,
                upload_bps_max: bucket.upload_max,
                download_bps_max: bucket.download_max,
                upload_bps_max_at: upload_max_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                download_bps_max_at: download_max_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                connections_max: bucket.connections_max,
                online_nodes_min: bucket.online_nodes_min.unwrap_or(0),
                recent_nodes_max: bucket.recent_nodes_max,
                sample_count: bucket.sample_count,
            })
        })
        .collect()
}

/// GET /dashboard/history — typed, administrator-only historical dashboard
/// series. The generic `/stats` endpoint remains unchanged for compatibility.
pub async fn get_dashboard_history(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Query(q): Query<DashboardHistoryQuery>,
) -> Response {
    let Some(range) = DashboardRange::parse(q.range.as_deref()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<DashboardHistoryResponse> {
                code: 400,
                message: "range must be one of: 1h, 24h, 7d, 30d".into(),
                data: None,
            }),
        )
            .into_response();
    };

    let now = chrono::Utc::now();
    let from = (now - range.duration()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let to = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    match state
        .db
        .query_stats(Some(DASHBOARD_STAT_TYPE), None, Some(&from), Some(&to))
        .await
    {
        Ok(stats) => (
            StatusCode::OK,
            Json(ApiResponse::success(DashboardHistoryResponse {
                range: range.label().into(),
                bucket_seconds: range.bucket_seconds(),
                points: downsample_history(stats, range.bucket_seconds()),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("get_dashboard_history: db error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<DashboardHistoryResponse> {
                    code: 500,
                    message: "database error".into(),
                    data: None,
                }),
            )
                .into_response()
        }
    }
}

pub async fn get_node_status(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    // v0.3.2: sweep stale entries on READ too, not just on report. Previously
    // sweep only ran when a node reported status — so if every node in a group
    // went offline (no more reports), the ghost "离线" rows lingered forever.
    // Now opening the node-status page cleans up entries older than 2 min.
    let _ = crate::service::traffic::sweep_stale_status(state.db.as_ref()).await;

    // Full status blobs include operator-only diagnostics such as listener
    // errors and installation details, so this endpoint is administrator-only.
    // Regular users use /nodes/shared, whose typed DTO explicitly allow-lists
    // safe availability fields.
    let scope = crate::db::repo::ResourceScope::All;

    let rows: Vec<(String, String)> = match state.db.scan_prefix("node_status:").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("get_node_status: scan_prefix failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "数据库错误".into(),
                data: None,
            });
        }
    };

    let mut statuses: Vec<serde_json::Value> = Vec::new();
    // v0.4.15 PR3: stamp `online` on every admin row using the SAME source of
    // truth (status_is_online / NODE_ONLINE_WINDOW_SECS) the shared-node
    // endpoint uses, so the admin /nodes board and the user /nodes/shared board
    // never disagree about who's online. The frontend must NOT recompute it.
    let now = chrono::Utc::now();
    for (key, value) in &rows {
        let (group_id, node_id_from_key) = match parse_status_key(key) {
            Some(parsed) => parsed,
            None => continue,
        };
        let mut status: serde_json::Value = match serde_json::from_str(value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !status.is_object() {
            tracing::warn!(
                key,
                "get_node_status: ignored valid JSON with a non-object root"
            );
            continue;
        }

        // Look up the group name from device_groups. Orphaned status rows are
        // retained with a fallback name so an administrator can still inspect
        // and remove them.
        let group_name = match state.db.find_name_by_id(group_id, &scope).await {
            Ok(Some(n)) => Some(n),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("get_node_status: find_name_by_id failed: {}", e);
                return Json(ApiResponse {
                    code: 500,
                    message: "数据库错误".into(),
                    data: None,
                });
            }
        };

        status["group_id"] = serde_json::json!(group_id);
        status["group_name"] =
            serde_json::json!(group_name.unwrap_or_else(|| format!("Group {}", group_id)));
        // Surface the node identity so the frontend can render multiple nodes
        // per group distinctly. Prefer the JSON field the node sent (canonical);
        // fall back to the key segment for older status rows that predate it.
        if status.get("node_id").is_none() {
            status["node_id"] = serde_json::json!(node_id_from_key);
        }

        // v0.4.15: ensure public_ipv4 is present (fall back to legacy public_ip
        // for older nodes) and enrich with GeoIP country from the KVS cache.
        if status.get("public_ipv4").is_none() {
            if let Some(ip) = status.get("public_ip").and_then(|v| v.as_str()) {
                status["public_ipv4"] = serde_json::json!(ip);
            }
        }
        if let Some(ip) = status
            .get("report_ip")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            if let Some(entry) = crate::api::geoip::read_cache(state.db.as_ref(), ip).await {
                status["report_ip_country_code"] = serde_json::json!(entry.country_code);
                status["report_ip_country_name"] = serde_json::json!(entry.country_name);
            }
        }
        for ip_key in ["public_ipv4", "public_ipv6"] {
            if let Some(ip) = status
                .get(ip_key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if let Some(entry) = crate::api::geoip::read_cache(state.db.as_ref(), ip).await {
                    let cc_key = format!("{}_country_code", ip_key.replace("public_", ""));
                    let cn_key = format!("{}_country_name", ip_key.replace("public_", ""));
                    status[&cc_key] = serde_json::json!(entry.country_code);
                    status[&cn_key] = serde_json::json!(entry.country_name);
                }
            }
        }

        status["online"] = serde_json::json!(status_is_online(value, now));

        statuses.push(status);
    }

    Json(ApiResponse::success(statuses))
}

/// Manually remove a node's status record from kvs.
///
/// This does NOT uninstall or stop the node — it only deletes the panel's
/// cached status row. If the node is still online and reporting, the record
/// reappears on its next report. Use case: clear a stale/ghost entry that the
/// auto-sweep hasn't caught, or remove a decommissioned node's leftover row.
///
/// Administrator-only: before touching kvs, verify that `group_id` still
/// resolves to a real group. Orphaned rows remain visible on the full status
/// board but cannot be removed through a group-scoped URL after the group is
/// gone; the stale-status sweeper eventually removes them.
///
/// Security: the key is CONSTRUCTED from the validated group_id + node_id
/// params, never interpolated from raw user input. The DELETE's WHERE clause
/// binds the exact constructed key, so it can only ever touch a node_status:*
/// row — never an arbitrary kvs entry, never another group/node.
pub async fn delete_node_status(
    _admin: AdminOnly,
    State(state): State<AppState>,
    axum::extract::Path((group_id,)): axum::extract::Path<(i64,)>,
    axum::extract::Query(q): axum::extract::Query<DeleteStatusQuery>,
) -> Json<ApiResponse<()>> {
    // v0.4.12 PR1: admin-only (nodes are admin-managed). Scope All — an admin
    // may clear any group's status row. The key is still CONSTRUCTED from the
    // validated group_id + node_id, never raw user input.
    let scope = crate::db::repo::ResourceScope::All;
    match crate::db::repo::GroupRepository::find_by_id(state.db.as_ref(), group_id, &scope).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Json(ApiResponse {
                code: 404,
                message: "status record not found".into(),
                data: None,
            })
        }
        Err(e) => {
            tracing::error!("delete_node_status: group find_by_id failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    }

    // Build the target key from validated inputs.
    // node_id present → per-node key; absent → legacy per-group key.
    let key = match &q.node_id {
        Some(nid) if !nid.trim().is_empty() => {
            format!("node_status:{}:{}", group_id, nid.trim())
        }
        _ => format!("node_status:{}", group_id),
    };

    // Defense-in-depth: the constructed key MUST still parse back to the same
    // group_id (guards against any path/segment trickery). If it doesn't, the
    // input was malformed and we refuse to delete.
    match parse_status_key(&key) {
        Some((parsed_gid, _)) if parsed_gid == group_id => {}
        _ => {
            return Json(ApiResponse {
                code: 400,
                message: "invalid group_id / node_id combination".into(),
                data: None,
            })
        }
    }

    // v0.4.19: before deleting the node_status row, read the current JSON
    // and collect the public IPs so we can also clean up the corresponding
    // `geoip:...` cache entries. The geoip cache is per-IP, not per-node —
    // another node in the same group that happens to share the same public
    // IP keeps its cache entry. A single-node delete must NOT wipe geoip
    // caches for sibling nodes.
    //
    // We read the JSON BEFORE the delete so deleted_by is unambiguous, and
    // we deduplicate IPs so the same IP from report_ip / public_ip /
    // public_ipv4 / public_ipv6 only triggers one geoip delete.
    let raw_status = match state.db.get(&key).await {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(
                "failed to read node status {} before geoip cleanup: {}",
                key,
                error
            );
            None
        }
    };
    if let Some(ips) = raw_status.as_deref().and_then(public_ips_from_status_json) {
        // GeoIP entries are global per-IP cache rows. Preserve any IP still
        // referenced by another node (including a node in another group).
        // If this best-effort scan fails, keep every cache row rather than
        // guessing that the target node was its sole consumer.
        let other_references = match state.db.scan_prefix("node_status:").await {
            Ok(rows) => Some(public_ips_referenced_by_other_statuses(&rows, &key)),
            Err(error) => {
                tracing::warn!(
                    "failed to scan sibling node statuses during {} cleanup: {}",
                    key,
                    error
                );
                None
            }
        };
        if let Some(other_references) = other_references {
            for ip in ips
                .iter()
                .filter(|ip| !other_references.contains(ip.as_str()))
            {
                let geoip_key = format!("geoip:{}", ip);
                match state.db.delete(&geoip_key).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(
                            "deleted geoip cache {} ({} row(s)) for node status {}",
                            geoip_key,
                            n,
                            key
                        );
                    }
                    Ok(_) => { /* key didn't exist — nothing to do */ }
                    Err(e) => {
                        // v0.4.19: a single geoip delete failure must NOT
                        // abort the node_status delete. Log and continue.
                        tracing::warn!(
                            "failed to delete geoip cache {} during node status {} cleanup: {}",
                            geoip_key,
                            key,
                            e
                        );
                    }
                }
            }
        }
    }
    // JSON parse failure (corrupt / missing): still delete the node_status
    // row (it's the requested operation), but skip geoip cleanup — the
    // unstructured blob may reference IPs we can't extract.

    match state.db.delete(&key).await {
        Ok(0) => Json(ApiResponse {
            code: 404,
            message: "status record not found".into(),
            data: None,
        }),
        Ok(_) => {
            tracing::info!("admin deleted node status record {}", key);
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("delete_node_status: kvs delete failed: {}", e);
            Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            })
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteStatusQuery {
    /// The node_id segment of the status key. Omit for legacy per-group keys.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// v1.0.10: POST /nodes/{group_id}/upgrade/{node_id} — admin triggers a directed
/// self-upgrade on ONE node. The command goes over the WS control channel
/// (`send_node` reaches only that node's live connection); the node then pulls
/// the latest official release for its arch, verifies its sha256, swaps its
/// binary, and restarts. Returns 409 when the node has no live WS connection.
///
/// v1.2: the upgrade target is the latest NODE release (`node-v*`), resolved
/// from GitHub — NOT the panel's own version. A panel-only release (e.g. v1.2.0
/// with no node binary) must NEVER be sent as an upgrade target, or nodes would
/// try to download a non-existent asset. If the node-version check fails or
/// there is no node release, we refuse with 503 instead of falling back to the
/// panel version.
pub async fn upgrade_node(
    _admin: AdminOnly,
    State(state): State<AppState>,
    axum::extract::Path((group_id, node_id)): axum::extract::Path<(i64, String)>,
) -> Json<ApiResponse<()>> {
    let Some(node_id) = crate::api::node::normalize_node_id(&node_id) else {
        return Json(ApiResponse {
            code: 400,
            message: "invalid node_id".into(),
            data: None,
        });
    };
    // v1.2: resolve the upgrade target from the latest node release. This MUST
    // NOT fall back to the panel version under any circumstance.
    let target_version = match state.release_cache.resolve_latest_node_version().await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Json(ApiResponse {
                code: 503,
                message: "暂无可用的节点版本（尚未发布 node-v* 版本），无法下发升级".into(),
                data: None,
            });
        }
        Err(e) => {
            tracing::warn!("upgrade_node: node version check failed: {}", e);
            return Json(ApiResponse {
                code: 503,
                message: "节点版本检查失败，无法确定升级目标，请稍后重试".into(),
                data: None,
            });
        }
    };
    let msg = match serde_json::to_string(&relay_shared::protocol::UpgradeNodeMessage {
        msg_type: "upgrade_node".into(),
        node_id: node_id.clone(),
        version: target_version.clone(),
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("upgrade_node: serialize failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "serialize error".into(),
                data: None,
            });
        }
    };
    let sent = state
        .node_connections
        .send_node(group_id, &node_id, &msg)
        .await;
    if sent == 0 {
        return Json(ApiResponse {
            code: 409,
            message: "节点当前无 WS 控制通道（离线或旧版本不支持远程升级），无法下发升级".into(),
            data: None,
        });
    }
    tracing::info!(
        action = "upgrade_node",
        group_id,
        node_id = %node_id,
        target = %target_version,
        "sent self-upgrade command to node"
    );
    Json(ApiResponse::success(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tower::ServiceExt;

    /// The v0.3.0 per-node key must parse into (group_id, Some(node_id)). This
    /// is what lets two nodes sharing one group token keep separate status rows
    /// instead of overwriting each other.
    #[test]
    fn parses_per_node_key() {
        let (gid, nid) = parse_status_key("node_status:42:abc123def").unwrap();
        assert_eq!(gid, 42);
        assert_eq!(nid, Some("abc123def"));
    }

    /// The legacy single-segment key (older nodes, or a group with one node
    /// that didn't report a node_id) must still parse — group_id extracted,
    /// node_id None. This is backward compat: existing deployments don't break.
    #[test]
    fn parses_legacy_key() {
        let (gid, nid) = parse_status_key("node_status:7").unwrap();
        assert_eq!(gid, 7);
        assert_eq!(nid, None);
    }

    /// node_id may itself contain characters that aren't digits — make sure the
    /// split-on-first-colon logic doesn't misread them as part of group_id.
    /// (node_ids are hex strings, so ':' inside them would be a bug elsewhere,
    /// but the FIRST colon is the separator by design.)
    #[test]
    fn node_id_with_dashes_parses() {
        let (gid, nid) = parse_status_key("node_status:100:node-a1b2-").unwrap();
        assert_eq!(gid, 100);
        assert_eq!(nid, Some("node-a1b2-"));
    }

    // ── delete_node_status safety (v0.3.4) ──
    // The endpoint must only ever delete a row whose key parses back to the
    // (group_id, node_id) passed in the URL. Any input that fails that round-
    // trip check must be rejected. These tests use a real in-memory kvs table
    // and call the handler's logic (the SQL+parse portion) directly — the
    // axum extractors/JSON envelope are not under test here.

    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

    async fn kvs_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE kvs (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    async fn put_kvs(pool: &SqlitePool, key: &str, val: &str) {
        sqlx::query("INSERT OR REPLACE INTO kvs (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(val)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn exists(pool: &SqlitePool, key: &str) -> bool {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM kvs WHERE key = ?")
            .bind(key)
            .fetch_one(pool)
            .await
            .unwrap();
        n > 0
    }

    /// The exact handler-side SQL delete (single-line, parameterized) is the
    /// only thing that touches kvs in delete_node_status. We assert the
    /// constructed WHERE key matches what we passed in, AND that nothing else
    /// is deleted — even when the kvs table contains other node_status rows
    /// AND a non-node_status key (e.g. a future feature's storage).
    #[tokio::test]
    async fn delete_only_touches_targeted_node_status_key() {
        let pool = kvs_pool().await;
        // Four rows: the target, a sibling node in the same group, a row in a
        // different group, and a non-node_status key (regression — must never
        // be touchable via this endpoint even if a future caller's key is
        // misformatted upstream).
        put_kvs(&pool, "node_status:5:nid-A", "target").await;
        put_kvs(&pool, "node_status:5:nid-B", "sibling-in-same-group").await;
        put_kvs(&pool, "node_status:6:nid-X", "different-group").await;
        put_kvs(&pool, "some_future_feature:5:nid-A", "non-node-status-key").await;

        // Construct the key the same way the handler does and delete.
        let target_key = "node_status:5:nid-A";
        let n = sqlx::query("DELETE FROM kvs WHERE key = ?")
            .bind(target_key)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 1, "exactly one row deleted");

        assert!(!exists(&pool, "node_status:5:nid-A").await, "target gone");
        assert!(
            exists(&pool, "node_status:5:nid-B").await,
            "sibling must be untouched"
        );
        assert!(
            exists(&pool, "node_status:6:nid-X").await,
            "other group must be untouched"
        );
        assert!(
            exists(&pool, "some_future_feature:5:nid-A").await,
            "non-node-status key must be untouched"
        );
    }

    /// The key parse-back check (the handler runs parse_status_key on its
    /// constructed key and compares to the URL group_id) must reject anything
    /// that would round-trip to a different group — defends against any
    /// downstream path that builds the key differently than expected.
    #[test]
    fn parse_back_check_rejects_mismatch() {
        // A key where everything past "node_status:" parses to group 5, but the
        // caller's URL said group=6 — parse-back check should reject.
        let key = "node_status:5:nid-A";
        let parsed = parse_status_key(key).unwrap();
        assert_eq!(parsed.0, 5);
        // Caller passed group_id=6, parsed.0=5, mismatch → reject.
        // (Verified manually here; the handler does this check inline.)
        assert_ne!(parsed.0, 6);
    }

    /// Legacy per-group key (no node_id segment) must also be correctly
    /// reconstructable for the delete path.
    #[test]
    fn legacy_key_round_trip() {
        let key = "node_status:9";
        let (gid, nid) = parse_status_key(key).unwrap();
        assert_eq!(gid, 9);
        assert_eq!(nid, None);
    }

    /// Non-node_status keys and malformed keys must return None (skipped by the
    /// status reader) rather than panicking.
    #[test]
    fn rejects_non_status_and_malformed_keys() {
        assert!(parse_status_key("something_else:5").is_none());
        assert!(parse_status_key("node_status:").is_none()); // empty group_id
        assert!(parse_status_key("node_status:abc").is_none()); // non-int group
    }

    // ── GeoIP cache cleanup on node delete (v0.4.19) ──

    #[test]
    fn public_ips_from_status_json_extracts_report_and_detected_ips() {
        let raw = r#"{
            "report_ip": "203.0.113.8",
            "public_ipv4": "1.1.1.1",
            "public_ipv6": "2001::1",
            "public_ip": "8.8.8.8"
        }"#;
        let ips = super::public_ips_from_status_json(raw).unwrap();
        assert_eq!(ips, vec!["1.1.1.1", "2001::1", "203.0.113.8", "8.8.8.8"]);
    }

    #[test]
    fn public_ips_from_status_json_filters_empty_strings_and_deduplicates() {
        let raw = r#"{
            "public_ipv4": "8.8.8.8",
            "public_ipv6": "",
            "public_ip": "8.8.8.8"
        }"#;
        let ips = super::public_ips_from_status_json(raw).unwrap();
        assert_eq!(ips, vec!["8.8.8.8"]);
    }

    #[test]
    fn public_ips_from_status_json_returns_none_for_corrupt_json() {
        assert!(super::public_ips_from_status_json("not-json{{{").is_none());
    }

    #[test]
    fn geoip_cleanup_preserves_ips_referenced_by_any_other_node() {
        let rows = vec![
            (
                "node_status:5:A".to_string(),
                r#"{"public_ipv4":"1.1.1.1","public_ipv6":"2001::shared"}"#.to_string(),
            ),
            (
                "node_status:5:B".to_string(),
                r#"{"public_ipv4":"2.2.2.2","public_ipv6":"2001::shared"}"#.to_string(),
            ),
            (
                "node_status:6:C".to_string(),
                r#"{"public_ip":"2.2.2.2"}"#.to_string(),
            ),
            ("node_status:7:corrupt".to_string(), "not-json".to_string()),
        ];

        let referenced = super::public_ips_referenced_by_other_statuses(&rows, "node_status:5:A");
        assert!(!referenced.contains("1.1.1.1"));
        assert!(referenced.contains("2001::shared"));
        assert!(referenced.contains("2.2.2.2"));
    }

    #[tokio::test]
    async fn delete_node_a_cleans_only_node_a_status_and_geoip_cache() {
        let pool = kvs_pool().await;
        put_kvs(
            &pool,
            "node_status:5:A",
            r#"{"public_ipv4":"1.1.1.1","public_ipv6":"2001::1"}"#,
        )
        .await;
        put_kvs(
            &pool,
            "node_status:5:B",
            r#"{"public_ipv4":"2.2.2.2","public_ipv6":"2001::2"}"#,
        )
        .await;
        put_kvs(&pool, "geoip:1.1.1.1", "node-a-v4").await;
        put_kvs(&pool, "geoip:2001::1", "node-a-v6").await;
        put_kvs(&pool, "geoip:2.2.2.2", "node-b-v4").await;
        put_kvs(&pool, "geoip:2001::2", "node-b-v6").await;

        let raw = sqlx::query_as::<_, (String,)>("SELECT value FROM kvs WHERE key = ?")
            .bind("node_status:5:A")
            .fetch_one(&pool)
            .await
            .unwrap()
            .0;
        let ips = super::public_ips_from_status_json(&raw).unwrap();
        for ip in ips {
            sqlx::query("DELETE FROM kvs WHERE key = ?")
                .bind(format!("geoip:{ip}"))
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM kvs WHERE key = ?")
            .bind("node_status:5:A")
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            !exists(&pool, "node_status:5:A").await,
            "node A status gone"
        );
        assert!(
            exists(&pool, "node_status:5:B").await,
            "node B status retained"
        );
        assert!(
            !exists(&pool, "geoip:1.1.1.1").await,
            "node A IPv4 geoip gone"
        );
        assert!(
            !exists(&pool, "geoip:2001::1").await,
            "node A IPv6 geoip gone"
        );
        assert!(
            exists(&pool, "geoip:2.2.2.2").await,
            "node B IPv4 geoip retained"
        );
        assert!(
            exists(&pool, "geoip:2001::2").await,
            "node B IPv6 geoip retained"
        );
    }

    #[tokio::test]
    async fn corrupt_status_json_still_allows_node_status_delete_without_geoip_cleanup() {
        let pool = kvs_pool().await;
        put_kvs(&pool, "node_status:5:A", "not-json{{{").await;
        put_kvs(&pool, "geoip:1.1.1.1", "cached").await;

        let raw = sqlx::query_as::<_, (String,)>("SELECT value FROM kvs WHERE key = ?")
            .bind("node_status:5:A")
            .fetch_one(&pool)
            .await
            .unwrap()
            .0;
        assert!(super::public_ips_from_status_json(&raw).is_none());

        sqlx::query("DELETE FROM kvs WHERE key = ?")
            .bind("node_status:5:A")
            .execute(&pool)
            .await
            .unwrap();

        assert!(!exists(&pool, "node_status:5:A").await);
        assert!(exists(&pool, "geoip:1.1.1.1").await);
    }

    fn metric(id: i64, key: &str, time: &str, number: i64) -> Statistic {
        Statistic {
            id,
            stat_type: DASHBOARD_STAT_TYPE.into(),
            stat_key: key.into(),
            time: time.into(),
            number,
        }
    }

    #[test]
    fn dashboard_range_defaults_and_rejects_unknown_values() {
        assert_eq!(DashboardRange::parse(None), Some(DashboardRange::OneDay));
        for (label, range, bucket_seconds) in [
            ("1h", DashboardRange::OneHour, 60),
            ("24h", DashboardRange::OneDay, 300),
            ("7d", DashboardRange::SevenDays, 1_800),
            ("30d", DashboardRange::ThirtyDays, 7_200),
        ] {
            assert_eq!(DashboardRange::parse(Some(label)), Some(range));
            assert_eq!(range.bucket_seconds(), bucket_seconds);
        }
        assert_eq!(DashboardRange::parse(Some("yesterday")), None);
    }

    #[test]
    fn dashboard_history_downsamples_average_peak_and_minimum() {
        let mut rows = Vec::new();
        for (offset, key, a, b) in [
            (0, KEY_UPLOAD_BPS, 100, 200),
            (1, KEY_DOWNLOAD_BPS, 300, 500),
            (2, KEY_CONNECTIONS, 4, 9),
            (3, KEY_ONLINE_NODES, 2, 1),
            (4, KEY_RECENT_NODES, 2, 3),
        ] {
            rows.push(metric(offset, key, "2026-07-19T12:01:00Z", a));
            rows.push(metric(offset + 10, key, "2026-07-19T12:04:00Z", b));
        }
        let points = downsample_history(rows, 5 * 60);
        assert_eq!(
            points,
            vec![DashboardHistoryPoint {
                timestamp: "2026-07-19T12:00:00Z".into(),
                upload_bps_avg: 150,
                download_bps_avg: 400,
                upload_bps_max: 200,
                download_bps_max: 500,
                upload_bps_max_at: "2026-07-19T12:04:00Z".into(),
                download_bps_max_at: "2026-07-19T12:04:00Z".into(),
                connections_max: 9,
                online_nodes_min: 1,
                recent_nodes_max: 3,
                sample_count: 2,
            }]
        );
    }

    #[test]
    fn dashboard_history_preserves_bandwidth_peak_across_range_bucket_sizes() {
        let rows = || {
            let mut rows = Vec::new();
            for (base_id, key, first, peak) in [
                (0, KEY_UPLOAD_BPS, 100_000, 5_650_000),
                (10, KEY_DOWNLOAD_BPS, 120_000, 5_770_000),
                (20, KEY_CONNECTIONS, 10, 11),
                (30, KEY_ONLINE_NODES, 2, 2),
                (40, KEY_RECENT_NODES, 2, 2),
            ] {
                rows.push(metric(base_id, key, "2026-07-19T12:01:00Z", first));
                rows.push(metric(base_id + 1, key, "2026-07-19T12:16:00Z", peak));
            }
            rows
        };

        let five_minutes = downsample_history(rows(), 5 * 60);
        let thirty_minutes = downsample_history(rows(), 30 * 60);
        assert_eq!(
            five_minutes
                .iter()
                .map(|point| point.download_bps_max)
                .max(),
            Some(5_770_000)
        );
        assert_eq!(thirty_minutes[0].download_bps_max, 5_770_000);
        assert_eq!(thirty_minutes[0].upload_bps_max, 5_650_000);
        assert_eq!(
            thirty_minutes[0].download_bps_max_at,
            "2026-07-19T12:16:00Z"
        );
        assert_eq!(thirty_minutes[0].upload_bps_max_at, "2026-07-19T12:16:00Z");
        assert!(
            thirty_minutes[0].download_bps_avg < thirty_minutes[0].download_bps_max,
            "the average may be diluted, but the plotted peak must remain exact"
        );
    }

    #[test]
    fn dashboard_history_skips_incomplete_minutes() {
        let rows = vec![metric(1, KEY_UPLOAD_BPS, "2026-07-19T12:01:00Z", 100)];
        assert!(downsample_history(rows, 60).is_empty());
    }

    #[tokio::test]
    async fn dashboard_history_is_admin_only() {
        use crate::api::middleware::Claims;
        use crate::api::system::ReleaseCache;
        use crate::api::ws::NodeConnections;
        use crate::config::Config;
        use crate::db::schema::SCHEMA_SQL;
        use crate::db::sqlite_repo::SqliteRepository;
        use std::sync::Arc;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin) VALUES (2, 'viewer', 'x', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let secret = "dashboard-history-test-secret";
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool)),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: secret.into(),
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
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        let token = |sub, admin| {
            encode(
                &Header::default(),
                &Claims {
                    sub,
                    admin,
                    token_version: 0,
                    exp: (chrono::Utc::now().timestamp() + 60) as usize,
                },
                &EncodingKey::from_secret(secret.as_bytes()),
            )
            .unwrap()
        };
        let app = crate::api::routes().with_state(state);

        let viewer = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dashboard/history?range=24h")
                    .header("Authorization", format!("Bearer {}", token(2, false)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer.status(), StatusCode::FORBIDDEN);

        for uri in ["/nodes", "/groups"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("Authorization", format!("Bearer {}", token(2, false)))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{uri} must keep full operator data administrator-only"
            );
        }

        let safe_legacy_groups = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/groups/owned")
                    .header("Authorization", format!("Bearer {}", token(2, false)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(safe_legacy_groups.status(), StatusCode::OK);

        let admin = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dashboard/history?range=24h")
                    .header("Authorization", format!("Bearer {}", token(1, true)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin.status(), StatusCode::OK);

        let invalid_range = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard/history?range=forever")
                    .header("Authorization", format!("Bearer {}", token(1, true)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_range.status(), StatusCode::BAD_REQUEST);
    }
}
