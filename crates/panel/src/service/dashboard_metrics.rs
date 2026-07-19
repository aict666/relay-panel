//! Persistent minute-level metrics for the administrator dashboard.
//!
//! Node status is stored as short-lived JSON in KVS. This sampler turns the
//! live fleet snapshot into a small set of global time series so the dashboard
//! survives browser refreshes and panel restarts without retaining per-node
//! payloads or sensitive addresses.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Timelike, Utc};

use crate::db::repo::Repository;

pub(crate) const DASHBOARD_STAT_TYPE: &str = "dashboard_global";
pub(crate) const KEY_UPLOAD_BPS: &str = "upload_bps";
pub(crate) const KEY_DOWNLOAD_BPS: &str = "download_bps";
pub(crate) const KEY_CONNECTIONS: &str = "connections";
pub(crate) const KEY_ONLINE_NODES: &str = "online_nodes";
pub(crate) const KEY_RECENT_NODES: &str = "recent_nodes";

/// The single backend source of truth for node availability.
pub(crate) const NODE_ONLINE_WINDOW_SECS: i64 = 30;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const CLEANUP_EVERY_TICKS: u64 = 60;
const RETENTION_DAYS: i64 = 30;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GlobalSnapshot {
    pub upload_bps: i64,
    pub download_bps: i64,
    pub connections: i64,
    pub online_nodes: i64,
    pub recent_nodes: i64,
}

/// Extract `last_seen` (RFC3339) from a stored node-status JSON value.
pub(crate) fn status_last_seen(value: &str) -> Option<DateTime<Utc>> {
    let v: serde_json::Value = serde_json::from_str(value).ok()?;
    let s = v.get("last_seen").and_then(|s| s.as_str())?;
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// A node is online when its most recent report is within the shared window.
pub(crate) fn status_is_online(value: &str, now: DateTime<Utc>) -> bool {
    status_last_seen(value)
        .map(|t| (now - t).num_seconds() <= NODE_ONLINE_WINDOW_SECS)
        .unwrap_or(false)
}

fn status_is_recent(value: &str, now: DateTime<Utc>) -> bool {
    status_last_seen(value)
        .map(|t| (now - t).num_seconds() <= crate::service::traffic::STALE_STATUS_THRESHOLD_SECS)
        .unwrap_or(false)
}

fn non_negative_i64(v: &serde_json::Value, key: &str) -> i64 {
    match v.get(key) {
        Some(value) => value
            .as_u64()
            .map(|n| n.min(i64::MAX as u64) as i64)
            .or_else(|| value.as_i64().filter(|n| *n >= 0))
            .unwrap_or(0),
        None => 0,
    }
}

/// Aggregate the same live fields as the dashboard's group roll-up. Invalid
/// JSON is ignored exactly as the `/nodes` handler ignores it; rows reported
/// within the two-minute retention window count as recent, while only rows in
/// the shared 30-second online window contribute rates and connections.
pub(crate) fn aggregate_status_rows(
    rows: &[(String, String)],
    now: DateTime<Utc>,
) -> GlobalSnapshot {
    let mut snapshot = GlobalSnapshot::default();
    for (_, raw) in rows {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        if !status_is_recent(raw, now) {
            continue;
        }
        snapshot.recent_nodes = snapshot.recent_nodes.saturating_add(1);
        if !status_is_online(raw, now) {
            continue;
        }
        snapshot.online_nodes = snapshot.online_nodes.saturating_add(1);
        snapshot.upload_bps = snapshot
            .upload_bps
            .saturating_add(non_negative_i64(&value, KEY_UPLOAD_BPS));
        snapshot.download_bps = snapshot
            .download_bps
            .saturating_add(non_negative_i64(&value, KEY_DOWNLOAD_BPS));
        snapshot.connections = snapshot
            .connections
            .saturating_add(non_negative_i64(&value, KEY_CONNECTIONS));
    }
    snapshot
}

fn minute_bucket(now: DateTime<Utc>) -> String {
    now.with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) async fn sample_once(
    db: &dyn Repository,
    now: DateTime<Utc>,
) -> Result<GlobalSnapshot, crate::db::error::DbError> {
    // Match `/nodes`: remove reports older than the shared two-minute grace
    // window before counting the current fleet. This also keeps ghost rows
    // from inflating history when nobody has the node-status page open.
    crate::service::traffic::sweep_stale_status_at(db, now).await?;
    let rows = db.scan_prefix("node_status:").await?;
    let snapshot = aggregate_status_rows(&rows, now);
    let values = [
        (KEY_UPLOAD_BPS, snapshot.upload_bps),
        (KEY_DOWNLOAD_BPS, snapshot.download_bps),
        (KEY_CONNECTIONS, snapshot.connections),
        (KEY_ONLINE_NODES, snapshot.online_nodes),
        (KEY_RECENT_NODES, snapshot.recent_nodes),
    ];
    db.upsert_stats(DASHBOARD_STAT_TYPE, &minute_bucket(now), &values)
        .await?;
    Ok(snapshot)
}

async fn cleanup(db: &dyn Repository, now: DateTime<Utc>) {
    let cutoff = minute_bucket(now - chrono::Duration::days(RETENTION_DAYS));
    match db.delete_stats_before(DASHBOARD_STAT_TYPE, &cutoff).await {
        Ok(n) if n > 0 => tracing::info!("dashboard metrics: removed {} expired row(s)", n),
        Ok(_) => {}
        Err(e) => tracing::error!("dashboard metrics cleanup failed: {}", e),
    }
}

/// Start the persistent sampler. `tokio::time::interval` ticks immediately, so
/// a fresh deployment gets its first point without waiting a full minute.
pub fn spawn(db: Arc<dyn Repository>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut tick_count = 0_u64;
        tracing::info!(
            "dashboard metrics sampler started (tick {}s, retention {}d)",
            SAMPLE_INTERVAL.as_secs(),
            RETENTION_DAYS
        );
        loop {
            ticker.tick().await;
            let now = Utc::now();
            match sample_once(db.as_ref(), now).await {
                Ok(sample) => tracing::debug!(
                    "dashboard metrics: up={} down={} connections={} nodes={}/{}",
                    sample.upload_bps,
                    sample.download_bps,
                    sample.connections,
                    sample.online_nodes,
                    sample.recent_nodes
                ),
                Err(e) => tracing::error!("dashboard metrics sample failed: {}", e),
            }
            if tick_count.is_multiple_of(CLEANUP_EVERY_TICKS) {
                cleanup(db.as_ref(), now).await;
            }
            tick_count = tick_count.wrapping_add(1);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{KvsRepository, StatisticsRepository};
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    fn status(last_seen: &str, upload: i64, download: i64, connections: i64) -> String {
        serde_json::json!({
            "last_seen": last_seen,
            "upload_bps": upload,
            "download_bps": download,
            "connections": connections,
        })
        .to_string()
    }

    #[test]
    fn aggregates_only_online_valid_rows() {
        let now = DateTime::parse_from_rfc3339("2026-07-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let rows = vec![
            (
                "node_status:1:a".into(),
                status("2026-07-19T11:59:50Z", 100, 200, 3),
            ),
            (
                "node_status:1:b".into(),
                status("2026-07-19T11:58:00Z", 999, 999, 9),
            ),
            ("node_status:2:bad".into(), "not json".into()),
            ("node_status:2:missing-time".into(), "{}".into()),
        ];
        assert_eq!(
            aggregate_status_rows(&rows, now),
            GlobalSnapshot {
                upload_bps: 100,
                download_bps: 200,
                connections: 3,
                online_nodes: 1,
                recent_nodes: 2,
            }
        );
    }

    #[test]
    fn negative_metrics_are_zero_and_addition_saturates() {
        let now = DateTime::parse_from_rfc3339("2026-07-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let rows = vec![
            (
                "node_status:1:a".into(),
                status("2026-07-19T12:00:00Z", -1, -2, -3),
            ),
            (
                "node_status:1:b".into(),
                status("2026-07-19T12:00:00Z", i64::MAX, i64::MAX, i64::MAX),
            ),
            (
                "node_status:1:c".into(),
                status("2026-07-19T12:00:00Z", 1, 1, 1),
            ),
        ];
        let sample = aggregate_status_rows(&rows, now);
        assert_eq!(sample.upload_bps, i64::MAX);
        assert_eq!(sample.download_bps, i64::MAX);
        assert_eq!(sample.connections, i64::MAX);
        assert_eq!(sample.online_nodes, 3);
    }

    #[tokio::test]
    async fn sample_persists_five_idempotent_series_rows() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        let now = DateTime::parse_from_rfc3339("2026-07-19T12:00:30Z")
            .unwrap()
            .with_timezone(&Utc);
        db.set(
            "node_status:1:a",
            &status("2026-07-19T12:00:20Z", 100, 200, 3),
        )
        .await
        .unwrap();

        sample_once(&db, now).await.unwrap();
        sample_once(&db, now).await.unwrap();
        let rows = db
            .query_stats(Some(DASHBOARD_STAT_TYPE), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            5,
            "repeating one minute must upsert, not append"
        );
        assert_eq!(
            rows.iter()
                .find(|r| r.stat_key == KEY_UPLOAD_BPS)
                .unwrap()
                .number,
            100
        );
    }

    #[tokio::test]
    async fn cleanup_keeps_only_the_last_thirty_days() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        db.upsert_stats(
            DASHBOARD_STAT_TYPE,
            "2026-06-18T12:00:00Z",
            &[(KEY_UPLOAD_BPS, 1)],
        )
        .await
        .unwrap();
        db.upsert_stats(
            DASHBOARD_STAT_TYPE,
            "2026-06-20T12:00:00Z",
            &[(KEY_UPLOAD_BPS, 2)],
        )
        .await
        .unwrap();

        let now = DateTime::parse_from_rfc3339("2026-07-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        cleanup(&db, now).await;
        let rows = db
            .query_stats(Some(DASHBOARD_STAT_TYPE), None, None, None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].number, 2);
    }
}
