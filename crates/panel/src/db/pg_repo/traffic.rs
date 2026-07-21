use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::protocol::TrafficEntry;

// ── TrafficRepository ──
//
// Same all-or-nothing batch contract as SQLite (see sqlite_repo/traffic.rs).
// PostgreSQL READ COMMITTED takes a fresh snapshot for each statement, so the
// validation SELECT and later UPDATE do not share one immutable snapshot.
// The writes therefore use `traffic_used = traffic_used + delta`: PostgreSQL's
// row locks serialize concurrent updates and each writer adds to the latest
// committed value instead of overwriting another node's report.
#[async_trait]
impl TrafficRepository for PgRepository {
    async fn apply_traffic_batch(
        &self,
        group_id: i64,
        entries: &[TrafficEntry],
    ) -> Result<Vec<TrafficEntryResult>, DbError> {
        let mut tx = self.pool.begin().await?;

        // ── v1.0.8: read this group's billing rate once for the whole batch
        // (every entry in a batch is for the SAME group_id). rate lives on
        // device_groups; users are CHARGED real * rate (rounded) while
        // forward_rules keeps real bytes. Missing group → rate=1.0 (defensive;
        // its rules will be rejected as Unavailable below anyway). ──
        let rate: f64 = sqlx::query_scalar("SELECT rate FROM device_groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten()
            .unwrap_or(1.0);
        if !(0.1..=100.0).contains(&rate) {
            let _ = tx.rollback().await;
            tracing::error!(
                "traffic_batch: group {} has out-of-range rate {} (expected 0.1..=100)",
                group_id,
                rate
            );
            return Ok(vec![TrafficEntryResult::Overflow]);
        }

        // ── Pass 1: validate u64→i64 per entry + aggregate duplicate rule_ids
        // into one per-rule delta (so the cumulative overflow check sees the
        // true batch total, not a per-row slice). ──
        let mut rule_delta: std::collections::HashMap<i64, (u64, u64)> =
            std::collections::HashMap::new();
        for entry in entries {
            if entry.upload > i64::MAX as u64 || entry.download > i64::MAX as u64 {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Overflow]);
            }
            let e = rule_delta.entry(entry.rule_id).or_insert((0, 0));
            e.0 = match e.0.checked_add(entry.upload) {
                Some(v) => v,
                None => {
                    let _ = tx.rollback().await;
                    return Ok(vec![TrafficEntryResult::Overflow]);
                }
            };
            e.1 = match e.1.checked_add(entry.download) {
                Some(v) => v,
                None => {
                    let _ = tx.rollback().await;
                    return Ok(vec![TrafficEntryResult::Overflow]);
                }
            };
        }

        // ── Pass 2: ownership + existing-value resolution.
        // SINGLE query per distinct rule_id, gated by the current entry or a
        // durable retired-entry lease created during a preset-tunnel move. Lease
        // expiry, rather than a later pause/ban/unshare/disable, is the accounting
        // cutoff so already-accepted bytes can still be flushed. A miss =
        // "not available" (missing OR foreign); NO second existence query (that
        // was the rule-id oracle). Reason logged server-side only.
        struct Resolved {
            rule_id: i64,
            uid: i64,
            real_delta: i64,
            /// v1.0.8: billed bytes charged to the USER = round((up+down) * rate).
            /// Separate from delta_up/delta_down (real bytes for the rule).
            billed_delta: i64,
        }
        let mut resolved: Vec<Resolved> = Vec::with_capacity(rule_delta.len());
        let mut user_delta: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
        for (rule_id, (dup, ddown)) in &rule_delta {
            let rule_delta_sum = match dup.checked_add(*ddown) {
                Some(v) if v <= i64::MAX as u64 => v as i64,
                _ => {
                    let _ = tx.rollback().await;
                    return Ok(vec![TrafficEntryResult::Overflow]);
                }
            };
            // Resolve ownership first. Totals are checked again only after all
            // affected user/rule rows have been locked in deterministic order.
            let row: Option<(i64, i64)> = sqlx::query_as(
                "SELECT fr.id, fr.uid \
                 FROM forward_rules fr \
                 JOIN users u ON u.id = fr.uid \
                 WHERE fr.id = $1 AND (fr.device_group_in = $2 OR EXISTS( \
                   SELECT 1 FROM forward_rule_retired_entries re \
                   WHERE re.rule_id=fr.id AND re.device_group_id=$2 \
                     AND re.expires_at>=EXTRACT(EPOCH FROM now())::BIGINT))",
            )
            .bind(rule_id)
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((rid, uid)) = row else {
                tracing::warn!(
                    "traffic_batch: rule {} not available to group {} \
                     (missing or foreign) — rejecting batch",
                    rule_id,
                    group_id
                );
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Unavailable]);
            };
            // v1.0.8: billed delta charged to the user = round(real * rate).
            let billed_delta = if let Some(delta) =
                crate::service::traffic::billed_traffic_delta(rule_delta_sum, rate)
            {
                delta
            } else {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Overflow]);
            };
            // The batch delta itself must fit even before it is added to the
            // locked current total below.
            let cur_user_delta = *user_delta.get(&uid).unwrap_or(&0);
            let new_user_delta = match cur_user_delta.checked_add(billed_delta) {
                Some(v) => v,
                None => {
                    let _ = tx.rollback().await;
                    return Ok(vec![TrafficEntryResult::Overflow]);
                }
            };
            user_delta.insert(uid, new_user_delta);
            resolved.push(Resolved {
                rule_id: rid,
                uid,
                real_delta: rule_delta_sum,
                billed_delta,
            });
        }

        // ── Pass 3: lock + revalidate. Every transaction that changes both
        // user and rule traffic (including admin reset) uses user -> rule.
        // Sorting each domain also prevents two multi-user batches from taking
        // the same rows in opposite HashMap iteration order. ──
        resolved.sort_unstable_by_key(|row| row.rule_id);
        let mut user_ids: Vec<i64> = user_delta.keys().copied().collect();
        user_ids.sort_unstable();
        for uid in &user_ids {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                    .bind(uid)
                    .fetch_optional(&mut *tx)
                    .await?;
            if exists.is_none() {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Unavailable]);
            }
        }
        for row in &resolved {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT id FROM forward_rules WHERE id = $1 FOR UPDATE")
                    .bind(row.rule_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if exists.is_none() {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Unavailable]);
            }
        }

        let mut checked_user_delta: std::collections::HashMap<i64, i64> =
            std::collections::HashMap::new();
        for row in &resolved {
            let current: Option<(i64, i64, i64)> = sqlx::query_as(
                "SELECT fr.uid, fr.traffic_used, u.traffic_used \
                 FROM forward_rules fr JOIN users u ON u.id=fr.uid \
                 WHERE fr.id=$1 AND (fr.device_group_in=$2 OR EXISTS( \
                   SELECT 1 FROM forward_rule_retired_entries re \
                   WHERE re.rule_id=fr.id AND re.device_group_id=$2 \
                     AND re.expires_at>=EXTRACT(EPOCH FROM now())::BIGINT))",
            )
            .bind(row.rule_id)
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((current_uid, rule_used, user_used)) = current else {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Unavailable]);
            };
            if current_uid != row.uid {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Unavailable]);
            }
            if rule_used.checked_add(row.real_delta).is_none() {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Overflow]);
            }
            let prior = *checked_user_delta.get(&row.uid).unwrap_or(&0);
            let next = match prior.checked_add(row.billed_delta) {
                Some(value) => value,
                None => {
                    let _ = tx.rollback().await;
                    return Ok(vec![TrafficEntryResult::Overflow]);
                }
            };
            if user_used.checked_add(next).is_none() {
                let _ = tx.rollback().await;
                return Ok(vec![TrafficEntryResult::Overflow]);
            }
            checked_user_delta.insert(row.uid, next);
        }

        // ── Pass 4: apply real rule bytes, then one aggregated billed update
        // per user. Rows remain locked from pass 3, so these increments cannot
        // cross a reset or another report between validation and commit. ──
        for r in &resolved {
            sqlx::query("UPDATE forward_rules SET traffic_used = traffic_used + $1 WHERE id = $2")
                .bind(r.real_delta)
                .bind(r.rule_id)
                .execute(&mut *tx)
                .await?;
        }
        for uid in user_ids {
            let billed_delta = checked_user_delta.get(&uid).copied().unwrap_or(0);
            sqlx::query("UPDATE users SET traffic_used = traffic_used + $1 WHERE id = $2")
                .bind(billed_delta)
                .bind(uid)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(vec![TrafficEntryResult::Ok])
    }
}
