use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;

#[async_trait]
impl DeviceGroupAuthRepository for PgRepository {
    async fn list_user_device_groups(&self, user_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_device_groups \
             WHERE user_id = $1 ORDER BY device_group_id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn set_user_device_groups(
        &self,
        user_id: i64,
        device_group_ids: &[i64],
    ) -> Result<(), DbError> {
        let mut group_ids = device_group_ids.to_vec();
        group_ids.sort_unstable();
        group_ids.dedup();
        let mut tx = self.pool.begin().await?;
        let target_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if target_exists.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        for group_id in &group_ids {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            let valid: Option<i64> = sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users owner ON owner.id = dg.uid \
                 WHERE dg.id = $1 AND dg.group_type IN ('in', 'both') AND owner.admin = TRUE",
            )
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::UserDeviceGroupInvalid);
            }
        }
        // Lock the parent before deleting child rows. Otherwise a concurrent
        // user deletion can hold the parent while waiting on those child rows,
        // as this transaction waits on the FK check during re-insertion.
        let user_exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        if user_exists.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        sqlx::query("DELETE FROM user_device_groups WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in &group_ids {
            sqlx::query(
                "INSERT INTO user_device_groups (user_id, device_group_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(user_id)
            .bind(dg_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn set_user_all_device_groups(&self, user_id: i64, all: bool) -> Result<u64, DbError> {
        // Admins are always all-allowed in code, so leave their flag alone.
        let r =
            sqlx::query("UPDATE users SET all_device_groups = $1 WHERE id = $2 AND admin = FALSE")
                .bind(all)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected())
    }

    async fn update_user_with_authorization(
        &self,
        user_id: i64,
        update: AdminUserUpdate<'_>,
    ) -> Result<Option<AdminUserUpdateOutcome>, DbError> {
        let normalized_group_ids = if update.all_device_groups == Some(true) {
            None
        } else {
            update.device_group_ids.map(|group_ids| {
                let mut group_ids = group_ids.to_vec();
                group_ids.sort_unstable();
                group_ids.dedup();
                group_ids
            })
        };
        let mut tx = self.pool.begin().await?;

        // Preserve `None = user missing` even when the submitted grant list is
        // invalid. This read takes no row lock, so canonical group -> user lock
        // ordering below is unchanged; the UPDATE remains authoritative if a
        // concurrent deletion wins after this preflight.
        let target_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if target_exists.is_none() {
            tx.rollback().await?;
            return Ok(None);
        }

        // Match the group -> user lock order used by rule writers. Besides
        // avoiding deadlocks, the advisory lock serializes validation with a
        // concurrent group type/ownership mutation.
        if let Some(group_ids) = &normalized_group_ids {
            for group_id in group_ids {
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(group_id)
                    .execute(&mut *tx)
                    .await?;
                let valid: Option<i64> = sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users owner ON owner.id = dg.uid \
                     WHERE dg.id = $1 AND dg.group_type IN ('in', 'both') AND owner.admin = TRUE",
                )
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
                if valid.is_none() {
                    tx.rollback().await?;
                    return Err(DbError::UserDeviceGroupInvalid);
                }
            }
        }

        let user = sqlx::query(
            "UPDATE users SET \
             balance = COALESCE($1, balance), \
             max_rules = COALESCE($2, max_rules), \
             traffic_limit = COALESCE($3, traffic_limit), \
             banned = COALESCE($4, banned), \
             suspended = COALESCE($5, suspended), \
             token_version = token_version + CASE WHEN $6 THEN 1 ELSE 0 END, \
             all_device_groups = CASE WHEN admin = FALSE \
                 THEN COALESCE($7, all_device_groups) ELSE all_device_groups END \
             WHERE id = $8",
        )
        .bind(update.balance)
        .bind(update.max_rules)
        .bind(update.traffic_limit)
        .bind(update.banned)
        .bind(update.suspended)
        .bind(update.banned == Some(true))
        .bind(update.all_device_groups)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        if user.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(None);
        }

        if let Some(group_ids) = &normalized_group_ids {
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            for group_id in group_ids {
                sqlx::query(
                    "INSERT INTO user_device_groups (user_id, device_group_id) \
                     VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(user_id)
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        let authz_changed = update.all_device_groups.is_some() || normalized_group_ids.is_some();
        let paused_rules = if authz_changed {
            let (is_admin, all_groups): (bool, bool) =
                sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let paused = if is_admin || all_groups {
                sqlx::query(
                    "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
                     WHERE uid = $1 AND paused = FALSE AND device_group_in NOT IN (\
                         SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                         WHERE dg.group_type IN ('in', 'both') AND owner.admin=TRUE\
                     )",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?
            } else {
                sqlx::query(
                    "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
                     WHERE uid = $1 AND paused = FALSE AND device_group_in NOT IN (\
                         SELECT dg.id FROM device_groups dg \
                         JOIN user_device_groups udg ON udg.device_group_id = dg.id \
                         JOIN users owner ON owner.id=dg.uid \
                         WHERE udg.user_id = $1 AND dg.group_type IN ('in', 'both') \
                           AND owner.admin=TRUE\
                     )",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?
            };
            paused.rows_affected()
        } else {
            0
        };

        tx.commit().await?;
        Ok(Some(AdminUserUpdateOutcome { paused_rules }))
    }

    async fn authorized_device_group_ids(&self, user_id: i64) -> Result<Vec<i64>, DbError> {
        // Admins and all_device_groups users get every administrator-managed
        // inbound-capable group. Historical regular-user-owned groups cannot
        // be valid rule entries.
        let flags: Option<(bool, bool)> =
            sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        let (is_admin, all) = match flags {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        if is_admin || all {
            let all_in: Vec<(i64,)> = sqlx::query_as(
                "SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                 WHERE dg.group_type IN ('in', 'both') AND owner.admin=TRUE ORDER BY dg.id",
            )
            .fetch_all(&self.pool)
            .await?;
            return Ok(all_in.into_iter().map(|(id,)| id).collect());
        }
        // Otherwise only the user's explicit assignments (inbound groups only —
        // the authorized set is compared against rule.device_group_in).
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT dg.id FROM device_groups dg \
             JOIN user_device_groups udg ON udg.device_group_id = dg.id \
             JOIN users owner ON owner.id=dg.uid \
             WHERE udg.user_id = $1 AND dg.group_type IN ('in', 'both') AND owner.admin=TRUE \
             ORDER BY dg.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn pause_rules_outside_groups(
        &self,
        user_id: i64,
        allowed_group_ids: &[i64],
    ) -> Result<u64, DbError> {
        // Empty allowed list → pause ALL of the user's currently-active rules.
        // v1.0.8: auto_paused=TRUE marks this as a SYSTEM pause (vs. a human
        // using the on/off switch), so a later re-authorization can safely
        // auto-resume it.
        if allowed_group_ids.is_empty() {
            let r = sqlx::query(
                "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
                 WHERE uid = $1 AND paused = FALSE",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await?;
            return Ok(r.rows_affected());
        }
        // Build "device_group_in NOT IN ($2, $3, ...)" with bound params.
        let placeholders = (0..allowed_group_ids.len())
            .map(|i| format!("${}", i + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
             WHERE uid = $1 AND paused = FALSE AND device_group_in NOT IN ({})",
            placeholders
        );
        let mut q = sqlx::query(&sql).bind(user_id);
        for gid in allowed_group_ids {
            q = q.bind(gid);
        }
        let r = q.execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn is_user_restricted(&self, user_id: i64) -> Result<bool, DbError> {
        let row: Option<(bool, bool)> =
            sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        // Restricted = a non-admin without the all-device-groups flag.
        Ok(matches!(row, Some((false, false))))
    }
}
