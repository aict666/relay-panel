use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;

#[async_trait]
impl DeviceGroupAuthRepository for SqliteRepository {
    async fn list_user_device_groups(&self, user_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_device_groups \
             WHERE user_id = ? ORDER BY device_group_id",
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
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let user_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if user_exists.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        for group_id in &group_ids {
            let valid: Option<i64> = sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users owner ON owner.id = dg.uid \
                 WHERE dg.id = ? AND dg.group_type IN ('in', 'both') AND owner.admin = 1",
            )
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::UserDeviceGroupInvalid);
            }
        }
        sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in &group_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO user_device_groups (user_id, device_group_id) \
                 VALUES (?, ?)",
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
        let r = sqlx::query("UPDATE users SET all_device_groups = ? WHERE id = ? AND admin = 0")
            .bind(all as i32)
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
        // Some API clients submit both representations. Per the wire contract,
        // an explicit list is ignored when this request enables all groups;
        // preserving the stored list also prevents an unrelated payload from
        // changing what would become effective after a later restriction.
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

        // Reserve SQLite's single writer before validating the grant snapshot,
        // so a concurrent group edit cannot invalidate it before insertion.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let target_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if target_exists.is_none() {
            tx.rollback().await?;
            return Ok(None);
        }
        if let Some(group_ids) = &normalized_group_ids {
            for group_id in group_ids {
                let valid: Option<i64> = sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users owner ON owner.id = dg.uid \
                     WHERE dg.id = ? AND dg.group_type IN ('in', 'both') AND owner.admin = 1",
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

        // Even an authorization-only request goes through this UPDATE so the
        // target row is checked before child rows are touched. Banning keeps
        // the existing token-version revocation semantics; admins retain their
        // implicit all-groups flag regardless of the submitted value.
        let user = sqlx::query(
            "UPDATE users SET \
             balance = COALESCE(?, balance), \
             max_rules = COALESCE(?, max_rules), \
             traffic_limit = COALESCE(?, traffic_limit), \
             banned = COALESCE(?, banned), \
             suspended = COALESCE(?, suspended), \
             token_version = token_version + CASE WHEN ? THEN 1 ELSE 0 END, \
             all_device_groups = CASE WHEN admin = 0 \
                 THEN COALESCE(?, all_device_groups) ELSE all_device_groups END \
             WHERE id = ?",
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
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            for group_id in group_ids {
                sqlx::query(
                    "INSERT OR IGNORE INTO user_device_groups (user_id, device_group_id) \
                     VALUES (?, ?)",
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
                sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = ?")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let paused = if is_admin || all_groups {
                sqlx::query(
                    "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                     WHERE uid = ? AND paused = 0 AND device_group_in NOT IN (\
                         SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                         WHERE dg.group_type IN ('in', 'both') AND owner.admin=1\
                     )",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?
            } else {
                sqlx::query(
                    "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                     WHERE uid = ? AND paused = 0 AND device_group_in NOT IN (\
                         SELECT dg.id FROM device_groups dg \
                         JOIN user_device_groups udg ON udg.device_group_id = dg.id \
                         JOIN users owner ON owner.id=dg.uid \
                         WHERE udg.user_id = ? AND dg.group_type IN ('in', 'both') \
                           AND owner.admin=1\
                     )",
                )
                .bind(user_id)
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
            sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = ?")
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
                 WHERE dg.group_type IN ('in', 'both') AND owner.admin=1 ORDER BY dg.id",
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
             WHERE udg.user_id = ? AND dg.group_type IN ('in', 'both') AND owner.admin=1 \
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
        // v1.0.8: auto_paused=1 marks this as a SYSTEM pause (vs. a human using
        // the on/off switch), so a later re-authorization can safely auto-resume
        // it.
        if allowed_group_ids.is_empty() {
            let r = sqlx::query(
                "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                 WHERE uid = ? AND paused = 0",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await?;
            return Ok(r.rows_affected());
        }
        // Build "device_group_in NOT IN (?, ?, ...)" with bound params.
        let placeholders = vec!["?"; allowed_group_ids.len()].join(", ");
        let sql = format!(
            "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
             WHERE uid = ? AND paused = 0 AND device_group_in NOT IN ({})",
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
            sqlx::query_as("SELECT admin, all_device_groups FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        // Restricted = a non-admin without the all-device-groups flag. Admins and
        // all-device-groups users are unrestricted (the rule API skips the
        // allowlist check for them).
        Ok(matches!(row, Some((false, false))))
    }
}
