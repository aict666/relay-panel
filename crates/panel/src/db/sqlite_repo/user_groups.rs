use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::UserGroup;

#[async_trait]
impl UserGroupRepository for SqliteRepository {
    async fn list_user_groups(&self) -> Result<Vec<UserGroup>, DbError> {
        let rows = sqlx::query_as("SELECT * FROM user_groups ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    async fn find_user_group_by_id(&self, id: i64) -> Result<Option<UserGroup>, DbError> {
        let row = sqlx::query_as("SELECT * FROM user_groups WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    async fn insert_user_group(
        &self,
        name: &str,
        remark: &str,
        allow_all_groups: bool,
    ) -> Result<i64, DbError> {
        sqlx::query("INSERT INTO user_groups (name, remark, allow_all_groups) VALUES (?, ?, ?)")
            .bind(name)
            .bind(remark)
            .bind(allow_all_groups as i32)
            .execute(&self.pool)
            .await?;
        let row: (i64,) = sqlx::query_as("SELECT last_insert_rowid()")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    async fn update_user_group(
        &self,
        id: i64,
        name: Option<&str>,
        remark: Option<&str>,
        allow_all_groups: Option<bool>,
    ) -> Result<u64, DbError> {
        if name.is_none() && remark.is_none() && allow_all_groups.is_none() {
            return Ok(0);
        }
        let mut sets = Vec::new();
        if let Some(n) = name {
            sets.push(("name", n.to_string()));
        }
        if let Some(r) = remark {
            sets.push(("remark", r.to_string()));
        }
        if let Some(a) = allow_all_groups {
            sets.push(("allow_all_groups", if a { "1".into() } else { "0".into() }));
        }
        if sets.is_empty() {
            return Ok(0);
        }
        let set_clause = sets
            .iter()
            .map(|(col, _)| format!("{} = ?", col))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("UPDATE user_groups SET {} WHERE id = ?", set_clause);
        let mut q = sqlx::query(&sql);
        for (_, val) in &sets {
            q = q.bind(val);
        }
        q = q.bind(id);
        let r = q.execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    /// Atomic group update + re-evaluation (v1.0.4).
    /// Updates the group row and pauses every non-admin user's rules on
    /// now-unauthorized groups, all in ONE transaction. If the pause step
    /// fails, the group update is rolled back so the authorization state
    /// is NOT partially changed.
    async fn update_user_group_with_pause(
        &self,
        id: i64,
        name: Option<&str>,
        remark: Option<&str>,
        allow_all_groups: bool,
    ) -> Result<UserGroup, DbError> {
        let mut tx = self.pool.begin().await?;

        // Update the group row.
        let mut sets = Vec::new();
        if let Some(n) = name {
            sets.push(("name", n.to_string()));
        }
        if let Some(r) = remark {
            sets.push(("remark", r.to_string()));
        }
        sets.push((
            "allow_all_groups",
            if allow_all_groups {
                "1".into()
            } else {
                "0".into()
            },
        ));
        let set_clause = sets
            .iter()
            .map(|(col, _)| format!("{} = ?", col))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("UPDATE user_groups SET {} WHERE id = ?", set_clause);
        let mut q = sqlx::query(&sql);
        for (_, val) in &sets {
            q = q.bind(val);
        }
        q = q.bind(id);
        let r = q.execute(&mut *tx).await?;
        if r.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }

        // Pause rules for every non-admin user in this group.
        let user_ids: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM users WHERE group_id = ? AND admin = 0")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        let mut paused_total = 0u64;
        for (uid,) in &user_ids {
            let allowed: Vec<(i64,)> = sqlx::query_as(
                "SELECT dg.id FROM device_groups dg \
                 JOIN user_group_device_groups ugdg ON ugdg.device_group_id = dg.id \
                 JOIN users u ON u.group_id = ugdg.user_group_id \
                 WHERE u.id = ? AND dg.group_type = 'in' \
                 ORDER BY dg.id",
            )
            .bind(uid)
            .fetch_all(&mut *tx)
            .await?;
            let allowed_ids: Vec<i64> = allowed.into_iter().map(|(id,)| id).collect();

            if allowed_ids.is_empty() {
                let r =
                    sqlx::query("UPDATE forward_rules SET paused = 1 WHERE uid = ? AND paused = 0")
                        .bind(uid)
                        .execute(&mut *tx)
                        .await?;
                paused_total += r.rows_affected();
            } else {
                let placeholders = vec!["?"; allowed_ids.len()].join(", ");
                let sql = format!(
                    "UPDATE forward_rules SET paused = 1 \
                     WHERE uid = ? AND paused = 0 AND device_group_in NOT IN ({})",
                    placeholders
                );
                let mut q = sqlx::query(&sql).bind(uid);
                for gid in &allowed_ids {
                    q = q.bind(gid);
                }
                let r = q.execute(&mut *tx).await?;
                paused_total += r.rows_affected();
            }
        }
        if paused_total > 0 {
            tracing::warn!(
                "user group {}: authorization change paused {} rule(s) across its users",
                id,
                paused_total
            );
        }

        tx.commit().await?;

        // Notify nodes (outside the transaction — safe since the DB is already
        // committed).
        // Note: we don't have access to AppState here, so the broadcast is
        // handled by the API layer after this call returns.

        // Read back the group.
        let row: Option<(i64, String, String, bool, String)> = sqlx::query_as(
            "SELECT id, name, COALESCE(remark, ''), allow_all_groups, created_at \
             FROM user_groups WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row
            .map(|(id, name, remark, allow_all, created_at)| UserGroup {
                id,
                name,
                remark,
                allow_all_groups: allow_all,
                created_at,
            })
            .ok_or(DbError::NotFound)?)
    }

    async fn delete_user_group(&self, id: i64) -> Result<u64, DbError> {
        let r = sqlx::query("DELETE FROM user_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    async fn count_users_in_group(&self, group_id: i64) -> Result<i64, DbError> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE group_id = ? AND admin = 0")
                .bind(group_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    async fn list_user_group_device_groups(&self, user_group_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_group_device_groups WHERE user_group_id = ? ORDER BY device_group_id",
        )
        .bind(user_group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn set_user_group_device_groups(
        &self,
        user_group_id: i64,
        device_group_ids: &[i64],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM user_group_device_groups WHERE user_group_id = ?")
            .bind(user_group_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in device_group_ids {
            sqlx::query(
                "INSERT INTO user_group_device_groups (user_group_id, device_group_id) VALUES (?, ?)",
            )
            .bind(user_group_id)
            .bind(dg_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn authorized_device_group_ids(&self, user_id: i64) -> Result<Vec<i64>, DbError> {
        // v1.0.4: legacy users with group_id=null get full access.
        let has_group: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ? AND group_id IS NOT NULL")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        if has_group.0 == 0 {
            let all: Vec<(i64,)> =
                sqlx::query_as("SELECT id FROM device_groups WHERE group_type = 'in' ORDER BY id")
                    .fetch_all(&self.pool)
                    .await?;
            return Ok(all.into_iter().map(|(id,)| id).collect());
        }
        // Allow all if the user's group has allow_all_groups=true.
        let allows_all = self.user_group_allows_all(user_id).await?;
        if allows_all {
            let all: Vec<(i64,)> =
                sqlx::query_as("SELECT id FROM device_groups WHERE group_type = 'in' ORDER BY id")
                    .fetch_all(&self.pool)
                    .await?;
            return Ok(all.into_iter().map(|(id,)| id).collect());
        }
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT dg.id FROM device_groups dg \
             JOIN user_group_device_groups ugdg ON ugdg.device_group_id = dg.id \
             JOIN users u ON u.group_id = ugdg.user_group_id \
             WHERE u.id = ? AND dg.group_type = 'in' \
             ORDER BY dg.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        // Always include user's own groups too.
        let mut ids: Vec<i64> = rows.into_iter().map(|(id,)| id).collect();
        let own: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM device_groups WHERE uid = ? AND group_type = 'in'")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;
        for (id,) in own {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    async fn user_group_allows_all(&self, user_id: i64) -> Result<bool, DbError> {
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT ug.allow_all_groups
             FROM user_groups ug
             JOIN users u ON u.group_id = ug.id
             WHERE u.id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(a,)| a).unwrap_or(false))
    }

    async fn pause_rules_outside_groups(
        &self,
        user_id: i64,
        allowed_group_ids: &[i64],
    ) -> Result<u64, DbError> {
        // Empty allowed list → pause ALL of the user's currently-active rules.
        if allowed_group_ids.is_empty() {
            let r = sqlx::query("UPDATE forward_rules SET paused = 1 WHERE uid = ? AND paused = 0")
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            return Ok(r.rows_affected());
        }
        // Build "device_group_in NOT IN (?, ?, ...)" with bound params.
        let placeholders = vec!["?"; allowed_group_ids.len()].join(", ");
        let sql = format!(
            "UPDATE forward_rules SET paused = 1 \
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

    async fn list_user_ids_in_group(&self, user_group_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM users WHERE group_id = ? AND admin = 0 ORDER BY id")
                .bind(user_group_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn is_user_restricted(&self, user_id: i64) -> Result<bool, DbError> {
        // Restricted = has a permission group AND that group is NOT allow-all.
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT ug.allow_all_groups FROM user_groups ug \
             JOIN users u ON u.group_id = ug.id WHERE u.id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        // No group row → legacy/unassigned → not restricted.
        // allow_all_groups = true → not restricted.
        Ok(matches!(row, Some((false,))))
    }
}
