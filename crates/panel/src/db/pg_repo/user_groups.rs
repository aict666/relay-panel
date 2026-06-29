use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::UserGroup;

#[async_trait]
impl UserGroupRepository for PgRepository {
    async fn list_user_groups(&self) -> Result<Vec<UserGroup>, DbError> {
        let rows = sqlx::query_as("SELECT * FROM user_groups ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    async fn find_user_group_by_id(&self, id: i64) -> Result<Option<UserGroup>, DbError> {
        let row = sqlx::query_as("SELECT * FROM user_groups WHERE id = $1")
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
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO user_groups (name, remark, allow_all_groups) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(name)
        .bind(remark)
        .bind(allow_all_groups)
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
        let mut idx = 0u32;
        if let Some(n) = name {
            sets.push((idx, format!("name = ${}", idx + 1), n.to_string()));
            idx += 1;
        }
        if let Some(r) = remark {
            sets.push((idx, format!("remark = ${}", idx + 1), r.to_string()));
            idx += 1;
        }
        if let Some(a) = allow_all_groups {
            sets.push((
                idx,
                format!("allow_all_groups = ${}", idx + 1),
                a.to_string(),
            ));
            idx += 1;
        }
        if sets.is_empty() {
            return Ok(0);
        }
        let set_clause: Vec<_> = sets.iter().map(|(_, s, _)| s.as_str()).collect();
        let sql = format!(
            "UPDATE user_groups SET {} WHERE id = ${}",
            set_clause.join(", "),
            idx + 1
        );
        let mut q = sqlx::query(&sql);
        for (_, _, v) in &sets {
            q = q.bind(v);
        }
        q = q.bind(id);
        let r = q.execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn delete_user_group(&self, id: i64) -> Result<u64, DbError> {
        let r = sqlx::query("DELETE FROM user_groups WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    async fn count_users_in_group(&self, group_id: i64) -> Result<i64, DbError> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE group_id = $1 AND admin = FALSE")
                .bind(group_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    async fn list_user_group_device_groups(&self, user_group_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_group_device_groups \
             WHERE user_group_id = $1 ORDER BY device_group_id",
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
        sqlx::query("DELETE FROM user_group_device_groups WHERE user_group_id = $1")
            .bind(user_group_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in device_group_ids {
            sqlx::query(
                "INSERT INTO user_group_device_groups (user_group_id, device_group_id) \
                 VALUES ($1, $2)",
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
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = $1 AND group_id IS NOT NULL")
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
             WHERE u.id = $1 AND dg.group_type = 'in' \
             ORDER BY dg.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let mut ids: Vec<i64> = rows.into_iter().map(|(id,)| id).collect();
        let own: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM device_groups WHERE uid = $1 AND group_type = 'in'")
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
             WHERE u.id = $1",
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
        if allowed_group_ids.is_empty() {
            let r = sqlx::query(
                "UPDATE forward_rules SET paused = TRUE WHERE uid = $1 AND paused = FALSE",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await?;
            return Ok(r.rows_affected());
        }
        // $1 = user_id; $2.. = allowed group ids.
        let placeholders = (0..allowed_group_ids.len())
            .map(|i| format!("${}", i + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE forward_rules SET paused = TRUE \
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

    async fn list_user_ids_in_group(&self, user_group_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT id FROM users WHERE group_id = $1 AND admin = FALSE ORDER BY id",
        )
        .bind(user_group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn is_user_restricted(&self, user_id: i64) -> Result<bool, DbError> {
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT ug.allow_all_groups FROM user_groups ug \
             JOIN users u ON u.group_id = ug.id WHERE u.id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(matches!(row, Some((false,))))
    }

    /// Atomic group update + re-evaluation (v1.0.4).
    /// See sqlite_repo for details.
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
        let mut idx = 0u32;
        if let Some(n) = name {
            sets.push((idx, format!("name = ${}", idx + 1), n.to_string()));
            idx += 1;
        }
        if let Some(r) = remark {
            sets.push((idx, format!("remark = ${}", idx + 1), r.to_string()));
            idx += 1;
        }
        sets.push((
            idx,
            format!("allow_all_groups = ${}", idx + 1),
            allow_all_groups.to_string(),
        ));
        let set_clause: Vec<_> = sets.iter().map(|(_, s, _)| s.as_str()).collect();
        let sql = format!(
            "UPDATE user_groups SET {} WHERE id = ${}",
            set_clause.join(", "),
            idx + 1
        );
        let mut q = sqlx::query(&sql);
        for (_, _, v) in &sets {
            q = q.bind(v);
        }
        q = q.bind(id);
        let r = q.execute(&mut *tx).await?;
        if r.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }

        // Pause rules for every non-admin user in this group.
        let user_ids: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM users WHERE group_id = $1 AND admin = FALSE")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        let mut paused_total = 0u64;
        for (uid,) in &user_ids {
            let allowed: Vec<(i64,)> = sqlx::query_as(
                "SELECT dg.id FROM device_groups dg \
                 JOIN user_group_device_groups ugdg ON ugdg.device_group_id = dg.id \
                 JOIN users u ON u.group_id = ugdg.user_group_id \
                 WHERE u.id = $1 AND dg.group_type = 'in' \
                 ORDER BY dg.id",
            )
            .bind(uid)
            .fetch_all(&mut *tx)
            .await?;
            let allowed_ids: Vec<i64> = allowed.into_iter().map(|(id,)| id).collect();

            if allowed_ids.is_empty() {
                let r = sqlx::query(
                    "UPDATE forward_rules SET paused = TRUE WHERE uid = $1 AND paused = FALSE",
                )
                .bind(uid)
                .execute(&mut *tx)
                .await?;
                paused_total += r.rows_affected();
            } else {
                let placeholders: Vec<String> = (0..allowed_ids.len())
                    .map(|i| format!("${}", i + 2))
                    .collect();
                let sql = format!(
                    "UPDATE forward_rules SET paused = TRUE \
                     WHERE uid = $1 AND paused = FALSE AND device_group_in NOT IN ({})",
                    placeholders.join(", ")
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

        // Read back the group.
        let row: Option<(i64, String, String, bool, String)> = sqlx::query_as(
            "SELECT id, name, COALESCE(remark, ''), allow_all_groups, created_at \
             FROM user_groups WHERE id = $1",
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
}
