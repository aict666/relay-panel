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
}
