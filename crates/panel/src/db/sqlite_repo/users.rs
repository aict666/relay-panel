use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::User;

// ── UserRepository ──

#[async_trait]
impl UserRepository for SqliteRepository {
    async fn find_by_username_not_banned(&self, username: &str) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE username = ? AND banned = 0")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_password_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT password FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(p,)| p))
    }

    async fn find_banned_by_id(&self, id: i64) -> Result<Option<bool>, DbError> {
        let row: Option<(bool,)> = sqlx::query_as("SELECT banned FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(b,)| b))
    }

    async fn find_auth_state_by_id(&self, id: i64) -> Result<Option<(bool, i64, bool)>, DbError> {
        let row: Option<(bool, i64, bool)> = sqlx::query_as(
            "SELECT banned, token_version, must_change_password FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn is_admin(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE id = ? AND admin = 1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn exists_by_id(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        plan_id: i64,
    ) -> Result<(), DbError> {
        sqlx::query("INSERT INTO users (username, password, plan_id) VALUES (?, ?, ?)")
            .bind(username)
            .bind(password_hash)
            .bind(plan_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn insert_user_from_plan(
        &self,
        username: &str,
        password_hash: &str,
        plan_id: i64,
    ) -> Result<u64, DbError> {
        // Atomic INSERT...SELECT: copies the plan's quota fields into the new
        // user row in one statement. If the plan doesn't exist the SELECT
        // yields no row → 0 rows_affected (caller fails the registration).
        // Note the column mapping: plans.traffic → users.traffic_limit.
        let result = sqlx::query(
            "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
             SELECT ?, ?, ?, max_rules, traffic, speed_limit, ip_limit \
             FROM plans WHERE id = ?",
        )
        .bind(username)
        .bind(password_hash)
        .bind(plan_id)
        .bind(plan_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn insert_public_registered_user(
        &self,
        username: &str,
        password_hash: &str,
        requested_plan_id: Option<i64>,
    ) -> Result<UserProvisionOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        macro_rules! reject {
            ($outcome:expr) => {{
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Ok($outcome);
            }};
        }

        let settings: Option<(bool, i64, String)> = try_sql!(
            sqlx::query_as(
                "SELECT registration_enabled, default_registration_plan_id, \
                 registration_allowed_plan_ids FROM app_settings WHERE id = 1",
            )
            .fetch_optional(&mut *conn)
            .await
        );
        let Some((enabled, default_plan_id, raw_allowed)) = settings else {
            reject!(UserProvisionOutcome::RegistrationDisabled);
        };
        if !enabled {
            reject!(UserProvisionOutcome::RegistrationDisabled);
        }
        let plan_id = requested_plan_id.unwrap_or(default_plan_id);
        let allowed = match serde_json::from_str::<Vec<i64>>(&raw_allowed) {
            Ok(allowed) => allowed,
            Err(error) => {
                tracing::error!(
                    "insert_public_registered_user: malformed allowed plan ids: {}",
                    error
                );
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Err(DbError::InvalidData(
                    "registration_allowed_plan_ids is not a JSON integer array",
                ));
            }
        };
        if !allowed.contains(&plan_id) {
            reject!(UserProvisionOutcome::PlanNotAllowed);
        }

        let inserted = try_sql!(
            sqlx::query(
                "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
                 SELECT ?, ?, ?, max_rules, traffic, speed_limit, ip_limit \
                 FROM plans WHERE id = ?",
            )
            .bind(username)
            .bind(password_hash)
            .bind(plan_id)
            .bind(plan_id)
            .execute(&mut *conn)
            .await
        );
        if inserted.rows_affected() == 0 {
            reject!(UserProvisionOutcome::PlanMissing(plan_id));
        }
        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(UserProvisionOutcome::Created)
    }

    async fn insert_admin_user_from_default(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<UserProvisionOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        macro_rules! reject {
            ($outcome:expr) => {{
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Ok($outcome);
            }};
        }

        let plan_id: i64 = try_sql!(
            sqlx::query_scalar("SELECT default_registration_plan_id FROM app_settings WHERE id=1")
                .fetch_optional(&mut *conn)
                .await
        )
        .unwrap_or(1);
        let inserted = try_sql!(
            sqlx::query(
                "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
                 SELECT ?, ?, ?, max_rules, traffic, speed_limit, ip_limit \
                 FROM plans WHERE id = ?",
            )
            .bind(username)
            .bind(password_hash)
            .bind(plan_id)
            .bind(plan_id)
            .execute(&mut *conn)
            .await
        );
        if inserted.rows_affected() == 0 {
            reject!(UserProvisionOutcome::PlanMissing(plan_id));
        }
        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(UserProvisionOutcome::Created)
    }

    async fn update_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError> {
        let result = sqlx::query("UPDATE users SET password = ? WHERE id = ?")
            .bind(new_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn change_own_password(
        &self,
        id: i64,
        expected_hash: &str,
        new_hash: &str,
    ) -> Result<u64, DbError> {
        // Atomic: new hash + bump token_version (revoke all sessions) + clear
        // must_change_password, in one UPDATE.
        let result = sqlx::query(
            "UPDATE users SET password = ?, token_version = token_version + 1, \
             must_change_password = 0 WHERE id = ? AND password = ?",
        )
        .bind(new_hash)
        .bind(id)
        .bind(expected_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn admin_reset_password(
        &self,
        actor_id: i64,
        id: i64,
        new_hash: &str,
        must_change_password: bool,
    ) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE users SET password = ?, token_version = token_version + 1, \
             must_change_password = ? WHERE id = ? AND (admin = 0 OR id = ?)",
        )
        .bind(new_hash)
        .bind(must_change_password)
        .bind(id)
        .bind(actor_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn update_user_fields(
        &self,
        id: i64,
        balance: Option<&str>,
        max_rules: Option<i32>,
        traffic_limit: Option<i64>,
        banned: Option<bool>,
        suspended: Option<bool>,
    ) -> Result<u64, DbError> {
        let mut sets: Vec<&str> = Vec::new();
        if balance.is_some() {
            sets.push("balance = ?");
        }
        if max_rules.is_some() {
            sets.push("max_rules = ?");
        }
        if traffic_limit.is_some() {
            sets.push("traffic_limit = ?");
        }
        if banned.is_some() {
            sets.push("banned = ?");
        }
        // v1.0.8: suspension. Unlike banned, suspended does NOT bump
        // token_version (the user stays signed in; forwarding is gated by
        // list_active_for_config).
        if suspended.is_some() {
            sets.push("suspended = ?");
        }
        // v0.4.10 PR4: banning a user revokes their sessions. token_version is
        // a self-increment expression (no bind), appended only when banning.
        if banned == Some(true) {
            sets.push("token_version = token_version + 1");
        }

        if sets.is_empty() {
            return Ok(0);
        }

        let sql = format!("UPDATE users SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        if let Some(v) = balance {
            q = q.bind(v);
        }
        if let Some(v) = max_rules {
            q = q.bind(v);
        }
        if let Some(v) = traffic_limit {
            q = q.bind(v);
        }
        if let Some(v) = banned {
            q = q.bind(v);
        }
        if let Some(v) = suspended {
            q = q.bind(v);
        }
        q = q.bind(id);

        let result = q.execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn admin_edit_user_plan(
        &self,
        user_id: i64,
        expected_plan_id: i64,
        clear: bool,
        plan_expire_at: Option<&str>,
    ) -> Result<AdminUserPlanEditOutcome, DbError> {
        // Acquire SQLite's writer lock before reading plan_id. This serializes
        // the optimistic check with purchases and prevents a read-then-write
        // promotion from observing a stale association.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        macro_rules! reject {
            ($outcome:expr) => {{
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Ok($outcome);
            }};
        }

        let target: Option<(bool, Option<i64>, Option<String>)> = try_sql!(
            sqlx::query_as(
                "SELECT u.admin, u.plan_id, p.plan_type FROM users u \
                 LEFT JOIN plans p ON p.id = u.plan_id WHERE u.id = ?",
            )
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await
        );
        let Some((is_admin, current_plan_id, plan_type)) = target else {
            reject!(AdminUserPlanEditOutcome::NotFound);
        };
        if is_admin {
            reject!(AdminUserPlanEditOutcome::AdminTarget);
        }
        if current_plan_id != Some(expected_plan_id) {
            reject!(AdminUserPlanEditOutcome::PlanChanged);
        }
        if !clear && plan_type.as_deref() != Some("time") {
            reject!(AdminUserPlanEditOutcome::ExpiryNotApplicable);
        }

        if clear {
            try_sql!(
                sqlx::query(
                    "UPDATE users SET plan_id = NULL, plan_expire_at = NULL, \
                     all_device_groups = 0 WHERE id = ?",
                )
                .bind(user_id)
                .execute(&mut *conn)
                .await
            );
            try_sql!(
                sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
                    .bind(user_id)
                    .execute(&mut *conn)
                    .await
            );
            try_sql!(
                sqlx::query(
                    "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                     WHERE uid = ? AND paused = 0",
                )
                .bind(user_id)
                .execute(&mut *conn)
                .await
            );
        } else {
            try_sql!(
                sqlx::query("UPDATE users SET plan_expire_at = ? WHERE id = ?")
                    .bind(plan_expire_at)
                    .bind(user_id)
                    .execute(&mut *conn)
                    .await
            );
        }

        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(AdminUserPlanEditOutcome::Updated)
    }

    async fn increment_user_traffic(&self, id: i64, delta: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn reset_traffic(&self, id: i64) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;
        let user = sqlx::query("UPDATE users SET traffic_used = 0 WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if user.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        sqlx::query("UPDATE forward_rules SET traffic_used = 0 WHERE uid = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(user.rows_affected())
    }

    async fn delete_non_admin(&self, id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM users WHERE id = ? AND admin = 0")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn delete_user_cascade(&self, uid: i64) -> Result<u64, DbError> {
        // v0.4.4: one atomic transaction. Previously this deleted rules + groups
        // in two un-transacted statements, MISSED tunnel_profiles entirely, and
        // left the user row to a separate delete_non_admin call — so a user with
        // a custom tunnel profile would have rules+groups permanently deleted and
        // THEN fail the FK check on the user delete, leaving the account half-gone.
        //
        // Delete order respects the FK graph: forward_rules references both
        // tunnel_profiles and device_groups, so it goes first; tunnel_profiles and
        // device_groups both reference users, so the user row goes last. The user
        // delete carries the `admin = 0` guard, and if it affects 0 rows (admin or
        // already gone) we roll the whole thing back by returning before commit.
        // Acquire the writer lock before checking tunnel_hops. Otherwise a
        // concurrent tunnel creator can pass its own validation after our read
        // and commit before the group DELETE, degrading this explicit conflict
        // into a generic foreign-key error.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        let target_admin: Option<bool> = try_sql!(
            sqlx::query_scalar("SELECT admin FROM users WHERE id = ?")
                .bind(uid)
                .fetch_optional(&mut *conn)
                .await
        );
        if target_admin != Some(false) {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(0);
        }
        let conflict: (i64, i64) = try_sql!(
            sqlx::query_as(
                "SELECT COUNT(DISTINCT g.id),COUNT(DISTINCT h.tunnel_id) \
                 FROM device_groups g JOIN tunnel_hops h ON h.device_group_id=g.id \
                 JOIN tunnels t ON t.id=h.tunnel_id \
                 WHERE g.uid=? AND t.uid<>?",
            )
            .bind(uid)
            .bind(uid)
            .fetch_one(&mut *conn)
            .await
        );
        if conflict.0 > 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::UserTunnelGroupConflict {
                groups: conflict.0,
                tunnels: conflict.1,
            });
        }
        let cross_owner_rules: i64 = try_sql!(
            sqlx::query_scalar(
                "SELECT COUNT(DISTINCT refs.rule_id) FROM ( \
                   SELECT id AS rule_id, device_group_in AS group_id FROM forward_rules WHERE uid<>? \
                   UNION SELECT id, device_group_out FROM forward_rules WHERE uid<>? AND device_group_out IS NOT NULL \
                   UNION SELECT h.rule_id, h.device_group_id FROM forward_rule_hops h \
                     JOIN forward_rules r ON r.id=h.rule_id WHERE r.uid<>? \
                   UNION SELECT retired.rule_id, retired.device_group_id \
                     FROM forward_rule_retired_entries retired \
                     JOIN forward_rules r ON r.id=retired.rule_id \
                     WHERE r.uid<>? AND retired.expires_at >= unixepoch() \
                   UNION SELECT transition.rule_id, transition.device_group_id \
                     FROM forward_rule_route_transitions transition \
                     JOIN forward_rules r ON r.id=transition.rule_id \
                     WHERE r.uid<>? AND transition.expires_at >= unixepoch() \
                 ) refs JOIN device_groups owned ON owned.id=refs.group_id WHERE owned.uid=?",
            )
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .fetch_one(&mut *conn)
            .await
        );
        let fallback_groups: i64 = try_sql!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM device_groups dependent \
                 JOIN device_groups owned ON owned.id=dependent.fallback_group \
                 WHERE owned.uid=? AND dependent.uid<>?",
            )
            .bind(uid)
            .bind(uid)
            .fetch_one(&mut *conn)
            .await
        );
        let plans: i64 = try_sql!(
            sqlx::query_scalar(
                "SELECT COUNT(DISTINCT pdg.plan_id) FROM plan_device_groups pdg \
                 JOIN device_groups owned ON owned.id=pdg.device_group_id WHERE owned.uid=?",
            )
            .bind(uid)
            .fetch_one(&mut *conn)
            .await
        );
        if cross_owner_rules > 0 || fallback_groups > 0 || plans > 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::UserGroupReferenceConflict {
                rules: cross_owner_rules,
                fallback_groups,
                plans,
            });
        }
        let owned_tunnel_conflict: (i64, i64) = try_sql!(
            sqlx::query_as(
                "SELECT COUNT(DISTINCT t.id),COUNT(DISTINCT refs.rule_id) FROM tunnels t \
                 JOIN ( \
                   SELECT id AS rule_id,tunnel_id FROM forward_rules \
                    WHERE uid<>? AND tunnel_id IS NOT NULL \
                   UNION \
                   SELECT retired.rule_id,retired.tunnel_id \
                    FROM forward_rule_retired_entries retired \
                    JOIN forward_rules r ON r.id=retired.rule_id \
                    WHERE r.uid<>? AND retired.expires_at >= unixepoch() \
                 ) refs ON refs.tunnel_id=t.id \
                 WHERE t.uid=?",
            )
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .fetch_one(&mut *conn)
            .await
        );
        if owned_tunnel_conflict.1 > 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::UserOwnedTunnelConflict {
                tunnels: owned_tunnel_conflict.0,
                rules: owned_tunnel_conflict.1,
            });
        }
        try_sql!(
            sqlx::query("DELETE FROM forward_rules WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        try_sql!(
            sqlx::query("DELETE FROM tunnel_profiles WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        try_sql!(
            sqlx::query("DELETE FROM tunnels WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        try_sql!(
            sqlx::query("DELETE FROM device_groups WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        let result = try_sql!(
            sqlx::query("DELETE FROM users WHERE id = ? AND admin = 0")
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        if result.rows_affected() == 0 {
            // Admin or non-existent: roll back so the cascade above is undone.
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(0);
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(result.rows_affected())
    }

    async fn list_users_public(&self) -> Result<Vec<crate::api::admin::UserPublic>, DbError> {
        let users: Vec<crate::api::admin::UserPublic> =
            sqlx::query_as("SELECT * FROM users ORDER BY id")
                .fetch_all(&self.pool)
                .await?;
        Ok(users)
    }

    async fn replace_initial_admin_password(
        &self,
        expected_hash: &str,
        new_hash: &str,
    ) -> Result<u64, DbError> {
        // Compare-and-swap is important for deployments that accidentally
        // start two panel replicas against the same database: only the winner
        // may print credentials that actually work.
        let result = sqlx::query(
            "UPDATE users SET password = ?, must_change_password = 1, \
             token_version = token_version + 1 WHERE id = 1 AND password = ?",
        )
        .bind(new_hash)
        .bind(expected_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
