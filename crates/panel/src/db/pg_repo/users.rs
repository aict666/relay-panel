use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::User;

// ── UserRepository ──

#[async_trait]
impl UserRepository for PgRepository {
    async fn find_by_username_not_banned(&self, username: &str) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE username = $1 AND banned = FALSE")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_password_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT password FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(p,)| p))
    }

    async fn find_banned_by_id(&self, id: i64) -> Result<Option<bool>, DbError> {
        let row: Option<(bool,)> = sqlx::query_as("SELECT banned FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(b,)| b))
    }

    async fn find_auth_state_by_id(&self, id: i64) -> Result<Option<(bool, i64, bool)>, DbError> {
        let row: Option<(bool, i64, bool)> = sqlx::query_as(
            "SELECT banned, token_version, must_change_password FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn is_admin(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM users WHERE id = $1 AND admin = TRUE")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    async fn exists_by_id(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM users WHERE id = $1")
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
        sqlx::query("INSERT INTO users (username, password, plan_id) VALUES ($1, $2, $3)")
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
        // user row in one statement. PG positional params can be reused, so
        // $3 serves both the plan_id column value AND the WHERE filter (unlike
        // SQLite's positional ? which must be bound once per occurrence).
        // 0 rows_affected = plan missing → caller fails the registration.
        let result = sqlx::query(
            "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
             SELECT $1, $2, $3, max_rules, traffic, speed_limit, ip_limit \
             FROM plans WHERE id = $3",
        )
        .bind(username)
        .bind(password_hash)
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
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(REGISTRATION_SETTINGS_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let settings: Option<(bool, i64, String)> = sqlx::query_as(
            "SELECT registration_enabled, default_registration_plan_id, \
             registration_allowed_plan_ids FROM app_settings WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some((enabled, default_plan_id, raw_allowed)) = settings else {
            tx.rollback().await?;
            return Ok(UserProvisionOutcome::RegistrationDisabled);
        };
        if !enabled {
            tx.rollback().await?;
            return Ok(UserProvisionOutcome::RegistrationDisabled);
        }
        let plan_id = requested_plan_id.unwrap_or(default_plan_id);
        let allowed = match serde_json::from_str::<Vec<i64>>(&raw_allowed) {
            Ok(allowed) => allowed,
            Err(error) => {
                tracing::error!(
                    "insert_public_registered_user: malformed allowed plan ids: {}",
                    error
                );
                tx.rollback().await?;
                return Err(DbError::InvalidData(
                    "registration_allowed_plan_ids is not a JSON integer array",
                ));
            }
        };
        if !allowed.contains(&plan_id) {
            tx.rollback().await?;
            return Ok(UserProvisionOutcome::PlanNotAllowed);
        }

        let inserted = sqlx::query(
            "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
             SELECT $1, $2, $3, max_rules, traffic, speed_limit, ip_limit \
             FROM plans WHERE id = $3",
        )
        .bind(username)
        .bind(password_hash)
        .bind(plan_id)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(UserProvisionOutcome::PlanMissing(plan_id));
        }
        tx.commit().await?;
        Ok(UserProvisionOutcome::Created)
    }

    async fn insert_admin_user_from_default(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<UserProvisionOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(REGISTRATION_SETTINGS_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let plan_id: i64 =
            sqlx::query_scalar("SELECT default_registration_plan_id FROM app_settings WHERE id=1")
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(1);
        let inserted = sqlx::query(
            "INSERT INTO users (username, password, plan_id, max_rules, traffic_limit, speed_limit, ip_limit) \
             SELECT $1, $2, $3, max_rules, traffic, speed_limit, ip_limit \
             FROM plans WHERE id = $3",
        )
        .bind(username)
        .bind(password_hash)
        .bind(plan_id)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(UserProvisionOutcome::PlanMissing(plan_id));
        }
        tx.commit().await?;
        Ok(UserProvisionOutcome::Created)
    }

    async fn update_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError> {
        let result = sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
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
        let result = sqlx::query(
            "UPDATE users SET password = $1, token_version = token_version + 1, \
             must_change_password = FALSE WHERE id = $2 AND password = $3",
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
            "UPDATE users SET password = $1, token_version = token_version + 1, \
             must_change_password = $2 WHERE id = $3 AND (admin = FALSE OR id = $4)",
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
        // Build SET clause + bind values in the same field order as SQLite.
        // PG needs numbered placeholders; we accumulate binds in a Vec and
        // generate `$1, $2, ...` after we know how many there are.
        let mut sets: Vec<&str> = Vec::new();
        if balance.is_some() {
            sets.push("balance = ");
        }
        if max_rules.is_some() {
            sets.push("max_rules = ");
        }
        if traffic_limit.is_some() {
            sets.push("traffic_limit = ");
        }
        if banned.is_some() {
            sets.push("banned = ");
        }
        // v1.0.8: suspension (no token_version bump — user stays signed in).
        if suspended.is_some() {
            sets.push("suspended = ");
        }

        if sets.is_empty() {
            return Ok(0);
        }

        // Number the placeholders. id is always the last bind.
        let mut ph = 1;
        let mut sets_with_ph: Vec<String> = sets
            .iter()
            .map(|s| {
                let p = format!("{s}${ph}");
                ph += 1;
                p
            })
            .collect();
        // v0.4.10 PR4: banning revokes sessions via a token_version self-
        // increment (a literal expression, NOT a bound placeholder), appended
        // only when banning. Added after the numbered sets so placeholder
        // numbering is unaffected.
        if banned == Some(true) {
            sets_with_ph.push("token_version = token_version + 1".to_string());
        }
        let sql = format!(
            "UPDATE users SET {} WHERE id = ${}",
            sets_with_ph.join(", "),
            ph
        );

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
        let mut tx = self.pool.begin().await?;
        let target: Option<(bool, Option<i64>)> =
            sqlx::query_as("SELECT admin, plan_id FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((is_admin, current_plan_id)) = target else {
            tx.rollback().await?;
            return Ok(AdminUserPlanEditOutcome::NotFound);
        };
        if is_admin {
            tx.rollback().await?;
            return Ok(AdminUserPlanEditOutcome::AdminTarget);
        }
        if current_plan_id != Some(expected_plan_id) {
            tx.rollback().await?;
            return Ok(AdminUserPlanEditOutcome::PlanChanged);
        }

        if !clear {
            // Keep the plan's type stable while validating and writing expiry.
            let plan_type: Option<String> =
                sqlx::query_scalar("SELECT plan_type FROM plans WHERE id = $1 FOR SHARE")
                    .bind(expected_plan_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if plan_type.as_deref() != Some("time") {
                tx.rollback().await?;
                return Ok(AdminUserPlanEditOutcome::ExpiryNotApplicable);
            }
            sqlx::query("UPDATE users SET plan_expire_at = $1 WHERE id = $2")
                .bind(plan_expire_at)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(AdminUserPlanEditOutcome::Updated);
        }

        sqlx::query(
            "UPDATE users SET plan_id = NULL, plan_expire_at = NULL, all_device_groups = FALSE \
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM user_device_groups WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
             WHERE uid = $1 AND paused = FALSE",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(AdminUserPlanEditOutcome::Updated)
    }

    async fn increment_user_traffic(&self, id: i64, delta: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET traffic_used = traffic_used + $1 WHERE id = $2")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn reset_traffic(&self, id: i64) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;
        let user = sqlx::query("UPDATE users SET traffic_used = 0 WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if user.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        sqlx::query("UPDATE forward_rules SET traffic_used = 0 WHERE uid = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(user.rows_affected())
    }

    async fn delete_non_admin(&self, id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1 AND admin = FALSE")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn delete_user_cascade(&self, uid: i64) -> Result<u64, DbError> {
        // v0.4.4: one atomic transaction (was two un-transacted DELETEs that
        // missed tunnel_profiles). FK order: forward_rules → tunnel_profiles →
        // device_groups → users. The user delete carries the admin guard; if it
        // affects 0 rows (admin or gone) we roll back so the cascade is undone.
        let mut tx = self.pool.begin().await?;
        let target_admin: Option<bool> =
            sqlx::query_scalar("SELECT admin FROM users WHERE id=$1 FOR UPDATE")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await?;
        if target_admin != Some(false) {
            tx.rollback().await?;
            return Ok(0);
        }
        // Lock every legacy user-owned group before checking tunnel_hops. Tunnel
        // path writers take a SHARE lock on the same rows, so either their path
        // commits first and is reported here, or deletion wins and their
        // in-transaction group revalidation fails safely.
        sqlx::query("SELECT id FROM device_groups WHERE uid=$1 ORDER BY id FOR UPDATE")
            .bind(uid)
            .fetch_all(&mut *tx)
            .await?;
        let conflict: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT g.id),COUNT(DISTINCT h.tunnel_id) \
             FROM device_groups g JOIN tunnel_hops h ON h.device_group_id=g.id \
             JOIN tunnels t ON t.id=h.tunnel_id \
             WHERE g.uid=$1 AND t.uid<>$1",
        )
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        if conflict.0 > 0 {
            tx.rollback().await?;
            return Err(DbError::UserTunnelGroupConflict {
                groups: conflict.0,
                tunnels: conflict.1,
            });
        }
        let cross_owner_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT refs.rule_id) FROM ( \
               SELECT id AS rule_id, device_group_in AS group_id FROM forward_rules WHERE uid<>$1 \
               UNION SELECT id, device_group_out FROM forward_rules WHERE uid<>$1 AND device_group_out IS NOT NULL \
               UNION SELECT h.rule_id, h.device_group_id FROM forward_rule_hops h \
                 JOIN forward_rules r ON r.id=h.rule_id WHERE r.uid<>$1 \
               UNION SELECT retired.rule_id, retired.device_group_id \
                 FROM forward_rule_retired_entries retired \
                 JOIN forward_rules r ON r.id=retired.rule_id \
                 WHERE r.uid<>$1 \
                   AND retired.expires_at >= EXTRACT(EPOCH FROM now())::BIGINT \
               UNION SELECT transition.rule_id, transition.device_group_id \
                 FROM forward_rule_route_transitions transition \
                 JOIN forward_rules r ON r.id=transition.rule_id \
                 WHERE r.uid<>$1 \
                   AND transition.expires_at >= EXTRACT(EPOCH FROM now())::BIGINT \
             ) refs JOIN device_groups owned ON owned.id=refs.group_id WHERE owned.uid=$1",
        )
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        let fallback_groups: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_groups dependent \
             JOIN device_groups owned ON owned.id=dependent.fallback_group \
             WHERE owned.uid=$1 AND dependent.uid<>$1",
        )
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        let plans: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT pdg.plan_id) FROM plan_device_groups pdg \
             JOIN device_groups owned ON owned.id=pdg.device_group_id WHERE owned.uid=$1",
        )
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        if cross_owner_rules > 0 || fallback_groups > 0 || plans > 0 {
            tx.rollback().await?;
            return Err(DbError::UserGroupReferenceConflict {
                rules: cross_owner_rules,
                fallback_groups,
                plans,
            });
        }
        // Lock historical user-owned tunnels after the user row. Rule binders
        // lock their rule owner before taking a SHARE lock on the tunnel, so
        // this order cannot form a cycle with a target-user deletion.
        sqlx::query("SELECT id FROM tunnels WHERE uid=$1 ORDER BY id FOR UPDATE")
            .bind(uid)
            .fetch_all(&mut *tx)
            .await?;
        let owned_tunnel_conflict: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT t.id),COUNT(DISTINCT refs.rule_id) FROM tunnels t \
             JOIN ( \
               SELECT id AS rule_id,tunnel_id FROM forward_rules \
                WHERE uid<>$1 AND tunnel_id IS NOT NULL \
               UNION \
               SELECT retired.rule_id,retired.tunnel_id \
                FROM forward_rule_retired_entries retired \
                JOIN forward_rules r ON r.id=retired.rule_id \
                WHERE r.uid<>$1 \
                  AND retired.expires_at >= EXTRACT(EPOCH FROM now())::BIGINT \
             ) refs ON refs.tunnel_id=t.id \
             WHERE t.uid=$1",
        )
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        if owned_tunnel_conflict.1 > 0 {
            tx.rollback().await?;
            return Err(DbError::UserOwnedTunnelConflict {
                tunnels: owned_tunnel_conflict.0,
                rules: owned_tunnel_conflict.1,
            });
        }
        sqlx::query("DELETE FROM forward_rules WHERE uid = $1")
            .bind(uid)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tunnel_profiles WHERE uid = $1")
            .bind(uid)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tunnels WHERE uid = $1")
            .bind(uid)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_groups WHERE uid = $1")
            .bind(uid)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM users WHERE id = $1 AND admin = FALSE")
            .bind(uid)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    async fn list_users_public(&self) -> Result<Vec<crate::api::admin::UserPublic>, DbError> {
        let users: Vec<crate::api::admin::UserPublic> =
            sqlx::query_as("SELECT * FROM users ORDER BY id")
                .fetch_all(&self.pool)
                .await?;
        Ok(users)
    }

    async fn count_placeholder_admin_password(&self) -> Result<i64, DbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE id = 1 AND password LIKE '$2b$12$PLACEHOLDER%'",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn replace_placeholder_admin_password(&self, hash: &str) -> Result<(), DbError> {
        // Also set must_change_password so the seeded "admin123" forces a change
        // on first login. This fires ONLY while the password is still the
        // placeholder (first boot); once the admin sets a real password the LIKE
        // guard never matches again, so we never re-flag a real account.
        sqlx::query(
            "UPDATE users SET password = $1, must_change_password = TRUE \
             WHERE id = 1 AND password LIKE '$2b$12$PLACEHOLDER%'",
        )
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
