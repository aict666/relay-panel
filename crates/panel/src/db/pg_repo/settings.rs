use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::Plan;

fn valid_plan_lifecycle(plan_type: &str, duration_days: i32, reset_traffic: bool) -> bool {
    match plan_type {
        "data" => duration_days >= 0,
        "time" => duration_days > 0,
        "monthly" => duration_days == 30 && reset_traffic,
        _ => false,
    }
}

// ── PlanRepository ──

#[async_trait]
impl PlanRepository for PgRepository {
    async fn list_plans(&self) -> Result<Vec<Plan>, DbError> {
        let plans: Vec<Plan> = sqlx::query_as("SELECT * FROM plans ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(plans)
    }

    async fn list_visible_plans(&self) -> Result<Vec<Plan>, DbError> {
        let plans: Vec<Plan> =
            sqlx::query_as("SELECT * FROM plans WHERE hidden = FALSE ORDER BY id")
                .fetch_all(&self.pool)
                .await?;
        Ok(plans)
    }

    async fn find_plan_name_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT name FROM plans WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(n,)| n))
    }

    async fn find_plan_by_id(&self, id: i64) -> Result<Option<Plan>, DbError> {
        let plan: Option<Plan> = sqlx::query_as("SELECT * FROM plans WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(plan)
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_plan(
        &self,
        name: &str,
        max_rules: i32,
        traffic: i64,
        price: &str,
        plan_type: &str,
        duration_days: i32,
        hidden: bool,
        reset_traffic: bool,
        description: &str,
        grant_all_groups: bool,
    ) -> Result<i64, DbError> {
        if !valid_plan_lifecycle(plan_type, duration_days, reset_traffic) {
            return Err(DbError::PlanInvariant);
        }
        // RETURNING id (PG); speed_limit/ip_limit keep their defaults.
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO plans \
             (name, max_rules, traffic, price, plan_type, duration_days, hidden, reset_traffic, description, grant_all_groups) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
        )
        .bind(name)
        .bind(max_rules)
        .bind(traffic)
        .bind(price)
        .bind(plan_type)
        .bind(duration_days)
        .bind(hidden)
        .bind(reset_traffic)
        .bind(description)
        .bind(grant_all_groups)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_plan_with_groups(
        &self,
        name: &str,
        max_rules: i32,
        traffic: i64,
        price: &str,
        plan_type: &str,
        duration_days: i32,
        hidden: bool,
        reset_traffic: bool,
        description: &str,
        grant_all_groups: bool,
        device_group_ids: &[i64],
    ) -> Result<i64, DbError> {
        if !valid_plan_lifecycle(plan_type, duration_days, reset_traffic) {
            return Err(DbError::PlanInvariant);
        }
        let mut tx = self.pool.begin().await?;
        let mut group_ids = device_group_ids.to_vec();
        group_ids.sort_unstable();
        group_ids.dedup();
        for group_id in &group_ids {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            let valid: Option<i64> = sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users u ON u.id = dg.uid \
                 WHERE dg.id = $1 AND dg.group_type IN ('in', 'both') AND u.admin = TRUE",
            )
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::PlanDeviceGroupInvalid);
            }
        }
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO plans \
             (name, max_rules, traffic, price, plan_type, duration_days, hidden, reset_traffic, description, grant_all_groups) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
        )
        .bind(name)
        .bind(max_rules)
        .bind(traffic)
        .bind(price)
        .bind(plan_type)
        .bind(duration_days)
        .bind(hidden)
        .bind(reset_traffic)
        .bind(description)
        .bind(grant_all_groups)
        .fetch_one(&mut *tx)
        .await?;
        let id = row.0;
        for dg in &group_ids {
            sqlx::query(
                "INSERT INTO plan_device_groups (plan_id, device_group_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(dg)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_plan_fields(
        &self,
        id: i64,
        name: Option<&str>,
        max_rules: Option<i32>,
        traffic: Option<i64>,
        price: Option<&str>,
        plan_type: Option<&str>,
        duration_days: Option<i32>,
        hidden: Option<bool>,
        reset_traffic: Option<bool>,
        description: Option<&str>,
        grant_all_groups: Option<bool>,
        device_group_ids: Option<&[i64]>,
    ) -> Result<u64, DbError> {
        let billing_changed = name.is_some()
            || max_rules.is_some()
            || traffic.is_some()
            || price.is_some()
            || plan_type.is_some()
            || duration_days.is_some()
            || hidden.is_some()
            || reset_traffic.is_some()
            || grant_all_groups.is_some()
            || device_group_ids.is_some();
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ");
        }
        if max_rules.is_some() {
            sets.push("max_rules = ");
        }
        if traffic.is_some() {
            sets.push("traffic = ");
        }
        if price.is_some() {
            sets.push("price = ");
        }
        if plan_type.is_some() {
            sets.push("plan_type = ");
        }
        if duration_days.is_some() {
            sets.push("duration_days = ");
        }
        if hidden.is_some() {
            sets.push("hidden = ");
        }
        if reset_traffic.is_some() {
            sets.push("reset_traffic = ");
        }
        if description.is_some() {
            sets.push("description = ");
        }
        if grant_all_groups.is_some() {
            sets.push("grant_all_groups = ");
        }

        let normalized_group_ids = device_group_ids.map(|group_ids| {
            let mut group_ids = group_ids.to_vec();
            group_ids.sort_unstable();
            group_ids.dedup();
            group_ids
        });
        let mut tx = self.pool.begin().await?;

        if normalized_group_ids.is_some() {
            // Preserve the repository's 0 = missing contract even if the same
            // request contains an invalid grant. This is intentionally an
            // unlocked preflight so group -> plan remains the lock order; the
            // later UPDATE/FOR UPDATE is still authoritative under a race.
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM plans WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
            if exists.is_none() {
                tx.rollback().await?;
                return Ok(0);
            }
        }

        // Keep the global PostgreSQL write order at group -> plan. Other paths
        // (group mutation and set_plan_device_groups) take the same advisory
        // group locks before touching plan/grant rows. Updating the plan row
        // first here could otherwise deadlock with a concurrent grant replace.
        if let Some(group_ids) = &normalized_group_ids {
            for group_id in group_ids {
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(group_id)
                    .execute(&mut *tx)
                    .await?;
                let valid: Option<i64> = sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users u ON u.id = dg.uid \
                     WHERE dg.id = $1 AND dg.group_type IN ('in', 'both') AND u.admin = TRUE",
                )
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
                if valid.is_none() {
                    tx.rollback().await?;
                    return Err(DbError::PlanDeviceGroupInvalid);
                }
            }
        }

        let existing: Option<(String, i32, bool)> = sqlx::query_as(
            "SELECT plan_type, duration_days, reset_traffic FROM plans WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((stored_type, stored_duration, stored_reset)) = existing else {
            tx.rollback().await?;
            return Ok(0);
        };
        let effective_type = plan_type.unwrap_or(&stored_type);
        if !valid_plan_lifecycle(
            effective_type,
            duration_days.unwrap_or(stored_duration),
            reset_traffic.unwrap_or(stored_reset),
        ) {
            tx.rollback().await?;
            return Err(DbError::PlanInvariant);
        }

        let rows_affected = if sets.is_empty() && !billing_changed {
            1
        } else {
            let mut ph = 1;
            let mut sets_with_ph: Vec<String> = sets
                .iter()
                .map(|s| {
                    let p = format!("{s}${ph}");
                    ph += 1;
                    p
                })
                .collect();
            if billing_changed {
                sets_with_ph.push("billing_revision = billing_revision + 1".to_string());
            }
            let id_ph = ph;
            let sql = format!(
                "UPDATE plans SET {} WHERE id = ${}",
                sets_with_ph.join(", "),
                id_ph
            );

            let mut q = sqlx::query(&sql);
            if let Some(v) = name {
                q = q.bind(v);
            }
            if let Some(v) = max_rules {
                q = q.bind(v);
            }
            if let Some(v) = traffic {
                q = q.bind(v);
            }
            if let Some(v) = price {
                q = q.bind(v);
            }
            if let Some(v) = plan_type {
                q = q.bind(v);
            }
            if let Some(v) = duration_days {
                q = q.bind(v);
            }
            if let Some(v) = hidden {
                q = q.bind(v);
            }
            if let Some(v) = reset_traffic {
                q = q.bind(v);
            }
            if let Some(v) = description {
                q = q.bind(v);
            }
            if let Some(v) = grant_all_groups {
                q = q.bind(v);
            }
            q.bind(id).execute(&mut *tx).await?.rows_affected()
        };

        if rows_affected == 0 {
            tx.rollback().await?;
            return Ok(0);
        }

        // Any purchase-affecting edit invalidates the user's accepted recurring
        // billing contract. Lock order is group -> plan -> users everywhere.
        if billing_changed {
            sqlx::query(
                "UPDATE users SET plan_auto_renew = FALSE, \
                 plan_auto_renew_price = NULL, plan_auto_renew_revision = NULL, \
                 plan_auto_renew_retry_at = NULL WHERE plan_id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(group_ids) = &normalized_group_ids {
            sqlx::query("DELETE FROM plan_device_groups WHERE plan_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for group_id in group_ids {
                sqlx::query(
                    "INSERT INTO plan_device_groups (plan_id, device_group_id) \
                     VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(id)
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(rows_affected)
    }

    async fn delete_plan(&self, id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM plans WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn delete_plan_checked(&self, id: i64) -> Result<PlanDeleteOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(REGISTRATION_SETTINGS_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM plans WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(PlanDeleteOutcome::NotFound);
        }

        let settings: Option<(i64, String)> = sqlx::query_as(
            "SELECT default_registration_plan_id, registration_allowed_plan_ids \
             FROM app_settings WHERE id = 1 FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((default_plan_id, raw_allowed)) = settings {
            if default_plan_id == id {
                tx.rollback().await?;
                return Ok(PlanDeleteOutcome::RegistrationDefault);
            }
            let allowed_plan_ids = match parse_allowed_plan_ids(&raw_allowed) {
                Ok(ids) => ids,
                Err(error) => {
                    tx.rollback().await?;
                    return Err(error);
                }
            };
            if allowed_plan_ids.contains(&id) {
                tx.rollback().await?;
                return Ok(PlanDeleteOutcome::RegistrationAllowed);
            }
        }

        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE plan_id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if users > 0 {
            tx.rollback().await?;
            return Ok(PlanDeleteOutcome::InUse { users });
        }

        sqlx::query("DELETE FROM plans WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(PlanDeleteOutcome::Deleted)
    }

    async fn count_users_on_plan(&self, plan_id: i64) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE plan_id = $1")
            .bind(plan_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    async fn list_due_subscription_user_ids(
        &self,
        now: &str,
        limit: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar("SELECT DISTINCT u.id FROM users u JOIN subscription_cycles c ON c.user_id=u.id AND c.subscription_id=u.subscription_id WHERE c.cancelled=FALSE AND c.starts_at<=$1 AND (c.ends_at IS NULL OR c.ends_at>$1) AND c.id<>COALESCE(u.current_cycle_id,'') ORDER BY u.id LIMIT $2")
            .bind(now).bind(limit.clamp(1,500)).fetch_all(&self.pool).await?)
    }

    async fn activate_subscription_cycle(&self, user_id: i64, now: &str) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        // Snapshot grants must be locked before the user (global lock order).
        let snapshots: Vec<String> = sqlx::query_scalar("SELECT c.entitlement_snapshot FROM subscription_cycles c JOIN users u ON u.id=c.user_id AND u.subscription_id=c.subscription_id WHERE u.id=$1 AND c.cancelled=FALSE AND c.starts_at<=$2 AND (c.ends_at IS NULL OR c.ends_at>$2) AND c.id<>COALESCE(u.current_cycle_id,'')")
            .bind(user_id).bind(now).fetch_all(&mut *tx).await?;
        let mut groups = Vec::new();
        for raw in &snapshots {
            groups.extend(
                crate::service::billing::EntitlementSnapshot::decode(raw)?.device_group_ids,
            );
        }
        groups.sort_unstable();
        groups.dedup();
        for group in groups {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        // Re-read under the lock. A purchase may have added a different due
        // snapshot while we waited: retry instead of activating unlocked grants.
        let locked: Vec<String> = sqlx::query_scalar("SELECT c.entitlement_snapshot FROM subscription_cycles c JOIN users u ON u.id=c.user_id AND u.subscription_id=c.subscription_id WHERE u.id=$1 AND c.cancelled=FALSE AND c.starts_at<=$2 AND (c.ends_at IS NULL OR c.ends_at>$2) AND c.id<>COALESCE(u.current_cycle_id,'')")
            .bind(user_id).bind(now).fetch_all(&mut *tx).await?;
        if locked != snapshots {
            return Ok(false);
        }
        let changed = super::billing::activate_paid_cycle(&mut tx, user_id, now).await?;
        tx.commit().await?;
        Ok(changed)
    }

    async fn list_expired_monthly_auto_renew_user_ids(
        &self,
        now: &str,
        limit: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT u.id FROM users u JOIN plans p ON p.id=u.plan_id \
             WHERE u.admin=FALSE AND u.banned=FALSE AND u.suspended=FALSE AND u.plan_auto_renew=TRUE AND p.plan_type='monthly' \
               AND u.plan_expire_at IS NOT NULL AND u.plan_expire_at<=$1 \
               AND (u.plan_auto_renew_retry_at IS NULL OR u.plan_auto_renew_retry_at<=$1) \
             ORDER BY COALESCE(u.plan_auto_renew_retry_at, u.plan_expire_at), u.id LIMIT $2",
        )
        .bind(now)
        .bind(limit.clamp(1, 500))
        .fetch_all(&self.pool)
        .await?)
    }

    async fn renew_expired_monthly_plan(
        &self,
        user_id: i64,
        now: &str,
    ) -> Result<MonthlyRenewalOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        let initial_plan_id: Option<i64> =
            sqlx::query_scalar("SELECT plan_id FROM users WHERE id=$1")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
        let Some(initial_plan_id) = initial_plan_id else {
            tx.rollback().await?;
            return Ok(MonthlyRenewalOutcome::NotEligible);
        };
        let preliminary_group_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT device_group_id FROM plan_device_groups WHERE plan_id=$1 ORDER BY device_group_id",
        )
        .bind(initial_plan_id)
        .fetch_all(&mut *tx)
        .await?;
        // Global lock order: grant groups -> plan -> user.
        for group_id in &preliminary_group_ids {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
        }
        let plan: Option<(String, String, i64, i32, i32, bool, bool, i64)> = sqlx::query_as(
            "SELECT name, price, traffic, max_rules, duration_days, reset_traffic, \
                    grant_all_groups, billing_revision \
             FROM plans WHERE id=$1 AND plan_type='monthly' FOR SHARE",
        )
        .bind(initial_plan_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((
            plan_name,
            price,
            traffic,
            max_rules,
            duration_days,
            reset_traffic,
            grant_all_groups,
            billing_revision,
        )) = plan
        else {
            tx.rollback().await?;
            return Ok(MonthlyRenewalOutcome::NotEligible);
        };
        let group_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT device_group_id FROM plan_device_groups WHERE plan_id=$1 ORDER BY device_group_id",
        )
        .bind(initial_plan_id)
        .fetch_all(&mut *tx)
        .await?;
        let row: Option<(
            String,
            Option<i64>,
            bool,
            bool,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT balance, plan_id, admin, plan_auto_renew, plan_expire_at, \
                    plan_auto_renew_price, plan_auto_renew_revision, \
                    plan_auto_renew_retry_at \
              FROM users WHERE id=$1 AND banned=FALSE AND suspended=FALSE FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((
            balance,
            current_plan_id,
            admin,
            auto_renew,
            expire_at,
            accepted_price,
            accepted_revision,
            retry_at,
        )) = row
        else {
            tx.rollback().await?;
            return Ok(MonthlyRenewalOutcome::NotEligible);
        };
        if admin
            || !auto_renew
            || current_plan_id != Some(initial_plan_id)
            || expire_at.as_deref().is_none_or(|expires| expires > now)
            || retry_at.as_deref().is_some_and(|retry| retry > now)
        {
            tx.rollback().await?;
            return Ok(MonthlyRenewalOutcome::NotEligible);
        }
        if !reset_traffic
            || duration_days != 30
            || accepted_price.as_deref() != Some(price.as_str())
            || accepted_revision != Some(billing_revision)
            || group_ids != preliminary_group_ids
        {
            sqlx::query(
                "UPDATE users SET plan_auto_renew=FALSE, plan_auto_renew_price=NULL, \
                 plan_auto_renew_revision=NULL, plan_auto_renew_retry_at=NULL WHERE id=$1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(MonthlyRenewalOutcome::ContractChanged);
        }
        if !grant_all_groups {
            for group_id in &group_ids {
                let valid: Option<i64> = sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                     WHERE dg.id=$1 AND dg.group_type IN ('in','both') AND owner.admin=TRUE",
                )
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
                if valid.is_none() {
                    sqlx::query(
                        "UPDATE users SET plan_auto_renew=FALSE, plan_auto_renew_price=NULL, \
                         plan_auto_renew_revision=NULL, plan_auto_renew_retry_at=NULL WHERE id=$1",
                    )
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await?;
                    return Ok(MonthlyRenewalOutcome::ContractChanged);
                }
            }
        }
        let balance_cents = relay_shared::money::balance_to_cents(&balance)
            .ok_or(DbError::InvalidData("non-canonical user balance"))?;
        let price_cents = relay_shared::money::balance_to_cents(
            accepted_price
                .as_deref()
                .expect("accepted price checked above"),
        )
        .ok_or(DbError::InvalidData("non-canonical monthly plan price"))?;
        if balance_cents < price_cents {
            sqlx::query(
                "UPDATE users SET plan_auto_renew_retry_at=to_char(\
                   $1::timestamp + interval '60 seconds', 'YYYY-MM-DD HH24:MI:SS') WHERE id=$2",
            )
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(MonthlyRenewalOutcome::InsufficientBalance);
        }
        let next_expire: String = sqlx::query_scalar(
            "SELECT to_char($1::timestamp + make_interval(days => $2), \
                    'YYYY-MM-DD HH24:MI:SS')",
        )
        .bind(now)
        .bind(duration_days)
        .fetch_one(&mut *tx)
        .await?;
        let new_balance = relay_shared::money::cents_to_balance(balance_cents - price_cents);
        let snapshot = crate::service::billing::EntitlementSnapshot {
            plan_id: initial_plan_id,
            plan_name: plan_name.clone(),
            plan_type: "monthly".into(),
            traffic_limit: traffic,
            max_rules,
            grant_all_groups,
            device_group_ids: group_ids.clone(),
            billing_revision,
        };
        let cycle = super::billing::replace_cycle(
            &mut tx,
            user_id,
            now,
            Some(&next_expire),
            &snapshot,
            "paid",
            None,
        )
        .await?;
        sqlx::query(
            "UPDATE users SET balance=$1, traffic_limit=$2, traffic_used=0, max_rules=$3, \
             plan_expire_at=$4, plan_auto_renew_retry_at=NULL, all_device_groups=$5 \
             WHERE id=$6",
        )
        .bind(&new_balance)
        .bind(traffic)
        .bind(max_rules)
        .bind(&next_expire)
        .bind(grant_all_groups)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE forward_rules SET traffic_used=0 WHERE uid=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM user_device_groups WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if !grant_all_groups {
            for group_id in &group_ids {
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
        if grant_all_groups {
            sqlx::query(
                "UPDATE forward_rules SET paused=TRUE, auto_paused=TRUE \
                 WHERE uid=$1 AND paused=FALSE AND device_group_in NOT IN (\
                   SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                   WHERE dg.group_type IN ('in','both') AND owner.admin=TRUE)",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE forward_rules SET paused=FALSE, auto_paused=FALSE \
                 WHERE uid=$1 AND paused=TRUE AND auto_paused=TRUE AND device_group_in IN (\
                   SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                   WHERE dg.group_type IN ('in','both') AND owner.admin=TRUE)",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else if group_ids.is_empty() {
            sqlx::query(
                "UPDATE forward_rules SET paused=TRUE, auto_paused=TRUE \
                 WHERE uid=$1 AND paused=FALSE",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else {
            let placeholders = (1..=group_ids.len())
                .map(|index| format!("${}", index + 1))
                .collect::<Vec<_>>()
                .join(", ");
            let pause_sql = format!(
                "UPDATE forward_rules SET paused=TRUE, auto_paused=TRUE \
                 WHERE uid=$1 AND paused=FALSE AND device_group_in NOT IN ({placeholders})"
            );
            let mut pause = sqlx::query(&pause_sql).bind(user_id);
            for group_id in &group_ids {
                pause = pause.bind(group_id);
            }
            pause.execute(&mut *tx).await?;
            let resume_sql = format!(
                "UPDATE forward_rules SET paused=FALSE, auto_paused=FALSE \
                 WHERE uid=$1 AND paused=TRUE AND auto_paused=TRUE \
                   AND device_group_in IN ({placeholders})"
            );
            let mut resume = sqlx::query(&resume_sql).bind(user_id);
            for group_id in &group_ids {
                resume = resume.bind(group_id);
            }
            resume.execute(&mut *tx).await?;
        }
        super::enforce_rule_limit(&mut tx, user_id).await?;
        super::billing::record_purchase(
            &mut tx,
            user_id,
            &balance,
            &new_balance,
            &relay_shared::money::cents_to_balance(price_cents),
            "auto_renew",
            &cycle,
            &snapshot,
            None,
            "Previously authorized automatic monthly renewal",
        )
        .await?;
        tx.commit().await?;
        Ok(MonthlyRenewalOutcome::Renewed {
            plan_id: initial_plan_id,
            plan_name,
        })
    }

    // v1.0.8: atomic plan purchase. PG defaults to READ COMMITTED, so the
    // SELECT ... FOR UPDATE row lock is what prevents 防双花: a concurrent tx
    // trying to lock the same user row blocks until this commits, then reads
    // the post-deduction balance. The lock + the UPDATE run on the same tx.
    async fn find_purchase_fingerprint(
        &self,
        user_id: i64,
        request_id: &str,
    ) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT fingerprint FROM purchase_requests WHERE user_id=$1 AND request_id=$2",
        )
        .bind(user_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn buy_plan_impl(
        &self,
        user_id: i64,
        plan_id: i64,
        plan_name: &str,
        price_cents: i64,
        traffic_to_add: i64,
        plan_max_rules: i32,
        duration_days: i32,
        reset_traffic: bool,
        grant_all_groups: bool,
        device_group_ids: &[i64],
        // v1.0.8: the NEW authorized group set AFTER purchase. Used inside the
        // transaction to pause rules outside this set (replacement semantics).
        new_authorized_group_ids: &[i64],
        plan_type: &str,
        auto_renew: bool,
        require_visible: bool,
        check_plan_snapshot: bool,
        expected_current_plan_id: Option<Option<i64>>,
        identity: Option<PurchaseIdentity<'_>>,
    ) -> Result<(), BuyPlanError> {
        let mut tx = self.pool.begin().await?;
        if let Some(identity) = identity {
            let inserted = sqlx::query("INSERT INTO purchase_requests (user_id, request_id, fingerprint, created_at) VALUES ($1, $2, $3, to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')) ON CONFLICT (user_id, request_id) DO NOTHING")
                .bind(user_id).bind(identity.request_id).bind(identity.fingerprint)
                .execute(&mut *tx).await?.rows_affected();
            if inserted == 0 {
                let saved: String = sqlx::query_scalar(
                    "SELECT fingerprint FROM purchase_requests WHERE user_id=$1 AND request_id=$2",
                )
                .bind(user_id)
                .bind(identity.request_id)
                .fetch_one(&mut *tx)
                .await?;
                tx.rollback().await?;
                return if saved == identity.fingerprint {
                    Ok(())
                } else {
                    Err(BuyPlanError::IdempotencyConflict)
                };
            }
        }
        let mut accepted_billing_price: Option<String> = None;
        let mut accepted_billing_revision: Option<i64> = None;

        // Plan/grant writers use group -> plan ordering. Lock the caller's
        // expected grant set before taking the shared plan-row lock below so a
        // purchase cannot deadlock with, or race, a grant replacement.
        if check_plan_snapshot && !grant_all_groups {
            let mut group_ids = device_group_ids.to_vec();
            group_ids.sort_unstable();
            group_ids.dedup();
            for group_id in group_ids {
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(group_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        // Hold a shared row lock so plan scalar/grant updates cannot cross the
        // charge transaction, and reject a snapshot resolved before a completed
        // admin edit. This prevents mixed old-price/new-plan purchases.
        if check_plan_snapshot {
            let current_plan: Option<(
                String,
                String,
                i64,
                i32,
                String,
                i32,
                bool,
                bool,
                bool,
                i64,
            )> = sqlx::query_as(
                "SELECT name, price, traffic, max_rules, plan_type, duration_days, \
                        reset_traffic, grant_all_groups, hidden, billing_revision \
                 FROM plans WHERE id = $1 FOR SHARE",
            )
            .bind(plan_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((
                current_name,
                current_price,
                current_traffic,
                current_max_rules,
                current_type,
                current_duration_days,
                current_reset_traffic,
                current_grant_all,
                current_hidden,
                current_billing_revision,
            )) = current_plan
            else {
                let _ = tx.rollback().await;
                return Err(BuyPlanError::PlanChanged);
            };
            let current_price_cents = relay_shared::money::balance_to_cents(&current_price)
                .ok_or_else(|| {
                    tracing::error!(
                        "buy_plan: plan {} has non-canonical price {:?}",
                        plan_id,
                        current_price
                    );
                    BuyPlanError::Database(DbError::NotFound)
                })?;
            let effective_current_duration = if matches!(current_type.as_str(), "time" | "monthly")
            {
                current_duration_days
            } else {
                0
            };
            let mut expected_group_ids = device_group_ids.to_vec();
            expected_group_ids.sort_unstable();
            expected_group_ids.dedup();
            let current_group_ids: Vec<i64> = if current_grant_all {
                Vec::new()
            } else {
                sqlx::query_scalar(
                    "SELECT device_group_id FROM plan_device_groups \
                 WHERE plan_id = $1 ORDER BY device_group_id",
                )
                .bind(plan_id)
                .fetch_all(&mut *tx)
                .await?
            };
            if !current_grant_all {
                for group_id in &current_group_ids {
                    let valid: Option<i64> = sqlx::query_scalar(
                        "SELECT dg.id FROM device_groups dg \
                         JOIN users owner ON owner.id=dg.uid \
                         WHERE dg.id=$1 AND dg.group_type IN ('in','both') \
                           AND owner.admin=TRUE",
                    )
                    .bind(group_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if valid.is_none() {
                        let _ = tx.rollback().await;
                        return Err(BuyPlanError::PlanChanged);
                    }
                }
            }
            let snapshot_changed = (require_visible && current_hidden)
                || current_name != plan_name
                || current_price_cents != price_cents
                || current_traffic != traffic_to_add
                || current_max_rules != plan_max_rules
                || current_type != plan_type
                || effective_current_duration != duration_days
                || current_reset_traffic != reset_traffic
                || current_grant_all != grant_all_groups
                || (!current_grant_all && current_group_ids != expected_group_ids);
            if snapshot_changed {
                let _ = tx.rollback().await;
                return Err(BuyPlanError::PlanChanged);
            }
            accepted_billing_price = Some(current_price);
            accepted_billing_revision = Some(current_billing_revision);
        }

        // FOR UPDATE locks the user row for the tx's duration.
        let row: Option<(String, Option<String>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT balance, plan_expire_at, plan_id, traffic_limit \
             FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((balance_str, current_expire, current_plan_id, current_traffic_limit)) = row
        else {
            let _ = tx.rollback().await;
            return Err(BuyPlanError::Database(DbError::NotFound));
        };
        if expected_current_plan_id.is_some_and(|expected| expected != current_plan_id) {
            let _ = tx.rollback().await;
            return Err(BuyPlanError::UserPlanChanged);
        }

        let balance_cents =
            relay_shared::money::balance_to_cents(&balance_str).ok_or_else(|| {
                tracing::error!(
                    "buy_plan: user {} has non-canonical balance {:?}",
                    user_id,
                    balance_str
                );
                BuyPlanError::Database(DbError::NotFound)
            })?;
        if balance_cents < price_cents {
            let _ = tx.rollback().await;
            return Err(BuyPlanError::InsufficientBalance);
        }
        let new_balance = relay_shared::money::cents_to_balance(balance_cents - price_cents);

        // Renew (same plan) vs switch (different plan, or none). See the sqlite
        // impl for the full rationale:
        //   - switch: traffic_limit = new, traffic_used = 0, expiry = now + days
        //             (fresh start, no carry-over).
        //   - renew:  traffic_limit += new, traffic_used kept, expiry stacks
        //             from max(now, current) + days.
        let is_switch = current_plan_id != Some(plan_id);
        let is_monthly = plan_type == "monthly";
        if is_monthly && auto_renew {
            let unavailable: bool =
                sqlx::query_scalar("SELECT banned OR suspended FROM users WHERE id=$1")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if unavailable {
                tx.rollback().await?;
                return Err(BuyPlanError::AutoRenewUnavailable);
            }
        }
        let now = crate::service::billing::now();
        let current_cycle = super::billing::ensure_cycle(&mut tx, user_id).await?;
        let snapshot = crate::service::billing::EntitlementSnapshot {
            plan_id,
            plan_name: plan_name.into(),
            plan_type: plan_type.into(),
            traffic_limit: traffic_to_add,
            max_rules: plan_max_rules,
            grant_all_groups,
            device_group_ids: device_group_ids.to_vec(),
            billing_revision: accepted_billing_revision.unwrap_or(1),
        };
        if is_monthly
            && !is_switch
            && current_expire
                .as_deref()
                .is_some_and(|end| end > now.as_str())
        {
            let start = current_expire.as_deref().expect("checked expiry");
            let end = crate::service::billing::add_days(start, duration_days)?;
            let cycle = super::billing::insert_cycle(
                &mut tx,
                user_id,
                current_cycle.as_ref().map(|c| c.subscription_id.as_str()),
                start,
                Some(&end),
                0,
                &snapshot,
                "paid",
            )
            .await?;
            sqlx::query("UPDATE users SET balance=$1,plan_expire_at=$2,plan_auto_renew=$3,plan_auto_renew_price=$4,plan_auto_renew_revision=$5,plan_auto_renew_retry_at=NULL WHERE id=$6")
                .bind(&new_balance).bind(&end).bind(auto_renew)
                .bind(auto_renew.then_some(accepted_billing_price).flatten())
                .bind(auto_renew.then_some(accepted_billing_revision).flatten()).bind(user_id).execute(&mut *tx).await?;
            super::billing::record_purchase(
                &mut tx,
                user_id,
                &balance_str,
                &new_balance,
                &relay_shared::money::cents_to_balance(price_cents),
                "prepayment",
                &cycle,
                &snapshot,
                identity,
                "Prepaid monthly period; current usage unchanged",
            )
            .await?;
            tx.commit().await?;
            return Ok(());
        }
        let prepaid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription_cycles WHERE user_id=$1 AND cancelled=FALSE AND id<>COALESCE((SELECT current_cycle_id FROM users WHERE id=$1),'') AND (ends_at IS NULL OR ends_at>$2)")
            .bind(user_id).bind(&now).fetch_one(&mut *tx).await?;
        if prepaid > 0 {
            return Err(BuyPlanError::PrepaidCyclesPresent);
        }
        let new_traffic_limit = if is_switch
            || is_monthly
            || reset_traffic
            || traffic_to_add == 0
            || current_traffic_limit == 0
        {
            if traffic_to_add < 0 {
                let _ = tx.rollback().await;
                return Err(BuyPlanError::QuotaOverflow);
            }
            traffic_to_add
        } else {
            match current_traffic_limit.checked_add(traffic_to_add) {
                Some(value) if value >= 0 => value,
                _ => {
                    let _ = tx.rollback().await;
                    return Err(BuyPlanError::QuotaOverflow);
                }
            }
        };

        // Compute the new expiry. duration_days=0 → NULL. Canonical TEXT
        // 'YYYY-MM-DD HH:MM:SS' UTC (lexically comparable, same as created_at).
        let new_expire = if duration_days <= 0 {
            None
        } else {
            let base = if is_switch {
                now.as_str()
            } else {
                current_expire.as_deref().unwrap_or(&now).max(&now)
            };
            Some(crate::service::billing::add_days(base, duration_days)?)
        };
        let mut effective_snapshot = snapshot.clone();
        effective_snapshot.traffic_limit = new_traffic_limit;
        let cycle = if is_switch || is_monthly || reset_traffic {
            super::billing::replace_cycle(
                &mut tx,
                user_id,
                &now,
                new_expire.as_deref(),
                &effective_snapshot,
                "paid",
                None,
            )
            .await?
        } else {
            super::billing::sync_cycle(&mut tx, user_id, new_expire.as_deref(), &effective_snapshot)
                .await?
        };

        if is_switch || is_monthly {
            // Switch: traffic_limit = new quota, traffic_used reset to 0.
            sqlx::query(
                "UPDATE users SET \
                 balance = $1, traffic_limit = $2, traffic_used = 0, max_rules = $3, \
                 plan_id = $4, plan_expire_at = $5, plan_auto_renew = $6, \
                 plan_auto_renew_price = $7, plan_auto_renew_revision = $8, \
                 plan_auto_renew_retry_at = NULL WHERE id = $9",
            )
            .bind(&new_balance)
            .bind(new_traffic_limit)
            .bind(plan_max_rules)
            .bind(plan_id)
            .bind(&new_expire)
            .bind(is_monthly && auto_renew)
            .bind(
                (is_monthly && auto_renew)
                    .then_some(accepted_billing_price)
                    .flatten(),
            )
            .bind(
                (is_monthly && auto_renew)
                    .then_some(accepted_billing_revision)
                    .flatten(),
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else if reset_traffic {
            // Explicit reset replaces quota and zeros usage (no historical refund).
            sqlx::query(
                "UPDATE users SET \
                 balance = $1, traffic_limit = $2, traffic_used = 0, \
                 max_rules = $3, plan_id = $4, plan_expire_at = $5, plan_auto_renew = FALSE, \
                 plan_auto_renew_price = NULL, plan_auto_renew_revision = NULL, \
                 plan_auto_renew_retry_at = NULL \
                 WHERE id = $6",
            )
            .bind(&new_balance)
            .bind(new_traffic_limit)
            .bind(plan_max_rules)
            .bind(plan_id)
            .bind(&new_expire)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else {
            // Renew: stack quota, keep usage.
            sqlx::query(
                "UPDATE users SET \
                 balance = $1, traffic_limit = $2, max_rules = $3, \
                 plan_id = $4, plan_expire_at = $5, plan_auto_renew = FALSE, \
                 plan_auto_renew_price = NULL, plan_auto_renew_revision = NULL, \
                 plan_auto_renew_retry_at = NULL \
                 WHERE id = $6",
            )
            .bind(&new_balance)
            .bind(new_traffic_limit)
            .bind(plan_max_rules)
            .bind(plan_id)
            .bind(&new_expire)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        if is_switch || is_monthly || reset_traffic {
            sqlx::query("UPDATE forward_rules SET traffic_used = 0 WHERE uid = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }

        let price_str = relay_shared::money::cents_to_balance(price_cents);
        super::billing::record_purchase(
            &mut tx,
            user_id,
            &balance_str,
            &new_balance,
            &price_str,
            "purchase",
            &cycle,
            &effective_snapshot,
            identity,
            "Confirmed plan purchase",
        )
        .await?;

        // v1.0.8: grant device-group authorization in the SAME tx (mirrors the
        // SQLite impl). Purchase REPLACES the user's authorization — BOTH
        // dimensions are reset so exactly the new plan's grant remains:
        //   - grant_all_groups → set all_device_groups=TRUE AND clear explicit
        //     user_device_groups rows.
        //   - else → clear all_device_groups=FALSE AND replace user_device_groups.
        //     Resetting the flag is the fix for the grant-all → per-group
        //     downgrade case (without it the user stayed unrestricted).
        if grant_all_groups {
            sqlx::query(
                "UPDATE users SET all_device_groups = TRUE WHERE id = $1 AND admin = FALSE",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        } else {
            // REPLACE semantics: reset the all-groups flag, clear old explicit
            // assignments, then insert the plan's.
            sqlx::query(
                "UPDATE users SET all_device_groups = FALSE WHERE id = $1 AND admin = FALSE",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            for dg_id in device_group_ids {
                sqlx::query(
                    "INSERT INTO user_device_groups (user_id, device_group_id) VALUES ($1, $2)",
                )
                .bind(user_id)
                .bind(dg_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Pause rules outside the new authorization (same logic as SQLite).
        // Inline the pause logic inside the transaction (using &mut *tx) to
        // avoid acquiring a separate pool connection while the transaction is
        // still open — that would risk a pool-exhaustion deadlock.
        // v1.0.8: auto_paused=TRUE marks these as SYSTEM pauses (see the resume
        // step below and the column doc on forward_rules.auto_paused).
        let n = if grant_all_groups {
            0
        } else if new_authorized_group_ids.is_empty() {
            let r = sqlx::query(
                "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
                 WHERE uid = $1 AND paused = FALSE",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            r.rows_affected()
        } else {
            let placeholders = (1..=new_authorized_group_ids.len())
                .map(|i| format!("${}", i + 1))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "UPDATE forward_rules SET paused = TRUE, auto_paused = TRUE \
                 WHERE uid = $1 AND paused = FALSE AND device_group_in NOT IN ({})",
                placeholders
            );
            let mut q = sqlx::query(&sql).bind(user_id);
            for gid in new_authorized_group_ids {
                q = q.bind(gid);
            }
            let r = q.execute(&mut *tx).await?;
            r.rows_affected()
        };
        if n > 0 {
            tracing::warn!(
                "buy_plan: user {} purchased plan {}, {} rule(s) paused due to authorization change",
                user_id, plan_id, n
            );
        }

        // v1.0.8: symmetric auto-resume — a rule this system previously paused
        // (auto_paused=TRUE) whose group is back in the new authorized set gets
        // un-paused here. A rule the user paused THEMSELVES (auto_paused=FALSE,
        // e.g. via the on/off switch) is deliberately left alone even if its
        // group is authorized again — buying a plan must never silently revive
        // a rule the user turned off on purpose.
        if grant_all_groups {
            let resumed = sqlx::query(
                "UPDATE forward_rules SET paused = FALSE, auto_paused = FALSE \
                 WHERE uid = $1 AND paused = TRUE AND auto_paused = TRUE \
                   AND device_group_in IN (\
                     SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                     WHERE dg.group_type IN ('in', 'both') AND owner.admin=TRUE\
                   )",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if resumed > 0 {
                tracing::info!(
                    "buy_plan: user {} purchased grant-all plan {}, {} previously auto-paused rule(s) resumed",
                    user_id,
                    plan_id,
                    resumed
                );
            }
        } else if !new_authorized_group_ids.is_empty() {
            let placeholders = (1..=new_authorized_group_ids.len())
                .map(|i| format!("${}", i + 1))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "UPDATE forward_rules SET paused = FALSE, auto_paused = FALSE \
                 WHERE uid = $1 AND paused = TRUE AND auto_paused = TRUE \
                 AND device_group_in IN ({})",
                placeholders
            );
            let mut q = sqlx::query(&sql).bind(user_id);
            for gid in new_authorized_group_ids {
                q = q.bind(gid);
            }
            let resumed = q.execute(&mut *tx).await?.rows_affected();
            if resumed > 0 {
                tracing::info!(
                    "buy_plan: user {} purchased plan {}, {} previously auto-paused rule(s) resumed",
                    user_id, plan_id, resumed
                );
            }
        }

        super::enforce_rule_limit(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_plan_device_groups(&self, plan_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM plan_device_groups \
             WHERE plan_id = $1 ORDER BY device_group_id",
        )
        .bind(plan_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn set_plan_device_groups(
        &self,
        plan_id: i64,
        device_group_ids: &[i64],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let mut group_ids = device_group_ids.to_vec();
        group_ids.sort_unstable();
        group_ids.dedup();
        let target_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM plans WHERE id = $1")
            .bind(plan_id)
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
                 JOIN users u ON u.id = dg.uid \
                 WHERE dg.id = $1 AND dg.group_type IN ('in', 'both') AND u.admin = TRUE",
            )
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::PlanDeviceGroupInvalid);
            }
        }
        // Lock the parent before touching grant rows. This prevents a
        // delete-vs-replace deadlock where DELETE owns the plan row while
        // waiting for child rows and replacement waits on the parent FK.
        let plan_exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM plans WHERE id = $1 FOR UPDATE")
                .bind(plan_id)
                .fetch_optional(&mut *tx)
                .await?;
        if plan_exists.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        sqlx::query("DELETE FROM plan_device_groups WHERE plan_id = $1")
            .bind(plan_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in &group_ids {
            sqlx::query(
                "INSERT INTO plan_device_groups (plan_id, device_group_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(plan_id)
            .bind(dg_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE plans SET billing_revision = billing_revision + 1 WHERE id = $1")
            .bind(plan_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE users SET plan_auto_renew = FALSE, \
             plan_auto_renew_price = NULL, plan_auto_renew_revision = NULL, \
             plan_auto_renew_retry_at = NULL WHERE plan_id = $1",
        )
        .bind(plan_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

// ── Helpers ──

fn parse_allowed_plan_ids(raw: &str) -> Result<Vec<i64>, DbError> {
    serde_json::from_str::<Vec<i64>>(raw).map_err(|_| {
        DbError::InvalidData("registration_allowed_plan_ids is not a JSON integer array")
    })
}

fn serialize_allowed_plan_ids(ids: &[i64]) -> String {
    serde_json::to_string(ids).expect("integer allow-list is JSON-serializable")
}

#[async_trait]
impl SettingsRepository for PgRepository {
    async fn get_registration_settings(&self) -> Result<Option<RegistrationSettings>, DbError> {
        let row: Option<(bool, i64, String, String)> = sqlx::query_as(
            "SELECT registration_enabled, default_registration_plan_id, \
             registration_allowed_plan_ids, site_name FROM app_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((enabled, plan_id, raw_allowed, site_name)) => {
                let allowed = parse_allowed_plan_ids(&raw_allowed)?;
                Ok(Some(RegistrationSettings {
                    registration_enabled: enabled,
                    default_registration_plan_id: plan_id,
                    allowed_plan_ids: allowed,
                    site_name,
                }))
            }
            None => Ok(None),
        }
    }

    async fn insert_settings_if_absent(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
    ) -> Result<(), DbError> {
        let allowed_json = serialize_allowed_plan_ids(allowed_plan_ids);
        sqlx::query(
            "INSERT INTO app_settings (id, registration_enabled, \
             default_registration_plan_id, registration_allowed_plan_ids) \
             VALUES (1, $1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(enabled)
        .bind(default_plan_id)
        .bind(&allowed_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_registration_settings(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
    ) -> Result<(), DbError> {
        let allowed_json = serialize_allowed_plan_ids(allowed_plan_ids);
        sqlx::query(
            "INSERT INTO app_settings (id, registration_enabled, \
             default_registration_plan_id, registration_allowed_plan_ids) \
             VALUES (1, $1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET \
                 registration_enabled = EXCLUDED.registration_enabled, \
                 default_registration_plan_id = EXCLUDED.default_registration_plan_id, \
                 registration_allowed_plan_ids = EXCLUDED.registration_allowed_plan_ids",
        )
        .bind(enabled)
        .bind(default_plan_id)
        .bind(&allowed_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_system_settings(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
        site_name: &str,
    ) -> Result<(), DbError> {
        let allowed_json = serialize_allowed_plan_ids(allowed_plan_ids);
        sqlx::query(
            "INSERT INTO app_settings (id, registration_enabled, \
             default_registration_plan_id, registration_allowed_plan_ids, site_name) \
             VALUES (1, $1, $2, $3, $4) \
             ON CONFLICT (id) DO UPDATE SET \
                 registration_enabled = EXCLUDED.registration_enabled, \
                 default_registration_plan_id = EXCLUDED.default_registration_plan_id, \
                 registration_allowed_plan_ids = EXCLUDED.registration_allowed_plan_ids, \
                 site_name = EXCLUDED.site_name",
        )
        .bind(enabled)
        .bind(default_plan_id)
        .bind(&allowed_json)
        .bind(site_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_site_config_compatible(
        &self,
        config_key: &str,
        config_json: &str,
        site_name: &str,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO app_settings (id, site_name) VALUES (1, $1)
             ON CONFLICT(id) DO UPDATE SET site_name = EXCLUDED.site_name",
        )
        .bind(site_name)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO kvs (key, value) VALUES ($1, $2)
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(config_key)
        .bind(config_json)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn set_system_settings_checked(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
        site_name: &str,
    ) -> Result<(), RegistrationSettingsWriteError> {
        let mut allowed = allowed_plan_ids.to_vec();
        allowed.sort_unstable();
        allowed.dedup();
        if allowed.is_empty() {
            return Err(RegistrationSettingsWriteError::AllowedPlansEmpty);
        }
        if !allowed.contains(&default_plan_id) {
            return Err(RegistrationSettingsWriteError::DefaultPlanNotInAllowed);
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(REGISTRATION_SETTINGS_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        // Sorted plan locks serialize this write with checked plan deletion and
        // avoid lock-order inversions between concurrent settings updates.
        for plan_id in &allowed {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT id FROM plans WHERE id = $1 FOR SHARE")
                    .bind(plan_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if exists.is_none() {
                tx.rollback().await?;
                return Err(RegistrationSettingsWriteError::PlanNotFound(*plan_id));
            }
        }

        let allowed_json = serialize_allowed_plan_ids(&allowed);
        sqlx::query(
            "INSERT INTO app_settings (id, registration_enabled, \
             default_registration_plan_id, registration_allowed_plan_ids, site_name) \
             VALUES (1, $1, $2, $3, $4) \
             ON CONFLICT (id) DO UPDATE SET \
                 registration_enabled = EXCLUDED.registration_enabled, \
                 default_registration_plan_id = EXCLUDED.default_registration_plan_id, \
                 registration_allowed_plan_ids = EXCLUDED.registration_allowed_plan_ids, \
                 site_name = EXCLUDED.site_name",
        )
        .bind(enabled)
        .bind(default_plan_id)
        .bind(&allowed_json)
        .bind(site_name)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
