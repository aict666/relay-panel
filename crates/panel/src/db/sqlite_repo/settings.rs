use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::Plan;

// ── PlanRepository ──

#[async_trait]
impl PlanRepository for SqliteRepository {
    async fn list_plans(&self) -> Result<Vec<Plan>, DbError> {
        let plans: Vec<Plan> = sqlx::query_as("SELECT * FROM plans ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(plans)
    }

    async fn list_visible_plans(&self) -> Result<Vec<Plan>, DbError> {
        let plans: Vec<Plan> = sqlx::query_as("SELECT * FROM plans WHERE hidden = 0 ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(plans)
    }

    async fn find_plan_name_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT name FROM plans WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(n,)| n))
    }

    async fn find_plan_by_id(&self, id: i64) -> Result<Option<Plan>, DbError> {
        let plan: Option<Plan> = sqlx::query_as("SELECT * FROM plans WHERE id = ?")
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
        // INSERT-then-last_insert_rowid (SQLite). speed_limit/ip_limit keep
        // their defaults (placeholders, never enforced) — not exposed here.
        let result = sqlx::query(
            "INSERT INTO plans \
             (name, max_rules, traffic, price, plan_type, duration_days, hidden, reset_traffic, description, grant_all_groups) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
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
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO plans \
             (name, max_rules, traffic, price, plan_type, duration_days, hidden, reset_traffic, description, grant_all_groups) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&mut *tx)
        .await?;
        let id = result.last_insert_rowid();
        for dg in device_group_ids {
            let valid: Option<i64> = sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users u ON u.id = dg.uid \
                 WHERE dg.id = ? AND dg.group_type IN ('in', 'both') AND u.admin = 1",
            )
            .bind(dg)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::PlanDeviceGroupInvalid);
            }
            sqlx::query(
                "INSERT OR IGNORE INTO plan_device_groups (plan_id, device_group_id) \
                 VALUES (?, ?)",
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
        if duration_days.is_some_and(|days| days < 0)
            || (plan_type == Some("time") && duration_days.is_some_and(|days| days == 0))
        {
            return Err(DbError::PlanInvariant);
        }
        let require_positive_duration = plan_type == Some("time") && duration_days.is_none();
        let require_non_time_plan = plan_type.is_none() && duration_days == Some(0);
        let has_invariant_guard = require_positive_duration || require_non_time_plan;
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ?");
        }
        if max_rules.is_some() {
            sets.push("max_rules = ?");
        }
        if traffic.is_some() {
            sets.push("traffic = ?");
        }
        if price.is_some() {
            sets.push("price = ?");
        }
        if plan_type.is_some() {
            sets.push("plan_type = ?");
        }
        if duration_days.is_some() {
            sets.push("duration_days = ?");
        }
        if hidden.is_some() {
            sets.push("hidden = ?");
        }
        if reset_traffic.is_some() {
            sets.push("reset_traffic = ?");
        }
        if description.is_some() {
            sets.push("description = ?");
        }
        if grant_all_groups.is_some() {
            sets.push("grant_all_groups = ?");
        }

        // A group-only edit reads the plan before replacing child rows. Acquire
        // SQLite's writer reservation up front so it cannot fail while
        // upgrading a stale read snapshot under a concurrent purchase/edit.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows_affected = if sets.is_empty() {
            let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM plans WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
            if exists.is_some() {
                1
            } else {
                0
            }
        } else {
            let invariant_sql = if require_positive_duration {
                " AND duration_days > 0"
            } else if require_non_time_plan {
                " AND plan_type <> 'time'"
            } else {
                ""
            };
            let sql = format!(
                "UPDATE plans SET {} WHERE id = ?{}",
                sets.join(", "),
                invariant_sql
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
            if has_invariant_guard {
                let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM plans WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?;
                if exists.is_some() {
                    tx.rollback().await?;
                    return Err(DbError::PlanInvariant);
                }
            }
            tx.rollback().await?;
            return Ok(0);
        }

        if let Some(group_ids) = device_group_ids {
            sqlx::query("DELETE FROM plan_device_groups WHERE plan_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for group_id in group_ids {
                let valid: Option<i64> = sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users u ON u.id = dg.uid \
                     WHERE dg.id = ? AND dg.group_type IN ('in', 'both') AND u.admin = 1",
                )
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
                if valid.is_none() {
                    tx.rollback().await?;
                    return Err(DbError::PlanDeviceGroupInvalid);
                }
                sqlx::query(
                    "INSERT OR IGNORE INTO plan_device_groups (plan_id, device_group_id) \
                     VALUES (?, ?)",
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
        let result = sqlx::query("DELETE FROM plans WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn delete_plan_checked(&self, id: i64) -> Result<PlanDeleteOutcome, DbError> {
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

        let exists: Option<i64> = try_sql!(
            sqlx::query_scalar("SELECT id FROM plans WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
        );
        if exists.is_none() {
            reject!(PlanDeleteOutcome::NotFound);
        }

        let settings: Option<(i64, String)> = try_sql!(
            sqlx::query_as(
                "SELECT default_registration_plan_id, registration_allowed_plan_ids \
                 FROM app_settings WHERE id = 1",
            )
            .fetch_optional(&mut *conn)
            .await
        );
        if let Some((default_plan_id, raw_allowed)) = settings {
            if default_plan_id == id {
                reject!(PlanDeleteOutcome::RegistrationDefault);
            }
            let allowed_plan_ids = match parse_allowed_plan_ids(&raw_allowed) {
                Ok(ids) => ids,
                Err(error) => {
                    try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                    return Err(error);
                }
            };
            if allowed_plan_ids.contains(&id) {
                reject!(PlanDeleteOutcome::RegistrationAllowed);
            }
        }

        let users: i64 = try_sql!(
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE plan_id = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
        );
        if users > 0 {
            reject!(PlanDeleteOutcome::InUse { users });
        }

        try_sql!(
            sqlx::query("DELETE FROM plans WHERE id = ?")
                .bind(id)
                .execute(&mut *conn)
                .await
        );
        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(PlanDeleteOutcome::Deleted)
    }

    async fn count_users_on_plan(&self, plan_id: i64) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE plan_id = ?")
            .bind(plan_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    // Atomic plan purchase. BEGIN IMMEDIATE reserves the single SQLite writer
    // before any plan/balance reads. A concurrent purchase waits, then reads
    // the committed balance instead of trying to upgrade a stale WAL snapshot
    // and surfacing SQLITE_BUSY_SNAPSHOT as an HTTP 500. (PG uses an explicit
    // SELECT ... FOR UPDATE row lock instead; see the PG impl.)
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
        // Explicit authorization snapshot for per-group plans. Grant-all is
        // derived from current group state inside this transaction.
        new_authorized_group_ids: &[i64],
        require_visible: bool,
        check_plan_snapshot: bool,
        expected_current_plan_id: Option<Option<i64>>,
    ) -> Result<(), BuyPlanError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        // Lock the purchase to one coherent plan snapshot. The handler resolves
        // display/validation fields before entering this transaction; compare
        // them again here so an intervening admin edit cannot mix a new plan id
        // with an old price, quota, duration, or grant set.
        if check_plan_snapshot {
            let current_plan: Option<(String, String, i64, i32, String, i32, bool, bool, bool)> =
                sqlx::query_as(
                    "SELECT name, price, traffic, max_rules, plan_type, duration_days, \
                        reset_traffic, grant_all_groups, hidden \
                 FROM plans WHERE id = ?",
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
            let effective_current_duration = if current_type == "time" {
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
                 WHERE plan_id = ? ORDER BY device_group_id",
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
                         WHERE dg.id=? AND dg.group_type IN ('in','both') \
                           AND owner.admin=1",
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
                || effective_current_duration != duration_days
                || current_reset_traffic != reset_traffic
                || current_grant_all != grant_all_groups
                || (!current_grant_all && current_group_ids != expected_group_ids);
            if snapshot_changed {
                let _ = tx.rollback().await;
                return Err(BuyPlanError::PlanChanged);
            }
        }

        // Read the user's current balance (canonical TEXT) + expiry + plan_id.
        // plan_id decides renew-vs-switch below.
        let row: Option<(String, Option<String>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT balance, plan_expire_at, plan_id, traffic_limit FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((balance_str, current_expire, current_plan_id, current_traffic_limit)) = row
        else {
            let _ = tx.rollback().await;
            // A missing user mid-purchase is a DB integrity issue, not a
            // balance issue — surface as a 500.
            return Err(BuyPlanError::Database(DbError::NotFound));
        };
        if expected_current_plan_id.is_some_and(|expected| expected != current_plan_id) {
            let _ = tx.rollback().await;
            return Err(BuyPlanError::UserPlanChanged);
        }

        // Decimal math in integer cents (no floats). balance_to_cents returns
        // None on a non-canonical string — treat that as a data-integrity fault
        // and refuse the purchase (500) rather than mis-billing.
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

        // Renew (buying the SAME plan again) vs switch (a different plan, or the
        // user had none). These diverge on traffic + expiry:
        //   - switch: quota REPLACES the old (traffic_limit = new, traffic_used
        //     = 0) and the expiry is recomputed from now — the new plan starts
        //     fresh, old usage/time does NOT carry over.
        //   - renew:  quota STACKS (traffic_limit += new, traffic_used kept) and
        //     the expiry extends from max(now, current) — 加流量/延期.
        // A missing current plan (None) is treated as a switch (fresh start).
        let is_switch = current_plan_id != Some(plan_id);
        let new_traffic_limit = if is_switch {
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

        // Compute the new expiry. duration_days=0 → NULL (no expiry). Stored as
        // 'YYYY-MM-DD HH:MM:SS' UTC (lexically comparable, same as created_at).
        // SQLite's datetime() does the civil-calendar math.
        let new_expire: Option<String> = if duration_days <= 0 {
            None
        } else if is_switch {
            // Switch: fresh expiry = now + duration_days (no carry-over).
            let row: (String,) = sqlx::query_as("SELECT datetime('now', ? || ' days')")
                .bind(format!("+{}", duration_days))
                .fetch_one(&mut *tx)
                .await?;
            Some(row.0)
        } else {
            // Renew: base = max(now, current_expire) so remaining time stacks.
            let row: (String,) = sqlx::query_as(
                "SELECT datetime(MAX(datetime('now'), COALESCE(?, datetime('now'))), ? || ' days')",
            )
            .bind(&current_expire)
            .bind(format!("+{}", duration_days))
            .fetch_one(&mut *tx)
            .await?;
            Some(row.0)
        };

        // Apply the user update per the renew/switch split above.
        if is_switch {
            // Switch: traffic_limit = new quota, traffic_used reset to 0.
            sqlx::query(
                "UPDATE users SET \
                 balance = ?, traffic_limit = ?, traffic_used = 0, max_rules = ?, \
                 plan_id = ?, plan_expire_at = ? \
                 WHERE id = ?",
            )
            .bind(&new_balance)
            .bind(new_traffic_limit)
            .bind(plan_max_rules)
            .bind(plan_id)
            .bind(&new_expire)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else if reset_traffic {
            // Renew + the plan's reset_traffic flag: stack quota, zero usage.
            sqlx::query(
                "UPDATE users SET \
                 balance = ?, traffic_limit = ?, traffic_used = 0, \
                 max_rules = ?, plan_id = ?, plan_expire_at = ? \
                 WHERE id = ?",
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
                 balance = ?, traffic_limit = ?, max_rules = ?, \
                 plan_id = ?, plan_expire_at = ? \
                 WHERE id = ?",
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

        // Insert the order row (snapshots plan_name + the canonical price).
        let price_str = relay_shared::money::cents_to_balance(price_cents);
        sqlx::query("INSERT INTO orders (user_id, plan_id, plan_name, price) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(plan_id)
            .bind(plan_name)
            .bind(&price_str)
            .execute(&mut *tx)
            .await?;

        // v1.0.8: grant device-group authorization in the SAME tx. Purchase
        // REPLACES the user's authorization — BOTH dimensions are reset so the
        // user is left with EXACTLY the new plan's grant, nothing lingering:
        //   - grant_all_groups → set all_device_groups=1 AND clear the explicit
        //     user_device_groups rows (redundant under the flag; clearing them
        //     avoids stale grants resurfacing if the user later downgrades).
        //   - else → clear all_device_groups=0 AND replace user_device_groups
        //     with the plan's set. Resetting the flag is the fix for the
        //     grant-all → per-group downgrade case: without it the user kept
        //     all_device_groups=1 and stayed effectively unrestricted.
        // The caller's new_authorized_group_ids drives per-group rule pauses.
        if grant_all_groups {
            sqlx::query("UPDATE users SET all_device_groups = 1 WHERE id = ? AND admin = 0")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        } else {
            // REPLACE semantics: reset the all-groups flag, clear old explicit
            // assignments, then insert the plan's.
            sqlx::query("UPDATE users SET all_device_groups = 0 WHERE id = ? AND admin = 0")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            for dg_id in device_group_ids {
                sqlx::query(
                    "INSERT INTO user_device_groups (user_id, device_group_id) \
                     VALUES (?, ?)",
                )
                .bind(user_id)
                .bind(dg_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Pause rules outside the new authorization. This is the key change from
        // the old append-only behavior: a new purchase can revoke access to
        // groups the user previously had, and those rules stop forwarding.
        // A grant-all plan must never interpret an empty explicit set as
        // "authorize nothing"; it skips this pause path entirely.
        // Inline the pause logic inside the transaction (using &mut *tx) to
        // avoid acquiring a separate pool connection while the transaction is
        // still open — that would risk a pool-exhaustion deadlock.
        // v1.0.8: auto_paused=1 marks these as SYSTEM pauses (see the resume
        // step below and the column doc on forward_rules.auto_paused).
        let n = if grant_all_groups {
            0
        } else if new_authorized_group_ids.is_empty() {
            let r = sqlx::query(
                "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                 WHERE uid = ? AND paused = 0",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            r.rows_affected()
        } else {
            let placeholders = vec!["?"; new_authorized_group_ids.len()].join(", ");
            let sql = format!(
                "UPDATE forward_rules SET paused = 1, auto_paused = 1 \
                 WHERE uid = ? AND paused = 0 AND device_group_in NOT IN ({})",
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
        // (auto_paused=1) whose group is back in the new authorized set gets
        // un-paused here. A rule the user paused THEMSELVES (auto_paused=0,
        // e.g. via the on/off switch) is deliberately left alone even if its
        // group is authorized again — buying a plan must never silently revive
        // a rule the user turned off on purpose.
        if grant_all_groups {
            let resumed = sqlx::query(
                "UPDATE forward_rules SET paused = 0, auto_paused = 0 \
                 WHERE uid = ? AND paused = 1 AND auto_paused = 1 \
                   AND device_group_in IN (\
                     SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
                     WHERE dg.group_type IN ('in', 'both') AND owner.admin=1\
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
            let placeholders = vec!["?"; new_authorized_group_ids.len()].join(", ");
            let sql = format!(
                "UPDATE forward_rules SET paused = 0, auto_paused = 0 \
                 WHERE uid = ? AND paused = 1 AND auto_paused = 1 \
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

        tx.commit().await?;
        Ok(())
    }

    async fn list_plan_device_groups(&self, plan_id: i64) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM plan_device_groups \
             WHERE plan_id = ? ORDER BY device_group_id",
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
        // REPLACE the grant set (delete-then-insert, deduped via the PK).
        let mut group_ids = device_group_ids.to_vec();
        group_ids.sort_unstable();
        group_ids.dedup();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let plan_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM plans WHERE id = ?")
            .bind(plan_id)
            .fetch_optional(&mut *tx)
            .await?;
        if plan_exists.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        for dg_id in &group_ids {
            let valid: Option<i64> = sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users u ON u.id = dg.uid \
                 WHERE dg.id = ? AND dg.group_type IN ('in', 'both') AND u.admin = 1",
            )
            .bind(dg_id)
            .fetch_optional(&mut *tx)
            .await?;
            if valid.is_none() {
                tx.rollback().await?;
                return Err(DbError::PlanDeviceGroupInvalid);
            }
        }
        sqlx::query("DELETE FROM plan_device_groups WHERE plan_id = ?")
            .bind(plan_id)
            .execute(&mut *tx)
            .await?;
        for dg_id in &group_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO plan_device_groups (plan_id, device_group_id) \
                 VALUES (?, ?)",
            )
            .bind(plan_id)
            .bind(dg_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

// ── Helpers ──

/// Parse the persisted allow-list without inventing a replacement snapshot.
/// A malformed row is an integrity fault: registration, settings reads, and
/// checked plan deletion must all fail closed until an administrator repairs it.
fn parse_allowed_plan_ids(raw: &str) -> Result<Vec<i64>, DbError> {
    serde_json::from_str::<Vec<i64>>(raw).map_err(|_| {
        DbError::InvalidData("registration_allowed_plan_ids is not a JSON integer array")
    })
}

/// Serialize a `Vec<i64>` to a JSON string.
fn serialize_allowed_plan_ids(ids: &[i64]) -> String {
    serde_json::to_string(ids).expect("integer allow-list is JSON-serializable")
}

#[async_trait]
impl SettingsRepository for SqliteRepository {
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
            "INSERT OR IGNORE INTO app_settings (id, registration_enabled, \
             default_registration_plan_id, registration_allowed_plan_ids) \
             VALUES (1, ?, ?, ?)",
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
             VALUES (1, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
                 registration_enabled = excluded.registration_enabled, \
                 default_registration_plan_id = excluded.default_registration_plan_id, \
                 registration_allowed_plan_ids = excluded.registration_allowed_plan_ids",
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
             VALUES (1, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
                 registration_enabled = excluded.registration_enabled, \
                 default_registration_plan_id = excluded.default_registration_plan_id, \
                 registration_allowed_plan_ids = excluded.registration_allowed_plan_ids, \
                 site_name = excluded.site_name",
        )
        .bind(enabled)
        .bind(default_plan_id)
        .bind(&allowed_json)
        .bind(site_name)
        .execute(&self.pool)
        .await?;
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

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .map_err(RegistrationSettingsWriteError::from)?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(RegistrationSettingsWriteError::from(error));
                    }
                }
            };
        }
        for plan_id in &allowed {
            let exists: Option<i64> = try_sql!(
                sqlx::query_scalar("SELECT id FROM plans WHERE id = ?")
                    .bind(plan_id)
                    .fetch_optional(&mut *conn)
                    .await
            );
            if exists.is_none() {
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Err(RegistrationSettingsWriteError::PlanNotFound(*plan_id));
            }
        }

        let allowed_json = serialize_allowed_plan_ids(&allowed);
        try_sql!(
            sqlx::query(
                "INSERT INTO app_settings (id, registration_enabled, \
                 default_registration_plan_id, registration_allowed_plan_ids, site_name) \
                 VALUES (1, ?, ?, ?, ?) \
                 ON CONFLICT(id) DO UPDATE SET \
                     registration_enabled = excluded.registration_enabled, \
                     default_registration_plan_id = excluded.default_registration_plan_id, \
                     registration_allowed_plan_ids = excluded.registration_allowed_plan_ids, \
                     site_name = excluded.site_name",
            )
            .bind(enabled)
            .bind(default_plan_id)
            .bind(&allowed_json)
            .bind(site_name)
            .execute(&mut *conn)
            .await
        );
        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(())
    }
}
