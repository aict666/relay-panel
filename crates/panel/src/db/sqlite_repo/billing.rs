use crate::db::error::DbError;
use crate::service::billing::{self, BalanceChange, EntitlementSnapshot, SubscriptionCycle};
use sqlx::SqliteConnection;

pub(super) async fn protected_cycle_grants(
    conn: &mut SqliteConnection,
    group: i64,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM subscription_cycles c JOIN users u ON u.id=c.user_id WHERE c.cancelled=0 AND (c.ends_at IS NULL OR c.ends_at>datetime('now')) AND EXISTS(SELECT 1 FROM json_each(c.entitlement_snapshot,'$.device_group_ids') g WHERE g.value=?)")
        .bind(group).fetch_one(conn).await?)
}

pub(super) async fn sync_usage(conn: &mut SqliteConnection, uid: i64) -> Result<(), DbError> {
    sqlx::query("UPDATE subscription_cycles SET traffic_used=(SELECT traffic_used FROM users WHERE id=?) WHERE id=(SELECT current_cycle_id FROM users WHERE id=?)")
        .bind(uid).bind(uid).execute(conn).await?;
    Ok(())
}

pub(super) async fn append_balance(
    conn: &mut SqliteConnection,
    change: BalanceChange<'_>,
) -> Result<String, DbError> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM balance_ledger WHERE user_id=?")
        .bind(change.user_id)
        .fetch_one(&mut *conn)
        .await?;
    if exists == 0 {
        sqlx::query("INSERT INTO balance_ledger (id,user_id,kind,amount_cents,balance_before,balance_after,reference_id,reason,created_at) VALUES (?,?,'opening',?,'0',?,'opening','Opening balance before first tracked movement',?)")
            .bind(uuid::Uuid::new_v4().to_string()).bind(change.user_id)
            .bind(billing::balance_delta("0", change.before)?).bind(change.before).bind(billing::now())
            .execute(&mut *conn).await?;
    }
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO balance_ledger (id,user_id,kind,amount_cents,balance_before,balance_after,reference_id,actor_id,reason,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(&id).bind(change.user_id).bind(change.kind).bind(billing::balance_delta(change.before, change.after)?)
        .bind(change.before).bind(change.after).bind(change.reference_id).bind(change.actor_id)
        .bind(change.reason).bind(billing::now()).execute(conn).await?;
    Ok(id)
}

pub(super) async fn ensure_cycle(
    conn: &mut SqliteConnection,
    uid: i64,
) -> Result<Option<SubscriptionCycle>, DbError> {
    let row: billing::CurrentEntitlement = sqlx::query_as(
        "SELECT current_cycle_id,plan_id,plan_expire_at,traffic_limit,traffic_used,max_rules,all_device_groups,created_at,plan_source FROM users WHERE id=?")
        .bind(uid).fetch_one(&mut *conn).await?;
    if let Some(id) = row.current_cycle_id {
        return Ok(
            sqlx::query_as("SELECT * FROM subscription_cycles WHERE id=?")
                .bind(id)
                .fetch_optional(conn)
                .await?,
        );
    }
    let Some(plan_id) = row.plan_id else {
        return Ok(None);
    };
    let plan: Option<(String, String, i64)> =
        sqlx::query_as("SELECT name,plan_type,billing_revision FROM plans WHERE id=?")
            .bind(plan_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((plan_name, plan_type, revision)) = plan else {
        return Ok(None);
    };
    let groups = sqlx::query_scalar(
        "SELECT device_group_id FROM user_device_groups WHERE user_id=? ORDER BY device_group_id",
    )
    .bind(uid)
    .fetch_all(&mut *conn)
    .await?;
    let snapshot = EntitlementSnapshot {
        plan_id,
        plan_name,
        plan_type,
        traffic_limit: row.traffic_limit,
        max_rules: row.max_rules,
        grant_all_groups: row.all_device_groups,
        device_group_ids: groups,
        billing_revision: revision,
    };
    let cycle = insert_cycle(
        conn,
        uid,
        None,
        &row.created_at,
        row.plan_expire_at.as_deref(),
        row.traffic_used,
        &snapshot,
        &row.plan_source,
    )
    .await?;
    sqlx::query("UPDATE users SET current_cycle_id=?,subscription_id=? WHERE id=?")
        .bind(&cycle.id)
        .bind(&cycle.subscription_id)
        .bind(uid)
        .execute(conn)
        .await?;
    Ok(Some(cycle))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_cycle(
    conn: &mut SqliteConnection,
    uid: i64,
    subscription_id: Option<&str>,
    starts: &str,
    ends: Option<&str>,
    used: i64,
    snapshot: &EntitlementSnapshot,
    source: &str,
) -> Result<SubscriptionCycle, DbError> {
    let id = uuid::Uuid::new_v4().to_string();
    let subscription = subscription_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let encoded = snapshot.encode();
    sqlx::query("INSERT INTO subscription_cycles (id,subscription_id,user_id,plan_id,starts_at,ends_at,traffic_limit,traffic_used,entitlement_snapshot,source) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(&id).bind(&subscription).bind(uid).bind(snapshot.plan_id).bind(starts).bind(ends)
        .bind(snapshot.traffic_limit).bind(used).bind(&encoded).bind(source).execute(conn).await?;
    Ok(SubscriptionCycle {
        id,
        subscription_id: subscription,
        user_id: uid,
        plan_id: snapshot.plan_id,
        starts_at: starts.into(),
        ends_at: ends.map(str::to_owned),
        traffic_limit: snapshot.traffic_limit,
        traffic_used: used,
        entitlement_snapshot: encoded,
        source: source.into(),
        cancelled: false,
    })
}

pub(super) async fn replace_cycle(
    conn: &mut SqliteConnection,
    uid: i64,
    starts: &str,
    ends: Option<&str>,
    snapshot: &EntitlementSnapshot,
    source: &str,
    subscription_id: Option<&str>,
) -> Result<SubscriptionCycle, DbError> {
    ensure_cycle(conn, uid).await?;
    sqlx::query("UPDATE subscription_cycles SET ends_at=CASE WHEN ends_at IS NULL OR ends_at>? THEN ? ELSE ends_at END WHERE id=(SELECT current_cycle_id FROM users WHERE id=?)")
        .bind(starts).bind(starts).bind(uid).execute(&mut *conn).await?;
    sqlx::query("UPDATE subscription_cycles SET cancelled=1 WHERE user_id=? AND starts_at>=? AND id<>COALESCE((SELECT current_cycle_id FROM users WHERE id=?),'')")
        .bind(uid).bind(starts).bind(uid).execute(&mut *conn).await?;
    let cycle = insert_cycle(
        conn,
        uid,
        subscription_id,
        starts,
        ends,
        0,
        snapshot,
        source,
    )
    .await?;
    sqlx::query("UPDATE users SET current_cycle_id=?,subscription_id=?,plan_source=? WHERE id=?")
        .bind(&cycle.id)
        .bind(&cycle.subscription_id)
        .bind(source)
        .bind(uid)
        .execute(conn)
        .await?;
    Ok(cycle)
}

pub(super) async fn sync_cycle(
    conn: &mut SqliteConnection,
    uid: i64,
    ends: Option<&str>,
    snapshot: &EntitlementSnapshot,
) -> Result<SubscriptionCycle, DbError> {
    let current = ensure_cycle(conn, uid)
        .await?
        .ok_or(DbError::InvalidData("missing current subscription cycle"))?;
    let used: i64 = sqlx::query_scalar("SELECT traffic_used FROM users WHERE id=?")
        .bind(uid)
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("UPDATE subscription_cycles SET ends_at=?,traffic_limit=?,traffic_used=?,entitlement_snapshot=? WHERE id=?")
        .bind(ends).bind(snapshot.traffic_limit).bind(used).bind(snapshot.encode()).bind(&current.id).execute(&mut *conn).await?;
    sqlx::query("UPDATE users SET plan_source='paid' WHERE id=?")
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    Ok(
        sqlx::query_as("SELECT * FROM subscription_cycles WHERE id=?")
            .bind(current.id)
            .fetch_one(conn)
            .await?,
    )
}

/// Caller owns the user writer lock. A prepaid cycle activation never charges.
pub(super) async fn activate_paid_cycle(
    conn: &mut SqliteConnection,
    uid: i64,
    now: &str,
) -> Result<bool, DbError> {
    let cycle: Option<SubscriptionCycle> = sqlx::query_as("SELECT c.* FROM subscription_cycles c JOIN users u ON u.id=c.user_id AND u.subscription_id=c.subscription_id WHERE u.id=? AND c.cancelled=0 AND c.starts_at<=? AND (c.ends_at IS NULL OR c.ends_at>?) AND c.id<>COALESCE(u.current_cycle_id,'') ORDER BY c.starts_at DESC LIMIT 1")
        .bind(uid).bind(now).bind(now).fetch_optional(&mut *conn).await?;
    let Some(cycle) = cycle else {
        return Ok(false);
    };
    let snapshot = EntitlementSnapshot::decode(&cycle.entitlement_snapshot)?;
    for group in &snapshot.device_group_ids {
        let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_groups g JOIN users owner ON owner.id=g.uid WHERE g.id=? AND g.group_type IN ('in','both') AND owner.admin=1")
            .bind(group).fetch_one(&mut *conn).await?;
        if valid != 1 {
            return Err(DbError::PlanDeviceGroupInvalid);
        }
    }
    sqlx::query("UPDATE users SET current_cycle_id=?,plan_id=?,traffic_limit=?,traffic_used=?,max_rules=?,all_device_groups=?,plan_source=? WHERE id=?")
        .bind(&cycle.id).bind(cycle.plan_id).bind(cycle.traffic_limit).bind(cycle.traffic_used)
        .bind(snapshot.max_rules).bind(snapshot.grant_all_groups).bind(&cycle.source).bind(uid).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM user_device_groups WHERE user_id=?")
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    if !snapshot.grant_all_groups {
        for group in &snapshot.device_group_ids {
            sqlx::query("INSERT INTO user_device_groups (user_id,device_group_id) VALUES (?,?)")
                .bind(uid)
                .bind(group)
                .execute(&mut *conn)
                .await?;
        }
    }
    sqlx::query("UPDATE forward_rules SET traffic_used=0 WHERE uid=?")
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE forward_rules SET paused=1,auto_paused=1 WHERE uid=? AND paused=0 AND device_group_in NOT IN (SELECT g.id FROM device_groups g JOIN users owner ON owner.id=g.uid WHERE g.group_type IN ('in','both') AND owner.admin=1 AND (? OR EXISTS(SELECT 1 FROM user_device_groups a WHERE a.user_id=? AND a.device_group_id=g.id)))")
        .bind(uid).bind(snapshot.grant_all_groups).bind(uid).execute(&mut *conn).await?;
    sqlx::query("UPDATE forward_rules SET paused=0,auto_paused=0 WHERE uid=? AND paused=1 AND auto_paused=1 AND device_group_in IN (SELECT g.id FROM device_groups g JOIN users owner ON owner.id=g.uid WHERE g.group_type IN ('in','both') AND owner.admin=1 AND (? OR EXISTS(SELECT 1 FROM user_device_groups a WHERE a.user_id=? AND a.device_group_id=g.id)))")
        .bind(uid).bind(snapshot.grant_all_groups).bind(uid).execute(&mut *conn).await?;
    super::enforce_rule_limit(conn, uid).await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_purchase(
    conn: &mut SqliteConnection,
    uid: i64,
    before: &str,
    after: &str,
    price: &str,
    kind: &str,
    cycle: &SubscriptionCycle,
    snapshot: &EntitlementSnapshot,
    identity: Option<crate::db::repo::PurchaseIdentity<'_>>,
    reason: &str,
) -> Result<(), DbError> {
    let transaction_id = identity
        .map(|intent| intent.request_id.to_owned())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let actor_id = identity.and_then(|intent| intent.actor_id);
    sqlx::query("INSERT INTO orders (user_id,plan_id,plan_name,price,transaction_id,kind,subscription_id,cycle_id,cycle_start,cycle_end,entitlement_snapshot,actor_id,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(uid).bind(snapshot.plan_id).bind(&snapshot.plan_name).bind(price).bind(&transaction_id).bind(kind)
        .bind(&cycle.subscription_id).bind(&cycle.id).bind(&cycle.starts_at).bind(&cycle.ends_at)
        .bind(snapshot.encode()).bind(actor_id).bind(reason).execute(&mut *conn).await?;
    append_balance(
        conn,
        BalanceChange {
            user_id: uid,
            kind,
            before,
            after,
            reference_id: &transaction_id,
            actor_id,
            reason,
        },
    )
    .await?;
    Ok(())
}

/// Catalog selection during registration is either a free trial or an intent,
/// never an unpaid purchase of a priced plan.
pub(super) async fn provision_registration(
    conn: &mut SqliteConnection,
    username: &str,
    plan_id: i64,
) -> Result<(), DbError> {
    let uid: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username=?")
        .bind(username)
        .fetch_one(&mut *conn)
        .await?;
    let plan: relay_shared::models::Plan = sqlx::query_as("SELECT * FROM plans WHERE id=?")
        .bind(plan_id)
        .fetch_one(&mut *conn)
        .await?;
    let price = relay_shared::money::balance_to_cents(&plan.price)
        .ok_or(DbError::InvalidData("invalid registration plan price"))?;
    if price != 0 {
        sqlx::query("UPDATE users SET registration_plan_id=?,plan_id=NULL,plan_expire_at=NULL,max_rules=0,traffic_limit=0,all_device_groups=0,plan_source='pending' WHERE id=?")
            .bind(plan_id).bind(uid).execute(conn).await?;
        return Ok(());
    }
    let groups: Vec<i64> = sqlx::query_scalar(
        "SELECT device_group_id FROM plan_device_groups WHERE plan_id=? ORDER BY device_group_id",
    )
    .bind(plan_id)
    .fetch_all(&mut *conn)
    .await?;
    for group in &groups {
        let valid:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_groups g JOIN users owner ON owner.id=g.uid WHERE g.id=? AND owner.admin=1 AND g.group_type IN ('in','both')")
            .bind(group).fetch_one(&mut *conn).await?;
        if !plan.grant_all_groups && valid != 1 {
            return Err(DbError::PlanDeviceGroupInvalid);
        }
    }
    sqlx::query("UPDATE users SET plan_source='trial',registration_plan_id=?,all_device_groups=? WHERE id=?")
        .bind(plan_id).bind(plan.grant_all_groups).bind(uid).execute(&mut *conn).await?;
    if !plan.grant_all_groups {
        for group in groups {
            sqlx::query("INSERT INTO user_device_groups(user_id,device_group_id) VALUES (?,?)")
                .bind(uid)
                .bind(group)
                .execute(&mut *conn)
                .await?;
        }
    }
    ensure_cycle(conn, uid).await?;
    Ok(())
}
