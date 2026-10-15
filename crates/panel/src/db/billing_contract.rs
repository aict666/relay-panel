//! Identical financial invariants for SQLite and PostgreSQL. Backend wrappers
//! choose an isolated database; no production data or backend-specific SQL.
use super::error::DbError;
use super::repo::*;
use relay_shared::protocol::TrafficEntry;

async fn fixture(db: &dyn Repository) -> (i64, i64, i64, Vec<i64>) {
    db.insert_user("billing-buyer", "test-only-hash", 1)
        .await
        .unwrap();
    let uid = UserRepository::find_by_username(db, "billing-buyer")
        .await
        .unwrap()
        .unwrap()
        .id;
    db.update_user_fields(uid, Some("100"), Some(10), Some(1000), None, None)
        .await
        .unwrap();
    db.set_user_all_device_groups(uid, true).await.unwrap();
    db.insert_group(
        "billing-entry",
        "in",
        "billing-token",
        1,
        "127.0.0.1",
        "20000-30000",
        1.0,
        false,
        "[]",
    )
    .await
    .unwrap();
    let group = db
        .find_by_token_after_insert("billing-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    for port in 21000..21003 {
        db.insert_quota_guarded(
            "billing-rule",
            uid,
            port,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            group,
            None,
            "direct",
            "127.0.0.1",
            80,
        )
        .await
        .unwrap();
    }
    let rules = db
        .list_rules(&ResourceScope::Owner(uid))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let plan = db
        .insert_plan(
            "billing-plan",
            10,
            1000,
            "10",
            "data",
            0,
            false,
            false,
            "",
            true,
        )
        .await
        .unwrap();
    (uid, group, plan, rules)
}

async fn user(db: &dyn Repository, uid: i64) -> relay_shared::models::User {
    UserRepository::find_by_id(db, uid).await.unwrap().unwrap()
}

async fn purchase(
    db: &dyn Repository,
    uid: i64,
    plan: i64,
    key: &str,
    fingerprint: &str,
) -> Result<(), BuyPlanError> {
    db.buy_plan_idempotent(
        uid,
        plan,
        "billing-plan",
        1000,
        1000,
        10,
        0,
        false,
        true,
        &[],
        &[],
        "data",
        false,
        true,
        Some(Some(1)),
        PurchaseIdentity {
            actor_id: None,
            request_id: key,
            fingerprint,
        },
    )
    .await
}

pub async fn traffic_batch_identity_contract(db: &dyn Repository) {
    let (uid, group, _, rules) = fixture(db).await;
    let entries = [TrafficEntry {
        rule_id: rules[0],
        upload: 100,
        download: 200,
    }];
    let (first, retry) = tokio::join!(
        db.apply_traffic_batch_with_id(group, Some("first"), None, &entries),
        db.apply_traffic_batch_with_id(group, Some("first"), None, &entries)
    );
    let results = [first.unwrap(), retry.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r.as_slice(), [TrafficEntryResult::AlreadyApplied]))
            .count(),
        1
    );
    assert_eq!(user(db, uid).await.traffic_used, 300);
    let invalid = [
        entries[0].clone(),
        TrafficEntry {
            rule_id: i64::MAX,
            upload: 1,
            download: 0,
        },
    ];
    assert!(matches!(
        db.apply_traffic_batch_with_id(group, Some("rejected"), None, &invalid)
            .await
            .unwrap()
            .as_slice(),
        [TrafficEntryResult::Unavailable]
    ));
    assert_eq!(user(db, uid).await.traffic_used, 300);
    // Rejection must also roll back the identity reservation.
    db.apply_traffic_batch_with_id(group, Some("rejected"), Some("first"), &entries)
        .await
        .unwrap();
    assert_eq!(user(db, uid).await.traffic_used, 600);
    assert_eq!(
        db.prune_traffic_batches("9999-01-01 00:00:00")
            .await
            .unwrap(),
        1
    );
    // The unconfirmed id survives indefinitely, including rule deletion.
    db.delete_rule(rules[0], &ResourceScope::Owner(uid))
        .await
        .unwrap();
    assert!(matches!(
        db.apply_traffic_batch_with_id(group, Some("rejected"), None, &entries)
            .await
            .unwrap()
            .as_slice(),
        [TrafficEntryResult::AlreadyApplied]
    ));
    assert_eq!(user(db, uid).await.traffic_used, 600);
}

pub async fn purchase_identity_contract(db: &dyn Repository) {
    let (uid, _, plan, _) = fixture(db).await;
    let (first, retry) = tokio::join!(
        purchase(db, uid, plan, "intent-1", "same-confirmed-body"),
        purchase(db, uid, plan, "intent-1", "same-confirmed-body")
    );
    first.unwrap();
    retry.unwrap();
    assert_eq!(user(db, uid).await.balance, "90");
    assert_eq!(db.list_orders_by_user(uid).await.unwrap().len(), 1);
    // Retry succeeds even if the catalog no longer matches or is hidden.
    db.update_plan_fields(
        plan,
        None,
        None,
        None,
        Some("20"),
        None,
        None,
        Some(true),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    purchase(db, uid, plan, "intent-1", "same-confirmed-body")
        .await
        .unwrap();
    assert!(matches!(
        purchase(db, uid, plan, "intent-1", "changed-body").await,
        Err(BuyPlanError::IdempotencyConflict)
    ));
    assert!(matches!(
        purchase(db, uid, plan, "intent-2", "new-intent").await,
        Err(BuyPlanError::PlanChanged)
    ));
    assert_eq!(
        db.find_purchase_fingerprint(uid, "intent-2").await.unwrap(),
        None
    );
    assert_eq!(user(db, uid).await.balance, "90");
    assert_eq!(db.list_orders_by_user(uid).await.unwrap().len(), 1);
}

pub async fn balance_compare_and_swap_contract(db: &dyn Repository) {
    let (uid, _, plan, _) = fixture(db).await;
    purchase(db, uid, plan, "charge", "body").await.unwrap();
    let stale = AdminUserUpdate {
        balance: Some("100"),
        expected_balance: Some("100"),
        max_rules: Some(3),
        ..Default::default()
    };
    assert!(matches!(
        db.update_user_with_authorization(uid, stale).await,
        Err(DbError::BalanceConflict)
    ));
    let current = user(db, uid).await;
    assert_eq!(current.balance, "90");
    assert_eq!(current.max_rules, 10);
    assert!(matches!(
        db.update_user_with_authorization(
            uid,
            AdminUserUpdate {
                balance: Some("100"),
                ..Default::default()
            }
        )
        .await,
        Err(DbError::BalanceConflict)
    ));
    db.update_user_with_authorization(
        uid,
        AdminUserUpdate {
            expected_balance: Some("90.00"),
            ..stale
        },
    )
    .await
    .unwrap();
    assert_eq!(user(db, uid).await.balance, "100");
}

pub async fn downgrade_rule_limit_contract(db: &dyn Repository) {
    let (uid, group, plan, rules) = fixture(db).await;
    db.buy_plan(uid, plan, "small", 1000, 1000, 1, 0, false, true, &[], &[])
        .await
        .unwrap();
    let active = db.list_active_for_config(group).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, rules[0]);
    let resume = RuleUpdateData {
        id: rules[1],
        owner_uid: Some(uid),
        effective_device_group_in: group,
        paused: Some(false),
        ..Default::default()
    };
    assert!(matches!(
        db.update_rule_full(&resume).await,
        Err(DbError::QuotaExceeded)
    ));
    assert!(matches!(
        db.update_rule_fields(
            rules[1],
            &ResourceScope::Owner(uid),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false)
        )
        .await,
        Err(DbError::QuotaExceeded)
    ));
    // An upgrade resumes only auto-paused configurations, not human pauses.
    db.update_rule_full(&RuleUpdateData {
        id: rules[0],
        owner_uid: Some(uid),
        paused: Some(true),
        ..Default::default()
    })
    .await
    .unwrap();
    db.buy_plan(uid, plan, "large", 1000, 1000, 10, 0, false, true, &[], &[])
        .await
        .unwrap();
    let active = db.list_active_for_config(group).await.unwrap();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|rule| rule.id != rules[0]));
}

pub async fn redeem_concurrency_and_expiry_contract(db: &dyn Repository) {
    let (uid, _, _, _) = fixture(db).await;
    let rows: Vec<_> = (0..20)
        .map(|n| NewRedeemCode {
            code: format!("CONCURRENT{n}"),
            amount: "1".into(),
            expires_at: None,
            batch_id: "concurrent".into(),
            remark: String::new(),
        })
        .collect();
    db.create_redeem_codes(&rows).await.unwrap();
    let results = futures_util::future::join_all(
        rows.iter()
            .map(|row| db.redeem_code(&row.code, uid, "2026-10-15 00:00:00")),
    )
    .await;
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(user(db, uid).await.balance, "120");
    assert!(matches!(
        db.redeem_code(&rows[0].code, uid, "2026-10-15 00:00:00")
            .await,
        Err(RedeemCodeError::NotRedeemable)
    ));
    for (n, expiry) in ["2026-9-1 00:00:00", "2026-10-15 00:00:00", "invalid"]
        .iter()
        .enumerate()
    {
        let code = format!("EXPIRED{n}");
        db.create_redeem_codes(&[NewRedeemCode {
            code: code.clone(),
            amount: "1".into(),
            expires_at: Some((*expiry).into()),
            batch_id: "expired".into(),
            remark: String::new(),
        }])
        .await
        .unwrap();
        assert!(matches!(
            db.redeem_code(&code, uid, "2026-10-15 00:00:00").await,
            Err(RedeemCodeError::Expired)
        ));
    }
    assert_eq!(user(db, uid).await.balance, "120");
}

pub async fn auto_renew_identity_and_account_state_contract(db: &dyn Repository) {
    let (uid, _, _, _) = fixture(db).await;
    let a = db
        .insert_plan(
            "monthly-a",
            10,
            1000,
            "10",
            "monthly",
            30,
            false,
            true,
            "",
            true,
        )
        .await
        .unwrap();
    let b = db
        .insert_plan(
            "monthly-b",
            10,
            1000,
            "10",
            "monthly",
            30,
            false,
            true,
            "",
            true,
        )
        .await
        .unwrap();
    db.buy_plan_guarded(
        uid,
        a,
        "monthly-a",
        1000,
        1000,
        10,
        30,
        true,
        true,
        &[],
        &[],
        "monthly",
        false,
        true,
        None,
    )
    .await
    .unwrap();
    let revision = db
        .find_plan_by_id(a)
        .await
        .unwrap()
        .unwrap()
        .billing_revision;
    db.buy_plan_guarded(
        uid,
        b,
        "monthly-b",
        1000,
        1000,
        10,
        30,
        true,
        true,
        &[],
        &[],
        "monthly",
        false,
        true,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        db.set_plan_auto_renew_guarded(uid, true, Some("10"), Some(revision), Some(a))
            .await
            .unwrap(),
        PlanAutoRenewUpdateOutcome::ContractChanged
    );
    for banned in [false, true] {
        db.update_user_with_authorization(
            uid,
            AdminUserUpdate {
                banned: Some(false),
                suspended: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.set_plan_auto_renew_guarded(uid, true, Some("10"), Some(revision), Some(b))
                .await
                .unwrap(),
            PlanAutoRenewUpdateOutcome::Updated
        );
        db.update_user_with_authorization(
            uid,
            AdminUserUpdate {
                banned: Some(banned),
                suspended: Some(!banned),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!user(db, uid).await.plan_auto_renew);
        assert_eq!(
            db.set_plan_auto_renew_guarded(uid, true, Some("10"), Some(revision), Some(b))
                .await
                .unwrap(),
            PlanAutoRenewUpdateOutcome::ContractChanged
        );
        assert!(db
            .list_expired_monthly_auto_renew_user_ids("2099-01-01 00:00:00", 100)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.renew_expired_monthly_plan(uid, "2099-01-01 00:00:00")
                .await
                .unwrap(),
            MonthlyRenewalOutcome::NotEligible
        );
    }
    assert_eq!(user(db, uid).await.balance, "80");
}

pub async fn purchase_quota_sentinel_and_reset_contract(db: &dyn Repository) {
    let (uid, _, plan, _) = fixture(db).await;
    db.buy_plan(
        uid,
        plan,
        "finite",
        1000,
        1000,
        10,
        0,
        false,
        true,
        &[],
        &[],
    )
    .await
    .unwrap();
    db.increment_user_traffic(uid, 400).await.unwrap();
    db.buy_plan(
        uid,
        plan,
        "unlimited",
        1000,
        0,
        10,
        0,
        false,
        true,
        &[],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(user(db, uid).await.traffic_limit, 0);
    db.buy_plan(
        uid,
        plan,
        "finite-again",
        1000,
        1000,
        10,
        0,
        false,
        true,
        &[],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(user(db, uid).await.traffic_limit, 1000);
    assert_eq!(user(db, uid).await.traffic_used, 400);
    db.buy_plan(uid, plan, "reset", 1000, 1000, 10, 0, true, true, &[], &[])
        .await
        .unwrap();
    assert_eq!(user(db, uid).await.traffic_limit, 1000); // Not stacked to 2000.
    assert_eq!(user(db, uid).await.traffic_used, 0);
}

async fn assert_ledger(db: &dyn Repository, uid: i64) {
    let mut rows = db.list_balance_entries(uid, 200, 0).await.unwrap();
    rows.reverse();
    let mut cents = 0;
    for row in rows {
        assert_eq!(
            relay_shared::money::balance_to_cents(&row.balance_before),
            Some(cents)
        );
        cents += row.amount_cents;
        assert_eq!(
            relay_shared::money::balance_to_cents(&row.balance_after),
            Some(cents)
        );
        assert!(!row.reference_id.is_empty());
        assert!(!row.reason.is_empty());
    }
    assert_eq!(
        relay_shared::money::balance_to_cents(&user(db, uid).await.balance),
        Some(cents)
    );
}

/// Backend wrapper injects an INSERT failure for ledger kind='purchase'.
pub async fn ledger_write_failure_contract(db: &dyn Repository) {
    let (uid, _, plan, _) = fixture(db).await;
    let before = user(db, uid).await;
    let ledger = db.list_balance_entries(uid, 200, 0).await.unwrap().len();
    assert!(matches!(
        purchase(db, uid, plan, "ledger-failure", "immutable-intent").await,
        Err(BuyPlanError::Database(_))
    ));
    let after = user(db, uid).await;
    assert_eq!(
        (
            after.balance,
            after.plan_id,
            after.traffic_limit,
            after.traffic_used
        ),
        (
            before.balance,
            before.plan_id,
            before.traffic_limit,
            before.traffic_used
        )
    );
    assert!(db.list_orders_by_user(uid).await.unwrap().is_empty());
    assert!(db.list_subscription_cycles(uid).await.unwrap().is_empty());
    assert!(db
        .find_purchase_fingerprint(uid, "ledger-failure")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.list_balance_entries(uid, 200, 0).await.unwrap().len(),
        ledger
    );
    assert_ledger(db, uid).await;
}

pub async fn monthly_prepayment_and_ledger_contract(db: &dyn Repository) {
    let (uid, group, _, rules) = fixture(db).await;
    let pid = db
        .insert_plan(
            "monthly", 10, 1000, "10", "monthly", 30, false, true, "", true,
        )
        .await
        .unwrap();
    let buy = |key: &'static str| async move {
        db.buy_plan_idempotent(
            uid,
            pid,
            "monthly",
            1000,
            1000,
            10,
            30,
            true,
            true,
            &[],
            &[],
            "monthly",
            false,
            true,
            None,
            PurchaseIdentity {
                request_id: key,
                fingerprint: key,
                actor_id: Some(uid),
            },
        )
        .await
    };
    buy("open").await.unwrap();
    let first = user(db, uid).await;
    db.apply_traffic_batch_with_id(
        group,
        Some("current-use"),
        None,
        &[TrafficEntry {
            rule_id: rules[0],
            upload: 400,
            download: 100,
        }],
    )
    .await
    .unwrap();
    let (a, b) = tokio::join!(buy("prepay"), buy("prepay"));
    a.unwrap();
    b.unwrap();
    assert_eq!(user(db, uid).await.traffic_used, 500);
    assert_eq!(user(db, uid).await.balance, "80");
    buy("prepay-2").await.unwrap();
    assert_eq!(db.list_orders_by_user(uid).await.unwrap().len(), 3);
    let cycles = db.list_subscription_cycles(uid).await.unwrap();
    let original = cycles
        .iter()
        .find(|cycle| Some(&cycle.id) == first.current_cycle_id.as_ref())
        .unwrap();
    let boundary = original.ends_at.as_deref().unwrap();
    assert_eq!(original.traffic_used, 500);
    assert!(!db
        .activate_subscription_cycle(uid, &original.starts_at)
        .await
        .unwrap());
    // The paid entitlement must survive future catalog edits and hiding.
    db.update_plan_fields(
        pid,
        None,
        None,
        Some(9000),
        None,
        None,
        None,
        Some(true),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let (a, b) = tokio::join!(
        db.activate_subscription_cycle(uid, boundary),
        db.activate_subscription_cycle(uid, boundary)
    );
    assert_ne!(a.unwrap(), b.unwrap(), "a boundary activates only once");
    let active = user(db, uid).await;
    assert_eq!((active.traffic_limit, active.traffic_used), (1000, 0));
    assert_eq!(active.balance, "70");
    assert_eq!(
        db.list_orders_by_user(uid).await.unwrap().len(),
        3,
        "activation must not charge"
    );
    let other = db
        .insert_plan("other", 5, 10, "1", "data", 0, false, false, "", true)
        .await
        .unwrap();
    assert!(matches!(
        db.buy_plan(uid, other, "other", 100, 10, 5, 0, false, true, &[], &[])
            .await,
        Err(BuyPlanError::PrepaidCyclesPresent)
    ));
    assert_eq!(user(db, uid).await.balance, "70");
    assert_eq!(
        db.admin_edit_user_plan(uid, pid, true, None).await.unwrap(),
        AdminUserPlanEditOutcome::PrepaidCyclesPresent
    );
    assert_ledger(db, uid).await;
    let orders = db.list_orders_by_user(uid).await.unwrap();
    assert_eq!(orders[0].kind, "prepayment");
    assert!(orders.iter().all(|order| order.transaction_id.is_some()
        && order.entitlement_snapshot.is_some()
        && order.cycle_end.is_some()));
}

pub async fn registration_entitlement_contract(db: &dyn Repository) {
    let (_, group, _, _) = fixture(db).await;
    let free = db
        .create_plan_with_groups(
            "trial",
            3,
            1000,
            "0",
            "monthly",
            30,
            false,
            true,
            "",
            false,
            &[group],
        )
        .await
        .unwrap();
    let paid = db
        .create_plan_with_groups(
            "paid",
            3,
            1000,
            "10",
            "monthly",
            30,
            false,
            true,
            "",
            false,
            &[group],
        )
        .await
        .unwrap();
    db.set_registration_settings(true, free, &[free, paid])
        .await
        .unwrap();
    assert_eq!(
        db.insert_public_registered_user("trial-user", "hash", Some(free))
            .await
            .unwrap(),
        UserProvisionOutcome::Created
    );
    let trial = UserRepository::find_by_username(db, "trial-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trial.plan_source, "trial");
    assert_eq!(trial.plan_id, Some(free));
    assert_eq!(
        db.authorized_device_group_ids(trial.id).await.unwrap(),
        vec![group]
    );
    assert!(trial.current_cycle_id.is_some());
    assert_eq!(
        db.insert_public_registered_user("paid-user", "hash", Some(paid))
            .await
            .unwrap(),
        UserProvisionOutcome::Created
    );
    let pending = UserRepository::find_by_username(db, "paid-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.plan_source, "pending");
    assert_eq!(pending.registration_plan_id, Some(paid));
    assert!(
        pending.plan_id.is_none()
            && pending.plan_expire_at.is_none()
            && pending.current_cycle_id.is_none()
    );
    assert!(db
        .authorized_device_group_ids(pending.id)
        .await
        .unwrap()
        .is_empty());
    assert!(db.list_orders_by_user(pending.id).await.unwrap().is_empty());
    db.update_user_fields(pending.id, Some("10"), None, None, None, None)
        .await
        .unwrap();
    db.buy_plan_guarded(
        pending.id,
        paid,
        "paid",
        1000,
        1000,
        3,
        30,
        true,
        false,
        &[group],
        &[group],
        "monthly",
        false,
        true,
        Some(None),
    )
    .await
    .unwrap();
    let activated = user(db, pending.id).await;
    assert_eq!(activated.plan_source, "paid");
    let cycles = db.list_subscription_cycles(pending.id).await.unwrap();
    assert_eq!(
        cycles.len(),
        1,
        "first payment must not extend a phantom trial"
    );
    assert_eq!(
        crate::service::billing::add_days(&cycles[0].starts_at, 30).unwrap(),
        activated.plan_expire_at.unwrap()
    );
    assert_eq!(
        db.authorized_device_group_ids(pending.id).await.unwrap(),
        vec![group]
    );
    assert_ledger(db, pending.id).await;
}

pub async fn prepaid_downtime_and_suspension_contract(db: &dyn Repository) {
    let (uid, group, _, rules) = fixture(db).await;
    let pid = db
        .insert_plan(
            "monthly", 10, 1000, "10", "monthly", 30, false, true, "", true,
        )
        .await
        .unwrap();
    for _ in 0..4 {
        db.buy_plan_guarded(
            uid,
            pid,
            "monthly",
            1000,
            1000,
            10,
            30,
            true,
            true,
            &[],
            &[],
            "monthly",
            false,
            true,
            None,
        )
        .await
        .unwrap();
    }
    db.increment_user_traffic(uid, 500).await.unwrap();
    db.update_rule_full(&RuleUpdateData {
        id: rules[0],
        owner_uid: Some(uid),
        paused: Some(true),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut cycles = db.list_subscription_cycles(uid).await.unwrap();
    cycles.retain(|cycle| cycle.source == "paid");
    assert_eq!(cycles.len(), 4);
    cycles.sort_by(|a, b| a.starts_at.cmp(&b.starts_at));
    db.update_user_with_authorization(
        uid,
        AdminUserUpdate {
            suspended: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Restart after more than one boundary: skip elapsed periods, activate the
    // actual paid period, but never undo suspension or a human rule pause.
    assert!(db
        .activate_subscription_cycle(uid, &cycles[2].starts_at)
        .await
        .unwrap());
    let active = user(db, uid).await;
    assert_eq!(
        active.current_cycle_id.as_deref(),
        Some(cycles[2].id.as_str())
    );
    assert_eq!((active.traffic_used, active.balance.as_str()), (0, "60"));
    assert!(active.suspended && !active.plan_auto_renew);
    assert!(db.list_active_for_config(group).await.unwrap().is_empty());
    assert_eq!(
        db.renew_expired_monthly_plan(uid, "2099-01-01 00:00:00")
            .await
            .unwrap(),
        MonthlyRenewalOutcome::NotEligible
    );
    db.update_user_with_authorization(
        uid,
        AdminUserUpdate {
            suspended: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let forwarded = db.list_active_for_config(group).await.unwrap();
    assert_eq!(forwarded.len(), 2);
    assert!(forwarded.iter().all(|rule| rule.id != rules[0]));
    db.increment_user_traffic(uid, 120).await.unwrap();
    assert!(!db
        .activate_subscription_cycle(uid, &cycles[2].starts_at)
        .await
        .unwrap());
    assert_eq!(user(db, uid).await.traffic_used, 120);
    db.update_user_with_authorization(
        uid,
        AdminUserUpdate {
            banned: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(db
        .activate_subscription_cycle(uid, &cycles[3].starts_at)
        .await
        .unwrap());
    assert!(user(db, uid).await.banned);
    assert!(db.list_active_for_config(group).await.unwrap().is_empty());
    assert_eq!(db.list_orders_by_user(uid).await.unwrap().len(), 4);
    assert_ledger(db, uid).await;
}

pub async fn prepaid_grants_and_financial_retention_contract(db: &dyn Repository) {
    let (uid, group, _, _) = fixture(db).await;
    let pid = db
        .create_plan_with_groups(
            "monthly",
            10,
            1000,
            "10",
            "monthly",
            30,
            false,
            true,
            "",
            false,
            &[group],
        )
        .await
        .unwrap();
    for _ in 0..2 {
        db.buy_plan_guarded(
            uid,
            pid,
            "monthly",
            1000,
            1000,
            10,
            30,
            true,
            false,
            &[group],
            &[group],
            "monthly",
            false,
            true,
            None,
        )
        .await
        .unwrap();
    }
    // Remove all live catalog/rule references; the paid snapshot alone must
    // still prevent deleting or invalidating the line promised to this buyer.
    db.update_plan_fields(
        pid,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[]),
    )
    .await
    .unwrap();
    db.delete_rules_by_uid(uid).await.unwrap();
    assert!(matches!(db.delete_group_checked(group).await.unwrap(),
        GroupDeleteOutcome::InUse { rule_count: 0, plan_count, .. } if plan_count >= 2));
    assert!(matches!(
        db.update_group_fields(
            group,
            &ResourceScope::All,
            None,
            Some("out"),
            None,
            None,
            None,
            None,
            None
        )
        .await,
        Err(DbError::GroupPlanInvariant { .. })
    ));
    let cycles = db.list_subscription_cycles(uid).await.unwrap();
    let current = user(db, uid).await.current_cycle_id;
    let next = cycles
        .iter()
        .find(|cycle| cycle.source == "paid" && Some(&cycle.id) != current.as_ref())
        .unwrap();
    assert!(db
        .activate_subscription_cycle(uid, &next.starts_at)
        .await
        .unwrap());
    assert_eq!(
        db.authorized_device_group_ids(uid).await.unwrap(),
        vec![group]
    );
    let ledger = db.list_balance_entries(uid, 200, 0).await.unwrap();
    assert_eq!(
        db.list_balance_entries(uid, 1, 1).await.unwrap()[0].id,
        ledger[1].id
    );
    assert_eq!(
        db.list_balance_entries(uid, 0, -1).await.unwrap()[0].id,
        ledger[0].id
    );
    assert_eq!(db.delete_user_cascade(uid).await.unwrap(), 1);
    assert_eq!(
        db.list_balance_entries(uid, 200, 0).await.unwrap().len(),
        ledger.len()
    );
    assert_eq!(db.list_orders_by_user(uid).await.unwrap().len(), 2);
    assert_eq!(
        db.list_subscription_cycles(uid).await.unwrap().len(),
        cycles.len()
    );
}
