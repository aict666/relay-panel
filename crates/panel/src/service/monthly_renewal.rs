//! Recurring monthly subscription scheduler.
//!
//! The candidate scan is intentionally only a hint. Every renewal predicate is
//! rechecked by the repository while the user row is write-locked, which makes
//! this safe across concurrent ticks and multiple panel instances.

use crate::api::AppState;
use crate::db::repo::MonthlyRenewalOutcome;
use std::time::Duration;

const TICK: Duration = Duration::from_secs(60);
const BATCH_LIMIT: i64 = 200;

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            "monthly renewal scheduler started (tick {}s)",
            TICK.as_secs()
        );
        loop {
            ticker.tick().await;
            tick(&state).await;
        }
    });
}

pub(crate) async fn tick(state: &AppState) {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut changed = false;
    match state
        .db
        .list_due_subscription_user_ids(&now, BATCH_LIMIT)
        .await
    {
        Ok(ids) => {
            for id in ids {
                match state.db.activate_subscription_cycle(id, &now).await {
                    Ok(activated) => changed |= activated,
                    Err(error) => {
                        tracing::error!(user_id = id, "prepaid cycle activation failed: {error}")
                    }
                }
            }
        }
        Err(error) => tracing::error!("prepaid cycle candidate scan failed: {error}"),
    }
    let user_ids = match state
        .db
        .list_expired_monthly_auto_renew_user_ids(&now, BATCH_LIMIT)
        .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!("monthly renewal candidate scan failed: {error}");
            return;
        }
    };

    for user_id in user_ids {
        match state.db.renew_expired_monthly_plan(user_id, &now).await {
            Ok(MonthlyRenewalOutcome::Renewed { plan_id, plan_name }) => {
                changed = true;
                tracing::info!(
                    action = "auto_renew_monthly_plan",
                    target_user_id = user_id,
                    plan_id,
                    "monthly subscription renewed"
                );
                crate::service::audit::record(
                    state,
                    None,
                    "auto_renew_monthly_plan",
                    "user",
                    user_id,
                    &format!("套餐 {plan_name}"),
                )
                .await;
            }
            // Keep the opt-in enabled: after a top-up, the next tick renews the
            // expired subscription without another user action. The repository
            // records a short retry delay so this user does not starve the
            // bounded candidate queue.
            Ok(MonthlyRenewalOutcome::InsufficientBalance) => {}
            // A billing-affecting plan edit invalidates the accepted contract.
            // Renewal is disabled atomically; the user must review and opt in
            // again before another charge can happen.
            Ok(MonthlyRenewalOutcome::ContractChanged) => {
                tracing::info!(user_id, "monthly renewal contract changed; opt-in disabled");
            }
            // Another panel instance renewed it, or the user/plan changed
            // after the candidate scan. Both are normal races.
            Ok(MonthlyRenewalOutcome::NotEligible) => {}
            Err(error) => {
                tracing::error!(user_id, "monthly renewal failed: {error}");
            }
        }
    }

    if changed {
        state
            .node_connections
            .broadcast_all(r#"{"type":"config_changed"}"#)
            .await;
    }
}
