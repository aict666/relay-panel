use super::err;
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::db::repo::BuyPlanError;
use axum::{extract::State, Json};
use relay_shared::models::*;
use relay_shared::protocol::*;

// === Shop (v1.0.8) ===
//
// Self-service plan purchase. GET /plans lists ONLY non-hidden plans. POST
// /user/buy-plan atomically charges the user's balance, stacks the plan's
// traffic onto their quota, sets max_rules / plan_id, computes a stacking
// expiry, and records an order row — all in one transaction (防双花).

/// GET /plans — public list of purchasable plans (hidden excluded).
pub async fn list_public_plans(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Plan>>> {
    let plans: Vec<Plan> = state.db.list_visible_plans().await.unwrap_or_else(|e| {
        tracing::error!("list_public_plans: db error: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(plans))
}

/// POST /user/buy-plan — purchase a plan. Refuses hidden plans, out-of-range
/// duration on time plans, and insufficient balance (atomic; no partial state).
pub async fn buy_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<BuyPlanRequest>,
) -> Json<ApiResponse<()>> {
    // Resolve the plan row first (outside the buy tx — read-only lookup).
    // Hidden plans are not self-purchasable even if the caller knows the id.
    let plan = match state.db.find_plan_by_id(req.plan_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return Json(err(404, "Plan not found")),
        Err(e) => {
            tracing::error!("buy_plan {}: plan lookup failed: {}", req.plan_id, e);
            return Json(err(500, "database error"));
        }
    };
    if plan.hidden {
        // Don't reveal existence — same 404 as a missing plan.
        return Json(err(404, "Plan not found"));
    }
    // A time plan must have a positive duration (the CRUD layer enforces this
    // too, but a pre-existing bad row shouldn't crash the purchase).
    if plan.plan_type == "time" && plan.duration_days <= 0 {
        return Json(err(400, "This plan has no valid duration"));
    }

    // Decimal money: compare + deduct in integer cents (no floats). price is
    // stored canonical, so balance_to_cents succeeds; a None here is a data
    // integrity fault — refuse rather than mis-bill.
    let price_cents = match relay_shared::money::balance_to_cents(&plan.price) {
        Some(c) => c,
        None => {
            tracing::error!(
                "buy_plan: plan {} has non-canonical price {:?}",
                plan.id,
                plan.price
            );
            return Json(err(500, "database error"));
        }
    };

    // duration_days drives the expiry. Non-time plans (or duration_days=0)
    // → no expiry (NULL), per the spec's "不限时=NULL".
    let duration_days = if plan.plan_type == "time" {
        plan.duration_days
    } else {
        0
    };

    match state
        .db
        .buy_plan(
            user.user_id,
            plan.id,
            &plan.name,
            price_cents,
            plan.traffic,
            plan.max_rules,
            duration_days,
            plan.reset_traffic,
        )
        .await
    {
        Ok(()) => {
            // The purchase can change what the user's nodes forward (max_rules
            // / traffic_limit / expiry all feed list_active_for_config), so
            // refresh node configs.
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(BuyPlanError::InsufficientBalance) => Json(err(400, "余额不足")),
        Err(BuyPlanError::Database(e)) => {
            tracing::error!("buy_plan {}: db error: {}", plan.id, e);
            Json(err(500, "database error"))
        }
    }
}

/// GET /user/orders — the calling user's purchase history, newest first.
pub async fn list_my_orders(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Order>>> {
    let orders: Vec<Order> = match state.db.list_orders_by_user(user.user_id).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("list_my_orders {}: db error: {}", user.user_id, e);
            return Json(err(500, "database error"));
        }
    };
    Json(ApiResponse::success(orders))
}
