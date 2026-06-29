use super::err;
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

// === Plans (v1.0.8) ===
//
// Admin CRUD over the plans table. GET returns ALL plans (including hidden);
// the public shop endpoint (GET /plans) filters hidden=0. Deletion is blocked
// (409) when any user's plan_id still references the plan.

/// Validate the invariant fields shared by create + update. Returns the
/// canonicalized price on success, or an error message on failure.
/// `name_required` controls whether an empty name is rejected (create) or
/// allowed through (update, where None means "leave unchanged").
fn validate_plan_fields(
    name: Option<&str>,
    max_rules: Option<i32>,
    traffic: Option<i64>,
    price: Option<&str>,
    plan_type: Option<&str>,
    duration_days: Option<i32>,
    name_required: bool,
) -> Result<Option<String>, String> {
    if let Some(n) = name {
        let trimmed = n.trim();
        if name_required && trimmed.is_empty() {
            return Err("name must not be empty".into());
        }
        if trimmed.len() > 100 {
            return Err("name must be at most 100 characters".into());
        }
    }
    if let Some(mr) = max_rules {
        if !(0..=100_000).contains(&mr) {
            return Err("max_rules must be between 0 and 100000".into());
        }
    }
    if let Some(t) = traffic {
        if t < 0 {
            return Err("traffic must be non-negative".into());
        }
    }
    if let Some(pt) = plan_type {
        if pt != "data" && pt != "time" {
            return Err("plan_type must be 'data' or 'time'".into());
        }
    }
    if let Some(dd) = duration_days {
        if dd < 0 {
            return Err("duration_days must be non-negative".into());
        }
        // A time plan with duration_days=0 makes no sense; reject it at write
        // time so the shop never offers an instantly-expiring plan.
        if plan_type == Some("time") && dd == 0 {
            return Err("duration_days must be > 0 for time plans".into());
        }
    }
    // price is a decimal string — canonicalize via the balance parser (same
    // rules: non-negative, ≤ 2 fraction digits, ≤ 9999999999.99). None on the
    // update path means "leave unchanged".
    match price {
        None => Ok(None),
        Some(raw) => match relay_shared::money::parse_balance(raw) {
            Ok(c) => Ok(Some(c)),
            Err(reason) => Err(reason.into()),
        },
    }
}

pub async fn list_plans(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Plan>>> {
    let plans: Vec<Plan> = state.db.list_plans().await.unwrap_or_else(|e| {
        tracing::error!("list_plans: db error: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(plans))
}

pub async fn create_plan(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreatePlanRequest>,
) -> Json<ApiResponse<i64>> {
    let canonical_price = match validate_plan_fields(
        Some(&req.name),
        Some(req.max_rules),
        Some(req.traffic),
        Some(&req.price),
        Some(&req.plan_type),
        Some(req.duration_days),
        true,
    ) {
        Ok(p) => p.unwrap_or_default(),
        Err(msg) => return Json(err(400, msg)),
    };

    match state
        .db
        .insert_plan(
            &req.name,
            req.max_rules,
            req.traffic,
            &canonical_price,
            &req.plan_type,
            req.duration_days,
            req.hidden,
            req.reset_traffic,
            &req.description,
        )
        .await
    {
        Ok(id) => Json(ApiResponse::success(id)),
        Err(e) => {
            tracing::error!("create_plan: db error: {}", e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn update_plan(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdatePlanRequest>,
) -> Json<ApiResponse<()>> {
    if req.name.is_none()
        && req.max_rules.is_none()
        && req.traffic.is_none()
        && req.price.is_none()
        && req.plan_type.is_none()
        && req.duration_days.is_none()
        && req.hidden.is_none()
        && req.reset_traffic.is_none()
        && req.description.is_none()
    {
        return Json(err(400, "No fields to update"));
    }

    // v1.0.8: when plan_type is being changed to 'time' in this same request,
    // the duration_days > 0 rule must be evaluated against the NEW type. If
    // plan_type isn't being changed, we can't know the existing type here
    // cheaply, so we only enforce the cross-field rule when plan_type is
    // present in the request.
    let effective_plan_type = req.plan_type.as_deref();
    let canonical_price = match validate_plan_fields(
        req.name.as_deref(),
        req.max_rules,
        req.traffic,
        req.price.as_deref(),
        effective_plan_type,
        req.duration_days,
        false,
    ) {
        Ok(p) => p,
        Err(msg) => return Json(err(400, msg)),
    };

    // Reject the (plan_type=time, duration_days=0) combination when BOTH are
    // supplied together — validate_plan_fields only checks it when plan_type is
    // present, so cover the case where the caller flips to time but leaves
    // duration_days untouched (None) by reading the existing row.
    if let Some("time") = effective_plan_type {
        if req.duration_days == Some(0) {
            return Json(err(400, "duration_days must be > 0 for time plans"));
        }
        if req.duration_days.is_none() {
            // Caller set plan_type=time without duration_days — verify the
            // existing row's duration_days is > 0 before flipping.
            match state.db.find_plan_by_id(id).await {
                Ok(Some(p)) if p.duration_days > 0 => {}
                Ok(Some(_)) => {
                    return Json(err(400, "duration_days must be > 0 for time plans"))
                }
                Ok(None) => return Json(err(404, "Plan not found")),
                Err(e) => {
                    tracing::error!("update_plan {}: lookup failed: {}", id, e);
                    return Json(err(500, "database error"));
                }
            }
        }
    }

    match state
        .db
        .update_plan_fields(
            id,
            req.name.as_deref(),
            req.max_rules,
            req.traffic,
            canonical_price.as_deref(),
            req.plan_type.as_deref(),
            req.duration_days,
            req.hidden,
            req.reset_traffic,
            req.description.as_deref(),
        )
        .await
    {
        Ok(0) => Json(err(404, "Plan not found")),
        Ok(_) => {
            // A plan change can alter max_rules / the shop list, but does NOT
            // change what nodes forward (gating is per-user, not per-plan).
            // No config_changed broadcast needed.
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("update_plan {}: db error: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn delete_plan(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    // Pre-delete safety check: refuse if any user's plan_id references this
    // plan. Deleting would orphan the FK and leave users on a ghost plan.
    let in_use = match state.db.count_users_on_plan(id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("delete_plan {}: count_users_on_plan failed: {}", id, e);
            return Json(err(500, "database error"));
        }
    };
    if in_use > 0 {
        return Json(err(
            409,
            format!("该套餐仍被 {} 个用户使用，请先迁移用户。", in_use),
        ));
    }

    match state.db.delete_plan(id).await {
        Ok(0) => Json(err(404, "Plan not found")),
        Ok(_) => Json(ApiResponse::success(())),
        Err(e) => {
            tracing::error!("delete_plan {}: db error: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}
