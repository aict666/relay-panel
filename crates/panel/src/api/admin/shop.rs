use super::err;
use super::{purchase_revision, PlanWithGroups};
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::db::repo::{BuyPlanError, PlanAutoRenewUpdateOutcome, PurchaseIdentity};
use axum::{extract::State, Json};
use relay_shared::models::*;
use relay_shared::protocol::*;

#[derive(serde::Deserialize, Default)]
pub struct LedgerQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn user_balance_ledger(
    user: AuthUser,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<LedgerQuery>,
) -> Json<ApiResponse<Vec<crate::service::billing::BalanceEntry>>> {
    match state
        .db
        .list_balance_entries(
            user.user_id,
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
    {
        Ok(rows) => Json(ApiResponse::success(rows)),
        Err(error) => {
            tracing::error!("balance ledger: {error}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn admin_balance_ledger(
    _admin: crate::api::middleware::AdminOnly,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    axum::extract::Query(query): axum::extract::Query<LedgerQuery>,
) -> Json<ApiResponse<Vec<crate::service::billing::BalanceEntry>>> {
    match state
        .db
        .list_balance_entries(id, query.limit.unwrap_or(50), query.offset.unwrap_or(0))
        .await
    {
        Ok(rows) => Json(ApiResponse::success(rows)),
        Err(error) => {
            tracing::error!("admin balance ledger: {error}");
            Json(err(500, "数据库错误"))
        }
    }
}

// === Shop (v1.0.8) ===
//
// Self-service plan purchase. GET /plans lists ONLY non-hidden plans. POST
// /user/buy-plan atomically charges the user's balance, applies the plan's
// quota/lifecycle semantics, sets max_rules / plan_id, computes expiry, and
// records an order row — all in one transaction (防双花).

/// GET /plans — public list of purchasable plans (hidden excluded). v1.0.9:
/// each plan carries its `device_group_ids` so the shop can show "包含线路".
pub async fn list_public_plans(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<PlanWithGroups>>> {
    let plans: Vec<Plan> = match state.db.list_visible_plans().await {
        Ok(p) => p,
        Err(e) => {
            // v1.0.9: a DB failure returns 500, not an empty "success" that the
            // shop would render as "no plans available".
            tracing::error!("list_public_plans: db error: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };
    let valid_group_ids: std::collections::HashSet<i64> =
        match state.db.list_all_inbound_group_ids().await {
            Ok(ids) => ids.into_iter().collect(),
            Err(e) => {
                tracing::error!("list_public_plans: valid group catalog failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        };
    let mut out = Vec::with_capacity(plans.len());
    for plan in plans {
        // grant_all_groups plans grant everything — the explicit list is moot,
        // so skip the lookup and return an empty list (the card shows "全部线路").
        let device_group_ids = if plan.grant_all_groups {
            Vec::new()
        } else {
            match state.db.list_plan_device_groups(plan.id).await {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::error!(
                        "list_public_plans: list_plan_device_groups({}) failed: {}",
                        plan.id,
                        e
                    );
                    return Json(err(500, "数据库错误"));
                }
            }
        };
        if device_group_ids
            .iter()
            .any(|group_id| !valid_group_ids.contains(group_id))
        {
            tracing::warn!(
                plan_id = plan.id,
                "list_public_plans: hiding historical plan with an unusable device-group grant"
            );
            continue;
        }
        let device_group_names = match state.db.list_group_names_by_ids(&device_group_ids).await {
            Ok(names) => names,
            Err(e) => {
                tracing::error!(
                    "list_public_plans: list_group_names_by_ids({}) failed: {}",
                    plan.id,
                    e
                );
                return Json(err(500, "数据库错误"));
            }
        };
        let purchase_revision = purchase_revision(&plan, &device_group_ids);
        out.push(PlanWithGroups {
            plan,
            device_group_ids,
            device_group_names,
            purchase_revision,
        });
    }
    Json(ApiResponse::success(out))
}

/// POST /user/buy-plan — purchase a plan. Refuses hidden plans, out-of-range
/// duration on time plans, and insufficient balance (atomic; no partial state).
pub async fn buy_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<BuyPlanRequest>,
) -> Json<ApiResponse<()>> {
    let Some(request_id) = req
        .request_id
        .as_deref()
        .filter(|id| relay_shared::protocol::valid_traffic_batch_id(id))
    else {
        return Json(err(400, "购买需要有效的 request_id，请刷新页面后重试"));
    };
    let fingerprint = format!(
        "self:{}",
        serde_json::to_string(&req).expect("purchase body serializes")
    );
    let identity = PurchaseIdentity {
        request_id,
        fingerprint: &fingerprint,
        actor_id: Some(user.user_id),
    };
    if let Some(response) = replay_purchase(&state, user.user_id, identity).await {
        return Json(response);
    }
    let Some(expected_current) = req.expected_current_plan_id.filter(|id| *id >= 0) else {
        return Json(err(400, "购买前必须确认当前套餐"));
    };
    if req.expected_price.is_none() || req.expected_revision.is_none() {
        return Json(err(400, "购买前必须确认套餐价格和内容"));
    }
    // Resolve the plan row first (outside the buy tx — read-only lookup).
    // Hidden plans are not self-purchasable even if the caller knows the id.
    let plan = match state.db.find_plan_by_id(req.plan_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return Json(err(404, "套餐不存在")),
        Err(e) => {
            tracing::error!("buy_plan {}: plan lookup failed: {}", req.plan_id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    if plan.hidden {
        // Don't reveal existence — same 404 as a missing plan.
        return Json(err(404, "套餐不存在"));
    }
    if let Some(expected_price) = req.expected_price.as_deref() {
        match relay_shared::money::parse_balance(expected_price) {
            Ok(expected) if expected == plan.price => {}
            Ok(_) => return Json(err(409, "套餐价格已变更，请刷新后重新确认")),
            Err(reason) => return Json(err(400, reason)),
        }
    }
    // A time plan must have a positive duration (the CRUD layer enforces this
    // too, but a pre-existing bad row shouldn't crash the purchase).
    if plan.plan_type == "time" && plan.duration_days <= 0 {
        return Json(err(400, "该套餐无有效时长"));
    }
    if plan.plan_type == "monthly" && (plan.duration_days != 30 || !plan.reset_traffic) {
        return Json(err(400, "该月付套餐配置无效"));
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
            return Json(err(500, "数据库错误"));
        }
    };

    // duration_days drives the expiry. Data plans use NULL; fixed-duration and
    // monthly plans carry an actual expiry.
    let duration_days = if matches!(plan.plan_type.as_str(), "time" | "monthly") {
        plan.duration_days
    } else {
        0
    };

    // v1.0.9: resolve the plan's device-group grant set. Only used when
    // grant_all_groups=false (buy_plan ignores the list otherwise), but fetch
    // it unconditionally so the same call shape covers both modes.
    let device_group_ids = if plan.grant_all_groups {
        Vec::new()
    } else {
        match state.db.list_plan_device_groups(plan.id).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(
                    "buy_plan {}: list_plan_device_groups failed: {}",
                    plan.id,
                    e
                );
                return Json(err(500, "数据库错误"));
            }
        }
    };
    if let Some(expected_revision) = req.expected_revision.as_deref() {
        if expected_revision != purchase_revision(&plan, &device_group_ids) {
            return Json(err(409, "套餐内容已变更，请刷新后重新确认"));
        }
    }

    // Per-group plans use their grant set for pause/resume. Grant-all semantics
    // are handled directly inside the purchase transaction, avoiding a stale
    // pre-transaction snapshot of the global group catalog.
    let new_authorized_group_ids = if plan.grant_all_groups {
        Vec::new()
    } else {
        device_group_ids.clone()
    };

    match state
        .db
        .buy_plan_idempotent(
            user.user_id,
            plan.id,
            &plan.name,
            price_cents,
            plan.traffic,
            plan.max_rules,
            duration_days,
            plan.reset_traffic,
            plan.grant_all_groups,
            &device_group_ids,
            &new_authorized_group_ids,
            &plan.plan_type,
            req.auto_renew && plan.plan_type == "monthly",
            true,
            Some(if expected_current == 0 {
                None
            } else {
                Some(expected_current)
            }),
            identity,
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
        Err(BuyPlanError::PrepaidCyclesPresent) => Json(err(
            409,
            "还有未使用的预付周期，不能直接切换套餐，请联系管理员先处理剩余权益",
        )),
        Err(BuyPlanError::AutoRenewUnavailable) => {
            Json(err(409, "封禁或暂停的账户不能开启自动续费"))
        }
        Err(BuyPlanError::IdempotencyConflict) => {
            Json(err(409, "交易标识已用于其他购买，请勿更改重试内容"))
        }
        Err(BuyPlanError::PlanChanged) => Json(err(409, "套餐已变更，请刷新后重新确认")),
        Err(BuyPlanError::UserPlanChanged) => Json(err(409, "当前套餐已变更，请刷新后重新确认")),
        Err(BuyPlanError::QuotaOverflow) => Json(err(409, "累计流量额度超出系统上限")),
        Err(BuyPlanError::Database(e)) => {
            tracing::error!("buy_plan {}: db error: {}", plan.id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

/// Check replay BEFORE catalog validation: a lost-ACK purchase still succeeds
/// on retry even after its product was changed or hidden. The transaction also
/// rechecks this identity, so simultaneous requests cannot bypass the guard.
pub(super) async fn replay_purchase(
    state: &AppState,
    user_id: i64,
    identity: PurchaseIdentity<'_>,
) -> Option<ApiResponse<()>> {
    match state
        .db
        .find_purchase_fingerprint(user_id, identity.request_id)
        .await
    {
        Ok(Some(saved)) if saved == identity.fingerprint => Some(ApiResponse::success(())),
        Ok(Some(_)) => Some(err(409, "交易标识已用于其他购买，请勿更改重试内容")),
        Ok(None) => None,
        Err(e) => {
            tracing::error!("purchase replay lookup failed: {e}");
            Some(err(500, "数据库错误"))
        }
    }
}

/// PUT /user/plan/auto-renew — explicit recurring-charge preference. The
/// repository validates the current plan atomically; a stale account page
/// cannot enable billing after another request switched the plan.
pub async fn set_plan_auto_renew(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<SetPlanAutoRenewRequest>,
) -> Json<ApiResponse<()>> {
    if req.enabled
        && (req.expected_price.is_none()
            || req.expected_revision.is_none()
            || req.expected_plan_id.is_none())
    {
        return Json(err(400, "开启自动续费前必须确认当前套餐价格"));
    }
    match state
        .db
        .set_plan_auto_renew_guarded(
            user.user_id,
            req.enabled,
            req.expected_price.as_deref(),
            req.expected_revision,
            req.expected_plan_id,
        )
        .await
    {
        Ok(PlanAutoRenewUpdateOutcome::Updated) => Json(ApiResponse::success(())),
        Ok(PlanAutoRenewUpdateOutcome::UserNotFound) => Json(err(404, "用户不存在")),
        Ok(PlanAutoRenewUpdateOutcome::NotMonthly) => {
            Json(err(409, "当前套餐不是月付套餐，无法开启自动续费"))
        }
        Ok(PlanAutoRenewUpdateOutcome::ContractChanged) => {
            Json(err(409, "套餐计费信息已变更，请刷新后重新确认"))
        }
        Err(e) => {
            tracing::error!("set_plan_auto_renew {}: db error: {}", user.user_id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

/// GET /user/orders — the calling user's purchase history, newest first.
/// v1.2.4: one order with the buyer's name resolved for display.
#[derive(Debug, serde::Serialize)]
pub struct AdminOrderRow {
    pub id: i64,
    pub user_id: i64,
    /// None when the account was deleted — the order row survives as the
    /// money-in record, so the id is kept and only the name goes missing.
    pub username: Option<String>,
    pub plan_name: String,
    pub price: String,
    pub created_at: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct AdminOrdersQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminOrdersResponse {
    pub items: Vec<AdminOrderRow>,
    pub total: i64,
}

/// GET /api/v1/admin/orders — every user's purchases.
///
/// The shop page shows the caller their own; this is the operator's view of
/// all of them, which is what answers "who bought what this week".
pub async fn list_all_orders(
    _admin: crate::api::middleware::AdminOnly,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AdminOrdersQuery>,
) -> Json<ApiResponse<AdminOrdersResponse>> {
    let limit = q.limit.unwrap_or(20).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);

    let total = match state.db.count_all_orders().await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("list_all_orders: count failed: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };
    let orders = match state.db.list_all_orders(limit, offset).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("list_all_orders: query failed: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };

    // One user fetch for the page, not one per row — the same shape the redeem
    // list uses. An id that no longer resolves stays None rather than blocking
    // the page: the order outlives the account on purpose.
    let names: std::collections::HashMap<i64, String> = match state.db.list_users_public().await {
        Ok(users) => users.into_iter().map(|u| (u.id, u.username)).collect(),
        Err(e) => {
            tracing::error!("list_all_orders: user lookup failed: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };

    let items = orders
        .into_iter()
        .map(|o| AdminOrderRow {
            id: o.id,
            user_id: o.user_id,
            username: names.get(&o.user_id).cloned(),
            plan_name: o.plan_name,
            price: o.price,
            created_at: o.created_at,
        })
        .collect();
    Json(ApiResponse::success(AdminOrdersResponse { items, total }))
}

pub async fn list_my_orders(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Order>>> {
    let orders: Vec<Order> = match state.db.list_orders_by_user(user.user_id).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("list_my_orders {}: db error: {}", user.user_id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    Json(ApiResponse::success(orders))
}
