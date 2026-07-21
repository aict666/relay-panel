use super::{err, UserPublic};
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::{AdminUserPlanEditOutcome, AdminUserUpdate, BuyPlanError};
use crate::service::password::PasswordValidationError;
use crate::service::users::CreateUserError;
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::protocol::{
    AdminBuyPlanRequest, AdminSetUserPlanRequest, ApiResponse, UpdateUserRequest,
};
// === Users ===
pub async fn list_users(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<UserPublic>>> {
    // SELECT * is safe here — UserPublic has no `password` field, so sqlx
    // simply ignores that column. The hash never reaches the API response.
    match state.db.list_users_public().await {
        Ok(users) => Json(ApiResponse::success(users)),
        Err(e) => {
            tracing::error!("list_users: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

/// Admin creates a NON-ADMIN user. Per the v0.4.4 two-tier model, admins can
/// only create regular users (never other admins) — `insert_user` always writes
/// admin=false (the schema default), so privilege escalation is impossible here.
/// The admin supplies the username + initial password.
#[derive(Debug, serde::Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

pub async fn create_user(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Json<ApiResponse<()>> {
    match crate::service::users::create_user(state.db.as_ref(), &req.username, &req.password).await
    {
        Ok(()) => {
            tracing::info!(
                action = "create_user",
                actor_admin_id = _admin.user_id,
                "admin created user {:?}",
                req.username
            );
            Json(ApiResponse::success(()))
        }
        Err(CreateUserError::InvalidUsername) => Json(err(
            400,
            "Username must be 1-64 chars, ASCII letters/digits/underscore only",
        )),
        Err(CreateUserError::Password(PasswordValidationError::TooShort)) => {
            Json(err(400, "密码至少8个字符"))
        }
        Err(CreateUserError::Password(PasswordValidationError::TooLong)) => {
            Json(err(400, "密码最多72字节"))
        }
        Err(CreateUserError::Hash(e)) => {
            tracing::error!("create_user: password hashing failed: {}", e);
            Json(err(500, "密码服务失败，请稍后重试"))
        }
        Err(CreateUserError::DuplicateUsername) => Json(err(409, "用户名已存在")),
        Err(CreateUserError::DefaultPlanMissing(plan_id)) => {
            tracing::error!(
                "create_user: configured default plan {} is missing; no user created",
                plan_id
            );
            Json(err(
                500,
                "Default plan is missing; contact an administrator",
            ))
        }
        Err(CreateUserError::Database(e)) => {
            tracing::error!("create_user: insert failed for {:?}: {}", req.username, e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_user(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    // Check the target first. Admin users are protected, and their associated
    // rules/groups must be protected too — do not clean anything up until the
    // target is known to be a deletable non-admin user.
    let is_admin = match state.db.is_admin(id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("delete_user {}: is_admin lookup failed: {}", id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    // Also need to confirm the row exists (is_admin returns false for both
    // "non-admin exists" and "doesn't exist" — distinguish via exists_by_id).
    let exists = match state.db.exists_by_id(id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("delete_user {}: exists lookup failed: {}", id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    if !exists || is_admin {
        return Json(err(404, "用户不存在（或为管理员，无法删除）"));
    }

    // Atomic cascade delete: removes the user's rules, tunnel_profiles and
    // device_groups, then the user row itself, all in ONE transaction with the
    // admin guard baked in. Returns 0 (and rolls back) if the target is an admin
    // or no longer exists — so we never leave a half-deleted account.
    match state.db.delete_user_cascade(id).await {
        Ok(0) => Json(err(404, "用户不存在（或为管理员，无法删除）")),
        Ok(_) => {
            tracing::warn!(
                action = "delete_user",
                target_user_id = id,
                actor_admin_id = _admin.user_id,
                "destructive admin op"
            );
            Json(ApiResponse::success(()))
        }
        Err(crate::db::error::DbError::UserTunnelGroupConflict { groups, tunnels }) => Json(err(
            409,
            format!(
                "该用户仍拥有 {groups} 个被 {tunnels} 条预设隧道引用的设备组，请先修改或删除相关隧道"
            ),
        )),
        Err(crate::db::error::DbError::UserGroupReferenceConflict {
            rules,
            fallback_groups,
            plans,
        }) => Json(err(
            409,
            format!(
                "该用户的设备组仍被引用（规则 {rules}、回退分组 {fallback_groups}、套餐 {plans}），请先解除相关引用"
            ),
        )),
        Err(crate::db::error::DbError::UserOwnedTunnelConflict { tunnels, rules }) => Json(err(
            409,
            format!(
                "该用户仍拥有 {tunnels} 条被其他用户的 {rules} 条规则引用的预设隧道，请先解绑相关规则"
            ),
        )),
        Err(e) => {
            tracing::error!("delete_user {}: cascade delete failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

// === Update user (v0.3.4) ===
/// Admin edits a user's quota / balance / ban status. Deliberately cannot
/// change password, admin role, or id (see UpdateUserRequest doc).
pub async fn update_user(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Json<ApiResponse<()>> {
    // v1.0.7: device-group authorization (all_device_groups / device_group_ids)
    // is handled ALONGSIDE the other fields (not early-return, which would drop
    // any balance/quota/banned submitted in the same request). All fields
    // optional — if nothing provided, bail early.
    if req.balance.is_none()
        && req.max_rules.is_none()
        && req.traffic_limit.is_none()
        && req.banned.is_none()
        && req.suspended.is_none()
        && req.all_device_groups.is_none()
        && req.device_group_ids.is_none()
    {
        return Json(err(400, "无需要更新的字段"));
    }

    // Clamp numeric inputs to sane ranges (prevent overflow / absurd values).
    if let Some(mr) = req.max_rules {
        if !(0..=100_000).contains(&mr) {
            return Json(err(400, "max_rules 必须在 0 到 100000 之间"));
        }
    }
    if let Some(tl) = req.traffic_limit {
        if tl < 0 {
            return Json(err(400, "流量限制必须为非负数"));
        }
    }

    // v0.3.5: balance is still a TEXT column but admins can now edit it via
    // this endpoint. Validate the input shape strictly (non-negative decimal,
    // ≤ 2 fraction digits, ≤ 9999999999.99) and store the canonical form so
    // every row in the DB looks the same regardless of what the caller typed.
    // The check happens before we touch the SQL builder so a rejected value
    // never reaches the DB.
    let canonical_balance: Option<String> = match req.balance.as_deref() {
        None => None,
        Some(raw) => match relay_shared::money::parse_balance(raw) {
            Ok(c) => Some(c),
            Err(reason) => return Json(err(400, reason)),
        },
    };

    // Cannot ban or suspend an admin user (privilege protection). The role is
    // immutable through this endpoint; the transactional update below still
    // decides whether a missing target is a 404.
    if req.banned == Some(true) || req.suspended == Some(true) {
        let is_admin = match state.db.is_admin(id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("update_user {}: is_admin lookup failed: {}", id, e);
                return Json(err(500, "数据库错误"));
            }
        };
        if is_admin {
            return if req.banned == Some(true) {
                Json(err(400, "无法封禁管理员用户"))
            } else {
                Json(err(400, "无法暂停管理员用户"))
            };
        }
    }

    // Scalar fields, both authorization representations, and the consequent
    // rule pauses are one logical edit. Keeping them in one repository
    // transaction prevents a bad group id (or a later SQL failure) from
    // committing only the balance/quota or only half of the authorization.
    let outcome = match state
        .db
        .update_user_with_authorization(
            id,
            AdminUserUpdate {
                balance: canonical_balance.as_deref(),
                max_rules: req.max_rules,
                traffic_limit: req.traffic_limit,
                banned: req.banned,
                suspended: req.suspended,
                all_device_groups: req.all_device_groups,
                device_group_ids: req.device_group_ids.as_deref(),
            },
        )
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return Json(err(404, "用户不存在")),
        Err(DbError::ForeignKeyViolation | DbError::UserDeviceGroupInvalid) => {
            return Json(err(400, "设备分组列表只能包含管理员拥有的入站分组"));
        }
        Err(e) => {
            tracing::error!(
                "update_user {}: transactional user update failed: {}",
                id,
                e
            );
            return Json(err(500, "数据库错误"));
        }
    };

    if let Some(banned) = req.banned {
        tracing::warn!(
            action = if banned { "ban_user" } else { "unban_user" },
            target_user_id = id,
            actor_admin_id = _admin.user_id,
            "destructive admin op"
        );
    }
    if let Some(suspended) = req.suspended {
        tracing::warn!(
            action = if suspended {
                "suspend_user"
            } else {
                "unsuspend_user"
            },
            target_user_id = id,
            actor_admin_id = _admin.user_id,
            "admin op"
        );
    }
    if outcome.paused_rules > 0 {
        tracing::warn!(
            "update_user {}: paused {} rule(s) outside new authorization",
            id,
            outcome.paused_rules
        );
    }

    // A field update (ban) or an authorization change (pause) both alter what
    // nodes should forward, so refresh node config once at the end.
    state
        .node_connections
        .broadcast_all(r#"{"type":"config_changed"}"#)
        .await;
    Json(ApiResponse::success(()))
}

// === v1.0.7: per-user device-group authorization ===

/// A user's current device-group authorization, for preloading the admin
/// editor. `all_device_groups` short-circuits `device_group_ids` (when true the
/// user may use every group regardless of the explicit list).
#[derive(Debug, serde::Serialize)]
pub struct UserDeviceGroups {
    pub all_device_groups: bool,
    pub device_group_ids: Vec<i64>,
}

/// GET /users/{id}/device-groups — the explicit assignments + the all flag.
/// Updates go through PUT /users/{id} (update_user).
pub async fn get_user_device_groups(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<UserDeviceGroups>> {
    let all_device_groups =
        match crate::db::repo::UserRepository::find_by_id(state.db.as_ref(), id).await {
            Ok(Some(u)) => u.all_device_groups,
            Ok(None) => return Json(err(404, "用户不存在")),
            Err(e) => {
                tracing::error!("get_user_device_groups {}: find_by_id failed: {}", id, e);
                return Json(err(500, "数据库错误"));
            }
        };
    let device_group_ids = match state.db.list_user_device_groups(id).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!("get_user_device_groups {}: list failed: {}", id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    Json(ApiResponse::success(UserDeviceGroups {
        all_device_groups,
        device_group_ids,
    }))
}

// === v1.0.7: admin manages a user's plan ===

/// POST /admin/users/{id}/buy-plan — admin assigns a plan to a user, charging
/// the user's balance per the normal purchase rules (same atomic transaction as
/// the self-service shop). Unlike the shop, hidden plans ARE purchasable here
/// (an admin may grant an unlisted plan). Admin targets are rejected (a plan on
/// an admin account is meaningless).
pub async fn admin_buy_plan_for_user(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<AdminBuyPlanRequest>,
) -> Json<ApiResponse<()>> {
    if req.expected_current_plan_id < 0 {
        return Json(err(400, "expected_current_plan_id 不能为负数"));
    }
    let expected_current_plan_id = if req.expected_current_plan_id == 0 {
        None
    } else {
        Some(req.expected_current_plan_id)
    };

    // Target must exist and be a non-admin.
    match crate::db::repo::UserRepository::find_by_id(state.db.as_ref(), id).await {
        Ok(Some(u)) if u.admin => return Json(err(400, "无法给管理员用户分配套餐")),
        Ok(Some(_)) => {}
        Ok(None) => return Json(err(404, "用户不存在")),
        Err(e) => {
            tracing::error!("admin_buy_plan_for_user {}: find_by_id failed: {}", id, e);
            return Json(err(500, "数据库错误"));
        }
    }

    let plan = match state.db.find_plan_by_id(req.plan_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return Json(err(404, "套餐不存在")),
        Err(e) => {
            tracing::error!("admin_buy_plan_for_user: plan lookup failed: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };
    if let Some(expected_price) = req.expected_price.as_deref() {
        match relay_shared::money::parse_balance(expected_price) {
            Ok(expected) if expected == plan.price => {}
            Ok(_) => return Json(err(409, "套餐价格已变更，请刷新后重新确认")),
            Err(reason) => return Json(err(400, reason)),
        }
    }
    if plan.plan_type == "time" && plan.duration_days <= 0 {
        return Json(err(400, "该套餐无有效时长"));
    }

    let price_cents = match relay_shared::money::balance_to_cents(&plan.price) {
        Some(c) => c,
        None => {
            tracing::error!(
                "admin_buy_plan_for_user: plan {} has non-canonical price {:?}",
                plan.id,
                plan.price
            );
            return Json(err(500, "数据库错误"));
        }
    };

    let duration_days = if plan.plan_type == "time" {
        plan.duration_days
    } else {
        0
    };

    let device_group_ids = if plan.grant_all_groups {
        Vec::new()
    } else {
        match state.db.list_plan_device_groups(plan.id).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(
                    "admin_buy_plan_for_user: list_plan_device_groups failed: {}",
                    e
                );
                return Json(err(500, "数据库错误"));
            }
        }
    };
    if let Some(expected_revision) = req.expected_revision.as_deref() {
        if expected_revision != super::plans::purchase_revision(&plan, &device_group_ids) {
            return Json(err(409, "套餐内容已变更，请刷新后重新确认"));
        }
    }

    // Grant-all is evaluated inside the purchase transaction. Only per-group
    // plans need an explicit authorization set here.
    let new_authorized_group_ids = if plan.grant_all_groups {
        Vec::new()
    } else {
        device_group_ids.clone()
    };

    match state
        .db
        .buy_plan_guarded(
            id,
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
            false,
            Some(expected_current_plan_id),
        )
        .await
    {
        Ok(()) => {
            tracing::info!(
                action = "admin_buy_plan_for_user",
                target_user_id = id,
                actor_admin_id = _admin.user_id,
                plan_id = plan.id,
                "admin assigned plan to user"
            );
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(BuyPlanError::InsufficientBalance) => Json(err(400, "余额不足")),
        Err(BuyPlanError::PlanChanged) => Json(err(409, "套餐已变更，请刷新后重新确认")),
        Err(BuyPlanError::UserPlanChanged) => {
            Json(err(409, "用户当前套餐已变更，请刷新后重新确认"))
        }
        Err(BuyPlanError::QuotaOverflow) => Json(err(409, "累计流量额度超出系统上限")),
        Err(BuyPlanError::Database(e)) => {
            tracing::error!("admin_buy_plan_for_user {}: db error: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

/// PUT /admin/users/{id}/plan — admin edits a user's plan association + expiry
/// WITHOUT charging. Used to remove a plan (clear=true → both NULL) or adjust
/// the expiry (clear=false → keep the user's current plan_id, set the expiry,
/// where a null plan_expire_at means "never expires"). Admin targets are
/// rejected (admin_set_user_plan also guards WHERE admin=false).
pub async fn admin_set_user_plan(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<AdminSetUserPlanRequest>,
) -> Json<ApiResponse<()>> {
    if req.expected_plan_id <= 0 {
        return Json(err(400, "expected_plan_id 必须为正整数"));
    }
    if req.clear && req.plan_expire_at.is_some() {
        return Json(err(400, "移除套餐时不能同时设置到期时间"));
    }
    if let Some(expire) = req.plan_expire_at.as_deref() {
        let canonical = chrono::NaiveDateTime::parse_from_str(expire, "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|value| value.format("%Y-%m-%d %H:%M:%S").to_string());
        if canonical.as_deref() != Some(expire) {
            return Json(err(
                400,
                "到期时间必须为 YYYY-MM-DD HH:MM:SS 格式的有效 UTC 时间",
            ));
        }
    }

    match state
        .db
        .admin_edit_user_plan(
            id,
            req.expected_plan_id,
            req.clear,
            req.plan_expire_at.as_deref(),
        )
        .await
    {
        Ok(AdminUserPlanEditOutcome::Updated) => {}
        Ok(AdminUserPlanEditOutcome::NotFound) => return Json(err(404, "用户不存在")),
        Ok(AdminUserPlanEditOutcome::AdminTarget) => {
            return Json(err(400, "无法修改管理员用户的套餐"));
        }
        Ok(AdminUserPlanEditOutcome::PlanChanged) => {
            return Json(err(409, "用户套餐已变更，请刷新后重新确认"));
        }
        Ok(AdminUserPlanEditOutcome::ExpiryNotApplicable) => {
            return Json(err(400, "只有时长套餐可以设置到期时间"));
        }
        Err(e) => {
            tracing::error!(
                "admin_set_user_plan {}: transactional edit failed: {}",
                id,
                e
            );
            return Json(err(500, "数据库错误"));
        }
    }

    tracing::info!(
        action = "admin_set_user_plan",
        target_user_id = id,
        actor_admin_id = _admin.user_id,
        "admin edited user plan (clear={})",
        req.clear
    );
    // Expiry / authorization changes feed list_active_for_config — refresh nodes.
    state
        .node_connections
        .broadcast_all(r#"{"type":"config_changed"}"#)
        .await;
    Json(ApiResponse::success(()))
}
