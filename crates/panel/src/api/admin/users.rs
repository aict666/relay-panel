use super::{err, UserPublic};
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::service::password::PasswordValidationError;
use crate::service::users::CreateUserError;
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::protocol::{ApiResponse, UpdateUserRequest};
// === Users ===
pub async fn list_users(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<UserPublic>>> {
    // SELECT * is safe here — UserPublic has no `password` field, so sqlx
    // simply ignores that column. The hash never reaches the API response.
    let users: Vec<UserPublic> = state.db.list_users_public().await.unwrap_or_else(|e| {
        tracing::error!("list_users: db error: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(users))
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
            Json(err(400, "Password must be at least 8 characters"))
        }
        Err(CreateUserError::Password(PasswordValidationError::TooLong)) => {
            Json(err(400, "Password must be at most 72 bytes"))
        }
        Err(CreateUserError::Hash(e)) => Json(err(500, format!("Failed to hash password: {}", e))),
        Err(CreateUserError::DuplicateUsername) => Json(err(409, "Username already exists")),
        Err(CreateUserError::DefaultPlanMissing) => {
            tracing::error!("create_user: default plan 1 is missing; no user created");
            Json(err(
                500,
                "Default plan is missing; contact an administrator",
            ))
        }
        Err(CreateUserError::Database(e)) => {
            tracing::error!("create_user: insert failed for {:?}: {}", req.username, e);
            Json(err(500, "database error"))
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
            return Json(err(500, "database error"));
        }
    };
    // Also need to confirm the row exists (is_admin returns false for both
    // "non-admin exists" and "doesn't exist" — distinguish via exists_by_id).
    let exists = match state.db.exists_by_id(id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("delete_user {}: exists lookup failed: {}", id, e);
            return Json(err(500, "database error"));
        }
    };
    if !exists || is_admin {
        return Json(err(
            404,
            "User not found (or is an admin and cannot be deleted)",
        ));
    }

    // Atomic cascade delete: removes the user's rules, tunnel_profiles and
    // device_groups, then the user row itself, all in ONE transaction with the
    // admin guard baked in. Returns 0 (and rolls back) if the target is an admin
    // or no longer exists — so we never leave a half-deleted account.
    match state.db.delete_user_cascade(id).await {
        Ok(0) => Json(err(
            404,
            "User not found (or is an admin and cannot be deleted)",
        )),
        Ok(_) => {
            tracing::warn!(
                action = "delete_user",
                target_user_id = id,
                actor_admin_id = _admin.user_id,
                "destructive admin op"
            );
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("delete_user {}: cascade delete failed: {}", id, e);
            Json(err(500, "database error"))
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
    // All fields optional — if nothing provided, bail early.
    if req.balance.is_none()
        && req.max_rules.is_none()
        && req.traffic_limit.is_none()
        && req.banned.is_none()
        && req.group_id.is_none()
    {
        return Json(err(400, "No fields to update"));
    }

    // Clamp numeric inputs to sane ranges (prevent overflow / absurd values).
    if let Some(mr) = req.max_rules {
        if !(0..=100_000).contains(&mr) {
            return Json(err(400, "max_rules must be between 0 and 100000"));
        }
    }
    if let Some(tl) = req.traffic_limit {
        if tl < 0 {
            return Json(err(400, "traffic_limit must be non-negative"));
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

    // Cannot ban an admin user (privilege protection).
    if req.banned == Some(true) {
        let is_admin = match state.db.is_admin(id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("update_user {}: is_admin lookup failed: {}", id, e);
                return Json(err(500, "database error"));
            }
        };
        if is_admin {
            return Json(err(400, "Cannot ban an admin user"));
        }
    }

    // Repository builds the dynamic UPDATE from the present fields.
    match state
        .db
        .update_user_fields(
            id,
            canonical_balance.as_deref(),
            req.max_rules,
            req.traffic_limit,
            req.banned,
        )
        .await
    {
        Ok(0) => Json(err(404, "User not found")),
        Ok(_) => {
            if let Some(banned) = req.banned {
                tracing::warn!(
                    action = if banned { "ban_user" } else { "unban_user" },
                    target_user_id = id,
                    actor_admin_id = _admin.user_id,
                    "destructive admin op"
                );
            }
            // If the user was banned/unbanned, nodes need a config refresh so
            // their rules stop/start forwarding (get_config filters banned).
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            // v1.0.4: handle group_id separately (simple single-field update).
            if let Some(gid) = req.group_id {
                if let Err(e) = state.db.set_user_group(id, Some(gid)).await {
                    tracing::error!("update_user {}: set_user_group failed: {}", id, e);
                }
            }
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("update_user {}: update_user_fields failed: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}
