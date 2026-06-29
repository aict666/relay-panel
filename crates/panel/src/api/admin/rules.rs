use super::err;
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::service::rules::{CreateRuleError, UpdateRuleError};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

/// Query params for list_rules (v0.4.20).
#[derive(serde::Deserialize, Default)]
pub struct ListRulesQuery {
    /// Admin-only: filter rules by owner. Non-admin is ignored.
    pub owner_uid: Option<i64>,
}

// === Forward Rules ===
pub async fn list_rules(
    user: AuthUser,
    Query(query): Query<ListRulesQuery>,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<ForwardRule>>> {
    // v0.4.20: admin can filter rules by owner_uid for user rule management.
    let scope = match (user.admin, query.owner_uid) {
        (true, Some(owner_uid)) => crate::db::repo::ResourceScope::Owner(owner_uid),
        _ => user.resource_scope(),
    };
    let rules: Vec<ForwardRule> = state.db.list_rules(&scope).await.unwrap_or_else(|e| {
        tracing::error!("list_rules: db error: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(rules))
}

pub async fn create_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Json<ApiResponse<()>> {
    // v1.0.4: non-admin users can only create rules on device groups they are authorized to use.
    if !user.admin && req.device_group_in != 0 {
        let allowed = state
            .db
            .authorized_device_group_ids(user.user_id)
            .await
            .unwrap_or_default();
        if !allowed.is_empty() && !allowed.contains(&req.device_group_in) {
            return Json(err(
                403,
                "device_group_in is not in your allowed device groups",
            ));
        }
    }
    match crate::service::rules::create_rule(state.db.as_ref(), user.user_id, user.admin, &req)
        .await
    {
        Ok(()) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(CreateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(CreateRuleError::PortConflict(port)) => Json(err(
            409,
            format!(
                "listen_port {} is already in use on this inbound group",
                port
            ),
        )),
        Err(CreateRuleError::Database(e)) => {
            tracing::error!("create_rule: service failed: {}", e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn update_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleRequest>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    // v1.0.4: non-admin users can only switch to device groups they are authorized for.
    if !user.admin {
        if let Some(dgi) = req.device_group_in {
            let allowed = state
                .db
                .authorized_device_group_ids(user.user_id)
                .await
                .unwrap_or_default();
            if !allowed.is_empty() && !allowed.contains(&dgi) {
                return Json(err(
                    403,
                    "device_group_in is not in your allowed device groups",
                ));
            }
        }
    }
    match crate::service::rules::update_rule(state.db.as_ref(), id, &scope, &req).await {
        Ok(()) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(UpdateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(UpdateRuleError::NotFound) => Json(err(404, "Rule not found")),
        Err(UpdateRuleError::PortConflict) => Json(err(
            409,
            "listen_port is already in use on this inbound group",
        )),
        Err(UpdateRuleError::Internal(msg)) => Json(err(500, msg)),
        Err(UpdateRuleError::Database(e)) => {
            tracing::error!("update_rule {}: service failed: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn delete_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    // v0.3.6: check rows_affected(). A non-existent rule previously returned
    // success AND broadcast config_changed — a no-op mutation that needlessly
    // triggered a node re-fetch. Now 404 + no broadcast when nothing was deleted.
    match crate::service::groups::delete_rule(state.db.as_ref(), id, &scope).await {
        // v0.3.6: nothing existed at that id. Return 404 and do NOT broadcast
        // config_changed — a no-op delete shouldn't trigger a node re-fetch.
        Ok(false) => Json(err(404, "Not found")),
        Ok(true) => {
            tracing::warn!(
                action = "delete_rule",
                rule_id = id,
                actor_id = user.user_id,
                actor_admin = user.admin,
                "destructive op"
            );
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("delete_rule {}: delete_rule failed: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}
