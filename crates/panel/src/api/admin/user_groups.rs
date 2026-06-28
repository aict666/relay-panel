use super::err;
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CreateUserGroupRequest {
    pub name: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub allow_all_groups: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateUserGroupRequest {
    pub name: Option<String>,
    pub remark: Option<String>,
    pub allow_all_groups: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SetUserGroupDeviceGroupsRequest {
    pub device_group_ids: Vec<i64>,
}

// === User Group CRUD ===

pub async fn list_user_groups(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<UserGroup>>> {
    let groups = state.db.list_user_groups().await.unwrap_or_else(|e| {
        tracing::error!("list_user_groups: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(groups))
}

pub async fn get_user_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<UserGroup>> {
    match state.db.find_user_group_by_id(id).await {
        Ok(Some(g)) => Json(ApiResponse::success(g)),
        Ok(None) => Json(err(404, "Not found")),
        Err(e) => {
            tracing::error!("get_user_group {}: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn create_user_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateUserGroupRequest>,
) -> Json<ApiResponse<UserGroup>> {
    if req.name.trim().is_empty() {
        return Json(err(400, "name is required"));
    }
    match state
        .db
        .insert_user_group(&req.name, &req.remark, req.allow_all_groups)
        .await
    {
        Ok(id) => match state.db.find_user_group_by_id(id).await {
            Ok(Some(g)) => Json(ApiResponse::success(g)),
            _ => Json(err(500, "failed to read back created group")),
        },
        Err(e) => {
            tracing::error!("create_user_group: {}", e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn update_user_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserGroupRequest>,
) -> Json<ApiResponse<UserGroup>> {
    if let Some(ref n) = req.name {
        if n.trim().is_empty() {
            return Json(err(400, "name must not be empty"));
        }
    }
    match state
        .db
        .update_user_group(
            id,
            req.name.as_deref(),
            req.remark.as_deref(),
            req.allow_all_groups,
        )
        .await
    {
        Ok(0) => Json(err(404, "Not found")),
        Ok(_) => match state.db.find_user_group_by_id(id).await {
            Ok(Some(g)) => Json(ApiResponse::success(g)),
            _ => Json(err(500, "failed to read back updated group")),
        },
        Err(e) => {
            tracing::error!("update_user_group {}: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn delete_user_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let count = match state.db.count_users_in_group(id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("delete_user_group count {}: {}", id, e);
            return Json(err(500, "database error"));
        }
    };
    if count > 0 {
        return Json(err(
            409,
            format!("该权限组仍有 {} 个用户使用，请先迁移用户。", count),
        ));
    }
    match state.db.delete_user_group(id).await {
        Ok(0) => Json(err(404, "Not found")),
        Ok(_) => Json(ApiResponse::success(())),
        Err(e) => {
            tracing::error!("delete_user_group {}: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

// === Device Group Assignments ===

pub async fn get_user_group_device_groups(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<Vec<i64>>> {
    match state.db.list_user_group_device_groups(id).await {
        Ok(ids) => Json(ApiResponse::success(ids)),
        Err(e) => {
            tracing::error!("get_user_group_device_groups {}: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}

pub async fn set_user_group_device_groups(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SetUserGroupDeviceGroupsRequest>,
) -> Json<ApiResponse<()>> {
    match state
        .db
        .set_user_group_device_groups(id, &req.device_group_ids)
        .await
    {
        Ok(()) => Json(ApiResponse::success(())),
        Err(e) => {
            tracing::error!("set_user_group_device_groups {}: {}", id, e);
            Json(err(500, "database error"))
        }
    }
}
