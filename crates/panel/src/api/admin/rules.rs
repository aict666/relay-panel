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
    match state.db.list_rules(&scope).await {
        Ok(rules) => Json(ApiResponse::success(rules)),
        Err(e) => {
            tracing::error!("list_rules: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Json<ApiResponse<()>> {
    let tunnel_entry = if let Some(tunnel_id) = req.tunnel_id {
        match state.db.find_tunnel_by_id(tunnel_id).await {
            Ok(Some(tunnel)) => tunnel.hops.first().map(|hop| hop.device_group_id),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("create_rule: tunnel lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        }
    } else {
        None
    };
    // A regular user's custom chain may use only groups in their effective
    // authorization set at EVERY position. Preset tunnels are different: an
    // administrator explicitly owns/shares their internal topology, so only
    // the preset entry is checked here.
    if !user.admin {
        let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("create_rule: authz lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        };
        let requested_groups: Vec<i64> = if req.tunnel_id.is_some() {
            vec![tunnel_entry.unwrap_or(req.device_group_in)]
        } else if let Some(hops) = req.hops.as_ref().filter(|hops| !hops.is_empty()) {
            hops.clone()
        } else {
            vec![req.device_group_in]
        };
        if requested_groups.iter().any(|gid| !allowed.contains(gid)) {
            return Json(err(403, "规则包含未授权的设备分组"));
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
        Err(CreateRuleError::Forbidden(msg)) => Json(err(403, msg)),
        Err(CreateRuleError::PortConflict(port)) => Json(err(
            409,
            format!("监听端口 {} 在此入口分组上已被占用", port),
        )),
        Err(CreateRuleError::Database(e)) => {
            tracing::error!("create_rule: service failed: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn update_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleRequest>,
) -> Json<ApiResponse<()>> {
    let stages_route = req.protocol.is_some()
        || req.device_group_in.is_some()
        || req.device_group_out.is_some()
        || req.route_mode.is_some()
        || req.hops.is_some()
        || req.tunnel_id.is_some();
    let scope = user.resource_scope();
    // Resolve the actual entry group exactly as the service layer does.  A
    // chain update derives its entry from hops[0], so authorizing only the
    // optional device_group_in field would let a restricted user smuggle an
    // unauthorized group through `hops`.
    let tunnel_entry = if let Some(Some(tunnel_id)) = req.tunnel_id {
        match state.db.find_tunnel_by_id(tunnel_id).await {
            Ok(Some(tunnel)) => tunnel.hops.first().map(|hop| hop.device_group_id),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("update_rule: tunnel lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        }
    } else {
        None
    };
    let hops_entry = req.hops.as_ref().and_then(|hops| hops.first().copied());
    if let (Some(device_group_in), Some(hops_entry)) = (req.device_group_in, hops_entry) {
        if device_group_in != hops_entry {
            return Json(err(
                400,
                "device_group_in must equal hops[0] (entry group) for chain rules",
            ));
        }
    }
    let requested_entry_group = tunnel_entry.or(hops_entry).or(req.device_group_in);

    // Custom hops are caller-controlled, so every position is authorized.
    // A shared preset tunnel remains entry-authorized because its downstream
    // topology is administrator-controlled.
    if !user.admin {
        let requested_groups: Vec<i64> = if matches!(req.tunnel_id, Some(Some(_))) {
            requested_entry_group.into_iter().collect()
        } else if let Some(hops) = req.hops.as_ref().filter(|hops| !hops.is_empty()) {
            hops.clone()
        } else {
            requested_entry_group.into_iter().collect()
        };
        if !requested_groups.is_empty() {
            let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("update_rule: authz lookup failed: {}", e);
                    return Json(err(500, "数据库错误"));
                }
            };
            if requested_groups.iter().any(|gid| !allowed.contains(gid)) {
                return Json(err(403, "规则包含未授权的设备分组"));
            }
        }
    }
    // v1.0.7: resuming a rule (paused → false) is ALSO gated on authorization.
    // A restricted user whose plan was removed has their rules auto-paused; they
    // must not be able to re-enable a rule pointing at a now-unauthorized group
    // by sending only {paused:false} — the device_group_in check above is
    // skipped when that field is absent. Only needed when not switching groups
    // in the same request (that path is already covered above).
    if !user.admin && req.paused == Some(false) && requested_entry_group.is_none() {
        match state.db.find_rule_by_id(id, &scope).await {
            Ok(Some(rule)) => {
                let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("update_rule: authz lookup failed: {}", e);
                        return Json(err(500, "数据库错误"));
                    }
                };
                let mut group_ids = vec![rule.device_group_in];
                if rule.route_mode == "chain" && rule.tunnel_id.is_none() {
                    match state.db.list_rule_hops(rule.id).await {
                        Ok(hops) => {
                            group_ids.extend(hops.into_iter().map(|hop| hop.device_group_id))
                        }
                        Err(e) => {
                            tracing::error!("update_rule: hop lookup failed: {}", e);
                            return Json(err(500, "数据库错误"));
                        }
                    }
                }
                if group_ids.iter().any(|gid| !allowed.contains(gid)) {
                    return Json(err(403, "无法启动包含未授权设备分组的规则"));
                }
            }
            Ok(None) => return Json(err(404, "规则不存在")),
            Err(e) => {
                tracing::error!("update_rule: rule lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        }
    }
    match crate::service::rules::update_rule(state.db.as_ref(), id, &scope, &req).await {
        Ok(()) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            if stages_route {
                super::schedule_route_transition_activation(&state);
            }
            Json(ApiResponse::success(()))
        }
        Err(UpdateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(UpdateRuleError::Forbidden(msg)) => Json(err(403, msg)),
        Err(UpdateRuleError::NotFound) => Json(err(404, "规则不存在")),
        Err(UpdateRuleError::PortConflict) => Json(err(409, "监听端口在此入口分组上已被占用")),
        Err(UpdateRuleError::Internal(msg)) => {
            tracing::error!("update_rule {}: internal error: {}", id, msg);
            Json(err(500, "服务器内部错误"))
        }
        Err(UpdateRuleError::Database(e)) => {
            tracing::error!("update_rule {}: service failed: {}", id, e);
            Json(err(500, "数据库错误"))
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
        Ok(false) => Json(err(404, "规则不存在")),
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
            Json(err(500, "数据库错误"))
        }
    }
}
