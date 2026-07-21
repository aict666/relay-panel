use super::err;
use crate::api::middleware::{AdminOnly, AuthUser};
use crate::api::AppState;
use crate::service::tunnels::TunnelError;
use axum::extract::{Path, State};
use axum::Json;
use relay_shared::models::Tunnel;
use relay_shared::protocol::{ApiResponse, CreateTunnelRequest, UpdateTunnelRequest};
use serde::Serialize;

fn map_error<T: Serialize>(error: TunnelError) -> ApiResponse<T> {
    match error {
        TunnelError::NotFound => err(404, "隧道不存在"),
        TunnelError::EmptyName => err(400, "隧道名称不能为空"),
        TunnelError::NameConflict => err(409, "隧道名称已存在"),
        TunnelError::HopCount => err(400, "隧道路径必须包含 2–8 个设备组"),
        TunnelError::DuplicateGroup => err(400, "隧道路径中的设备组不能重复"),
        TunnelError::EntryPort => err(400, "入口 hop 不配置内部端口"),
        TunnelError::InvalidEntry => err(400, "入口设备组不存在或不支持入口"),
        TunnelError::InvalidHop => err(400, "中继/出口设备组不存在或不能用于转发"),
        TunnelError::MissingConnectHost => err(400, "中继/出口设备组必须配置连接地址"),
        TunnelError::InvalidPort => err(400, "隧道内部端口必须在 1–65535 之间"),
        TunnelError::PortConflict { group_id, port } if group_id != 0 => err(
            409,
            format!("设备组 {group_id} 的 TCP 端口 {port} 已被占用"),
        ),
        TunnelError::PortConflict { .. } => err(409, "隧道 TCP 端口已被并发占用，请重试"),
        TunnelError::PortPool(message) => err(409, message),
        TunnelError::ConcurrentUpdate => err(409, "隧道路径已被其他管理员修改，请刷新后重试"),
        TunnelError::EntryAuthorization { rules, users } => err(
            409,
            format!("修改入口会导致 {users} 个用户的 {rules} 条绑定规则失去入口授权"),
        ),
        TunnelError::InUse(count) => err(409, format!("该隧道正被 {count} 条规则使用")),
        TunnelError::Database(error) => {
            tracing::error!("tunnel database error: {}", error);
            err(500, "数据库错误")
        }
    }
}

/// Authenticated catalog. Regular users see only tunnels whose entry group is
/// in their effective authorization set. Internal dial addresses are removed.
pub async fn list_available_tunnels(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Tunnel>>> {
    let allowed = if user.admin {
        None
    } else {
        match state.db.authorized_device_group_ids(user.user_id).await {
            Ok(ids) => Some(ids),
            Err(error) => {
                tracing::error!("list_available_tunnels auth lookup: {}", error);
                return Json(err(500, "数据库错误"));
            }
        }
    };
    match state.db.list_tunnels().await {
        Ok(mut tunnels) => {
            if let Some(allowed) = allowed {
                let mut visible = Vec::new();
                for tunnel in tunnels {
                    if !tunnel.shared
                        || !tunnel
                            .hops
                            .first()
                            .is_some_and(|hop| allowed.contains(&hop.device_group_id))
                    {
                        continue;
                    }
                    // Historical rows may predate the administrator-managed
                    // group invariant. Do not advertise a preset that rule
                    // writes and runtime config will reject as unusable.
                    let mut valid = (2..=8).contains(&tunnel.hops.len());
                    for (position, hop) in tunnel.hops.iter().enumerate() {
                        let group = match crate::db::repo::GroupRepository::find_by_id(
                            state.db.as_ref(),
                            hop.device_group_id,
                            &crate::db::repo::ResourceScope::All,
                        )
                        .await
                        {
                            Ok(Some(group)) => group,
                            Ok(None) => {
                                valid = false;
                                break;
                            }
                            Err(error) => {
                                tracing::error!(
                                    "list_available_tunnels group lookup failed: {}",
                                    error
                                );
                                return Json(err(500, "数据库错误"));
                            }
                        };
                        let owner_is_admin = match state.db.is_admin(group.uid).await {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::error!(
                                    "list_available_tunnels owner lookup failed: {}",
                                    error
                                );
                                return Json(err(500, "数据库错误"));
                            }
                        };
                        valid &= owner_is_admin
                            && if position == 0 {
                                matches!(group.group_type.as_str(), "in" | "both")
                                    && hop.listen_port.is_none()
                            } else {
                                group.group_type != "monitor"
                                    && !group.connect_host.trim().is_empty()
                                    && hop.listen_port.is_some()
                            };
                        if !valid {
                            break;
                        }
                    }
                    if valid {
                        visible.push(tunnel);
                    }
                }
                tunnels = visible;
            }
            for tunnel in &mut tunnels {
                if !user.admin {
                    // The global binding count is operational inventory for
                    // administrators, not part of the user catalog. Exposing
                    // it lets one tenant infer other users' activity.
                    tunnel.bound_rule_count = 0;
                }
                for hop in &mut tunnel.hops {
                    hop.connect_host = None;
                    if !user.admin {
                        // Internal relay ports are operational infrastructure,
                        // not required to select a preset route.
                        hop.listen_port = None;
                    }
                }
            }
            Json(ApiResponse::success(tunnels))
        }
        Err(error) => {
            tracing::error!("list_available_tunnels: {}", error);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn list_admin_tunnels(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Tunnel>>> {
    match state.db.list_tunnels().await {
        Ok(tunnels) => Json(ApiResponse::success(tunnels)),
        Err(error) => {
            tracing::error!("list_admin_tunnels: {}", error);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn get_admin_tunnel(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<Tunnel>> {
    match state.db.find_tunnel_by_id(id).await {
        Ok(Some(tunnel)) => Json(ApiResponse::success(tunnel)),
        Ok(None) => Json(err(404, "隧道不存在")),
        Err(error) => {
            tracing::error!("get_admin_tunnel {id}: {error}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_tunnel(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateTunnelRequest>,
) -> Json<ApiResponse<Tunnel>> {
    match crate::service::tunnels::create_tunnel(state.db.as_ref(), admin.user_id, &req).await {
        Ok(tunnel) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(tunnel))
        }
        Err(error) => Json(map_error(error)),
    }
}

pub async fn update_tunnel(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateTunnelRequest>,
) -> Json<ApiResponse<Tunnel>> {
    let stages_route = req.hops.is_some();
    match crate::service::tunnels::update_tunnel(state.db.as_ref(), id, &req).await {
        Ok(tunnel) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            if stages_route {
                super::schedule_route_transition_activation(&state);
            }
            Json(ApiResponse::success(tunnel))
        }
        Err(error) => Json(map_error(error)),
    }
}

pub async fn delete_tunnel(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    match crate::service::tunnels::delete_tunnel(state.db.as_ref(), id).await {
        Ok(()) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(error) => Json(map_error(error)),
    }
}
