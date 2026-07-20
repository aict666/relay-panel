//! Administrator-managed reusable route tunnels.

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use crate::service::rules::{auto_assign_port, group_type_supports_inbound};
use relay_shared::models::{Tunnel, TunnelHop};
use relay_shared::protocol::{CreateTunnelRequest, TunnelHopRequest, UpdateTunnelRequest};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub enum TunnelError {
    NotFound,
    EmptyName,
    NameConflict,
    HopCount,
    DuplicateGroup,
    EntryPort,
    InvalidEntry,
    InvalidHop,
    MissingConnectHost,
    InvalidPort,
    PortConflict { group_id: i64, port: u16 },
    PortPool(String),
    ConcurrentUpdate,
    EntryAuthorization { rules: usize, users: usize },
    InUse(usize),
    Database(DbError),
}

fn map_db_error(error: DbError) -> TunnelError {
    match error {
        DbError::UniqueViolation => TunnelError::NameConflict,
        DbError::PortConflict => TunnelError::PortConflict {
            group_id: 0,
            port: 0,
        },
        DbError::TunnelUnavailable => TunnelError::ConcurrentUpdate,
        DbError::TunnelEntryAuthorization { rules, users } => TunnelError::EntryAuthorization {
            rules: rules as usize,
            users: users as usize,
        },
        other => TunnelError::Database(other),
    }
}

/// Reusing a shared listener port is safe only when both its incoming identity
/// and its complete downstream route are unchanged. Otherwise phase-one
/// pre-warming would mutate the old path in place instead of building a
/// parallel new path, recreating the very switch-order outage it prevents.
fn can_reuse_hop_port(
    old_hops: &[TunnelHop],
    requested: &[TunnelHopRequest],
    position: usize,
) -> bool {
    let Some(old_position) = old_hops
        .iter()
        .position(|old| old.device_group_id == requested[position].device_group_id)
    else {
        return false;
    };
    let suffix_unchanged = old_hops.len() == requested.len()
        && old_hops[position..]
            .iter()
            .zip(&requested[position..])
            .all(|(old, new)| {
                old.device_group_id == new.device_group_id
                    && new
                        .listen_port
                        .is_none_or(|port| old.listen_port == Some(i32::from(port)))
            });
    old_position == position
        && position > 0
        && old_hops[old_position - 1].device_group_id == requested[position - 1].device_group_id
        && suffix_unchanged
}

async fn resolve_hops(
    db: &dyn Repository,
    requested: &[TunnelHopRequest],
    old_hops: &[TunnelHop],
) -> Result<Vec<(i64, Option<i32>)>, TunnelError> {
    if !(2..=8).contains(&requested.len()) {
        return Err(TunnelError::HopCount);
    }
    let mut seen = HashSet::new();
    let old_ports: HashMap<i64, Option<i32>> = old_hops
        .iter()
        .map(|hop| (hop.device_group_id, hop.listen_port))
        .collect();
    let mut resolved = Vec::with_capacity(requested.len());

    for (position, hop) in requested.iter().enumerate() {
        if !seen.insert(hop.device_group_id) {
            return Err(TunnelError::DuplicateGroup);
        }
        let group = GroupRepository::find_by_id(db, hop.device_group_id, &ResourceScope::All)
            .await
            .map_err(TunnelError::Database)?
            .ok_or(if position == 0 {
                TunnelError::InvalidEntry
            } else {
                TunnelError::InvalidHop
            })?;

        if position == 0 {
            if hop.listen_port.is_some() {
                return Err(TunnelError::EntryPort);
            }
            if !group_type_supports_inbound(&group.group_type) {
                return Err(TunnelError::InvalidEntry);
            }
            resolved.push((group.id, None));
            continue;
        }
        if group.group_type == "monitor" {
            return Err(TunnelError::InvalidHop);
        }
        if group.connect_host.trim().is_empty() {
            return Err(TunnelError::MissingConnectHost);
        }

        let safe_old_port = can_reuse_hop_port(old_hops, requested, position)
            .then(|| old_ports.get(&group.id).copied().flatten())
            .flatten();
        let port = if let Some(port) = hop.listen_port {
            if port == 0 {
                return Err(TunnelError::InvalidPort);
            }
            // The edit form sends the persisted port back even when the user
            // did not explicitly pin it. If the incoming link changed, choose
            // a fresh port automatically so old/new HMAC contexts can coexist.
            if old_ports.get(&group.id).copied().flatten() == Some(i32::from(port))
                && safe_old_port.is_none()
            {
                auto_assign_port(db, group.id, "tcp")
                    .await
                    .map_err(TunnelError::PortPool)?
            } else {
                let conflicts = db
                    .list_group_port_protocols(group.id)
                    .await
                    .map_err(TunnelError::Database)?
                    .into_iter()
                    .any(|(used, protocol)| {
                        used == i32::from(port)
                            && matches!(protocol.as_str(), "tcp" | "tcp_udp")
                            && safe_old_port != Some(used)
                    });
                if conflicts {
                    return Err(TunnelError::PortConflict {
                        group_id: group.id,
                        port,
                    });
                }
                port
            }
        } else if let Some(old) = safe_old_port {
            old as u16
        } else {
            auto_assign_port(db, group.id, "tcp")
                .await
                .map_err(TunnelError::PortPool)?
        };
        resolved.push((group.id, Some(i32::from(port))));
    }
    Ok(resolved)
}

pub async fn create_tunnel(
    db: &dyn Repository,
    uid: i64,
    req: &CreateTunnelRequest,
) -> Result<Tunnel, TunnelError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(TunnelError::EmptyName);
    }
    let has_auto_port = req.hops.iter().skip(1).any(|hop| hop.listen_port.is_none());
    let mut attempts = 0;
    let id = loop {
        let hops = resolve_hops(db, &req.hops, &[]).await?;
        match db
            .create_tunnel_full(name, req.enabled, req.shared, uid, &hops)
            .await
        {
            Ok(id) => break id,
            Err(DbError::PortConflict) if has_auto_port && attempts < 7 => {
                attempts += 1;
                // Another writer claimed our candidate after the optimistic
                // pool scan. Re-scan and let the write transaction validate a
                // new port; duplicates can never commit.
                continue;
            }
            Err(error) => return Err(map_db_error(error)),
        }
    };
    db.find_tunnel_by_id(id)
        .await
        .map_err(TunnelError::Database)?
        .ok_or(TunnelError::NotFound)
}

pub async fn update_tunnel(
    db: &dyn Repository,
    id: i64,
    req: &UpdateTunnelRequest,
) -> Result<Tunnel, TunnelError> {
    let current = db
        .find_tunnel_by_id(id)
        .await
        .map_err(TunnelError::Database)?
        .ok_or(TunnelError::NotFound)?;
    let name = req.name.as_deref().map(str::trim);
    if name.is_some_and(str::is_empty) {
        return Err(TunnelError::EmptyName);
    }
    let expected_hops: Vec<(i64, Option<i32>)> = match (&req.hops, &req.expected_hops) {
        (Some(_), Some(expected)) => expected
            .iter()
            .map(|hop| (hop.device_group_id, hop.listen_port.map(i32::from)))
            .collect(),
        // A full path replacement without the snapshot cannot distinguish a
        // deliberate edit from a stale form. Reject it before resolving auto
        // ports; scalar-only partial updates remain backward compatible.
        (Some(_), None) => return Err(TunnelError::ConcurrentUpdate),
        (None, _) => Vec::new(),
    };
    let mut hops = if let Some(requested) = &req.hops {
        resolve_hops(db, requested, &current.hops).await?
    } else {
        Vec::new()
    };

    let has_new_auto_port = req.hops.as_ref().is_some_and(|requested| {
        requested.iter().enumerate().skip(1).any(|(position, hop)| {
            hop.listen_port.is_none() && !can_reuse_hop_port(&current.hops, requested, position)
                || hop.listen_port.is_some()
                    && !can_reuse_hop_port(&current.hops, requested, position)
                    && current.hops.iter().any(|old| {
                        old.device_group_id == hop.device_group_id
                            && old.listen_port.map(|port| port as u16) == hop.listen_port
                    })
        })
    });
    let mut attempts = 0;
    let rows = loop {
        match db
            .update_tunnel_full(
                id,
                name,
                req.enabled,
                req.shared,
                req.hops.as_ref().map(|_| hops.as_slice()),
                req.hops.as_ref().map(|_| expected_hops.as_slice()),
            )
            .await
        {
            Ok(rows) => break rows,
            Err(DbError::PortConflict) if has_new_auto_port && attempts < 7 => {
                attempts += 1;
                hops = resolve_hops(db, req.hops.as_ref().unwrap(), &current.hops).await?;
            }
            Err(error) => return Err(map_db_error(error)),
        }
    };
    if rows == 0 {
        return Err(TunnelError::NotFound);
    }
    db.find_tunnel_by_id(id)
        .await
        .map_err(TunnelError::Database)?
        .ok_or(TunnelError::NotFound)
}

pub async fn delete_tunnel(db: &dyn Repository, id: i64) -> Result<(), TunnelError> {
    match db.delete_tunnel(id).await.map_err(map_db_error)? {
        crate::db::repo::TunnelDeleteOutcome::Deleted => Ok(()),
        crate::db::repo::TunnelDeleteOutcome::NotFound => Err(TunnelError::NotFound),
        crate::db::repo::TunnelDeleteOutcome::InUse(count) => {
            Err(TunnelError::InUse(count as usize))
        }
    }
}
