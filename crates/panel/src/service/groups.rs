//! Device group + rule deletion service.
//!
//! Extracted from `api/admin/{groups,rules}.rs`. Houses the group CRUD business
//! rules (admin-owned token generation, no-fields guard, 404-on-zero-rows) and
//! the rule deletion mutation. The handlers keep HTTP concerns + the
//! connection-manager side effects (`close_group` / `broadcast_all`) and audit
//! logging — those depend on `node_connections`, not the `Repository`.

use crate::db::error::DbError;
use crate::db::repo::ResourceScope;
use crate::db::Repository;
use crate::service::rules::group_type_to_str;
use relay_shared::models::{encode_blocked_protocols, BlockedProtocol, DeviceGroup};
use relay_shared::protocol::GroupType;

#[derive(Debug)]
pub enum CreateGroupError {
    InvalidName,
    InvalidBlockedProtocolsForGroupType,
    /// INSERT succeeded but the follow-up SELECT-by-token found nothing.
    FetchFailed,
    Database(DbError),
}

#[derive(Debug)]
pub enum UpdateGroupError {
    InvalidName,
    InvalidBlockedProtocolsForGroupType,
    NotFound,
    NoFields,
    TunnelInvariant {
        entry_tunnels: i64,
        downstream_tunnels: i64,
    },
    RuleInvariant {
        entry_rules: i64,
        downstream_rules: i64,
    },
    PlanInvariant {
        plans: i64,
    },
    Database(DbError),
}

#[derive(Debug, PartialEq, Eq)]
pub struct GroupUpdateOutcome {
    pub blocked_protocols_before: String,
    pub blocked_protocols_after: String,
}

/// v1.0.8: billing rate bounds. `rate` lives on device_groups; users are
/// charged real bytes × rate in `apply_traffic_batch`. 1.0 = bill what you
/// use. The same bounds are enforced inside `apply_traffic_batch` (a stray
/// out-of-range value refuses the whole traffic batch) — this is the
/// write-side guard so bad values never get persisted.
pub const RATE_MIN: f64 = 0.1;
pub const RATE_MAX: f64 = 100.0;
pub const RATE_DEFAULT: f64 = 1.0;

/// Validate a billing rate. Returns the clamped-or-passed value, or `None`
/// when the input is out of `[RATE_MIN, RATE_MAX]` (callers map None → 400).
pub fn validate_rate(rate: f64) -> Option<f64> {
    (RATE_MIN..=RATE_MAX).contains(&rate).then_some(rate)
}

/// Create an admin-owned device group. Generates a fresh token, inserts, then
/// returns the persisted row (INSERT-then-SELECT-by-token; the token is a
/// freshly generated UUID so the SELECT is guaranteed to hit the new row).
///
/// v0.4.12 PR1: device groups are admin-managed shared infrastructure — the
/// caller passes the creating admin's id as `owner_uid` (the handler ignores
/// any client-supplied owner_uid).
#[allow(clippy::too_many_arguments)]
pub async fn create_group(
    db: &dyn Repository,
    name: &str,
    group_type: &GroupType,
    owner_uid: i64,
    connect_host: &str,
    port_range: &str,
    rate: f64,
    hidden: bool,
    blocked_protocols: &[BlockedProtocol],
) -> Result<DeviceGroup, CreateGroupError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CreateGroupError::InvalidName);
    }
    let token = uuid::Uuid::new_v4().to_string();
    let group_type = group_type_to_str(group_type);
    if !blocked_protocols.is_empty() && !matches!(group_type, "in" | "both") {
        return Err(CreateGroupError::InvalidBlockedProtocolsForGroupType);
    }
    let blocked_protocols = encode_blocked_protocols(blocked_protocols);
    db.insert_group(
        name,
        group_type,
        &token,
        owner_uid,
        connect_host,
        port_range,
        rate,
        hidden,
        &blocked_protocols,
    )
    .await
    .map_err(CreateGroupError::Database)?;

    match db.find_by_token_after_insert(&token).await {
        Ok(Some(g)) => Ok(g),
        Ok(None) => Err(CreateGroupError::FetchFailed),
        Err(e) => Err(CreateGroupError::Database(e)),
    }
}

/// Rotate a device group's node token. Generates a fresh UUID and persists it.
/// Returns `Ok(Some(new_token))` when a row changed, `Ok(None)` when the group
/// didn't exist (the handler maps that to 404). The connection teardown
/// (`close_group`) + broadcast stay in the handler.
pub async fn rotate_group_token(db: &dyn Repository, id: i64) -> Result<Option<String>, DbError> {
    // v0.4.12 PR1: admin-only. Scope All — an admin operates on any group.
    let new_token = uuid::Uuid::new_v4().to_string();
    match db
        .update_group_token(id, &ResourceScope::All, &new_token)
        .await?
    {
        0 => Ok(None),
        _ => Ok(Some(new_token)),
    }
}

/// Update an admin-owned device group. Enforces the no-fields guard and
/// 404-on-zero-rows. The token is NOT updatable here (rotation is a separate
/// endpoint).
#[allow(clippy::too_many_arguments)]
pub async fn update_group(
    db: &dyn Repository,
    id: i64,
    name: Option<&str>,
    group_type: Option<&GroupType>,
    connect_host: Option<&str>,
    port_range: Option<&str>,
    rate: Option<f64>,
    hidden: Option<bool>,
    blocked_protocols: Option<&[BlockedProtocol]>,
) -> Result<GroupUpdateOutcome, UpdateGroupError> {
    if name.is_none()
        && group_type.is_none()
        && connect_host.is_none()
        && port_range.is_none()
        && rate.is_none()
        && hidden.is_none()
        && blocked_protocols.is_none()
    {
        return Err(UpdateGroupError::NoFields);
    }

    let name = match name {
        Some(name) => {
            let name = name.trim();
            if name.is_empty() {
                return Err(UpdateGroupError::InvalidName);
            }
            Some(name)
        }
        None => None,
    };

    // Canonicalize here; compatibility with the effective group type and
    // automatic clearing are enforced under the repository write lock.
    let blocked_protocols = blocked_protocols.map(encode_blocked_protocols);

    match db
        .update_group_fields(
            id,
            &ResourceScope::All,
            name,
            group_type.map(group_type_to_str),
            connect_host,
            port_range,
            rate,
            hidden,
            blocked_protocols.as_deref(),
        )
        .await
        .map_err(|error| match error {
            DbError::TunnelGroupInvariant {
                entry_tunnels,
                downstream_tunnels,
            } => UpdateGroupError::TunnelInvariant {
                entry_tunnels,
                downstream_tunnels,
            },
            DbError::RuleGroupInvariant {
                entry_rules,
                downstream_rules,
            } => UpdateGroupError::RuleInvariant {
                entry_rules,
                downstream_rules,
            },
            DbError::GroupPlanInvariant { plans } => UpdateGroupError::PlanInvariant { plans },
            DbError::GroupProtocolPolicyInvariant => {
                UpdateGroupError::InvalidBlockedProtocolsForGroupType
            }
            other => UpdateGroupError::Database(other),
        })? {
        result if result.rows_affected == 0 => Err(UpdateGroupError::NotFound),
        result => Ok(GroupUpdateOutcome {
            blocked_protocols_before: result
                .blocked_protocols_before
                .expect("updated group has a locked before-policy value"),
            blocked_protocols_after: result
                .blocked_protocols_after
                .expect("updated group has a committed after-policy value"),
        }),
    }
}

/// Error returned when a group cannot be deleted because rules or reusable
/// tunnel paths still reference it.
#[derive(Debug)]
pub struct GroupInUseError {
    pub group_id: i64,
    pub rule_count: i64,
    pub tunnel_count: i64,
    pub fallback_group_count: i64,
    pub plan_count: i64,
}

impl std::fmt::Display for GroupInUseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "group {} still referenced by {} rule(s), {} tunnel(s), {} fallback group(s), and {} plan(s)",
            self.group_id,
            self.rule_count,
            self.tunnel_count,
            self.fallback_group_count,
            self.plan_count
        )
    }
}

impl std::error::Error for GroupInUseError {}

/// Delete an admin-owned device group. Rule, tunnel and group-fallback
/// references are classified inside the same transaction as the DELETE.
pub async fn delete_group(
    db: &dyn Repository,
    id: i64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match db.delete_group_checked(id).await? {
        crate::db::repo::GroupDeleteOutcome::Deleted => Ok(true),
        crate::db::repo::GroupDeleteOutcome::NotFound => Ok(false),
        crate::db::repo::GroupDeleteOutcome::InUse {
            rule_count,
            tunnel_count,
            fallback_group_count,
            plan_count,
        } => Err(Box::new(GroupInUseError {
            group_id: id,
            rule_count,
            tunnel_count,
            fallback_group_count,
            plan_count,
        })),
    }
}

/// Delete a rule within `scope` (owner-scoped for regular users, All for
/// admins). Returns `Ok(true)` when a row was deleted, `Ok(false)` when nothing
/// matched (the handler maps that to 404 + no broadcast).
pub async fn delete_rule(
    db: &dyn Repository,
    id: i64,
    scope: &ResourceScope,
) -> Result<bool, DbError> {
    Ok(db.delete_rule(id, scope).await? > 0)
}
