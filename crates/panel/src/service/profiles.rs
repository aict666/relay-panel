//! Tunnel profile service.
//!
//! Extracted from `api/admin/profiles.rs`. Houses the profile validation +
//! mutation business rules (name/transport normalization + whitelist, builtin
//! read-only guard, transport-change compatibility with bound rules, delete
//! protection by usage count). The handler keeps only HTTP concerns + the
//! user-facing (Chinese) error text, mapping each error variant to a message.

use crate::db::error::DbError;
use crate::db::repo::{ProfileDeleteOutcome, ProfileUpdateOutcome};
use crate::db::Repository;
use relay_shared::models::TunnelProfile;

/// Normalize a profile transport value. `"tls"` is an accepted alias for
/// `"tls_simple"`; everything else is passed through unchanged (the caller then
/// validates it against the whitelist).
pub fn normalize_transport(transport: &str) -> String {
    if transport == "tls" {
        "tls_simple".to_string()
    } else {
        transport.to_string()
    }
}

/// v0.4.11 PR1: the only transports a tunnel template may store. "direct" is no
/// longer a tunnel template concept.
pub fn is_valid_transport(transport: &str) -> bool {
    matches!(transport, "ws" | "tls_simple")
}

#[derive(Debug)]
pub enum CreateProfileError {
    EmptyName,
    DuplicateName,
    InvalidTransport,
    /// INSERT succeeded but the follow-up SELECT-by-name found nothing.
    FetchFailed,
    Database(DbError),
}

#[derive(Debug)]
pub enum UpdateProfileError {
    NotFound,
    BuiltinReadOnly,
    EmptyName,
    DuplicateName,
    InvalidTransport,
    /// A transport change would break `count` already-bound rules; `sample`
    /// is one stored protocol/public-transport pair.
    TransportConflict {
        count: usize,
        sample: String,
    },
    NoFields,
    Database(DbError),
}

#[derive(Debug)]
pub enum DeleteProfileError {
    NotFound,
    BuiltinReadOnly,
    /// Still referenced by `count` rules; cannot delete until they're rebound.
    InUse(usize),
    Database(DbError),
}

/// Create a custom tunnel profile owned by `uid`. Validates the name (trimmed,
/// non-empty) and transport (normalized + whitelisted), inserts, then returns
/// the persisted row (INSERT-then-SELECT-by-name; name is UNIQUE).
#[allow(clippy::too_many_arguments)]
pub async fn create_profile(
    db: &dyn Repository,
    name: &str,
    transport: &str,
    tls_mode: &str,
    ws_path: &str,
    host_header: &str,
    sni: &str,
    uid: i64,
) -> Result<TunnelProfile, CreateProfileError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CreateProfileError::EmptyName);
    }
    let transport = normalize_transport(transport);
    if !is_valid_transport(&transport) {
        return Err(CreateProfileError::InvalidTransport);
    }

    match db
        .insert_profile(name, &transport, tls_mode, ws_path, host_header, sni, uid)
        .await
    {
        Ok(()) => {}
        Err(DbError::UniqueViolation) => return Err(CreateProfileError::DuplicateName),
        Err(error) => return Err(CreateProfileError::Database(error)),
    }

    // INSERT-then-SELECT-by-name: name has a UNIQUE constraint so this hits the
    // just-inserted row.
    match db.find_by_name(name).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(CreateProfileError::FetchFailed),
        Err(e) => Err(CreateProfileError::Database(e)),
    }
}

/// Update a custom tunnel profile. Enforces the builtin read-only guard, the
/// transport whitelist, and (on a transport change) compatibility with every
/// rule already bound to the profile. Returns `NoFields` when nothing is set.
#[allow(clippy::too_many_arguments)]
pub async fn update_profile(
    db: &dyn Repository,
    id: i64,
    name: Option<&str>,
    transport: Option<&str>,
    tls_mode: Option<&str>,
    ws_path: Option<&str>,
    host_header: Option<&str>,
    sni: Option<&str>,
) -> Result<(), UpdateProfileError> {
    let canonical_name = name.map(str::trim);
    if canonical_name.is_some_and(str::is_empty) {
        return Err(UpdateProfileError::EmptyName);
    }

    // Normalize + validate transport if provided. Bound-rule compatibility is
    // checked under the profile write lock in the repository.
    let normalized_transport = transport.map(normalize_transport);
    if let Some(ref t) = normalized_transport {
        if !is_valid_transport(t) {
            return Err(UpdateProfileError::InvalidTransport);
        }
    }

    if name.is_none()
        && transport.is_none()
        && tls_mode.is_none()
        && ws_path.is_none()
        && host_header.is_none()
        && sni.is_none()
    {
        return Err(UpdateProfileError::NoFields);
    }

    match db
        .update_profile_checked(
            id,
            canonical_name,
            normalized_transport.as_deref(),
            tls_mode,
            ws_path,
            host_header,
            sni,
        )
        .await
    {
        Ok(ProfileUpdateOutcome::Updated) => Ok(()),
        Ok(ProfileUpdateOutcome::NotFound) => Err(UpdateProfileError::NotFound),
        Ok(ProfileUpdateOutcome::BuiltinReadOnly) => Err(UpdateProfileError::BuiltinReadOnly),
        Ok(ProfileUpdateOutcome::BindingConflict { count, sample }) => {
            Err(UpdateProfileError::TransportConflict {
                count: count as usize,
                sample,
            })
        }
        Err(DbError::UniqueViolation) => Err(UpdateProfileError::DuplicateName),
        Err(error) => Err(UpdateProfileError::Database(error)),
    }
}

/// Delete a custom tunnel profile. Enforces the builtin read-only guard and
/// refuses to delete a profile still referenced by rules (the FK has no
/// ON DELETE clause, so a raw delete would fail anyway — we surface a friendly
/// count instead).
pub async fn delete_profile(db: &dyn Repository, id: i64) -> Result<(), DeleteProfileError> {
    match db.delete_profile_checked(id).await {
        Ok(ProfileDeleteOutcome::Deleted) => Ok(()),
        Ok(ProfileDeleteOutcome::NotFound) => Err(DeleteProfileError::NotFound),
        Ok(ProfileDeleteOutcome::BuiltinReadOnly) => Err(DeleteProfileError::BuiltinReadOnly),
        Ok(ProfileDeleteOutcome::InUse { rules }) => Err(DeleteProfileError::InUse(rules as usize)),
        Err(error) => Err(DeleteProfileError::Database(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_normalization_and_whitelist() {
        assert_eq!(normalize_transport("tls"), "tls_simple");
        assert_eq!(normalize_transport("ws"), "ws");
        assert_eq!(normalize_transport("tls_simple"), "tls_simple");
        assert_eq!(normalize_transport("raw"), "raw");

        assert!(is_valid_transport("ws"));
        assert!(is_valid_transport("tls_simple"));
        assert!(!is_valid_transport("raw"));
        assert!(!is_valid_transport("direct"));
        assert!(!is_valid_transport("wss"));
    }
}
