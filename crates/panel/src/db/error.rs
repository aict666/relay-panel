// v0.4.3: Unified database error type.
//
// Hides the backend-specific error codes (SQLite 2067 vs PostgreSQL 23505 for
// UNIQUE violations) behind a single enum. Handlers match on DbError variants
// instead of raw error codes, so the same handler code works on both backends.
//
// The `Other` variant retains the underlying sqlx::Error for logging (via
// tracing::error!), but handlers MUST NOT return its stringified form to the
// API client — use a generic message instead (e.g. "database error") to avoid
// leaking schema/SQL details.

/// A unified database error that abstracts over SQLite and PostgreSQL error
/// codes. Every Repository method returns `Result<T, DbError>`.
#[derive(Debug)]
pub enum DbError {
    /// UNIQUE constraint violation. SQLite code "2067", PostgreSQL "23505".
    UniqueViolation,
    /// v0.4.11 PR4: a listen_port is already occupied on the rule's inbound
    /// group by a conflicting socket type (TCP vs UDP). Distinct from
    /// `UniqueViolation` so handlers can return a clear, port-specific 409.
    /// Detected by the in-transaction conflict pre-check; the partial unique
    /// indexes on forward_rules are the DB-layer backstop.
    PortConflict,
    /// A tunnel entry replacement would strand bound rules whose ordinary
    /// owners are not authorized for the new inbound group. Computed inside
    /// the same write transaction as the path replacement.
    TunnelEntryAuthorization { rules: i64, users: i64 },
    /// A preset tunnel disappeared, was disabled while a rule was being
    /// attached, or its entry/exit changed after service-layer validation.
    /// Rechecked inside the rule write transaction to close the TOCTOU gap.
    TunnelUnavailable,
    /// The preset tunnel still exists and its path is unchanged, but the rule
    /// owner is not allowed to bind/resume it (not shared, or hop 0 is outside
    /// the owner's effective device-group authorization). Checked in the same
    /// transaction as the rule write to close the sharing-toggle race.
    TunnelAccessDenied,
    /// A device-group edit would invalidate one or more preset-tunnel hops.
    /// Checked in the same write transaction as the group update.
    TunnelGroupInvariant {
        entry_tunnels: i64,
        downstream_tunnels: i64,
    },
    /// Deleting a regular user would also delete one or more legacy
    /// user-owned device groups that are now part of administrator tunnels.
    UserTunnelGroupConflict { groups: i64, tunnels: i64 },
    /// FOREIGN KEY constraint violation. SQLite code "787", PostgreSQL "23503".
    ForeignKeyViolation,
    /// A required row was not found (for fetch_one-or-None patterns that are
    /// expected to succeed).
    NotFound,
    /// Any other database error. The inner sqlx::Error is retained for
    /// logging but should NOT be serialized into an API response.
    Other(sqlx::Error),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::UniqueViolation => write!(f, "unique constraint violation"),
            DbError::PortConflict => write!(f, "listen_port conflict on inbound group"),
            DbError::TunnelEntryAuthorization { rules, users } => write!(
                f,
                "tunnel entry authorization conflict ({rules} rules, {users} users)"
            ),
            DbError::TunnelUnavailable => write!(f, "preset tunnel is unavailable or changed"),
            DbError::TunnelAccessDenied => write!(f, "preset tunnel access denied"),
            DbError::TunnelGroupInvariant {
                entry_tunnels,
                downstream_tunnels,
            } => write!(
                f,
                "device-group edit would invalidate preset tunnels ({entry_tunnels} entry, {downstream_tunnels} downstream)"
            ),
            DbError::UserTunnelGroupConflict { groups, tunnels } => write!(
                f,
                "user owns {groups} device groups referenced by {tunnels} preset tunnels"
            ),
            DbError::ForeignKeyViolation => write!(f, "foreign key constraint violation"),
            DbError::NotFound => write!(f, "not found"),
            DbError::Other(e) => write!(f, "database error: {}", e),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DbError::Other(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for DbError {
    /// Map a raw sqlx::Error to a DbError by inspecting the database error code.
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db_err) = &e {
            match db_err.code().as_deref() {
                // SQLite SQLITE_CONSTRAINT_UNIQUE
                Some("2067") => return DbError::UniqueViolation,
                // PostgreSQL SQLSTATE 23505 (unique_violation)
                Some("23505") => return DbError::UniqueViolation,
                // SQLite SQLITE_CONSTRAINT_FOREIGNKEY
                Some("787") => return DbError::ForeignKeyViolation,
                // PostgreSQL SQLSTATE 23503 (foreign_key_violation)
                Some("23503") => return DbError::ForeignKeyViolation,
                // PostgreSQL SERIALIZABLE transaction lost a race. Preset
                // tunnel path updates are the only serializable repository
                // operation; surface this as a refresh/retry conflict instead
                // of a generic 500.
                Some("40001") => return DbError::TunnelUnavailable,
                _ => {}
            }
        }
        // RowNotFound → NotFound
        if matches!(e, sqlx::Error::RowNotFound) {
            return DbError::NotFound;
        }
        DbError::Other(e)
    }
}
