// v0.4.3 PR1: SQLite implementation of the Repository traits.
//
// All SQL that was previously inline in handler files (admin.rs, node.rs,
// config.rs, stats.rs, auth.rs, middleware.rs, ws.rs) lives here now.
// Handlers call `state.db.method()` and never write SQL directly.
//
// The SQL itself is UNCHANGED from the v0.4.2 codebase — same SQLite dialect,
// same ? placeholders, same statements. This is a pure mechanical move,
// not a rewrite. PR2 will add PgRepository with PostgreSQL-native SQL.

use sqlx::SqlitePool;

mod announcements;
mod billing;
mod groups;
mod kvs;
mod orders;
mod profiles;
mod redeem;
mod rules;
mod settings;
mod stats;
#[cfg(test)]
mod tests;
mod traffic;
mod tunnels;
mod user_groups;
mod users;

pub struct SqliteRepository {
    pub(super) pool: SqlitePool,
}

impl SqliteRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

/// Caller holds the writer reservation. Keep oldest active rules and preserve
/// excess rules as auto-paused instead of deleting user work.
async fn enforce_rule_limit(
    conn: &mut sqlx::SqliteConnection,
    uid: i64,
) -> Result<u64, super::error::DbError> {
    Ok(sqlx::query(
        "UPDATE forward_rules SET paused=1, auto_paused=1 WHERE id IN (
        SELECT r.id FROM forward_rules r JOIN users u ON u.id=r.uid
        WHERE r.uid=? AND r.paused=0 AND u.admin=0 AND u.max_rules>0
        ORDER BY r.id LIMIT -1 OFFSET (SELECT max_rules FROM users WHERE id=?)
    )",
    )
    .bind(uid)
    .bind(uid)
    .execute(conn)
    .await?
    .rows_affected())
}

// ── Aggregate Repository ──
//
// The aggregate trait has no methods of its own — it just combines the domain
// traits. A blanket impl for any type satisfying all supertraits would work,
// but spelling it out keeps the impl block discoverable and avoids coherence
// surprises when PgRepository is added in PR2.
#[async_trait::async_trait]
impl super::repo::Repository for SqliteRepository {}
