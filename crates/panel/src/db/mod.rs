#[cfg(test)]
pub(crate) mod billing_contract;
pub mod error;
pub mod init;
pub mod pg_repo;
pub mod pg_schema;
pub mod repo;
pub mod schema;
pub mod sqlite_repo;

// Re-export the aggregate trait so callers can write `crate::db::Repository`
// instead of `crate::db::repo::Repository`. The domain traits are accessed via
// the aggregate (any `dyn Repository` exposes all of UserRepository /
// RuleRepository / ... methods). When a caller needs to disambiguate a method
// that exists on multiple traits (e.g. find_by_id is on both UserRepository
// and GroupRepository), it imports the specific trait from `crate::db::repo`.
pub use repo::Repository;
