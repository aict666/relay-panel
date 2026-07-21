use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::TunnelProfile;

// ── TunnelProfileRepository ──

#[async_trait]
impl TunnelProfileRepository for SqliteRepository {
    async fn list_profiles(&self, scope: &ProfileScope) -> Result<Vec<TunnelProfile>, DbError> {
        let profiles: Vec<TunnelProfile> = match scope {
            ProfileScope::All => sqlx::query_as("SELECT * FROM tunnel_profiles ORDER BY id"),
            // v0.4.11 PR1: available templates for rule selection = ws/tls_simple,
            // builtin + admin-created custom. Excludes direct profiles.
            ProfileScope::AvailableTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE transport IN ('ws', 'tls_simple')
                     ORDER BY id",
            ),
            // v0.4.11 PR1: manageable custom templates = is_builtin=false, ws/tls_simple.
            // Used by admin management page.
            ProfileScope::ManageableCustomTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE is_builtin = 0 AND transport IN ('ws', 'tls_simple')
                     ORDER BY id",
            ),
        }
        .fetch_all(&self.pool)
        .await?;
        Ok(profiles)
    }

    async fn find_builtin_flag_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<bool>, DbError> {
        // Read-only guard for builtin profiles (seeded by Migration 6). The
        // caller translates Some(true) → 400 "cannot edit builtin", None → 404.
        let row: Option<(bool,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT is_builtin FROM tunnel_profiles WHERE id = ?").bind(id),
            Some(uid) => {
                sqlx::query_as("SELECT is_builtin FROM tunnel_profiles WHERE id = ? AND uid = ?")
                    .bind(id)
                    .bind(uid)
            }
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(b,)| b))
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<TunnelProfile>, DbError> {
        // Used by INSERT-then-SELECT-by-name to return the freshly created row
        // to the caller. Name is unique (UNIQUE constraint in the schema).
        let profile: Option<TunnelProfile> =
            sqlx::query_as("SELECT * FROM tunnel_profiles WHERE name = ?")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        Ok(profile)
    }

    async fn find_profile_by_id(
        &self,
        id: i64,
        scope: &ProfileScope,
    ) -> Result<Option<TunnelProfile>, DbError> {
        let profile: Option<TunnelProfile> = match scope {
            ProfileScope::All => {
                sqlx::query_as("SELECT * FROM tunnel_profiles WHERE id = ?").bind(id)
            }
            // v0.4.11 PR1: available templates for rule selection = ws/tls_simple.
            ProfileScope::AvailableTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE id = ? AND transport IN ('ws', 'tls_simple')",
            )
            .bind(id),
            // v0.4.11 PR1: manageable custom templates = is_builtin=false, ws/tls_simple.
            ProfileScope::ManageableCustomTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE id = ? AND is_builtin = 0 AND transport IN ('ws', 'tls_simple')",
            )
            .bind(id),
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(profile)
    }

    async fn count_rules_by_profile(
        &self,
        profile_id: i64,
        scope: &ResourceScope,
    ) -> Result<i64, DbError> {
        let (n,): (i64,) = match scope.owner_id() {
            None => {
                sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = ?")
                    .bind(profile_id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = ? AND uid = ?",
            )
            .bind(profile_id)
            .bind(uid),
        }
        .fetch_one(&self.pool)
        .await?;
        Ok(n)
    }

    async fn list_rule_protocols_by_profile(
        &self,
        profile_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<String>, DbError> {
        let rows: Vec<(String,)> = match scope.owner_id() {
            None => {
                sqlx::query_as("SELECT protocol FROM forward_rules WHERE tunnel_profile_id = ?")
                    .bind(profile_id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT protocol FROM forward_rules WHERE tunnel_profile_id = ? AND uid = ?",
            )
            .bind(profile_id)
            .bind(uid),
        }
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn insert_profile(
        &self,
        name: &str,
        transport: &str,
        tls_mode: &str,
        ws_path: &str,
        host_header: &str,
        sni: &str,
        uid: i64,
    ) -> Result<(), DbError> {
        // is_builtin=0: user-created profiles are always mutable.
        sqlx::query(
            "INSERT INTO tunnel_profiles \
                (name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        )
        .bind(name)
        .bind(transport)
        .bind(tls_mode)
        .bind(ws_path)
        .bind(host_header)
        .bind(sni)
        .bind(uid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_profile_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        transport: Option<&str>,
        tls_mode: Option<&str>,
        ws_path: Option<&str>,
        host_header: Option<&str>,
        sni: Option<&str>,
    ) -> Result<u64, DbError> {
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ?");
        }
        if transport.is_some() {
            sets.push("transport = ?");
        }
        if tls_mode.is_some() {
            sets.push("tls_mode = ?");
        }
        if ws_path.is_some() {
            sets.push("ws_path = ?");
        }
        if host_header.is_some() {
            sets.push("host_header = ?");
        }
        if sni.is_some() {
            sets.push("sni = ?");
        }

        if sets.is_empty() {
            return Ok(0);
        }

        let sql = match scope.owner_id() {
            None => format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ?",
                sets.join(", ")
            ),
            Some(_) => format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ? AND uid = ?",
                sets.join(", ")
            ),
        };
        let mut q = sqlx::query(&sql);
        if let Some(v) = name {
            q = q.bind(v);
        }
        if let Some(v) = transport {
            q = q.bind(v);
        }
        if let Some(v) = tls_mode {
            q = q.bind(v);
        }
        if let Some(v) = ws_path {
            q = q.bind(v);
        }
        if let Some(v) = host_header {
            q = q.bind(v);
        }
        if let Some(v) = sni {
            q = q.bind(v);
        }
        q = q.bind(id);
        if let Some(uid) = scope.owner_id() {
            q = q.bind(uid);
        }

        let result = q.execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn delete_profile(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("DELETE FROM tunnel_profiles WHERE id = ?").bind(id),
            Some(uid) => sqlx::query("DELETE FROM tunnel_profiles WHERE id = ? AND uid = ?")
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn update_profile_checked(
        &self,
        id: i64,
        name: Option<&str>,
        transport: Option<&str>,
        tls_mode: Option<&str>,
        ws_path: Option<&str>,
        host_header: Option<&str>,
        sni: Option<&str>,
    ) -> Result<ProfileUpdateOutcome, DbError> {
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ?");
        }
        if transport.is_some() {
            sets.push("transport = ?");
        }
        if tls_mode.is_some() {
            sets.push("tls_mode = ?");
        }
        if ws_path.is_some() {
            sets.push("ws_path = ?");
        }
        if host_header.is_some() {
            sets.push("host_header = ?");
        }
        if sni.is_some() {
            sets.push("sni = ?");
        }

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        macro_rules! reject {
            ($outcome:expr) => {{
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Ok($outcome);
            }};
        }

        let builtin: Option<bool> = try_sql!(
            sqlx::query_scalar("SELECT is_builtin FROM tunnel_profiles WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
        );
        match builtin {
            None => reject!(ProfileUpdateOutcome::NotFound),
            Some(true) => reject!(ProfileUpdateOutcome::BuiltinReadOnly),
            Some(false) => {}
        }

        if let Some(new_transport) = transport {
            let (count, sample): (i64, Option<String>) = try_sql!(
                sqlx::query_as(
                    "SELECT COUNT(*), MIN(protocol || '/' || public_transport) \
                     FROM forward_rules WHERE tunnel_profile_id = ? \
                       AND (protocol <> 'tcp' OR public_transport <> ?)",
                )
                .bind(id)
                .bind(new_transport)
                .fetch_one(&mut *conn)
                .await
            );
            if count > 0 {
                reject!(ProfileUpdateOutcome::BindingConflict {
                    count,
                    sample: sample.unwrap_or_else(|| "unknown".into()),
                });
            }
        }

        if !sets.is_empty() {
            let sql = format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ?",
                sets.join(", ")
            );
            let mut query = sqlx::query(&sql);
            if let Some(value) = name {
                query = query.bind(value);
            }
            if let Some(value) = transport {
                query = query.bind(value);
            }
            if let Some(value) = tls_mode {
                query = query.bind(value);
            }
            if let Some(value) = ws_path {
                query = query.bind(value);
            }
            if let Some(value) = host_header {
                query = query.bind(value);
            }
            if let Some(value) = sni {
                query = query.bind(value);
            }
            query = query.bind(id);
            try_sql!(query.execute(&mut *conn).await);
        }

        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(ProfileUpdateOutcome::Updated)
    }

    async fn delete_profile_checked(&self, id: i64) -> Result<ProfileDeleteOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_sql {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        macro_rules! reject {
            ($outcome:expr) => {{
                try_sql!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
                return Ok($outcome);
            }};
        }

        let builtin: Option<bool> = try_sql!(
            sqlx::query_scalar("SELECT is_builtin FROM tunnel_profiles WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
        );
        match builtin {
            None => reject!(ProfileDeleteOutcome::NotFound),
            Some(true) => reject!(ProfileDeleteOutcome::BuiltinReadOnly),
            Some(false) => {}
        }
        let rules: i64 = try_sql!(
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
        );
        if rules > 0 {
            reject!(ProfileDeleteOutcome::InUse { rules });
        }
        try_sql!(
            sqlx::query("DELETE FROM tunnel_profiles WHERE id = ?")
                .bind(id)
                .execute(&mut *conn)
                .await
        );
        try_sql!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(ProfileDeleteOutcome::Deleted)
    }
}
