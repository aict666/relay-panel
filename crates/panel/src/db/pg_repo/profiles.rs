use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::TunnelProfile;

// ── TunnelProfileRepository ──

#[async_trait]
impl TunnelProfileRepository for PgRepository {
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
                     WHERE is_builtin = FALSE AND transport IN ('ws', 'tls_simple')
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
        let row: Option<(bool,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT is_builtin FROM tunnel_profiles WHERE id = $1").bind(id),
            Some(uid) => {
                sqlx::query_as("SELECT is_builtin FROM tunnel_profiles WHERE id = $1 AND uid = $2")
                    .bind(id)
                    .bind(uid)
            }
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(b,)| b))
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<TunnelProfile>, DbError> {
        let profile: Option<TunnelProfile> =
            sqlx::query_as("SELECT * FROM tunnel_profiles WHERE name = $1")
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
                sqlx::query_as("SELECT * FROM tunnel_profiles WHERE id = $1").bind(id)
            }
            // v0.4.11 PR1: available templates for rule selection = ws/tls_simple.
            ProfileScope::AvailableTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE id = $1 AND transport IN ('ws', 'tls_simple')",
            )
            .bind(id),
            // v0.4.11 PR1: manageable custom templates = is_builtin=false, ws/tls_simple.
            ProfileScope::ManageableCustomTemplates => sqlx::query_as(
                "SELECT * FROM tunnel_profiles
                     WHERE id = $1 AND is_builtin = FALSE AND transport IN ('ws', 'tls_simple')",
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
                sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = $1")
                    .bind(profile_id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = $1 AND uid = $2",
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
                sqlx::query_as("SELECT protocol FROM forward_rules WHERE tunnel_profile_id = $1")
                    .bind(profile_id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT protocol FROM forward_rules WHERE tunnel_profile_id = $1 AND uid = $2",
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
        // is_builtin=FALSE: user-created profiles are always mutable (same as
        // SQLite's literal 0).
        sqlx::query(
            "INSERT INTO tunnel_profiles \
                (name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7)",
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
            sets.push("name = ");
        }
        if transport.is_some() {
            sets.push("transport = ");
        }
        if tls_mode.is_some() {
            sets.push("tls_mode = ");
        }
        if ws_path.is_some() {
            sets.push("ws_path = ");
        }
        if host_header.is_some() {
            sets.push("host_header = ");
        }
        if sni.is_some() {
            sets.push("sni = ");
        }

        if sets.is_empty() {
            return Ok(0);
        }

        let mut ph = 1;
        let sets_with_ph: Vec<String> = sets
            .iter()
            .map(|s| {
                let p = format!("{s}${ph}");
                ph += 1;
                p
            })
            .collect();
        let id_ph = ph;
        let uid_ph = ph + 1;
        let sql = match scope.owner_id() {
            None => format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ${}",
                sets_with_ph.join(", "),
                id_ph
            ),
            Some(_) => format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ${} AND uid = ${}",
                sets_with_ph.join(", "),
                id_ph,
                uid_ph
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
            None => sqlx::query("DELETE FROM tunnel_profiles WHERE id = $1").bind(id),
            Some(uid) => sqlx::query("DELETE FROM tunnel_profiles WHERE id = $1 AND uid = $2")
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
        let mut tx = self.pool.begin().await?;
        let builtin: Option<bool> =
            sqlx::query_scalar("SELECT is_builtin FROM tunnel_profiles WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        match builtin {
            None => {
                tx.rollback().await?;
                return Ok(ProfileUpdateOutcome::NotFound);
            }
            Some(true) => {
                tx.rollback().await?;
                return Ok(ProfileUpdateOutcome::BuiltinReadOnly);
            }
            Some(false) => {}
        }

        if let Some(new_transport) = transport {
            let (count, sample): (i64, Option<String>) = sqlx::query_as(
                "SELECT COUNT(*), MIN(protocol || '/' || public_transport) \
                 FROM forward_rules WHERE tunnel_profile_id = $1 \
                   AND (protocol <> 'tcp' OR public_transport <> $2)",
            )
            .bind(id)
            .bind(new_transport)
            .fetch_one(&mut *tx)
            .await?;
            if count > 0 {
                tx.rollback().await?;
                return Ok(ProfileUpdateOutcome::BindingConflict {
                    count,
                    sample: sample.unwrap_or_else(|| "unknown".into()),
                });
            }
        }

        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ");
        }
        if transport.is_some() {
            sets.push("transport = ");
        }
        if tls_mode.is_some() {
            sets.push("tls_mode = ");
        }
        if ws_path.is_some() {
            sets.push("ws_path = ");
        }
        if host_header.is_some() {
            sets.push("host_header = ");
        }
        if sni.is_some() {
            sets.push("sni = ");
        }
        if !sets.is_empty() {
            let mut placeholder = 1;
            let assignments: Vec<String> = sets
                .iter()
                .map(|prefix| {
                    let assignment = format!("{prefix}${placeholder}");
                    placeholder += 1;
                    assignment
                })
                .collect();
            let sql = format!(
                "UPDATE tunnel_profiles SET {} WHERE id = ${placeholder}",
                assignments.join(", ")
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
            query.bind(id).execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(ProfileUpdateOutcome::Updated)
    }

    async fn delete_profile_checked(&self, id: i64) -> Result<ProfileDeleteOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        let builtin: Option<bool> =
            sqlx::query_scalar("SELECT is_builtin FROM tunnel_profiles WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        match builtin {
            None => {
                tx.rollback().await?;
                return Ok(ProfileDeleteOutcome::NotFound);
            }
            Some(true) => {
                tx.rollback().await?;
                return Ok(ProfileDeleteOutcome::BuiltinReadOnly);
            }
            Some(false) => {}
        }
        let rules: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE tunnel_profile_id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if rules > 0 {
            tx.rollback().await?;
            return Ok(ProfileDeleteOutcome::InUse { rules });
        }
        sqlx::query("DELETE FROM tunnel_profiles WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ProfileDeleteOutcome::Deleted)
    }
}
