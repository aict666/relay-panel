use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::{decode_blocked_protocols, DeviceGroup, SharedGroupSummary};

// ── GroupRepository ──

#[async_trait]
impl GroupRepository for SqliteRepository {
    async fn list_groups(&self, scope: &ResourceScope) -> Result<Vec<DeviceGroup>, DbError> {
        let groups: Vec<DeviceGroup> = match scope.owner_id() {
            None => sqlx::query_as("SELECT * FROM device_groups ORDER BY id"),
            Some(uid) => {
                sqlx::query_as("SELECT * FROM device_groups WHERE uid = ? ORDER BY id").bind(uid)
            }
        }
        .fetch_all(&self.pool)
        .await?;
        Ok(groups)
    }

    async fn list_shared_groups(
        &self,
        uid: i64,
        is_admin: bool,
    ) -> Result<Vec<SharedGroupSummary>, DbError> {
        // v0.4.11 PR3: admins manage groups directly — no shared infrastructure needed.
        if is_admin {
            return Ok(vec![]);
        }
        // v0.4.12 PR1: regular users see ALL ADMIN-owned inbound-capable groups,
        // independent of whether they already have rules. The JOIN to users
        // enforces admin ownership so a regular user's group is never exposed
        // as "shared". `both` is inbound-capable and therefore follows the
        // same sharing/authorization path as `in`.
        // v1.0.7: `g.hidden` is SELECTED (not filtered here) so the caller
        // decides. Only the node-status path (`list_shared_node_summary`) hides
        // it; the rule dropdown / shop still list hidden groups so existing and
        // new rules keep working. Admins get [] above and are unaffected.
        let groups: Vec<SharedGroupSummary> = sqlx::query_as(
            "SELECT g.id, g.name, g.group_type, g.connect_host, g.capabilities, g.region, g.line_type, g.blocked_protocols, g.hidden \
             FROM device_groups g \
             JOIN users u ON u.id = g.uid \
             WHERE g.uid != ? AND u.admin = 1 AND g.group_type IN ('in', 'both') \
             ORDER BY g.id",
        )
        .bind(uid)
        .fetch_all(&self.pool)
        .await?;
        Ok(groups)
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<DeviceGroup>, DbError> {
        // Historical regular-user-owned groups remain visible through the safe
        // compatibility catalog, but their old tokens must not authenticate a
        // data-plane node or receive/report runtime state.
        let group: Option<DeviceGroup> = sqlx::query_as(
            "SELECT g.* FROM device_groups g JOIN users owner ON owner.id=g.uid \
             WHERE g.token = ? AND owner.admin = 1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(group)
    }

    async fn list_group_credential_revisions(&self) -> Result<Vec<(i64, i64)>, DbError> {
        Ok(sqlx::query_as(
            "SELECT g.id, g.credential_revision FROM device_groups g \
             JOIN users owner ON owner.id=g.uid WHERE owner.admin=1 ORDER BY g.id",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    async fn find_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<DeviceGroup>, DbError> {
        let group: Option<DeviceGroup> = match scope.owner_id() {
            None => sqlx::query_as("SELECT * FROM device_groups WHERE id = ?").bind(id),
            Some(uid) => sqlx::query_as("SELECT * FROM device_groups WHERE id = ? AND uid = ?")
                .bind(id)
                .bind(uid),
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(group)
    }

    async fn find_name_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT name FROM device_groups WHERE id = ?").bind(id),
            Some(uid) => sqlx::query_as("SELECT name FROM device_groups WHERE id = ? AND uid = ?")
                .bind(id)
                .bind(uid),
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(n,)| n))
    }

    async fn insert_group(
        &self,
        name: &str,
        group_type: &str,
        token: &str,
        uid: i64,
        connect_host: &str,
        port_range: &str,
        rate: f64,
        hidden: bool,
        blocked_protocols: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO device_groups (name, group_type, token, uid, connect_host, port_range, rate, hidden, blocked_protocols) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(group_type)
        .bind(token)
        .bind(uid)
        .bind(connect_host)
        .bind(port_range)
        .bind(rate)
        .bind(hidden)
        .bind(blocked_protocols)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_token_after_insert(
        &self,
        token: &str,
    ) -> Result<Option<DeviceGroup>, DbError> {
        // INSERT-then-SELECT-by-token pattern: token is freshly generated
        // (UUID v4), so the SELECT is guaranteed to hit the just-inserted row.
        let group: Option<DeviceGroup> =
            sqlx::query_as("SELECT * FROM device_groups WHERE token = ?")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;
        Ok(group)
    }

    async fn update_group_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        group_type: Option<&str>,
        connect_host: Option<&str>,
        port_range: Option<&str>,
        rate: Option<f64>,
        hidden: Option<bool>,
        blocked_protocols: Option<&str>,
    ) -> Result<GroupUpdateResult, DbError> {
        // Token is NOT updatable here (rotation is a separate endpoint). Build
        // the SET clause from the present fields; binding order matches below.
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ?");
        }
        if group_type.is_some() {
            sets.push("group_type = ?");
        }
        if connect_host.is_some() {
            sets.push("connect_host = ?");
        }
        if port_range.is_some() {
            sets.push("port_range = ?");
        }
        if rate.is_some() {
            sets.push("rate = ?");
        }
        if hidden.is_some() {
            sets.push("hidden = ?");
        }
        if blocked_protocols.is_some() {
            sets.push("blocked_protocols = ?");
        }

        if sets.is_empty() {
            return Ok(GroupUpdateResult {
                rows_affected: 0,
                blocked_protocols_before: None,
                blocked_protocols_after: None,
            });
        }

        // BEGIN IMMEDIATE serializes this invariant check with tunnel path
        // writers. Checking before the transaction left a window where a new
        // tunnel could bind the group immediately before the UPDATE.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! rollback_on_err {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(error.into());
                    }
                }
            };
        }

        let current: Option<(String, String, String)> = match scope.owner_id() {
            None => rollback_on_err!(
                sqlx::query_as(
                    "SELECT group_type, connect_host, blocked_protocols FROM device_groups WHERE id = ?",
                )
                    .bind(id)
                    .fetch_optional(&mut *conn)
                    .await
            ),
            Some(uid) => rollback_on_err!(
                sqlx::query_as(
                    "SELECT group_type, connect_host, blocked_protocols FROM device_groups WHERE id = ? AND uid = ?",
                )
                .bind(id)
                .bind(uid)
                .fetch_optional(&mut *conn)
                .await
            ),
        };
        let Some((current_type, current_host, current_blocked_protocols)) = current else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(GroupUpdateResult {
                rows_affected: 0,
                blocked_protocols_before: None,
                blocked_protocols_after: None,
            });
        };

        let effective_type = group_type.unwrap_or(&current_type);
        let effective_host = connect_host.unwrap_or(&current_host);
        let ingress_capable = matches!(effective_type, "in" | "both");
        if !ingress_capable
            && blocked_protocols.is_some_and(|value| !decode_blocked_protocols(value).is_empty())
        {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::GroupProtocolPolicyInvariant);
        }
        let blocked_protocols_to_write = if ingress_capable {
            blocked_protocols.map(str::to_owned)
        } else if blocked_protocols.is_some() || current_blocked_protocols.trim() != "[]" {
            // Changing away from ingress must atomically clear any retained
            // policy, including malformed/non-canonical historical storage.
            Some("[]".to_string())
        } else {
            None
        };
        if blocked_protocols_to_write.is_some() && blocked_protocols.is_none() {
            sets.push("blocked_protocols = ?");
        }
        let entry_rules: i64 = rollback_on_err!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM (\
                   SELECT id AS rule_id FROM forward_rules WHERE device_group_in = ? \
                   UNION \
                   SELECT rule_id FROM forward_rule_hops \
                    WHERE device_group_id = ? AND position = 0 \
                   UNION \
                   SELECT rule_id FROM forward_rule_retired_entries \
                    WHERE device_group_id = ? AND expires_at >= unixepoch()\
                 )",
            )
            .bind(id)
            .bind(id)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        let downstream_rules: i64 = rollback_on_err!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM (\
                   SELECT id AS rule_id FROM forward_rules WHERE device_group_out = ? \
                   UNION \
                   SELECT rule_id FROM forward_rule_hops \
                    WHERE device_group_id = ? AND position > 0 \
                   UNION \
                   SELECT rule_id FROM forward_rule_route_transitions \
                    WHERE device_group_id = ? AND expires_at >= unixepoch()\
                 )",
            )
            .bind(id)
            .bind(id)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        let invalid_rule_entry = entry_rules > 0 && !matches!(effective_type, "in" | "both");
        let invalid_rule_downstream = downstream_rules > 0
            && (effective_type == "monitor" || effective_host.trim().is_empty());
        if invalid_rule_entry || invalid_rule_downstream {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::RuleGroupInvariant {
                entry_rules,
                downstream_rules,
            });
        }
        let (entry_tunnels, downstream_tunnels): (i64, i64) = rollback_on_err!(
            sqlx::query_as(
                "SELECT COUNT(DISTINCT CASE WHEN position = 0 THEN tunnel_id END), \
                        COUNT(DISTINCT CASE WHEN position > 0 THEN tunnel_id END) \
                 FROM tunnel_hops WHERE device_group_id = ?",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        let invalid_entry = entry_tunnels > 0 && !matches!(effective_type, "in" | "both");
        let invalid_downstream = downstream_tunnels > 0
            && (effective_type == "monitor" || effective_host.trim().is_empty());
        if invalid_entry || invalid_downstream {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::TunnelGroupInvariant {
                entry_tunnels,
                downstream_tunnels,
            });
        }
        let plan_count: i64 = rollback_on_err!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM plan_device_groups WHERE device_group_id = ?",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        if plan_count > 0 && !matches!(effective_type, "in" | "both") {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::GroupPlanInvariant { plans: plan_count });
        }

        let sql = match scope.owner_id() {
            None => format!("UPDATE device_groups SET {} WHERE id = ?", sets.join(", ")),
            Some(_) => format!(
                "UPDATE device_groups SET {} WHERE id = ? AND uid = ?",
                sets.join(", ")
            ),
        };
        let mut q = sqlx::query(&sql);
        if let Some(v) = name {
            q = q.bind(v);
        }
        if let Some(v) = group_type {
            q = q.bind(v);
        }
        if let Some(v) = connect_host {
            q = q.bind(v);
        }
        if let Some(v) = port_range {
            q = q.bind(v);
        }
        if let Some(v) = rate {
            q = q.bind(v);
        }
        if let Some(v) = hidden {
            q = q.bind(v);
        }
        if let Some(v) = blocked_protocols_to_write.as_deref() {
            q = q.bind(v);
        }
        q = q.bind(id);
        if let Some(uid) = scope.owner_id() {
            q = q.bind(uid);
        }

        let result = rollback_on_err!(q.execute(&mut *conn).await);
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(GroupUpdateResult {
            rows_affected: result.rows_affected(),
            blocked_protocols_before: Some(current_blocked_protocols.clone()),
            blocked_protocols_after: Some(
                blocked_protocols_to_write.unwrap_or(current_blocked_protocols),
            ),
        })
    }

    async fn update_group_token(
        &self,
        id: i64,
        scope: &ResourceScope,
        new_token: &str,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE device_groups SET token = ?, credential_revision = credential_revision + 1 WHERE id = ?",
            )
                .bind(new_token)
                .bind(id),
            Some(uid) => sqlx::query(
                "UPDATE device_groups SET token = ?, credential_revision = credential_revision + 1 WHERE id = ? AND uid = ?",
            )
                .bind(new_token)
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn count_rules_by_group(&self, id: i64) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forward_rules \
             WHERE device_group_in = ? OR device_group_out = ?",
        )
        .bind(id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        // Also count chain hop references (intermediate/exit groups).
        let hop_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM forward_rule_hops WHERE device_group_id = ?")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0 + hop_count.0)
    }

    async fn delete_group(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("DELETE FROM device_groups WHERE id = ?").bind(id),
            Some(uid) => sqlx::query("DELETE FROM device_groups WHERE id = ? AND uid = ?")
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn delete_group_checked(&self, id: i64) -> Result<GroupDeleteOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_ {
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
        let exists: Option<i64> = try_!(
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
        );
        if exists.is_none() {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(GroupDeleteOutcome::NotFound);
        }
        let rule_count: i64 = try_!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM ( \
               SELECT id AS rule_id FROM forward_rules \
                WHERE device_group_in = ? OR device_group_out = ? \
               UNION \
               SELECT rule_id FROM forward_rule_hops WHERE device_group_id = ? \
               UNION \
               SELECT rule_id FROM forward_rule_retired_entries \
                WHERE device_group_id = ? AND expires_at >= unixepoch() \
               UNION \
               SELECT rule_id FROM forward_rule_route_transitions \
                WHERE device_group_id = ? AND expires_at >= unixepoch() \
             ) refs",
            )
            .bind(id)
            .bind(id)
            .bind(id)
            .bind(id)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        let tunnel_count: i64 = try_!(
            sqlx::query_scalar(
                "SELECT COUNT(DISTINCT tunnel_id) FROM tunnel_hops WHERE device_group_id = ?",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        let fallback_group_count: i64 = try_!(
            sqlx::query_scalar("SELECT COUNT(*) FROM device_groups WHERE fallback_group = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
        );
        let plan_count: i64 = try_!(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM plan_device_groups WHERE device_group_id = ?",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await
        );
        if rule_count > 0 || tunnel_count > 0 || fallback_group_count > 0 || plan_count > 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(GroupDeleteOutcome::InUse {
                rule_count,
                tunnel_count,
                fallback_group_count,
                plan_count,
            });
        }
        try_!(
            sqlx::query("DELETE FROM device_groups WHERE id = ?")
                .bind(id)
                .execute(&mut *conn)
                .await
        );
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(GroupDeleteOutcome::Deleted)
    }

    async fn delete_groups_by_uid(&self, uid: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM device_groups WHERE uid = ?")
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn list_all_inbound_group_ids(&self) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT dg.id FROM device_groups dg JOIN users owner ON owner.id=dg.uid \
             WHERE dg.group_type IN ('in', 'both') AND owner.admin=1 ORDER BY dg.id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn list_group_names_by_ids(&self, ids: &[i64]) -> Result<Vec<String>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!(
            "SELECT name FROM device_groups WHERE id IN ({}) ORDER BY name",
            placeholders
        );
        let mut q = sqlx::query_as(&sql);
        for id in ids {
            q = q.bind(id);
        }
        let rows: Vec<(String,)> = q.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
    }
}
