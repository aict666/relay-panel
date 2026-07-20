use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    TunnelDeleteOutcome, TunnelRepository, ENTRY_DRAIN_LEASE_TTL_SECS,
    ROUTE_TRANSITION_LEASE_TTL_SECS, ROUTE_TRANSITION_STAGE_SECS,
};
use async_trait::async_trait;
use relay_shared::models::{ForwardRule, ForwardRuleTarget, Tunnel, TunnelHop};
use std::collections::HashMap;

fn attach_tunnel_details(tunnels: &mut [Tunnel], hops: Vec<TunnelHop>, counts: Vec<(i64, i64)>) {
    let mut hops_by_tunnel: HashMap<i64, Vec<TunnelHop>> = HashMap::new();
    for hop in hops {
        hops_by_tunnel.entry(hop.tunnel_id).or_default().push(hop);
    }
    let counts: HashMap<i64, i64> = counts.into_iter().collect();
    for tunnel in tunnels {
        tunnel.hops = hops_by_tunnel.remove(&tunnel.id).unwrap_or_default();
        tunnel.bound_rule_count = counts.get(&tunnel.id).copied().unwrap_or(0);
    }
}

impl SqliteRepository {
    async fn enrich_tunnel(&self, tunnel: &mut Tunnel) -> Result<(), DbError> {
        tunnel.hops = self.list_tunnel_hops(tunnel.id).await?;
        tunnel.bound_rule_count = self.count_rules_by_tunnel(tunnel.id).await?;
        Ok(())
    }
}

#[async_trait]
impl TunnelRepository for SqliteRepository {
    async fn list_tunnels(&self) -> Result<Vec<Tunnel>, DbError> {
        let mut tunnels: Vec<Tunnel> = sqlx::query_as("SELECT * FROM tunnels ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let hops: Vec<TunnelHop> = sqlx::query_as(
            "SELECT h.*, g.name AS group_name, g.connect_host AS connect_host \
             FROM tunnel_hops h JOIN device_groups g ON g.id=h.device_group_id \
             ORDER BY h.tunnel_id,h.position,h.id",
        )
        .fetch_all(&self.pool)
        .await?;
        let counts: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT t.id,COUNT(fr.id) FROM tunnels t \
             LEFT JOIN forward_rules fr ON fr.tunnel_id=t.id GROUP BY t.id",
        )
        .fetch_all(&self.pool)
        .await?;
        attach_tunnel_details(&mut tunnels, hops, counts);
        Ok(tunnels)
    }

    async fn find_tunnel_by_id(&self, id: i64) -> Result<Option<Tunnel>, DbError> {
        let mut tunnel: Option<Tunnel> = sqlx::query_as("SELECT * FROM tunnels WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(value) = &mut tunnel {
            self.enrich_tunnel(value).await?;
        }
        Ok(tunnel)
    }

    async fn list_tunnel_hops(&self, tunnel_id: i64) -> Result<Vec<TunnelHop>, DbError> {
        Ok(sqlx::query_as(
            "SELECT h.*, g.name AS group_name, g.connect_host AS connect_host \
             FROM tunnel_hops h JOIN device_groups g ON g.id = h.device_group_id \
             WHERE h.tunnel_id = ? ORDER BY h.position, h.id",
        )
        .bind(tunnel_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn count_tunnels_by_group(&self, group_id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(DISTINCT tunnel_id) FROM tunnel_hops WHERE device_group_id = ?",
        )
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn count_rules_by_tunnel(&self, tunnel_id: i64) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE tunnel_id = ?")
                .bind(tunnel_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn list_tunnel_rule_owners(&self, tunnel_id: i64) -> Result<Vec<(i64, i64)>, DbError> {
        Ok(
            sqlx::query_as("SELECT id, uid FROM forward_rules WHERE tunnel_id = ? ORDER BY id")
                .bind(tunnel_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn create_tunnel_full(
        &self,
        name: &str,
        enabled: bool,
        shared: bool,
        uid: i64,
        hops: &[(i64, Option<i32>)],
    ) -> Result<i64, DbError> {
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

        if !(2..=8).contains(&hops.len()) {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::TunnelUnavailable);
        }
        let mut group_ids: Vec<i64> = hops.iter().map(|hop| hop.0).collect();
        group_ids.sort_unstable();
        group_ids.dedup();
        if group_ids.len() != hops.len() {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::TunnelUnavailable);
        }
        // BEGIN IMMEDIATE serializes this revalidation with group updates. The
        // earlier service-layer read is not authoritative because it happened
        // before the SQLite writer lock was acquired.
        for (position, (group_id, port)) in hops.iter().enumerate() {
            let group: Option<(String, String)> = try_!(
                sqlx::query_as("SELECT group_type, connect_host FROM device_groups WHERE id = ?",)
                    .bind(group_id)
                    .fetch_optional(&mut *conn)
                    .await
            );
            let Some((group_type, connect_host)) = group else {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::TunnelUnavailable);
            };
            let valid = if position == 0 {
                port.is_none() && matches!(group_type.as_str(), "in" | "both")
            } else {
                port.is_some() && group_type != "monitor" && !connect_host.trim().is_empty()
            };
            if !valid {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::TunnelUnavailable);
            }
        }

        for (group_id, port) in hops.iter().skip(1) {
            let Some(port) = port else {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            };
            let conflict: Option<(i64,)> = try_!(sqlx::query_as(
                "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in = ? AND listen_port = ? AND protocol IN ('tcp','tcp_udp')) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id WHERE h.device_group_id = ? AND h.listen_port = ? AND r.protocol IN ('tcp','tcp_udp')) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops WHERE device_group_id = ? AND tunnel_port = ?) \
                 OR EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id = ? AND listen_port = ?) \
                 OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                   WHERE device_group_id = ? AND listen_port = ? AND expires_at >= unixepoch() \
                     AND protocol IN ('tcp','tcp_udp')) \
                 LIMIT 1",
            )
            .bind(group_id).bind(port)
            .bind(group_id).bind(port)
            .bind(group_id).bind(port)
            .bind(group_id).bind(port)
            .bind(group_id).bind(port)
            .fetch_optional(&mut *conn).await);
            if conflict.is_some() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            }
        }

        let result = try_!(
            sqlx::query("INSERT INTO tunnels (name, enabled, shared, uid) VALUES (?, ?, ?, ?)",)
                .bind(name)
                .bind(enabled)
                .bind(shared)
                .bind(uid)
                .execute(&mut *conn)
                .await
        );
        let tunnel_id = result.last_insert_rowid();
        for (position, (group_id, port)) in hops.iter().enumerate() {
            try_!(
                sqlx::query(
                    "INSERT INTO tunnel_hops (tunnel_id, position, device_group_id, listen_port) \
                 VALUES (?, ?, ?, ?)",
                )
                .bind(tunnel_id)
                .bind(position as i32)
                .bind(group_id)
                .bind(port)
                .execute(&mut *conn)
                .await
            );
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(tunnel_id)
    }

    async fn update_tunnel_full(
        &self,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
        shared: Option<bool>,
        hops: Option<&[(i64, Option<i32>)]>,
        expected_hops: Option<&[(i64, Option<i32>)]>,
    ) -> Result<u64, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let mut entry_transition: Option<(i64, i64)> = None;
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
        let previous_state: Option<(bool, bool)> = try_!(
            sqlx::query_as("SELECT enabled, shared FROM tunnels WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
        );
        let Some((was_enabled, was_shared)) = previous_state else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(0);
        };

        if let Some(hops) = hops {
            let current_hops: Vec<(i64, Option<i32>)> = try_!(
                sqlx::query_as(
                    "SELECT device_group_id, listen_port FROM tunnel_hops \
                 WHERE tunnel_id = ? ORDER BY position, id",
                )
                .bind(id)
                .fetch_all(&mut *conn)
                .await
            );
            if expected_hops != Some(current_hops.as_slice()) {
                sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                return Err(DbError::TunnelUnavailable);
            }

            if !(2..=8).contains(&hops.len()) {
                sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                return Err(DbError::TunnelUnavailable);
            }
            for (position, (group_id, port)) in hops.iter().enumerate() {
                let group: Option<(String, String)> = try_!(
                    sqlx::query_as(
                        "SELECT group_type, connect_host FROM device_groups WHERE id = ?",
                    )
                    .bind(group_id)
                    .fetch_optional(&mut *conn)
                    .await
                );
                let Some((group_type, connect_host)) = group else {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::TunnelUnavailable);
                };
                let valid = if position == 0 {
                    port.is_none() && matches!(group_type.as_str(), "in" | "both")
                } else {
                    port.is_some() && group_type != "monitor" && !connect_host.trim().is_empty()
                };
                if !valid {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::TunnelUnavailable);
                }
            }

            let old_entry = current_hops.first().map(|hop| hop.0);
            let new_entry = hops.first().map(|hop| hop.0);
            if old_entry != new_entry {
                let affected: (i64, i64) = try_!(
                    sqlx::query_as(
                        "SELECT COUNT(fr.id), COUNT(DISTINCT fr.uid) \
                     FROM forward_rules fr JOIN users u ON u.id = fr.uid \
                     WHERE fr.tunnel_id = ? AND u.admin = 0 AND u.all_device_groups = 0 \
                       AND NOT EXISTS (SELECT 1 FROM user_device_groups udg \
                                       WHERE udg.user_id = fr.uid AND udg.device_group_id = ?)",
                    )
                    .bind(id)
                    .bind(new_entry)
                    .fetch_one(&mut *conn)
                    .await
                );
                if affected.0 > 0 {
                    sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                    return Err(DbError::TunnelEntryAuthorization {
                        rules: affected.0,
                        users: affected.1,
                    });
                }
                if let (Some(old_entry), Some(new_entry)) = (old_entry, new_entry) {
                    entry_transition = Some((old_entry, new_entry));
                }
            }
            let entry_conflict: Option<(i64,)> = try_!(sqlx::query_as(
                "SELECT 1 FROM forward_rules bound WHERE bound.tunnel_id=? AND ( \
                 EXISTS (SELECT 1 FROM forward_rules other \
                   WHERE (other.tunnel_id IS NULL OR other.tunnel_id<>?) \
                     AND other.device_group_in=? AND other.listen_port=bound.listen_port \
                     AND ((bound.protocol IN ('tcp','tcp_udp') AND other.protocol IN ('tcp','tcp_udp')) \
                       OR (bound.protocol IN ('udp','tcp_udp') AND other.protocol IN ('udp','tcp_udp')))) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules owner ON owner.id=h.rule_id \
                   WHERE h.device_group_id=? AND h.listen_port=bound.listen_port \
                     AND ((bound.protocol IN ('tcp','tcp_udp') AND owner.protocol IN ('tcp','tcp_udp')) \
                       OR (bound.protocol IN ('udp','tcp_udp') AND owner.protocol IN ('udp','tcp_udp')))) \
                 OR (bound.protocol IN ('tcp','tcp_udp') AND EXISTS \
                   (SELECT 1 FROM forward_rule_hops WHERE device_group_id=? AND tunnel_port=bound.listen_port)) \
                 OR (bound.protocol IN ('tcp','tcp_udp') AND EXISTS \
                   (SELECT 1 FROM tunnel_hops WHERE tunnel_id<>? AND device_group_id=? AND listen_port=bound.listen_port)) \
                 OR EXISTS (SELECT 1 FROM forward_rule_route_transitions rt \
                   WHERE rt.rule_id<>bound.id AND rt.device_group_id=? \
                     AND rt.listen_port=bound.listen_port \
                     AND rt.expires_at>=unixepoch() \
                     AND ((bound.protocol IN ('tcp','tcp_udp') AND rt.protocol IN ('tcp','tcp_udp')) \
                       OR (bound.protocol IN ('udp','tcp_udp') AND rt.protocol IN ('udp','tcp_udp')))) \
                 ) LIMIT 1",
            )
            .bind(id).bind(id).bind(new_entry)
            .bind(new_entry).bind(new_entry)
            .bind(id).bind(new_entry)
            .bind(new_entry)
            .fetch_optional(&mut *conn)
            .await);
            if entry_conflict.is_some() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            }
            for (group_id, port) in hops.iter().skip(1) {
                let Some(port) = port else {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::PortConflict);
                };
                let conflict: Option<(i64,)> = try_!(sqlx::query_as(
                    "SELECT 1 WHERE \
                     EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in = ? AND listen_port = ? AND protocol IN ('tcp','tcp_udp')) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id WHERE h.device_group_id = ? AND h.listen_port = ? AND r.protocol IN ('tcp','tcp_udp')) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops WHERE device_group_id = ? AND tunnel_port = ?) \
                     OR EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id = ? AND listen_port = ? AND tunnel_id != ?) \
                     OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                       WHERE rule_id NOT IN (SELECT id FROM forward_rules WHERE tunnel_id = ?) \
                         AND device_group_id = ? AND listen_port = ? AND expires_at >= unixepoch() \
                         AND protocol IN ('tcp','tcp_udp')) \
                     LIMIT 1",
                )
                .bind(group_id).bind(port)
                .bind(group_id).bind(port)
                .bind(group_id).bind(port)
                .bind(group_id).bind(port).bind(id)
                .bind(id).bind(group_id).bind(port)
                .fetch_optional(&mut *conn).await);
                if conflict.is_some() {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::PortConflict);
                }
            }
        }
        let result = try_!(
            sqlx::query(
                "UPDATE tunnels SET name = COALESCE(?, name), \
                 enabled = COALESCE(?, enabled), shared = COALESCE(?, shared) WHERE id = ?",
            )
            .bind(name)
            .bind(enabled)
            .bind(shared)
            .bind(id)
            .execute(&mut *conn)
            .await
        );
        if result.rows_affected() == 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(0);
        }
        if let Some(hops) = hops {
            // Preserve the old non-entry path just long enough for the new
            // snapshot to converge across independently polling nodes.
            try_!(
                sqlx::query(
                    "DELETE FROM forward_rule_route_transitions WHERE rule_id IN \
                     (SELECT id FROM forward_rules WHERE tunnel_id=?)",
                )
                .bind(id)
                .execute(&mut *conn)
                .await
            );
            let remains_enabled = enabled.unwrap_or(was_enabled);
            if was_enabled && remains_enabled {
                try_!(
                    sqlx::query(
                        "INSERT INTO forward_rule_route_transitions \
                         (rule_id,device_group_id,listen_port,protocol,activate_at,expires_at) \
                         SELECT fr.id,old_hop.device_group_id,old_hop.listen_port,'tcp', \
                           unixepoch()+?,unixepoch()+? \
                         FROM forward_rules fr JOIN users u ON u.id=fr.uid \
                         JOIN tunnel_hops old_hop ON old_hop.tunnel_id=? AND old_hop.position>0 \
                         WHERE fr.tunnel_id=? AND fr.paused=0 \
                           AND u.banned=0 AND u.suspended=0 \
                           AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
                           AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
                           AND (u.admin=1 OR (?=1 AND (u.all_device_groups=1 OR EXISTS( \
                             SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                               AND udg.device_group_id=?)))) \
                         ON CONFLICT(rule_id,device_group_id,listen_port,protocol) DO UPDATE \
                           SET activate_at=excluded.activate_at,expires_at=excluded.expires_at",
                    )
                    .bind(ROUTE_TRANSITION_STAGE_SECS)
                    .bind(ROUTE_TRANSITION_LEASE_TTL_SECS)
                    .bind(id)
                    .bind(id)
                    .bind(was_shared)
                    .bind(hops.first().map(|hop| hop.0))
                    .execute(&mut *conn)
                    .await
                );
            }
            if let Some((old_entry, new_entry)) = entry_transition {
                // A tunnel that was disabled before this write had no entry
                // listener or live streams to drain. Enabling it while also
                // replacing the path must not mint authority for the old path.
                if was_enabled {
                    try_!(
                        sqlx::query(
                            "INSERT INTO forward_rule_retired_entries \
                       (rule_id,tunnel_id,device_group_id,expires_at) \
                     SELECT fr.id,?,?,unixepoch()+? FROM forward_rules fr \
                     JOIN users u ON u.id=fr.uid \
                     WHERE fr.tunnel_id=? \
                       AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
                       AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
                       AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
                       AND (u.admin=1 OR (?=1 AND \
                         (u.all_device_groups=1 OR EXISTS(SELECT 1 FROM user_device_groups udg \
                           WHERE udg.user_id=u.id AND udg.device_group_id=?)))) \
                     ON CONFLICT(rule_id,tunnel_id,device_group_id) DO UPDATE \
                       SET expires_at=excluded.expires_at",
                        )
                        .bind(id)
                        .bind(old_entry)
                        .bind(ENTRY_DRAIN_LEASE_TTL_SECS)
                        .bind(id)
                        .bind(was_shared)
                        .bind(old_entry)
                        .execute(&mut *conn)
                        .await
                    );
                }
                // Moving back to a previously-retired entry makes it current
                // again; it must no longer receive drain-only metadata.
                try_!(
                    sqlx::query(
                        "DELETE FROM forward_rule_retired_entries WHERE device_group_id=? \
                     AND rule_id IN (SELECT id FROM forward_rules WHERE tunnel_id=?)",
                    )
                    .bind(new_entry)
                    .bind(id)
                    .execute(&mut *conn)
                    .await
                );
            }
            try_!(
                sqlx::query("DELETE FROM tunnel_hops WHERE tunnel_id = ?")
                    .bind(id)
                    .execute(&mut *conn)
                    .await
            );
            for (position, (group_id, port)) in hops.iter().enumerate() {
                try_!(sqlx::query(
                    "INSERT INTO tunnel_hops (tunnel_id, position, device_group_id, listen_port) VALUES (?, ?, ?, ?)",
                )
                .bind(id).bind(position as i32).bind(group_id).bind(port)
                .execute(&mut *conn).await);
            }
            try_!(sqlx::query(
                "UPDATE forward_rules SET device_group_in=?,device_group_out=? WHERE tunnel_id=?",
            )
            .bind(hops.first().map(|hop| hop.0))
            .bind(hops.last().map(|hop| hop.0))
            .bind(id)
            .execute(&mut *conn)
            .await);
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(1)
    }

    async fn delete_tunnel(&self, id: i64) -> Result<TunnelDeleteOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM tunnels WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
        if exists.is_none() {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(TunnelDeleteOutcome::NotFound);
        }
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE tunnel_id = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
        if count > 0 {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(TunnelDeleteOutcome::InUse(count));
        }
        sqlx::query("DELETE FROM tunnels WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(TunnelDeleteOutcome::Deleted)
    }

    async fn list_active_rules_for_tunnel(
        &self,
        tunnel_id: i64,
    ) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules: Vec<ForwardRule> = sqlx::query_as(
            "SELECT fr.* FROM forward_rules fr JOIN users u ON u.id=fr.uid JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE fr.tunnel_id=? AND t.enabled=1 AND (u.admin=1 OR (t.shared=1 AND \
               (u.all_device_groups=1 OR EXISTS (SELECT 1 FROM user_device_groups udg \
                 WHERE udg.user_id=u.id AND udg.device_group_id=fr.device_group_in)))) \
             AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) ORDER BY fr.id",
        ).bind(tunnel_id).fetch_all(&self.pool).await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT rt.* FROM forward_rule_targets rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             WHERE fr.tunnel_id=? AND rt.enabled=1 ORDER BY rt.rule_id,rt.position,rt.id",
        )
        .bind(tunnel_id)
        .fetch_all(&self.pool)
        .await?;
        let mut targets_by_rule: std::collections::HashMap<i64, Vec<ForwardRuleTarget>> =
            std::collections::HashMap::new();
        for target in targets {
            targets_by_rule
                .entry(target.rule_id)
                .or_default()
                .push(target);
        }
        for rule in &mut rules {
            rule.targets = targets_by_rule.remove(&rule.id).unwrap_or_default();
            rule.tunnel_enabled = Some(true);
        }
        Ok(rules)
    }

    async fn list_active_tunnel_rules_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules: Vec<ForwardRule> = sqlx::query_as(
            "SELECT fr.* FROM forward_rules fr JOIN users u ON u.id=fr.uid \
             JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE t.enabled=1 AND EXISTS(SELECT 1 FROM tunnel_hops member \
               WHERE member.tunnel_id=t.id AND member.device_group_id=?) \
             AND (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS \
               (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                AND udg.device_group_id=fr.device_group_in)))) \
             AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT rt.* FROM forward_rule_targets rt \
             WHERE rt.enabled=1 AND EXISTS(SELECT 1 FROM forward_rules fr \
               JOIN users u ON u.id=fr.uid JOIN tunnels t ON t.id=fr.tunnel_id \
               WHERE fr.id=rt.rule_id AND t.enabled=1 \
               AND EXISTS(SELECT 1 FROM tunnel_hops member WHERE member.tunnel_id=t.id \
                 AND member.device_group_id=?) \
               AND (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS \
                 (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                  AND udg.device_group_id=fr.device_group_in)))) \
               AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now'))) \
             ORDER BY rt.rule_id,rt.position,rt.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let mut targets_by_rule: HashMap<i64, Vec<ForwardRuleTarget>> = HashMap::new();
        for target in targets {
            targets_by_rule
                .entry(target.rule_id)
                .or_default()
                .push(target);
        }
        for rule in &mut rules {
            rule.targets = targets_by_rule.remove(&rule.id).unwrap_or_default();
            rule.tunnel_enabled = Some(true);
        }
        Ok(rules)
    }

    async fn list_enabled_tunnels_for_group(&self, group_id: i64) -> Result<Vec<Tunnel>, DbError> {
        let mut tunnels: Vec<Tunnel> = sqlx::query_as(
            "SELECT DISTINCT t.* FROM tunnels t JOIN tunnel_hops h ON h.tunnel_id=t.id \
             WHERE t.enabled=1 AND h.device_group_id=? ORDER BY t.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let hops: Vec<TunnelHop> = sqlx::query_as(
            "SELECT h.*,g.name AS group_name,g.connect_host AS connect_host \
             FROM tunnel_hops h JOIN device_groups g ON g.id=h.device_group_id \
             JOIN tunnels t ON t.id=h.tunnel_id WHERE t.enabled=1 AND EXISTS \
               (SELECT 1 FROM tunnel_hops member WHERE member.tunnel_id=t.id \
                AND member.device_group_id=?) ORDER BY h.tunnel_id,h.position,h.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let counts: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT t.id,COUNT(fr.id) FROM tunnels t \
             LEFT JOIN forward_rules fr ON fr.tunnel_id=t.id \
             WHERE t.enabled=1 AND EXISTS(SELECT 1 FROM tunnel_hops member \
               WHERE member.tunnel_id=t.id AND member.device_group_id=?) GROUP BY t.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        attach_tunnel_details(&mut tunnels, hops, counts);
        Ok(tunnels)
    }

    async fn list_group_tokens(&self, group_ids: &[i64]) -> Result<Vec<(i64, String)>, DbError> {
        if group_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT id,token FROM device_groups WHERE id IN (",
        );
        let mut separated = query.separated(",");
        for group_id in group_ids {
            separated.push_bind(group_id);
        }
        separated.push_unseparated(") ORDER BY id");
        Ok(query.build_query_as().fetch_all(&self.pool).await?)
    }

    async fn list_disabled_bound_tunnel_ids(&self) -> Result<Vec<i64>, DbError> {
        sqlx::query_scalar(
            "SELECT DISTINCT t.id FROM tunnels t \
             WHERE t.enabled=0 \
             AND EXISTS(SELECT 1 FROM forward_rules fr WHERE fr.tunnel_id=t.id) \
             ORDER BY t.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DbError::from)
    }

    async fn list_draining_tunnel_rule_ids_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT fr.id FROM forward_rules fr \
             JOIN users u ON u.id=fr.uid \
             JOIN forward_rule_retired_entries re ON re.rule_id=fr.id \
             JOIN tunnels source_tunnel ON source_tunnel.id=re.tunnel_id \
             WHERE re.device_group_id=? AND re.expires_at>=unixepoch() \
               AND fr.tunnel_id=re.tunnel_id \
               AND source_tunnel.enabled=1 AND fr.paused=0 \
               AND u.banned=0 AND u.suspended=0 \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
               AND (u.admin=1 OR (source_tunnel.shared=1 AND (u.all_device_groups=1 OR EXISTS( \
                 SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                   AND udg.device_group_id=re.device_group_id)))) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_route_transition_rule_ids_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT fr.id FROM forward_rule_route_transitions rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             JOIN users u ON u.id=fr.uid \
             LEFT JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE rt.device_group_id=? AND rt.expires_at>=unixepoch() \
               AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
               AND (fr.tunnel_id IS NULL OR (t.enabled=1 AND \
                 (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS( \
                   SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                     AND udg.device_group_id=fr.device_group_in)))))) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_route_staging_rule_ids_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT fr.id FROM forward_rule_route_transitions rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             JOIN users u ON u.id=fr.uid \
             LEFT JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE rt.activate_at>unixepoch() AND rt.expires_at>=unixepoch() \
               AND (fr.device_group_in=? OR EXISTS( \
                 SELECT 1 FROM forward_rule_retired_entries re WHERE re.rule_id=fr.id \
                   AND re.device_group_id=? AND re.expires_at>=unixepoch())) \
               AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
               AND (fr.tunnel_id IS NULL OR (t.enabled=1 AND \
                 (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS( \
                   SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                     AND udg.device_group_id=?)))))) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .bind(group_id)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_route_drain_rule_ids_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT fr.id FROM forward_rule_route_transitions rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             JOIN users u ON u.id=fr.uid \
             LEFT JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE rt.device_group_id=? AND rt.expires_at<unixepoch() \
               AND fr.paused=0 AND u.banned=0 AND u.suspended=0 \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
               AND (fr.tunnel_id IS NULL OR (t.enabled=1 AND \
                 (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS( \
                   SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                     AND udg.device_group_id=fr.device_group_in)))))) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_rule_restart_entry_group_ids(&self, rule_id: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT device_group_in FROM forward_rules WHERE id=? \
             UNION SELECT device_group_id FROM forward_rule_retired_entries WHERE rule_id=? \
             ORDER BY 1",
        )
        .bind(rule_id)
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn renew_draining_tunnel_rule_ids_for_group(
        &self,
        group_id: i64,
        rule_ids: &[i64],
    ) -> Result<u64, DbError> {
        if rule_ids.is_empty() {
            return Ok(0);
        }
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "UPDATE forward_rule_retired_entries SET expires_at=unixepoch()+",
        );
        query
            .push_bind(ENTRY_DRAIN_LEASE_TTL_SECS)
            .push(" WHERE device_group_id=")
            .push_bind(group_id)
            .push(" AND expires_at>=unixepoch()")
            .push(" AND rule_id IN (");
        let mut separated = query.separated(",");
        for rule_id in rule_ids {
            separated.push_bind(rule_id);
        }
        separated.push_unseparated(
            ") AND EXISTS( \
          SELECT 1 FROM forward_rules fr \
          JOIN users u ON u.id=fr.uid \
          JOIN tunnels source_tunnel ON source_tunnel.id=forward_rule_retired_entries.tunnel_id \
          WHERE fr.id=forward_rule_retired_entries.rule_id \
            AND fr.tunnel_id=forward_rule_retired_entries.tunnel_id \
            AND source_tunnel.enabled=1 AND fr.paused=0 \
            AND u.banned=0 AND u.suspended=0 \
            AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
            AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
            AND (u.admin=1 OR (source_tunnel.shared=1 AND (u.all_device_groups=1 OR EXISTS( \
              SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                AND udg.device_group_id=forward_rule_retired_entries.device_group_id)))))",
        );
        Ok(query.build().execute(&self.pool).await?.rows_affected())
    }
}
