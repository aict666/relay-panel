use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{TunnelDeleteOutcome, TunnelRepository, ENTRY_DRAIN_LEASE_TTL_SECS};
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

impl PgRepository {
    async fn enrich_tunnel(&self, tunnel: &mut Tunnel) -> Result<(), DbError> {
        tunnel.hops = self.list_tunnel_hops(tunnel.id).await?;
        tunnel.bound_rule_count = self.count_rules_by_tunnel(tunnel.id).await?;
        Ok(())
    }
}

#[async_trait]
impl TunnelRepository for PgRepository {
    async fn list_tunnels(&self) -> Result<Vec<Tunnel>, DbError> {
        let mut tunnels: Vec<Tunnel> = sqlx::query_as("SELECT * FROM tunnels ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let hops: Vec<TunnelHop> = sqlx::query_as(
            "SELECT h.*,g.name AS group_name,g.connect_host AS connect_host \
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
        let mut tunnel: Option<Tunnel> = sqlx::query_as("SELECT * FROM tunnels WHERE id=$1")
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
             FROM tunnel_hops h JOIN device_groups g ON g.id=h.device_group_id \
             WHERE h.tunnel_id=$1 ORDER BY h.position,h.id",
        )
        .bind(tunnel_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn count_tunnels_by_group(&self, group_id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(DISTINCT tunnel_id) FROM tunnel_hops WHERE device_group_id=$1",
        )
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn count_rules_by_tunnel(&self, tunnel_id: i64) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE tunnel_id=$1")
                .bind(tunnel_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn list_tunnel_rule_owners(&self, tunnel_id: i64) -> Result<Vec<(i64, i64)>, DbError> {
        Ok(
            sqlx::query_as("SELECT id,uid FROM forward_rules WHERE tunnel_id=$1 ORDER BY id")
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
        let mut tx = self.pool.begin().await?;
        if !(2..=8).contains(&hops.len()) {
            tx.rollback().await?;
            return Err(DbError::TunnelUnavailable);
        }
        let mut groups: Vec<i64> = hops.iter().map(|h| h.0).collect();
        groups.sort_unstable();
        groups.dedup();
        if groups.len() != hops.len() {
            tx.rollback().await?;
            return Err(DbError::TunnelUnavailable);
        }
        for group_id in groups {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
        }
        // The service performs friendly validation before port allocation, but
        // group fields can change before this transaction obtains its locks.
        // Re-read every hop under the same lock domain as group updates so an
        // entry cannot become outbound-only, and a new downstream hop cannot
        // lose its connect_host or become a monitor between validation and write.
        for (position, (group_id, port)) in hops.iter().enumerate() {
            let group: Option<(String, String)> = sqlx::query_as(
                "SELECT group_type, connect_host FROM device_groups WHERE id=$1 FOR SHARE",
            )
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((group_type, connect_host)) = group else {
                tx.rollback().await?;
                return Err(DbError::TunnelUnavailable);
            };
            let valid = if position == 0 {
                port.is_none() && matches!(group_type.as_str(), "in" | "both")
            } else {
                port.is_some() && group_type != "monitor" && !connect_host.trim().is_empty()
            };
            if !valid {
                tx.rollback().await?;
                return Err(DbError::TunnelUnavailable);
            }
        }
        for (group_id, port) in hops.iter().skip(1) {
            let Some(port) = port else {
                tx.rollback().await?;
                return Err(DbError::PortConflict);
            };
            let conflict: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in=$1 AND listen_port=$2 AND protocol IN ('tcp','tcp_udp')) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id WHERE h.device_group_id=$1 AND h.listen_port=$2 AND r.protocol IN ('tcp','tcp_udp')) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops WHERE device_group_id=$1 AND tunnel_port=$2) \
                 OR EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=$1 AND listen_port=$2) LIMIT 1",
            ).bind(group_id).bind(port).fetch_optional(&mut *tx).await?;
            if conflict.is_some() {
                tx.rollback().await?;
                return Err(DbError::PortConflict);
            }
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO tunnels(name,enabled,shared,uid) VALUES($1,$2,$3,$4) RETURNING id",
        )
        .bind(name)
        .bind(enabled)
        .bind(shared)
        .bind(uid)
        .fetch_one(&mut *tx)
        .await?;
        for (position, (group_id, port)) in hops.iter().enumerate() {
            sqlx::query("INSERT INTO tunnel_hops(tunnel_id,position,device_group_id,listen_port) VALUES($1,$2,$3,$4)")
                .bind(id).bind(position as i32).bind(group_id).bind(port).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(id)
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
        let mut tx = self.pool.begin().await?;
        // Path replacement needs a serializable snapshot for the authorization
        // predicate and topology rewrite. Scalar-only partial updates stay at
        // READ COMMITTED: the row lock plus COALESCE lets disjoint fields merge
        // instead of either losing state or raising an avoidable serialization
        // failure.
        if hops.is_some() {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *tx)
                .await?;
        }
        // The caller's exact snapshot gives us the old groups without reading
        // mutable rows first. Lock those groups before taking the current path
        // snapshot so two administrators replacing the same route serialize
        // and the loser receives TunnelUnavailable (409), not a late
        // PostgreSQL serialization failure (500).
        let mut groups: Vec<i64> = hops
            .into_iter()
            .flatten()
            .map(|hop| hop.0)
            .chain(expected_hops.into_iter().flatten().map(|hop| hop.0))
            .collect();
        groups.sort_unstable();
        groups.dedup();
        for group_id in groups {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
        }
        let current_hops: Vec<(i64, Option<i32>)> = if hops.is_some() {
            sqlx::query_as(
                "SELECT device_group_id, listen_port FROM tunnel_hops \
                 WHERE tunnel_id=$1 ORDER BY position,id",
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await?
        } else {
            Vec::new()
        };
        if hops.is_some() {
            // Lock bound rules before the tunnel row. Rule updates use the same
            // group -> rule -> tunnel order, avoiding a deadlock cycle.
            sqlx::query("SELECT id FROM forward_rules WHERE tunnel_id=$1 ORDER BY id FOR UPDATE")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        }
        let previous_state: Option<(bool, bool)> =
            sqlx::query_as("SELECT enabled,shared FROM tunnels WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((was_enabled, was_shared)) = previous_state else {
            tx.rollback().await?;
            return Ok(0);
        };
        if hops.is_some() && expected_hops != Some(current_hops.as_slice()) {
            tx.rollback().await?;
            return Err(DbError::TunnelUnavailable);
        }
        if let Some(hops) = hops {
            if !(2..=8).contains(&hops.len()) {
                tx.rollback().await?;
                return Err(DbError::TunnelUnavailable);
            }
            for (position, (group_id, port)) in hops.iter().enumerate() {
                let group: Option<(String, String)> = sqlx::query_as(
                    "SELECT group_type, connect_host FROM device_groups WHERE id=$1 FOR SHARE",
                )
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some((group_type, connect_host)) = group else {
                    tx.rollback().await?;
                    return Err(DbError::TunnelUnavailable);
                };
                let valid = if position == 0 {
                    port.is_none() && matches!(group_type.as_str(), "in" | "both")
                } else {
                    port.is_some() && group_type != "monitor" && !connect_host.trim().is_empty()
                };
                if !valid {
                    tx.rollback().await?;
                    return Err(DbError::TunnelUnavailable);
                }
            }
            let old_entry = current_hops.first().map(|hop| hop.0);
            let new_entry = hops.first().map(|hop| hop.0);
            if old_entry != new_entry {
                let affected: (i64, i64) = sqlx::query_as(
                    "SELECT COUNT(fr.id), COUNT(DISTINCT fr.uid) \
                 FROM forward_rules fr JOIN users u ON u.id=fr.uid \
                 WHERE fr.tunnel_id=$1 AND u.admin=FALSE AND u.all_device_groups=FALSE \
                   AND NOT EXISTS (SELECT 1 FROM user_device_groups udg \
                                   WHERE udg.user_id=fr.uid AND udg.device_group_id=$2)",
                )
                .bind(id)
                .bind(new_entry)
                .fetch_one(&mut *tx)
                .await?;
                if affected.0 > 0 {
                    tx.rollback().await?;
                    return Err(DbError::TunnelEntryAuthorization {
                        rules: affected.0,
                        users: affected.1,
                    });
                }
            }
            let entry_conflict: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM forward_rules bound WHERE bound.tunnel_id=$1 AND ( \
             EXISTS (SELECT 1 FROM forward_rules other \
               WHERE (other.tunnel_id IS NULL OR other.tunnel_id<>$1) \
                 AND other.device_group_in=$2 AND other.listen_port=bound.listen_port \
                 AND ((bound.protocol IN ('tcp','tcp_udp') AND other.protocol IN ('tcp','tcp_udp')) \
                   OR (bound.protocol IN ('udp','tcp_udp') AND other.protocol IN ('udp','tcp_udp')))) \
             OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules owner ON owner.id=h.rule_id \
               WHERE h.device_group_id=$2 AND h.listen_port=bound.listen_port \
                 AND ((bound.protocol IN ('tcp','tcp_udp') AND owner.protocol IN ('tcp','tcp_udp')) \
                   OR (bound.protocol IN ('udp','tcp_udp') AND owner.protocol IN ('udp','tcp_udp')))) \
             OR (bound.protocol IN ('tcp','tcp_udp') AND EXISTS \
               (SELECT 1 FROM forward_rule_hops WHERE device_group_id=$2 AND tunnel_port=bound.listen_port)) \
             OR (bound.protocol IN ('tcp','tcp_udp') AND EXISTS \
               (SELECT 1 FROM tunnel_hops WHERE tunnel_id<>$1 AND device_group_id=$2 AND listen_port=bound.listen_port)) \
             ) LIMIT 1",
        )
            .bind(id)
            .bind(new_entry)
            .fetch_optional(&mut *tx)
            .await?;
            if entry_conflict.is_some() {
                tx.rollback().await?;
                return Err(DbError::PortConflict);
            }
            for (group_id, port) in hops.iter().skip(1) {
                let Some(port) = port else {
                    tx.rollback().await?;
                    return Err(DbError::PortConflict);
                };
                let conflict: Option<(i32,)> = sqlx::query_as(
                    "SELECT 1 WHERE \
                     EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in=$1 AND listen_port=$2 AND protocol IN ('tcp','tcp_udp')) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id WHERE h.device_group_id=$1 AND h.listen_port=$2 AND r.protocol IN ('tcp','tcp_udp')) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops WHERE device_group_id=$1 AND tunnel_port=$2) \
                     OR EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=$1 AND listen_port=$2 AND tunnel_id<>$3) LIMIT 1",
                ).bind(group_id).bind(port).bind(id).fetch_optional(&mut *tx).await?;
                if conflict.is_some() {
                    tx.rollback().await?;
                    return Err(DbError::PortConflict);
                }
            }
        }
        let result = sqlx::query(
            "UPDATE tunnels SET name=COALESCE($1,name), enabled=COALESCE($2,enabled), \
             shared=COALESCE($3,shared) WHERE id=$4",
        )
        .bind(name)
        .bind(enabled)
        .bind(shared)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        if let Some(hops) = hops {
            let old_entry = current_hops.first().map(|hop| hop.0);
            let new_entry = hops.first().map(|hop| hop.0);
            if old_entry != new_entry {
                if let (Some(old_entry), Some(new_entry)) = (old_entry, new_entry) {
                    // If the tunnel was disabled before this transaction, the
                    // old entry had no listener and therefore no live stream to
                    // drain. Enabling and moving it in one write must not grant
                    // the old group a lease.
                    if was_enabled {
                        sqlx::query(
                            "INSERT INTO forward_rule_retired_entries \
                           (rule_id,tunnel_id,device_group_id,expires_at) \
                         SELECT fr.id,$1,$2,EXTRACT(EPOCH FROM now())::BIGINT+$3 \
                         FROM forward_rules fr JOIN users u ON u.id=fr.uid \
                         WHERE fr.tunnel_id=$1 \
                           AND fr.paused=FALSE AND u.banned=FALSE AND u.suspended=FALSE \
                           AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
                           AND (u.plan_expire_at IS NULL OR u.plan_expire_at> \
                             to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')) \
                           AND (u.admin=TRUE OR ($4=TRUE AND \
                             (u.all_device_groups=TRUE OR EXISTS(SELECT 1 FROM user_device_groups udg \
                               WHERE udg.user_id=u.id AND udg.device_group_id=$2)))) \
                         ON CONFLICT(rule_id,tunnel_id,device_group_id) DO UPDATE \
                           SET expires_at=excluded.expires_at",
                        )
                        .bind(id)
                        .bind(old_entry)
                        .bind(ENTRY_DRAIN_LEASE_TTL_SECS)
                        .bind(was_shared)
                        .execute(&mut *tx)
                        .await?;
                    }
                    sqlx::query(
                        "DELETE FROM forward_rule_retired_entries WHERE device_group_id=$1 \
                         AND rule_id IN (SELECT id FROM forward_rules WHERE tunnel_id=$2)",
                    )
                    .bind(new_entry)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            sqlx::query("DELETE FROM tunnel_hops WHERE tunnel_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for (position, (group_id, port)) in hops.iter().enumerate() {
                sqlx::query("INSERT INTO tunnel_hops(tunnel_id,position,device_group_id,listen_port) VALUES($1,$2,$3,$4)")
                    .bind(id).bind(position as i32).bind(group_id).bind(port).execute(&mut *tx).await?;
            }
            sqlx::query(
                "UPDATE forward_rules SET device_group_in=$1,device_group_out=$2 WHERE tunnel_id=$3",
            )
            .bind(hops.first().map(|hop| hop.0))
            .bind(hops.last().map(|hop| hop.0))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(1)
    }

    async fn delete_tunnel(&self, id: i64) -> Result<TunnelDeleteOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM tunnels WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(TunnelDeleteOutcome::NotFound);
        }
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE tunnel_id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if count > 0 {
            tx.rollback().await?;
            return Ok(TunnelDeleteOutcome::InUse(count));
        }
        sqlx::query("DELETE FROM tunnels WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(TunnelDeleteOutcome::Deleted)
    }

    async fn list_active_rules_for_tunnel(
        &self,
        tunnel_id: i64,
    ) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules:Vec<ForwardRule>=sqlx::query_as(
            "SELECT fr.* FROM forward_rules fr JOIN users u ON u.id=fr.uid JOIN tunnels t ON t.id=fr.tunnel_id \
             WHERE fr.tunnel_id=$1 AND t.enabled=TRUE AND (u.admin=TRUE OR (t.shared=TRUE AND \
               (u.all_device_groups=TRUE OR EXISTS (SELECT 1 FROM user_device_groups udg \
                 WHERE udg.user_id=u.id AND udg.device_group_id=fr.device_group_in)))) \
             AND fr.paused=FALSE AND u.banned=FALSE AND u.suspended=FALSE \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')) ORDER BY fr.id"
        ).bind(tunnel_id).fetch_all(&self.pool).await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT rt.* FROM forward_rule_targets rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             WHERE fr.tunnel_id=$1 AND rt.enabled=TRUE ORDER BY rt.rule_id,rt.position,rt.id",
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
             WHERE t.enabled=TRUE AND EXISTS(SELECT 1 FROM tunnel_hops member \
               WHERE member.tunnel_id=t.id AND member.device_group_id=$1) \
             AND (u.admin=TRUE OR (t.shared=TRUE AND (u.all_device_groups=TRUE OR EXISTS \
               (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                AND udg.device_group_id=fr.device_group_in)))) \
             AND fr.paused=FALSE AND u.banned=FALSE AND u.suspended=FALSE \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT rt.* FROM forward_rule_targets rt \
             WHERE rt.enabled=TRUE AND EXISTS(SELECT 1 FROM forward_rules fr \
               JOIN users u ON u.id=fr.uid JOIN tunnels t ON t.id=fr.tunnel_id \
               WHERE fr.id=rt.rule_id AND t.enabled=TRUE \
               AND EXISTS(SELECT 1 FROM tunnel_hops member WHERE member.tunnel_id=t.id \
                 AND member.device_group_id=$1) \
               AND (u.admin=TRUE OR (t.shared=TRUE AND (u.all_device_groups=TRUE OR EXISTS \
                 (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                  AND udg.device_group_id=fr.device_group_in)))) \
               AND fr.paused=FALSE AND u.banned=FALSE AND u.suspended=FALSE \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at>to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'))) \
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
        let mut tunnels:Vec<Tunnel>=sqlx::query_as(
            "SELECT DISTINCT t.* FROM tunnels t JOIN tunnel_hops h ON h.tunnel_id=t.id WHERE t.enabled=TRUE AND h.device_group_id=$1 ORDER BY t.id"
        ).bind(group_id).fetch_all(&self.pool).await?;
        let hops: Vec<TunnelHop> = sqlx::query_as(
            "SELECT h.*,g.name AS group_name,g.connect_host AS connect_host \
             FROM tunnel_hops h JOIN device_groups g ON g.id=h.device_group_id \
             JOIN tunnels t ON t.id=h.tunnel_id WHERE t.enabled=TRUE AND EXISTS \
               (SELECT 1 FROM tunnel_hops member WHERE member.tunnel_id=t.id \
                AND member.device_group_id=$1) ORDER BY h.tunnel_id,h.position,h.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let counts: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT t.id,COUNT(fr.id) FROM tunnels t \
             LEFT JOIN forward_rules fr ON fr.tunnel_id=t.id \
             WHERE t.enabled=TRUE AND EXISTS(SELECT 1 FROM tunnel_hops member \
               WHERE member.tunnel_id=t.id AND member.device_group_id=$1) GROUP BY t.id",
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
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
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
             WHERE t.enabled=FALSE \
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
             WHERE re.device_group_id=$1 \
               AND re.expires_at>=EXTRACT(EPOCH FROM now())::BIGINT \
               AND fr.tunnel_id=re.tunnel_id \
               AND source_tunnel.enabled=TRUE AND fr.paused=FALSE \
               AND u.banned=FALSE AND u.suspended=FALSE \
               AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
               AND (u.plan_expire_at IS NULL OR u.plan_expire_at> \
                 to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')) \
               AND (u.admin=TRUE OR (source_tunnel.shared=TRUE AND (u.all_device_groups=TRUE OR EXISTS( \
                 SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                   AND udg.device_group_id=re.device_group_id)))) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_rule_restart_entry_group_ids(&self, rule_id: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT device_group_in FROM forward_rules WHERE id=$1 \
             UNION SELECT device_group_id FROM forward_rule_retired_entries WHERE rule_id=$1 \
             ORDER BY 1",
        )
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
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE forward_rule_retired_entries SET expires_at=EXTRACT(EPOCH FROM now())::BIGINT+",
        );
        query
            .push_bind(ENTRY_DRAIN_LEASE_TTL_SECS)
            .push(" WHERE device_group_id=")
            .push_bind(group_id)
            .push(" AND expires_at>=EXTRACT(EPOCH FROM now())::BIGINT")
            .push(" AND rule_id IN (");
        let mut separated = query.separated(",");
        for rule_id in rule_ids {
            separated.push_bind(rule_id);
        }
        separated.push_unseparated(") AND EXISTS( \
          SELECT 1 FROM forward_rules fr \
          JOIN users u ON u.id=fr.uid \
          JOIN tunnels source_tunnel ON source_tunnel.id=forward_rule_retired_entries.tunnel_id \
          WHERE fr.id=forward_rule_retired_entries.rule_id \
            AND fr.tunnel_id=forward_rule_retired_entries.tunnel_id \
            AND source_tunnel.enabled=TRUE AND fr.paused=FALSE \
            AND u.banned=FALSE AND u.suspended=FALSE \
            AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
            AND (u.plan_expire_at IS NULL OR u.plan_expire_at> \
              to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')) \
            AND (u.admin=TRUE OR (source_tunnel.shared=TRUE AND (u.all_device_groups=TRUE OR EXISTS( \
              SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                AND udg.device_group_id=forward_rule_retired_entries.device_group_id)))))");
        Ok(query.build().execute(&self.pool).await?.rows_affected())
    }
}
