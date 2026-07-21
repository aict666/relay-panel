use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::{ForwardRule, ForwardRuleTarget};

// ── RuleRepository ──

#[async_trait]
impl RuleRepository for SqliteRepository {
    async fn list_rules(&self, scope: &ResourceScope) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules: Vec<ForwardRule> = match scope.owner_id() {
            None => sqlx::query_as("SELECT * FROM forward_rules ORDER BY id"),
            Some(uid) => {
                sqlx::query_as("SELECT * FROM forward_rules WHERE uid = ? ORDER BY id").bind(uid)
            }
        }
        .fetch_all(&self.pool)
        .await?;
        let tunnel_ids: std::collections::HashSet<i64> =
            rules.iter().filter_map(|rule| rule.tunnel_id).collect();
        let mut tunnel_cache = std::collections::HashMap::with_capacity(tunnel_ids.len());
        for tunnel_id in tunnel_ids {
            if let Some(tunnel) = self.find_tunnel_by_id(tunnel_id).await? {
                tunnel_cache.insert(tunnel_id, tunnel);
            }
        }
        for rule in &mut rules {
            rule.targets = self.list_rule_targets(rule.id, scope).await?;
            rule.hops = self.list_rule_hops_enriched(rule.id).await?;
            if let Some(tunnel_id) = rule.tunnel_id {
                if let Some(tunnel) = tunnel_cache.get(&tunnel_id) {
                    rule.tunnel_name = Some(tunnel.name.clone());
                    rule.tunnel_enabled = Some(tunnel.enabled);
                    rule.tunnel_shared = Some(tunnel.shared);
                    rule.tunnel_hops = tunnel
                        .hops
                        .iter()
                        .cloned()
                        .map(|mut hop| {
                            hop.connect_host = None;
                            hop
                        })
                        .collect();
                }
            }
        }
        Ok(rules)
    }

    async fn find_rule_by_id(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<ForwardRule>, DbError> {
        let mut rule: Option<ForwardRule> = match scope.owner_id() {
            None => sqlx::query_as("SELECT * FROM forward_rules WHERE id = ?").bind(rule_id),
            Some(uid) => sqlx::query_as("SELECT * FROM forward_rules WHERE id = ? AND uid = ?")
                .bind(rule_id)
                .bind(uid),
        }
        .fetch_optional(&self.pool)
        .await?;
        if let Some(r) = &mut rule {
            r.targets = self.list_rule_targets(r.id, scope).await?;
            r.hops = self.list_rule_hops_enriched(r.id).await?;
            if let Some(tunnel_id) = r.tunnel_id {
                if let Some(tunnel) = self.find_tunnel_by_id(tunnel_id).await? {
                    r.tunnel_name = Some(tunnel.name);
                    r.tunnel_enabled = Some(tunnel.enabled);
                    r.tunnel_shared = Some(tunnel.shared);
                    r.tunnel_hops = tunnel
                        .hops
                        .into_iter()
                        .map(|mut hop| {
                            hop.connect_host = None;
                            hop
                        })
                        .collect();
                }
            }
        }
        Ok(rule)
    }

    async fn list_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<relay_shared::models::ForwardRuleTarget>, DbError> {
        let targets = match scope.owner_id() {
            None => sqlx::query_as(
                "SELECT * FROM forward_rule_targets WHERE rule_id = ? ORDER BY position, id",
            )
            .bind(rule_id),
            Some(uid) => sqlx::query_as(
                "SELECT * FROM forward_rule_targets WHERE rule_id = ? AND EXISTS \
                 (SELECT 1 FROM forward_rules WHERE id = forward_rule_targets.rule_id AND uid = ?) \
                 ORDER BY position, id",
            )
            .bind(rule_id)
            .bind(uid),
        }
        .fetch_all(&self.pool)
        .await?;
        Ok(targets)
    }

    async fn list_enabled_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<relay_shared::models::ForwardRuleTarget>, DbError> {
        let targets = match scope.owner_id() {
            None => sqlx::query_as(
                "SELECT * FROM forward_rule_targets WHERE rule_id = ? AND enabled = 1 ORDER BY position, id",
            )
            .bind(rule_id),
            Some(uid) => sqlx::query_as(
                "SELECT * FROM forward_rule_targets WHERE rule_id = ? AND enabled = 1 AND EXISTS \
                 (SELECT 1 FROM forward_rules WHERE id = forward_rule_targets.rule_id AND uid = ?) \
                 ORDER BY position, id",
            )
            .bind(rule_id)
            .bind(uid),
        }
        .fetch_all(&self.pool)
        .await?;
        Ok(targets)
    }

    async fn replace_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        targets: &[relay_shared::protocol::RuleTargetRequest],
    ) -> Result<(), DbError> {
        // Scope guard: under Owner scope, no-op unless the rule is owned by uid.
        // Correctness over cleverness — a 0-row DELETE/INSERT under a foreign
        // rule would corrupt the rule's target list, so we bail before the tx.
        if let Some(uid) = scope.owner_id() {
            let owned: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM forward_rules WHERE id = ? AND uid = ?")
                    .bind(rule_id)
                    .bind(uid)
                    .fetch_optional(&self.pool)
                    .await?;
            if owned.is_none() {
                return Ok(());
            }
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM forward_rule_targets WHERE rule_id = ?")
            .bind(rule_id)
            .execute(&mut *tx)
            .await?;
        for (idx, target) in targets.iter().enumerate() {
            sqlx::query(
                "INSERT INTO forward_rule_targets (rule_id, host, port, position, enabled, weight) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(rule_id)
            .bind(target.host.trim())
            .bind(target.port as i32)
            .bind(idx as i32 + 1)
            .bind(target.enabled)
            .bind(target.weight.clamp(1, 100) as i32)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn set_rule_load_balance_strategy(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        strategy: &str,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("UPDATE forward_rules SET load_balance_strategy = ? WHERE id = ?")
                .bind(strategy)
                .bind(rule_id),
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET load_balance_strategy = ? WHERE id = ? AND uid = ?",
            )
            .bind(strategy)
            .bind(rule_id)
            .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn set_rule_rate_limits(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE forward_rules SET upload_limit_mbps = ?, download_limit_mbps = ? WHERE id = ?",
            )
            .bind(upload_limit_mbps)
            .bind(download_limit_mbps)
            .bind(rule_id),
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET upload_limit_mbps = ?, download_limit_mbps = ? \
                 WHERE id = ? AND uid = ?",
            )
            .bind(upload_limit_mbps)
            .bind(download_limit_mbps)
            .bind(rule_id)
            .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn set_rule_connection_controls(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        max_connections: i32,
        auto_restart_minutes: i32,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE forward_rules SET max_connections = ?, auto_restart_minutes = ? WHERE id = ?",
            )
            .bind(max_connections)
            .bind(auto_restart_minutes)
            .bind(rule_id),
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET max_connections = ?, auto_restart_minutes = ? \
                 WHERE id = ? AND uid = ?",
            )
            .bind(max_connections)
            .bind(auto_restart_minutes)
            .bind(rule_id)
            .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn list_auto_restart_rules(&self) -> Result<Vec<(i64, i64, i32)>, DbError> {
        // Paused rules are excluded here rather than at the scheduler: a paused
        // rule has no listener on any node, so restarting it would be a
        // guaranteed no-op that still costs a WS round-trip per node per tick.
        Ok(sqlx::query_as(
            "SELECT id, device_group_in, auto_restart_minutes FROM forward_rules \
             WHERE auto_restart_minutes > 0 AND paused = 0",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    async fn set_rule_tunnel_profile(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        profile_id: Option<i64>,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("UPDATE forward_rules SET tunnel_profile_id = ? WHERE id = ?")
                .bind(profile_id)
                .bind(rule_id),
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET tunnel_profile_id = ? WHERE id = ? AND uid = ?",
            )
            .bind(profile_id)
            .bind(rule_id)
            .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn list_group_port_protocols(
        &self,
        device_group_in: i64,
    ) -> Result<Vec<(i32, String)>, DbError> {
        // Entry listen ports on this group as inbound + any chain hop ports
        // that land on this group (intermediate/exit).
        let mut rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT listen_port, protocol FROM forward_rules WHERE device_group_in = ?",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        let hop_rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT h.listen_port, fr.protocol \
             FROM forward_rule_hops h \
             JOIN forward_rules fr ON fr.id = h.rule_id \
             WHERE h.device_group_id = ?",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        rows.extend(hop_rows);
        let tunnel_rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT tunnel_port, 'tcp' FROM forward_rule_hops \
             WHERE device_group_id = ? AND tunnel_port IS NOT NULL",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        rows.extend(tunnel_rows);
        let preset_tunnel_rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT listen_port, 'tcp' FROM tunnel_hops \
             WHERE device_group_id = ? AND listen_port IS NOT NULL",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        rows.extend(preset_tunnel_rows);
        let transition_rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT listen_port,protocol FROM forward_rule_route_transitions \
             WHERE device_group_id=? AND expires_at>=unixepoch()",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        rows.extend(transition_rows);
        Ok(rows)
    }

    async fn group_port_range(&self, group_id: i64) -> Result<Option<String>, DbError> {
        // port_range is TEXT NOT NULL, so the Option here reflects row existence
        // (missing group -> None), not a null column.
        let range: Option<String> =
            sqlx::query_scalar("SELECT port_range FROM device_groups WHERE id = ?")
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(range)
    }

    async fn count_by_uid(&self, uid: i64) -> Result<i64, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid = ?")
            .bind(uid)
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    async fn max_rules_for_uid(&self, uid: i64) -> Result<i32, DbError> {
        // COALESCE maps SQL NULL → 0. max_rules is NOT NULL in the schema, but
        // keep COALESCE for defense-in-depth against manual DB edits.
        let max_rules: i32 =
            sqlx::query_scalar("SELECT COALESCE(max_rules, 0) FROM users WHERE id = ?")
                .bind(uid)
                .fetch_one(&self.pool)
                .await?;
        Ok(max_rules)
    }

    async fn insert_quota_guarded(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        protocol: &str,
        public_transport: &str,
        node_transport: &str,
        route_mode: &str,
        entry_transport: &str,
        ws_path: Option<&str>,
        device_group_in: i64,
        device_group_out: Option<i64>,
        forward_mode: &str,
        target_addr: &str,
        target_port: i32,
    ) -> Result<u64, DbError> {
        // v0.4.11 PR4: socket-type the candidate occupies, derived from protocol.
        let needs_tcp = matches!(protocol, "tcp" | "tcp_udp");
        let needs_udp = matches!(protocol, "udp" | "tcp_udp");

        // BEGIN IMMEDIATE acquires the write lock up front, so the
        // port-conflict pre-check and the INSERT are indivisible against a
        // concurrent creator. A plain (deferred) BEGIN would only take the
        // lock at first write, leaving a check-then-insert TOCTOU window. The
        // partial unique indexes are still the authoritative DB-layer backstop.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        // Port-conflict pre-check: same inbound group + same port + an
        // overlapping socket type (TCP-bearing vs TCP-bearing, UDP-bearing vs
        // UDP-bearing). A pure-TCP and a pure-UDP rule do NOT conflict.
        let conflict: Result<Option<(i64,)>, sqlx::Error> = sqlx::query_as(
            "SELECT 1 WHERE EXISTS(SELECT 1 FROM forward_rules \
               WHERE device_group_in=? AND listen_port=? \
                 AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                   OR (?=1 AND protocol IN ('udp','tcp_udp')))) \
             OR EXISTS(SELECT 1 FROM forward_rule_route_transitions \
               WHERE device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                 AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                   OR (?=1 AND protocol IN ('udp','tcp_udp')))) LIMIT 1",
        )
        .bind(device_group_in)
        .bind(listen_port)
        .bind(needs_tcp as i32)
        .bind(needs_udp as i32)
        .bind(device_group_in)
        .bind(listen_port)
        .bind(needs_tcp as i32)
        .bind(needs_udp as i32)
        .fetch_optional(&mut *conn)
        .await;
        match conflict {
            Ok(Some(_)) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            }
            Ok(None) => {}
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e.into());
            }
        }

        // Atomic quota-guarded INSERT: the WHERE clause is evaluated as part of
        // the same statement. max_rules = 0 means unlimited. If the quota is
        // full the SELECT yields no rows → 0 rows affected, which the caller
        // translates to a 400. Parameters are bound in SQL order: first the row
        // values, then the three uid params used by the WHERE subqueries.
        let result = sqlx::query(
            "INSERT INTO forward_rules \
               (name, uid, listen_port, protocol, public_transport, node_transport, \
                route_mode, entry_transport, ws_path, \
                device_group_in, device_group_out, forward_mode, target_addr, target_port) \
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? \
             WHERE (SELECT max_rules FROM users WHERE id = ?) = 0 \
                OR (SELECT COUNT(*) FROM forward_rules WHERE uid = ?) \
                   < (SELECT max_rules FROM users WHERE id = ?)",
        )
        .bind(name)
        .bind(uid)
        .bind(listen_port)
        .bind(protocol)
        .bind(public_transport)
        .bind(node_transport)
        .bind(route_mode)
        .bind(entry_transport) // legacy entry_transport mirrors public_transport
        .bind(ws_path)
        .bind(device_group_in)
        .bind(device_group_out)
        .bind(forward_mode)
        .bind(target_addr)
        .bind(target_port)
        .bind(uid) // max_rules subquery (unlimited check)
        .bind(uid) // COUNT(*) subquery
        .bind(uid) // max_rules subquery (limit check)
        .execute(&mut *conn)
        .await;

        match result {
            Ok(r) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(r.rows_affected())
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e.into())
            }
        }
    }

    async fn create_rule_full_with_tunnel(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        protocol: &str,
        public_transport: &str,
        node_transport: &str,
        route_mode: &str,
        entry_transport: &str,
        ws_path: Option<&str>,
        device_group_in: i64,
        device_group_out: Option<i64>,
        forward_mode: &str,
        target_addr: &str,
        target_port: i32,
        targets: &[relay_shared::protocol::RuleTargetRequest],
        hops: &[(i64, i32)],
        load_balance_strategy: &str,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
        tunnel_profile_id: Option<i64>,
        tunnel_id: Option<i64>,
        max_connections: i32,
        auto_restart_minutes: i32,
    ) -> Result<Option<i64>, DbError> {
        // v1.2: atomic create. Same BEGIN IMMEDIATE + conflict pre-check +
        // quota-guarded INSERT shape as insert_quota_guarded, but the INSERT is
        // followed by the targets / LB / rate-limit / tunnel writes INSIDE the
        // same transaction, and the new row's id comes from last_insert_rowid()
        // instead of a post-commit (owner_uid, listen_port) re-lookup (which
        // was wrong when two inbound groups reused a port — see trait docs).

        let needs_tcp = matches!(protocol, "tcp" | "tcp_udp");
        let needs_udp = matches!(protocol, "udp" | "tcp_udp");

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        // Convert any sqlx error into a ROLLBACK + DbError early return, so the
        // body stays linear (no per-statement match arms). The macro evaluates
        // to `!` (it always returns), so `try_!(expr)` is well-typed for any
        // sqlx::Error-producing statement.
        macro_rules! try_ {
            ($conn:expr, $expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *$conn).await;
                        return Err(DbError::from(e));
                    }
                }
            };
        }

        // The API/service checks these predicates for an early, friendly
        // rejection. Re-evaluate them after BEGIN IMMEDIATE so revoking the
        // owner's grant or changing the group between that check and INSERT
        // cannot leave a newly-active unauthorized rule.
        let owner: Option<(bool, bool, bool)> = try_!(
            conn,
            sqlx::query_as("SELECT admin,all_device_groups,banned FROM users WHERE id=?",)
                .bind(uid)
                .fetch_optional(&mut *conn)
                .await
        );
        let Some((owner_is_admin, owner_all_groups, owner_banned)) = owner else {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::RuleGroupAccessDenied);
        };
        if owner_banned {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::RuleGroupAccessDenied);
        }
        let valid_entry: Option<i64> = try_!(
            conn,
            sqlx::query_scalar(
                "SELECT dg.id FROM device_groups dg \
                 JOIN users group_owner ON group_owner.id=dg.uid \
                 WHERE dg.id=? AND dg.group_type IN ('in','both') \
                   AND group_owner.admin=1",
            )
            .bind(device_group_in)
            .fetch_optional(&mut *conn)
            .await
        );
        if valid_entry.is_none() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::RuleGroupUnavailable);
        }
        if !owner_is_admin && !owner_all_groups {
            let authorized: Option<i64> = try_!(
                conn,
                sqlx::query_scalar(
                    "SELECT 1 FROM user_device_groups \
                     WHERE user_id=? AND device_group_id=?",
                )
                .bind(uid)
                .bind(device_group_in)
                .fetch_optional(&mut *conn)
                .await
            );
            if authorized.is_none() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::RuleGroupAccessDenied);
            }
        }
        for (position, (group_id, _)) in hops.iter().enumerate().skip(1) {
            let valid: Option<i64> = try_!(
                conn,
                sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users owner ON owner.id=dg.uid \
                     WHERE dg.id=? AND dg.group_type<>'monitor' \
                       AND TRIM(dg.connect_host)<>'' AND owner.admin=1",
                )
                .bind(group_id)
                .fetch_optional(&mut *conn)
                .await
            );
            if valid.is_none() {
                tracing::debug!("create_rule_full: invalid downstream hop at {position}");
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::RuleGroupUnavailable);
            }
        }

        if let Some(profile_id) = tunnel_profile_id {
            if protocol != "tcp" {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::ProfileUnavailable);
            }
            let valid: Option<i64> = try_!(
                conn,
                sqlx::query_scalar(
                    "SELECT id FROM tunnel_profiles WHERE id = ? AND transport = ?",
                )
                .bind(profile_id)
                .bind(public_transport)
                .fetch_optional(&mut *conn)
                .await
            );
            if valid.is_none() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::ProfileUnavailable);
            }
        }

        // The service resolves preset topology before opening this transaction,
        // but an administrator may edit/disable it concurrently. Re-read the
        // complete derived endpoints while holding SQLite's writer lock.
        if let Some(tunnel_id) = tunnel_id {
            let topology: Option<(bool, bool, i64, i64)> = try_!(
                conn,
                sqlx::query_as(
                    "SELECT t.enabled, \
                       (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS \
                         (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id AND udg.device_group_id=entry.device_group_id)))), \
                       entry.device_group_id, exit.device_group_id \
                     FROM tunnels t \
                     JOIN users u ON u.id=? \
                     JOIN tunnel_hops entry ON entry.tunnel_id=t.id AND entry.position=0 \
                     JOIN tunnel_hops exit ON exit.tunnel_id=t.id \
                       AND exit.position=(SELECT MAX(position) FROM tunnel_hops WHERE tunnel_id=t.id) \
                     WHERE t.id=? \
                       AND (SELECT COUNT(*) FROM tunnel_hops h WHERE h.tunnel_id=t.id) BETWEEN 2 AND 8 \
                       AND (SELECT COUNT(DISTINCT h.device_group_id) FROM tunnel_hops h WHERE h.tunnel_id=t.id) = \
                           (SELECT COUNT(*) FROM tunnel_hops h WHERE h.tunnel_id=t.id) \
                       AND NOT EXISTS (SELECT 1 FROM tunnel_hops checked \
                         JOIN device_groups dg ON dg.id=checked.device_group_id \
                         JOIN users owner ON owner.id=dg.uid \
                         WHERE checked.tunnel_id=t.id AND (owner.admin<>1 \
                           OR (checked.position=0 AND (dg.group_type NOT IN ('in','both') OR checked.listen_port IS NOT NULL)) \
                           OR (checked.position>0 AND (dg.group_type='monitor' OR TRIM(dg.connect_host)='' OR checked.listen_port IS NULL))))",
                )
                .bind(uid)
                .bind(tunnel_id)
                .fetch_optional(&mut *conn)
                .await
            );
            match topology {
                Some((true, true, entry, exit))
                    if entry == device_group_in && Some(exit) == device_group_out => {}
                Some((true, false, entry, exit))
                    if entry == device_group_in && Some(exit) == device_group_out =>
                {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::TunnelAccessDenied);
                }
                _ => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::TunnelUnavailable);
                }
            }
        }

        // Port-conflict pre-check (socket-type aware, scoped to the group).
        let conflict: Option<(i64,)> = try_!(
            conn,
            sqlx::query_as(
                "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM forward_rules \
                   WHERE device_group_in=? AND listen_port=? \
                     AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                       OR (?=1 AND protocol IN ('udp','tcp_udp')))) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id \
                   WHERE h.device_group_id=? AND h.listen_port=? \
                     AND ((?=1 AND r.protocol IN ('tcp','tcp_udp')) \
                       OR (?=1 AND r.protocol IN ('udp','tcp_udp')))) \
                 OR (?=1 AND EXISTS (SELECT 1 FROM forward_rule_hops \
                   WHERE device_group_id=? AND tunnel_port=?)) \
                 OR (?=1 AND EXISTS (SELECT 1 FROM tunnel_hops \
                   WHERE device_group_id=? AND listen_port=?)) \
                 OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                   WHERE device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                     AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                       OR (?=1 AND protocol IN ('udp','tcp_udp')))) LIMIT 1",
            )
            .bind(device_group_in)
            .bind(listen_port)
            .bind(needs_tcp as i32)
            .bind(needs_udp as i32)
            .bind(device_group_in)
            .bind(listen_port)
            .bind(needs_tcp as i32)
            .bind(needs_udp as i32)
            .bind(needs_tcp as i32)
            .bind(device_group_in)
            .bind(listen_port)
            .bind(needs_tcp as i32)
            .bind(device_group_in)
            .bind(listen_port)
            .bind(device_group_in)
            .bind(listen_port)
            .bind(needs_tcp as i32)
            .bind(needs_udp as i32)
            .fetch_optional(&mut *conn)
            .await
        );
        if conflict.is_some() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::PortConflict);
        }
        for (group_id, hop_port) in hops {
            let hop_conflict: Option<(i64,)> = try_!(
                conn,
                sqlx::query_as(
                    "SELECT 1 WHERE \
                     EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in=? AND listen_port=? \
                       AND ((?=1 AND protocol IN ('tcp','tcp_udp')) OR (?=1 AND protocol IN ('udp','tcp_udp')))) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id \
                       WHERE h.device_group_id=? AND h.listen_port=? \
                       AND ((?=1 AND r.protocol IN ('tcp','tcp_udp')) OR (?=1 AND r.protocol IN ('udp','tcp_udp')))) \
                     OR (?=1 AND EXISTS (SELECT 1 FROM forward_rule_hops WHERE device_group_id=? AND tunnel_port=?)) \
                     OR (?=1 AND EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=? AND listen_port=?)) \
                     OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                       WHERE device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                         AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                           OR (?=1 AND protocol IN ('udp','tcp_udp')))) LIMIT 1",
                )
                .bind(group_id).bind(hop_port).bind(needs_tcp as i32).bind(needs_udp as i32)
                .bind(group_id).bind(hop_port).bind(needs_tcp as i32).bind(needs_udp as i32)
                .bind(needs_tcp as i32).bind(group_id).bind(hop_port)
                .bind(needs_tcp as i32).bind(group_id).bind(hop_port)
                .bind(group_id).bind(hop_port).bind(needs_tcp as i32).bind(needs_udp as i32)
                .fetch_optional(&mut *conn)
                .await
            );
            if hop_conflict.is_some() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            }
        }

        // Atomic quota-guarded INSERT. 0 rows affected ⇒ quota exhausted.
        let result = try_!(
            conn,
            sqlx::query(
                "INSERT INTO forward_rules \
                   (name, uid, listen_port, protocol, public_transport, node_transport, \
                    route_mode, entry_transport, ws_path, \
                    device_group_in, device_group_out, forward_mode, target_addr, target_port, tunnel_id) \
                 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? \
                 WHERE (SELECT max_rules FROM users WHERE id = ?) = 0 \
                    OR (SELECT COUNT(*) FROM forward_rules WHERE uid = ?) \
                       < (SELECT max_rules FROM users WHERE id = ?)",
            )
            .bind(name)
            .bind(uid)
            .bind(listen_port)
            .bind(protocol)
            .bind(public_transport)
            .bind(node_transport)
            .bind(route_mode)
            .bind(entry_transport)
            .bind(ws_path)
            .bind(device_group_in)
            .bind(device_group_out)
            .bind(forward_mode)
            .bind(target_addr)
            .bind(target_port)
            .bind(tunnel_id)
            .bind(uid)
            .bind(uid)
            .bind(uid)
            .execute(&mut *conn)
            .await
        );

        if result.rows_affected() == 0 {
            // Quota exhausted — nothing was inserted. The tx made no writes, so
            // COMMIT it cleanly and report None to the caller.
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            return Ok(None);
        }
        let rule_id = result.last_insert_rowid();

        // Targets: DELETE-then-INSERT keeps the SQL identical to
        // replace_rule_targets (the row is brand new, so there are none).
        try_!(
            conn,
            sqlx::query("DELETE FROM forward_rule_targets WHERE rule_id = ?")
                .bind(rule_id)
                .execute(&mut *conn)
                .await
        );
        for (idx, target) in targets.iter().enumerate() {
            try_!(
                conn,
                sqlx::query(
                    "INSERT INTO forward_rule_targets (rule_id, host, port, position, enabled, weight) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(rule_id)
                .bind(target.host.trim())
                .bind(target.port as i32)
                .bind(idx as i32 + 1)
                .bind(target.enabled)
                .bind(target.weight.clamp(1, 100) as i32)
                .execute(&mut *conn)
                .await
            );
        }

        // Chain hops belong to the same atomic create as the rule and targets.
        // Any FK/constraint/database failure rolls back the rule row too.
        for (position, (group_id, hop_port)) in hops.iter().enumerate() {
            try_!(
                conn,
                sqlx::query(
                    "INSERT INTO forward_rule_hops \
                     (rule_id, position, device_group_id, listen_port) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(rule_id)
                .bind(position as i32)
                .bind(group_id)
                .bind(hop_port)
                .execute(&mut *conn)
                .await
            );
        }

        // Load-balance strategy: only written when not "first" (the column
        // default), matching the service's pre-v1.2 conditional.
        if load_balance_strategy != "first" {
            try_!(
                conn,
                sqlx::query("UPDATE forward_rules SET load_balance_strategy = ? WHERE id = ?")
                    .bind(load_balance_strategy)
                    .bind(rule_id)
                    .execute(&mut *conn)
                    .await
            );
        }

        // Rate limits: only written when either cap is non-zero (0 = unlimited
        // = the column default).
        if upload_limit_mbps != 0 || download_limit_mbps != 0 {
            try_!(
                conn,
                sqlx::query(
                    "UPDATE forward_rules SET upload_limit_mbps = ?, download_limit_mbps = ? \
                     WHERE id = ?",
                )
                .bind(upload_limit_mbps)
                .bind(download_limit_mbps)
                .bind(rule_id)
                .execute(&mut *conn)
                .await
            );
        }

        // Connection controls are part of the same atomic create. Keeping the
        // update in this transaction avoids the old create-then-edit workflow
        // and guarantees a write failure cannot leave a partially configured
        // rule behind.
        if max_connections != 0 || auto_restart_minutes != 0 {
            try_!(
                conn,
                sqlx::query(
                    "UPDATE forward_rules SET max_connections = ?, auto_restart_minutes = ? \
                     WHERE id = ?",
                )
                .bind(max_connections)
                .bind(auto_restart_minutes)
                .bind(rule_id)
                .execute(&mut *conn)
                .await
            );
        }

        // Tunnel profile: only written when Some (Raw transport rules never
        // reach here with a profile — the service rejects that combination
        // earlier).
        if let Some(pid) = tunnel_profile_id {
            try_!(
                conn,
                sqlx::query("UPDATE forward_rules SET tunnel_profile_id = ? WHERE id = ?")
                    .bind(pid)
                    .bind(rule_id)
                    .execute(&mut *conn)
                    .await
            );
        }

        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(Some(rule_id))
    }

    async fn find_transport_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<(String, String)>, DbError> {
        let row: Option<(String, String)> = match scope.owner_id() {
            None => {
                sqlx::query_as("SELECT protocol, public_transport FROM forward_rules WHERE id = ?")
                    .bind(id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT protocol, public_transport FROM forward_rules WHERE id = ? AND uid = ?",
            )
            .bind(id)
            .bind(uid),
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn find_device_group_out_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<Option<i64>>, DbError> {
        let row: Option<(Option<i64>,)> = match scope.owner_id() {
            None => {
                sqlx::query_as("SELECT device_group_out FROM forward_rules WHERE id = ?").bind(id)
            }
            Some(uid) => sqlx::query_as(
                "SELECT device_group_out FROM forward_rules WHERE id = ? AND uid = ?",
            )
            .bind(id)
            .bind(uid),
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(v,)| v))
    }

    async fn update_rule_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        listen_port: Option<i32>,
        protocol: Option<&str>,
        public_transport: Option<&str>,
        node_transport: Option<&str>,
        entry_transport: Option<&str>,
        route_mode: Option<&str>,
        ws_path: Option<Option<&str>>,
        device_group_in: Option<i64>,
        device_group_out: Option<Option<i64>>,
        forward_mode: Option<&str>,
        target_addr: Option<&str>,
        target_port: Option<i32>,
        paused: Option<bool>,
    ) -> Result<u64, DbError> {
        // Build the SET clause from the present fields, in the SAME order the
        // values are bound below. public_transport carries the two derived
        // mirror columns (node_transport, entry_transport) whenever it is set.
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ?");
        }
        if listen_port.is_some() {
            sets.push("listen_port = ?");
        }
        if protocol.is_some() {
            sets.push("protocol = ?");
        }
        if public_transport.is_some() {
            sets.push("public_transport = ?");
            sets.push("node_transport = ?");
            sets.push("entry_transport = ?");
        }
        if route_mode.is_some() {
            sets.push("route_mode = ?");
        }
        if ws_path.is_some() {
            sets.push("ws_path = ?");
        }
        if device_group_in.is_some() {
            sets.push("device_group_in = ?");
        }
        if device_group_out.is_some() {
            sets.push("device_group_out = ?");
        }
        if forward_mode.is_some() {
            sets.push("forward_mode = ?");
        }
        if target_addr.is_some() {
            sets.push("target_addr = ?");
        }
        if target_port.is_some() {
            sets.push("target_port = ?");
        }
        if paused.is_some() {
            sets.push("paused = ?");
            // v1.0.8: an explicit paused write is always a human action (the
            // on/off switch, batch pause/resume) — clear auto_paused so a later
            // buy_plan re-authorization doesn't treat this rule as something IT
            // needs to reconcile.
            sets.push("auto_paused = 0");
        }

        if sets.is_empty() {
            return Ok(0);
        }

        let sql = match scope.owner_id() {
            None => format!("UPDATE forward_rules SET {} WHERE id = ?", sets.join(", ")),
            Some(_) => format!(
                "UPDATE forward_rules SET {} WHERE id = ? AND uid = ?",
                sets.join(", ")
            ),
        };
        let mut q = sqlx::query(&sql);
        if let Some(v) = name {
            q = q.bind(v);
        }
        if let Some(v) = listen_port {
            q = q.bind(v);
        }
        if let Some(v) = protocol {
            q = q.bind(v);
        }
        // public_transport: bind THREE values (public, derived node, legacy mirror).
        if let Some(v) = public_transport {
            q = q.bind(v);
            q = q.bind(node_transport.unwrap_or(v));
            q = q.bind(entry_transport.unwrap_or(v));
        }
        if let Some(v) = route_mode {
            q = q.bind(v);
        }
        // ws_path: outer Some → "update this column"; inner None → NULL.
        if let Some(v) = ws_path {
            q = q.bind(v);
        }
        if let Some(v) = device_group_in {
            q = q.bind(v);
        }
        if let Some(v) = device_group_out {
            q = q.bind(v);
        }
        if let Some(v) = forward_mode {
            q = q.bind(v);
        }
        if let Some(v) = target_addr {
            q = q.bind(v);
        }
        if let Some(v) = target_port {
            q = q.bind(v);
        }
        if let Some(v) = paused {
            q = q.bind(v);
        }
        q = q.bind(id);
        if let Some(uid) = scope.owner_id() {
            q = q.bind(uid);
        }

        let result = q.execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn update_rule_full(&self, update: &RuleUpdateData) -> Result<u64, DbError> {
        if update.is_pause_only() {
            let result = if let Some(uid) = update.owner_uid {
                sqlx::query("UPDATE forward_rules SET paused=1,auto_paused=0 WHERE id=? AND uid=?")
                    .bind(update.id)
                    .bind(uid)
                    .execute(&self.pool)
                    .await?
            } else {
                sqlx::query("UPDATE forward_rules SET paused=1,auto_paused=0 WHERE id=?")
                    .bind(update.id)
                    .execute(&self.pool)
                    .await?
            };
            return Ok(result.rows_affected());
        }

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

        let existing: Option<(
            i64,
            String,
            i32,
            i64,
            Option<i64>,
            Option<i64>,
            bool,
            String,
            String,
            Option<i64>,
        )> = if let Some(uid) = update.owner_uid {
            try_!(
                    sqlx::query_as(
                        "SELECT uid,protocol,listen_port,device_group_in,device_group_out,tunnel_id,paused,route_mode,public_transport,tunnel_profile_id \
                     FROM forward_rules WHERE id=? AND uid=?",
                    )
                    .bind(update.id)
                    .bind(uid)
                    .fetch_optional(&mut *conn)
                    .await
                )
        } else {
            try_!(
                    sqlx::query_as(
                        "SELECT uid,protocol,listen_port,device_group_in,device_group_out,tunnel_id,paused,route_mode,public_transport,tunnel_profile_id \
                     FROM forward_rules WHERE id=?",
                    )
                    .bind(update.id)
                    .fetch_optional(&mut *conn)
                    .await
                )
        };
        let Some((
            rule_owner_id,
            old_protocol,
            old_port,
            old_group,
            old_out,
            old_tunnel_id,
            old_paused,
            old_route_mode,
            old_public_transport,
            old_profile_id,
        )) = existing
        else {
            try_!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
            return Ok(0);
        };
        let effective_protocol = update.protocol.as_deref().unwrap_or(&old_protocol);
        let effective_port = update.listen_port.unwrap_or(old_port);
        let effective_group = update.device_group_in.unwrap_or(old_group);
        let effective_out = update.device_group_out.unwrap_or(old_out);
        let effective_tunnel_id = update.tunnel_id.unwrap_or(old_tunnel_id);
        let effective_paused = update.paused.unwrap_or(old_paused);
        let effective_route_mode = update.route_mode.as_deref().unwrap_or(&old_route_mode);
        let route_update_requested = update.protocol.is_some()
            || update.tunnel_id.is_some()
            || update.hops.is_some()
            || update.route_mode.is_some()
            || update.device_group_in.is_some()
            || update.device_group_out.is_some();
        let authorization_required = route_update_requested || (old_paused && !effective_paused);
        if authorization_required {
            let owner: Option<(bool, bool, bool)> = try_!(
                sqlx::query_as("SELECT admin,all_device_groups,banned FROM users WHERE id=?",)
                    .bind(rule_owner_id)
                    .fetch_optional(&mut *conn)
                    .await
            );
            let Some((owner_is_admin, owner_all_groups, owner_banned)) = owner else {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::RuleGroupAccessDenied);
            };
            let valid_entry: Option<i64> = try_!(
                sqlx::query_scalar(
                    "SELECT dg.id FROM device_groups dg \
                     JOIN users group_owner ON group_owner.id=dg.uid \
                     WHERE dg.id=? AND dg.group_type IN ('in','both') \
                       AND group_owner.admin=1",
                )
                .bind(effective_group)
                .fetch_optional(&mut *conn)
                .await
            );
            if valid_entry.is_none() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::RuleGroupUnavailable);
            }
            if owner_banned || (!owner_is_admin && !owner_all_groups) {
                let authorized: Option<i64> = if owner_banned {
                    None
                } else {
                    try_!(
                        sqlx::query_scalar(
                            "SELECT 1 FROM user_device_groups \
                             WHERE user_id=? AND device_group_id=?",
                        )
                        .bind(rule_owner_id)
                        .bind(effective_group)
                        .fetch_optional(&mut *conn)
                        .await
                    )
                };
                if authorized.is_none() {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::RuleGroupAccessDenied);
                }
            }
            if effective_tunnel_id.is_none() && effective_route_mode == "chain" {
                let downstream_groups: Vec<i64> = if let Some(hops) = &update.hops {
                    hops.iter().skip(1).map(|(group_id, _)| *group_id).collect()
                } else {
                    try_!(
                        sqlx::query_scalar(
                            "SELECT device_group_id FROM forward_rule_hops \
                             WHERE rule_id=? AND position>0 ORDER BY position",
                        )
                        .bind(update.id)
                        .fetch_all(&mut *conn)
                        .await
                    )
                };
                for group_id in downstream_groups {
                    let valid: Option<i64> = try_!(
                        sqlx::query_scalar(
                            "SELECT dg.id FROM device_groups dg \
                             JOIN users owner ON owner.id=dg.uid \
                             WHERE dg.id=? AND dg.group_type<>'monitor' \
                               AND TRIM(dg.connect_host)<>'' AND owner.admin=1",
                        )
                        .bind(group_id)
                        .fetch_optional(&mut *conn)
                        .await
                    );
                    if valid.is_none() {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::RuleGroupUnavailable);
                    }
                }
            }
        }
        let effective_public_transport = update
            .public_transport
            .as_deref()
            .unwrap_or(&old_public_transport);
        let effective_profile_id = update.tunnel_profile_id.unwrap_or(old_profile_id);
        if let Some(profile_id) = effective_profile_id {
            if effective_protocol != "tcp" {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::ProfileUnavailable);
            }
            let valid: Option<i64> = try_!(
                sqlx::query_scalar(
                    "SELECT id FROM tunnel_profiles WHERE id = ? AND transport = ?",
                )
                .bind(profile_id)
                .bind(effective_public_transport)
                .fetch_optional(&mut *conn)
                .await
            );
            if valid.is_none() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::ProfileUnavailable);
            }
        }
        let mut old_downstream_ports: Vec<(i64, i32, String)> =
            if route_update_requested && !old_paused {
                if let Some(tunnel_id) = old_tunnel_id {
                    try_!(
                        sqlx::query_as(
                            "SELECT device_group_id,listen_port,'tcp' FROM tunnel_hops \
                         WHERE tunnel_id=? AND position>0 AND listen_port IS NOT NULL \
                         ORDER BY position",
                        )
                        .bind(tunnel_id)
                        .fetch_all(&mut *conn)
                        .await
                    )
                } else if old_route_mode == "chain" {
                    try_!(
                        sqlx::query_as(
                            "SELECT device_group_id,listen_port,? FROM forward_rule_hops \
                         WHERE rule_id=? AND position>0 \
                         UNION ALL SELECT device_group_id,tunnel_port,'tcp' \
                         FROM forward_rule_hops WHERE rule_id=? AND position>0 \
                           AND tunnel_port IS NOT NULL",
                        )
                        .bind(&old_protocol)
                        .bind(update.id)
                        .bind(update.id)
                        .fetch_all(&mut *conn)
                        .await
                    )
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
        let needs_tcp = matches!(effective_protocol, "tcp" | "tcp_udp");
        let needs_udp = matches!(effective_protocol, "udp" | "tcp_udp");

        if let Some(tunnel_id) = effective_tunnel_id {
            let topology: Option<(bool, bool, i64, i64)> = try_!(
                sqlx::query_as(
                    "SELECT t.enabled, \
                       (u.admin=1 OR (t.shared=1 AND (u.all_device_groups=1 OR EXISTS \
                         (SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id AND udg.device_group_id=entry.device_group_id)))), \
                       entry.device_group_id, exit.device_group_id \
                     FROM tunnels t \
                     JOIN users u ON u.id=(SELECT uid FROM forward_rules WHERE id=?) \
                     JOIN tunnel_hops entry ON entry.tunnel_id=t.id AND entry.position=0 \
                     JOIN tunnel_hops exit ON exit.tunnel_id=t.id \
                       AND exit.position=(SELECT MAX(position) FROM tunnel_hops WHERE tunnel_id=t.id) \
                     WHERE t.id=? \
                       AND (SELECT COUNT(*) FROM tunnel_hops h WHERE h.tunnel_id=t.id) BETWEEN 2 AND 8 \
                       AND (SELECT COUNT(DISTINCT h.device_group_id) FROM tunnel_hops h WHERE h.tunnel_id=t.id) = \
                           (SELECT COUNT(*) FROM tunnel_hops h WHERE h.tunnel_id=t.id) \
                       AND NOT EXISTS (SELECT 1 FROM tunnel_hops checked \
                         JOIN device_groups dg ON dg.id=checked.device_group_id \
                         JOIN users owner ON owner.id=dg.uid \
                         WHERE checked.tunnel_id=t.id AND (owner.admin<>1 \
                           OR (checked.position=0 AND (dg.group_type NOT IN ('in','both') OR checked.listen_port IS NOT NULL)) \
                           OR (checked.position>0 AND (dg.group_type='monitor' OR TRIM(dg.connect_host)='' OR checked.listen_port IS NULL))))",
                )
                .bind(update.id)
                .bind(tunnel_id)
                .fetch_optional(&mut *conn)
                .await
            );
            let enabled_required = old_tunnel_id != Some(tunnel_id);
            let access_required = enabled_required || update.paused == Some(false);
            match topology {
                Some((enabled, allowed, entry, exit))
                    if (!enabled_required || enabled)
                        && entry == effective_group
                        && Some(exit) == effective_out =>
                {
                    if access_required && !allowed {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::TunnelAccessDenied);
                    }
                }
                _ => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(DbError::TunnelUnavailable);
                }
            }
        }

        let conflict: Option<(i64,)> = try_!(
            sqlx::query_as(
                "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM forward_rules WHERE id<>? AND device_group_in=? AND listen_port=? \
                   AND ((?=1 AND protocol IN ('tcp','tcp_udp')) OR (?=1 AND protocol IN ('udp','tcp_udp')))) \
                 OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id \
                   WHERE h.rule_id<>? AND h.device_group_id=? AND h.listen_port=? \
                   AND ((?=1 AND r.protocol IN ('tcp','tcp_udp')) OR (?=1 AND r.protocol IN ('udp','tcp_udp')))) \
                 OR (?=1 AND EXISTS (SELECT 1 FROM forward_rule_hops WHERE rule_id<>? AND device_group_id=? AND tunnel_port=?)) \
                 OR (?=1 AND EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=? AND listen_port=?)) \
                 OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                   WHERE rule_id<>? AND device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                     AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                       OR (?=1 AND protocol IN ('udp','tcp_udp')))) LIMIT 1",
            )
            .bind(update.id).bind(effective_group).bind(effective_port)
            .bind(needs_tcp as i32).bind(needs_udp as i32)
            .bind(update.id).bind(effective_group).bind(effective_port)
            .bind(needs_tcp as i32).bind(needs_udp as i32)
            .bind(needs_tcp as i32).bind(update.id).bind(effective_group).bind(effective_port)
            .bind(needs_tcp as i32).bind(effective_group).bind(effective_port)
            .bind(update.id).bind(effective_group).bind(effective_port)
            .bind(needs_tcp as i32).bind(needs_udp as i32)
            .fetch_optional(&mut *conn)
            .await
        );
        if conflict.is_some() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::PortConflict);
        }

        let effective_hops = if let Some(hops) = &update.hops {
            hops.clone()
        } else {
            try_!(
                sqlx::query_as::<_, (i64, i32)>(
                    "SELECT device_group_id,listen_port FROM forward_rule_hops WHERE rule_id=? ORDER BY position",
                )
                .bind(update.id)
                .fetch_all(&mut *conn)
                .await
            )
        };
        for (group_id, port) in &effective_hops {
            let conflict: Option<(i64,)> = try_!(
                sqlx::query_as(
                    "SELECT 1 WHERE \
                     EXISTS (SELECT 1 FROM forward_rules WHERE id<>? AND device_group_in=? AND listen_port=? \
                       AND ((?=1 AND protocol IN ('tcp','tcp_udp')) OR (?=1 AND protocol IN ('udp','tcp_udp')))) \
                     OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id \
                       WHERE h.rule_id<>? AND h.device_group_id=? AND h.listen_port=? \
                       AND ((?=1 AND r.protocol IN ('tcp','tcp_udp')) OR (?=1 AND r.protocol IN ('udp','tcp_udp')))) \
                     OR (?=1 AND EXISTS (SELECT 1 FROM forward_rule_hops WHERE rule_id<>? AND device_group_id=? AND tunnel_port=?)) \
                     OR (?=1 AND EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=? AND listen_port=?)) \
                     OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
                       WHERE rule_id<>? AND device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                         AND ((?=1 AND protocol IN ('tcp','tcp_udp')) \
                           OR (?=1 AND protocol IN ('udp','tcp_udp')))) LIMIT 1",
                )
                .bind(update.id).bind(group_id).bind(port).bind(needs_tcp as i32).bind(needs_udp as i32)
                .bind(update.id).bind(group_id).bind(port).bind(needs_tcp as i32).bind(needs_udp as i32)
                .bind(needs_tcp as i32).bind(update.id).bind(group_id).bind(port)
                .bind(needs_tcp as i32).bind(group_id).bind(port)
                .bind(update.id).bind(group_id).bind(port)
                .bind(needs_tcp as i32).bind(needs_udp as i32)
                .fetch_optional(&mut *conn)
                .await
            );
            if conflict.is_some() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(DbError::PortConflict);
            }
        }

        let mut sets: Vec<&str> = Vec::new();
        if update.name.is_some() {
            sets.push("name = ?");
        }
        if update.listen_port.is_some() {
            sets.push("listen_port = ?");
        }
        if update.protocol.is_some() {
            sets.push("protocol = ?");
        }
        if update.public_transport.is_some() {
            sets.extend([
                "public_transport = ?",
                "node_transport = ?",
                "entry_transport = ?",
            ]);
        }
        if update.route_mode.is_some() {
            sets.push("route_mode = ?");
        }
        if update.ws_path.is_some() {
            sets.push("ws_path = ?");
        }
        if update.device_group_in.is_some() {
            sets.push("device_group_in = ?");
        }
        if update.device_group_out.is_some() {
            sets.push("device_group_out = ?");
        }
        if update.forward_mode.is_some() {
            sets.push("forward_mode = ?");
        }
        if update.target_addr.is_some() {
            sets.push("target_addr = ?");
        }
        if update.target_port.is_some() {
            sets.push("target_port = ?");
        }
        if update.paused.is_some() {
            sets.extend(["paused = ?", "auto_paused = 0"]);
        }

        let rows = if sets.is_empty() {
            let found: Option<i64> = if let Some(uid) = update.owner_uid {
                try_!(
                    sqlx::query_scalar("SELECT id FROM forward_rules WHERE id = ? AND uid = ?",)
                        .bind(update.id)
                        .bind(uid)
                        .fetch_optional(&mut *conn)
                        .await
                )
            } else {
                try_!(
                    sqlx::query_scalar("SELECT id FROM forward_rules WHERE id = ?")
                        .bind(update.id)
                        .fetch_optional(&mut *conn)
                        .await
                )
            };
            u64::from(found.is_some())
        } else {
            let sql = if update.owner_uid.is_some() {
                format!(
                    "UPDATE forward_rules SET {} WHERE id = ? AND uid = ?",
                    sets.join(", ")
                )
            } else {
                format!("UPDATE forward_rules SET {} WHERE id = ?", sets.join(", "))
            };
            let mut query = sqlx::query(&sql);
            if let Some(value) = update.name.as_deref() {
                query = query.bind(value);
            }
            if let Some(value) = update.listen_port {
                query = query.bind(value);
            }
            if let Some(value) = update.protocol.as_deref() {
                query = query.bind(value);
            }
            if let Some(value) = update.public_transport.as_deref() {
                query = query.bind(value);
                query = query.bind(update.node_transport.as_deref().unwrap_or(value));
                query = query.bind(update.entry_transport.as_deref().unwrap_or(value));
            }
            if let Some(value) = update.route_mode.as_deref() {
                query = query.bind(value);
            }
            if let Some(value) = &update.ws_path {
                query = query.bind(value.as_deref());
            }
            if let Some(value) = update.device_group_in {
                query = query.bind(value);
            }
            if let Some(value) = update.device_group_out {
                query = query.bind(value);
            }
            if let Some(value) = update.forward_mode.as_deref() {
                query = query.bind(value);
            }
            if let Some(value) = update.target_addr.as_deref() {
                query = query.bind(value);
            }
            if let Some(value) = update.target_port {
                query = query.bind(value);
            }
            if let Some(value) = update.paused {
                query = query.bind(value);
            }
            query = query.bind(update.id);
            if let Some(uid) = update.owner_uid {
                query = query.bind(uid);
            }
            try_!(query.execute(&mut *conn).await).rows_affected()
        };

        if rows == 0 {
            try_!(sqlx::query("ROLLBACK").execute(&mut *conn).await);
            return Ok(0);
        }

        if route_update_requested || effective_paused {
            try_!(
                sqlx::query("DELETE FROM forward_rule_route_transitions WHERE rule_id=?")
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
        }
        if route_update_requested && !old_paused && !effective_paused {
            // A direct→chain/preset change has no old downstream listener to
            // retain, but it still needs an entry staging marker so the newly
            // added path can bind before the public listener switches.
            if old_downstream_ports.is_empty() {
                if let Some(tunnel_id) = effective_tunnel_id {
                    if let Some(marker) = try_!(
                        sqlx::query_as::<_, (i64, i32, String)>(
                            "SELECT device_group_id,listen_port,'tcp' FROM tunnel_hops \
                             WHERE tunnel_id=? AND position=1 AND listen_port IS NOT NULL",
                        )
                        .bind(tunnel_id)
                        .fetch_optional(&mut *conn)
                        .await
                    ) {
                        old_downstream_ports.push(marker);
                    }
                } else if effective_route_mode == "chain" {
                    if let Some((group_id, listen_port)) = effective_hops.get(1) {
                        old_downstream_ports.push((
                            *group_id,
                            *listen_port,
                            effective_protocol.to_string(),
                        ));
                    }
                }
            }
            for (group_id, listen_port, protocol) in old_downstream_ports {
                try_!(
                    sqlx::query(
                        "INSERT INTO forward_rule_route_transitions \
                         (rule_id,device_group_id,listen_port,protocol,activate_at,expires_at) \
                         VALUES (?,?,?,?,unixepoch()+?,unixepoch()+?) \
                         ON CONFLICT(rule_id,device_group_id,listen_port,protocol) DO UPDATE \
                           SET activate_at=excluded.activate_at,expires_at=excluded.expires_at",
                    )
                    .bind(update.id)
                    .bind(group_id)
                    .bind(listen_port)
                    .bind(protocol)
                    .bind(ROUTE_TRANSITION_STAGE_SECS)
                    .bind(ROUTE_TRANSITION_LEASE_TTL_SECS)
                    .execute(&mut *conn)
                    .await
                );
            }
        }

        if old_group != effective_group && !effective_paused {
            if let Some(source_tunnel_id) = old_tunnel_id {
                try_!(
                    sqlx::query(
                        "INSERT INTO forward_rule_retired_entries \
                         (rule_id,tunnel_id,device_group_id,expires_at) \
                         SELECT fr.id,?,?,unixepoch()+? FROM forward_rules fr \
                         JOIN users u ON u.id=fr.uid \
                         JOIN tunnels source_tunnel ON source_tunnel.id=? \
                         WHERE fr.id=? AND source_tunnel.enabled=1 AND fr.paused=0 \
                           AND u.banned=0 AND u.suspended=0 \
                           AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
                           AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
                           AND (u.admin=1 OR (source_tunnel.shared=1 AND \
                             (u.all_device_groups=1 OR EXISTS(SELECT 1 FROM user_device_groups udg \
                               WHERE udg.user_id=u.id AND udg.device_group_id=?)))) \
                         ON CONFLICT(rule_id,tunnel_id,device_group_id) DO UPDATE \
                           SET expires_at=excluded.expires_at",
                    )
                    .bind(source_tunnel_id)
                    .bind(old_group)
                    .bind(ENTRY_DRAIN_LEASE_TTL_SECS)
                    .bind(source_tunnel_id)
                    .bind(update.id)
                    .bind(old_group)
                    .execute(&mut *conn)
                    .await
                );
                try_!(
                    sqlx::query(
                        "DELETE FROM forward_rule_retired_entries \
                     WHERE rule_id=? AND device_group_id=?",
                    )
                    .bind(update.id)
                    .bind(effective_group)
                    .execute(&mut *conn)
                    .await
                );
            }
        }

        if let Some(hops) = &update.hops {
            let old_tunnel_ports: std::collections::HashMap<(i64, i32), Option<i32>> = try_!(
                sqlx::query_as::<_, (i64, i32, Option<i32>)>(
                    "SELECT device_group_id, listen_port, tunnel_port FROM forward_rule_hops WHERE rule_id = ?",
                )
                .bind(update.id)
                .fetch_all(&mut *conn)
                .await
            )
            .into_iter()
            .map(|(group_id, listen_port, tunnel_port)| {
                ((group_id, listen_port), tunnel_port)
            })
            .collect();
            try_!(
                sqlx::query("DELETE FROM forward_rule_hops WHERE rule_id = ?")
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
            for (position, (group_id, listen_port)) in hops.iter().enumerate() {
                try_!(
                    sqlx::query(
                        "INSERT INTO forward_rule_hops \
                     (rule_id, position, device_group_id, listen_port, tunnel_port) \
                     VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(update.id)
                    .bind(position as i32)
                    .bind(group_id)
                    .bind(listen_port)
                    .bind(
                        old_tunnel_ports
                            .get(&(*group_id, *listen_port))
                            .copied()
                            .flatten(),
                    )
                    .execute(&mut *conn)
                    .await
                );
            }
        }

        if let Some(targets) = &update.targets {
            try_!(
                sqlx::query("DELETE FROM forward_rule_targets WHERE rule_id = ?")
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
            for (position, target) in targets.iter().enumerate() {
                try_!(
                    sqlx::query(
                        "INSERT INTO forward_rule_targets \
                     (rule_id, host, port, position, enabled, weight) VALUES (?, ?, ?, ?, ?, ?)",
                    )
                    .bind(update.id)
                    .bind(target.host.trim())
                    .bind(target.port as i32)
                    .bind(position as i32 + 1)
                    .bind(target.enabled)
                    .bind(target.weight.clamp(1, 100) as i32)
                    .execute(&mut *conn)
                    .await
                );
            }
        }

        if let Some(strategy) = update.load_balance_strategy.as_deref() {
            try_!(
                sqlx::query("UPDATE forward_rules SET load_balance_strategy = ? WHERE id = ?")
                    .bind(strategy)
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
        }
        if let Some((upload, download)) = update.rate_limits {
            try_!(sqlx::query(
                "UPDATE forward_rules SET upload_limit_mbps = ?, download_limit_mbps = ? WHERE id = ?",
            )
            .bind(upload)
            .bind(download)
            .bind(update.id)
            .execute(&mut *conn)
            .await);
        }
        if let Some((max_connections, auto_restart_minutes)) = update.connection_controls {
            try_!(sqlx::query(
                "UPDATE forward_rules SET max_connections = ?, auto_restart_minutes = ? WHERE id = ?",
            )
            .bind(max_connections)
            .bind(auto_restart_minutes)
            .bind(update.id)
            .execute(&mut *conn)
            .await);
        }
        if let Some(profile_id) = update.tunnel_profile_id {
            try_!(
                sqlx::query("UPDATE forward_rules SET tunnel_profile_id = ? WHERE id = ?")
                    .bind(profile_id)
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
        }
        if let Some(tunnel_id) = update.tunnel_id {
            try_!(
                sqlx::query("UPDATE forward_rules SET tunnel_id = ? WHERE id = ?")
                    .bind(tunnel_id)
                    .bind(update.id)
                    .execute(&mut *conn)
                    .await
            );
        }

        try_!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(rows)
    }

    async fn increment_rule_traffic(
        &self,
        id: i64,
        upload: u64,
        download: u64,
    ) -> Result<(), DbError> {
        // NOTE: this overload is unused by node.rs (which uses apply_traffic_batch
        // for atomicity), but is part of the trait contract for any future
        // single-rule increment use case. Upload/download are added together
        // into the single i64 traffic_used column.
        sqlx::query("UPDATE forward_rules SET traffic_used = traffic_used + ? + ? WHERE id = ?")
            .bind(upload as i64)
            .bind(download as i64)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_rule_owner(
        &self,
        rule_id: i64,
        device_group_in: i64,
    ) -> Result<Option<(i64, i64)>, DbError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT id, uid FROM forward_rules WHERE id = ? AND device_group_in = ?",
        )
        .bind(rule_id)
        .bind(device_group_in)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete_rule(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("DELETE FROM forward_rules WHERE id = ?").bind(id),
            Some(uid) => sqlx::query("DELETE FROM forward_rules WHERE id = ? AND uid = ?")
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn delete_rules_by_uid(&self, uid: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM forward_rules WHERE uid = ?")
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn list_active_for_config(&self, group_id: i64) -> Result<Vec<ForwardRule>, DbError> {
        // The JOIN on users is the v0.3.5 WS-drift fix: a banned or over-quota
        // user's rules must be filtered from the node's config. The service
        // layer (config.rs) just iterates the result and resolves targets.
        //
        // Shared entries are administrator-managed. Revalidate their current
        // type, owner role, and the rule owner's current grant here so legacy
        // rows or out-of-band edits cannot reach a node config.
        // v1.0.8: FOUR gating conditions (banned, suspended, over-quota,
        // expired). suspended stops forwarding WITHOUT bumping token_version
        // (the user stays logged in). plan_expire_at is a TEXT UTC timestamp
        // comparable lexically with datetime('now'). NULL = no expiry.
        let mut rules: Vec<ForwardRule> = sqlx::query_as(
            "SELECT fr.* FROM forward_rules fr \
             JOIN users u ON fr.uid = u.id \
             LEFT JOIN tunnels t ON t.id = fr.tunnel_id \
             WHERE fr.device_group_in = ? AND fr.paused = 0 \
             AND u.banned = 0 \
             AND u.suspended = 0 \
             AND EXISTS(SELECT 1 FROM device_groups entry \
               JOIN users entry_owner ON entry_owner.id=entry.uid \
               WHERE entry.id=fr.device_group_in AND entry.group_type IN ('in','both') \
                 AND entry_owner.admin=1) \
             AND (u.admin = 1 OR (\
               (fr.tunnel_id IS NULL OR t.shared = 1) AND \
               (u.all_device_groups = 1 OR EXISTS (SELECT 1 FROM user_device_groups udg \
                 WHERE udg.user_id = u.id AND udg.device_group_id = fr.device_group_in)))) \
             AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at > datetime('now'))",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT rt.* FROM forward_rule_targets rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             WHERE fr.device_group_in=? AND rt.enabled=1 \
             ORDER BY rt.rule_id,rt.position,rt.id",
        )
        .bind(group_id)
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
        }
        Ok(rules)
    }

    async fn replace_rule_hops(&self, rule_id: i64, hops: &[(i64, i32)]) -> Result<(), DbError> {
        // Preserve allocated tunnel ports from one coherent snapshot and
        // serialize competing replacements before the initial read.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let old_tunnel_ports: std::collections::HashMap<i64, Option<i32>> =
            sqlx::query_as::<_, (i64, Option<i32>)>(
                "SELECT device_group_id, tunnel_port FROM forward_rule_hops WHERE rule_id = ?",
            )
            .bind(rule_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
        sqlx::query("DELETE FROM forward_rule_hops WHERE rule_id = ?")
            .bind(rule_id)
            .execute(&mut *tx)
            .await?;
        for (pos, (gid, port)) in hops.iter().enumerate() {
            sqlx::query(
                "INSERT INTO forward_rule_hops \
                 (rule_id, position, device_group_id, listen_port, tunnel_port) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(rule_id)
            .bind(pos as i32)
            .bind(gid)
            .bind(port)
            .bind(old_tunnel_ports.get(gid).copied().flatten())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn claim_rule_hop_tunnel_port(
        &self,
        hop_id: i64,
        port: i32,
    ) -> Result<Option<i32>, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let row: Option<(i64, Option<i32>)> =
            sqlx::query_as("SELECT device_group_id,tunnel_port FROM forward_rule_hops WHERE id=?")
                .bind(hop_id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((group_id, stored)) = row else {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            return Ok(None);
        };
        if stored.is_some() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            return Ok(stored);
        }
        let conflict: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 WHERE \
             EXISTS (SELECT 1 FROM forward_rules WHERE device_group_in=? AND listen_port=? AND protocol IN ('tcp','tcp_udp')) \
             OR EXISTS (SELECT 1 FROM forward_rule_hops h JOIN forward_rules r ON r.id=h.rule_id \
               WHERE h.device_group_id=? AND h.listen_port=? AND r.protocol IN ('tcp','tcp_udp')) \
             OR EXISTS (SELECT 1 FROM forward_rule_hops WHERE id<>? AND device_group_id=? AND tunnel_port=?) \
             OR EXISTS (SELECT 1 FROM tunnel_hops WHERE device_group_id=? AND listen_port=?) \
             OR EXISTS (SELECT 1 FROM forward_rule_route_transitions \
               WHERE device_group_id=? AND listen_port=? AND expires_at>=unixepoch() \
                 AND protocol IN ('tcp','tcp_udp')) LIMIT 1",
        )
        .bind(group_id).bind(port)
        .bind(group_id).bind(port)
        .bind(hop_id).bind(group_id).bind(port)
        .bind(group_id).bind(port)
        .bind(group_id).bind(port)
        .fetch_optional(&mut *conn)
        .await?;
        if conflict.is_some() {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Err(DbError::PortConflict);
        }
        sqlx::query("UPDATE forward_rule_hops SET tunnel_port=? WHERE id=?")
            .bind(port)
            .bind(hop_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(Some(port))
    }

    async fn list_rule_hops(
        &self,
        rule_id: i64,
    ) -> Result<Vec<relay_shared::models::ForwardRuleHop>, DbError> {
        let hops = sqlx::query_as(
            "SELECT * FROM forward_rule_hops WHERE rule_id = ? ORDER BY position, id",
        )
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(hops)
    }

    async fn list_active_chain_hops_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<relay_shared::models::ForwardRuleHop>, DbError> {
        // All hop placements on this group for active, gated chain rules.
        // Includes position 0 so callers can also use this alone if desired;
        // node_config currently uses list_active_for_config for entry + this
        // for intermediate/exit (position > 0) to avoid double-emitting.
        let hops = sqlx::query_as(
            "SELECT h.* FROM forward_rule_hops h \
             JOIN forward_rules fr ON fr.id = h.rule_id \
             JOIN users u ON fr.uid = u.id \
             WHERE h.device_group_id = ? \
             AND fr.route_mode = 'chain' AND fr.tunnel_id IS NULL AND fr.paused = 0 \
             AND u.banned = 0 AND u.suspended = 0 \
             AND EXISTS(SELECT 1 FROM device_groups entry \
               JOIN users entry_owner ON entry_owner.id=entry.uid \
               WHERE entry.id=fr.device_group_in AND entry.group_type IN ('in','both') \
                 AND entry_owner.admin=1) \
             AND (u.admin = 1 OR u.all_device_groups = 1 OR EXISTS (\
               SELECT 1 FROM user_device_groups udg WHERE udg.user_id = u.id \
                 AND udg.device_group_id = fr.device_group_in)) \
             AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at > datetime('now')) \
             ORDER BY h.rule_id, h.position",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(hops)
    }

    async fn list_active_chain_rules_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules: Vec<ForwardRule> = sqlx::query_as(
            "SELECT DISTINCT fr.* FROM forward_rules fr \
             JOIN forward_rule_hops h ON h.rule_id=fr.id \
             JOIN users u ON u.id=fr.uid \
             WHERE h.device_group_id=? AND fr.route_mode='chain' \
             AND fr.tunnel_id IS NULL AND fr.paused=0 \
             AND u.banned=0 AND u.suspended=0 \
             AND EXISTS(SELECT 1 FROM device_groups entry \
               JOIN users entry_owner ON entry_owner.id=entry.uid \
               WHERE entry.id=fr.device_group_in AND entry.group_type IN ('in','both') \
                 AND entry_owner.admin=1) \
             AND (u.admin=1 OR u.all_device_groups=1 OR EXISTS (\
               SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                 AND udg.device_group_id=fr.device_group_in)) \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
             ORDER BY fr.id",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let targets: Vec<ForwardRuleTarget> = sqlx::query_as(
            "SELECT DISTINCT rt.* FROM forward_rule_targets rt \
             JOIN forward_rules fr ON fr.id=rt.rule_id \
             JOIN forward_rule_hops h ON h.rule_id=fr.id \
             JOIN users u ON u.id=fr.uid \
             WHERE h.device_group_id=? AND fr.route_mode='chain' \
             AND fr.tunnel_id IS NULL AND fr.paused=0 \
             AND rt.enabled=1 AND u.banned=0 AND u.suspended=0 \
             AND EXISTS(SELECT 1 FROM device_groups entry \
               JOIN users entry_owner ON entry_owner.id=entry.uid \
               WHERE entry.id=fr.device_group_in AND entry.group_type IN ('in','both') \
                 AND entry_owner.admin=1) \
             AND (u.admin=1 OR u.all_device_groups=1 OR EXISTS (\
               SELECT 1 FROM user_device_groups udg WHERE udg.user_id=u.id \
                 AND udg.device_group_id=fr.device_group_in)) \
             AND (u.traffic_limit=0 OR u.traffic_used<u.traffic_limit) \
             AND (u.plan_expire_at IS NULL OR u.plan_expire_at>datetime('now')) \
             ORDER BY rt.rule_id,rt.position,rt.id",
        )
        .bind(group_id)
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
        }
        Ok(rules)
    }

    async fn find_rule_hop_at(
        &self,
        rule_id: i64,
        position: i32,
    ) -> Result<Option<relay_shared::models::ForwardRuleHop>, DbError> {
        let hop =
            sqlx::query_as("SELECT * FROM forward_rule_hops WHERE rule_id = ? AND position = ?")
                .bind(rule_id)
                .bind(position)
                .fetch_optional(&self.pool)
                .await?;
        Ok(hop)
    }
}

impl SqliteRepository {
    /// Hops with group_name / connect_host filled for API display.
    async fn list_rule_hops_enriched(
        &self,
        rule_id: i64,
    ) -> Result<Vec<relay_shared::models::ForwardRuleHop>, DbError> {
        let mut hops = self.list_rule_hops(rule_id).await?;
        for hop in &mut hops {
            if let Some((name, host)) = sqlx::query_as::<_, (String, String)>(
                "SELECT name, connect_host FROM device_groups WHERE id = ?",
            )
            .bind(hop.device_group_id)
            .fetch_optional(&self.pool)
            .await?
            {
                hop.group_name = Some(name);
                hop.connect_host = Some(host);
            }
        }
        Ok(hops)
    }
}
