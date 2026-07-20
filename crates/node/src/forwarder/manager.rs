use super::gate::RuleRuntime;
use super::limiter::RateLimit;
use super::selector::TargetSelector;
use super::tcp;
use super::tls;
use super::udp;
use super::uot;
use super::ws;
use crate::reporter::{ConnectionTracker, TrafficCounter};
use relay_shared::protocol::{
    ListenerConfig, ListenerError, LoadBalanceStrategy, NodeConfigResponse, NodeTransport,
    Protocol, TunnelClientConfig, TunnelListenerConfig, UotRole,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Key: (port, protocol, node_transport). This lets two listeners coexist on
/// the same port + L4 protocol when their transport differs — e.g. a raw TCP
/// rule and a WS rule both on port 12345 are two distinct listeners. (The
/// panel already guarantees no two rules share the same (port, protocol) when
/// transport matches; this key is the precise identity of a listener.)
type ListenerKey = (u16, Protocol, NodeTransport);

/// A snapshot of the fields that change a running listener's behaviour but are
/// NOT part of the [`ListenerKey`]. v0.3.6: this is the "config fingerprint"
/// used to decide whether an existing listener must be restarted (hot update)
/// or left alone.
///
/// Why each field is here:
/// - `rule_id`: traffic attribution. If the rule id changed (e.g. a rule was
///   deleted and a new one reuses the same port), the listener must restart so
///   traffic is attributed to the new rule.
/// - `targets`: where the listener forwards. Changing target_addr / target_port
///   / outbound connect_host changes this; without a restart the old task keeps
///   using the captured-old targets forever. Targets compare in ORDER — the
///   primary/secondary target priority must be preserved, so we do NOT sort.
/// - `ws_path`: only meaningful for Ws listeners, but harmless to include for
///   all (Raw/Udp always have None). A ws_path change must restart the WS
///   listener so it validates the new path.
///
/// `speed_limit` / `ip_limit` are deliberately NOT here: they are placeholder
/// fields that are always None in v0.3.x (the node has no limiter), so they
/// never change behaviour and must not trigger spurious restarts.
///
/// `upload_limit_bps` / `download_limit_bps` ARE here (v1.0.9): the rate limiter
/// is captured by the listener task when it spawns, so a limit change with no
/// other change would otherwise leave the running task on the OLD cap until the
/// node restarts. Including them forces a restart that re-reads the new cap.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenerFingerprint {
    rule_id: i64,
    targets: Vec<String>,
    target_weights: Vec<u16>,
    ws_path: Option<String>,
    /// v0.4.6: a strategy change must restart the listener so the new selector
    /// (and its cursor) takes effect.
    load_balance_strategy: LoadBalanceStrategy,
    /// v0.4.7: a transport change (raw↔ws↔tls_simple) must restart the listener
    /// so the right forwarder (tcp/ws/tls) is spawned. Derived from a tunnel
    /// profile, so it can change without the rule's listen port moving.
    node_transport: NodeTransport,
    /// v1.0.9: per-rule rate caps (BYTES/sec, None = unlimited). A change here
    /// (including clearing a limit) must restart the listener so the new cap
    /// takes effect without a node restart.
    upload_limit_bps: Option<u64>,
    download_limit_bps: Option<u64>,
    /// v1.2.0: concurrent-connection cap (None = unlimited). The accept loop
    /// captures this when it spawns, so a change must restart the listener for
    /// the new cap to apply — same reasoning as the rate caps above.
    ///
    /// Note this restart does NOT drop live connections (only an explicit
    /// `restart_rule` does that), so editing the cap on a busy rule is safe:
    /// existing connections keep running and the new cap governs admissions
    /// from that point on. A lowered cap takes effect by attrition.
    max_connections: Option<u32>,
    uot_role: UotRole,
    uot_token: Option<String>,
    uot_next_token: Option<String>,
    zero_rtt: bool,
    tcp_fast_open: bool,
}

impl ListenerFingerprint {
    fn from_listener(l: &ListenerConfig) -> Self {
        Self {
            rule_id: l.rule_id,
            targets: l.targets.clone(),
            target_weights: l.target_weights.clone(),
            ws_path: l.ws_path.clone(),
            load_balance_strategy: l.load_balance_strategy,
            node_transport: l.node_transport,
            upload_limit_bps: l.upload_limit_bps,
            download_limit_bps: l.download_limit_bps,
            max_connections: l.max_connections,
            uot_role: l.uot_role,
            uot_token: l.uot_token.clone(),
            uot_next_token: l.uot_next_token.clone(),
            zero_rtt: l.zero_rtt,
            tcp_fast_open: l.tcp_fast_open,
        }
    }
}

/// Decide how to probe the listener's downstream target. UOT ingress/relay
/// targets are relay TCP sockets, but an UOT egress targets the user's native
/// UDP service and must never be judged by whether that numeric port accepts
/// TCP connections.
fn target_probe_uses_tcp(listener: &ListenerConfig) -> bool {
    listener.protocol == Protocol::Tcp
        || matches!(listener.uot_role, UotRole::Ingress | UotRole::Relay)
}

struct ManagedListener {
    handle: JoinHandle<()>,
    fingerprint: ListenerFingerprint,
}

type TunnelListenerKey = (i64, u16);

struct ManagedTunnelListener {
    handle: JoinHandle<()>,
    config: TunnelListenerConfig,
    state: super::tunnel::TunnelListenerState,
    runtime: super::tunnel::TunnelRuntime,
}

struct RetiredTunnelRuntime {
    tunnel_id: i64,
    runtime: super::tunnel::TunnelRuntime,
}

struct RetiredRuleRuntime {
    rule_id: i64,
    runtime: RuleRuntime,
}

type TunnelReplayKey = (i64, u8, String, String);

// A signed header is accepted for at most 60 seconds, while ReplayCache keeps
// two 120-second nonce buckets. Retain an inactive link a little longer than
// both windows so a quick pause, disable/re-enable or transient empty route
// cannot reset replay protection; old credential revisions then release memory.
const TUNNEL_REPLAY_RETENTION: Duration = Duration::from_secs(5 * 60);

struct TunnelReplayCacheEntry {
    cache: Arc<super::tunnel::ReplayCache>,
    last_used: Instant,
}

fn tunnel_replay_key(tunnel: &TunnelListenerConfig) -> TunnelReplayKey {
    (
        tunnel.tunnel_id,
        tunnel.hop_position,
        tunnel.link_scope.clone(),
        tunnel.auth_token.clone(),
    )
}

fn tunnel_credentials_revoked(
    previous: &TunnelListenerConfig,
    next: &TunnelListenerConfig,
) -> bool {
    (previous.link_scope == next.link_scope && previous.auth_token != next.auth_token)
        || previous
            .next
            .as_ref()
            .zip(next.next.as_ref())
            .is_some_and(|(previous, next)| {
                previous.link_scope == next.link_scope && previous.auth_token != next.auth_token
            })
}

fn link_scope_group_ids(scope: &str) -> impl Iterator<Item = i64> + '_ {
    // Scope format is tunnel_id:position:from_group:to_group. Ignore malformed
    // values rather than letting a control-plane typo broaden revocation.
    scope
        .split(':')
        .skip(2)
        .take(2)
        .filter_map(|part| part.parse().ok())
}

fn link_scope_credentials(scope: &str, revisions: &HashMap<i64, i64>) -> Vec<(i64, Option<i64>)> {
    link_scope_group_ids(scope)
        .map(|group_id| {
            let revision = revisions.get(&group_id).copied();
            (group_id, revision)
        })
        .collect()
}

fn link_scope_uses_group(scope: &str, group_id: i64) -> bool {
    link_scope_group_ids(scope).any(|candidate| candidate == group_id)
}

fn tunnel_listener_uses_group(config: &TunnelListenerConfig, group_id: i64) -> bool {
    link_scope_uses_group(&config.link_scope, group_id)
        || config
            .next
            .as_ref()
            .is_some_and(|next| link_scope_uses_group(&next.link_scope, group_id))
}

/// Remove every data-plane credential and public entry that depends on one
/// revoked device-group token while preserving unrelated offline forwarding.
/// The returned snapshot is safe to persist and load after a process restart.
fn fail_closed_config_for_group(config: &NodeConfigResponse, group_id: i64) -> NodeConfigResponse {
    let mut sanitized = config.clone();
    let affected_rule_ids: HashSet<i64> = sanitized
        .tunnels
        .iter()
        .flat_map(|tunnel| tunnel.clients.iter())
        .filter(|client| link_scope_uses_group(&client.link_scope, group_id))
        .map(|client| client.rule_id)
        .collect();

    sanitized
        .listeners
        .retain(|listener| !affected_rule_ids.contains(&listener.rule_id));
    sanitized
        .drain_rule_ids
        .retain(|rule_id| !affected_rule_ids.contains(rule_id));
    sanitized
        .route_transition_rule_ids
        .retain(|rule_id| !affected_rule_ids.contains(rule_id));
    sanitized
        .route_staging_rule_ids
        .retain(|rule_id| !affected_rule_ids.contains(rule_id));
    sanitized
        .route_drain_rule_ids
        .retain(|rule_id| !affected_rule_ids.contains(rule_id));
    sanitized.tunnels.retain_mut(|tunnel| {
        if tunnel_listener_uses_group(tunnel, group_id) {
            return false;
        }
        tunnel
            .clients
            .retain(|client| !link_scope_uses_group(&client.link_scope, group_id));
        tunnel.port != 0 || !tunnel.clients.is_empty()
    });
    sanitized
}

/// v0.4.8: snapshot of one rule's listener state, for diagnosis. `running`
/// reflects whether the listener task is alive right now (a task can exit
/// without the manager knowing until the next apply).
#[derive(Debug, Clone)]
pub struct ListenerInfo {
    pub port: u16,
    pub protocol: String,
    pub transport: String,
    pub targets: Vec<String>,
    pub running: bool,
    /// Present for a reusable preset tunnel. Diagnosis sends an authenticated
    /// probe through the complete route instead of merely opening the next
    /// shared listener's TCP socket.
    pub tunnel: Option<TunnelClientConfig>,
}

struct ManagedRateLimit {
    upload_bps: Option<u64>,
    download_bps: Option<u64>,
    limiter: RateLimit,
}

impl ManagedRateLimit {
    fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        Self {
            upload_bps,
            download_bps,
            limiter: RateLimit::new(upload_bps, download_bps),
        }
    }
}

pub struct ForwarderManager {
    listeners: HashMap<ListenerKey, ManagedListener>,
    shared_tunnel_listeners: HashMap<TunnelListenerKey, ManagedTunnelListener>,
    /// Listener generations removed by an ordinary path edit. Their accept
    /// sockets are gone, but authenticated TCP streams may still be draining.
    /// Keeping the runtime makes a later credential revocation authoritative.
    retired_tunnel_runtimes: Vec<RetiredTunnelRuntime>,
    /// Public-entry rule runtimes moved to another device group. Their accept
    /// loops are gone, but keeping the sender alive lets established TCP
    /// connections drain while traffic remains attributed to the old entry.
    retired_rule_runtimes: Vec<RetiredRuleRuntime>,
    /// Replay state survives route/target rebuilds and short listener absences
    /// while the incoming link identity and credential stay unchanged.
    tunnel_replay_caches: HashMap<TunnelReplayKey, TunnelReplayCacheEntry>,
    /// Persistent per-rule traffic buckets. Keeping these outside a single
    /// apply_config call ensures a recovered TCP or UDP half of a tcp_udp rule
    /// rejoins the sibling's existing aggregate budget instead of receiving a
    /// fresh independent bucket.
    rule_limiters: HashMap<i64, ManagedRateLimit>,
    /// v1.2.0: per-rule runtime state (live-connection counter + restart
    /// cancellation), keyed by rule_id. Lives HERE rather than in the listener
    /// because a rule's IPv4 and IPv6 listeners must share one connection
    /// budget, and because it has to survive the listener being torn down and
    /// rebuilt by `apply_config` (a config edit must not reset the count while
    /// the connections it counted are still alive). Entries are dropped when the
    /// rule leaves the config, which cancels its connections — see `gate.rs`.
    rule_runtime: HashMap<i64, RuleRuntime>,
    /// v1.2.0: the most recent config, kept so `restart_rule` can rebuild a
    /// rule's listeners without asking the panel for the config again. A restart
    /// must be able to run while the control channel is busy, and re-fetching
    /// would also let a config change ride in on what the operator asked to be a
    /// pure restart.
    last_config: Option<NodeConfigResponse>,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    /// Bind/runtime errors captured from spawned listener tasks since the last
    /// `take_listener_errors()`. Shared so a task can push its failure after the
    /// manager has already moved on. Drained by the status reporter.
    listener_errors: Arc<Mutex<Vec<ListenerError>>>,
    /// v0.4.1: shared TLS acceptor for tls_simple listeners (supports hot-reload
    /// via cert_reloader). None = no cert configured (tls_simple rules skipped).
    tls_acceptor: Option<super::cert_reloader::SharedTlsAcceptor>,
    /// v1.0.4: dual-stack listen addresses from env.
    listen_ipv4: String,
    listen_ipv6: String,
    /// v1.0.4: resolved outbound source IPv4 (None = auto-route).
    source_ipv4: Option<std::net::Ipv4Addr>,
}

impl ForwarderManager {
    pub fn new(counter: Arc<TrafficCounter>, connections: Arc<ConnectionTracker>) -> Self {
        Self {
            listeners: HashMap::new(),
            shared_tunnel_listeners: HashMap::new(),
            retired_tunnel_runtimes: Vec::new(),
            retired_rule_runtimes: Vec::new(),
            tunnel_replay_caches: HashMap::new(),
            rule_limiters: HashMap::new(),
            rule_runtime: HashMap::new(),
            last_config: None,
            counter,
            connections,
            listener_errors: Arc::new(Mutex::new(Vec::new())),
            tls_acceptor: None,
            listen_ipv4: "0.0.0.0".into(),
            listen_ipv6: "::".into(),
            source_ipv4: None,
        }
    }

    /// v1.0.4: configure dual-stack listen and outbound source.
    /// Returns Err on misconfigured outbound (invalid IP, missing interface,
    /// non-local IP) so the caller can abort instead of silently auto-routing
    /// out the wrong NIC.
    pub fn set_network_config(
        &mut self,
        cfg: &crate::config::NodeConfig,
    ) -> Result<(), crate::forwarder::outbound::OutboundError> {
        self.listen_ipv4 = cfg.listen_ipv4.clone();
        self.listen_ipv6 = cfg.listen_ipv6.clone();
        self.source_ipv4 = crate::forwarder::outbound::init_outbound(
            &crate::forwarder::outbound::OutboundConfig {
                bind_ipv4: cfg.outbound_bind_ipv4.clone(),
                interface: cfg.outbound_interface.clone(),
            },
        )?;
        Ok(())
    }

    /// Drain the accumulated listener errors (called by the status reporter so
    /// each error is reported exactly once, then cleared). An empty Vec means
    /// all listeners bound successfully since the last call.
    pub async fn take_listener_errors(&self) -> Vec<ListenerError> {
        self.listener_errors.lock().await.drain(..).collect()
    }

    /// Rules for which this node still owns at least one established TCP stream
    /// from a retired preset-tunnel entry generation. The panel renews only
    /// these accounting leases; once the last stream closes the lease expires.
    pub fn active_draining_rule_ids(&self) -> Vec<i64> {
        let configured: HashSet<i64> = self
            .last_config
            .as_ref()
            .into_iter()
            .flat_map(|config| config.drain_rule_ids.iter().copied())
            .collect();
        let mut ids: Vec<i64> = self
            .retired_rule_runtimes
            .iter()
            .filter(|retired| !retired.runtime.is_idle() && configured.contains(&retired.rule_id))
            .map(|retired| retired.rule_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// v0.4.9: return the rule's TCP listener, for diagnosis. Diagnosis is
    /// TCP-only, and a tcp_udp rule runs TWO listeners (Tcp + Udp) keyed in a
    /// HashMap — iterating that map and taking the first match would be
    /// nondeterministic and could return the Udp listener. This filters on
    /// `Protocol::Tcp` so the TCP listener is selected deterministically.
    ///
    /// For a pure-tcp rule there is exactly one (Tcp) listener, so this returns
    /// it. A pure-udp rule has no Tcp listener and returns None — but the panel
    /// rejects pure-UDP rules before dispatching a probe, so that branch is
    /// unreachable in practice (kept defensive). `running` is the JoinHandle's
    /// `is_finished()` inverse — a task that has exited (without the manager
    /// re-applying config) is reported as not running.
    ///
    /// (v0.4.8 had a generic `listener_info_for_rule` that returned the first
    /// match regardless of L4; it was removed in v0.4.9 since diagnosis is now
    /// TCP-only and the nondeterministic selection was a latent bug for
    /// tcp_udp rules.)
    pub fn listener_info_for_rule_tcp(&self, rule_id: i64) -> Option<ListenerInfo> {
        let tunnel = self.last_config.as_ref().and_then(|config| {
            config
                .tunnels
                .iter()
                .flat_map(|listener| listener.clients.iter())
                .find(|client| client.rule_id == rule_id)
                .cloned()
        });
        for ((port, proto, transport), ml) in &self.listeners {
            if ml.fingerprint.rule_id == rule_id && *proto == Protocol::Tcp {
                return Some(ListenerInfo {
                    port: *port,
                    protocol: "tcp".to_string(),
                    transport: format!("{:?}", transport).to_lowercase(),
                    targets: ml.fingerprint.targets.clone(),
                    running: !ml.handle.is_finished(),
                    tunnel,
                });
            }
        }
        None
    }

    /// Resolved outbound source address used by the real forwarding path.
    /// Diagnostics must reuse it or a multi-homed node can report a false
    /// failure while production traffic succeeds through the configured NIC.
    pub(crate) fn outbound_source_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.source_ipv4
    }

    /// v0.4.1: set the shared TLS acceptor for tls_simple listeners. Called at
    /// startup after loading the cert+key (or starting the CertReloader).
    /// None = no cert (tls_simple rules skipped).
    pub fn set_tls_acceptor(&mut self, acceptor: Option<super::cert_reloader::SharedTlsAcceptor>) {
        self.tls_acceptor = acceptor;
    }

    /// v0.4.1: expose the listener_errors Arc so the CertReloader (spawned
    /// before the manager is wrapped in Arc<Mutex>) can push reload errors.
    pub fn listener_errors_arc(&self) -> Arc<Mutex<Vec<ListenerError>>> {
        Arc::clone(&self.listener_errors)
    }

    pub async fn apply_config(&mut self, config: &NodeConfigResponse) {
        // Credential generations are independent from topology. Compare them
        // before reconciling listeners so a token rotation still cancels the
        // old generation when the same snapshot also changes/removes a hop or
        // moves the shared port. An empty previous map is an upgrade/bootstrap
        // case, not evidence that every credential changed.
        let current_credential_revisions: HashMap<i64, i64> = config
            .credential_revisions
            .iter()
            .map(|revision| (revision.group_id, revision.revision))
            .collect();
        let revoked_groups: Vec<(i64, Option<i64>)> = self
            .last_config
            .as_ref()
            .filter(|previous| !previous.credential_revisions.is_empty())
            .into_iter()
            .flat_map(|previous| previous.credential_revisions.iter())
            .filter(|previous| {
                current_credential_revisions
                    .get(&previous.group_id)
                    .is_none_or(|current| *current != previous.revision)
            })
            .map(|previous| {
                let current_revision = current_credential_revisions
                    .get(&previous.group_id)
                    .copied();
                (previous.group_id, current_revision)
            })
            .collect();
        // ── Step 1: recover dead listeners ──
        // v0.3.6: a listener task that exited (bind failure, unrecoverable
        // error, or the v0.3.5 "instant accept error killed the task" bug) left
        // its JoinHandle registered, so apply_config thought it was still
        // running and the port stayed dead until the node restarted. Now we
        // detect finished handles up front and drop them, so the restart logic
        // below can bring them back if they're still desired.
        let dead: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|(_, m)| m.handle.is_finished())
            .map(|(k, _)| *k)
            .collect();
        let mut dead_rule_ids: Vec<i64> = Vec::new();
        for key in &dead {
            let (port, proto, transport) = *key;
            tracing::warn!(
                "listener {:?}/{:?} on port {} has exited; will restart if still desired",
                proto,
                transport,
                port
            );
            if let Some(m) = self.listeners.remove(key) {
                dead_rule_ids.push(m.fingerprint.rule_id);
            }
        }

        // ── Step 2: compute the desired set ──
        // Protocol::TcpUdp should never appear here (the panel expands it), but
        // we skip it defensively.
        // A route-transition lease is deliberately ignored when any credential
        // generation changed in this snapshot. Revocation must win over
        // availability even if an unrelated control-plane lease is stale.
        let route_transition_rule_ids: HashSet<i64> = if revoked_groups.is_empty() {
            config.route_transition_rule_ids.iter().copied().collect()
        } else {
            HashSet::new()
        };
        let route_staging_rule_ids: HashSet<i64> = if revoked_groups.is_empty() {
            config.route_staging_rule_ids.iter().copied().collect()
        } else {
            HashSet::new()
        };
        let route_drain_rule_ids: HashSet<i64> = if revoked_groups.is_empty() {
            config.route_drain_rule_ids.iter().copied().collect()
        } else {
            HashSet::new()
        };
        let retained_route_rule_ids: HashSet<i64> = route_transition_rule_ids
            .union(&route_staging_rule_ids)
            .copied()
            .collect();
        let mut active_keys: HashSet<ListenerKey> = config
            .listeners
            .iter()
            .filter(|l| l.protocol != Protocol::TcpUdp)
            .map(|l| (l.port, l.protocol, l.node_transport))
            .collect();
        // Old downstream accept loops are already bound and hold their full
        // previous forwarding context. Keeping their keys desired avoids a
        // cross-node remove-before-add window without rebuilding secrets from
        // the new snapshot. Dead generations are not resurrected.
        active_keys.extend(self.listeners.iter().filter_map(|(key, listener)| {
            retained_route_rule_ids
                .contains(&listener.fingerprint.rule_id)
                .then_some(*key)
        }));

        // v0.5.1: collect the rule_ids present in the NEW config so we can
        // decide which stopped listeners truly belong to deleted rules (and
        // therefore need their traffic counters pruned) vs. listeners that
        // are merely being restarted with a different fingerprint.
        let mut desired_rule_ids: HashSet<i64> =
            config.listeners.iter().map(|l| l.rule_id).collect();
        desired_rule_ids.extend(retained_route_rule_ids.iter().copied());
        let draining_rule_ids: HashSet<i64> = config.drain_rule_ids.iter().copied().collect();
        let runtime_draining_rule_ids: HashSet<i64> = draining_rule_ids
            .union(&route_drain_rule_ids)
            .copied()
            .collect();

        // Retired entry runtimes are reaped only after their last TCP stream
        // closes. A pause/delete/unshare/disable removes the rule from the
        // drain list and is an explicit cancellation, not a topology drain.
        let mut finished_retired = Vec::new();
        self.retired_rule_runtimes.retain(|retired| {
            if retired.runtime.is_idle() {
                finished_retired.push(retired.rule_id);
                false
            } else {
                if !runtime_draining_rule_ids.contains(&retired.rule_id)
                    && !desired_rule_ids.contains(&retired.rule_id)
                {
                    retired.runtime.cancel_all();
                }
                true
            }
        });
        for rule_id in finished_retired {
            if !desired_rule_ids.contains(&rule_id) {
                self.rule_limiters.remove(&rule_id);
                if !runtime_draining_rule_ids.contains(&rule_id) {
                    self.counter.prune_rule(rule_id).await;
                }
            }
        }

        // If a tunnel moves back to this group before the old streams finish,
        // reuse the same runtime so the connection cap and restart signal stay
        // shared across the draining and newly accepted generations.
        let mut index = 0;
        while index < self.retired_rule_runtimes.len() {
            if desired_rule_ids.contains(&self.retired_rule_runtimes[index].rule_id) {
                let RetiredRuleRuntime { rule_id, runtime } =
                    self.retired_rule_runtimes.swap_remove(index);
                self.rule_runtime.insert(rule_id, runtime);
            } else {
                index += 1;
            }
        }
        let mut preserved_rule_ids = runtime_draining_rule_ids.clone();
        preserved_rule_ids.extend(
            self.retired_rule_runtimes
                .iter()
                .map(|retired| retired.rule_id),
        );

        // v0.5.1: prune counters for dead listeners whose rule is no longer in
        // the new config AND has no other live listener referencing it.
        for rule_id in &dead_rule_ids {
            if !desired_rule_ids.contains(rule_id)
                && !preserved_rule_ids.contains(rule_id)
                && !self
                    .listeners
                    .values()
                    .any(|live| live.fingerprint.rule_id == *rule_id)
            {
                self.counter.prune_rule(*rule_id).await;
            }
        }

        // ── Step 3: stop listeners no longer desired, AND restart listeners
        // whose fingerprint changed (target / ws_path / rule_id). Both are
        // "tear down the current task" — the restart case just immediately
        // re-adds it in step 4.
        let mut to_stop: Vec<ListenerKey> = self
            .listeners
            .keys()
            .filter(|k| !active_keys.contains(k))
            .copied()
            .collect();
        // Fingerprint-changed listeners that ARE still desired: stop them now so
        // step 4 starts them fresh with the new config.
        let previous_tunnel_clients: HashMap<i64, TunnelClientConfig> = self
            .last_config
            .as_ref()
            .into_iter()
            .flat_map(|config| config.tunnels.iter())
            .flat_map(|tunnel| tunnel.clients.iter().cloned())
            .map(|client| (client.rule_id, client))
            .collect();
        let tunnel_clients: HashMap<i64, TunnelClientConfig> = config
            .tunnels
            .iter()
            .flat_map(|tunnel| tunnel.clients.iter().cloned())
            .map(|client| (client.rule_id, client))
            .collect();
        let mut revoked_rule_ids = HashSet::new();
        for listener in &config.listeners {
            let key = (listener.port, listener.protocol, listener.node_transport);
            if let Some(m) = self.listeners.get(&key) {
                let new_fp = ListenerFingerprint::from_listener(listener);
                if m.fingerprint != new_fp {
                    // A derived link key changing while the next address stays
                    // the same identifies a device-group token rotation. It is
                    // a credential revocation, so unlike ordinary target/path
                    // edits the old authenticated TCP streams must not drain.
                    if previous_tunnel_clients
                        .get(&listener.rule_id)
                        .zip(tunnel_clients.get(&listener.rule_id))
                        .is_some_and(|(old, new)| {
                            old.link_scope == new.link_scope && old.auth_token != new.auth_token
                        })
                    {
                        revoked_rule_ids.insert(listener.rule_id);
                    }
                    if !route_staging_rule_ids.contains(&listener.rule_id) {
                        to_stop.push(key);
                    }
                }
            }
        }
        for rule_id in revoked_rule_ids {
            if let Some(runtime) = self.rule_runtime.get(&rule_id) {
                runtime.cancel_all();
            }
        }
        for key in to_stop {
            if let Some(m) = self.listeners.remove(&key) {
                let handle = m.handle;
                let (port, proto, transport) = key;
                handle.abort();
                // v0.3.6: await the aborted task so the OS releases the listen
                // socket BEFORE we try to re-bind on the same port in step 4.
                // Without this, the new bind can race the old task's teardown
                // and fail with "address already in use". A wait on an aborted
                // task returns promptly (it's just the cleanup signal).
                let _ = (&mut { handle }).await;
                // v0.5.1: prune traffic-counter entries for this rule_id when
                // the rule is genuinely gone (not just being restarted with a
                // new fingerprint) AND no other live listener still references
                // this rule_id (e.g. the UDP listener of a tcp_udp rule). This
                // prevents orphaned bytes from poisoning future traffic batches.
                let rule_id = m.fingerprint.rule_id;
                if !desired_rule_ids.contains(&rule_id)
                    && !preserved_rule_ids.contains(&rule_id)
                    && !self
                        .listeners
                        .values()
                        .any(|live| live.fingerprint.rule_id == rule_id)
                {
                    self.counter.prune_rule(rule_id).await;
                }
                tracing::info!(
                    "stopped {:?}/{:?} listener on port {} for reconfiguration",
                    proto,
                    transport,
                    port
                );
            }
        }

        // Shared preset-tunnel sockets participate in the same port lifecycle.
        // Reconcile them after old public listeners stop and before new public
        // listeners bind, so a port can safely move between roles in one push.
        self.apply_shared_tunnel_listeners(
            config,
            &current_credential_revisions,
            &route_transition_rule_ids,
        )
        .await;

        // Revoke only after shared accept loops have been updated or stopped.
        // Cancelling first left a narrow security window: an old listener could
        // accept after the generation bump, subscribe to the new generation and
        // then authenticate with its still-old context. At this point a retained
        // listener already exposes the new key, while a removed listener's accept
        // task has been aborted and awaited; the final cancel is therefore
        // authoritative for every old generation.
        for (group_id, current_revision) in revoked_groups {
            tracing::warn!(
                group_id,
                "device-group credential generation changed; revoking authenticated tunnel streams"
            );
            self.revoke_tunnel_credential_generations(group_id, current_revision);
        }

        // ── Step 4: start new / changed listeners ──
        // Per-rule rate limiters are shared across ALL listeners of the same
        // rule and persist across apply calls. A tcp_udp rule's TCP + UDP halves
        // therefore keep drawing from one bucket even if only one dead listener
        // is recovered during this pass.
        for listener in &config.listeners {
            let listener_tunnel = tunnel_clients.get(&listener.rule_id).cloned();
            let key = (listener.port, listener.protocol, listener.node_transport);
            // Phase one of a route edit pre-warms downstream listeners while
            // the entry keeps its previous generation. If that generation has
            // already died, fail open to the new one instead of leaving the
            // public protocol unavailable for the whole staging interval.
            if route_staging_rule_ids.contains(&listener.rule_id)
                && self.listeners.iter().any(|(old_key, old)| {
                    old.fingerprint.rule_id == listener.rule_id && old_key.1 == listener.protocol
                })
            {
                continue;
            }
            // Skip if already running with the SAME fingerprint (no change).
            if let Some(m) = self.listeners.get(&key) {
                if m.fingerprint == ListenerFingerprint::from_listener(listener) {
                    continue;
                }
            }

            // v1.0.4: dual-stack listen — parse IPs via IpAddr (NEVER string
            // concatenation, which produced ":::port" for IPv6). Empty string
            // = that family disabled.
            let ip_v4 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv4);
            let ip_v6 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv6);
            let targets = listener.targets.clone();
            // v0.4.6: one selector per listener, shared across all of its
            // connections/sessions so a round-robin cursor advances globally.
            let selector = Arc::new(TargetSelector::with_weights(
                listener.load_balance_strategy,
                targets.len(),
                listener.target_weights.clone(),
            ));
            // v0.4.6: shared per-rule limiter. Both expanded listeners of a
            // tcp_udp rule reuse the same Arc so the budget isn't doubled.
            let rate_limit = self
                .rule_limiters
                .entry(listener.rule_id)
                .and_modify(|managed| {
                    if managed.upload_bps != listener.upload_limit_bps
                        || managed.download_bps != listener.download_limit_bps
                    {
                        *managed = ManagedRateLimit::new(
                            listener.upload_limit_bps,
                            listener.download_limit_bps,
                        );
                    }
                })
                .or_insert_with(|| {
                    ManagedRateLimit::new(listener.upload_limit_bps, listener.download_limit_bps)
                })
                .limiter
                .clone();
            let counter = self.counter.clone();
            let connections = self.connections.clone();
            let port = listener.port;
            let rule_id = listener.rule_id;
            let ws_path = listener.ws_path.clone();
            let errors = self.listener_errors.clone();
            let src_ipv4 = self.source_ipv4;
            let proto_str = match listener.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Uot => "uot",
                Protocol::TcpUdp => "tcpudp",
            }
            .to_string();

            // Defensive guards before spawning.
            // UDP only supports Raw transport (WS/TLS are TCP-only).
            if listener.protocol == Protocol::Udp && listener.node_transport != NodeTransport::Raw {
                tracing::warn!(
                    "rule {}: UDP does not support node_transport {:?} — skipping listener on {}",
                    rule_id,
                    listener.node_transport,
                    port
                );
                continue;
            }
            // v1.0.8: WS / TLS entry transports are DISABLED at runtime. The
            // panel hid them in v0.4.20 (every rule is `raw`), and having the
            // NODE terminate WS/TLS is fundamentally incompatible with
            // transparently relaying an end-to-end tunnel — VLESS+WS+TLS,
            // Trojan, VMess, etc. MUST be raw-forwarded, because the client's
            // WS/TLS handshake is meant for the FINAL server, not this relay.
            // The implementations (ws.rs / tls.rs / cert_reloader.rs) are kept
            // for possible future revival but are never served. A stray ws/tls
            // config is skipped + reported so the operator can see why the port
            // isn't forwarding (the `(Tcp, Ws)` / `(Tcp, TlsSimple)` match arms
            // below are consequently unreachable at runtime — kept on purpose).
            if matches!(
                listener.node_transport,
                NodeTransport::Ws | NodeTransport::TlsSimple
            ) {
                tracing::warn!(
                    "rule {}: node_transport {:?} is disabled and will not be served — \
                     skipping listener on port {} (use raw; WS/TLS entry transport is retired)",
                    rule_id,
                    listener.node_transport,
                    port
                );
                errors.lock().await.push(ListenerError {
                    port,
                    protocol: proto_str.clone(),
                    error: format!("{:?} entry transport is disabled", listener.node_transport),
                    tunnel_id: None,
                    rule_id: Some(rule_id),
                });
                continue;
            }
            let uot_config_valid = match listener.uot_role {
                UotRole::Ingress => {
                    listener.protocol == Protocol::Udp
                        && listener.uot_token.as_deref().is_some_and(|t| t.len() == 64)
                }
                UotRole::Relay => {
                    listener.protocol == Protocol::Uot
                        && listener.uot_token.as_deref().is_some_and(|t| t.len() == 64)
                        && listener
                            .uot_next_token
                            .as_deref()
                            .is_some_and(|t| t.len() == 64)
                }
                UotRole::Egress => {
                    listener.protocol == Protocol::Uot
                        && listener.uot_token.as_deref().is_some_and(|t| t.len() == 64)
                }
                UotRole::Disabled => listener.protocol != Protocol::Uot,
            };
            if !uot_config_valid {
                tracing::error!(
                    "rule {}: invalid UOT role/token configuration on port {}; refusing listener",
                    rule_id,
                    port
                );
                errors.lock().await.push(ListenerError {
                    port,
                    protocol: proto_str.clone(),
                    error: "invalid UOT role/token configuration".into(),
                    tunnel_id: None,
                    rule_id: Some(rule_id),
                });
                continue;
            }
            super::selector::spawn_active_probes(
                Arc::downgrade(&selector),
                targets.clone(),
                self.source_ipv4,
                target_probe_uses_tcp(listener),
            );

            let handle: tokio::task::JoinHandle<()> = match (
                listener.protocol,
                listener.node_transport,
            ) {
                // v1.0.4: TCP — bind BOTH families synchronously (errors surface
                // now, per-family success known), then supervise both serve loops
                // with select! so if either dies the task ends and the manager's
                // dead-listener detection restarts it.
                (Protocol::Tcp, NodeTransport::Raw) => {
                    use crate::forwarder::outbound::bind_tcp_listener_with_fast_open;
                    // tcp_fast_open controls outbound dialing on every chain
                    // hop. Only non-billing downstream hops enable TFO on the
                    // listening socket; the public entry must not unexpectedly
                    // accept replayable Fast Open data from arbitrary clients.
                    let listener_fast_open = listener.tcp_fast_open && !listener.count_traffic;
                    let mut v4_listener = None;
                    let mut v6_listener = None;
                    if let Some(ip4) = ip_v4 {
                        match bind_tcp_listener_with_fast_open(ip4, port, listener_fast_open) {
                            Ok(l) => {
                                tracing::info!(
                                    "TCP bound {} (rule {})",
                                    SocketAddr::new(ip4, port),
                                    rule_id
                                );
                                v4_listener = Some(l);
                            }
                            Err(e) => {
                                tracing::error!("TCP IPv4 bind {}:{} failed: {}", ip4, port, e);
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv4: {}", e),
                                    tunnel_id: None,
                                    rule_id: Some(rule_id),
                                });
                            }
                        }
                    }
                    if let Some(ip6) = ip_v6 {
                        match bind_tcp_listener_with_fast_open(ip6, port, listener_fast_open) {
                            Ok(l) => {
                                tracing::info!(
                                    "TCP bound {} (rule {})",
                                    SocketAddr::new(ip6, port),
                                    rule_id
                                );
                                v6_listener = Some(l);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "TCP IPv6 bind [{}]:{} failed: {} — IPv4 continues",
                                    ip6,
                                    port,
                                    e
                                );
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv6: {}", e),
                                    tunnel_id: None,
                                    rule_id: Some(rule_id),
                                });
                            }
                        }
                    }
                    // Only fail the rule when NEITHER family bound.
                    if v4_listener.is_none() && v6_listener.is_none() {
                        tracing::error!(
                            "TCP rule {}: no listener bound on port {} (all families failed)",
                            rule_id,
                            port
                        );
                        continue;
                    }
                    let tgt = targets.clone();
                    let sel = selector.clone();
                    let rl = rate_limit.clone();
                    let ctr = counter.clone();
                    let cn = connections.clone();
                    let rid = rule_id;
                    let ipv4_src = src_ipv4;
                    let count_traffic = listener.count_traffic;
                    let tcp_fast_open = listener.tcp_fast_open;
                    let tunnel4 = listener_tunnel.clone();
                    let tunnel6 = listener_tunnel.clone();
                    // v1.2.0: both families get a gate cloned from the SAME
                    // RuleRuntime, so `max_connections` is a per-rule total
                    // rather than a per-family allowance.
                    let gate4 = self
                        .rule_runtime
                        .entry(rule_id)
                        .or_default()
                        .gate_with_credentials(
                            listener.max_connections,
                            listener_tunnel.as_ref().into_iter().flat_map(|client| {
                                link_scope_credentials(
                                    &client.link_scope,
                                    &current_credential_revisions,
                                )
                            }),
                        );
                    let gate6 = gate4.clone();
                    tokio::spawn(async move {
                        type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                        let (tgt4, sel4, rl4, ctr4, cn4) = (
                            tgt.clone(),
                            sel.clone(),
                            rl.clone(),
                            ctr.clone(),
                            cn.clone(),
                        );
                        let v4_fut = async move {
                            if let Some(l) = v4_listener {
                                tcp::serve_tcp_listener(
                                    l,
                                    tgt4,
                                    sel4,
                                    rl4,
                                    ctr4,
                                    cn4,
                                    rid,
                                    ipv4_src,
                                    gate4,
                                    count_traffic,
                                    tcp_fast_open,
                                    tunnel4,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        let v6_fut = async move {
                            if let Some(l) = v6_listener {
                                tcp::serve_tcp_listener(
                                    l,
                                    tgt,
                                    sel,
                                    rl,
                                    ctr,
                                    cn,
                                    rid,
                                    ipv4_src,
                                    gate6,
                                    count_traffic,
                                    tcp_fast_open,
                                    tunnel6,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        tokio::select! {
                            r = v4_fut => { if let Err(e) = r { tracing::error!("TCP v4 serve ended (rule {}): {}", rid, e); } }
                            r = v6_fut => { if let Err(e) = r { tracing::error!("TCP v6 serve ended (rule {}): {}", rid, e); } }
                        }
                    })
                }
                // v1.0.4: UDP — bind BOTH families synchronously, supervise both
                // receive loops with select! (mirrors the TCP arm above).
                (Protocol::Udp, NodeTransport::Raw) => {
                    use crate::forwarder::outbound::bind_udp_socket;
                    let mut v4_sock = None;
                    let mut v6_sock = None;
                    if let Some(ip4) = ip_v4 {
                        match bind_udp_socket(ip4, port) {
                            Ok(s) => {
                                tracing::info!(
                                    "UDP bound {} (rule {})",
                                    SocketAddr::new(ip4, port),
                                    rule_id
                                );
                                v4_sock = Some(Arc::new(s));
                            }
                            Err(e) => {
                                tracing::error!("UDP IPv4 bind {}:{} failed: {}", ip4, port, e);
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv4: {}", e),
                                    tunnel_id: None,
                                    rule_id: Some(rule_id),
                                });
                            }
                        }
                    }
                    if let Some(ip6) = ip_v6 {
                        match bind_udp_socket(ip6, port) {
                            Ok(s) => {
                                tracing::info!(
                                    "UDP bound {} (rule {})",
                                    SocketAddr::new(ip6, port),
                                    rule_id
                                );
                                v6_sock = Some(Arc::new(s));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "UDP IPv6 bind [{}]:{} failed: {} — IPv4 continues",
                                    ip6,
                                    port,
                                    e
                                );
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv6: {}", e),
                                    tunnel_id: None,
                                    rule_id: Some(rule_id),
                                });
                            }
                        }
                    }
                    if v4_sock.is_none() && v6_sock.is_none() {
                        tracing::error!(
                            "UDP rule {}: no listener bound on port {} (all families failed)",
                            rule_id,
                            port
                        );
                        continue;
                    }
                    let tgt = targets.clone();
                    let sel = selector.clone();
                    let rl = rate_limit.clone();
                    let ctr = counter.clone();
                    let cn = connections.clone();
                    let rid = rule_id;
                    let ipv4_src = src_ipv4;
                    let count_traffic = listener.count_traffic;
                    let uot_role = listener.uot_role;
                    let uot_token4 = listener.uot_token.clone();
                    let uot_token6 = listener.uot_token.clone();
                    let zero_rtt = listener.zero_rtt;
                    let tunnel4 = listener_tunnel.clone();
                    let tunnel6 = listener_tunnel.clone();
                    let credential_cancellation = listener_tunnel.as_ref().map(|client| {
                        self.rule_runtime
                            .entry(rule_id)
                            .or_default()
                            .cancellation_with_credentials(link_scope_credentials(
                                &client.link_scope,
                                &current_credential_revisions,
                            ))
                    });
                    let credential_cancellation4 = credential_cancellation.clone();
                    let credential_cancellation6 = credential_cancellation;
                    tokio::spawn(async move {
                        type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                        let (tgt4, sel4, rl4, ctr4, cn4) = (
                            tgt.clone(),
                            sel.clone(),
                            rl.clone(),
                            ctr.clone(),
                            cn.clone(),
                        );
                        let v4_fut = async move {
                            if let Some(s) = v4_sock {
                                if uot_role == UotRole::Ingress || tunnel4.is_some() {
                                    uot::serve_ingress(
                                        s,
                                        tgt4,
                                        sel4,
                                        uot_token4.unwrap_or_default(),
                                        zero_rtt,
                                        rl4,
                                        ctr4,
                                        cn4,
                                        rid,
                                        ipv4_src,
                                        count_traffic,
                                        tunnel4,
                                        credential_cancellation4,
                                    )
                                    .await
                                } else {
                                    udp::serve_udp_listener(
                                        s,
                                        tgt4,
                                        sel4,
                                        rl4,
                                        ctr4,
                                        cn4,
                                        rid,
                                        ipv4_src,
                                        count_traffic,
                                    )
                                    .await
                                }
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        let v6_fut = async move {
                            if let Some(s) = v6_sock {
                                if uot_role == UotRole::Ingress || tunnel6.is_some() {
                                    uot::serve_ingress(
                                        s,
                                        tgt,
                                        sel,
                                        uot_token6.unwrap_or_default(),
                                        zero_rtt,
                                        rl,
                                        ctr,
                                        cn,
                                        rid,
                                        ipv4_src,
                                        count_traffic,
                                        tunnel6,
                                        credential_cancellation6,
                                    )
                                    .await
                                } else {
                                    udp::serve_udp_listener(
                                        s,
                                        tgt,
                                        sel,
                                        rl,
                                        ctr,
                                        cn,
                                        rid,
                                        ipv4_src,
                                        count_traffic,
                                    )
                                    .await
                                }
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        tokio::select! {
                            r = v4_fut => { if let Err(e) = r { tracing::error!("UDP v4 serve ended (rule {}): {}", rid, e); } }
                            r = v6_fut => { if let Err(e) = r { tracing::error!("UDP v6 serve ended (rule {}): {}", rid, e); } }
                        }
                    })
                }
                // Internal UOT server for intermediate/exit hops. It is always
                // raw TCP on the wire and authenticated before any frame is
                // accepted; the public rule API cannot create this protocol.
                (Protocol::Uot, NodeTransport::Raw) => {
                    use crate::forwarder::outbound::bind_tcp_listener;
                    let mut v4_listener = None;
                    let mut v6_listener = None;
                    if let Some(ip4) = ip_v4 {
                        match bind_tcp_listener(ip4, port) {
                            Ok(listener) => v4_listener = Some(listener),
                            Err(error) => errors.lock().await.push(ListenerError {
                                port,
                                protocol: proto_str.clone(),
                                error: format!("IPv4: {}", error),
                                tunnel_id: None,
                                rule_id: Some(rule_id),
                            }),
                        }
                    }
                    if let Some(ip6) = ip_v6 {
                        match bind_tcp_listener(ip6, port) {
                            Ok(listener) => v6_listener = Some(listener),
                            Err(error) => errors.lock().await.push(ListenerError {
                                port,
                                protocol: proto_str.clone(),
                                error: format!("IPv6: {}", error),
                                tunnel_id: None,
                                rule_id: Some(rule_id),
                            }),
                        }
                    }
                    if v4_listener.is_none() && v6_listener.is_none() {
                        continue;
                    }
                    let inbound_token = listener.uot_token.clone().unwrap_or_default();
                    let downstream_token = listener.uot_next_token.clone();
                    let relay = listener.uot_role == UotRole::Relay;
                    let (tgt4, sel4, token4, next4) = (
                        targets.clone(),
                        selector.clone(),
                        inbound_token.clone(),
                        downstream_token.clone(),
                    );
                    tokio::spawn(async move {
                        type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                        let v4_fut = async move {
                            if let Some(listener) = v4_listener {
                                uot::serve_listener(
                                    listener, tgt4, sel4, token4, next4, relay, src_ipv4,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        let v6_fut = async move {
                            if let Some(listener) = v6_listener {
                                uot::serve_listener(
                                    listener,
                                    targets,
                                    selector,
                                    inbound_token,
                                    downstream_token,
                                    relay,
                                    src_ipv4,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        tokio::select! {
                            result = v4_fut => if let Err(error) = result {
                                tracing::error!("UOT v4 serve ended (rule {}): {}", rule_id, error);
                            },
                            result = v6_fut => if let Err(error) = result {
                                tracing::error!("UOT v6 serve ended (rule {}): {}", rule_id, error);
                            },
                        }
                    })
                }
                // WS and TLS use IPv4 only (unchanged — this PR does not extend
                // their IPv6/outbound capability).
                (Protocol::Tcp, NodeTransport::Ws) => {
                    let ws_addr = SocketAddr::new(
                        ip_v4.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        port,
                    );
                    tokio::spawn(async move {
                        if let Err(e) = ws::start_ws_listener(
                            ws_addr,
                            targets,
                            selector,
                            rate_limit,
                            counter,
                            connections,
                            rule_id,
                            ws_path,
                        )
                        .await
                        {
                            tracing::error!("WS listener on {} failed: {}", port, e);
                            errors.lock().await.push(ListenerError {
                                port,
                                protocol: proto_str.clone(),
                                error: e.to_string(),
                                tunnel_id: None,
                                rule_id: Some(rule_id),
                            });
                        }
                    })
                }
                // v0.4.1: TLS Simple — node terminates TLS, then forwards TCP.
                // The tls_acceptor is cloned from the manager's shared Arc.
                // If None, the guard above already skipped this listener.
                (Protocol::Tcp, NodeTransport::TlsSimple) => {
                    let Some(tls_acceptor) = self.tls_acceptor.clone() else {
                        // Unreachable (guard above checks this), but defensive.
                        continue;
                    };
                    let tls_addr = SocketAddr::new(
                        ip_v4.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        port,
                    );
                    tokio::spawn(async move {
                        if let Err(e) = tls::start_tls_listener(
                            tls_addr,
                            targets,
                            selector,
                            rate_limit,
                            counter,
                            connections,
                            rule_id,
                            tls_acceptor,
                        )
                        .await
                        {
                            tracing::error!("TLS listener on {} failed: {}", port, e);
                            errors.lock().await.push(ListenerError {
                                port,
                                protocol: proto_str.clone(),
                                error: e.to_string(),
                                tunnel_id: None,
                                rule_id: Some(rule_id),
                            });
                        }
                    })
                }
                (Protocol::TcpUdp, _) => {
                    tracing::warn!(
                        "Received Protocol::TcpUdp in node — panel should have expanded it. Skipping."
                    );
                    continue;
                }
                (proto, transport) => {
                    tracing::warn!(
                        "rule {}: no listener implementation for {:?}/{:?} — skipping port {}",
                        rule_id,
                        proto,
                        transport,
                        port
                    );
                    continue;
                }
            };

            self.listeners.insert(
                key,
                ManagedListener {
                    handle,
                    fingerprint: ListenerFingerprint::from_listener(listener),
                },
            );
        }

        // ── Step 5: forget rules that are gone ──
        // v1.2.0: dropping a rule's RuleRuntime drops its watch::Sender, which
        // cancels any connection still forwarding for it. That is deliberate: a
        // rule removed from the config can no longer have its traffic attributed
        // or billed (step 2/3 already pruned its counters), so letting its
        // connections outlive it would forward bytes nobody accounts for.
        let leaving_rule_ids: Vec<i64> = self
            .rule_runtime
            .keys()
            .filter(|rule_id| !desired_rule_ids.contains(rule_id))
            .copied()
            .collect();
        for rule_id in leaving_rule_ids {
            let Some(runtime) = self.rule_runtime.remove(&rule_id) else {
                continue;
            };
            if runtime_draining_rule_ids.contains(&rule_id) && !runtime.is_idle() {
                self.retired_rule_runtimes
                    .push(RetiredRuleRuntime { rule_id, runtime });
            }
            // Otherwise dropping the runtime cancels its receivers, preserving
            // the existing pause/delete/security-revocation behavior.
        }
        let retired_rule_ids: HashSet<i64> = self
            .retired_rule_runtimes
            .iter()
            .map(|retired| retired.rule_id)
            .collect();
        self.rule_limiters.retain(|rule_id, _| {
            desired_rule_ids.contains(rule_id) || retired_rule_ids.contains(rule_id)
        });
        // v1.2.0: remember the applied config so restart_rule can rebuild a
        // rule's listeners from it without a round-trip to the panel.
        self.last_config = Some(config.clone());
    }

    async fn apply_shared_tunnel_listeners(
        &mut self,
        config: &NodeConfigResponse,
        credential_revisions: &HashMap<i64, i64>,
        route_transition_rule_ids: &HashSet<i64>,
    ) {
        self.retired_tunnel_runtimes
            .retain(|retired| !retired.runtime.is_idle());
        for retired in &self.retired_tunnel_runtimes {
            if config.terminate_tunnel_ids.contains(&retired.tunnel_id) {
                retired.runtime.cancel_all();
            }
        }
        let mut desired: HashMap<TunnelListenerKey, TunnelListenerConfig> = config
            .tunnels
            .iter()
            .filter(|tunnel| tunnel.port != 0)
            .map(|tunnel| ((tunnel.tunnel_id, tunnel.port), tunnel.clone()))
            .collect();
        // If the shared socket remains at the same key, retain only the old
        // routes covered by the lease. The current config still supplies the
        // accepting credential, next hop and all unrelated routes.
        for (key, managed) in &self.shared_tunnel_listeners {
            let Some(wanted) = desired.get_mut(key) else {
                continue;
            };
            for route in &managed.config.routes {
                if route_transition_rule_ids.contains(&route.rule_id)
                    && !wanted
                        .routes
                        .iter()
                        .any(|candidate| candidate.rule_id == route.rule_id)
                {
                    wanted.routes.push(route.clone());
                }
            }
        }
        // Never evict a live link. Inactive histories outlive the complete
        // signed-header and nonce-cache acceptance window, then old unused
        // credential revisions release their memory.
        let desired_replay_keys: HashSet<TunnelReplayKey> =
            desired.values().map(tunnel_replay_key).collect();
        let now = Instant::now();
        self.tunnel_replay_caches.retain(|key, entry| {
            if desired_replay_keys.contains(key) {
                entry.last_used = now;
                true
            } else {
                now.saturating_duration_since(entry.last_used) < TUNNEL_REPLAY_RETENTION
            }
        });
        let mut stop = Vec::new();
        let mut hot_updates = Vec::new();
        for (key, managed) in &self.shared_tunnel_listeners {
            let wanted = desired.get(key);
            let changed = wanted.is_none_or(|wanted| managed.config != *wanted);
            if managed.handle.is_finished() {
                if wanted.is_none()
                    && config
                        .terminate_tunnel_ids
                        .contains(&managed.config.tunnel_id)
                {
                    managed.runtime.cancel_all();
                }
                stop.push(*key);
            } else if let Some(wanted) = wanted {
                if changed {
                    hot_updates.push((*key, wanted.clone()));
                }
            } else {
                let terminated = config
                    .terminate_tunnel_ids
                    .contains(&managed.config.tunnel_id);
                if terminated {
                    managed.runtime.cancel_all();
                }
                let keep_for_transition = !terminated
                    && managed
                        .config
                        .routes
                        .iter()
                        .any(|route| route_transition_rule_ids.contains(&route.rule_id));
                if !keep_for_transition {
                    stop.push(*key);
                }
            }
        }
        for key in stop {
            if let Some(managed) = self.shared_tunnel_listeners.remove(&key) {
                let ManagedTunnelListener {
                    mut handle,
                    config: previous,
                    runtime,
                    ..
                } = managed;
                handle.abort();
                let _ = (&mut handle).await;
                if !runtime.is_idle() {
                    self.retired_tunnel_runtimes.push(RetiredTunnelRuntime {
                        tunnel_id: previous.tunnel_id,
                        runtime,
                    });
                }
            }
        }

        // Keep the bound socket stable when only the route table, next hop or
        // credentials change. This preserves unrelated rules on the same shared
        // port. A credential rotation swaps the accepting context first, then
        // cancels streams authenticated with the previous generation.
        for (key, wanted) in hot_updates {
            let replay = self.replay_cache_for_tunnel(&wanted);
            if let Some(managed) = self.shared_tunnel_listeners.get_mut(&key) {
                let credentials_revoked = tunnel_credentials_revoked(&managed.config, &wanted);
                managed.state.update(
                    wanted.clone(),
                    credential_revisions,
                    replay,
                    credentials_revoked,
                );
                managed.config = wanted;
            }
        }

        for tunnel in desired.values() {
            if tunnel.port == 0 {
                continue;
            }
            let key = (tunnel.tunnel_id, tunnel.port);
            if self.shared_tunnel_listeners.contains_key(&key) {
                continue;
            }
            let ip_v4 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv4);
            let ip_v6 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv6);
            let mut v4 = None;
            let mut v6 = None;
            if let Some(ip) = ip_v4 {
                match crate::forwarder::outbound::bind_tcp_listener(ip, tunnel.port) {
                    Ok(listener) => v4 = Some(listener),
                    Err(error) => self.listener_errors.lock().await.push(ListenerError {
                        port: tunnel.port,
                        protocol: "tunnel/tcp".into(),
                        error: format!("IPv4: {error}"),
                        tunnel_id: Some(tunnel.tunnel_id),
                        rule_id: None,
                    }),
                }
            }
            if let Some(ip) = ip_v6 {
                match crate::forwarder::outbound::bind_tcp_listener(ip, tunnel.port) {
                    Ok(listener) => v6 = Some(listener),
                    Err(error) => self.listener_errors.lock().await.push(ListenerError {
                        port: tunnel.port,
                        protocol: "tunnel/tcp".into(),
                        error: format!("IPv6: {error}"),
                        tunnel_id: Some(tunnel.tunnel_id),
                        rule_id: None,
                    }),
                }
            }
            if v4.is_none() && v6.is_none() {
                continue;
            }
            let replay = self.replay_cache_for_tunnel(tunnel);
            let udp_sessions = Arc::new(tokio::sync::Semaphore::new(4096));
            let runtime = super::tunnel::TunnelRuntime::new();
            let source = self.source_ipv4;
            let state = super::tunnel::TunnelListenerState::new(
                tunnel.clone(),
                credential_revisions,
                source,
                replay,
                udp_sessions,
                runtime.clone(),
            );
            let state4 = state.clone();
            let state6 = state.clone();
            let handle = tokio::spawn(async move {
                type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                let v4_fut = async move {
                    if let Some(listener) = v4 {
                        super::tunnel::serve_listener(listener, state4).await
                    } else {
                        std::future::pending::<SrvResult>().await
                    }
                };
                let v6_fut = async move {
                    if let Some(listener) = v6 {
                        super::tunnel::serve_listener(listener, state6).await
                    } else {
                        std::future::pending::<SrvResult>().await
                    }
                };
                tokio::select! {
                    result = v4_fut => if let Err(error) = result { tracing::error!("shared tunnel v4 listener ended: {error}"); },
                    result = v6_fut => if let Err(error) = result { tracing::error!("shared tunnel v6 listener ended: {error}"); },
                }
            });
            self.shared_tunnel_listeners.insert(
                key,
                ManagedTunnelListener {
                    handle,
                    config: tunnel.clone(),
                    state,
                    runtime,
                },
            );
        }
    }

    /// Revoke every authenticated preset-tunnel generation held by this node.
    /// A rotated device group may belong to a listener generation that has
    /// already left the current path, so the latest config cannot enumerate
    /// every affected connection precisely.
    pub fn revoke_tunnel_credentials(&mut self, group_id: i64) {
        self.revoke_tunnel_credential_generations(group_id, None);
    }

    /// Fail closed when the panel announced a credential rotation but the node
    /// could not fetch the replacement config. Existing generations using the
    /// group are revoked and accept loops whose *current* route still uses the
    /// old credential are stopped. An unrelated current route is left running
    /// even if it still has a historical connection draining through the group.
    pub async fn fail_closed_tunnel_credentials(
        &mut self,
        group_id: i64,
    ) -> Option<NodeConfigResponse> {
        self.revoke_tunnel_credentials(group_id);

        let sanitized = self
            .last_config
            .as_ref()
            .map(|config| fail_closed_config_for_group(config, group_id));
        let affected_rule_ids: HashSet<i64> = self
            .last_config
            .as_ref()
            .into_iter()
            .flat_map(|config| config.listeners.iter())
            .filter(|listener| {
                sanitized.as_ref().is_none_or(|safe| {
                    !safe
                        .listeners
                        .iter()
                        .any(|candidate| candidate.rule_id == listener.rule_id)
                })
            })
            .map(|listener| listener.rule_id)
            .collect();

        let listener_keys: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|(_, listener)| affected_rule_ids.contains(&listener.fingerprint.rule_id))
            .map(|(key, _)| *key)
            .collect();
        let tunnel_keys: Vec<TunnelListenerKey> = self
            .shared_tunnel_listeners
            .iter()
            .filter(|(_, listener)| tunnel_listener_uses_group(&listener.config, group_id))
            .map(|(key, _)| *key)
            .collect();

        let mut handles = Vec::with_capacity(listener_keys.len() + tunnel_keys.len());
        for key in listener_keys {
            if let Some(listener) = self.listeners.remove(&key) {
                listener.handle.abort();
                handles.push(listener.handle);
            }
        }
        for key in tunnel_keys {
            if let Some(listener) = self.shared_tunnel_listeners.remove(&key) {
                listener.handle.abort();
                handles.push(listener.handle);
            }
        }
        for mut handle in handles {
            let _ = (&mut handle).await;
        }
        if let Some(config) = sanitized.as_ref() {
            self.last_config = Some(config.clone());
        }
        sanitized
    }

    fn revoke_tunnel_credential_generations(
        &mut self,
        group_id: i64,
        current_revision: Option<i64>,
    ) {
        for managed in self.shared_tunnel_listeners.values() {
            if managed.runtime.uses_credential_group(group_id) {
                managed
                    .runtime
                    .revoke_credential_group(group_id, current_revision);
            }
        }
        for retired in &self.retired_tunnel_runtimes {
            if retired.runtime.uses_credential_group(group_id) {
                retired
                    .runtime
                    .revoke_credential_group(group_id, current_revision);
            }
        }
        for retired in &self.retired_rule_runtimes {
            if retired.runtime.uses_credential_group(group_id) {
                retired
                    .runtime
                    .revoke_credential_group(group_id, current_revision);
            }
        }

        // Entry-side public TCP connections are owned by per-rule runtimes.
        // Restrict cancellation to rules carrying preset-tunnel client metadata
        // so direct and rule-local chain connections remain untouched.
        let preset_rule_ids: Vec<i64> = self
            .rule_runtime
            .iter()
            .filter(|(_, runtime)| runtime.uses_credential_group(group_id))
            .map(|(rule_id, _)| *rule_id)
            .collect();
        for rule_id in preset_rule_ids {
            if let Some(runtime) = self.rule_runtime.get(&rule_id) {
                runtime.revoke_credential_group(group_id, current_revision);
            }
        }
    }

    /// Fail closed after the panel explicitly rejects this node's credential.
    /// An ordinary empty config intentionally lets old tunnel streams drain
    /// during topology edits; credential rejection is different and must tear
    /// down every authenticated generation immediately.
    pub fn revoke_all_tunnel_credentials(&mut self) {
        for managed in self.shared_tunnel_listeners.values() {
            managed.runtime.cancel_all();
        }
        for retired in &self.retired_tunnel_runtimes {
            retired.runtime.cancel_all();
        }
        for retired in &self.retired_rule_runtimes {
            retired.runtime.cancel_all();
        }
        for runtime in self.rule_runtime.values() {
            if runtime.uses_tunnel_credentials() {
                runtime.cancel_all();
            }
        }
    }

    fn replay_cache_for_tunnel(
        &mut self,
        tunnel: &TunnelListenerConfig,
    ) -> Arc<super::tunnel::ReplayCache> {
        let replay_key = tunnel_replay_key(tunnel);
        let now = Instant::now();
        self.tunnel_replay_caches
            .entry(replay_key)
            .and_modify(|entry| entry.last_used = now)
            .or_insert_with(|| TunnelReplayCacheEntry {
                cache: Arc::new(super::tunnel::ReplayCache::default()),
                last_used: now,
            })
            .cache
            .clone()
    }

    /// v1.2.0: restart ONE rule — drop every connection it is currently
    /// forwarding, then rebuild its listeners from the last applied config.
    ///
    /// Returns `(connections_dropped, listeners_restarted)`. A rule with no
    /// listeners on this node returns `(0, 0)`; the caller reports that as
    /// "nothing to do here" rather than an error, because a rule legitimately
    /// spans only some of a group's nodes.
    ///
    /// Order matters. Connections are cancelled BEFORE the listeners are torn
    /// down and rebuilt: the connection tasks are detached, so tearing the
    /// listener down first would rebind the port while the old connections kept
    /// forwarding — the exact no-op this command exists to avoid.
    ///
    /// The rule's `paused` state is never consulted or written here. A restart
    /// is not a state transition: it re-creates whatever the current config
    /// says should be running. If the panel has paused the rule, the config
    /// carries no listener for it and this is a no-op.
    pub async fn restart_rule(&mut self, rule_id: i64) -> (u64, usize) {
        // Cancel first — see the ordering note above.
        //
        // No runtime is NOT the same as nothing to do: direct UDP listeners have
        // no accept() and therefore no per-rule cancellation runtime. Preset
        // tunnel UDP listeners do have one so credential rotation can close warm
        // UOT channels, but restart must continue to handle both kinds. Treating
        // a missing runtime as "return early" made direct UDP restart a silent
        // no-op — and silent is the operative word, because the panel reports
        // success as soon as the command reaches the node. Whether there are
        // connections to cancel is decided here; whether there are listeners to
        // rebuild is decided below.
        let dropped = self
            .rule_runtime
            .get(&rule_id)
            .map(|rt| rt.cancel_all())
            .unwrap_or(0);
        let retired_dropped = self
            .retired_rule_runtimes
            .iter()
            .filter(|retired| retired.rule_id == rule_id)
            .map(|retired| retired.runtime.cancel_all())
            .sum::<u64>();
        let dropped = dropped.saturating_add(retired_dropped);

        let keys: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|(_, m)| m.fingerprint.rule_id == rule_id)
            .map(|(k, _)| *k)
            .collect();

        // Genuinely nothing here — this node doesn't serve the rule (it may
        // legitimately span only some of a group's nodes), or it's paused.
        if keys.is_empty() {
            return (dropped, 0);
        }

        for key in &keys {
            if let Some(m) = self.listeners.remove(key) {
                let handle = m.handle;
                handle.abort();
                // Await the aborted task so the OS releases the listen socket
                // before the rebuild re-binds the same port — without this the
                // bind races teardown and fails with "address already in use".
                // (Same reason as the equivalent await in apply_config.)
                let _ = (&mut { handle }).await;
            }
        }

        let restarted = keys.len();
        if restarted > 0 {
            // Rebuild from the cached config. apply_config re-creates exactly
            // the listeners we just removed (every other listener still matches
            // its fingerprint and is skipped), and it reuses this rule's
            // existing RuleRuntime, so the live counter stays consistent with
            // the connections that survive — there are none, we just cancelled
            // them all.
            if let Some(cfg) = self.last_config.clone() {
                self.apply_config(&cfg).await;
            } else {
                tracing::warn!(
                    "rule {}: restart tore down {} listener(s) but no cached config exists \
                     to rebuild from; the next config push will restore them",
                    rule_id,
                    restarted
                );
            }
        }

        tracing::info!(
            "rule {}: restarted — dropped {} connection(s), rebuilt {} listener(s)",
            rule_id,
            dropped,
            restarted
        );
        (dropped, restarted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::{ConnectionTracker, TrafficCounter};
    use relay_shared::protocol::{ListenerConfig, NodeConfigResponse, NodeTransport, Protocol};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    impl ForwarderManager {
        /// Test-only accessor: the set of listener keys currently registered.
        fn listener_keys(&self) -> Vec<ListenerKey> {
            self.listeners.keys().copied().collect()
        }

        /// Test-only accessor for a listener's fingerprint, if present.
        fn fingerprint(&self, key: &ListenerKey) -> Option<ListenerFingerprint> {
            self.listeners.get(key).map(|m| m.fingerprint.clone())
        }
    }

    /// Build a single-rule config. `targets` defaults to a dummy; tests that
    /// exercise hot-update pass explicit targets.
    fn one_rule(port: u16, proto: Protocol, transport: NodeTransport) -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port,
                protocol: proto,
                node_transport: transport,
                ws_path: None,
                targets: vec!["127.0.0.1:1".into()],
                target_weights: vec![],
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
                uot_role: UotRole::Disabled,
                uot_token: None,
                uot_next_token: None,
                zero_rtt: false,
                tcp_fast_open: false,
                count_traffic: true,
            }],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        }
    }

    fn cfg(
        port: u16,
        proto: Protocol,
        transport: NodeTransport,
        targets: Vec<&str>,
        ws_path: Option<&str>,
    ) -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port,
                protocol: proto,
                node_transport: transport,
                ws_path: ws_path.map(str::to_string),
                targets: targets.into_iter().map(String::from).collect(),
                target_weights: vec![],
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
                uot_role: UotRole::Disabled,
                uot_token: None,
                uot_next_token: None,
                zero_rtt: false,
                tcp_fast_open: false,
                count_traffic: true,
            }],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        }
    }

    fn fresh_mgr() -> ForwarderManager {
        ForwarderManager::new(
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
        )
    }

    #[tokio::test]
    async fn shared_route_update_keeps_same_accept_loop() {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        let mut config = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 901,
                port,
                hop_position: 1,
                auth_token: "manager-hot-key".repeat(5),
                link_scope: "901:0".into(),
                next: None,
                routes: vec![relay_shared::protocol::TunnelRouteConfig {
                    rule_id: 1,
                    protocol: "tcp".into(),
                    targets: vec!["127.0.0.1:9".into()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        manager.apply_config(&config).await;
        let key = (901, port);
        let original_task = manager.shared_tunnel_listeners[&key].handle.id();

        config.tunnels[0]
            .routes
            .push(relay_shared::protocol::TunnelRouteConfig {
                rule_id: 2,
                protocol: "tcp".into(),
                targets: vec!["127.0.0.1:10".into()],
                target_weights: vec![1],
                load_balance_strategy: LoadBalanceStrategy::First,
            });
        manager.apply_config(&config).await;

        assert_eq!(
            manager.shared_tunnel_listeners[&key].handle.id(),
            original_task,
            "route-table changes must not abort and rebind the shared socket"
        );
    }

    #[tokio::test]
    async fn route_transition_keeps_old_ordinary_listener_until_lease_disappears() {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        manager
            .apply_config(&one_rule(port, Protocol::Tcp, NodeTransport::Raw))
            .await;
        let key = (port, Protocol::Tcp, NodeTransport::Raw);
        let original_task = manager.listeners[&key].handle.id();

        let mut switched = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![1],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        manager.apply_config(&switched).await;
        assert_eq!(manager.listeners[&key].handle.id(), original_task);
        assert!(manager.rule_runtime.contains_key(&1));
        let gate = manager.rule_runtime[&1].gate(None);
        let live_connection = gate.admit().unwrap();

        switched.route_transition_rule_ids.clear();
        switched.route_drain_rule_ids = vec![1];
        manager.apply_config(&switched).await;
        assert!(!manager.listeners.contains_key(&key));
        assert!(!manager.rule_runtime.contains_key(&1));
        assert_eq!(manager.retired_rule_runtimes.len(), 1);

        drop(live_connection);
        manager.apply_config(&switched).await;
        assert!(manager.retired_rule_runtimes.is_empty());
    }

    #[tokio::test]
    async fn route_staging_keeps_old_entry_generation_until_activation() {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        let original = one_rule(port, Protocol::Tcp, NodeTransport::Raw);
        manager.apply_config(&original).await;
        let key = (port, Protocol::Tcp, NodeTransport::Raw);
        let original_task = manager.listeners[&key].handle.id();
        let original_fingerprint = manager.listeners[&key].fingerprint.clone();

        let mut staged = original.clone();
        staged.listeners[0].targets = vec!["127.0.0.1:10".into()];
        staged.route_staging_rule_ids = vec![1];
        staged.route_transition_rule_ids = vec![1];
        manager.apply_config(&staged).await;
        assert_eq!(manager.listeners[&key].handle.id(), original_task);
        assert_eq!(manager.listeners[&key].fingerprint, original_fingerprint);

        staged.route_staging_rule_ids.clear();
        manager.apply_config(&staged).await;
        assert_ne!(manager.listeners[&key].handle.id(), original_task);
        assert_ne!(manager.listeners[&key].fingerprint, original_fingerprint);
    }

    #[tokio::test]
    async fn route_transition_retains_removed_shared_route_and_socket() {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        let tunnel = TunnelListenerConfig {
            tunnel_id: 902,
            port,
            hop_position: 1,
            auth_token: "transition-key".repeat(5),
            link_scope: "902:0:10:20".into(),
            next: None,
            routes: vec![relay_shared::protocol::TunnelRouteConfig {
                rule_id: 1,
                protocol: "tcp".into(),
                targets: vec!["127.0.0.1:9".into()],
                target_weights: vec![1],
                load_balance_strategy: LoadBalanceStrategy::First,
            }],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let active = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![tunnel],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        manager.apply_config(&active).await;
        let key = (902, port);
        let original_task = manager.shared_tunnel_listeners[&key].handle.id();

        let mut switched = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![1],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        manager.apply_config(&switched).await;
        let retained = &manager.shared_tunnel_listeners[&key];
        assert_eq!(retained.handle.id(), original_task);
        assert_eq!(retained.config.routes[0].rule_id, 1);

        switched.route_transition_rule_ids.clear();
        manager.apply_config(&switched).await;
        assert!(!manager.shared_tunnel_listeners.contains_key(&key));
    }

    #[tokio::test]
    async fn tunnel_termination_overrides_route_transition_lease() {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        let mut active = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 903,
                port,
                hop_position: 1,
                auth_token: "terminated-key".repeat(5),
                link_scope: "903:0:10:20".into(),
                next: None,
                routes: vec![relay_shared::protocol::TunnelRouteConfig {
                    rule_id: 1,
                    protocol: "tcp".into(),
                    targets: vec!["127.0.0.1:9".into()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        manager.apply_config(&active).await;
        active.tunnels.clear();
        active.terminate_tunnel_ids.push(903);
        active.route_transition_rule_ids.push(1);
        manager.apply_config(&active).await;
        assert!(manager.shared_tunnel_listeners.is_empty());
    }

    /// v1.0.9: a rate-limit change (set OR cleared) must change the listener
    /// fingerprint so apply() restarts the listener and the new cap takes
    /// effect — without this, a running task keeps its captured old cap until
    /// the node restarts.
    #[test]
    fn rate_limit_change_alters_fingerprint() {
        let mut l = one_rule(40050, Protocol::Tcp, NodeTransport::Raw)
            .listeners
            .pop()
            .unwrap();
        let unlimited = ListenerFingerprint::from_listener(&l);

        l.upload_limit_bps = Some(1_000_000);
        let up_limited = ListenerFingerprint::from_listener(&l);
        assert_ne!(
            unlimited, up_limited,
            "setting an upload cap must change the fingerprint"
        );

        // Clearing the upload cap and setting a download cap: still distinct.
        l.upload_limit_bps = None;
        l.download_limit_bps = Some(2_000_000);
        let down_limited = ListenerFingerprint::from_listener(&l);
        assert_ne!(up_limited, down_limited);
        assert_ne!(unlimited, down_limited);
    }

    /// v1.2.0: a connection-cap change must restart the listener, for the same
    /// reason a rate-limit change must — the accept loop captures the cap when
    /// it spawns.
    #[test]
    fn max_connections_change_alters_fingerprint() {
        let mut l = one_rule(40051, Protocol::Tcp, NodeTransport::Raw)
            .listeners
            .pop()
            .unwrap();
        let uncapped = ListenerFingerprint::from_listener(&l);

        l.max_connections = Some(100);
        let capped = ListenerFingerprint::from_listener(&l);
        assert_ne!(
            uncapped, capped,
            "setting a connection cap must change the fingerprint"
        );

        l.max_connections = Some(200);
        assert_ne!(
            capped,
            ListenerFingerprint::from_listener(&l),
            "raising the cap must also change the fingerprint"
        );
    }

    #[test]
    fn tcp_fast_open_change_alters_fingerprint() {
        let mut listener = one_rule(40051, Protocol::Tcp, NodeTransport::Raw)
            .listeners
            .pop()
            .unwrap();
        let ordinary = ListenerFingerprint::from_listener(&listener);
        listener.tcp_fast_open = true;
        let fast_open = ListenerFingerprint::from_listener(&listener);
        assert_ne!(
            ordinary, fast_open,
            "enabling TFO must hot-reload the captured TCP listener/dialer"
        );
    }

    #[test]
    fn uot_egress_does_not_tcp_probe_the_final_udp_target() {
        let mut ingress = one_rule(40052, Protocol::Udp, NodeTransport::Raw)
            .listeners
            .pop()
            .unwrap();
        ingress.uot_role = UotRole::Ingress;
        assert!(target_probe_uses_tcp(&ingress));

        let mut relay = one_rule(40053, Protocol::Uot, NodeTransport::Raw)
            .listeners
            .pop()
            .unwrap();
        relay.uot_role = UotRole::Relay;
        assert!(target_probe_uses_tcp(&relay));

        let mut egress = relay;
        egress.uot_role = UotRole::Egress;
        assert!(!target_probe_uses_tcp(&egress));
    }

    /// Spawn an echo server and return its address. Used by the restart tests to
    /// prove a forwarded connection is really carrying data.
    async fn echo_target() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut b = [0u8; 256];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn tagged_udp_target(tag: u8) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((_n, peer)) = socket.recv_from(&mut buf).await {
                if socket.send_to(&[tag], peer).await.is_err() {
                    return;
                }
            }
        });
        addr
    }

    /// THE test for the restart feature: a live connection must actually be
    /// dropped, and the listener must come back up.
    ///
    /// This is not a formality. Connection tasks are detached `tokio::spawn`s,
    /// so the intuitive implementation (abort the listener, re-bind) leaves
    /// every established connection forwarding — the port gets rebound and not
    /// one connection is shed, which is the whole point of the feature. If this
    /// test regresses to "connection still alive", the restart is a placebo.
    #[tokio::test]
    async fn restart_rule_drops_live_connections_and_rebuilds_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = echo_target().await;
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new(); // IPv4-only keeps the assertions simple.
        let port = 40561;
        let c = cfg(
            port,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec![&target.to_string()],
            None,
        );
        mgr.apply_config(&c).await;

        // Establish a connection and prove it forwards.
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener must be up");
        client.write_all(b"before").await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before", "the rule must forward before restart");

        let (dropped, restarted) = mgr.restart_rule(1).await;
        assert_eq!(dropped, 1, "the one live connection must be counted");
        assert_eq!(restarted, 1, "the rule's single TCP listener must rebuild");

        // The OLD connection must now be dead. Read returns EOF (or errors) —
        // anything that echoes here means the restart shed nothing.
        let r = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!(
                "restart did NOT drop the connection — it echoed {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(_) => panic!("restart did NOT drop the connection — the read is still hanging"),
        }

        // ...and the listener must be serving again, on the same port.
        let mut fresh = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener must be re-bound after restart");
        fresh.write_all(b"after").await.unwrap();
        let n = fresh.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after", "the rebuilt listener must forward");
    }

    #[tokio::test]
    async fn restart_rule_also_cancels_retired_entry_runtime() {
        let mut manager = fresh_mgr();
        let runtime = RuleRuntime::new();
        let mut old_gate = runtime.gate_with_credential_groups(None, [10, 20]);
        let guard = old_gate.admit().unwrap();
        manager.retired_rule_runtimes.push(RetiredRuleRuntime {
            rule_id: 77,
            runtime,
        });

        let (dropped, restarted) = manager.restart_rule(77).await;
        assert_eq!((dropped, restarted), (1, 0));
        tokio::time::timeout(Duration::from_secs(1), old_gate.cancelled())
            .await
            .expect("restart must cancel a rule generation draining on its old entry");
        drop(guard);
    }

    /// Restarting a rule this node doesn't serve is a no-op, not a panic or a
    /// fabricated runtime entry — a rule legitimately spans only some nodes.
    #[tokio::test]
    async fn restart_unknown_rule_is_a_noop() {
        let mut mgr = fresh_mgr();
        assert_eq!(mgr.restart_rule(999).await, (0, 0));
        assert!(
            mgr.rule_runtime.is_empty(),
            "must not create runtime state for a rule that isn't here"
        );
    }

    /// A UDP-only rule must still restart: its listener is torn down and
    /// rebuilt, which is what drops its sessions (they live in the listener
    /// task's session map).
    ///
    /// Direct UDP has no accept() and no cancellable per-connection tasks, so it
    /// does not create a RuleRuntime (preset-tunnel UDP does create one for
    /// credential revocation). Therefore restart_rule must NOT treat "no
    /// runtime" as "nothing to do": a direct UDP-only rule has no runtime but
    /// very much has a listener. Getting this wrong is invisible from the panel,
    /// which reports success as soon as the command reaches the node — the
    /// operator would be told the rule restarted while the node did nothing.
    #[tokio::test]
    async fn restart_udp_only_rule_rebuilds_its_listener() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let c = cfg(
            40571,
            Protocol::Udp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c).await;
        assert_eq!(
            mgr.listener_keys().len(),
            1,
            "the UDP listener must be running before we restart it"
        );

        let (dropped, restarted) = mgr.restart_rule(1).await;
        assert_eq!(
            restarted, 1,
            "a UDP-only rule's listener MUST be rebuilt; 0 here means the \
             restart silently did nothing while the panel reported success"
        );
        // UDP sessions aren't individually cancellable — they die with the
        // listener — so nothing is reported as a dropped connection.
        assert_eq!(dropped, 0, "UDP has no per-connection tasks to cancel");
        assert_eq!(
            mgr.listener_keys().len(),
            1,
            "the listener must be back after the restart"
        );
    }

    /// The cap must survive an unrelated config push. apply_config rebuilds its
    /// local limiter map each run; if the connection counter were rebuilt the
    /// same way, every config edit would reset the count to 0 while the counted
    /// connections were still alive, and the cap would over-admit.
    #[tokio::test]
    async fn rule_runtime_survives_apply_and_is_dropped_with_the_rule() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let c = cfg(
            40562,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:1"],
            None,
        );
        mgr.apply_config(&c).await;
        assert!(
            mgr.rule_runtime.contains_key(&1),
            "runtime created on apply"
        );

        // Re-applying the identical config must not disturb the runtime.
        mgr.apply_config(&c).await;
        assert!(
            mgr.rule_runtime.contains_key(&1),
            "an unchanged apply must keep the rule's runtime"
        );

        // Removing the rule drops its runtime (which cancels its connections).
        mgr.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
        assert!(
            !mgr.rule_runtime.contains_key(&1),
            "a removed rule must not leak its runtime"
        );
    }

    #[tokio::test]
    async fn moved_tunnel_entry_drains_runtime_but_pause_still_cancels() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv4 = "127.0.0.1".into();
        mgr.listen_ipv6 = String::new();
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let mut active = one_rule(port, Protocol::Tcp, NodeTransport::Raw);
        active.tunnels.push(TunnelListenerConfig {
            tunnel_id: 77,
            port: 0,
            hop_position: 0,
            auth_token: String::new(),
            link_scope: String::new(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 0,
            clients: vec![TunnelClientConfig {
                tunnel_id: 77,
                rule_id: 1,
                hop_position: 0,
                address: "127.0.0.1:9".into(),
                auth_token: "a".repeat(64),
                link_scope: "77:0:10:20".into(),
            }],
        });
        mgr.apply_config(&active).await;

        let mut gate = mgr.rule_runtime.get(&1).unwrap().gate(None);
        let guard = gate.admit().expect("one simulated established connection");
        mgr.counter.add(1, 100, 200).await;

        let mut moved = NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![1],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&moved).await;
        assert!(!mgr.rule_runtime.contains_key(&1));
        assert_eq!(mgr.retired_rule_runtimes.len(), 1);
        assert_eq!(mgr.active_draining_rule_ids(), vec![1]);
        assert!(
            mgr.counter.has_rule(1).await,
            "unreported bytes stay billable"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), gate.cancelled())
                .await
                .is_err(),
            "an entry move must not cancel the established connection"
        );

        // Removing the durable drain lease represents pause/delete/unshare or
        // disable. Those state changes must retain the old fail-closed behavior.
        moved.drain_rule_ids.clear();
        mgr.apply_config(&moved).await;
        assert!(mgr.active_draining_rule_ids().is_empty());
        tokio::time::timeout(Duration::from_secs(1), gate.cancelled())
            .await
            .expect("pause must cancel a draining connection");
        drop(guard);
        mgr.apply_config(&moved).await;
        assert!(mgr.retired_rule_runtimes.is_empty());
        assert!(!mgr.counter.has_rule(1).await);
    }

    #[tokio::test]
    async fn reactivated_rule_keeps_retired_credential_scope_revocable() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv4 = "127.0.0.1".into();
        mgr.listen_ipv6 = String::new();
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let mut active = one_rule(port, Protocol::Tcp, NodeTransport::Raw);
        active.tunnels.push(TunnelListenerConfig {
            tunnel_id: 78,
            port: 0,
            hop_position: 0,
            auth_token: String::new(),
            link_scope: String::new(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 0,
            clients: vec![TunnelClientConfig {
                tunnel_id: 78,
                rule_id: 1,
                hop_position: 0,
                address: "127.0.0.1:9".into(),
                auth_token: "b".repeat(64),
                link_scope: "78:0:10:20".into(),
            }],
        });
        mgr.apply_config(&active).await;
        let mut old_gate = mgr
            .rule_runtime
            .get(&1)
            .unwrap()
            .gate_with_credential_groups(None, [10, 20]);
        let guard = old_gate.admit().unwrap();

        mgr.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![1],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
        assert_eq!(mgr.retired_rule_runtimes.len(), 1);

        // The rule comes back to this group as direct while its old preset
        // stream is still alive. Reactivation must not discard the old path's
        // credential groups.
        let direct = one_rule(port, Protocol::Tcp, NodeTransport::Raw);
        mgr.apply_config(&direct).await;
        assert!(mgr
            .rule_runtime
            .get(&1)
            .is_some_and(|runtime| runtime.uses_credential_group(20)));

        mgr.revoke_tunnel_credentials(20);
        tokio::time::timeout(Duration::from_secs(1), old_gate.cancelled())
            .await
            .expect("old preset generation must remain reachable by token revocation");
        drop(guard);
    }

    #[tokio::test]
    async fn drained_historical_credential_group_does_not_cancel_current_path() {
        let mut manager = fresh_mgr();
        let runtime = RuleRuntime::new();
        let mut old_gate = runtime.gate_with_credential_groups(None, [10, 20]);
        let old_connection = old_gate.admit().unwrap();
        manager.rule_runtime.insert(1, runtime);

        let mut current_gate = manager
            .rule_runtime
            .get(&1)
            .unwrap()
            .gate_with_credential_groups(None, [10, 30]);
        let current_connection = current_gate.admit().unwrap();

        manager.revoke_tunnel_credentials(20);
        tokio::time::timeout(Duration::from_secs(1), old_gate.cancelled())
            .await
            .expect("the historical generation must be revoked");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), current_gate.cancelled())
                .await
                .is_err()
        );
        drop(old_connection);
        drop(current_connection);
    }

    #[tokio::test]
    async fn credential_rotation_cancels_old_revision_not_new_revision() {
        let mut manager = fresh_mgr();
        let runtime = RuleRuntime::new();
        let mut old_gate = runtime.gate_with_credentials(None, [(10, Some(1)), (20, Some(1))]);
        let old_connection = old_gate.admit().unwrap();
        let mut current_gate = runtime.gate_with_credentials(None, [(10, Some(1)), (20, Some(2))]);
        let current_connection = current_gate.admit().unwrap();
        manager.rule_runtime.insert(1, runtime);

        manager.revoke_tunnel_credential_generations(20, Some(2));
        tokio::time::timeout(Duration::from_secs(1), old_gate.cancelled())
            .await
            .expect("the pre-rotation generation must be revoked");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), current_gate.cancelled())
                .await
                .is_err(),
            "connections authenticated with the current revision must survive"
        );
        drop(old_connection);
        drop(current_connection);
    }

    #[tokio::test]
    async fn failed_rotation_fetch_stops_old_credential_accept_loop_until_resync() {
        let mut manager = fresh_mgr();
        manager.listen_ipv4 = "127.0.0.1".into();
        manager.listen_ipv6 = String::new();
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let mut config = one_rule(port, Protocol::Tcp, NodeTransport::Raw);
        config.credential_revisions = vec![
            relay_shared::protocol::GroupCredentialRevision {
                group_id: 10,
                revision: 1,
            },
            relay_shared::protocol::GroupCredentialRevision {
                group_id: 20,
                revision: 1,
            },
        ];
        config.tunnels.push(TunnelListenerConfig {
            tunnel_id: 90,
            port: 0,
            hop_position: 0,
            auth_token: String::new(),
            link_scope: String::new(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 0,
            clients: vec![TunnelClientConfig {
                tunnel_id: 90,
                rule_id: 1,
                hop_position: 0,
                address: "127.0.0.1:9".into(),
                auth_token: "a".repeat(64),
                link_scope: "90:0:10:20".into(),
            }],
        });
        manager.apply_config(&config).await;
        assert!(manager
            .listeners
            .values()
            .any(|listener| listener.fingerprint.rule_id == 1));

        let persisted = manager
            .fail_closed_tunnel_credentials(20)
            .await
            .expect("an applied snapshot must produce a fail-closed cache");
        assert!(!manager
            .listeners
            .values()
            .any(|listener| listener.fingerprint.rule_id == 1));
        assert!(persisted.listeners.is_empty());
        assert!(persisted.tunnels.is_empty());
        assert!(manager.last_config.as_ref().unwrap().listeners.is_empty());

        manager.apply_config(&config).await;
        assert!(manager
            .listeners
            .values()
            .any(|listener| listener.fingerprint.rule_id == 1));
    }

    #[tokio::test]
    async fn preset_udp_warm_channel_subscribes_to_credential_revocation() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv4 = "127.0.0.1".into();
        mgr.listen_ipv6 = String::new();
        let reserved = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let mut active = one_rule(port, Protocol::Udp, NodeTransport::Raw);
        active.tunnels.push(TunnelListenerConfig {
            tunnel_id: 79,
            port: 0,
            hop_position: 0,
            auth_token: String::new(),
            link_scope: String::new(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 0,
            clients: vec![TunnelClientConfig {
                tunnel_id: 79,
                rule_id: 1,
                hop_position: 0,
                address: "127.0.0.1:9".into(),
                auth_token: "c".repeat(64),
                link_scope: "79:0:10:20".into(),
            }],
        });
        mgr.apply_config(&active).await;
        assert!(mgr.rule_runtime.contains_key(&1));
        assert!(mgr
            .listeners
            .values()
            .all(|listener| !listener.handle.is_finished()));

        mgr.revoke_tunnel_credentials(20);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if mgr
                    .listeners
                    .values()
                    .all(|listener| listener.handle.is_finished())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("revocation must stop the preset UDP listener and warm channel");
    }

    #[tokio::test]
    async fn recovered_listener_reuses_persistent_rule_limiter() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let mut config = one_rule(40563, Protocol::Udp, NodeTransport::Raw);
        config.listeners[0].upload_limit_bps = Some(1024);
        config.listeners[0].download_limit_bps = Some(2048);
        mgr.apply_config(&config).await;

        let first = match &mgr.rule_limiters.get(&1).unwrap().limiter {
            RateLimit::Limited(limiter) => limiter.clone(),
            RateLimit::Unlimited => panic!("test config must create a real limiter"),
        };
        let key = (40563, Protocol::Udp, NodeTransport::Raw);
        mgr.listeners.get(&key).unwrap().handle.abort();
        tokio::task::yield_now().await;
        mgr.apply_config(&config).await;

        let recovered = match &mgr.rule_limiters.get(&1).unwrap().limiter {
            RateLimit::Limited(limiter) => limiter.clone(),
            RateLimit::Unlimited => panic!("recovered listener lost its limiter"),
        };
        assert!(
            Arc::ptr_eq(&first, &recovered),
            "partial listener recovery must rejoin the existing aggregate bucket"
        );

        mgr.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
        assert!(
            mgr.rule_limiters.is_empty(),
            "deleted rule leaked its limiter"
        );
    }

    #[tokio::test]
    async fn raw_tcp_and_udp_are_scheduled() {
        let mut mgr = fresh_mgr();
        let c = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 1,
                    port: 40001,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
                ListenerConfig {
                    rule_id: 2,
                    port: 40002,
                    protocol: Protocol::Udp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&c).await;
        let keys = mgr.listener_keys();
        assert!(keys.contains(&(40001, Protocol::Tcp, NodeTransport::Raw)));
        assert!(keys.contains(&(40002, Protocol::Udp, NodeTransport::Raw)));
    }

    /// v1.0.8: WS entry transport is disabled — a ws rule must NOT start a
    /// listener, and a listener_error must be reported so the panel shows why.
    #[tokio::test]
    async fn ws_ingress_is_disabled() {
        let mut mgr = fresh_mgr();
        mgr.apply_config(&one_rule(40010, Protocol::Tcp, NodeTransport::Ws))
            .await;
        assert!(
            mgr.listener_keys().is_empty(),
            "ws entry transport is disabled — no listener must start"
        );
        let errs = mgr.take_listener_errors().await;
        assert_eq!(errs.len(), 1, "a listener_error must be pushed");
        assert!(errs[0].error.contains("disabled"), "got: {}", errs[0].error);
    }

    /// v1.0.8: TLS entry transport is disabled — a tls_simple rule is skipped
    /// (regardless of whether a cert is configured) with a reported error.
    #[tokio::test]
    async fn tls_simple_is_disabled() {
        let mut mgr = fresh_mgr();
        mgr.apply_config(&one_rule(40030, Protocol::Tcp, NodeTransport::TlsSimple))
            .await;
        assert!(
            mgr.listener_keys().is_empty(),
            "tls_simple is disabled — no listener must start"
        );
        let errs = mgr.take_listener_errors().await;
        assert_eq!(errs.len(), 1, "a listener_error must be pushed");
        assert!(errs[0].error.contains("disabled"), "got: {}", errs[0].error);
    }

    #[tokio::test]
    async fn udp_with_ws_is_skipped() {
        let mut mgr = fresh_mgr();
        mgr.apply_config(&one_rule(40040, Protocol::Udp, NodeTransport::Ws))
            .await;
        assert!(mgr.listener_keys().is_empty());
    }

    /// The ListenerKey includes the protocol, so a TCP and a UDP raw listener
    /// on the SAME port are two distinct listeners. (v1.0.8: this used to pair
    /// raw+ws, but ws is disabled now; tcp+udp is the remaining same-port case.)
    #[tokio::test]
    async fn same_port_tcp_and_udp_are_distinct_listeners() {
        let mut mgr = fresh_mgr();
        let c = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 1,
                    port: 40050,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
                ListenerConfig {
                    rule_id: 2,
                    port: 40050,
                    protocol: Protocol::Udp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&c).await;
        assert_eq!(mgr.listener_keys().len(), 2);
    }

    /// End-to-end regression for a tcp_udp chain after both staged switches:
    /// raw TCP keeps the legacy hop port while UDP travels through the
    /// dedicated authenticated UOT port. This exercises the real manager,
    /// TCP forwarder, UOT client/server, and final TCP+UDP targets together.
    #[tokio::test]
    async fn tcp_udp_chain_runs_tcp_fast_open_and_dedicated_uot_together() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp_target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = tcp_target.local_addr().unwrap().port();
        let udp_target = tokio::net::UdpSocket::bind(("127.0.0.1", target_port))
            .await
            .unwrap();
        let tcp_echo = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp_target.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    loop {
                        let Ok(n) = stream.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let udp_echo = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = udp_target.recv_from(&mut buf).await {
                if udp_target.send_to(&buf[..n], peer).await.is_err() {
                    return;
                }
            }
        });

        let reserve_pair = || {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = tcp.local_addr().unwrap().port();
            let udp = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
            drop((tcp, udp));
            port
        };
        let entry_port = reserve_pair();
        let exit_port = reserve_pair();
        let tunnel_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tunnel_port = tunnel_reservation.local_addr().unwrap().port();
        drop(tunnel_reservation);
        assert_ne!(exit_port, tunnel_port);

        let token = "c".repeat(64);
        let target = format!("127.0.0.1:{target_port}");
        let exit_config = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 42,
                    port: exit_port,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec![target.clone()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    count_traffic: false,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: true,
                },
                ListenerConfig {
                    rule_id: 42,
                    port: exit_port,
                    protocol: Protocol::Udp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec![target.clone()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    count_traffic: false,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                },
                ListenerConfig {
                    rule_id: 42,
                    port: tunnel_port,
                    protocol: Protocol::Uot,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec![target],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    count_traffic: false,
                    uot_role: UotRole::Egress,
                    uot_token: Some(token.clone()),
                    uot_next_token: None,
                    zero_rtt: true,
                    tcp_fast_open: false,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };

        let mut exit = fresh_mgr();
        exit.listen_ipv6 = String::new();
        exit.apply_config(&exit_config).await;
        assert!(exit.take_listener_errors().await.is_empty());

        let entry_config = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 42,
                    port: entry_port,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec![format!("127.0.0.1:{exit_port}")],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    count_traffic: true,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: true,
                },
                ListenerConfig {
                    rule_id: 42,
                    port: entry_port,
                    protocol: Protocol::Udp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec![format!("127.0.0.1:{tunnel_port}")],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    count_traffic: true,
                    uot_role: UotRole::Ingress,
                    uot_token: Some(token),
                    uot_next_token: None,
                    zero_rtt: true,
                    tcp_fast_open: false,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        let mut entry = fresh_mgr();
        entry.listen_ipv6 = String::new();
        entry.apply_config(&entry_config).await;
        assert!(entry.take_listener_errors().await.is_empty());

        let tcp_roundtrip = async {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", entry_port)).await?;
            client.write_all(b"tcp-fast-open-chain").await?;
            let mut reply = [0u8; 19];
            client.read_exact(&mut reply).await?;
            std::io::Result::Ok(reply)
        };
        let tcp_reply = tokio::time::timeout(Duration::from_secs(5), tcp_roundtrip)
            .await
            .expect("TCP chain timed out")
            .unwrap();
        assert_eq!(&tcp_reply, b"tcp-fast-open-chain");

        let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_client
            .send_to(b"udp-over-dedicated-uot", ("127.0.0.1", entry_port))
            .await
            .unwrap();
        let mut reply = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut reply))
            .await
            .expect("UOT chain timed out")
            .unwrap();
        assert_eq!(&reply[..n], b"udp-over-dedicated-uot");

        entry
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                tunnels: vec![],
                credential_revisions: vec![],
                terminate_tunnel_ids: vec![],
                drain_rule_ids: vec![],
                route_transition_rule_ids: vec![],
                route_staging_rule_ids: vec![],
                route_drain_rule_ids: vec![],
            })
            .await;
        exit.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
        tcp_echo.abort();
        udp_echo.abort();
    }

    // ── v0.3.6: hot update + finished recovery ──

    /// Identical config applied twice must NOT restart the listener — the
    /// fingerprint comparison is an equality check, so the second apply is a
    /// no-op. We assert by checking the fingerprint object identity is unchanged
    /// and the key stays registered exactly once.
    #[tokio::test]
    async fn identical_config_does_not_restart() {
        let mut mgr = fresh_mgr();
        let c = cfg(
            40060,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c).await;
        let fp_before = mgr
            .fingerprint(&(40060, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        // Re-apply the exact same config.
        mgr.apply_config(&c).await;
        let fp_after = mgr
            .fingerprint(&(40060, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        assert_eq!(fp_before, fp_after, "fingerprint must be unchanged");
        assert_eq!(mgr.listener_keys().len(), 1);
    }

    /// Changing targets must restart the listener so the new target is used.
    /// We observe the restart via the fingerprint change (the new targets are
    /// captured on the re-registered listener).
    #[tokio::test]
    async fn target_change_restarts_listener() {
        let mut mgr = fresh_mgr();
        let c1 = cfg(
            40061,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c1).await;
        assert_eq!(
            mgr.fingerprint(&(40061, Protocol::Tcp, NodeTransport::Raw))
                .unwrap()
                .targets,
            vec!["127.0.0.1:9".to_string()]
        );

        let c2 = cfg(
            40061,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:10"],
            None,
        );
        mgr.apply_config(&c2).await;
        assert_eq!(
            mgr.fingerprint(&(40061, Protocol::Tcp, NodeTransport::Raw))
                .unwrap()
                .targets,
            vec!["127.0.0.1:10".to_string()],
            "target change must update the running fingerprint"
        );
    }

    /// A live UDP session owns a detached target-reply task. Updating the
    /// target must still release and re-bind the same listening port; otherwise
    /// the old task's socket reference causes EADDRINUSE and silently leaves the
    /// rule absent until the next config push.
    #[tokio::test]
    async fn udp_target_change_rebinds_same_port_after_live_session() {
        let target_a = tagged_udp_target(b'a').await;
        let target_b = tagged_udp_target(b'b').await;
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let c1 = cfg(
            port,
            Protocol::Udp,
            NodeTransport::Raw,
            vec![&target_a.to_string()],
            None,
        );
        mgr.apply_config(&c1).await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = SocketAddr::from(([127, 0, 0, 1], port));
        client.send_to(b"first", listener).await.unwrap();
        let mut reply = [0u8; 8];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .expect("first UDP reply timed out")
            .unwrap();
        assert_eq!(&reply[..n], b"a");

        let c2 = cfg(
            port,
            Protocol::Udp,
            NodeTransport::Raw,
            vec![&target_b.to_string()],
            None,
        );
        mgr.apply_config(&c2).await;
        assert!(
            mgr.fingerprint(&(port, Protocol::Udp, NodeTransport::Raw))
                .is_some(),
            "updated UDP listener must be registered after same-port rebind"
        );

        client.send_to(b"second", listener).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .expect("second UDP reply timed out")
            .unwrap();
        assert_eq!(&reply[..n], b"b", "traffic must use the updated target");
    }

    /// Target ORDER matters (primary vs secondary). Reordering without changing
    /// the set must still count as a change — we must not sort before comparing.
    #[tokio::test]
    async fn target_order_is_significant() {
        let mut mgr = fresh_mgr();
        let c1 = cfg(
            40062,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9", "127.0.0.1:10"],
            None,
        );
        mgr.apply_config(&c1).await;
        let fp1 = mgr
            .fingerprint(&(40062, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        let c2 = cfg(
            40062,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:10", "127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c2).await;
        let fp2 = mgr
            .fingerprint(&(40062, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        assert_ne!(fp1, fp2, "reordered targets must be a different config");
    }

    /// A load_balance_strategy change must restart the listener so the new
    /// selector takes effect, even when targets and ws_path are unchanged.
    #[tokio::test]
    async fn strategy_change_restarts_listener() {
        let mut mgr = fresh_mgr();
        let mk = |strategy: LoadBalanceStrategy| NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port: 40065,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                targets: vec!["127.0.0.1:9".into(), "127.0.0.1:10".into()],
                target_weights: vec![],
                load_balance_strategy: strategy,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
                uot_role: UotRole::Disabled,
                uot_token: None,
                uot_next_token: None,
                zero_rtt: false,
                tcp_fast_open: false,
                count_traffic: true,
            }],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&mk(LoadBalanceStrategy::First)).await;
        let fp1 = mgr
            .fingerprint(&(40065, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        mgr.apply_config(&mk(LoadBalanceStrategy::RoundRobin)).await;
        let fp2 = mgr
            .fingerprint(&(40065, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        assert_ne!(fp1, fp2, "strategy change must be a different fingerprint");
        assert_eq!(fp2.load_balance_strategy, LoadBalanceStrategy::RoundRobin);
    }

    /// v1.0.8: flipping a raw listener to a now-DISABLED transport (ws) must
    /// tear the raw listener down and serve nothing — the disabled transport is
    /// skipped, so no new key appears. (Before ws was disabled this tested the
    /// raw→ws restart; ws.rs is kept but no longer served.)
    #[tokio::test]
    async fn transport_change_to_disabled_stops_listener() {
        let mut mgr = fresh_mgr();
        let mk = |transport: NodeTransport| NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port: 40066,
                protocol: Protocol::Tcp,
                node_transport: transport,
                ws_path: None,
                targets: vec!["127.0.0.1:9".into()],
                target_weights: vec![],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
                uot_role: UotRole::Disabled,
                uot_token: None,
                uot_next_token: None,
                zero_rtt: false,
                tcp_fast_open: false,
                count_traffic: true,
            }],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&mk(NodeTransport::Raw)).await;
        assert!(mgr
            .fingerprint(&(40066, Protocol::Tcp, NodeTransport::Raw))
            .is_some());
        // Flip to ws (disabled): the old raw listener is stopped, and ws is
        // skipped, so NO listener remains for this port.
        mgr.apply_config(&mk(NodeTransport::Ws)).await;
        assert!(
            mgr.fingerprint(&(40066, Protocol::Tcp, NodeTransport::Raw))
                .is_none(),
            "old raw listener must be stopped after transport flip"
        );
        assert!(
            mgr.fingerprint(&(40066, Protocol::Tcp, NodeTransport::Ws))
                .is_none(),
            "ws is disabled — no ws listener may start"
        );
        assert!(
            mgr.listener_keys().is_empty(),
            "no listener should remain for the port"
        );
    }

    /// Removing a rule from the config stops its listener.
    #[tokio::test]
    async fn removed_rule_stops_listener() {
        let mut mgr = fresh_mgr();
        let c1 = cfg(
            40064,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c1).await;
        assert_eq!(mgr.listener_keys().len(), 1);
        // Empty config = rule removed.
        mgr.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
        assert!(mgr.listener_keys().is_empty(), "removed rule must stop");
    }

    /// Changing a field that does NOT affect runtime (here: rule_id on a port
    /// that isn't running yet — simulating an unrelated rule) must not restart
    /// an existing, unchanged listener on a different port.
    #[tokio::test]
    async fn unrelated_change_does_not_restart_other_listeners() {
        let mut mgr = fresh_mgr();
        let c1 = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 1,
                    port: 40070,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:9".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
                ListenerConfig {
                    rule_id: 2,
                    port: 40071,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:9".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&c1).await;
        let fp70 = mgr
            .fingerprint(&(40070, Protocol::Tcp, NodeTransport::Raw))
            .unwrap();
        // Change rule 2's target only; rule 1 (port 40070) must be untouched.
        let c2 = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 1,
                    port: 40070,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:9".into()],
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
                ListenerConfig {
                    rule_id: 2,
                    port: 40071,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:10".into()], // changed
                    target_weights: vec![],
                    load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&c2).await;
        assert_eq!(
            mgr.fingerprint(&(40070, Protocol::Tcp, NodeTransport::Raw))
                .unwrap(),
            fp70,
            "unchanged listener on 40070 must not restart"
        );
    }

    /// A finished JoinHandle is detected and cleared, so a dead listener can be
    /// restarted on the next apply if still desired.
    ///
    /// We simulate a listener task that has already exited: spawn a task that
    /// returns immediately, let the runtime poll it to completion, then inject
    /// its handle into the manager under a known key. The next apply_config
    /// must (a) drop the dead handle and (b) re-start the listener because the
    /// config still wants it.
    #[tokio::test]
    async fn finished_handle_is_recovered() {
        let mut mgr = fresh_mgr();

        // A handle for a task that has finished. Spawn + yield so the runtime
        // completes it; the JoinHandle is NOT awaited (awaiting would consume
        // it), so we can still query is_finished() and insert it.
        let finished_handle: JoinHandle<()> = tokio::spawn(async {});
        // Give the runtime a chance to run the task to completion.
        for _ in 0..10 {
            tokio::task::yield_now().await;
            if finished_handle.is_finished() {
                break;
            }
        }
        assert!(
            finished_handle.is_finished(),
            "test setup: handle must be finished before injection"
        );

        // Inject it as if a listener had been running and then exited.
        let key = (40072, Protocol::Tcp, NodeTransport::Raw);
        mgr.listeners.insert(
            key,
            ManagedListener {
                handle: finished_handle,
                fingerprint: ListenerFingerprint {
                    rule_id: 1,
                    targets: vec!["stale".into()],
                    ws_path: None,
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    node_transport: NodeTransport::Raw,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                },
            },
        );
        assert_eq!(mgr.listener_keys().len(), 1);

        // Apply a config that still wants this port. apply_config must detect
        // the dead handle, remove it, and start a fresh listener.
        let c = cfg(
            40072,
            Protocol::Tcp,
            NodeTransport::Raw,
            vec!["127.0.0.1:9"],
            None,
        );
        mgr.apply_config(&c).await;

        // The key is still registered (restarted), but with the NEW fingerprint
        // — proving the stale entry was cleared and replaced, not reused.
        assert!(
            mgr.listener_keys().contains(&key),
            "dead listener must be restarted"
        );
        assert_eq!(
            mgr.fingerprint(&key).unwrap().targets,
            vec!["127.0.0.1:9".to_string()],
            "restarted listener must carry the new config, not the stale one"
        );
    }

    /// v0.4.9: listener_info_for_rule_tcp must select the TCP listener for a
    /// tcp_udp rule (which runs Tcp + Udp under the same rule_id). HashMap
    /// iteration order is nondeterministic, so the generic
    /// listener_info_for_rule could return either; this asserts the TCP one is
    /// picked deterministically. Uses direct injection (no port binding) so the
    /// test is fast and not order-dependent.
    #[tokio::test]
    async fn listener_info_for_rule_tcp_picks_tcp_for_tcp_udp_rule() {
        let mut mgr = fresh_mgr();
        // A tcp_udp rule → two listeners: Tcp + Udp, same rule_id, same port,
        // different protocol. Each gets its own live (pending) JoinHandle —
        // JoinHandle isn't Clone, so we spawn one per listener.
        let mk_live_handle = || {
            tokio::spawn(async {
                // never completes during the test → is_finished() stays false
                std::future::pending::<()>().await;
            })
        };
        mgr.listeners.insert(
            (40080, Protocol::Tcp, NodeTransport::Raw),
            ManagedListener {
                handle: mk_live_handle(),
                fingerprint: ListenerFingerprint {
                    rule_id: 7,
                    targets: vec!["tcp-target".into()],
                    ws_path: None,
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    node_transport: NodeTransport::Raw,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                },
            },
        );
        mgr.listeners.insert(
            (40080, Protocol::Udp, NodeTransport::Raw),
            ManagedListener {
                handle: mk_live_handle(),
                fingerprint: ListenerFingerprint {
                    rule_id: 7,
                    targets: vec!["udp-target".into()],
                    ws_path: None,
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    node_transport: NodeTransport::Raw,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                },
            },
        );
        // Both listeners are registered under rule 7.
        assert_eq!(mgr.listener_keys().len(), 2);

        // The TCP selector returns the TCP listener deterministically,
        // regardless of HashMap iteration order.
        let info = mgr
            .listener_info_for_rule_tcp(7)
            .expect("rule 7 has a TCP listener");
        assert_eq!(info.protocol, "tcp");
        assert_eq!(info.port, 40080);
        assert_eq!(info.targets, vec!["tcp-target".to_string()]);
        assert!(info.running, "a pending task is alive → running");
    }

    /// v0.4.9: a pure-udp rule has no TCP listener → listener_info_for_rule_tcp
    /// returns None. The panel rejects pure-UDP rules before dispatch, so this
    /// is defensive, but the contract must hold. An unknown rule_id is also None.
    #[tokio::test]
    async fn listener_info_for_rule_tcp_returns_none_for_udp_only_rule() {
        let mut mgr = fresh_mgr();
        let live_handle: JoinHandle<()> = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        mgr.listeners.insert(
            (40090, Protocol::Udp, NodeTransport::Raw),
            ManagedListener {
                handle: live_handle,
                fingerprint: ListenerFingerprint {
                    rule_id: 9,
                    targets: vec!["udp-target".into()],
                    ws_path: None,
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    node_transport: NodeTransport::Raw,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                },
            },
        );
        assert!(mgr.listener_info_for_rule_tcp(9).is_none());
        // An unknown rule_id also returns None.
        assert!(mgr.listener_info_for_rule_tcp(999).is_none());
    }

    // ── v1.0.3 PR1: traffic counter poison-pill pruning ──

    /// When a rule is deleted from the config, the counter entry for its
    /// rule_id must be pruned so orphaned bytes don't poison future batches.
    #[tokio::test]
    async fn deleted_rule_prunes_traffic_counter() {
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let mut mgr = ForwarderManager::new(counter.clone(), connections.clone());

        // v1.0.8: use a port not shared with any other test in this file.
        // `cargo test` runs #[tokio::test] fns in parallel by default, and this
        // test previously hardcoded port 40001 — the SAME port used by
        // `raw_tcp_and_udp_are_scheduled`, `tcp_udp_to_tcp_does_not_prune_
        // surviving_rule_counter`, and `dead_listener_prunes_counter_when_
        // rule_removed`. When two of those tests overlapped in time, one lost
        // the OS-level bind race on 40001 for BOTH the v4 and v6 listener, hit
        // the "no listener bound on port" branch, and never inserted a
        // `self.listeners` entry at all. The `mgr.listeners.get(&key)` below
        // then found nothing, silently skipping the abort/prune path entirely
        // — so the manually-primed counter entry for rule 1 was never touched
        // and the final assertion failed. This was the actual flake (not a
        // timing issue with is_finished(), despite what an earlier fix here
        // assumed) — confirmed by port collision, not the spin loop below.
        // Fix: give each of the 4 tests its own port (40001/40003/40004/40005).
        //
        // Apply a config with one rule.
        mgr.apply_config(&one_rule(40003, Protocol::Tcp, NodeTransport::Raw))
            .await;
        // Simulate traffic: accumulate bytes for rule 1.
        counter.add(1, 100, 50).await;
        assert!(counter.has_rule(1).await);

        // Abort the listener so it finishes, then apply empty config.
        // Without this, the listener is still running when apply_config
        // checks is_finished() and won't be detected as dead.
        //
        // abort() only REQUESTS cancellation; the task isn't actually finished
        // until the runtime polls it once more. Spin on is_finished(), yielding
        // so the runtime drives the cancelled task to completion, before
        // applying the empty config. (This spin is still correct defensive
        // practice even though it wasn't the source of the observed flake.)
        let key = (40003, Protocol::Tcp, NodeTransport::Raw);
        if let Some(m) = mgr.listeners.get(&key) {
            m.handle.abort();
            while !m.handle.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        mgr.apply_config(&NodeConfigResponse {
            listeners: Vec::new(),
            tunnels: Vec::new(),
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;

        // Counter must be pruned.
        assert!(
            !counter.has_rule(1).await,
            "orphan rule_id must be pruned after rule deletion"
        );
    }

    /// When a tcp_udp rule is changed to tcp-only (one listener removed), the
    /// remaining listener's counter must NOT be pruned — only the deleted
    /// listener is gone, but the rule itself still exists.
    ///
    /// v1.0.8: uses port 40004, dedicated to this test — see the port-collision
    /// note in `deleted_rule_prunes_traffic_counter` above for why every test
    /// in this file needs its own port.
    #[tokio::test]
    async fn tcp_udp_to_tcp_does_not_prune_surviving_rule_counter() {
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let mut mgr = ForwarderManager::new(counter.clone(), connections.clone());

        // tcp_udp rule: two listeners share rule_id 1.
        let tcp_udp_cfg = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 1,
                    port: 40004,
                    protocol: Protocol::Tcp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
                ListenerConfig {
                    rule_id: 1,
                    port: 40004,
                    protocol: Protocol::Udp,
                    node_transport: NodeTransport::Raw,
                    ws_path: None,
                    targets: vec!["127.0.0.1:1".into()],
                    target_weights: vec![],
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    max_connections: None,
                    uot_role: UotRole::Disabled,
                    uot_token: None,
                    uot_next_token: None,
                    zero_rtt: false,
                    tcp_fast_open: false,
                    count_traffic: true,
                },
            ],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&tcp_udp_cfg).await;
        counter.add(1, 200, 100).await;
        assert!(counter.has_rule(1).await);

        // Change to tcp-only: remove the UDP listener for rule 1.
        let tcp_cfg = NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port: 40004,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                targets: vec!["127.0.0.1:2".into()],
                target_weights: vec![],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
                uot_role: UotRole::Disabled,
                uot_token: None,
                uot_next_token: None,
                zero_rtt: false,
                tcp_fast_open: false,
                count_traffic: true,
            }],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        };
        mgr.apply_config(&tcp_cfg).await;

        // Rule 1 still exists (TCP listener survived) — counter must NOT be pruned.
        assert!(
            counter.has_rule(1).await,
            "surviving rule's counter must not be pruned when only the UDP listener is removed"
        );
    }

    /// A dead listener whose rule was also removed from the config must have
    /// its counter pruned, same as a normally-stopped listener.
    ///
    /// v1.0.8: uses port 40005, dedicated to this test — see the port-collision
    /// note in `deleted_rule_prunes_traffic_counter` above.
    #[tokio::test]
    async fn dead_listener_prunes_counter_when_rule_removed() {
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let mut mgr = ForwarderManager::new(counter.clone(), connections.clone());

        // Apply config with rule 1.
        mgr.apply_config(&one_rule(40005, Protocol::Tcp, NodeTransport::Raw))
            .await;
        counter.add(1, 50, 25).await;

        // Simulate a dead listener: abort its JoinHandle so is_finished() is true.
        let key = (40005, Protocol::Tcp, NodeTransport::Raw);
        if let Some(m) = mgr.listeners.get(&key) {
            m.handle.abort();
            // Briefly wait for the abort to propagate.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Apply empty config — step 1 finds the dead listener and removes it.
        mgr.apply_config(&NodeConfigResponse {
            listeners: Vec::new(),
            tunnels: Vec::new(),
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;

        assert!(
            !counter.has_rule(1).await,
            "dead listener for a removed rule must prune its counter entry"
        );
    }

    #[tokio::test]
    async fn udp_and_tcp_udp_rules_share_preset_port_without_crosstalk() {
        use relay_shared::protocol::{TunnelClientConfig, TunnelRouteConfig};

        async fn udp_target(tag: u8) -> (String, tokio::task::JoinHandle<()>) {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap().to_string();
            let task = tokio::spawn(async move {
                let mut payload = [0u8; 128];
                let (n, peer) = socket.recv_from(&mut payload).await.unwrap();
                let mut response = vec![tag];
                response.extend_from_slice(&payload[..n]);
                socket.send_to(&response, peer).await.unwrap();
            });
            (address, task)
        }

        async fn tcp_udp_target(
            tag: u8,
        ) -> (
            String,
            tokio::task::JoinHandle<()>,
            tokio::task::JoinHandle<()>,
        ) {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = tcp.local_addr().unwrap();
            let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
            let tcp_task = tokio::spawn(async move {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let mut payload = [0u8; 128];
                let n = stream.read(&mut payload).await.unwrap();
                stream.write_all(&[tag]).await.unwrap();
                stream.write_all(&payload[..n]).await.unwrap();
            });
            let udp_task = tokio::spawn(async move {
                let mut payload = [0u8; 128];
                let (n, peer) = udp.recv_from(&mut payload).await.unwrap();
                let mut response = vec![tag];
                response.extend_from_slice(&payload[..n]);
                udp.send_to(&response, peer).await.unwrap();
            });
            (address.to_string(), tcp_task, udp_task)
        }

        fn reserve_udp_port() -> u16 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        }

        let (target_a, target_task_a) = udp_target(b'A').await;
        let (target_b, target_task_b) = udp_target(b'B').await;
        let (target_c, target_tcp_task_c, target_udp_task_c) = tcp_udp_target(b'C').await;
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let shared_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let entry_a = reserve_udp_port();
        let entry_b = reserve_udp_port();
        let entry_c_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let entry_c = entry_c_reservation.local_addr().unwrap().port();
        let entry_c_udp_reservation = std::net::UdpSocket::bind(("127.0.0.1", entry_c)).unwrap();
        drop(entry_c_reservation);
        drop(entry_c_udp_reservation);
        let shared_address = format!("127.0.0.1:{shared_port}");
        let token = "udp-shared-key".repeat(6);

        let mut exit = fresh_mgr();
        exit.listen_ipv6 = String::new();
        exit.apply_config(&NodeConfigResponse {
            listeners: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 901,
                port: shared_port,
                hop_position: 1,
                auth_token: token.clone(),
                link_scope: "901:0".into(),
                next: None,
                routes: vec![
                    TunnelRouteConfig {
                        rule_id: 1001,
                        protocol: "udp".into(),
                        targets: vec![target_a],
                        target_weights: vec![1],
                        load_balance_strategy: LoadBalanceStrategy::First,
                    },
                    TunnelRouteConfig {
                        rule_id: 1002,
                        protocol: "udp".into(),
                        targets: vec![target_b],
                        target_weights: vec![1],
                        load_balance_strategy: LoadBalanceStrategy::First,
                    },
                    TunnelRouteConfig {
                        rule_id: 1003,
                        protocol: "tcp_udp".into(),
                        targets: vec![target_c],
                        target_weights: vec![1],
                        load_balance_strategy: LoadBalanceStrategy::First,
                    },
                ],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
        })
        .await;
        assert!(exit.take_listener_errors().await.is_empty());

        let make_listener = |rule_id, port, protocol| ListenerConfig {
            rule_id,
            port,
            protocol,
            node_transport: NodeTransport::Raw,
            ws_path: None,
            targets: vec![shared_address.clone()],
            target_weights: vec![1],
            load_balance_strategy: LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
            count_traffic: true,
            uot_role: UotRole::Disabled,
            uot_token: Some(token.clone()),
            uot_next_token: None,
            zero_rtt: true,
            tcp_fast_open: false,
        };
        let make_client = |rule_id| TunnelClientConfig {
            tunnel_id: 901,
            rule_id,
            hop_position: 0,
            address: shared_address.clone(),
            auth_token: token.clone(),
            link_scope: "901:0".into(),
        };
        let mut entry = fresh_mgr();
        entry.listen_ipv6 = String::new();
        entry
            .apply_config(&NodeConfigResponse {
                listeners: vec![
                    make_listener(1001, entry_a, Protocol::Udp),
                    make_listener(1002, entry_b, Protocol::Udp),
                    make_listener(1003, entry_c, Protocol::Tcp),
                    make_listener(1003, entry_c, Protocol::Udp),
                ],
                credential_revisions: vec![],
                terminate_tunnel_ids: vec![],
                drain_rule_ids: vec![],
                route_transition_rule_ids: vec![],
                route_staging_rule_ids: vec![],
                route_drain_rule_ids: vec![],
                tunnels: vec![TunnelListenerConfig {
                    tunnel_id: 901,
                    port: 0,
                    hop_position: 0,
                    auth_token: String::new(),
                    link_scope: String::new(),
                    next: None,
                    routes: vec![],
                    handshake_timeout_ms: 1_000,
                    max_unauthenticated: 0,
                    clients: vec![make_client(1001), make_client(1002), make_client(1003)],
                }],
            })
            .await;
        assert!(entry.take_listener_errors().await.is_empty());

        for (entry_port, payload, tag) in [
            (entry_a, b"one".as_slice(), b'A'),
            (entry_b, b"two".as_slice(), b'B'),
            (entry_c, b"three-udp".as_slice(), b'C'),
        ] {
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client
                .send_to(payload, ("127.0.0.1", entry_port))
                .await
                .unwrap();
            let mut response = [0u8; 16];
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
                    .await
                    .expect("preset UDP roundtrip timed out")
                    .unwrap();
            assert_eq!(response[0], tag);
            assert_eq!(&response[1..n], payload);
        }

        let mut tcp_client = tokio::net::TcpStream::connect(("127.0.0.1", entry_c))
            .await
            .unwrap();
        let tcp_payload = b"three-tcp";
        tcp_client.write_all(tcp_payload).await.unwrap();
        let mut tcp_response = vec![0u8; tcp_payload.len() + 1];
        tokio::time::timeout(
            Duration::from_secs(5),
            tcp_client.read_exact(&mut tcp_response),
        )
        .await
        .expect("preset TCP half of tcp_udp roundtrip timed out")
        .unwrap();
        assert_eq!(tcp_response[0], b'C');
        assert_eq!(&tcp_response[1..], tcp_payload);

        target_task_a.await.unwrap();
        target_task_b.await.unwrap();
        target_tcp_task_c.await.unwrap();
        target_udp_task_c.await.unwrap();
        entry
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                tunnels: vec![],
                credential_revisions: vec![],
                terminate_tunnel_ids: vec![],
                drain_rule_ids: vec![],
                route_transition_rule_ids: vec![],
                route_staging_rule_ids: vec![],
                route_drain_rule_ids: vec![],
            })
            .await;
        exit.apply_config(&NodeConfigResponse {
            listeners: vec![],
            tunnels: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
        })
        .await;
    }

    #[tokio::test]
    async fn shared_tunnel_reuses_replay_cache_across_route_updates() {
        use relay_shared::protocol::TunnelRouteConfig;

        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let make_config = |target: &str| NodeConfigResponse {
            listeners: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 902,
                port,
                hop_position: 1,
                auth_token: "stable-token".into(),
                link_scope: "902:0:1:2".into(),
                next: None,
                routes: vec![TunnelRouteConfig {
                    rule_id: 1101,
                    protocol: "tcp".into(),
                    targets: vec![target.into()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
        };
        let mut manager = fresh_mgr();
        manager.listen_ipv6 = String::new();
        manager.apply_config(&make_config("127.0.0.1:9")).await;
        let before = Arc::as_ptr(&manager.tunnel_replay_caches.values().next().unwrap().cache);
        manager.apply_config(&make_config("127.0.0.1:10")).await;
        let after = Arc::as_ptr(&manager.tunnel_replay_caches.values().next().unwrap().cache);
        assert_eq!(before, after, "route-only edits must retain replay history");
    }

    #[tokio::test]
    async fn live_replay_cache_is_not_evicted_by_tunnel_count() {
        let mut manager = fresh_mgr();
        let make_tunnel = |id| TunnelListenerConfig {
            tunnel_id: id,
            port: 1,
            hop_position: 1,
            auth_token: format!("token-{id}"),
            link_scope: format!("{id}:0:1:2"),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let first_config = make_tunnel(1);
        let first = manager.replay_cache_for_tunnel(&first_config);
        for id in 2..=1026 {
            manager.replay_cache_for_tunnel(&make_tunnel(id));
        }
        let again = manager.replay_cache_for_tunnel(&first_config);
        assert!(
            Arc::ptr_eq(&first, &again),
            "a live link must retain nonce history regardless of tunnel count"
        );

        manager
            .apply_shared_tunnel_listeners(
                &NodeConfigResponse {
                    listeners: vec![],
                    tunnels: vec![],
                    credential_revisions: vec![],
                    terminate_tunnel_ids: vec![],
                    drain_rule_ids: vec![],
                    route_transition_rule_ids: vec![],
                    route_staging_rule_ids: vec![],
                    route_drain_rule_ids: vec![],
                },
                &HashMap::new(),
                &HashSet::new(),
            )
            .await;
        let retained = manager
            .tunnel_replay_caches
            .get(&tunnel_replay_key(&first_config))
            .expect("a temporary listener absence must retain replay history");
        assert!(Arc::ptr_eq(&first, &retained.cache));
    }

    #[tokio::test]
    async fn shared_tunnel_token_rotation_cancels_detached_active_streams() {
        use relay_shared::protocol::{TunnelClientConfig, TunnelRouteConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap().to_string();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let make_config = |token: &str| NodeConfigResponse {
            listeners: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 903,
                port,
                hop_position: 1,
                auth_token: token.into(),
                link_scope: "903:0:1:2".into(),
                next: None,
                routes: vec![TunnelRouteConfig {
                    rule_id: 1201,
                    protocol: "tcp".into(),
                    targets: vec![target_address.clone()],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
        };
        let mut manager = fresh_mgr();
        manager.listen_ipv6 = String::new();
        manager.apply_config(&make_config("old-token")).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        crate::forwarder::tunnel::write_header(
            &mut client,
            &TunnelClientConfig {
                tunnel_id: 903,
                rule_id: 1201,
                hop_position: 0,
                address: format!("127.0.0.1:{port}"),
                auth_token: "old-token".into(),
                link_scope: "903:0:1:2".into(),
            },
            crate::forwarder::tunnel::TunnelMode::Tcp,
        )
        .await
        .unwrap();
        accepted_rx.await.unwrap();

        manager.apply_config(&make_config("new-token")).await;
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("rotated credential did not revoke active tunnel stream");
        assert!(closed.is_err() || closed.unwrap() == 0);
        let _ = client.shutdown().await;
        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn retired_shared_tunnel_runtime_remains_revocable() {
        use relay_shared::protocol::{TunnelClientConfig, TunnelRouteConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap().to_string();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (_stream, _) = target.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
        });
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let config = NodeConfigResponse {
            listeners: vec![],
            credential_revisions: vec![],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 904,
                port,
                hop_position: 1,
                auth_token: "retired-token".into(),
                link_scope: "904:0:1:2".into(),
                next: None,
                routes: vec![TunnelRouteConfig {
                    rule_id: 1301,
                    protocol: "tcp".into(),
                    targets: vec![target_address],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
        };
        let mut manager = fresh_mgr();
        manager.listen_ipv6 = String::new();
        manager.apply_config(&config).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        crate::forwarder::tunnel::write_header(
            &mut client,
            &TunnelClientConfig {
                tunnel_id: 904,
                rule_id: 1301,
                hop_position: 0,
                address: format!("127.0.0.1:{port}"),
                auth_token: "retired-token".into(),
                link_scope: "904:0:1:2".into(),
            },
            crate::forwarder::tunnel::TunnelMode::Tcp,
        )
        .await
        .unwrap();
        accepted_rx.await.unwrap();

        manager
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                tunnels: vec![],
                credential_revisions: vec![],
                terminate_tunnel_ids: vec![],
                drain_rule_ids: vec![],
                route_transition_rule_ids: vec![],
                route_staging_rule_ids: vec![],
                route_drain_rule_ids: vec![],
            })
            .await;
        assert_eq!(manager.retired_tunnel_runtimes.len(), 1);
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.read(&mut byte))
                .await
                .is_err(),
            "ordinary path removal must let established TCP drain"
        );

        manager.revoke_tunnel_credentials(999);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.read(&mut byte))
                .await
                .is_err(),
            "an unrelated group rotation must not interrupt this tunnel"
        );
        manager.revoke_tunnel_credentials(2);
        let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("credential revocation did not reach retired tunnel runtime");
        assert!(closed.is_err() || closed.unwrap() == 0);
        let _ = client.shutdown().await;
        let _ = release_tx.send(());
        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn credential_revision_revokes_stream_during_simultaneous_path_removal() {
        use relay_shared::protocol::{
            GroupCredentialRevision, TunnelClientConfig, TunnelRouteConfig,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap().to_string();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (_stream, _) = target.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
        });
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let config = NodeConfigResponse {
            listeners: vec![],
            credential_revisions: vec![GroupCredentialRevision {
                group_id: 3,
                revision: 7,
            }],
            terminate_tunnel_ids: vec![],
            drain_rule_ids: vec![],
            route_transition_rule_ids: vec![],
            route_staging_rule_ids: vec![],
            route_drain_rule_ids: vec![],
            tunnels: vec![TunnelListenerConfig {
                tunnel_id: 905,
                port,
                hop_position: 1,
                auth_token: "credential-rejected-token".into(),
                link_scope: "905:0:3:4".into(),
                next: None,
                routes: vec![TunnelRouteConfig {
                    rule_id: 1401,
                    protocol: "tcp".into(),
                    targets: vec![target_address],
                    target_weights: vec![1],
                    load_balance_strategy: LoadBalanceStrategy::First,
                }],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }],
        };
        let mut manager = fresh_mgr();
        manager.listen_ipv6 = String::new();
        manager.apply_config(&config).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        crate::forwarder::tunnel::write_header(
            &mut client,
            &TunnelClientConfig {
                tunnel_id: 905,
                rule_id: 1401,
                hop_position: 0,
                address: format!("127.0.0.1:{port}"),
                auth_token: "credential-rejected-token".into(),
                link_scope: "905:0:3:4".into(),
            },
            crate::forwarder::tunnel::TunnelMode::Tcp,
        )
        .await
        .unwrap();
        accepted_rx.await.unwrap();

        manager
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                tunnels: vec![],
                credential_revisions: vec![GroupCredentialRevision {
                    group_id: 3,
                    revision: 8,
                }],
                terminate_tunnel_ids: vec![],
                drain_rule_ids: vec![],
                route_transition_rule_ids: vec![],
                route_staging_rule_ids: vec![],
                route_drain_rule_ids: vec![],
            })
            .await;
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("credential generation change did not revoke the removed path");
        assert!(closed.is_err() || closed.unwrap() == 0);
        let _ = client.shutdown().await;
        let _ = release_tx.send(());
        target_task.await.unwrap();
    }
}
