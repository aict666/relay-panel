use crate::api::node::extract_node_token;
use crate::api::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use relay_shared::protocol::NodeConfigResponse;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// One live connection's sender + its optional per-node identity (v0.4.14
/// X-Node-ID). `node_id` is None for an older node that didn't send the header;
/// such a connection still receives config_changed broadcasts but cannot be
/// targeted by directed diagnosis.
struct ConnEntry {
    tx: mpsc::UnboundedSender<String>,
    node_id: Option<String>,
}
/// Per-group map of live connection senders.
type GroupConns = HashMap<u64, ConnEntry>;
/// Shared registry: group_id -> that group's live connections.
type ConnMap = Arc<RwLock<HashMap<i64, GroupConns>>>;

/// Tracks live WebSocket connections per group_id so the panel can push
/// `config_changed` notifications when an admin mutates rules or groups.
///
/// Each connection registers an mpsc sender; on disconnect it unregisters.
/// `broadcast` fans a message out to every live connection (we broadcast to
/// ALL groups on any admin mutation — correct and simple for small fleets).
#[derive(Clone, Default)]
pub struct NodeConnections {
    next_id: Arc<AtomicU64>,
    inner: ConnMap,
    /// Per-group authentication generation. Token rotation increments this
    /// under a lock shared with generation-aware registration, closing the
    /// validate-before-upgrade race for newly arriving sockets.
    generations: Arc<RwLock<HashMap<i64, u64>>>,
}

impl NodeConnections {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new connection. Returns (conn_id, receiver) — the caller
    /// owns the receiver and forwards anything it receives to the socket.
    /// `node_id` is the v0.4.14 X-Node-ID (None for older nodes).
    #[cfg(test)]
    pub async fn register(
        &self,
        group_id: i64,
        node_id: Option<String>,
    ) -> (u64, mpsc::UnboundedReceiver<String>) {
        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .write()
            .await
            .entry(group_id)
            .or_default()
            .insert(conn_id, ConnEntry { tx, node_id });
        (conn_id, rx)
    }

    async fn auth_generation(&self, group_id: i64) -> u64 {
        self.generations
            .read()
            .await
            .get(&group_id)
            .copied()
            .unwrap_or(0)
    }

    /// Register only if no token rotation occurred since authentication
    /// started. The generation read lock is held until the sender is inserted;
    /// close_group takes the write lock before removing connections, so either
    /// registration wins and is then closed, or rotation wins and registration
    /// is rejected.
    async fn register_if_generation(
        &self,
        group_id: i64,
        node_id: Option<String>,
        expected_generation: u64,
    ) -> Option<(u64, mpsc::UnboundedReceiver<String>)> {
        let generations = self.generations.read().await;
        let current = generations.get(&group_id).copied().unwrap_or(0);
        if current != expected_generation {
            return None;
        }

        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .write()
            .await
            .entry(group_id)
            .or_default()
            .insert(conn_id, ConnEntry { tx, node_id });
        drop(generations);
        Some((conn_id, rx))
    }

    /// Remove a connection. Called when the socket task exits.
    pub async fn unregister(&self, group_id: i64, conn_id: u64) {
        let mut map = self.inner.write().await;
        if let Some(conns) = map.get_mut(&group_id) {
            conns.remove(&conn_id);
            if conns.is_empty() {
                map.remove(&group_id);
            }
        }
    }

    /// Fan a message out to every live connection across every group.
    /// Dead senders (receiver dropped) are pruned opportunistically.
    pub async fn broadcast_all(&self, msg: &str) {
        let mut map = self.inner.write().await;
        for conns in map.values_mut() {
            conns.retain(|_, e| e.tx.send(msg.to_string()).is_ok());
        }
    }

    /// Send a message to every live connection in ONE group only (not all
    /// groups like broadcast_all). Returns the number of connections the message
    /// was handed to (dead senders pruned). Does NOT close the connections.
    ///
    /// v0.4.14: directed diagnosis now uses `send_node` instead; this group-wide
    /// send is retained as general infrastructure (no current caller).
    #[allow(dead_code)]
    pub async fn send_group(&self, group_id: i64, msg: &str) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.get_mut(&group_id) else {
            return 0;
        };
        let mut sent = 0usize;
        conns.retain(|_, e| {
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    /// v0.4.14: send a message ONLY to the connection(s) in a group whose
    /// X-Node-ID matches `node_id`. Used by directed diagnosis to target a
    /// specific node instead of the whole group. Returns how many connections
    /// received it (0 = that node has no live WS connection right now). Dead
    /// senders are pruned.
    pub async fn send_node(&self, group_id: i64, node_id: &str, msg: &str) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.get_mut(&group_id) else {
            return 0;
        };
        let mut sent = 0usize;
        conns.retain(|_, e| {
            if e.node_id.as_deref() != Some(node_id) {
                return true; // not the target node — leave untouched
            }
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false // target but dead — prune
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    /// v0.4.14: the set of node_ids in a group that currently have a live WS
    /// connection AND advertised an X-Node-ID. This is the source of truth for
    /// "is this node's control channel online", replacing the stale kvs
    /// last_seen heuristic for diagnosis. Older nodes (no X-Node-ID) are NOT
    /// included — they can't be targeted by directed diagnosis.
    pub async fn online_node_ids(&self, group_id: i64) -> std::collections::HashSet<String> {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|conns| conns.values().filter_map(|e| e.node_id.clone()).collect())
            .unwrap_or_default()
    }

    /// Number of live connections currently registered for a group. Used by
    /// diagnosis to decide "WS online" vs "control channel offline".
    #[allow(dead_code)]
    pub async fn group_conn_count(&self, group_id: i64) -> usize {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Force-close every live connection for ONE group. Used by token rotation:
    /// the old token is invalid immediately, so the old WS connection (which
    /// authenticated with it at upgrade time) must be torn down — otherwise the
    /// node keeps an authenticated socket open with a revoked credential until
    /// its next reconnect.
    ///
    /// Drops the group's senders; each connection's `push_rx.recv()` returns
    /// None and the socket task exits (handle_node_ws → unregister, a no-op
    /// since close_group already removed the entry). The node then reconnects
    /// and re-authenticates with the new token.
    pub async fn close_group(&self, group_id: i64) -> usize {
        let mut generations = self.generations.write().await;
        let generation = generations.entry(group_id).or_insert(0);
        *generation = generation.wrapping_add(1);
        let mut map = self.inner.write().await;
        let closed = map.remove(&group_id).map(|conns| conns.len()).unwrap_or(0);
        drop(map);
        drop(generations);
        closed
    }
}

/// WebSocket endpoint for node control channel.
/// Node authenticates via Authorization: Bearer <NODE_TOKEN>.
/// The token is intentionally NOT accepted from `?token=` because query
/// parameters leak into access/proxy logs (Nginx/Caddy/CDN).
///
/// Protocol:
///   - On compatible connect: server sends config_snapshot (NodeConfigResponse JSON)
///   - On incompatible connect: socket is control-only; a blocked group gets
///     an empty compatibility hint so its cached forwarding fails closed
///   - ping/pong: heartbeat
///   - config_changed: server pushes `{"type":"config_changed"}` to all
///     connections whenever an admin mutates rules/groups; the node then
///     re-fetches /node/config over HTTP.
pub async fn node_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = match extract_node_token(&headers) {
        Some(t) => t,
        None => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };

    // Authenticate before reporting a protocol mismatch. A revoked node must
    // receive 401 even when it is old, so it cannot interpret 426 as permission
    // to retain cached forwarding state.
    use relay_shared::models::DeviceGroup;
    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("node_ws_handler: find_by_token failed: {}", e);
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let group = match group {
        Some(g) => g,
        None => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };

    // Keep authenticated protocol-incompatible nodes on a control-only socket.
    // Refusing the WebSocket with 426 would put an old node into the same long
    // backoff as its HTTP poll. If an administrator enables an ingress policy
    // during that interval there would be no live channel on which to tell the
    // node to fail its cached listeners closed.
    //
    // The bridge never exposes the incompatible current snapshot. While the
    // policy is disabled it sends no initial config at all; once a policy is
    // active it sends a wire-compatible empty hint. Historical clients that
    // apply WebSocket snapshots directly stop in memory; their ordinary HTTP
    // poll receives the same empty snapshot with 200 and persists it to disk.
    let protocol_compatible = crate::api::node::config_protocol_compatible(&headers);
    if !protocol_compatible {
        tracing::warn!(
            group_id = group.id,
            received = ?crate::api::node::extract_config_protocol_version(&headers),
            required = relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
            "opening protocol-incompatible control-only channel"
        );
    }

    let group_id = group.id;
    // v0.4.14: optional per-node identity. None for an older node that didn't
    // send X-Node-ID — it still connects and gets config_changed, it just can't
    // be targeted by directed diagnosis.
    let node_id = match headers.get("X-Node-ID") {
        None => None,
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(crate::api::node::normalize_node_id)
        {
            Some(node_id) => Some(node_id),
            None => return axum::http::StatusCode::BAD_REQUEST.into_response(),
        },
    };
    // Clone the Arc<dyn Repository> so the WS task can keep using it after the
    // upgrade handler returns. The pool snapshot is shared read-only.
    let db = state.db.clone();

    ws.on_upgrade(move |socket| {
        handle_node_ws(
            socket,
            group_id,
            node_id,
            token,
            db,
            state.node_connections,
            protocol_compatible,
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WsInitialSnapshotMode {
    Current,
    ControlOnly,
    FailClosed,
}

fn ws_initial_snapshot_mode(
    protocol_compatible: bool,
    protocol_policy_active: bool,
) -> WsInitialSnapshotMode {
    match (protocol_compatible, protocol_policy_active) {
        (true, _) => WsInitialSnapshotMode::Current,
        (false, false) => WsInitialSnapshotMode::ControlOnly,
        (false, true) => WsInitialSnapshotMode::FailClosed,
    }
}

async fn handle_node_ws(
    socket: WebSocket,
    group_id: i64,
    node_id: Option<String>,
    token: String,
    db: std::sync::Arc<dyn crate::db::Repository>,
    node_connections: NodeConnections,
    protocol_compatible: bool,
) {
    // Capture the generation before revalidating the credential. If rotation
    // happens before the lookup, the old token fails; if it happens after the
    // lookup, register_if_generation observes the increment and refuses the
    // stale connection.
    let auth_generation = node_connections.auth_generation(group_id).await;
    let token_still_valid = match db.find_by_token(&token).await {
        Ok(Some(group)) => group.id == group_id,
        Ok(None) => false,
        Err(e) => {
            tracing::error!(
                "websocket post-upgrade token revalidation failed for group {}: {}",
                group_id,
                e
            );
            false
        }
    };
    if !token_still_valid {
        tracing::warn!(
            "websocket rejected after token changed: group_id={}",
            group_id
        );
        return;
    }

    let Some((conn_id, mut push_rx)) = node_connections
        .register_if_generation(group_id, node_id.clone(), auth_generation)
        .await
    else {
        tracing::warn!(
            "websocket registration raced with token rotation: group_id={}",
            group_id
        );
        return;
    };

    // Re-read the policy only AFTER registration. This ordering closes the
    // update/upgrade race for incompatible nodes: a policy commit before this
    // read is visible here, while a commit after it broadcasts into the already
    // registered connection's queue. The pre-upgrade group snapshot cannot
    // provide that guarantee because the broadcast could occur before the
    // socket becomes discoverable in NodeConnections.
    let current_group = match db.find_by_token(&token).await {
        Ok(Some(group)) if group.id == group_id => group,
        Ok(_) => {
            tracing::warn!(
                group_id,
                "websocket credential changed while refreshing post-registration policy"
            );
            node_connections.unregister(group_id, conn_id).await;
            return;
        }
        Err(error) => {
            tracing::error!(
                group_id,
                %error,
                "websocket failed to refresh post-registration policy"
            );
            node_connections.unregister(group_id, conn_id).await;
            return;
        }
    };
    let initial_snapshot_mode = ws_initial_snapshot_mode(
        protocol_compatible,
        !relay_shared::models::decode_blocked_protocols(&current_group.blocked_protocols)
            .is_empty(),
    );
    if !protocol_compatible {
        tracing::warn!(
            group_id,
            policy_active = matches!(initial_snapshot_mode, WsInitialSnapshotMode::FailClosed),
            "protocol-incompatible control-only channel registered"
        );
    }

    tracing::info!(
        "websocket connected: group_id={} node_id={:?}",
        group_id,
        node_id
    );

    // Split so we can concurrently read ping/close from the socket AND write
    // broadcast pushes from the channel. Both halves borrow independent state.
    let (mut sender, mut receiver) = socket.split();

    // Send an empty, backward-compatible snapshot to a protocol-incompatible
    // node in a blocked group. Newer pre-v10 nodes use it as a signal to fetch
    // the serialized HTTP snapshot; older ones apply it directly, and their
    // regular HTTP poll then persists the same empty configuration. Never build
    // or expose the v10 listener snapshot on this compatibility bridge.
    let initial_config = match initial_snapshot_mode {
        WsInitialSnapshotMode::FailClosed => Some(policy_fail_closed_snapshot()),
        WsInitialSnapshotMode::ControlOnly => None,
        WsInitialSnapshotMode::Current => {
            // A normal freshly-connected node gets its current config immediately,
            // without waiting for the first HTTP poll. None (DB error) means skip
            // the push; the node will retry through its ordinary HTTP poll.
            build_config_snapshot(db.as_ref(), group_id, &token).await
        }
    };
    if let Some(config) = initial_config {
        if let Ok(config_json) = serde_json::to_string(&config) {
            let _ = sender.send(Message::Text(config_json.into())).await;
        }
    }

    use tokio::time::{timeout, Duration};

    // The read loop idles when the node neither pings nor sends data. We
    // cap idle at 120s so a silently-dropped connection (NAT timeout,
    // half-open TCP) is eventually cleaned up. The node's heartbeat is
    // expected well within this window.
    const READ_TIMEOUT: Duration = Duration::from_secs(120);

    // Drive both halves. `receiver.recv()` (wrapped in a timeout) and
    // `push_rx.recv()` borrow different variables, so select! can hold both
    // pending at once; the branch bodies both use `sender` but only one
    // runs at a time.
    loop {
        tokio::select! {
            msg = timeout(READ_TIMEOUT, receiver.next()) => match msg {
                Err(_) => {
                    tracing::warn!(
                        "websocket idle timeout ({}s): group_id={}",
                        READ_TIMEOUT.as_secs(),
                        group_id
                    );
                    break;
                }
                Ok(Some(Ok(Message::Ping(data)))) => {
                    let _ = sender.send(Message::Pong(data)).await;
                }
                Ok(Some(Ok(Message::Pong(_)))) => {
                    // keepalive acknowledged
                }
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                    tracing::info!("websocket disconnected: group_id={}", group_id);
                    break;
                }
                Ok(Some(Ok(_))) => {
                    // ignore other message types
                }
            },
            pushed = push_rx.recv() => match pushed {
                Some(text) => {
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        tracing::warn!(
                            "websocket send failed: group_id={}, closing",
                            group_id
                        );
                        break;
                    }
                }
                None => break, // all senders dropped — shouldn't happen here
            },
        }
    }

    node_connections.unregister(group_id, conn_id).await;
}

fn policy_fail_closed_snapshot() -> NodeConfigResponse {
    crate::service::node_config::empty_node_config(Vec::new())
}

async fn build_config_snapshot(
    db: &dyn crate::db::Repository,
    group_id: i64,
    token: &str,
) -> Option<NodeConfigResponse> {
    // v0.3.6: delegate to the shared `build_node_config` (same function
    // `get_config` uses). This fixes the v0.3.5 drift where the WS path queried
    // forward_rules WITHOUT joining users, so a reconnecting node could be
    // handed a banned / over-quota user's rules until the next HTTP poll. Now
    // both paths apply the identical filter (paused / banned / quota) and the
    // identical target resolution + listener assembly.
    //
    // Returns None on DB error so the caller skips the snapshot push (rather
    // than pushing an empty config that would incorrectly tear down the node's
    // listeners). An empty Ok is a legitimate "no rules" snapshot.
    match crate::service::node_config::build_node_config(db, group_id).await {
        Ok(cfg) => match db.find_by_token(token).await {
            Ok(Some(group)) if group.id == group_id => Some(cfg),
            Ok(_) => {
                tracing::warn!(
                    "build_config_snapshot: token rotated during build for group {}",
                    group_id
                );
                None
            }
            Err(e) => {
                tracing::error!(
                    "build_config_snapshot: post-build token revalidation failed for group {}: {}",
                    group_id,
                    e
                );
                None
            }
        },
        Err(e) => {
            tracing::error!(
                "build_config_snapshot: build_node_config failed for group {}: {}",
                group_id,
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompatible_node_stays_control_only_until_policy_needs_fail_closed() {
        assert_eq!(
            ws_initial_snapshot_mode(false, false),
            WsInitialSnapshotMode::ControlOnly
        );
        assert_eq!(
            ws_initial_snapshot_mode(false, true),
            WsInitialSnapshotMode::FailClosed
        );
        assert_eq!(
            ws_initial_snapshot_mode(true, true),
            WsInitialSnapshotMode::Current
        );
    }

    #[test]
    fn protocol_incompatible_policy_snapshot_is_wire_compatible_and_empty() {
        let snapshot = policy_fail_closed_snapshot();
        assert!(snapshot.listeners.is_empty());
        assert!(snapshot.tunnels.is_empty());
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: NodeConfigResponse = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.listeners.is_empty());
        assert!(decoded.tunnels.is_empty());
    }

    /// register() must hand back a receiver that actually receives what
    /// broadcast_all sends. This is the contract every admin mutation
    /// relies on for the config_changed push.
    #[tokio::test]
    async fn register_then_broadcast_delivers() {
        let conns = NodeConnections::new();
        let (_id, mut rx) = conns.register(7, None).await;

        conns.broadcast_all(r#"{"type":"config_changed"}"#).await;

        let msg = rx.recv().await;
        assert_eq!(msg.as_deref(), Some(r#"{"type":"config_changed"}"#));
    }

    /// broadcast_all must fan out to EVERY registered connection, not just
    /// the first one — otherwise only one node per group would get pushes.
    #[tokio::test]
    async fn broadcast_fans_out_to_multiple_connections_same_group() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(1, None).await;
        let (_, mut rx_b) = conns.register(1, None).await;
        // Different group should also receive (broadcast_all hits all groups).
        let (_, mut rx_c) = conns.register(99, None).await;

        conns.broadcast_all("hi").await;

        assert_eq!(rx_a.recv().await.as_deref(), Some("hi"));
        assert_eq!(rx_b.recv().await.as_deref(), Some("hi"));
        assert_eq!(rx_c.recv().await.as_deref(), Some("hi"));
    }

    /// After unregister, a connection must no longer receive broadcasts.
    /// This is what prevents memory growth as nodes reconnect.
    #[tokio::test]
    async fn unregister_stops_delivery() {
        let conns = NodeConnections::new();
        let (id, mut rx) = conns.register(3, None).await;

        conns.unregister(3, id).await;
        conns.broadcast_all("late").await;

        // recv on an unregistered sender's receiver: either the sender was
        // removed (so nothing arrives) — either way, no "late" message.
        let leaked = rx.try_recv().ok();
        assert_ne!(leaked.as_deref(), Some("late"));
    }

    /// If a connection's receiver is dropped (node disconnected without
    /// cleanly unregistering), broadcast_all must prune the dead sender
    /// instead of leaking it forever. Verified by checking that the next
    /// broadcast doesn't panic and the live connection still gets the msg.
    #[tokio::test]
    async fn broadcast_prunes_dead_senders() {
        let conns = NodeConnections::new();

        // Register and immediately drop the receiver — simulates a node
        // whose socket died before unregister ran.
        let (_, rx_dead) = conns.register(5, None).await;
        drop(rx_dead);

        // Live connection on the same group.
        let (_, mut rx_live) = conns.register(5, None).await;

        // First broadcast hits the dead sender (send fails) and prunes it;
        // the live sender must still receive.
        conns.broadcast_all("after-death").await;
        assert_eq!(rx_live.recv().await.as_deref(), Some("after-death"));

        // Second broadcast must not error on the pruned entry.
        conns.broadcast_all("again").await;
        assert_eq!(rx_live.recv().await.as_deref(), Some("again"));
    }

    /// close_group must disconnect every connection of the targeted group by
    /// dropping their senders (receiver returns None). This is the token-
    /// rotation contract: the old token is invalid, so every socket that
    /// authenticated with it must be torn down.
    #[tokio::test]
    async fn close_group_disconnects_all_connections_in_group() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(3, None).await;
        let (_, mut rx_b) = conns.register(3, None).await;
        // A different group must be UNAFFECTED.
        let (_, mut rx_other) = conns.register(7, None).await;

        let closed = conns.close_group(3).await;

        // Both connections in group 3 see their receiver return None (sender
        // dropped) — the handle_node_ws loop breaks on this and the socket
        // closes, forcing the node to reconnect and re-auth with the new token.
        assert_eq!(closed, 2, "close_group must report the count closed");
        assert!(rx_a.recv().await.is_none(), "group-3 conn A must be closed");
        assert!(rx_b.recv().await.is_none(), "group-3 conn B must be closed");
        // The other group keeps working.
        conns.broadcast_all("still-here").await;
        assert_eq!(rx_other.recv().await.as_deref(), Some("still-here"));
    }

    /// close_group on a group with no connections returns 0 and is a no-op.
    #[tokio::test]
    async fn close_group_unknown_group_is_noop() {
        let conns = NodeConnections::new();
        let (_, mut rx) = conns.register(3, None).await;

        let closed = conns.close_group(999).await;

        assert_eq!(closed, 0);
        // The real group is untouched.
        conns.broadcast_all("ok").await;
        assert_eq!(rx.recv().await.as_deref(), Some("ok"));
    }

    /// A socket that authenticated before token rotation must not be able to
    /// register afterwards, even when close_group saw no live connection yet.
    #[tokio::test]
    async fn stale_auth_generation_cannot_register_after_rotation() {
        let conns = NodeConnections::new();
        let stale_generation = conns.auth_generation(12).await;

        assert_eq!(conns.close_group(12).await, 0);
        assert!(conns
            .register_if_generation(12, Some("stale-node".into()), stale_generation)
            .await
            .is_none());

        let current_generation = conns.auth_generation(12).await;
        assert!(conns
            .register_if_generation(12, Some("fresh-node".into()), current_generation)
            .await
            .is_some());
    }

    /// v0.4.14: send_node delivers ONLY to the connection whose X-Node-ID
    /// matches; other nodes in the same group are untouched.
    #[tokio::test]
    async fn send_node_targets_only_matching_node() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(1, Some("node-a".into())).await;
        let (_, mut rx_b) = conns.register(1, Some("node-b".into())).await;

        let sent = conns.send_node(1, "node-a", "probe").await;
        assert_eq!(sent, 1, "exactly one connection matched node-a");
        assert_eq!(rx_a.recv().await.as_deref(), Some("probe"));
        // node-b must NOT have received it.
        assert!(
            rx_b.try_recv().is_err(),
            "node-b must not receive node-a's probe"
        );
    }

    /// send_node to a node that has no live connection returns 0 (control
    /// channel offline) — the diagnose path turns this into an immediate
    /// "offline" instead of waiting for a timeout.
    #[tokio::test]
    async fn send_node_unknown_node_returns_zero() {
        let conns = NodeConnections::new();
        let (_, _rx) = conns.register(1, Some("node-a".into())).await;
        assert_eq!(conns.send_node(1, "ghost", "probe").await, 0);
        assert_eq!(conns.send_node(999, "node-a", "probe").await, 0);
    }

    /// online_node_ids returns the node_ids with a live connection; older nodes
    /// (no X-Node-ID) are excluded so they don't get targeted.
    #[tokio::test]
    async fn online_node_ids_excludes_nodeless_connections() {
        let conns = NodeConnections::new();
        let (_, _a) = conns.register(1, Some("node-a".into())).await;
        let (_, _b) = conns.register(1, Some("node-b".into())).await;
        let (_, _legacy) = conns.register(1, None).await; // older node, no X-Node-ID

        let ids = conns.online_node_ids(1).await;
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("node-a"));
        assert!(ids.contains("node-b"));
        // An empty group → empty set.
        assert!(conns.online_node_ids(42).await.is_empty());
    }
}
