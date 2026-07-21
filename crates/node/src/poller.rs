use crate::config::NodeConfig;
use crate::forwarder::ForwarderManager;
use relay_shared::protocol::{NodeConfigResponse, CONFIG_PROTOCOL_VERSION};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Path for the config cache file. Used when the panel is unreachable.
const CACHE_FILE: &str = "config-cache.json";

/// Cache envelope used only when a protocol-blocking policy is active. Older
/// nodes expect `listeners` at the JSON root, so they cannot accidentally load
/// this envelope, ignore the v10 policy fields and resume unfiltered listeners
/// after a binary downgrade. Policy-free snapshots retain the historical raw
/// format so ordinary rollback/offline recovery remains compatible.
#[derive(serde::Serialize, serde::Deserialize)]
struct ProtocolBoundCache {
    config_protocol_version: u32,
    config: NodeConfigResponse,
}

/// File holding this node's stable identity. Generated once on first start
/// (a random hex string) and reused forever after, so the panel can tell
/// multiple nodes sharing one group token apart (fixes status overwrite:
/// node_status:{group_id} was a single key overwritten by every node).
const NODE_ID_FILE: &str = "node-id";

/// v0.4.0: outcome of a config fetch, distinguishing a permanent protocol
/// mismatch (426) from a transient failure (network/5xx). The caller uses this
/// to decide the poll interval: 426 → long backoff (upgrade needed), transient
/// → keep the normal interval.
pub enum FetchResult {
    /// A valid config was received and cached.
    Ok(NodeConfigResponse),
    /// The panel reports a permanent config-protocol mismatch (426). The node
    /// keeps its cached config; the caller should back off (the only fix is an
    /// upgrade, so polling fast is pointless).
    ProtocolMismatch,
    /// The panel authoritatively rejected this group credential (401/403).
    /// Unlike a network outage this must fail closed: callers apply the empty
    /// config returned here and the disk cache is replaced immediately.
    CredentialsRejected(NodeConfigResponse),
    /// Transient failure (network error, 5xx, non-JSON body). The caller keeps
    /// the cached config and retries on the normal interval.
    Transient,
}

/// Outcome of one serialized fetch-and-apply operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncResult {
    Ok,
    ProtocolMismatch,
    CredentialsRejected,
    Transient,
}

/// Serializes every production config fetch through the cache write and
/// manager apply. The HTTP fallback loop and WebSocket control loop otherwise
/// issue independent requests; an older request that completes last could
/// overwrite a newly-rotated credential or re-enable a stopped tunnel both in
/// memory and in `config-cache.json`.
#[derive(Clone, Default)]
pub struct ConfigSynchronizer {
    gate: Arc<Mutex<()>>,
}

impl ConfigSynchronizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn sync(
        &self,
        config: &NodeConfig,
        manager: &Arc<Mutex<ForwarderManager>>,
    ) -> SyncResult {
        // Hold this guard before the HTTP request starts. Ordering only the
        // final apply is insufficient because fetch_config also persists the
        // response to disk before returning it.
        let _guard = self.gate.lock().await;
        match fetch_config(config).await {
            FetchResult::Ok(response) => {
                manager.lock().await.apply_config(&response).await;
                SyncResult::Ok
            }
            FetchResult::ProtocolMismatch => SyncResult::ProtocolMismatch,
            FetchResult::CredentialsRejected(response) => {
                let mut manager = manager.lock().await;
                manager.revoke_all_tunnel_credentials();
                manager.apply_config(&response).await;
                SyncResult::CredentialsRejected
            }
            FetchResult::Transient => SyncResult::Transient,
        }
    }

    /// Synchronize after an explicit panel credential-revocation command. If
    /// the replacement snapshot cannot be fetched, fail the affected links
    /// closed both in memory and in the restart cache while this same ordering
    /// gate is held. That prevents a concurrent ordinary poll or a process
    /// restart from restoring the revoked generation.
    pub async fn sync_after_tunnel_credential_revoke(
        &self,
        config: &NodeConfig,
        manager: &Arc<Mutex<ForwarderManager>>,
        group_id: i64,
    ) -> SyncResult {
        let _guard = self.gate.lock().await;
        match fetch_config(config).await {
            FetchResult::Ok(response) => {
                manager.lock().await.apply_config(&response).await;
                SyncResult::Ok
            }
            FetchResult::CredentialsRejected(response) => {
                let mut manager = manager.lock().await;
                manager.revoke_all_tunnel_credentials();
                manager.apply_config(&response).await;
                SyncResult::CredentialsRejected
            }
            FetchResult::ProtocolMismatch => {
                persist_revocation_fallback(manager, group_id).await;
                SyncResult::ProtocolMismatch
            }
            FetchResult::Transient => {
                persist_revocation_fallback(manager, group_id).await;
                SyncResult::Transient
            }
        }
    }
}

async fn persist_revocation_fallback(manager: &Arc<Mutex<ForwarderManager>>, group_id: i64) {
    let sanitized = manager
        .lock()
        .await
        .fail_closed_tunnel_credentials(group_id)
        .await;
    if let Some(config) = sanitized {
        save_cache_fail_closed(&config);
    } else {
        // No applied in-memory snapshot means the on-disk cache cannot be
        // proven free of this credential. Remove it rather than allowing a
        // restart to resurrect unknown state.
        remove_cache_fail_closed();
    }
}

pub async fn fetch_config(config: &NodeConfig) -> FetchResult {
    let url = format!("{}/api/v1/node/config", config.panel_url);
    let client = reqwest::Client::new();

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        // v0.4.0: send our config-protocol version so the panel can refuse to
        // send config we can't deserialize (keeps old nodes on their cached
        // config instead of crashing on unknown fields/enum variants).
        .header("X-Config-Protocol-Version", CONFIG_PROTOCOL_VERSION)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("fetch_config: network error: {}", e);
            return FetchResult::Transient;
        }
    };

    let status = resp.status();
    if status == reqwest::StatusCode::UPGRADE_REQUIRED {
        // Permanent: the panel's config protocol doesn't match ours. Parse the
        // structured body for a clear log line, then back off.
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let required = body.get("required").and_then(|v| v.as_u64());
        tracing::warn!(
            required = ?required,
            "fetch_config: config protocol mismatch (panel requires v{:?}, node has v{}); \
             keeping cached config — upgrade relay-node",
            required,
            CONFIG_PROTOCOL_VERSION
        );
        return FetchResult::ProtocolMismatch;
    }
    if matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        tracing::error!(
            status = %status,
            "fetch_config: node credential rejected; stopping cached forwarding"
        );
        let empty = empty_config();
        save_cache_fail_closed(&empty);
        return FetchResult::CredentialsRejected(empty);
    }
    if !status.is_success() {
        tracing::warn!(status = %status, "fetch_config: non-2xx response; keeping cached config");
        return FetchResult::Transient;
    }

    match resp.json::<NodeConfigResponse>().await {
        Ok(cfg) => {
            save_cache(&cfg);
            FetchResult::Ok(cfg)
        }
        Err(e) => {
            tracing::warn!("fetch_config: response parse failed: {}", e);
            FetchResult::Transient
        }
    }
}

fn empty_config() -> NodeConfigResponse {
    NodeConfigResponse {
        listeners: Vec::new(),
        tunnels: Vec::new(),
        credential_revisions: vec![],
        terminate_tunnel_ids: Vec::new(),
        drain_rule_ids: Vec::new(),
        route_transition_rule_ids: vec![],
        route_staging_rule_ids: vec![],
        route_drain_rule_ids: vec![],
        public_entry_blocked_protocols: vec![],
    }
}

/// Load cached config from config-cache.json.
/// Returns None if file doesn't exist or is corrupt.
pub fn load_cache() -> Option<NodeConfigResponse> {
    let path = cache_path();
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let resp = load_cache_at(&path)?;
    tracing::info!(
        "Loaded cached config from {} ({} listeners)",
        path.display(),
        resp.listeners.len()
    );
    Some(resp)
}

fn load_cache_at(path: &std::path::Path) -> Option<NodeConfigResponse> {
    let data = std::fs::read_to_string(path).ok()?;
    if let Ok(bound) = serde_json::from_str::<ProtocolBoundCache>(&data) {
        if bound.config_protocol_version != CONFIG_PROTOCOL_VERSION {
            tracing::warn!(
                cached = bound.config_protocol_version,
                current = CONFIG_PROTOCOL_VERSION,
                "Ignoring protocol-bound config cache from an incompatible node version"
            );
            return None;
        }
        return Some(bound.config);
    }
    // Backward compatibility for every policy-free cache written before v10.
    serde_json::from_str::<NodeConfigResponse>(&data).ok()
}

/// Save config to config-cache.json (next to the binary or in working dir).
fn save_cache(config: &NodeConfigResponse) {
    let path = cache_path();
    if let Err(error) = save_cache_at(config, &path) {
        tracing::warn!(
            "Failed to write config cache to {}: {}",
            path.display(),
            error
        );
    }
}

fn save_cache_fail_closed(config: &NodeConfigResponse) {
    let path = cache_path();
    if let Err(error) = save_cache_at(config, &path) {
        tracing::error!(
            "Failed to persist fail-closed config cache to {}: {}; removing stale cache",
            path.display(),
            error
        );
        remove_cache_at_fail_closed(&path);
    }
}

fn save_cache_at(config: &NodeConfigResponse, path: &std::path::Path) -> std::io::Result<()> {
    let policy_active = !config.public_entry_blocked_protocols.is_empty()
        || config
            .listeners
            .iter()
            .any(|listener| !listener.blocked_protocols.is_empty());
    let json = if policy_active {
        serde_json::to_vec_pretty(&ProtocolBoundCache {
            config_protocol_version: CONFIG_PROTOCOL_VERSION,
            config: config.clone(),
        })
    } else {
        serde_json::to_vec_pretty(config)
    }
    .map_err(|error| std::io::Error::other(format!("serialize config cache: {error}")))?;
    write_private_atomic(path, &json)
}

fn remove_cache_fail_closed() {
    remove_cache_at_fail_closed(&cache_path());
}

fn remove_cache_at_fail_closed(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::warn!("Removed stale config cache {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::error!(
            "Failed to remove stale config cache {} after credential revocation: {}",
            path.display(),
            error
        ),
    }
}

fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(CACHE_FILE);
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn data_dir() -> PathBuf {
    std::env::var_os("RELAY_NODE_DATA_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn cache_path() -> PathBuf {
    data_dir().join(CACHE_FILE)
}

/// Resolve where the node-id file lives — same directory logic as cache_path
/// so the two files sit together (production: /opt/relay-node/, dev: cwd).
fn node_id_path() -> PathBuf {
    data_dir().join(NODE_ID_FILE)
}

/// Get this node's stable identity, generating + persisting it on first call.
///
/// The id is a random hex string generated once and reused across restarts, so
/// the panel can distinguish multiple physical nodes that share one inbound
/// group token (each gets its own node_status:{group_id}:{node_id} key instead
/// of all overwriting node_status:{group_id}).
///
/// Generation uses the OS random source via std; we deliberately do NOT derive
/// it from hostname/MAC (those can change/DHCP) — a stable random id is the
/// contract the panel's status dedup depends on.
pub fn get_or_create_node_id() -> String {
    get_or_create_node_id_at(&node_id_path())
}

/// Inner implementation taking an explicit path, so it's unit-testable without
/// touching the real /opt/relay-node or cwd.
fn get_or_create_node_id_at(path: &std::path::Path) -> String {
    // Try to load an existing id first.
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // No id yet: generate one (16 random bytes → 32 hex chars). std's
    // fill_bytes uses the OS CSPRNG; we don't need cryptographic strength but
    // it's the most portable "good enough random" available without extra deps.
    let mut bytes = [0u8; 16];
    use std::io::Read;
    // /dev/urandom on Linux (the only supported platform); fall back to a
    // time+pid-based id if unavailable so the node still boots.
    let id = match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => hex_encode(&bytes),
        Err(_) => {
            tracing::warn!("could not read /dev/urandom for node_id; using fallback");
            fallback_id()
        }
    };
    if let Err(e) = std::fs::write(path, &id) {
        tracing::warn!("failed to persist node_id to {}: {}", path.display(), e);
        // Non-fatal: we return the in-memory id; it'll regenerate next start,
        // which means status may flap for this node until the file is writable.
    } else {
        tracing::info!("generated node_id {} -> {}", id, path.display());
    }
    id
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Fallback id when /dev/urandom is unavailable. Not random, but unique enough
/// per (host, pid, time) to avoid collisions in practice — and only used on
/// broken systems where /dev/urandom is missing (shouldn't happen on Linux).
fn fallback_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("node-{}-{}", std::process::id(), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_write_is_atomic_and_private() {
        let path = std::env::temp_dir().join(format!(
            "relaypanel-test-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_private_atomic(&path, br#"{"listeners":[]}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"listeners":[]}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let prefix = format!(".{}.tmp-", path.file_name().unwrap().to_string_lossy());
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .count();
        assert_eq!(leftovers, 0, "atomic cache write left temporary files");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn protocol_policy_cache_is_bound_to_v10_and_unreadable_as_a_legacy_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "relaypanel-test-policy-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = empty_config();
        config.public_entry_blocked_protocols = vec![relay_shared::models::BlockedProtocol::Tls];
        save_cache_at(&config, &path).unwrap();

        let encoded = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value["config_protocol_version"],
            serde_json::json!(CONFIG_PROTOCOL_VERSION)
        );
        assert!(value.get("listeners").is_none());
        assert!(value["config"]["listeners"].is_array());

        // All pre-v10 NodeConfigResponse versions require a root `listeners`
        // field. This models their serde behavior and proves a downgraded node
        // fails closed instead of ignoring the policy nested in the envelope.
        #[derive(serde::Deserialize)]
        struct LegacyNodeConfigResponse {
            #[allow(dead_code)]
            listeners: Vec<serde_json::Value>,
        }
        assert!(serde_json::from_str::<LegacyNodeConfigResponse>(&encoded).is_err());

        let loaded = load_cache_at(&path).expect("current node must load its protected cache");
        assert_eq!(
            loaded.public_entry_blocked_protocols,
            vec![relay_shared::models::BlockedProtocol::Tls]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn policy_free_cache_keeps_the_legacy_root_shape() {
        let path = std::env::temp_dir().join(format!(
            "relaypanel-test-plain-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        save_cache_at(&empty_config(), &path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(value["listeners"].is_array());
        assert!(value.get("config").is_none());
        assert!(load_cache_at(&path).is_some());
        let _ = std::fs::remove_file(path);
    }

    /// A node_id generated once must be reused verbatim on every subsequent
    /// call — this stability is the contract the panel's status dedup depends
    /// on. If this breaks, a restarting node would look like a NEW node and its
    /// old status entry would stale forever.
    #[test]
    fn node_id_is_stable_across_calls() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "relaypanel-test-nodeid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = get_or_create_node_id_at(&path);
        let second = get_or_create_node_id_at(&path);
        assert!(!first.is_empty(), "first id must be non-empty");
        assert_eq!(
            first, second,
            "node_id must be stable: a restart must reuse the persisted id"
        );
        // The file must exist and hold exactly the id (so it survives a real
        // process restart, not just in-memory caching).
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim(), first);
        let _ = std::fs::remove_file(&path);
    }

    /// Two different nodes (different id files) must get DIFFERENT ids. This is
    /// what lets the panel tell them apart — if they collided, the status
    /// overwrite bug would be back.
    #[test]
    fn distinct_nodes_get_distinct_ids() {
        let dir = std::env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path_a = dir.join(format!("relaypanel-test-nodeid-a-{}", stamp));
        let path_b = dir.join(format!("relaypanel-test-nodeid-b-{}", stamp));
        let a = get_or_create_node_id_at(&path_a);
        let b = get_or_create_node_id_at(&path_b);
        assert_ne!(a, b, "two fresh nodes must not share an id");
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    /// A pre-existing node-id file must be honored as-is (an operator who set
    /// a specific id, or a node restored from backup, keeps that identity).
    #[test]
    fn existing_node_id_file_is_honored() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "relaypanel-test-nodeid-existing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "my-fixed-id-12345").unwrap();
        let id = get_or_create_node_id_at(&path);
        assert_eq!(id, "my-fixed-id-12345");
        let _ = std::fs::remove_file(&path);
    }

    /// A v7 node must be able to boot from an older cache while panel/node
    /// binaries are being rolled. All newly-added routing/UOT/TFO fields have
    /// safe defaults, so the cached listener stays native instead of
    /// disappearing or changing its TCP handshake behaviour.
    #[test]
    fn v5_cache_deserializes_as_native_forwarding() {
        let cached = r#"{
            "listeners": [{
                "rule_id": 7,
                "port": 20000,
                "protocol": "udp",
                "node_transport": "raw",
                "targets": ["127.0.0.1:53"],
                "count_traffic": true
            }]
        }"#;
        let config: NodeConfigResponse = serde_json::from_str(cached).unwrap();
        let listener = &config.listeners[0];
        assert!(listener.target_weights.is_empty());
        assert_eq!(listener.uot_role, relay_shared::protocol::UotRole::Disabled);
        assert!(!listener.zero_rtt);
        assert!(!listener.tcp_fast_open);
    }
}
