//! Config-protocol v8 reusable tunnel transport.
//!
//! Every connection starts with one fixed client-first HMAC header. After that
//! TCP/probe traffic is a raw byte stream and UDP uses the existing UOT frame
//! format. Payload bytes are authenticated only at setup and are intentionally
//! not encrypted; applications that need confidentiality must use end-to-end
//! TLS/WireGuard/etc.

use hmac::{Hmac, Mac};
use relay_shared::protocol::{TunnelClientConfig, TunnelListenerConfig, TunnelRouteConfig};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};

use super::selector::{TargetLease, TargetSelector};

const MAGIC: &[u8; 8] = b"RPTUN001";
const VERSION: u8 = 2;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 32;
const SIGNED_LEN: usize = 52;
pub const HEADER_LEN: usize = SIGNED_LEN + TAG_LEN;
/// Nodes are expected to run an ordinary time synchronizer. A full minute of
/// skew keeps the one-way handshake operational during normal NTP correction,
/// while bounding how long a captured header can remain valid.
const HEADER_MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);
/// Two skew windows are the longest possible lifetime of a header: one first
/// observed when the receiver is 60 seconds behind can remain timestamp-valid
/// until the receiver is 60 seconds ahead of that signed timestamp.
const REPLAY_BUCKET_DURATION: Duration = Duration::from_secs(120);
/// Fixed-size Bloom buckets keep replay memory bounded without evicting a nonce
/// that is still inside the authenticated timestamp window. False positives
/// fail closed; there are no false negatives before a bucket expires.
const REPLAY_BLOOM_BITS: usize = 1 << 23;
const REPLAY_BLOOM_WORDS: usize = REPLAY_BLOOM_BITS / u64::BITS as usize;
const REPLAY_BLOOM_HASHES: u64 = 4;
type HmacSha256 = Hmac<Sha256>;
type Nonce = [u8; NONCE_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelMode {
    Tcp = 1,
    Udp = 2,
    Probe = 3,
}

impl TunnelMode {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Probe),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Header {
    mode: TunnelMode,
    tunnel_id: i64,
    rule_id: i64,
    hop_position: u8,
    #[cfg_attr(not(test), allow(dead_code))]
    nonce: Nonce,
}

#[derive(Default)]
struct ReplayBloom {
    words: Option<Box<[u64]>>,
}

impl ReplayBloom {
    fn contains(&self, nonce: &Nonce) -> bool {
        let Some(words) = self.words.as_ref() else {
            return false;
        };
        replay_bloom_indexes(nonce).all(|index| {
            let word = index / u64::BITS as usize;
            let bit = index % u64::BITS as usize;
            words[word] & (1u64 << bit) != 0
        })
    }

    fn insert(&mut self, nonce: &Nonce) {
        let words = self
            .words
            .get_or_insert_with(|| vec![0u64; REPLAY_BLOOM_WORDS].into_boxed_slice());
        for index in replay_bloom_indexes(nonce) {
            let word = index / u64::BITS as usize;
            let bit = index % u64::BITS as usize;
            words[word] |= 1u64 << bit;
        }
    }
}

fn replay_bloom_indexes(nonce: &Nonce) -> impl Iterator<Item = usize> {
    let left = u64::from_be_bytes(nonce[..8].try_into().unwrap());
    let right = u64::from_be_bytes(nonce[8..].try_into().unwrap());
    let first = mix_replay_hash(left ^ right.rotate_left(17));
    // An odd second hash traverses the complete power-of-two bit space.
    let second = mix_replay_hash(right ^ left.rotate_right(11) ^ 0x9e37_79b9_7f4a_7c15) | 1;
    (0..REPLAY_BLOOM_HASHES).map(move |round| {
        first
            .wrapping_add(round.wrapping_mul(second))
            .wrapping_add(round.wrapping_mul(round).wrapping_mul(0x9e37_79b9)) as usize
            & (REPLAY_BLOOM_BITS - 1)
    })
}

fn mix_replay_hash(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

struct ReplayValues {
    current: ReplayBloom,
    previous: ReplayBloom,
    bucket_started: Instant,
}

impl Default for ReplayValues {
    fn default() -> Self {
        Self {
            current: ReplayBloom::default(),
            previous: ReplayBloom::default(),
            bucket_started: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct ReplayCache {
    values: Mutex<ReplayValues>,
}

impl ReplayCache {
    async fn insert(&self, nonce: Nonce) -> bool {
        self.insert_at(nonce, Instant::now()).await
    }

    async fn insert_at(&self, nonce: Nonce, now: Instant) -> bool {
        let mut values = self.values.lock().await;
        let elapsed = now.saturating_duration_since(values.bucket_started);
        if elapsed >= REPLAY_BUCKET_DURATION {
            if elapsed < REPLAY_BUCKET_DURATION.saturating_mul(2) {
                values.previous = std::mem::take(&mut values.current);
                values.current = ReplayBloom::default();
                values.bucket_started = values
                    .bucket_started
                    .checked_add(REPLAY_BUCKET_DURATION)
                    .unwrap_or(now);
            } else {
                values.current = ReplayBloom::default();
                values.previous = ReplayBloom::default();
                values.bucket_started = now;
            }
        }
        if values.current.contains(&nonce) || values.previous.contains(&nonce) {
            return false;
        }
        values.current.insert(&nonce);
        true
    }
}

/// Cancellation generation for authenticated streams on one shared listener.
/// Connection handles retain a sender clone, so merely replacing a listener
/// lets established streams drain; explicit credential revocation bumps the
/// generation and tears them down.
#[derive(Clone)]
pub struct TunnelRuntime {
    cancel: watch::Sender<u64>,
    active: Arc<AtomicUsize>,
    credential_generations: Arc<StdMutex<Vec<Weak<TunnelCredentialGeneration>>>>,
}

#[derive(Debug)]
struct TunnelCredentialGeneration {
    groups: Vec<(i64, Option<i64>)>,
    cancel: watch::Sender<u64>,
}

#[derive(Debug)]
struct TunnelRuleGeneration {
    cancel: watch::Sender<u64>,
}

impl TunnelRuleGeneration {
    fn new() -> Self {
        let (cancel, _) = watch::channel(0);
        Self { cancel }
    }

    fn cancel(&self) {
        self.cancel.send_modify(|generation| *generation += 1);
    }
}

impl TunnelCredentialGeneration {
    fn cancel(&self) {
        self.cancel.send_modify(|generation| *generation += 1);
    }
}

impl TunnelRuntime {
    pub fn new() -> Self {
        let (cancel, _) = watch::channel(0);
        Self {
            cancel,
            active: Arc::new(AtomicUsize::new(0)),
            credential_generations: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn credential_generation(
        &self,
        config: &TunnelListenerConfig,
        credential_revisions: &HashMap<i64, i64>,
    ) -> Arc<TunnelCredentialGeneration> {
        let mut groups: Vec<(i64, Option<i64>)> = link_scope_group_ids(&config.link_scope)
            .chain(
                config
                    .next
                    .as_ref()
                    .into_iter()
                    .flat_map(|next| link_scope_group_ids(&next.link_scope)),
            )
            .map(|group_id| {
                let revision = credential_revisions.get(&group_id).copied();
                (group_id, revision)
            })
            .collect();
        groups.sort_unstable();
        groups.dedup();
        let (cancel, _) = watch::channel(0);
        let generation = Arc::new(TunnelCredentialGeneration { groups, cancel });
        let mut generations = self
            .credential_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        generations.retain(|existing| existing.strong_count() > 0);
        generations.push(Arc::downgrade(&generation));
        generation
    }

    fn connection(
        &self,
        credential_generation: Arc<TunnelCredentialGeneration>,
    ) -> TunnelConnectionCancel {
        self.active.fetch_add(1, Ordering::AcqRel);
        let receiver = self.cancel.subscribe();
        let credential_cancel = credential_generation.cancel.subscribe();
        // A watch subscriber starts at the sender's current version. If a
        // revoke raced between accept/context selection and this subscription,
        // changed() alone would wait for a *second* revoke forever. Preserve
        // the already-raised generation as an immediate cancellation.
        let cancelled_on_subscribe = *receiver.borrow() != 0 || *credential_cancel.borrow() != 0;
        TunnelConnectionCancel {
            receiver,
            credential_cancel,
            cancelled_on_subscribe,
            keepalive: self.cancel.clone(),
            active: self.active.clone(),
            _credential_generation: credential_generation,
        }
    }

    pub fn cancel_all(&self) {
        self.cancel.send_modify(|generation| *generation += 1);
    }

    pub fn is_idle(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    pub fn uses_credential_group(&self, group_id: i64) -> bool {
        let mut generations = self
            .credential_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut found = false;
        generations.retain(|generation| {
            let Some(generation) = generation.upgrade() else {
                return false;
            };
            found |= generation
                .groups
                .iter()
                .any(|(generation_group_id, _)| *generation_group_id == group_id);
            true
        });
        found
    }

    pub fn revoke_credential_group(&self, group_id: i64, current_revision: Option<i64>) {
        let mut generations = self
            .credential_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        generations.retain(|generation| {
            let Some(generation) = generation.upgrade() else {
                return false;
            };
            if generation
                .groups
                .iter()
                .any(|(generation_group_id, revision)| {
                    *generation_group_id == group_id
                        && current_revision.is_none_or(|current| *revision != Some(current))
                })
            {
                generation.cancel();
            }
            true
        });
    }
}

impl Default for TunnelRuntime {
    fn default() -> Self {
        Self::new()
    }
}

struct TunnelConnectionCancel {
    receiver: watch::Receiver<u64>,
    credential_cancel: watch::Receiver<u64>,
    cancelled_on_subscribe: bool,
    // Keep the channel open after the manager drops an old listener. That is
    // what distinguishes ordinary path replacement (drain) from revocation.
    keepalive: watch::Sender<u64>,
    active: Arc<AtomicUsize>,
    _credential_generation: Arc<TunnelCredentialGeneration>,
}

impl Drop for TunnelConnectionCancel {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl TunnelConnectionCancel {
    async fn cancelled(&mut self) {
        if self.cancelled_on_subscribe {
            return;
        }
        tokio::select! {
            _ = self.receiver.changed() => {}
            _ = self.credential_cancel.changed() => {}
        }
        let _ = &self.keepalive;
    }
}

pub async fn write_header(
    stream: &mut TcpStream,
    config: &TunnelClientConfig,
    mode: TunnelMode,
) -> std::io::Result<()> {
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = mode as u8;
    header[10] = config.hop_position;
    header[11] = 0;
    header[12..20].copy_from_slice(&config.tunnel_id.to_be_bytes());
    header[20..28].copy_from_slice(&config.rule_id.to_be_bytes());
    let timestamp = unix_timestamp_secs()?;
    header[28..36].copy_from_slice(&timestamp.to_be_bytes());
    getrandom::fill(&mut header[36..52])
        .map_err(|error| std::io::Error::other(format!("tunnel nonce: {error}")))?;
    let tag = auth_tag(&config.auth_token, &header[..SIGNED_LEN])?;
    header[SIGNED_LEN..].copy_from_slice(&tag);
    stream.write_all(&header).await?;
    stream.flush().await
}

async fn read_header(
    stream: &mut TcpStream,
    token: &str,
    timeout: Duration,
    replay: &ReplayCache,
) -> std::io::Result<Header> {
    let mut bytes = [0u8; HEADER_LEN];
    tokio::time::timeout(timeout, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel handshake timeout")
        })??;
    if &bytes[..8] != MAGIC || bytes[8] != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid tunnel header",
        ));
    }
    verify_auth_tag(token, &bytes[..SIGNED_LEN], &bytes[SIGNED_LEN..])?;
    let timestamp = u64::from_be_bytes(bytes[28..36].try_into().unwrap());
    let now = unix_timestamp_secs()?;
    if now.abs_diff(timestamp) > HEADER_MAX_CLOCK_SKEW.as_secs() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "tunnel header timestamp outside allowed clock skew",
        ));
    }
    let nonce: [u8; NONCE_LEN] = bytes[36..52].try_into().unwrap();
    if !replay.insert(nonce).await {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "tunnel nonce replay",
        ));
    }
    Ok(Header {
        mode: TunnelMode::from_byte(bytes[9]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid tunnel mode")
        })?,
        tunnel_id: i64::from_be_bytes(bytes[12..20].try_into().unwrap()),
        rule_id: i64::from_be_bytes(bytes[20..28].try_into().unwrap()),
        hop_position: bytes[10],
        nonce,
    })
}

fn unix_timestamp_secs() -> std::io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| std::io::Error::other(format!("system clock before unix epoch: {error}")))
}

fn auth_tag(token: &str, signed: &[u8]) -> std::io::Result<[u8; TAG_LEN]> {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid tunnel key"))?;
    mac.update(b"relay-panel-preset-header-v1\0");
    mac.update(signed);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_auth_tag(token: &str, signed: &[u8], tag: &[u8]) -> std::io::Result<()> {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid tunnel key"))?;
    mac.update(b"relay-panel-preset-header-v1\0");
    mac.update(signed);
    mac.verify_slice(tag).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "tunnel HMAC rejected")
    })
}

#[derive(Clone)]
pub struct TunnelListenerState {
    current: Arc<RwLock<Arc<TunnelConnectionContext>>>,
    source_ipv4: Option<Ipv4Addr>,
    udp_sessions: Arc<Semaphore>,
    /// Shared across hot configuration generations, otherwise repeatedly
    /// updating a route could multiply the unauthenticated handshake cap.
    unauthenticated: Arc<Semaphore>,
    runtime: TunnelRuntime,
}

impl TunnelListenerState {
    pub fn new(
        config: TunnelListenerConfig,
        credential_revisions: &HashMap<i64, i64>,
        source_ipv4: Option<Ipv4Addr>,
        replay: Arc<ReplayCache>,
        udp_sessions: Arc<Semaphore>,
        runtime: TunnelRuntime,
    ) -> Self {
        let unauthenticated = Arc::new(Semaphore::new(
            config.max_unauthenticated.clamp(1, 4096) as usize
        ));
        let current = build_context(
            config,
            TunnelContextResources {
                source_ipv4,
                replay,
                udp_sessions: udp_sessions.clone(),
                unauthenticated: unauthenticated.clone(),
            },
            None,
            &runtime,
            credential_revisions,
        );
        Self {
            current: Arc::new(RwLock::new(current)),
            source_ipv4,
            udp_sessions,
            unauthenticated,
            runtime,
        }
    }

    /// Swap authentication, next-hop and route-table state without touching the
    /// bound TCP socket. Connections that already captured the previous context
    /// continue draining; the next accepted connection sees this snapshot.
    pub fn update(
        &self,
        config: TunnelListenerConfig,
        credential_revisions: &HashMap<i64, i64>,
        replay: Arc<ReplayCache>,
        revoke_previous: bool,
    ) {
        let previous = self.snapshot();
        let next = build_context(
            config,
            TunnelContextResources {
                source_ipv4: self.source_ipv4,
                replay,
                udp_sessions: self.udp_sessions.clone(),
                unauthenticated: self.unauthenticated.clone(),
            },
            Some(&previous),
            &self.runtime,
            credential_revisions,
        );
        let removed_rule_generations: Vec<_> = previous
            .rule_generations
            .iter()
            .filter(|(rule_id, _)| !next.rule_generations.contains_key(rule_id))
            .map(|(_, generation)| generation.clone())
            .collect();
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        // A route disappearing means pause/ban/quota/unshare/unbind. Cancel only
        // that rule's already-authenticated and pre-auth accepted connections;
        // unrelated rules on this shared socket must keep running.
        for generation in removed_rule_generations {
            generation.cancel();
        }
        if revoke_previous {
            previous.credential_generation.cancel();
        }
    }

    fn snapshot(&self) -> Arc<TunnelConnectionContext> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

struct TunnelContextResources {
    source_ipv4: Option<Ipv4Addr>,
    replay: Arc<ReplayCache>,
    udp_sessions: Arc<Semaphore>,
    unauthenticated: Arc<Semaphore>,
}

fn build_context(
    config: TunnelListenerConfig,
    resources: TunnelContextResources,
    previous: Option<&TunnelConnectionContext>,
    runtime: &TunnelRuntime,
    credential_revisions: &HashMap<i64, i64>,
) -> Arc<TunnelConnectionContext> {
    let TunnelContextResources {
        source_ipv4,
        replay,
        udp_sessions,
        unauthenticated,
    } = resources;
    let final_hop = config.next.is_none();
    let selectors: HashMap<i64, Arc<TargetSelector>> = config
        .routes
        .iter()
        .map(|route| {
            let selector = previous
                .and_then(|previous| {
                    previous
                        .route_indexes
                        .get(&route.rule_id)
                        .and_then(|index| previous.config.routes.get(*index))
                        .filter(|old| **old == *route)
                        .and_then(|_| previous.selectors.get(&route.rule_id).cloned())
                })
                .unwrap_or_else(|| {
                    let selector = Arc::new(TargetSelector::with_weights(
                        route.load_balance_strategy,
                        route.targets.len(),
                        route.target_weights.clone(),
                    ));
                    if final_hop
                        && !route.targets.is_empty()
                        && route.load_balance_strategy
                            != relay_shared::protocol::LoadBalanceStrategy::First
                    {
                        super::selector::spawn_active_probes(
                            Arc::downgrade(&selector),
                            route.targets.clone(),
                            source_ipv4,
                            route.protocol != "udp",
                        );
                    }
                    selector
                });
            (route.rule_id, selector)
        })
        .collect();
    // Shared listeners can carry many rules. Build the route index once per
    // hot configuration generation instead of cloning and linearly scanning
    // the complete route table for every accepted connection.
    let route_indexes = config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| (route.rule_id, index))
        .collect();
    let rule_generations = config
        .routes
        .iter()
        .map(|route| {
            let generation = previous
                .and_then(|previous| previous.rule_generations.get(&route.rule_id).cloned())
                .unwrap_or_else(|| Arc::new(TunnelRuleGeneration::new()));
            (route.rule_id, generation)
        })
        .collect();
    let credential_generation = runtime.credential_generation(&config, credential_revisions);
    Arc::new(TunnelConnectionContext {
        unauthenticated,
        config,
        source_ipv4,
        replay,
        udp_sessions,
        route_indexes: Arc::new(route_indexes),
        selectors: Arc::new(selectors),
        rule_generations: Arc::new(rule_generations),
        credential_generation,
    })
}

pub async fn serve_listener(
    listener: TcpListener,
    state: TunnelListenerState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, peer) = listener.accept().await?;
        // Subscribe before reading the current context. Credential updates swap
        // the context first and then bump the runtime generation, so an accept
        // racing that update either uses the new key or observes cancellation.
        let context = state.snapshot();
        let mut cancellation = state
            .runtime
            .connection(context.credential_generation.clone());
        let Ok(permit) = context.unauthenticated.clone().try_acquire_owned() else {
            tracing::debug!(
                "tunnel {} unauthenticated connection cap reached",
                context.config.tunnel_id
            );
            drop(stream);
            continue;
        };
        tokio::spawn(async move {
            tokio::select! {
                result = handle_connection(stream, peer, permit, context) => {
                    if let Err(error) = result {
                        tracing::debug!(
                            "shared tunnel connection from {} rejected/ended: {}",
                            peer,
                            error
                        );
                    }
                }
                _ = cancellation.cancelled() => {
                    tracing::debug!("shared tunnel connection from {} revoked", peer);
                }
            }
        });
    }
}

struct TunnelConnectionContext {
    config: TunnelListenerConfig,
    source_ipv4: Option<Ipv4Addr>,
    replay: Arc<ReplayCache>,
    unauthenticated: Arc<Semaphore>,
    udp_sessions: Arc<Semaphore>,
    route_indexes: Arc<HashMap<i64, usize>>,
    selectors: Arc<HashMap<i64, Arc<TargetSelector>>>,
    rule_generations: Arc<HashMap<i64, Arc<TunnelRuleGeneration>>>,
    credential_generation: Arc<TunnelCredentialGeneration>,
}

fn link_scope_group_ids(scope: &str) -> impl Iterator<Item = i64> + '_ {
    scope
        .split(':')
        .skip(2)
        .take(2)
        .filter_map(|part| part.parse().ok())
}

async fn handle_connection(
    mut inbound: TcpStream,
    _peer: SocketAddr,
    permit: OwnedSemaphorePermit,
    context: Arc<TunnelConnectionContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    inbound.set_nodelay(true)?;
    super::outbound::apply_keepalive(&inbound, "preset tunnel accept");
    let header = read_header(
        &mut inbound,
        &context.config.auth_token,
        Duration::from_millis(context.config.handshake_timeout_ms.clamp(250, 30_000)),
        context.replay.as_ref(),
    )
    .await?;
    drop(permit);
    if header.tunnel_id != context.config.tunnel_id
        || header.hop_position.saturating_add(1) != context.config.hop_position
    {
        return Err("tunnel id/hop mismatch".into());
    }
    let route_index = context
        .route_indexes
        .get(&header.rule_id)
        .copied()
        .ok_or("unknown or inactive tunnel rule")?;
    let route = context
        .config
        .routes
        .get(route_index)
        .cloned()
        .ok_or("missing indexed tunnel route")?;
    if !mode_allowed(&route, header.mode) {
        return Err("tunnel mode is not allowed by rule protocol".into());
    }
    let selector = context
        .selectors
        .get(&route.rule_id)
        .cloned()
        .ok_or("missing tunnel target selector")?;
    let rule_generation = context
        .rule_generations
        .get(&route.rule_id)
        .cloned()
        .ok_or("missing tunnel rule generation")?;
    let mut rule_cancel = rule_generation.cancel.subscribe();
    if *rule_cancel.borrow() != 0 {
        return Err("tunnel rule revoked".into());
    }
    let tunnel_id = context.config.tunnel_id;
    let next = context.config.next.clone();

    let forwarding = async move {
        if header.mode == TunnelMode::Probe {
            let ok = if let Some(next) = &next {
                let mut outbound =
                    super::outbound::tcp_connect(&next.address, context.source_ipv4, 5).await?;
                write_header(
                    &mut outbound,
                    &TunnelClientConfig {
                        tunnel_id,
                        rule_id: route.rule_id,
                        hop_position: next.hop_position,
                        address: next.address.clone(),
                        auth_token: next.auth_token.clone(),
                        link_scope: next.link_scope.clone(),
                    },
                    TunnelMode::Probe,
                )
                .await?;
                let mut result = [0u8; 1];
                outbound.read_exact(&mut result).await.is_ok() && result[0] == 1
            } else {
                connect_route_target(&route, selector.clone(), context.source_ipv4)
                    .await
                    .is_ok()
            };
            inbound.write_all(&[u8::from(ok)]).await?;
            return Ok(());
        }

        if let Some(next) = &next {
            let mut outbound =
                super::outbound::tcp_connect(&next.address, context.source_ipv4, 5).await?;
            write_header(
                &mut outbound,
                &TunnelClientConfig {
                    tunnel_id,
                    rule_id: route.rule_id,
                    hop_position: next.hop_position,
                    address: next.address.clone(),
                    auth_token: next.auth_token.clone(),
                    link_scope: next.link_scope.clone(),
                },
                header.mode,
            )
            .await?;
            copy_raw(inbound, outbound).await?;
        } else if header.mode == TunnelMode::Tcp {
            let (outbound, _target_lease) =
                connect_route_target(&route, selector, context.source_ipv4).await?;
            copy_raw(inbound, outbound).await?;
        } else {
            super::uot::serve_authenticated_egress(
                inbound,
                route.targets,
                selector,
                context.source_ipv4,
                context.udp_sessions.clone(),
            )
            .await?;
        }
        Ok(())
    };
    tokio::select! {
        result = forwarding => result,
        _ = rule_cancel.changed() => Err("tunnel rule revoked".into()),
    }
}

fn mode_allowed(route: &TunnelRouteConfig, mode: TunnelMode) -> bool {
    match mode {
        TunnelMode::Tcp | TunnelMode::Probe => matches!(route.protocol.as_str(), "tcp" | "tcp_udp"),
        TunnelMode::Udp => matches!(route.protocol.as_str(), "udp" | "tcp_udp"),
    }
}

async fn connect_route_target(
    route: &TunnelRouteConfig,
    selector: Arc<TargetSelector>,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(TcpStream, Option<TargetLease>), Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();
    for index in selector.order() {
        let Some(target) = route.targets.get(index) else {
            continue;
        };
        let started = std::time::Instant::now();
        match super::outbound::tcp_connect(target, source_ipv4, 5).await {
            Ok(stream) => {
                selector.report_timed(index, true, Some(started.elapsed()));
                let lease = selector.acquire(index);
                return Ok((stream, lease));
            }
            Err(error) => {
                selector.report(index, false);
                errors.push(format!("{target}: {error}"));
            }
        }
    }
    Err(format!("no reachable tunnel target: {}", errors.join("; ")).into())
}

async fn copy_raw(
    inbound: TcpStream,
    outbound: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "linux")]
    {
        super::splice::zero_copy_bidirectional(inbound, outbound).await?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut inbound, mut outbound) = (inbound, outbound);
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::{LoadBalanceStrategy, TunnelNextConfig};

    fn fixed_header_at(
        token: &str,
        tunnel_id: i64,
        rule_id: i64,
        hop_position: u8,
        mode: TunnelMode,
        timestamp: u64,
        nonce: [u8; NONCE_LEN],
    ) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = VERSION;
        bytes[9] = mode as u8;
        bytes[10] = hop_position;
        bytes[12..20].copy_from_slice(&tunnel_id.to_be_bytes());
        bytes[20..28].copy_from_slice(&rule_id.to_be_bytes());
        bytes[28..36].copy_from_slice(&timestamp.to_be_bytes());
        bytes[36..52].copy_from_slice(&nonce);
        let tag = auth_tag(token, &bytes[..SIGNED_LEN]).unwrap();
        bytes[SIGNED_LEN..].copy_from_slice(&tag);
        bytes
    }

    fn fixed_header(
        token: &str,
        tunnel_id: i64,
        rule_id: i64,
        hop_position: u8,
        mode: TunnelMode,
        nonce: [u8; NONCE_LEN],
    ) -> [u8; HEADER_LEN] {
        fixed_header_at(
            token,
            tunnel_id,
            rule_id,
            hop_position,
            mode,
            unix_timestamp_secs().unwrap(),
            nonce,
        )
    }

    fn route(rule_id: i64, protocol: &str, target: String) -> TunnelRouteConfig {
        TunnelRouteConfig {
            rule_id,
            protocol: protocol.into(),
            targets: vec![target],
            target_weights: vec![1],
            load_balance_strategy: LoadBalanceStrategy::First,
        }
    }

    fn listener_state(config: TunnelListenerConfig) -> TunnelListenerState {
        let runtime = TunnelRuntime::new();
        TunnelListenerState::new(
            config,
            &HashMap::new(),
            None,
            Arc::new(ReplayCache::default()),
            Arc::new(Semaphore::new(64)),
            runtime,
        )
    }

    #[test]
    fn hot_updates_keep_one_global_unauthenticated_cap() {
        let mut config = TunnelListenerConfig {
            tunnel_id: 1,
            port: 1000,
            hop_position: 1,
            auth_token: "key".into(),
            link_scope: "1:0:1:2".into(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 2,
            clients: vec![],
        };
        let state = listener_state(config.clone());
        let before = state.snapshot().unauthenticated.clone();
        let _permit = before.clone().try_acquire_owned().unwrap();

        config.max_unauthenticated = 128;
        state.update(
            config,
            &HashMap::new(),
            Arc::new(ReplayCache::default()),
            false,
        );
        let after = state.snapshot().unauthenticated.clone();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.available_permits(), 1);
    }

    #[test]
    fn hot_update_forgets_old_credential_group_after_old_context_drops() {
        let runtime = TunnelRuntime::new();
        let old = TunnelListenerConfig {
            tunnel_id: 9,
            port: 1000,
            hop_position: 1,
            auth_token: "a".repeat(64),
            link_scope: "9:0:10:20".into(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let state = TunnelListenerState::new(
            old,
            &HashMap::new(),
            None,
            Arc::new(ReplayCache::default()),
            Arc::new(Semaphore::new(64)),
            runtime.clone(),
        );
        let old_context = state.snapshot();
        let mut new = old_context.config.clone();
        new.auth_token = "b".repeat(64);
        new.link_scope = "9:0:10:30".into();
        state.update(
            new,
            &HashMap::new(),
            Arc::new(ReplayCache::default()),
            false,
        );

        assert!(runtime.uses_credential_group(20));
        assert!(runtime.uses_credential_group(30));
        drop(old_context);
        assert!(!runtime.uses_credential_group(20));
        assert!(runtime.uses_credential_group(30));
    }

    #[tokio::test]
    async fn hot_update_revokes_only_removed_rule_generation() {
        let mut config = TunnelListenerConfig {
            tunnel_id: 9,
            port: 1000,
            hop_position: 1,
            auth_token: "a".repeat(64),
            link_scope: "9:0:10:20".into(),
            next: None,
            routes: vec![
                route(101, "tcp", "127.0.0.1:1".into()),
                route(102, "tcp", "127.0.0.1:2".into()),
            ],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let state = listener_state(config.clone());
        let before = state.snapshot();
        let removed = before.rule_generations.get(&101).unwrap().clone();
        let retained = before.rule_generations.get(&102).unwrap().clone();
        let mut removed_cancel = removed.cancel.subscribe();
        let mut retained_cancel = retained.cancel.subscribe();

        config.routes.remove(0);
        state.update(
            config,
            &HashMap::new(),
            Arc::new(ReplayCache::default()),
            false,
        );
        let after = state.snapshot();

        tokio::time::timeout(Duration::from_secs(1), removed_cancel.changed())
            .await
            .expect("a removed rule must revoke its old shared-port connections")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), retained_cancel.changed())
                .await
                .is_err(),
            "removing one route must not revoke another rule on the shared port"
        );
        assert!(Arc::ptr_eq(
            &retained,
            after.rule_generations.get(&102).unwrap()
        ));
    }

    #[tokio::test]
    async fn hot_rotation_cancels_old_shared_revision_only() {
        let runtime = TunnelRuntime::new();
        let old_revisions = HashMap::from([(10, 1), (20, 1)]);
        let config = TunnelListenerConfig {
            tunnel_id: 9,
            port: 1000,
            hop_position: 1,
            auth_token: "a".repeat(64),
            link_scope: "9:0:10:20".into(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let state = TunnelListenerState::new(
            config,
            &old_revisions,
            None,
            Arc::new(ReplayCache::default()),
            Arc::new(Semaphore::new(64)),
            runtime.clone(),
        );
        let old_context = state.snapshot();
        let mut old_connection = runtime.connection(old_context.credential_generation.clone());

        let mut current_config = old_context.config.clone();
        current_config.auth_token = "b".repeat(64);
        let current_revisions = HashMap::from([(10, 1), (20, 2)]);
        state.update(
            current_config,
            &current_revisions,
            Arc::new(ReplayCache::default()),
            true,
        );
        let current_context = state.snapshot();
        let mut current_connection =
            runtime.connection(current_context.credential_generation.clone());

        tokio::time::timeout(Duration::from_secs(1), old_connection.cancelled())
            .await
            .expect("the old shared-listener credential must be revoked");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), current_connection.cancelled())
                .await
                .is_err(),
            "the replacement shared-listener credential must remain active"
        );
    }

    #[tokio::test]
    async fn connection_subscribed_after_revocation_is_cancelled_immediately() {
        let runtime = TunnelRuntime::new();
        let config = TunnelListenerConfig {
            tunnel_id: 10,
            port: 1000,
            hop_position: 1,
            auth_token: "a".repeat(64),
            link_scope: "10:0:10:20".into(),
            next: None,
            routes: vec![],
            handshake_timeout_ms: 3_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let credential = runtime.credential_generation(&config, &HashMap::from([(10, 1), (20, 1)]));

        credential.cancel();
        let mut credential_late = runtime.connection(credential.clone());
        tokio::time::timeout(Duration::from_millis(25), credential_late.cancelled())
            .await
            .expect("a subscription created after credential revocation must not miss it");

        let fresh = runtime.credential_generation(&config, &HashMap::new());
        runtime.cancel_all();
        let mut tunnel_late = runtime.connection(fresh);
        tokio::time::timeout(Duration::from_millis(25), tunnel_late.cancelled())
            .await
            .expect("a subscription created after tunnel termination must not miss it");
    }

    async fn tagged_echo(tag: u8) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut payload = [0u8; 4];
                // Active health probes intentionally connect and close without
                // application bytes. Ignore those and wait for the real test
                // connection instead of letting the probe consume the fixture.
                if stream.read_exact(&mut payload).await.is_err() {
                    continue;
                }
                stream.write_all(&[tag]).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                return;
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn header_hmac_and_replay_are_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TunnelClientConfig {
            tunnel_id: 7,
            rule_id: 9,
            hop_position: 0,
            address: address.to_string(),
            auth_token: "a".repeat(64),
            link_scope: "test:0".into(),
        };
        let cache = ReplayCache::default();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_header(&mut stream, &"a".repeat(64), Duration::from_secs(1), &cache).await
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        write_header(&mut stream, &client, TunnelMode::Tcp)
            .await
            .unwrap();
        let header = server.await.unwrap().unwrap();
        assert_eq!(header.tunnel_id, 7);
        assert_eq!(header.rule_id, 9);
        assert_eq!(header.mode, TunnelMode::Tcp);
        assert_ne!(header.nonce, [0u8; NONCE_LEN]);
    }

    #[tokio::test]
    async fn wrong_hmac_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_header(
                &mut stream,
                &"correct".repeat(16),
                Duration::from_secs(1),
                &ReplayCache::default(),
            )
            .await
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let client = TunnelClientConfig {
            tunnel_id: 7,
            rule_id: 9,
            hop_position: 0,
            address: address.to_string(),
            auth_token: "wrong".repeat(20),
            link_scope: "test:0".into(),
        };
        write_header(&mut stream, &client, TunnelMode::Tcp)
            .await
            .unwrap();
        assert_eq!(
            server.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected_across_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = "replay-key".repeat(8);
        let bytes = fixed_header(&token, 1, 2, 0, TunnelMode::Tcp, [9u8; NONCE_LEN]);
        let server_token = token.clone();
        let server = tokio::spawn(async move {
            let cache = ReplayCache::default();
            let (mut first, _) = listener.accept().await.unwrap();
            read_header(&mut first, &server_token, Duration::from_secs(1), &cache)
                .await
                .unwrap();
            let (mut replay, _) = listener.accept().await.unwrap();
            read_header(&mut replay, &server_token, Duration::from_secs(1), &cache).await
        });
        for _ in 0..2 {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
        assert_eq!(
            server.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn stale_authenticated_header_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = "stale-key".repeat(8);
        let timestamp = unix_timestamp_secs().unwrap() - HEADER_MAX_CLOCK_SKEW.as_secs() - 1;
        let bytes = fixed_header_at(
            &token,
            1,
            2,
            0,
            TunnelMode::Tcp,
            timestamp,
            [8u8; NONCE_LEN],
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_header(
                &mut stream,
                &token,
                Duration::from_secs(1),
                &ReplayCache::default(),
            )
            .await
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        assert_eq!(
            server.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn replay_history_is_not_evicted_by_connection_volume() {
        let cache = ReplayCache::default();
        let first = 1u128.to_be_bytes();
        assert!(cache.insert(first).await);
        for value in 2u128..20_000 {
            // A Bloom false positive deliberately fails closed; it must never
            // clear or evict the first nonce while adding later traffic.
            let _ = cache.insert(value.to_be_bytes()).await;
        }
        assert!(
            !cache.insert(first).await,
            "a still-valid nonce must survive connection-volume pressure"
        );
    }

    #[tokio::test]
    async fn two_tcp_rules_share_one_listener_without_target_crosstalk() {
        let (target_a, task_a) = tagged_echo(b'A').await;
        let (target_b, task_b) = tagged_echo(b'B').await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = "shared-key".repeat(8);
        let config = TunnelListenerConfig {
            tunnel_id: 77,
            port: address.port(),
            hop_position: 1,
            auth_token: token.clone(),
            link_scope: "77:0".into(),
            next: None,
            routes: vec![route(101, "tcp", target_a), route(102, "tcp", target_b)],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let server = tokio::spawn(serve_listener(listener, listener_state(config)));

        for (rule_id, expected) in [(101, b'A'), (102, b'B')] {
            let mut client = TcpStream::connect(address).await.unwrap();
            write_header(
                &mut client,
                &TunnelClientConfig {
                    tunnel_id: 77,
                    rule_id,
                    hop_position: 0,
                    address: address.to_string(),
                    auth_token: token.clone(),
                    link_scope: "77:0".into(),
                },
                TunnelMode::Tcp,
            )
            .await
            .unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0u8; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], expected);
            assert_eq!(&reply[1..], b"ping");
        }

        task_a.await.unwrap();
        task_b.await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn shared_listener_keeps_round_robin_state_across_connections() {
        let (target_a, task_a) = tagged_echo(b'A').await;
        let (target_b, task_b) = tagged_echo(b'B').await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = "round-robin-key".repeat(6);
        let config = TunnelListenerConfig {
            tunnel_id: 78,
            port: address.port(),
            hop_position: 1,
            auth_token: token.clone(),
            link_scope: "78:0".into(),
            next: None,
            routes: vec![TunnelRouteConfig {
                rule_id: 103,
                protocol: "tcp".into(),
                targets: vec![target_a, target_b],
                target_weights: vec![1, 1],
                load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            }],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let server = tokio::spawn(serve_listener(listener, listener_state(config)));

        for expected in [b'A', b'B'] {
            let mut client = TcpStream::connect(address).await.unwrap();
            write_header(
                &mut client,
                &TunnelClientConfig {
                    tunnel_id: 78,
                    rule_id: 103,
                    hop_position: 0,
                    address: address.to_string(),
                    auth_token: token.clone(),
                    link_scope: "78:0".into(),
                },
                TunnelMode::Tcp,
            )
            .await
            .unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, [expected, b'p', b'i', b'n', b'g']);
        }

        task_a.await.unwrap();
        task_b.await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn shared_listener_hot_updates_routes_without_rebinding_socket() {
        let (target_a, task_a) = tagged_echo(b'A').await;
        let (target_b, task_b) = tagged_echo(b'B').await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = "hot-route-key".repeat(6);
        let mut config = TunnelListenerConfig {
            tunnel_id: 79,
            port: address.port(),
            hop_position: 1,
            auth_token: token.clone(),
            link_scope: "79:0".into(),
            next: None,
            routes: vec![route(104, "tcp", "127.0.0.1:9".into())],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let state = listener_state(config.clone());
        let server = tokio::spawn(serve_listener(listener, state.clone()));

        config.routes = vec![route(104, "tcp", target_a), route(105, "tcp", target_b)];
        state.update(
            config,
            &HashMap::new(),
            Arc::new(ReplayCache::default()),
            false,
        );

        for (rule_id, expected) in [(104, b'A'), (105, b'B')] {
            let mut client = TcpStream::connect(address).await.unwrap();
            write_header(
                &mut client,
                &TunnelClientConfig {
                    tunnel_id: 79,
                    rule_id,
                    hop_position: 0,
                    address: address.to_string(),
                    auth_token: token.clone(),
                    link_scope: "79:0".into(),
                },
                TunnelMode::Tcp,
            )
            .await
            .unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0u8; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [expected, b'p', b'i', b'n', b'g']);
        }

        task_a.await.unwrap();
        task_b.await.unwrap();
        assert!(
            !server.is_finished(),
            "route hot update must keep the accept loop alive"
        );
        server.abort();
    }

    #[tokio::test]
    async fn final_hop_active_probes_seed_least_latency_selector() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_address = closed.local_addr().unwrap().to_string();
        drop(closed);
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = TunnelListenerConfig {
            tunnel_id: 80,
            port: 1,
            hop_position: 1,
            auth_token: "probe-key".repeat(8),
            link_scope: "80:0".into(),
            next: None,
            routes: vec![TunnelRouteConfig {
                rule_id: 106,
                protocol: "tcp".into(),
                targets: vec![closed_address, live.local_addr().unwrap().to_string()],
                target_weights: vec![1, 1],
                load_balance_strategy: LoadBalanceStrategy::LeastLatency,
            }],
            handshake_timeout_ms: 1_000,
            max_unauthenticated: 16,
            clients: vec![],
        };
        let state = listener_state(config);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let context = state.snapshot();
                if context.selectors[&106].order().first() == Some(&1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("active probes must rank the reachable target before live traffic");
    }

    #[tokio::test]
    async fn authenticated_probe_traverses_three_hops_and_final_target() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap().to_string();
        let target_task = tokio::spawn(async move {
            let (_stream, _) = target.accept().await.unwrap();
        });

        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_address = exit_listener.local_addr().unwrap();
        let exit_token = "exit-key".repeat(8);
        let exit_task = tokio::spawn(serve_listener(
            exit_listener,
            listener_state(TunnelListenerConfig {
                tunnel_id: 88,
                port: exit_address.port(),
                hop_position: 2,
                auth_token: exit_token.clone(),
                link_scope: "88:1".into(),
                next: None,
                routes: vec![route(201, "tcp", target_address)],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }),
        ));

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let relay_token = "relay-key".repeat(8);
        let relay_task = tokio::spawn(serve_listener(
            relay_listener,
            listener_state(TunnelListenerConfig {
                tunnel_id: 88,
                port: relay_address.port(),
                hop_position: 1,
                auth_token: relay_token.clone(),
                link_scope: "88:0".into(),
                next: Some(TunnelNextConfig {
                    hop_position: 1,
                    address: exit_address.to_string(),
                    auth_token: exit_token,
                    link_scope: "88:1".into(),
                }),
                routes: vec![route(201, "tcp", String::new())],
                handshake_timeout_ms: 1_000,
                max_unauthenticated: 16,
                clients: vec![],
            }),
        ));

        let mut client = TcpStream::connect(relay_address).await.unwrap();
        write_header(
            &mut client,
            &TunnelClientConfig {
                tunnel_id: 88,
                rule_id: 201,
                hop_position: 0,
                address: relay_address.to_string(),
                auth_token: relay_token,
                link_scope: "88:0".into(),
            },
            TunnelMode::Probe,
        )
        .await
        .unwrap();
        let mut result = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, [1]);

        target_task.await.unwrap();
        relay_task.abort();
        exit_task.abort();
    }
}
