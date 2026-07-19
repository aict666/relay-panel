//! Authenticated multiplexed UDP-over-TCP for the UDP component of udp/tcp_udp
//! multi-hop chains.
//!
//! One warm TCP connection carries many UDP client sessions. Frames preserve
//! datagram boundaries (`session_id + length + payload`); relay hops copy the
//! authenticated byte stream without decoding it, while the exit maps each
//! session id to a native UDP socket. This gives the entry a zero additional
//! application round trip for a new session once the tunnel is warm.

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, Semaphore};

use super::limiter::RateLimit;
use super::selector::{TargetLease, TargetSelector};
use crate::reporter::{ConnectionTracker, TrafficCounter, UDP_SESSION_TIMEOUT};

const MAGIC: &[u8; 8] = b"RPUOT002";
const TOKEN_LEN: usize = 64;
const NONCE_LEN: usize = 32;
const AUTH_TAG_LEN: usize = 32;
const FRAME_HEADER_LEN: usize = 10;
const CHANNEL_DEPTH: usize = 2048;
const MAX_UOT_TUNNELS_PER_LISTENER: usize = 256;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct Frame {
    session_id: u64,
    payload: Vec<u8>,
}

struct EntrySession {
    id: u64,
    last_ms: Arc<AtomicU64>,
}

struct ExitSession {
    socket: Arc<UdpSocket>,
    last_ms: Arc<AtomicU64>,
    _target_lease: Option<TargetLease>,
}

struct ClientConfig {
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    token: String,
    zero_rtt: bool,
    source_ipv4: Option<Ipv4Addr>,
    reply_tx: mpsc::Sender<Frame>,
    shutdown: Arc<ShutdownState>,
}

struct ShutdownState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl ShutdownState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct ShutdownGuard(Arc<ShutdownState>);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_ingress(
    inbound: Arc<UdpSocket>,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    token: String,
    zero_rtt: bool,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    rule_id: i64,
    source_ipv4: Option<Ipv4Addr>,
    count_traffic: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let shutdown = ShutdownState::new();
    let _shutdown_guard = ShutdownGuard(shutdown.clone());
    let (out_tx, out_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (reply_tx, mut reply_rx) = mpsc::channel(CHANNEL_DEPTH);
    tokio::spawn(run_client(
        ClientConfig {
            targets,
            selector,
            token,
            zero_rtt,
            source_ipv4,
            reply_tx,
            shutdown: shutdown.clone(),
        },
        out_rx,
    ));

    let sessions: Arc<DashMap<SocketAddr, EntrySession>> = Arc::new(DashMap::new());
    let reverse: Arc<DashMap<u64, SocketAddr>> = Arc::new(DashMap::new());
    let next_session = Arc::new(AtomicU64::new(1));

    // Do not let the detached reply task keep the UDP listen port occupied
    // after the ingress listener is aborted for a hot config update.
    let reply_socket = Arc::downgrade(&inbound);
    let reply_sessions = sessions.clone();
    let reply_reverse = reverse.clone();
    let reply_counter = counter.clone();
    let reply_connections = connections.clone();
    let reply_limit = rate_limit.clone();
    let reply_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = reply_shutdown.cancelled() => break,
                frame = reply_rx.recv() => frame,
            };
            let Some(frame) = frame else { break };
            let Some(client) = reply_reverse.get(&frame.session_id).map(|v| *v) else {
                continue;
            };
            reply_limit
                .acquire_download(frame.payload.len() as u64)
                .await;
            let Some(reply_socket) = reply_socket.upgrade() else {
                break;
            };
            if reply_socket.send_to(&frame.payload, client).await.is_ok() {
                if count_traffic {
                    reply_counter
                        .add(rule_id, 0, frame.payload.len() as u64)
                        .await;
                }
                reply_connections.udp_touch(client, rule_id).await;
                if let Some(s) = reply_sessions.get(&client) {
                    s.last_ms.store(now_millis(), Ordering::Relaxed);
                }
            }
        }
    });

    let cleanup_sessions = sessions.clone();
    let cleanup_reverse = reverse.clone();
    let cleanup_connections = connections.clone();
    let cleanup_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = cleanup_shutdown.cancelled() => {
                    let clients: Vec<SocketAddr> = cleanup_sessions.iter().map(|s| *s.key()).collect();
                    for client in clients {
                        cleanup_connections.udp_close(client, rule_id).await;
                    }
                    cleanup_sessions.clear();
                    cleanup_reverse.clear();
                    break;
                }
                _ = interval.tick() => {}
            }
            let cutoff = now_millis().saturating_sub(UDP_SESSION_TIMEOUT.as_millis() as u64);
            let expired: Vec<(SocketAddr, u64)> = cleanup_sessions
                .iter()
                .filter(|s| s.last_ms.load(Ordering::Relaxed) < cutoff)
                .map(|s| (*s.key(), s.id))
                .collect();
            for (client, id) in expired {
                cleanup_sessions.remove(&client);
                cleanup_reverse.remove(&id);
                cleanup_connections.udp_close(client, rule_id).await;
            }
        }
    });

    let mut buf = vec![0u8; u16::MAX as usize];
    loop {
        let (n, client) = inbound.recv_from(&mut buf).await?;
        connections.udp_touch(client, rule_id).await;
        let session_id = if let Some(s) = sessions.get(&client) {
            s.last_ms.store(now_millis(), Ordering::Relaxed);
            s.id
        } else {
            let id = next_session.fetch_add(1, Ordering::Relaxed).max(1);
            let last_ms = Arc::new(AtomicU64::new(now_millis()));
            sessions.insert(
                client,
                EntrySession {
                    id,
                    last_ms: last_ms.clone(),
                },
            );
            reverse.insert(id, client);
            id
        };
        rate_limit.acquire_upload(n as u64).await;
        if out_tx
            .send(Frame {
                session_id,
                payload: buf[..n].to_vec(),
            })
            .await
            .is_err()
        {
            return Err("UOT client task stopped".into());
        }
        if count_traffic {
            counter.add(rule_id, n as u64, 0).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_listener(
    listener: TcpListener,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    inbound_token: String,
    downstream_token: Option<String>,
    relay: bool,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bound both authenticated tunnels and unauthenticated sockets waiting on
    // the five-second challenge timeout. A public tunnel port must not be able
    // to consume every process fd through a slow-auth connection flood.
    let tunnel_slots = Arc::new(Semaphore::new(MAX_UOT_TUNNELS_PER_LISTENER));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(error) if is_transient_accept_error(&error) => {
                tracing::warn!("UOT transient accept error: {}; retrying", error);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let Ok(tunnel_slot) = tunnel_slots.clone().try_acquire_owned() else {
            tracing::debug!(
                "UOT listener at tunnel cap {}; rejecting {}",
                MAX_UOT_TUNNELS_PER_LISTENER,
                peer
            );
            drop(stream);
            continue;
        };
        let targets = targets.clone();
        let selector = selector.clone();
        let inbound_token = inbound_token.clone();
        let downstream_token = downstream_token.clone();
        tokio::spawn(async move {
            let _tunnel_slot = tunnel_slot;
            let result = if relay {
                handle_relay(
                    stream,
                    &inbound_token,
                    &targets,
                    selector,
                    downstream_token.as_deref().unwrap_or_default(),
                    source_ipv4,
                )
                .await
            } else {
                handle_egress(stream, &inbound_token, &targets, selector, source_ipv4).await
            };
            if let Err(error) = result {
                tracing::debug!("UOT connection from {} ended: {}", peer, error);
            }
        });
    }
}

fn is_transient_accept_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ResourceBusy
    ) || error
        .raw_os_error()
        .is_some_and(|code| matches!(code, 12 | 23 | 24 | 105))
}

async fn handle_relay(
    mut inbound: TcpStream,
    inbound_token: &str,
    targets: &[String],
    selector: Arc<TargetSelector>,
    downstream_token: &str,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    authenticate(&mut inbound, inbound_token).await?;
    let (mut outbound, _lease) = connect_target(targets, selector, source_ipv4).await?;
    send_handshake(&mut outbound, downstream_token).await?;
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn handle_egress(
    mut stream: TcpStream,
    inbound_token: &str,
    targets: &[String],
    selector: Arc<TargetSelector>,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    authenticate(&mut stream, inbound_token).await?;
    let session_shutdown = ShutdownState::new();
    let _session_shutdown_guard = ShutdownGuard(session_shutdown.clone());
    let (mut reader, mut writer) = stream.into_split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<Frame>(CHANNEL_DEPTH);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = reply_rx.recv().await {
            write_frame(&mut writer, &frame).await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let sessions: Arc<DashMap<u64, ExitSession>> = Arc::new(DashMap::new());

    while let Some(frame) = read_frame(&mut reader).await? {
        let socket = if let Some(s) = sessions.get(&frame.session_id) {
            s.last_ms.store(now_millis(), Ordering::Relaxed);
            s.socket.clone()
        } else {
            let (idx, target) = resolve_udp_target(targets, &selector).await?;
            let socket = Arc::new(super::outbound::udp_outbound_socket(source_ipv4).await?);
            socket.connect(target).await?;
            let last_ms = Arc::new(AtomicU64::new(now_millis()));
            sessions.insert(
                frame.session_id,
                ExitSession {
                    socket: socket.clone(),
                    last_ms: last_ms.clone(),
                    _target_lease: selector.acquire(idx),
                },
            );
            let recv_socket = socket.clone();
            let recv_sessions = sessions.clone();
            let recv_tx = reply_tx.clone();
            let recv_shutdown = session_shutdown.clone();
            let sid = frame.session_id;
            tokio::spawn(async move {
                let mut buf = vec![0u8; u16::MAX as usize];
                loop {
                    let received = tokio::select! {
                        _ = recv_shutdown.cancelled() => break,
                        result = tokio::time::timeout(
                            Duration::from_secs(15),
                            recv_socket.recv(&mut buf),
                        ) => result,
                    };
                    match received {
                        Ok(Ok(n)) => {
                            last_ms.store(now_millis(), Ordering::Relaxed);
                            if recv_tx
                                .send(Frame {
                                    session_id: sid,
                                    payload: buf[..n].to_vec(),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            if now_millis().saturating_sub(last_ms.load(Ordering::Relaxed))
                                >= UDP_SESSION_TIMEOUT.as_millis() as u64
                            {
                                break;
                            }
                        }
                    }
                }
                recv_sessions.remove(&sid);
            });
            socket
        };
        socket.send(&frame.payload).await?;
    }
    writer_task.abort();
    Ok(())
}

async fn run_client(config: ClientConfig, mut outbound_rx: mpsc::Receiver<Frame>) {
    let mut pending = if config.zero_rtt {
        None
    } else {
        outbound_rx.recv().await
    };
    loop {
        if config.shutdown.cancelled.load(Ordering::Acquire) {
            return;
        }
        let (mut stream, _lease) = match connect_target(
            &config.targets,
            config.selector.clone(),
            config.source_ipv4,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("UOT downstream unavailable: {}; retrying", error);
                // A warm tunnel keeps probing even before traffic arrives. A
                // non-prewarmed tunnel deliberately waits for its first frame.
                if pending.is_none() && !config.zero_rtt {
                    pending = outbound_rx.recv().await;
                    if pending.is_none() {
                        return;
                    }
                }
                tokio::select! {
                    _ = config.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                continue;
            }
        };
        if send_handshake(&mut stream, &config.token).await.is_err() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        let (mut reader, mut writer) = stream.into_split();
        if let Some(frame) = pending.take() {
            if write_frame(&mut writer, &frame).await.is_err() {
                pending = Some(frame);
                continue;
            }
        }
        // Keep frame reads in one dedicated task. `read_exact` is not
        // cancellation-safe: selecting it directly against outbound_rx can
        // consume half a reply frame, lose those bytes when an outbound packet
        // wins the select, and permanently desynchronize the UOT stream.
        let reply_tx = config.reply_tx.clone();
        let mut reader_task: tokio::task::JoinHandle<std::io::Result<()>> =
            tokio::spawn(async move {
                loop {
                    match read_frame(&mut reader).await? {
                        Some(frame) => {
                            if reply_tx.send(frame).await.is_err() {
                                return Ok(());
                            }
                        }
                        None => return Ok(()),
                    }
                }
            });
        loop {
            tokio::select! {
                _ = config.shutdown.cancelled() => {
                    reader_task.abort();
                    return;
                },
                frame = outbound_rx.recv() => {
                    let Some(frame) = frame else {
                        reader_task.abort();
                        return;
                    };
                    if write_frame(&mut writer, &frame).await.is_err() {
                        pending = Some(frame);
                        break;
                    }
                }
                result = &mut reader_task => {
                    if let Ok(Err(error)) = result {
                        tracing::debug!("UOT reply stream ended: {}", error);
                    }
                    break;
                }
            }
        }
        reader_task.abort();
    }
}

async fn connect_target(
    targets: &[String],
    selector: Arc<TargetSelector>,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(TcpStream, Option<TargetLease>), Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();
    for idx in selector.order() {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        let started = std::time::Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(5),
            super::outbound::tcp_connect(target, source_ipv4, 5),
        )
        .await
        {
            Ok(Ok(stream)) => {
                selector.report_timed(idx, true, Some(started.elapsed()));
                let lease = selector.acquire(idx);
                return Ok((stream, lease));
            }
            Ok(Err(error)) => errors.push(error.to_string()),
            Err(_) => errors.push(format!("{} timed out", target)),
        }
        selector.report(idx, false);
    }
    Err(format!("no reachable UOT target: {}", errors.join("; ")).into())
}

async fn resolve_udp_target(
    targets: &[String],
    selector: &Arc<TargetSelector>,
) -> Result<(usize, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    for idx in selector.order() {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        match super::outbound::resolve_cached(target).await {
            Ok(addrs) if !addrs.is_empty() => {
                selector.report(idx, true);
                return Ok((idx, addrs[0]));
            }
            _ => selector.report(idx, false),
        }
    }
    Err("no resolvable UDP target".into())
}

async fn send_handshake(stream: &mut TcpStream, token: &str) -> std::io::Result<()> {
    validate_token(token)?;
    let mut challenge = [0u8; MAGIC.len() + NONCE_LEN];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut challenge))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "UOT challenge timeout")
        })??;
    if !constant_time_eq(&challenge[..MAGIC.len()], MAGIC) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UOT challenge magic",
        ));
    }
    let nonce = &challenge[MAGIC.len()..];
    let client_tag = auth_tag(token, b"client", nonce)?;
    stream.write_all(&client_tag).await?;
    stream.flush().await?;

    // Verify that the peer also knows the token before allowing any tunneled
    // datagram. The token itself is never transmitted in either direction.
    let mut server_tag = [0u8; AUTH_TAG_LEN];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut server_tag))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "UOT server auth timeout")
        })??;
    verify_auth_tag(token, b"server", nonce, &server_tag)
}

async fn authenticate(stream: &mut TcpStream, expected: &str) -> std::io::Result<()> {
    validate_token(expected)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|error| std::io::Error::other(format!("UOT nonce generation failed: {error}")))?;
    stream.write_all(MAGIC).await?;
    stream.write_all(&nonce).await?;
    stream.flush().await?;

    let mut client_tag = [0u8; AUTH_TAG_LEN];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut client_tag))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UOT auth timeout"))??;
    verify_auth_tag(expected, b"client", &nonce, &client_tag)?;
    let server_tag = auth_tag(expected, b"server", &nonce)?;
    stream.write_all(&server_tag).await?;
    stream.flush().await
}

fn validate_token(token: &str) -> std::io::Result<()> {
    if token.len() == TOKEN_LEN {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid UOT token length",
        ))
    }
}

fn auth_tag(token: &str, role: &[u8], nonce: &[u8]) -> std::io::Result<[u8; AUTH_TAG_LEN]> {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid UOT HMAC key")
    })?;
    mac.update(b"relay-panel-uot-auth-v2\0");
    mac.update(role);
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_auth_tag(token: &str, role: &[u8], nonce: &[u8], received: &[u8]) -> std::io::Result<()> {
    let expected = auth_tag(token, role, nonce)?;
    if constant_time_eq(&expected, received) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "UOT authentication failed",
        ))
    }
}

fn constant_time_eq(expected: &[u8], received: &[u8]) -> bool {
    if expected.len() != received.len() {
        return false;
    }
    expected
        .iter()
        .zip(received)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> std::io::Result<()> {
    let len = u16::try_from(frame.payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "UOT datagram too large")
    })?;
    writer.write_all(&frame.session_id.to_be_bytes()).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Frame>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
    let len = u16::from_be_bytes(header[8..].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Frame {
        session_id,
        payload,
    }))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::LoadBalanceStrategy;

    #[tokio::test]
    async fn frame_roundtrip_preserves_datagram_boundary() {
        let (mut a, mut b) = tokio::io::duplex(128);
        let want = Frame {
            session_id: 42,
            payload: b"hello-uot".to_vec(),
        };
        let writer = tokio::spawn(async move { write_frame(&mut a, &want).await });
        let got = read_frame(&mut b).await.unwrap().unwrap();
        writer.await.unwrap().unwrap();
        assert_eq!(got.session_id, 42);
        assert_eq!(got.payload, b"hello-uot");
    }

    #[tokio::test]
    async fn challenge_response_rejects_wrong_token_without_sending_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = "a".repeat(TOKEN_LEN);
        let wrong = "b".repeat(TOKEN_LEN);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            authenticate(&mut stream, &expected).await
        });
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            send_handshake(&mut stream, &wrong).await
        });

        let (server_result, client_result) = tokio::time::timeout(Duration::from_secs(2), async {
            (server.await.unwrap(), client.await.unwrap())
        })
        .await
        .expect("mismatched UOT authentication deadlocked");
        assert!(server_result.is_err(), "server must reject the wrong key");
        assert!(client_result.is_err(), "client must require server proof");

        // A wire response is a 32-byte HMAC, never the 64-byte static token.
        let nonce = [7u8; NONCE_LEN];
        let tag = auth_tag(&"a".repeat(TOKEN_LEN), b"client", &nonce).unwrap();
        assert_eq!(tag.len(), AUTH_TAG_LEN);
        assert_ne!(tag.as_slice(), "a".repeat(TOKEN_LEN).as_bytes());
    }

    #[test]
    fn weighted_selector_is_usable_by_uot() {
        let selector = TargetSelector::with_weights(LoadBalanceStrategy::Weighted, 2, vec![3, 1]);
        let picked: Vec<usize> = (0..4).map(|_| selector.order()[0]).collect();
        assert_eq!(picked, vec![0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn three_hop_uot_roundtrip() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            for _ in 0..3 {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        let exit_token = "b".repeat(TOKEN_LEN);
        let exit_task = tokio::spawn(serve_listener(
            exit_listener,
            vec![echo_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            exit_token.clone(),
            None,
            false,
            None,
        ));

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_token = "a".repeat(TOKEN_LEN);
        let relay_task = tokio::spawn(serve_listener(
            relay_listener,
            vec![exit_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            relay_token.clone(),
            Some(exit_token),
            true,
            None,
        ));

        let ingress_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ingress_addr = ingress_socket.local_addr().unwrap();
        let ingress_task = tokio::spawn(serve_ingress(
            ingress_socket,
            vec![relay_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            relay_token,
            true,
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            1,
            None,
            true,
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut reply = [0u8; 2048];
        for payload in [
            b"one".as_slice(),
            b"two-two".as_slice(),
            b"three".as_slice(),
        ] {
            client.send_to(payload, ingress_addr).await.unwrap();
            let (n, peer) =
                tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut reply))
                    .await
                    .expect("UOT response timeout")
                    .unwrap();
            assert_eq!(peer, ingress_addr);
            assert_eq!(&reply[..n], payload);
        }

        echo_task.await.unwrap();
        ingress_task.abort();
        relay_task.abort();
        exit_task.abort();
    }

    #[tokio::test]
    async fn staged_dual_listener_accepts_native_udp_and_uot_on_same_port() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            for _ in 0..2 {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        // TCP and UDP use independent socket namespaces, so a staged node can
        // keep its legacy UDP listener while preparing UOT on the same numeric
        // port for upgraded upstream nodes.
        let legacy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let shared_addr = legacy_socket.local_addr().unwrap();
        let uot_listener = TcpListener::bind(shared_addr).await.unwrap();
        assert_eq!(uot_listener.local_addr().unwrap(), shared_addr);

        let legacy_task = tokio::spawn(crate::forwarder::udp::serve_udp_listener(
            legacy_socket,
            vec![echo_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            2,
            None,
            false,
        ));

        let token = "d".repeat(TOKEN_LEN);
        let exit_task = tokio::spawn(serve_listener(
            uot_listener,
            vec![echo_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            token.clone(),
            None,
            false,
            None,
        ));

        let native_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        native_client.send_to(b"legacy", shared_addr).await.unwrap();
        let mut native_reply = [0u8; 2048];
        let (n, peer) = tokio::time::timeout(
            Duration::from_secs(3),
            native_client.recv_from(&mut native_reply),
        )
        .await
        .expect("native UDP response timeout")
        .unwrap();
        assert_eq!(peer, shared_addr);
        assert_eq!(&native_reply[..n], b"legacy");

        let ingress_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ingress_addr = ingress_socket.local_addr().unwrap();
        let ingress_task = tokio::spawn(serve_ingress(
            ingress_socket,
            vec![shared_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            token,
            true,
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            1,
            None,
            true,
        ));

        let uot_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        uot_client.send_to(b"uot", ingress_addr).await.unwrap();
        let mut uot_reply = [0u8; 2048];
        let (n, peer) =
            tokio::time::timeout(Duration::from_secs(3), uot_client.recv_from(&mut uot_reply))
                .await
                .expect("UOT response timeout")
                .unwrap();
        assert_eq!(peer, ingress_addr);
        assert_eq!(&uot_reply[..n], b"uot");

        echo_task.await.unwrap();
        ingress_task.abort();
        legacy_task.abort();
        exit_task.abort();
    }

    /// Regression for a cancellation-corruption bug in run_client. The server
    /// deliberately sends half a reply header, then an outbound datagram wins
    /// the client's select before the remainder arrives. The partial read must
    /// stay alive and finish the same frame instead of dropping consumed bytes.
    #[tokio::test]
    async fn simultaneous_upload_does_not_cancel_partial_reply_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let token = "e".repeat(TOKEN_LEN);
        let server_token = token.clone();
        let (partial_tx, partial_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            authenticate(&mut stream, &server_token).await.unwrap();

            let reply = Frame {
                session_id: 42,
                payload: b"reply".to_vec(),
            };
            let mut encoded = Vec::with_capacity(FRAME_HEADER_LEN + reply.payload.len());
            encoded.extend_from_slice(&reply.session_id.to_be_bytes());
            encoded.extend_from_slice(&(reply.payload.len() as u16).to_be_bytes());
            encoded.extend_from_slice(&reply.payload);
            stream.write_all(&encoded[..5]).await.unwrap();
            stream.flush().await.unwrap();
            let _ = partial_tx.send(());

            let upload = read_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(upload.session_id, 7);
            assert_eq!(upload.payload, b"upload");
            stream.write_all(&encoded[5..]).await.unwrap();
            stream.flush().await.unwrap();
        });

        let shutdown = ShutdownState::new();
        let (out_tx, out_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (reply_tx, mut reply_rx) = mpsc::channel(CHANNEL_DEPTH);
        let client = tokio::spawn(run_client(
            ClientConfig {
                targets: vec![target],
                selector: Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
                token,
                zero_rtt: true,
                source_ipv4: None,
                reply_tx,
                shutdown: shutdown.clone(),
            },
            out_rx,
        ));

        partial_rx.await.unwrap();
        // Give the socket reader a chance to consume the deliberately partial
        // header before making the upload branch ready.
        tokio::time::sleep(Duration::from_millis(25)).await;
        out_tx
            .send(Frame {
                session_id: 7,
                payload: b"upload".to_vec(),
            })
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("partial reply frame became desynchronized")
            .expect("UOT client stopped before delivering reply");
        assert_eq!(reply.session_id, 42);
        assert_eq!(reply.payload, b"reply");
        server.await.unwrap();

        shutdown.cancelled.store(true, Ordering::Release);
        shutdown.notify.notify_waiters();
        client.await.unwrap();
    }
}
