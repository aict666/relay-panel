use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::gate::RuleGate;
use super::limiter::RateLimit;
use super::selector::TargetSelector;
use crate::reporter::{ConnectionTracker, TrafficCounter};
use relay_shared::protocol::TunnelClientConfig;

/// v1.2.0: how often the "rule is at its connection cap" warning may be logged
/// per listener. A rule sitting at its cap rejects on EVERY accept, so an
/// unthrottled warn! here would itself become the outage (disk + CPU) that the
/// cap exists to prevent.
const CAP_WARN_INTERVAL: Duration = Duration::from_secs(60);
const TLS_FIRST_BYTE_TIMEOUT: Duration = Duration::from_millis(100);
const TLS_HEADER_TIMEOUT: Duration = Duration::from_millis(200);
const TLS_MAX_PLAINTEXT_RECORD_LEN: u16 = 1 << 14;

enum TlsSniffResult {
    Allow(Vec<u8>),
    Block,
}

/// v1.0.4: serve an ALREADY-BOUND TcpListener. Binding happens in the manager
/// (synchronously, so errors surface immediately and per-family success is
/// known). This function only runs the accept loop.
///
/// v1.2.0: `gate` carries the rule's connection cap and its restart
/// cancellation. It is cloned from the rule's `RuleRuntime`, so the rule's IPv4
/// and IPv6 listeners share one connection budget and one cancel signal.
#[allow(clippy::too_many_arguments)]
pub async fn serve_tcp_listener(
    listener: TcpListener,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    rule_id: i64,
    source_ipv4: Option<Ipv4Addr>,
    gate: RuleGate,
    count_traffic: bool,
    tcp_fast_open: bool,
    block_tls: bool,
    tunnel: Option<TunnelClientConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    tracing::info!("TCP listening on {} (rule {})", listen_addr, rule_id);

    // v0.3.6: accept-loop resilience. A transient accept error (EMFILE,
    // ENOMEM, temporary resource exhaustion) used to `?`-propagate and kill the
    // whole listener task, leaving the port dead until node restart. Now we
    // classify the error: transient -> back off and retry; the listener stays
    // up. A non-transient error (e.g. the listener was closed) ends the task.
    let mut last_cap_warn: Option<std::time::Instant> = None;
    loop {
        match listener.accept().await {
            Ok((inbound, client_addr)) => {
                // v1.2.0: admit against the rule's connection cap BEFORE doing
                // any further work. `admit` is called here, in the sequential
                // accept loop, rather than inside the spawned task below — if the
                // count were incremented in the task, an inbound flood would let
                // an unbounded number of accepts through before the first
                // increment landed, which is exactly the case the cap is for.
                let Some(conn_guard) = gate.admit() else {
                    // At cap: close immediately. We accept-then-drop rather than
                    // stop accepting, because leaving connections in the kernel's
                    // backlog would stall the queue and make the client hang
                    // instead of failing fast and retrying elsewhere.
                    drop(inbound);
                    let now = std::time::Instant::now();
                    if last_cap_warn.is_none_or(|t| now.duration_since(t) >= CAP_WARN_INTERVAL) {
                        last_cap_warn = Some(now);
                        tracing::warn!(
                            "TCP rule {}: at connection cap ({} live / {} max), rejecting new \
                             connections (latest from {}); rate-limited to once per {}s",
                            rule_id,
                            gate.live(),
                            gate.max_connections.unwrap_or(0),
                            client_addr,
                            CAP_WARN_INTERVAL.as_secs()
                        );
                    }
                    continue;
                };
                // v1.0.8: disable Nagle on the accepted (client-facing) socket.
                // See the note in outbound::tcp_connect — a relay MUST set
                // TCP_NODELAY on both ends or small packets get buffered ~40ms
                // per hop, which compounds into heavy jitter on long chains.
                if let Err(e) = inbound.set_nodelay(true) {
                    tracing::debug!(
                        "TCP accept {}: set_nodelay(true) failed: {}",
                        client_addr,
                        e
                    );
                }
                // v1.2: enable TCP keepalive so a client that vanishes without a
                // FIN/RST (NAT rebind, mobile handoff, cable pull) is reaped by
                // the kernel instead of leaving the copy task blocked on read()
                // forever, holding two fds until the node exhausts them (EMFILE).
                super::outbound::apply_keepalive(&inbound, "TCP accept");
                let targets = targets.clone();
                let selector = selector.clone();
                let rate_limit = rate_limit.clone();
                let counter = counter.clone();
                let connections = connections.clone();
                let mut gate = gate.clone();
                let tunnel = tunnel.clone();

                tokio::spawn(async move {
                    // RAII guard: increments the active-TCP count on create,
                    // decrements on drop (end of task — normal close, error, or
                    // panic). Guarantees the count is correct even on abrupt close.
                    let _guard = connections.tcp_handle();
                    // v1.2.0: holds this connection's slot in the rule's cap;
                    // drops with the task however it ends, including when the
                    // select! below takes the cancellation branch.
                    let _conn_guard = conn_guard;
                    // v1.2.0: this task is DETACHED — aborting the accept loop
                    // does not stop it (verified: an established connection keeps
                    // forwarding after the listener task is aborted). So a rule
                    // restart cannot work by killing the listener; it fires this
                    // cancellation instead, and dropping the handle_tcp_connection
                    // future here closes both sockets.
                    tokio::select! {
                        _ = gate.cancelled() => {
                            tracing::debug!(
                                "TCP rule {}: dropping connection from {} (rule restarted)",
                                rule_id,
                                client_addr
                            );
                        }
                        r = handle_tcp_connection(
                            inbound,
                            client_addr,
                            targets,
                            selector,
                            rate_limit,
                            counter,
                            rule_id,
                            source_ipv4,
                            count_traffic,
                            tcp_fast_open,
                            block_tls,
                            connections,
                            tunnel,
                        ) => {
                            if let Err(e) = r {
                                tracing::debug!("TCP connection error: {}", e);
                            }
                        }
                    }
                });
            }
            Err(e) if is_transient_accept_error(&e) => {
                // Back off briefly to avoid a hot error loop spamming logs, then
                // continue accepting. 100ms is short enough that real clients
                // don't notice but long enough to shed an error storm.
                tracing::warn!(
                    "TCP listener on {} (rule {}): transient accept error: {}; retrying in 100ms",
                    listen_addr,
                    rule_id,
                    e
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                // Non-transient (e.g. listener closed, EBADF). End the task; the
                // manager's is_finished recovery will restart it on next config
                // if still desired.
                return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
            }
        }
    }
}

/// Classify whether an `accept` error is worth retrying. Transient OS-level
/// resource exhaustion (too many open files, out of memory) clears on its own;
/// retrying is the right call. A bad-fd or closed-listener error is permanent.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ResourceBusy
    ) || e.raw_os_error().is_some_and(|c| {
        // EMFILE (24) / ENFILE (23) / ENOBUFS (105) / ENOMEM (12): transient
        // resource exhaustion under load.
        matches!(c, 24 | 23 | 105 | 12)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    rule_id: i64,
    source_ipv4: Option<Ipv4Addr>,
    count_traffic: bool,
    tcp_fast_open: bool,
    block_tls: bool,
    connections: Arc<ConnectionTracker>,
    tunnel: Option<TunnelClientConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sniffed_prefix = if block_tls {
        match sniff_tls_client_hello(&mut inbound).await {
            TlsSniffResult::Allow(prefix) => prefix,
            TlsSniffResult::Block => {
                connections.record_blocked_tls(rule_id, client_addr);
                return Ok(());
            }
        }
    } else {
        Vec::new()
    };

    // TCP_FASTOPEN_CONNECT defers the SYN until the first write when a cookie
    // exists. That is ideal for client-first traffic, but blindly using it for
    // server-first protocols (SSH/SMTP banners) would deadlock: the relay waits
    // to read the target while the kernel waits for client data before sending
    // SYN. Only choose TFO when at least one client byte is already pending;
    // otherwise preserve the ordinary connect-before-read path.
    let target_order = selector.order();
    // A cookie hit returns before the SYN outcome is known, so that connection
    // cannot safely participate in this attempt's fallback loop. Preserve
    // deterministic multi-target failover by using TFO only when the selector
    // has exactly one candidate.
    let tcp_fast_open = fast_open_has_client_data(
        &inbound,
        tcp_fast_open && target_order.len() == 1,
        !sniffed_prefix.is_empty(),
    )
    .await;

    // v0.4.6: pick targets per the rule's load-balancing strategy. The selector
    // returns the ordered indices to attempt; we connect to the first reachable.
    //
    // v1.0.5: keep the REAL reason each target failed (DNS / timeout / no route /
    // source-bind) instead of collapsing everything into "no target available".
    // On a multi-NIC server a silent failure is impossible to diagnose, so we
    // accumulate per-target reasons and log them together when nothing connects.
    let mut outbound = None;
    let mut target_lease = None;
    let mut failures: Vec<String> = Vec::new();
    for idx in target_order {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        let started = std::time::Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(5),
            super::outbound::tcp_connect_with_fast_open(target, source_ipv4, 5, tcp_fast_open),
        )
        .await
        {
            Ok(Ok(stream)) => {
                selector.report_timed(idx, true, Some(started.elapsed()));
                target_lease = selector.acquire(idx);
                outbound = Some(stream);
                break;
            }
            Ok(Err(e)) => {
                // tcp_connect already classifies the cause (InvalidIp / Connect /
                // Bind). Preserve it verbatim so DNS vs. refused vs. source-bind
                // failures are distinguishable in the log.
                selector.report(idx, false);
                failures.push(format!("{} -> {}", target, e));
            }
            Err(_) => {
                // Outer timeout fired: the connect didn't finish within 5s.
                selector.report(idx, false);
                failures.push(format!("{} -> timed out after 5s", target));
            }
        }
    }

    let mut outbound = match outbound {
        Some(s) => s,
        None => {
            let detail = if failures.is_empty() {
                "no reachable target (all targets in circuit-break or empty)".to_string()
            } else {
                failures.join("; ")
            };
            tracing::warn!(
                "TCP rule {}: no target available for client {} — {}",
                rule_id,
                client_addr,
                detail
            );
            return Err(format!("no target available: {}", detail).into());
        }
    };
    // Keep the least-connections count until this forwarded connection ends.
    let _target_lease = target_lease;

    // One client-first authenticated routing header, then the original byte
    // stream continues unchanged. This happens before the Linux splice fast
    // path, so tunnel setup costs no per-byte userspace copy.
    if let Some(tunnel) = &tunnel {
        super::tunnel::write_header(&mut outbound, tunnel, super::tunnel::TunnelMode::Tcp).await?;
    }

    // Protocol sniffing consumes at most six user bytes. Replay them before
    // entering the regular forwarding loop, and account for them exactly once.
    // The remainder can still use Linux splice(2).
    let prefixed_upload = sniffed_prefix.len() as u64;
    if !sniffed_prefix.is_empty() {
        rate_limit.acquire_upload(prefixed_upload).await;
        outbound.write_all(&sniffed_prefix).await?;
    }

    // getpeername may transiently report ENOTCONN on a cookie-hit TFO socket
    // before the first payload triggers SYN. Logging must never turn that
    // harmless deferred state into a failed forwarded connection.
    match outbound.peer_addr() {
        Ok(peer) => tracing::debug!("TCP: {} -> {}", client_addr, peer),
        Err(error) => tracing::debug!(
            "TCP: {} -> deferred TFO peer (getpeername: {})",
            client_addr,
            error
        ),
    }

    // v1.0.8: ZERO-COPY fast path. An UNLIMITED rule on Linux is forwarded with
    // splice(2) — bytes move inside the kernel via a pipe and are never copied
    // into userspace, which slashes CPU on high-throughput links. A rate-limited
    // rule CANNOT use splice (the bytes must reach userspace to be throttled),
    // but that's fine: a capped rule isn't running at max throughput, so the
    // userspace copy's CPU cost is negligible. Byte counts still come back from
    // the splice return values, so billing is unaffected. Non-Linux always uses
    // the userspace copy below.
    #[cfg(target_os = "linux")]
    if matches!(rate_limit, RateLimit::Unlimited) {
        match super::splice::zero_copy_bidirectional(inbound, outbound).await {
            // (up = client→target, down = target→client) — same attribution as
            // the userspace path's counter.add(rule_id, up, down).
            Ok((up, down)) => {
                if count_traffic {
                    counter
                        .add(rule_id, up.saturating_add(prefixed_upload), down)
                        .await;
                }
            }
            Err(e) => {
                tracing::warn!("TCP splice forward failed (rule {}): {}", rule_id, e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    // Userspace bidirectional copy with traffic counting + per-rule rate
    // limiting (the rate-limited path, and the fallback on non-Linux). We own
    // both halves and pump both directions concurrently. When either side
    // returns (the remote closed the connection) we shut down the matching write
    // half so the other copy also sees EOF and returns.
    //
    // v0.4.6: each chunk is throttled through the shared RateLimit BEFORE being
    // written, so the rule's aggregate cap holds across all connections.
    let (mut ri, mut wi) = inbound.into_split();
    let (mut ro, mut wo) = outbound.into_split();

    let counter_up = counter.clone();
    let counter_down = counter.clone();
    let rl_up = rate_limit.clone();
    let rl_down = rate_limit;

    let upload = Box::pin(async move {
        let mut total = prefixed_upload;
        // v1.0.8: 32 KiB copy buffer (this userspace path is only used by
        // rate-limited rules, which are capped anyway; the unlimited fast path
        // uses splice above). Heap-allocated as part of this Box::pin'd future,
        // so it does not grow the task stack.
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = match ri.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            rl_up.acquire_upload(n as u64).await;
            if wo.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        if count_traffic {
            counter_up.add(rule_id, total, 0).await;
        }
        let _ = wo.shutdown().await;
    });
    let download = Box::pin(async move {
        let mut total = 0u64;
        // v1.0.8: 32 KiB copy buffer (see the upload side above).
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = match ro.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            rl_down.acquire_download(n as u64).await;
            if wi.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        if count_traffic {
            counter_down.add(rule_id, 0, total).await;
        }
        let _ = wi.shutdown().await;
    });

    let ((), ()) = tokio::join!(upload, download);

    tracing::debug!("TCP: connection closed for {}", client_addr);
    Ok(())
}

async fn fast_open_has_client_data(
    inbound: &TcpStream,
    requested: bool,
    buffered_client_data: bool,
) -> bool {
    if !requested {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        if buffered_client_data {
            return true;
        }
        let mut first_byte = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_millis(5), inbound.peek(&mut first_byte)).await,
            Ok(Ok(n)) if n > 0
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (inbound, buffered_client_data);
        false
    }
}

async fn sniff_tls_client_hello(inbound: &mut TcpStream) -> TlsSniffResult {
    let mut header = [0u8; 6];
    let first =
        match tokio::time::timeout(TLS_FIRST_BYTE_TIMEOUT, inbound.read(&mut header[..1])).await {
            Err(_) => return TlsSniffResult::Allow(Vec::new()),
            // EOF only closes the client's upload direction. The peer may
            // still be waiting for a server-first banner, so preserve normal
            // half-close semantics and let the forwarding path propagate EOF.
            Ok(Ok(0)) => return TlsSniffResult::Allow(Vec::new()),
            Ok(Ok(n)) => n,
            // A read error is not evidence of a blocked protocol. Treat it as
            // fail-open; the normal forwarding path will surface a terminal socket
            // error if the connection is no longer usable.
            Ok(Err(_)) => return TlsSniffResult::Allow(Vec::new()),
        };
    debug_assert_eq!(first, 1);
    if header[0] != 0x16 {
        return TlsSniffResult::Allow(header[..1].to_vec());
    }

    let mut filled = 1usize;
    let deadline = tokio::time::sleep(TLS_HEADER_TIMEOUT);
    tokio::pin!(deadline);
    while filled < header.len() {
        tokio::select! {
            _ = &mut deadline => return TlsSniffResult::Allow(header[..filled].to_vec()),
            result = inbound.read(&mut header[filled..]) => match result {
                // A half-closed client may legitimately send a short request
                // and wait for the server response. Preserve those bytes and
                // forward the EOF through the normal copy path.
                Ok(0) => return TlsSniffResult::Allow(header[..filled].to_vec()),
                Ok(n) => filled += n,
                Err(_) => return TlsSniffResult::Allow(header[..filled].to_vec()),
            }
        }
    }

    if is_tls_client_hello_header(&header) {
        TlsSniffResult::Block
    } else {
        TlsSniffResult::Allow(header.to_vec())
    }
}

fn is_tls_client_hello_header(header: &[u8; 6]) -> bool {
    let record_len = u16::from_be_bytes([header[3], header[4]]);
    header[0] == 0x16
        && header[1] == 0x03
        && header[2] <= 0x04
        // A handshake message may be fragmented across TLS records, so a
        // one-byte record containing only the ClientHello type is valid. The
        // first ClientHello is plaintext and must stay within TLSPlaintext's
        // 2^14-byte record limit; out-of-range data is not evidence of TLS.
        && (1..=TLS_MAX_PLAINTEXT_RECORD_LEN).contains(&record_len)
        && header[5] == 0x01
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::outbound::bind_tcp_listener;
    use relay_shared::protocol::LoadBalanceStrategy;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn tls_header_classifier_accepts_legacy_through_tls13_record_versions() {
        for minor in 0x00..=0x04 {
            assert!(is_tls_client_hello_header(&[
                0x16, 0x03, minor, 0x00, 0x04, 0x01
            ]));
        }
        assert!(!is_tls_client_hello_header(&[
            0x16, 0x03, 0x03, 0x00, 0x00, 0x01
        ]));
        assert!(is_tls_client_hello_header(&[
            0x16, 0x03, 0x03, 0x00, 0x01, 0x01
        ]));
        assert!(is_tls_client_hello_header(&[
            0x16, 0x03, 0x03, 0x40, 0x00, 0x01
        ]));
        assert!(!is_tls_client_hello_header(&[
            0x16, 0x03, 0x03, 0x40, 0x01, 0x01
        ]));
        assert!(!is_tls_client_hello_header(&[
            0x16, 0x03, 0x03, 0x00, 0x04, 0x02
        ]));
        assert!(!is_tls_client_hello_header(b"GET / "));
    }

    /// v1.0.8: end-to-end raw TCP forwarding still works after the NODELAY /
    /// 64 KiB buffer changes, and the client-facing socket has Nagle disabled.
    /// Topology: client → [serve_tcp_listener] → echo target.
    #[tokio::test]
    async fn raw_tcp_forward_roundtrips_and_client_has_nodelay() {
        // Echo target: read a chunk, write it straight back.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = target.accept().await {
                let mut b = vec![0u8; 1024];
                if let Ok(n) = s.read(&mut b).await {
                    let _ = s.write_all(&b[..n]).await;
                }
            }
        });

        // Relay listener on an ephemeral port, forwarding to the echo target.
        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let selector = Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1));
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            selector,
            RateLimit::Unlimited,
            counter.clone(),
            connections,
            1,
            None,
            runtime.gate(None),
            true,
            false,
            false,
            None,
        ));
        // Keep the runtime alive for the duration of the test: dropping it would
        // cancel the connection we are about to make.
        let _runtime = runtime;

        // Client connects to the relay and round-trips through to the echo.
        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        // The client's own socket having NODELAY isn't what we set (we set it on
        // the RELAY's accepted socket), but we can at least prove the relay path
        // forwards bytes correctly under the new buffer/nodelay code.
        client.write_all(b"ping-through-relay").await.unwrap();
        let mut got = vec![0u8; 64];
        let n = client.read(&mut got).await.unwrap();
        assert_eq!(
            &got[..n],
            b"ping-through-relay",
            "relay must echo the target"
        );
    }

    #[tokio::test]
    async fn tls_client_hello_is_rejected_before_target_dial() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            counter.clone(),
            connections.clone(),
            41,
            None,
            runtime.gate(None),
            true,
            false,
            true,
            None,
        ));
        let _runtime = runtime;

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        // TLS handshake record, TLS 1.2 legacy version, record length 4,
        // handshake type ClientHello. The detector intentionally needs only
        // this stable six-byte prefix.
        client
            .write_all(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x01])
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("blocked client was not closed promptly");
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), target.accept())
                .await
                .is_err(),
            "blocked TLS must not open the target connection"
        );
        assert_eq!(
            connections
                .blocked_protocol_connections()
                .get("tls")
                .copied(),
            Some(1)
        );
        assert!(
            counter.drain().await.is_empty(),
            "blocked bytes are not billable"
        );
    }

    #[tokio::test]
    async fn incomplete_tls_prefix_fails_open_and_replays_billable_bytes() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let payload = vec![0x16, 0x03, 0xff, b'n', b'o', b't', b'-', b't', b'l', b's'];
        let expected = payload.clone();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut received = vec![0u8; expected.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            stream.write_all(&received).await.unwrap();
        });

        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let counter = Arc::new(TrafficCounter::new());
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            counter.clone(),
            Arc::new(ConnectionTracker::new()),
            42,
            None,
            runtime.gate(None),
            true,
            false,
            true,
            None,
        ));
        let _runtime = runtime;

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client.write_all(&payload[..2]).await.unwrap();
        tokio::time::sleep(TLS_HEADER_TIMEOUT + Duration::from_millis(25)).await;
        client.write_all(&payload[2..]).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(client);

        let mut observed = None;
        for _ in 0..20 {
            let snapshot = counter.snapshot().await;
            observed = snapshot.entries.first().cloned();
            if observed.as_ref().is_some_and(|entry| {
                entry.upload == payload.len() as u64 && entry.download == payload.len() as u64
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let entry = observed.expect("forwarded traffic must be counted");
        assert_eq!(entry.upload, payload.len() as u64);
        assert_eq!(entry.download, payload.len() as u64);
    }

    #[tokio::test]
    async fn zero_byte_upload_half_close_still_receives_server_first_data() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let banner = b"SSH-2.0-relay-test\r\n".to_vec();
        let expected = banner.clone();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut byte = [0u8; 1];
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "client upload half-close must reach the target"
            );
            stream.write_all(&banner).await.unwrap();
        });

        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            43,
            None,
            runtime.gate(None),
            true,
            false,
            true,
            None,
        ));
        let _runtime = runtime;

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut received))
            .await
            .expect("server-first response timed out")
            .unwrap();
        assert_eq!(received, expected);
    }

    /// TFO must never deadlock server-first protocols. With no client payload
    /// pending, the relay deliberately falls back to the ordinary handshake so
    /// an SSH/SMTP-style target can send its banner immediately.
    #[tokio::test]
    async fn tcp_fast_open_falls_back_for_server_first_protocols() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            stream.write_all(b"server-banner").await.unwrap();
        });

        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            2,
            None,
            runtime.gate(None),
            true,
            true,
            true,
            None,
        ));
        let _runtime = runtime;

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        let mut banner = [0u8; 13];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut banner))
            .await
            .expect("server-first connection deadlocked under TFO")
            .unwrap();
        assert_eq!(&banner, b"server-banner");
    }

    /// A TFO cookie hit cannot prove connect success before the first payload is
    /// written. Multi-target rules therefore retain ordinary connect semantics
    /// so a refused primary still falls through to the healthy backup.
    #[tokio::test]
    async fn tcp_fast_open_preserves_multi_target_failover() {
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_addr = unavailable.local_addr().unwrap();
        drop(unavailable);

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            stream.write_all(&byte).await.unwrap();
        });

        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![unavailable_addr.to_string(), target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::Failover, 2)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            3,
            None,
            runtime.gate(None),
            true,
            true,
            false,
            None,
        ));
        let _runtime = runtime;

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client.write_all(b"f").await.unwrap();
        let mut reply = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .expect("TFO rule did not fail over to the backup")
            .unwrap();
        assert_eq!(&reply, b"f");
    }

    /// The production Linux path uses splice(2) for unlimited rules. Prove that
    /// its first pipe→socket transfer also triggers TCP_FASTOPEN_CONNECT and
    /// puts relay payload in SYN; testing TcpStream::write_all alone would miss
    /// an incompatibility between TFO and the actual zero-copy data path.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_fast_open_works_through_linux_splice_path() {
        use crate::forwarder::outbound::{
            bind_tcp_listener_with_fast_open, tcp_connect_with_fast_open,
        };
        use std::os::fd::AsRawFd;

        const TFO_CLIENT_AND_SERVER: u32 = 0x1 | 0x2;
        const TCPI_OPT_SYN_DATA: u8 = 32;

        fn tcp_info_options(stream: &TcpStream) -> std::io::Result<u8> {
            let mut info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
            let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_INFO,
                    info.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(unsafe { info.assume_init() }.tcpi_options)
        }

        let required = std::env::var_os("RELAY_REQUIRE_LINUX_TFO_TEST").is_some();
        let sysctl = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok());
        if !matches!(sysctl, Some(value) if value & TFO_CLIENT_AND_SERVER == TFO_CLIENT_AND_SERVER)
        {
            assert!(
                !required,
                "CI requires client+server TFO sysctl bits (0x3), got {:?}",
                sysctl
            );
            return;
        }

        let target = bind_tcp_listener_with_fast_open(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, true)
            .expect("bind TFO target");
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut warmup, _) = target.accept().await.unwrap();
            let mut warmup_byte = [0u8; 1];
            warmup.read_exact(&mut warmup_byte).await.unwrap();
            warmup.write_all(&warmup_byte).await.unwrap();
            drop(warmup);

            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0u8; 17];
            stream.read_exact(&mut payload).await.unwrap();
            let options = tcp_info_options(&stream).unwrap();
            stream.write_all(&payload).await.unwrap();
            (payload, options)
        });

        // First contact solicits the target's cookie before traffic enters the
        // relay. The next destination connection is therefore the warm TFO case.
        let mut warmup = tcp_connect_with_fast_open(&target_addr.to_string(), None, 5, true)
            .await
            .expect("warm-up target connection");
        warmup.write_all(b"w").await.unwrap();
        let mut warmup_reply = [0u8; 1];
        warmup.read_exact(&mut warmup_reply).await.unwrap();
        drop(warmup);

        let relay = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        let relay_task = tokio::spawn(serve_tcp_listener(
            relay,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            4,
            None,
            runtime.gate(None),
            true,
            true,
            None,
        ));

        let payload = *b"splice-syn-data!!";
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        client.write_all(&payload).await.unwrap();
        let mut reply = [0u8; 17];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .expect("Linux splice + TFO relay timed out")
            .unwrap();
        assert_eq!(reply, payload);
        let (received, options) = target_task.await.unwrap();
        assert_eq!(received, payload);
        assert_ne!(
            options & TCPI_OPT_SYN_DATA,
            0,
            "target TCP_INFO proves splice did not send relay payload in SYN (options=0x{options:02x})"
        );

        relay_task.abort();
        drop(runtime);
    }

    /// v1.2.0: the cap is enforced at accept. Connections up to the cap forward
    /// normally; the one over it is closed immediately rather than queued, so a
    /// client fails fast instead of hanging.
    #[tokio::test]
    async fn accept_loop_rejects_over_the_connection_cap() {
        // Echo target that serves many connections concurrently.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = target.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
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

        let listener = bind_tcp_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let runtime = crate::forwarder::gate::RuleRuntime::new();
        tokio::spawn(serve_tcp_listener(
            listener,
            vec![target_addr.to_string()],
            Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            1,
            None,
            runtime.gate(Some(2)),
            true,
            false,
            false,
            None,
        ));
        let _runtime = runtime;

        // Two connections fit under the cap and must both forward.
        let mut a = TcpStream::connect(listen_addr).await.unwrap();
        a.write_all(b"a").await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(a.read(&mut buf).await.unwrap(), 1, "conn 1 must forward");

        let mut b = TcpStream::connect(listen_addr).await.unwrap();
        b.write_all(b"b").await.unwrap();
        assert_eq!(b.read(&mut buf).await.unwrap(), 1, "conn 2 must forward");

        // The third is over the cap. The TCP handshake still completes (the
        // kernel accepts it, then we close), so the rejection shows up as EOF on
        // read rather than a connect error.
        let mut c = TcpStream::connect(listen_addr).await.unwrap();
        let _ = c.write_all(b"c").await;
        match tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!(
                "over-cap connection was served — echoed {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(_) => panic!("over-cap connection hung instead of being closed"),
        }

        // Closing one frees its slot, and a new connection is admitted again.
        drop(a);
        // Give the closed connection's task a moment to drop its guard.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut d = TcpStream::connect(listen_addr).await.unwrap();
            if d.write_all(b"d").await.is_ok() {
                if let Ok(Ok(1)) =
                    tokio::time::timeout(Duration::from_millis(200), d.read(&mut buf)).await
                {
                    return; // slot was freed and reused — done.
                }
            }
        }
        panic!("a freed slot was never reused — the guard did not release the cap");
    }
}
