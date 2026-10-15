// Plain WebSocket (ws://) ingress listener — v0.3.0-alpha.
//
// This is the plaintext WS listener. For encrypted ingress, use TLS Simple
// (tls.rs — node terminates TLS directly via rustls). Business WSS (WebSocket
// Secure via reverse proxy) was removed in v0.4.1.
//
// Forwarding model — same as TCP, but the inbound side is a WebSocket:
//   1. Accept a TCP connection on `listen_addr`.
//   2. Upgrade it to a WebSocket (tungstenite handshake).
//   3. Connect a plain TCP `outbound` to the first reachable target.
//   4. Pump both directions concurrently:
//        ws→target:  each inbound Binary/Text frame's payload is written to
//                    `outbound`.
//        target→ws:  bytes read from `outbound` are sent as Binary frames.
//   5. Traffic is attributed to `rule_id` exactly like TCP (not the port),
//      and counted via the shared TrafficCounter.
//
// We deliberately do NOT try to shoehorn the WS stream into AsyncRead/AsyncWrite
// + io::copy. Frame-level copying is clearer, has fewer abstraction layers, and
// makes the traffic-count points explicit. The target side is still a plain
// TcpStream, so the only WS-specific code is the two pump loops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

use super::limiter::RateLimit;
use super::selector::TargetSelector;
use crate::reporter::{ConnectionTracker, TrafficCounter};

/// Max payload we accept in a single WS frame, to stop a malicious peer from
/// forcing us to buffer an arbitrarily large frame (§8.5 of the design doc:
/// "WS 帧分片大小限制 默认 16KB/帧"). 1 MiB is generous for any sane app
/// while keeping per-frame memory bounded.
const MAX_WS_FRAME_PAYLOAD: usize = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn start_ws_listener(
    listen_addr: SocketAddr,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    rule_id: i64,
    ws_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve the path this listener accepts. None / empty → built-in default
    // "/relay" (the contract the panel's ws_path field documents).
    let expected_path = ws_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/relay")
        .to_string();
    tracing::info!(
        "WS listening on {} (rule {}, path {})",
        listen_addr,
        rule_id,
        expected_path
    );

    // v0.3.6: bind ONCE and accept in a loop. v0.3.5's `listener_accept`
    // re-bound on every iteration (the listener was dropped after one accept),
    // which both wasted resources and meant a transient accept error killed the
    // task via `?`. Now we keep the listener alive and retry transient errors.
    let listener = TcpListener::bind(listen_addr).await?;
    loop {
        let (inbound, client_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) if is_transient_accept_error(&e) => {
                tracing::warn!(
                    "WS listener on {} (rule {}): transient accept error: {}; retrying in 100ms",
                    listen_addr,
                    rule_id,
                    e
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        };
        let targets = targets.clone();
        let selector = selector.clone();
        let rate_limit = rate_limit.clone();
        let counter = counter.clone();
        let connections = connections.clone();
        let expected_path = expected_path.clone();

        tokio::spawn(async move {
            // RAII guard identical to the TCP path: increments the active count
            // on entry, decrements on drop (covers normal close, error, panic).
            let _guard = connections.tcp_handle();
            if let Err(e) = handle_ws_connection(
                inbound,
                client_addr,
                targets,
                selector,
                rate_limit,
                counter,
                rule_id,
                &expected_path,
            )
            .await
            {
                // v0.4.0: handshake/connection errors are common when a reverse
                // proxy misroutes (wrong path, missing Host header) or a client
                // connects without a proper WS upgrade. Log at warn so the
                // operator can diagnose WSS routing issues from the relay-node
                // log without needing panel-side handshake_errors reporting.
                tracing::warn!(
                    "WS connection error on rule {} (path {}, from {}): {}",
                    rule_id,
                    expected_path,
                    client_addr,
                    e
                );
            }
        });
    }
}

/// Classify whether an `accept` error is worth retrying (same logic as the TCP
/// listener's classifier). v0.3.6: a transient accept error no longer kills the
/// WS listener task; it backs off and continues.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ResourceBusy
    ) || e
        .raw_os_error()
        .is_some_and(|c| matches!(c, 24 | 23 | 105 | 12))
}

/// Callback that rejects the WS handshake if the request path doesn't match
/// the configured `ws_path`. tungstenite hands us the inbound `Request` during
/// the handshake; returning Err aborts the upgrade (client gets a 404/bad path).
struct PathCheck<'a> {
    expected: &'a str,
}

impl tokio_tungstenite::tungstenite::handshake::server::Callback for PathCheck<'_> {
    fn on_request(
        self,
        request: &tokio_tungstenite::tungstenite::handshake::server::Request,
        response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        let actual = request.uri().path();
        if actual == self.expected {
            Ok(response)
        } else {
            // Reject: the client hit the wrong path. Return a 404 so probes /
            // browsers hitting "/" don't silently get a working tunnel.
            let reject =
                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(Some(
                    format!("wrong path: expected {}, got {}", self.expected, actual),
                ));
            Err(reject)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ws_connection(
    inbound: TcpStream,
    client_addr: SocketAddr,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    rule_id: i64,
    expected_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Upgrade the raw TCP stream to a WebSocket, validating the request path
    // against the configured ws_path during the handshake. A request to the
    // wrong path is rejected (no tunnel); on any other handshake failure the
    // connection is simply dropped (the client sees a closed socket).
    let callback = PathCheck {
        expected: expected_path,
    };
    let ws = tokio_tungstenite::accept_hdr_async(inbound, callback).await?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Connect to the first reachable target — same logic as TCP. A WS ingress
    // rule always forwards to a plain TCP/UDP target (the *ingress* is WS, the
    // *target* protocol is whatever the target speaks; we treat it as a byte
    // stream, which is correct for the overwhelming majority of cases).
    let mut outbound = None;
    for idx in selector.order() {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                selector.report(idx, true);
                outbound = Some(stream);
                break;
            }
            _ => {
                selector.report(idx, false);
                continue;
            }
        }
    }
    let outbound = match outbound {
        Some(s) => s,
        None => {
            tracing::warn!("WS: no target available for {}", client_addr);
            return Err("no target available".into());
        }
    };
    tracing::debug!("WS: {} -> {}", client_addr, outbound.peer_addr()?);

    // Split the target TCP stream into owned read/write halves so the two pump
    // arms can run concurrently without borrowing the same TcpStream.
    let (mut target_read, mut target_write) = outbound.into_split();

    // Bidirectional pump. Each arm owns one half of the target connection:
    //   - ws→target: reads WS frames, writes their payload to `target_write`.
    //   - target→ws: reads bytes from `target_read`, sends them as Binary frames.
    // Either side returning (peer closed / error) ends the session; we then
    // shut down the target write side and close the WS so both ends see a
    // clean teardown.
    let counter_up = counter.handle(rule_id).await;
    let counter_down = counter_up.clone();
    let rl_up = rate_limit.clone();
    let rl_down = rate_limit;

    let upload = Box::pin(async move {
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            while let Some(msg_result) = ws_stream.next().await {
                let payload: Vec<u8> = match msg_result? {
                    // tokio-tungstenite 0.29 wraps Binary in bytes::Bytes and
                    // Text in Utf8Bytes; both expose an as-byte slice.
                    Message::Binary(bytes) => bytes.as_ref().to_vec(),
                    Message::Text(text) => text.as_bytes().to_vec(),
                    Message::Ping(_) | Message::Pong(_) | Message::Close(_) => {
                        // Control frames: tungstenite handles Ping/Pong automatically;
                        // we just ignore them here and keep the data pump running.
                        continue;
                    }
                    Message::Frame(_) => continue,
                };
                if payload.is_empty() {
                    continue;
                }
                if payload.len() > MAX_WS_FRAME_PAYLOAD {
                    tracing::warn!(
                        "WS rule {}: frame payload {} exceeds limit {}, dropping connection",
                        rule_id,
                        payload.len(),
                        MAX_WS_FRAME_PAYLOAD
                    );
                    return Err("ws frame too large".into());
                }
                // v0.4.6: throttle ws→target (upload) bytes before forwarding.
                rl_up.acquire_upload(payload.len() as u64).await;
                super::meter::write_counted(&mut target_write, &payload, Some(&counter_up), true)
                    .await?;
            }
            Ok(())
        }
        .await;
        // Shut down the target's write side so the download arm sees EOF.
        let _ = target_write.shutdown().await;
        result
    });

    let download = Box::pin(async move {
        // Read target bytes and send them as Binary WS frames. 8 KiB is a
        // reasonable trade-off between syscall overhead and frame granularity.
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => break, // target closed its side
                Ok(n) => {
                    // v0.4.6: throttle target→ws (download) bytes before sending.
                    rl_down.acquire_download(n as u64).await;
                    if let Err(e) = ws_sink
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                    {
                        tracing::debug!("WS rule {}: send frame failed: {}", rule_id, e);
                        break;
                    }
                    counter_down.add_download(n as u64);
                }
                Err(e) => {
                    tracing::debug!("WS rule {}: target read failed: {}", rule_id, e);
                    break;
                }
            }
        }
        // Close the WebSocket cleanly so the client disconnects promptly.
        let _ = ws_sink.close().await;
    });

    let (up_res, ()) = tokio::join!(upload, download);
    tracing::debug!("WS: connection closed for {}", client_addr);
    up_res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::TrafficCounter;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a tiny TCP echo server: every byte it receives on a connection it
    /// writes straight back. Used as the WS listener's forwarding target so a
    /// test can verify end-to-end that bytes flow client→WS→target→WS→client.
    ///
    /// Returns the (port, join_handle_of_accept_loop). The accept loop runs
    /// forever; the handle is kept only so the task is not dropped.
    async fn spawn_echo_target() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    // Echo until the peer closes. A 1 KiB buffer is plenty for
                    // the small payloads these tests send.
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        (port, handle)
    }

    /// Full round-trip: a WS client connects to the listener, sends a Binary
    /// frame, and must receive the same payload echoed back. This proves the
    /// two pump arms (ws→target, target→ws) both work and that the WS upgrade
    /// succeeds. The echo target is plain TCP, so any data the WS listener
    /// forwards reaches it as bytes and comes back as a Binary frame.
    #[tokio::test]
    async fn ws_listener_forwards_binary_both_directions() {
        let (target_port, _echo) = spawn_echo_target().await;

        // Bind the WS listener on an ephemeral port, pointing at the echo target.
        let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_port = ws_listener.local_addr().unwrap().port();
        let counter = Arc::new(TrafficCounter::new());
        let counter_for_listener = counter.clone();
        let target_addr = format!("127.0.0.1:{}", target_port);
        let _listener_task = tokio::spawn(async move {
            // Drive the per-connection handler directly for exactly one
            // connection, so the test can observe the result and doesn't hang
            // forever in start_ws_listener's infinite accept loop.
            let (inbound, client_addr) = ws_listener.accept().await.unwrap();
            handle_ws_connection(
                inbound,
                client_addr,
                vec![target_addr],
                Arc::new(crate::forwarder::selector::TargetSelector::new(
                    relay_shared::protocol::LoadBalanceStrategy::First,
                    1,
                )),
                crate::forwarder::limiter::RateLimit::new(None, None),
                counter_for_listener,
                42,
                "/relay",
            )
            .await
            .ok();
        });

        // Give the listener a moment to enter accept(). A tiny sleep is the
        // pragmatic choice used across the codebase's integration glue.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect a WS client and send a Binary frame, then read back one frame.
        use futures_util::{SinkExt, StreamExt};
        let (mut ws_client, _resp) =
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/relay", ws_port))
                .await
                .expect("ws connect");

        let payload = b"hello-ws-ingress";
        ws_client
            .send(Message::Binary(payload.to_vec().into()))
            .await
            .expect("send binary");

        // The first frame back must be our payload echoed by the target.
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), ws_client.next())
            .await
            .expect("timed out waiting for echo")
            .expect("stream ended")
            .expect("ws error");

        match echoed {
            Message::Binary(bytes) => assert_eq!(bytes.as_ref(), payload),
            other => panic!("expected Binary echo, got {:?}", other),
        }

        // Accounting must be visible BEFORE close, not on a session-final flush.
        let snapshot = counter.snapshot().await;
        assert_eq!(
            (snapshot.entries[0].upload, snapshot.entries[0].download),
            (payload.len() as u64, payload.len() as u64)
        );
        let _ = ws_client.close(None).await;
        // Give the handler a beat to finish its join! arms after the close.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Traffic for rule 42 must be non-zero in BOTH directions (the echo
        // target sent the same bytes back, so upload == download for one frame).
        let drained = counter.drain().await;
        let entry = drained
            .iter()
            .find(|e| e.rule_id == 42)
            .unwrap_or_else(|| panic!("traffic counted for rule 42, got: {:?}", drained));
        assert!(
            entry.upload >= payload.len() as u64,
            "upload counted: {:?}",
            entry
        );
        assert!(
            entry.download >= payload.len() as u64,
            "download counted: {:?}",
            entry
        );
    }

    /// A Text frame from the client must also be forwarded (its UTF-8 bytes
    /// reach the target just like a Binary frame). This pins the Text arm of
    /// the ws→target pump.
    #[tokio::test]
    async fn ws_listener_forwards_text_frame_payload() {
        let (target_port, _echo) = spawn_echo_target().await;
        let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_port = ws_listener.local_addr().unwrap().port();
        let counter = Arc::new(TrafficCounter::new());
        let target_addr = format!("127.0.0.1:{}", target_port);
        let _listener_task = tokio::spawn(async move {
            let (inbound, client_addr) = ws_listener.accept().await.unwrap();
            handle_ws_connection(
                inbound,
                client_addr,
                vec![target_addr],
                Arc::new(crate::forwarder::selector::TargetSelector::new(
                    relay_shared::protocol::LoadBalanceStrategy::First,
                    1,
                )),
                crate::forwarder::limiter::RateLimit::new(None, None),
                counter,
                7,
                "/relay",
            )
            .await
            .ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        use futures_util::{SinkExt, StreamExt};
        let (mut ws_client, _resp) =
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/relay", ws_port))
                .await
                .unwrap();
        ws_client.send(Message::Text("ping".into())).await.unwrap();

        let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), ws_client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match echoed {
            Message::Binary(bytes) => assert_eq!(bytes.as_ref(), b"ping"),
            other => panic!("expected Binary echo, got {:?}", other),
        }
    }

    /// The listener configured for "/relay" must REJECT a connection to a
    /// different path. Without this check, ws_path was a no-op — any path got
    /// a working tunnel, which defeats the point of per-rule path routing.
    #[tokio::test]
    async fn ws_listener_rejects_wrong_path() {
        let (target_port, _echo) = spawn_echo_target().await;
        let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_port = ws_listener.local_addr().unwrap().port();
        let counter = Arc::new(TrafficCounter::new());
        let target_addr = format!("127.0.0.1:{}", target_port);
        let _listener_task = tokio::spawn(async move {
            let (inbound, client_addr) = ws_listener.accept().await.unwrap();
            // Listener expects "/relay"; the client below will hit "/wrong".
            handle_ws_connection(
                inbound,
                client_addr,
                vec![target_addr],
                Arc::new(crate::forwarder::selector::TargetSelector::new(
                    relay_shared::protocol::LoadBalanceStrategy::First,
                    1,
                )),
                crate::forwarder::limiter::RateLimit::new(None, None),
                counter,
                9,
                "/relay",
            )
            .await
            .ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to the WRONG path — the handshake must fail (client gets an
        // error / closed connection, NOT a working WS).
        let result =
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/wrong", ws_port)).await;
        assert!(
            result.is_err(),
            "connection to the wrong path must be rejected, not upgraded"
        );
    }
}
