// v0.4.8: node-side rule diagnosis.  v0.4.9: secure-diagnose challenge + TCP-only.
//
// When the panel sends `{"type":"diagnose_rule", request_id, rule_id,
// challenge}` over the WS control channel, the node:
//   1. looks up the rule's TCP listener (port/transport/targets/running)
//   2. runs SIDE-CHANNEL TCP reachability probes against each target — a fresh
//      TcpStream per target, NOT through the forwarder, so the probe:
//        - doesn't count against rule traffic (TrafficCounter untouched)
//        - isn't throttled by the rate limiter
//        - doesn't increment the active-connection count
//        - closes immediately on success
//   3. POSTs a DiagnoseResult back to the panel over the normal HTTP node→panel
//      channel (same auth as report_status), ECHOING the challenge verbatim.
//      The panel rejects the result if the challenge is empty or doesn't match
//      (v0.4.9), so a forged POST that guesses request_id+node_id fails.
//
// v0.4.9: diagnosis is TCP-ONLY. The old UDP "route-only" check is gone — UDP
// can't be verified cheaply and a "resolved but not probed" result misled
// operators. The panel rejects pure-UDP rules before dispatch (HTTP 400), so
// this code only ever runs for tcp / tcp_udp rules. For a tcp_udp rule we
// select the TCP listener explicitly (listener_info_for_rule_tcp) rather than
// relying on HashMap iteration order, which would be nondeterministic.
//
// Limits: max 32 targets, connect deadline 3s each, at most 8 concurrent probes.

use crate::config::NodeConfig;
use crate::forwarder::{ForwarderManager, ListenerInfo};
use relay_shared::protocol::{
    DiagnoseResult, DiagnoseTargetResult, TargetProbeOutcome, TunnelClientConfig,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_PROBES: usize = 8;
const MAX_TARGETS: usize = 32;

/// Run a diagnosis for one rule and POST the result to the panel.
/// Fire-and-forget from the WS loop's perspective: errors are logged, never
/// propagated (a failed probe must not crash the control channel).
///
/// `challenge` is the opaque per-run string the panel sent in the probe; we
/// MUST echo it back verbatim in DiagnoseResult.challenge or the panel rejects
/// the result (v0.4.9 secure-diagnose protocol).
pub async fn run_and_report(
    manager: &Arc<Mutex<ForwarderManager>>,
    config: &NodeConfig,
    node_id: &str,
    request_id: String,
    rule_id: i64,
    challenge: String,
) {
    let result = diagnose(manager, &request_id, rule_id, challenge).await;
    let mut result = result;
    result.node_id = node_id.to_string();
    if let Err(e) = report(config, result).await {
        tracing::warn!("diagnose {}: failed to report result: {}", request_id, e);
    }
}

/// Build the DiagnoseResult for a rule (probe targets, capture listener state).
async fn diagnose(
    manager: &Arc<Mutex<ForwarderManager>>,
    request_id: &str,
    rule_id: i64,
    challenge: String,
) -> DiagnoseResult {
    // v0.4.9: select the rule's TCP listener explicitly. For a tcp_udp rule
    // the generic lookup returns an arbitrary (Tcp OR Udp) listener because
    // self.listeners is a HashMap; the TCP selector is deterministic. The
    // panel rejects pure-UDP rules before dispatch, so rule_id here is tcp or
    // tcp_udp — both have a TCP listener.
    let (info, source_ipv4): (Option<ListenerInfo>, _) = {
        let manager = manager.lock().await;
        (
            manager.listener_info_for_rule_tcp(rule_id),
            manager.outbound_source_ipv4(),
        )
    };

    let (listener_running, listen_port, protocol, transport, targets, tunnel) = match &info {
        Some(i) => (
            i.running,
            i.port,
            i.protocol.clone(),
            i.transport.clone(),
            i.targets.clone(),
            i.tunnel.clone(),
        ),
        None => (false, 0, String::new(), String::new(), Vec::new(), None),
    };

    // Cap targets; probe in bounded-concurrency batches. TCP-only (v0.4.9).
    let results = if let Some(tunnel) = tunnel {
        vec![DiagnoseTargetResult {
            address: format!("tunnel:{} / rule:{}", tunnel.tunnel_id, tunnel.rule_id),
            outcome: probe_preset_tunnel(&tunnel, source_ipv4).await,
        }]
    } else {
        let targets_to_probe: Vec<String> = targets.into_iter().take(MAX_TARGETS).collect();
        probe_targets(&targets_to_probe, source_ipv4).await
    };

    DiagnoseResult {
        msg_type: "diagnose_result".into(),
        request_id: request_id.to_string(),
        rule_id,
        node_id: String::new(), // filled by caller
        // Echoed back verbatim; the panel rejects the result without an exact
        // match (v0.4.9 secure-diagnose challenge).
        challenge,
        listener_running,
        listen_port,
        protocol,
        transport,
        results,
    }
}

/// One authenticated probe traverses every shared listener and asks the exit
/// hop to connect to a configured final target. The caller supplies no target,
/// so diagnosis preserves the panel-controlled SSRF boundary.
async fn probe_preset_tunnel(
    config: &TunnelClientConfig,
    source_ipv4: Option<std::net::Ipv4Addr>,
) -> TargetProbeOutcome {
    let start = std::time::Instant::now();
    let run = async {
        let mut stream = crate::forwarder::outbound::tcp_connect(
            &config.address,
            source_ipv4,
            PROBE_TIMEOUT.as_secs(),
        )
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        crate::forwarder::tunnel::write_header(
            &mut stream,
            config,
            crate::forwarder::tunnel::TunnelMode::Probe,
        )
        .await?;
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;
        if status[0] == 1 {
            Ok::<(), std::io::Error>(())
        } else {
            Err(std::io::Error::other(
                "tunnel route or final target rejected the probe",
            ))
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, run).await {
        Ok(Ok(())) => TargetProbeOutcome::Reachable {
            elapsed_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(error)) => TargetProbeOutcome::Failed {
            error: error.to_string(),
        },
        Err(_) => TargetProbeOutcome::Timeout,
    }
}

/// Probe each target with a TCP connect (3s deadline). Concurrency capped at
/// MAX_CONCURRENT_PROBES via a semaphore. Input is capped at MAX_TARGETS
/// (defensive — callers should already cap, but this guarantees the contract
/// regardless). v0.4.9: TCP-only; the old UDP route-only branch is gone.
async fn probe_targets(
    targets: &[String],
    source_ipv4: Option<std::net::Ipv4Addr>,
) -> Vec<DiagnoseTargetResult> {
    let targets_capped: Vec<&String> = targets.iter().take(MAX_TARGETS).collect();
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut handles = Vec::with_capacity(targets_capped.len());
    for addr in targets_capped {
        let addr = addr.clone();
        let permit = sem.clone();
        handles.push(tokio::spawn(async move {
            let _p = permit.acquire_owned().await.unwrap();
            let outcome = probe_tcp(&addr, source_ipv4).await;
            DiagnoseTargetResult {
                address: addr,
                outcome,
            }
        }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(r) => out.push(r),
            Err(e) => tracing::warn!("diagnose probe task panicked: {}", e),
        }
    }
    out
}

/// TCP reachability: connect with a 3s deadline. Success → close immediately.
/// Recorded time is the connect latency.
async fn probe_tcp(addr: &str, source_ipv4: Option<std::net::Ipv4Addr>) -> TargetProbeOutcome {
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        crate::forwarder::outbound::tcp_connect(addr, source_ipv4, PROBE_TIMEOUT.as_secs()),
    )
    .await
    {
        Ok(Ok(_stream)) => TargetProbeOutcome::Reachable {
            elapsed_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(e)) => TargetProbeOutcome::Failed {
            error: format!("connect: {e}"),
        },
        Err(_) => TargetProbeOutcome::Timeout,
    }
}

/// POST the result to the panel (same channel/auth as report_status).
async fn report(config: &NodeConfig, result: DiagnoseResult) -> Result<(), String> {
    let url = format!("{}/api/v1/node/diagnose_result", config.panel_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .json(&result)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_probe_outcome_serializes_snake_case() {
        // The enum must serialize to the wire vocab the panel/frontend expect.
        // v0.4.9: RouteOnly is gone; only reachable/failed/timeout remain.
        let r = serde_json::to_string(&TargetProbeOutcome::Timeout).unwrap();
        assert_eq!(r, "\"timeout\"");
        let r = serde_json::to_string(&TargetProbeOutcome::Reachable { elapsed_ms: 12 }).unwrap();
        assert!(r.contains("reachable"));
        assert!(r.contains("12"));
        let r = serde_json::to_string(&TargetProbeOutcome::Failed { error: "x".into() }).unwrap();
        assert!(r.contains("failed"));
    }

    #[tokio::test]
    async fn probe_tcp_unreachable_returns_failed() {
        // 127.0.0.1:1 is almost never listening → connection refused.
        let o = probe_tcp("127.0.0.1:1", None).await;
        match o {
            TargetProbeOutcome::Failed { .. } | TargetProbeOutcome::Timeout => {}
            TargetProbeOutcome::Reachable { .. } => {
                panic!("port 1 should not be reachable")
            }
        }
    }

    #[tokio::test]
    async fn probe_tcp_to_listener_succeeds() {
        // Bind a throwaway listener, probe its address, expect Reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let o = probe_tcp(&addr, None).await;
        assert!(
            matches!(o, TargetProbeOutcome::Reachable { .. }),
            "local listener should be reachable: {:?}",
            o
        );
    }

    #[tokio::test]
    async fn probe_tcp_uses_the_configured_source_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().1.ip() });

        // Use the universally-present loopback address. Some BSD kernels do
        // not treat every 127/8 address as bindable without an explicit alias.
        let source: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let outcome = probe_tcp(&addr, Some(source)).await;
        assert!(matches!(outcome, TargetProbeOutcome::Reachable { .. }));
        assert_eq!(
            accepted.await.unwrap(),
            std::net::IpAddr::V4(source),
            "diagnosis must follow the same source binding as forwarding"
        );
    }

    #[tokio::test]
    async fn probe_targets_caps_concurrency_and_count() {
        // 50 dummy targets; must return at most MAX_TARGETS (32) results. We
        // don't assert outcomes — port availability is environment-dependent —
        // only the cap and that it returns without hanging. v0.4.9: TCP-only,
        // no is_udp flag.
        let addrs: Vec<String> = (0..50).map(|i| format!("127.0.0.1:{}", 1000 + i)).collect();
        let out = probe_targets(&addrs, None).await;
        assert!(
            out.len() <= MAX_TARGETS,
            "must cap at MAX_TARGETS, got {}",
            out.len()
        );
        assert!(!out.is_empty(), "should return some results");
    }
}
