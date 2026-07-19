// v0.4.6: shared multi-target selection for all forwarders (TCP / WS / TLS / UDP).
//
// One `TargetSelector` is created per listener and shared (Arc) across all of
// that listener's connections / UDP sessions, so a round-robin cursor advances
// globally for the rule rather than per-connection.
//
// `order()` returns the list of target indices to TRY for a single new
// connection / session, in priority order. The caller connects to the first
// index that succeeds:
//   - First       → only index 0 (no fallback). A failed primary fails the
//                    connection; later targets are standby config only.
//   - Failover     → strict 0,1,2,…; always starts at the primary and falls
//                    through to the next on failure.
//   - RoundRobin   → starts at the next cursor position and wraps; a failed
//                    pick may try the remaining targets in ring order.
//
// v0.4.21: per-target circuit breaker. After 3 consecutive connect() failures
// a target is skipped for 30 seconds (TARGET_CIRCUIT_BREAK_SECS). A successful
// connect() resets the failure count and clears the breaker immediately.
// Circuit-broken targets are filtered from order() results, with fail-open:
// if ALL targets are in circuit break, the full order list is returned so
// the connection is not permanently blocked.

use relay_shared::protocol::LoadBalanceStrategy;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TARGET_FAILURE_THRESHOLD: u32 = 3;
const TARGET_CIRCUIT_BREAK_SECS: u64 = 30;

/// Per-target health for circuit breaking. Uses atomics so concurrent
/// connections can report results without a Mutex.
#[derive(Debug)]
struct TargetHealth {
    failure_count: AtomicU32,
    circuit_until_ms: AtomicU64,
    latency_us: AtomicU64,
    attempts: AtomicU64,
    failures: AtomicU64,
    active_connections: AtomicUsize,
}

impl Default for TargetHealth {
    fn default() -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            circuit_until_ms: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
pub struct TargetSelector {
    strategy: LoadBalanceStrategy,
    len: usize,
    cursor: AtomicUsize,
    health: Vec<TargetHealth>,
    weights: Vec<u16>,
}

impl TargetSelector {
    #[cfg(test)]
    pub fn new(strategy: LoadBalanceStrategy, len: usize) -> Self {
        Self::with_weights(strategy, len, Vec::new())
    }

    pub fn with_weights(strategy: LoadBalanceStrategy, len: usize, weights: Vec<u16>) -> Self {
        let mut health = Vec::with_capacity(len);
        for _ in 0..len {
            health.push(TargetHealth::default());
        }
        Self {
            strategy,
            len,
            cursor: AtomicUsize::new(0),
            health,
            weights: (0..len)
                .map(|i| weights.get(i).copied().unwrap_or(1).clamp(1, 100))
                .collect(),
        }
    }

    /// Report the result of a connect() attempt for target `idx`.
    ///
    /// - `success`: reset failure_count and circuit_until_ms.
    /// - `!success`: increment failure_count; if >= THRESHOLD, set
    ///   circuit_until_ms = now + CIRCUIT_BREAK_SECS.
    ///
    /// Out-of-bounds `idx` is silently ignored (no panic).
    pub fn report(&self, idx: usize, success: bool) {
        self.report_timed(idx, success, None);
    }

    /// Report a passive connect result or an active probe. Successful latency
    /// samples feed an EWMA; attempts/failures form a rolling-enough lifetime
    /// loss ratio used by least-latency scoring and anomaly circuit breaking.
    pub fn report_timed(&self, idx: usize, success: bool, latency: Option<Duration>) {
        let Some(h) = self.health.get(idx) else {
            return;
        };
        h.attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            h.failure_count.store(0, Ordering::Relaxed);
            h.circuit_until_ms.store(0, Ordering::Relaxed);
            if let Some(latency) = latency {
                let sample = latency.as_micros().max(1) as u64;
                let previous = h.latency_us.load(Ordering::Relaxed);
                let ewma = if previous == 0 {
                    sample
                } else {
                    previous.saturating_mul(7).saturating_add(sample) / 8
                };
                h.latency_us.store(ewma, Ordering::Relaxed);
            }
        } else {
            h.failures.fetch_add(1, Ordering::Relaxed);
            let count = h.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
            let attempts = h.attempts.load(Ordering::Relaxed);
            let failures = h.failures.load(Ordering::Relaxed);
            let anomalous_loss = attempts >= 5 && failures.saturating_mul(100) / attempts >= 80;
            if count >= TARGET_FAILURE_THRESHOLD || anomalous_loss {
                let now_ms = now_millis();
                let until = now_ms.saturating_add(TARGET_CIRCUIT_BREAK_SECS * 1000);
                h.circuit_until_ms.store(until, Ordering::Relaxed);
            }
        }
    }

    /// Whether target `idx` is currently in circuit break (should be skipped).
    fn is_circuit_open(&self, idx: usize) -> bool {
        let Some(h) = self.health.get(idx) else {
            return false;
        };
        let until = h.circuit_until_ms.load(Ordering::Relaxed);
        if until == 0 {
            return false;
        }
        now_millis() < until
    }

    /// The ordered target indices to attempt for ONE new connection / session.
    /// Empty when there are no targets.
    ///
    /// v0.4.21: targets currently in circuit break are filtered out. If ALL
    /// targets are in circuit break, fail-open returns the unfiltered order
    /// so the connection isn't permanently blocked.
    pub fn order(&self) -> Vec<usize> {
        if self.len == 0 {
            return Vec::new();
        }
        let candidates: Vec<usize> = match self.strategy {
            LoadBalanceStrategy::First => vec![0],
            LoadBalanceStrategy::Failover => (0..self.len).collect(),
            LoadBalanceStrategy::RoundRobin => {
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) % self.len;
                (0..self.len).map(|i| (start + i) % self.len).collect()
            }
            LoadBalanceStrategy::Weighted => {
                let total: usize = self.weights.iter().map(|w| *w as usize).sum();
                let mut slot = self.cursor.fetch_add(1, Ordering::Relaxed) % total.max(1);
                let mut picked = 0;
                for (idx, weight) in self.weights.iter().enumerate() {
                    if slot < *weight as usize {
                        picked = idx;
                        break;
                    }
                    slot -= *weight as usize;
                }
                std::iter::once(picked)
                    .chain((0..self.len).filter(|idx| *idx != picked))
                    .collect()
            }
            LoadBalanceStrategy::LeastLatency => {
                let mut order: Vec<usize> = (0..self.len).collect();
                order.sort_by_key(|idx| self.latency_loss_score(*idx));
                order
            }
            LoadBalanceStrategy::LeastConnections => {
                let mut order: Vec<usize> = (0..self.len).collect();
                order.sort_by_key(|idx| {
                    self.health[*idx].active_connections.load(Ordering::Relaxed)
                });
                order
            }
        };
        let alive: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&i| !self.is_circuit_open(i))
            .collect();
        if alive.is_empty() {
            candidates
        } else {
            alive
        }
    }

    fn latency_loss_score(&self, idx: usize) -> u64 {
        let h = &self.health[idx];
        let latency = h.latency_us.load(Ordering::Relaxed);
        if latency == 0 {
            return u64::MAX / 2 + idx as u64;
        }
        let attempts = h.attempts.load(Ordering::Relaxed).max(1);
        let loss_percent = h.failures.load(Ordering::Relaxed).saturating_mul(100) / attempts;
        latency.saturating_mul(100 + loss_percent.saturating_mul(4)) / 100
    }

    /// Hold one least-connections slot for the lifetime of a TCP connection or
    /// UDP session. Dropping the guard always decrements, including task aborts.
    pub fn acquire(self: &Arc<Self>, idx: usize) -> Option<TargetLease> {
        let health = self.health.get(idx)?;
        health.active_connections.fetch_add(1, Ordering::Relaxed);
        Some(TargetLease {
            selector: self.clone(),
            idx,
        })
    }
}

pub struct TargetLease {
    selector: Arc<TargetSelector>,
    idx: usize,
}

impl Drop for TargetLease {
    fn drop(&mut self) {
        if let Some(h) = self.selector.health.get(self.idx) {
            h.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Active health probing shared by TCP, UOT and native UDP listeners. The
/// caller marks relay TCP targets for a real connect probe; native UDP targets
/// (including the final target behind an UOT egress) use fresh DNS resolution,
/// because a generic relay cannot demand an application-specific UDP reply. A
/// Weak selector makes the task self-terminate after the listener and its
/// sessions are gone.
pub fn spawn_active_probes(
    selector: Weak<TargetSelector>,
    targets: Vec<String>,
    source_ipv4: Option<Ipv4Addr>,
    tcp_probe: bool,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(selector) = selector.upgrade() else {
                break;
            };
            for (idx, target) in targets.iter().enumerate() {
                let started = Instant::now();
                let success = if tcp_probe {
                    matches!(
                        tokio::time::timeout(
                            Duration::from_secs(3),
                            super::outbound::tcp_connect(target, source_ipv4, 3),
                        )
                        .await,
                        Ok(Ok(_))
                    )
                } else {
                    matches!(
                        tokio::time::timeout(
                            Duration::from_secs(3),
                            super::outbound::resolve_fresh(target),
                        )
                        .await,
                        Ok(Ok(addrs)) if !addrs.is_empty()
                    )
                };
                selector.report_timed(idx, success, success.then(|| started.elapsed()));
            }
        }
    });
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

    #[test]
    fn empty_targets_yield_no_order() {
        let s = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 0);
        assert!(s.order().is_empty());
    }

    #[test]
    fn first_only_tries_primary() {
        let s = TargetSelector::new(LoadBalanceStrategy::First, 3);
        assert_eq!(s.order(), vec![0]);
        assert_eq!(s.order(), vec![0], "First never advances");
    }

    #[test]
    fn failover_is_strict_priority_from_primary() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        assert_eq!(s.order(), vec![0, 1, 2]);
        assert_eq!(
            s.order(),
            vec![0, 1, 2],
            "Failover always starts at primary"
        );
    }

    #[test]
    fn round_robin_advances_and_wraps() {
        let s = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 3);
        assert_eq!(s.order(), vec![0, 1, 2]);
        assert_eq!(s.order(), vec![1, 2, 0]);
        assert_eq!(s.order(), vec![2, 0, 1]);
        assert_eq!(s.order(), vec![0, 1, 2], "wraps back to primary");
    }

    #[test]
    fn round_robin_single_target_is_stable() {
        let s = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 1);
        assert_eq!(s.order(), vec![0]);
        assert_eq!(s.order(), vec![0]);
    }

    // --- v0.4.21: circuit-breaker tests ---

    #[test]
    fn report_success_resets_failure_count() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        s.report(0, false);
        s.report(0, false);
        s.report(0, true);
        assert_eq!(s.order(), vec![0, 1, 2]);
    }

    #[test]
    fn three_failures_triggers_circuit() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        s.report(0, false);
        s.report(0, false);
        s.report(0, false);
        let order = s.order();
        assert!(
            !order.contains(&0),
            "target 0 should be circuit-broken, got {:?}",
            order
        );
        assert_eq!(order, vec![1, 2]);
    }

    #[test]
    fn circuit_expires_target_rejoins_after_30s() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        s.health[0]
            .circuit_until_ms
            .store(now_millis().saturating_sub(1000), Ordering::Relaxed);
        assert_eq!(s.order(), vec![0, 1, 2]);
    }

    #[test]
    fn all_targets_circuit_open_fail_open() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        for i in 0..3 {
            s.report(i, false);
            s.report(i, false);
            s.report(i, false);
        }
        let order = s.order();
        assert!(!order.is_empty(), "must fail-open, not return empty list");
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn report_out_of_bounds_ignored() {
        let s = TargetSelector::new(LoadBalanceStrategy::First, 1);
        s.report(1, false);
        s.report(5, true);
        s.report(usize::MAX, false);
        assert_eq!(s.order(), vec![0]);
    }

    #[test]
    fn first_always_returns_index_zero_even_when_circuit() {
        let s = TargetSelector::new(LoadBalanceStrategy::First, 3);
        s.report(0, false);
        s.report(0, false);
        s.report(0, false);
        assert_eq!(s.order(), vec![0]);
    }

    #[test]
    fn round_robin_skips_circuit_target() {
        let s = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 3);
        assert_eq!(s.order(), vec![0, 1, 2]);
        s.report(0, false);
        s.report(0, false);
        s.report(0, false);
        let order = s.order();
        assert!(!order.contains(&0));
        assert_eq!(order, vec![1, 2]);
    }

    #[test]
    fn failover_skips_circuit_primary() {
        let s = TargetSelector::new(LoadBalanceStrategy::Failover, 3);
        s.report(0, false);
        s.report(0, false);
        s.report(0, false);
        assert_eq!(s.order(), vec![1, 2]);
    }

    #[test]
    fn concurrent_reports_no_panic() {
        use std::sync::Arc;
        use std::thread;
        let s = Arc::new(TargetSelector::new(LoadBalanceStrategy::RoundRobin, 5));
        let mut handles = vec![];
        for t in 0..10 {
            let s = s.clone();
            handles.push(thread::spawn(move || {
                for i in 0..5 {
                    s.report(i, false);
                    let _ = s.order();
                }
                s.report(t % 5, true);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let order = s.order();
        assert!(!order.is_empty());
    }

    #[test]
    fn weighted_round_robin_honors_ratio() {
        let s = TargetSelector::with_weights(LoadBalanceStrategy::Weighted, 2, vec![3, 1]);
        let picks: Vec<usize> = (0..8).map(|_| s.order()[0]).collect();
        assert_eq!(picks, vec![0, 0, 0, 1, 0, 0, 0, 1]);
    }

    #[test]
    fn least_latency_includes_loss_penalty() {
        let s = TargetSelector::new(LoadBalanceStrategy::LeastLatency, 2);
        s.report_timed(0, true, Some(Duration::from_millis(20)));
        s.report_timed(1, true, Some(Duration::from_millis(40)));
        assert_eq!(s.order()[0], 0);
        // Two non-consecutive losses keep the circuit closed but add enough
        // loss penalty to make the nominally slower healthy line preferable.
        s.report(0, false);
        s.report_timed(0, true, Some(Duration::from_millis(20)));
        s.report(0, false);
        s.report_timed(0, true, Some(Duration::from_millis(20)));
        assert_eq!(s.order()[0], 1);
    }

    #[test]
    fn least_connections_tracks_raii_lease() {
        let s = Arc::new(TargetSelector::new(
            LoadBalanceStrategy::LeastConnections,
            2,
        ));
        let lease = s.acquire(0).unwrap();
        assert_eq!(s.order()[0], 1);
        drop(lease);
        assert_eq!(s.order()[0], 0);
    }
}
