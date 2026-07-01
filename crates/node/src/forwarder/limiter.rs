// v0.4.6: per-rule, bidirectional, connection-shared rate limiting.
//
// One `RuleLimiter` covers BOTH the upload and download directions of a single
// rule, and is shared (Arc) across ALL of that rule's connections / UDP
// sessions / TCP+UDP listeners. This is deliberate: a `tcp_udp` rule must NOT
// get double the budget, and the cap is on the RULE's aggregate traffic, not
// per-connection.
//
// Implementation: a continuously-refilled token bucket per direction. The
// balance math is done in a SYNCHRONOUS `Bucket::charge()` that runs under the
// bucket lock and returns how long the caller must sleep; the SLEEP then
// happens AFTER the lock is released (RuleLimiter::charge). This is critical:
// the bucket is shared across ALL of a rule's connections, so if a throttled
// connection slept while holding the lock, every other connection of the rule
// would be frozen behind it (head-of-line blocking → jitter + unfairness).
//
// The balance is allowed to go NEGATIVE ("debt"): a chunk LARGER than the burst
// capacity is still admitted, it just incurs a proportionally longer wait to
// repay the debt. (The earlier version capped the balance and looped forever
// when `want > rate*burst`, hanging any connection whose read chunk exceeded
// one second of the configured rate — e.g. a 64 KiB read on a sub-512 kbps
// limit.) Steady-state throughput still equals the cap; short bursts up to one
// second of traffic are allowed.
//
// A rate of 0 / None means unlimited: `acquire()` is a no-op, so unlimited
// rules pay only a single branch per chunk.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// One second of burst capacity — lets a connection send a full-rate chunk
/// immediately, then throttle back to the refill rate.
const BURST_SECS: u64 = 1;

struct Bucket {
    /// Refill rate in bytes/sec. 0 = this direction is unlimited.
    rate_bps: u64,
    /// Current token balance in bytes. The POSITIVE side is capped at
    /// rate_bps * BURST_SECS; the balance MAY go negative ("debt") so a chunk
    /// bigger than the burst capacity is still admitted (with a longer wait).
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            // Start full so the first chunk isn't artificially delayed.
            tokens: rate_bps.saturating_mul(BURST_SECS) as f64,
            last_refill: Instant::now(),
        }
    }

    /// SYNCHRONOUS: refill by elapsed wall time (positive side capped at the
    /// burst ceiling), then charge `want` bytes — the balance is allowed to go
    /// negative. Returns `Some(wait)` if the caller must sleep to repay the
    /// resulting debt, or `None` if there was enough balance.
    ///
    /// This intentionally does NOT sleep: the caller (RuleLimiter::charge) holds
    /// the bucket lock only for this call and releases it BEFORE sleeping, so a
    /// throttled connection never blocks the other connections sharing the
    /// bucket. Because `want` is charged unconditionally (into debt if needed),
    /// there is no unbounded retry loop — a large chunk simply yields a larger
    /// (but finite) `wait`.
    fn charge(&mut self, want: u64) -> Option<Duration> {
        if self.rate_bps == 0 {
            return None;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        let cap = self.rate_bps.saturating_mul(BURST_SECS) as f64;
        self.tokens += elapsed * self.rate_bps as f64;
        if self.tokens > cap {
            // Only the positive (burst-credit) side is capped; debt is not.
            self.tokens = cap;
        }
        self.tokens -= want as f64;
        if self.tokens >= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(-self.tokens / self.rate_bps as f64))
        }
    }
}

/// Per-rule rate limiter. Shared across all connections of the rule.
pub struct RuleLimiter {
    upload: Mutex<Bucket>,
    download: Mutex<Bucket>,
    /// Cached so callers can short-circuit without locking when both are zero.
    unlimited: bool,
}

impl RuleLimiter {
    /// `upload_bps` / `download_bps` are bytes/sec; None / 0 means unlimited.
    pub fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        let up = upload_bps.unwrap_or(0);
        let down = download_bps.unwrap_or(0);
        Self {
            upload: Mutex::new(Bucket::new(up)),
            download: Mutex::new(Bucket::new(down)),
            unlimited: up == 0 && down == 0,
        }
    }

    #[allow(dead_code)]
    pub fn unlimited() -> Self {
        Self::new(None, None)
    }

    #[allow(dead_code)]
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Charge `n` bytes against a bucket, then sleep for any resulting debt.
    /// The lock is held ONLY for the synchronous `charge()` and is dropped
    /// (end of the block) BEFORE the sleep — so a throttled connection never
    /// holds the shared bucket lock while it waits.
    async fn charge(bucket: &Mutex<Bucket>, n: u64) {
        let wait = { bucket.lock().await.charge(n) };
        if let Some(w) = wait {
            tokio::time::sleep(w).await;
        }
    }

    /// Reserve `n` upload (client→target) bytes. No-op for unlimited limiters.
    pub async fn acquire_upload(&self, n: u64) {
        if self.unlimited {
            return;
        }
        Self::charge(&self.upload, n).await;
    }

    /// Reserve `n` download (target→client) bytes. No-op for unlimited limiters.
    pub async fn acquire_download(&self, n: u64) {
        if self.unlimited {
            return;
        }
        Self::charge(&self.download, n).await;
    }
}

/// A handle that is either a real shared limiter or "no limit" (the common
/// case for v0.4.5 rules and any rule with 0 caps). Cloned cheaply into every
/// connection / UDP session task of a rule.
#[derive(Clone)]
pub enum RateLimit {
    Unlimited,
    Limited(Arc<RuleLimiter>),
}

impl RateLimit {
    /// Build the shared limiter for a listener's (rule_id, direction) caps.
    /// `None`/0 on both sides → Unlimited (zero per-connection overhead).
    pub fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        if upload_bps.unwrap_or(0) == 0 && download_bps.unwrap_or(0) == 0 {
            RateLimit::Unlimited
        } else {
            RateLimit::Limited(Arc::new(RuleLimiter::new(upload_bps, download_bps)))
        }
    }

    pub async fn acquire_upload(&self, n: u64) {
        if let RateLimit::Limited(l) = self {
            l.acquire_upload(n).await;
        }
    }
    pub async fn acquire_download(&self, n: u64) {
        if let RateLimit::Limited(l) = self {
            l.acquire_download(n).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_is_instant_noop() {
        let r = RateLimit::new(None, None);
        assert!(matches!(r, RateLimit::Unlimited));
        // Should return immediately even for a huge amount.
        let start = Instant::now();
        r.acquire_upload(u64::MAX / 2).await;
        r.acquire_download(u64::MAX / 2).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn acquire_blocks_then_refills() {
        // 1000 byte/s. Requesting 1000 bytes right away consumes the initial
        // full bucket; requesting another 1000 immediately must wait ~1s.
        let r = RateLimit::new(Some(1000), Some(1000));
        r.acquire_upload(1000).await; // drains burst
        let start = Instant::now();
        r.acquire_upload(1000).await; // must refill ~1s
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "expected ~1s wait, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn shared_bucket_aggregates_across_clone() {
        // Two tasks sharing one limiter must draw from the SAME bucket, so the
        // combined rate is capped, not doubled.
        let r = RateLimit::new(Some(1000), Some(0));
        // Drain the initial burst once.
        r.acquire_upload(1000).await;
        let r2 = r.clone();
        let h1 = tokio::spawn(async move { r.acquire_upload(500).await });
        let h2 = tokio::spawn(async move { r2.acquire_upload(500).await });
        let start = Instant::now();
        h1.await.unwrap();
        h2.await.unwrap();
        // Together they requested 1000 bytes at 1000 byte/s → ~1s total (the
        // two halves may serialize on the bucket lock, but the refill time is
        // bounded by the aggregate amount).
        assert!(start.elapsed() >= Duration::from_millis(900));
    }

    /// Regression: a chunk LARGER than the burst capacity (rate * BURST_SECS)
    /// must still complete, not loop forever. The old code capped the balance
    /// below `want` and spun forever, hanging the connection. Rate is high so
    /// the real wait is short (~0.5s).
    #[tokio::test]
    async fn large_chunk_over_burst_does_not_hang() {
        // 100_000 B/s, burst cap = 100_000. Ask for 150_000 (1.5× the cap).
        let r = RateLimit::new(Some(100_000), None);
        let start = Instant::now();
        r.acquire_upload(150_000).await;
        let elapsed = start.elapsed();
        // Starts with the full 100_000 burst → 50_000 debt at 100_000 B/s ≈ 0.5s.
        assert!(
            elapsed >= Duration::from_millis(400),
            "must wait to repay the debt, got {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must not hang — the wait is finite, got {:?}",
            elapsed
        );
    }

    /// Two connections sharing a rate-limited bucket both complete and the
    /// aggregate is paced to the cap (not doubled). The lock is provably NOT
    /// held during the sleep because `Bucket::charge` is synchronous and its
    /// guard is dropped before `RuleLimiter::charge` sleeps.
    #[tokio::test]
    async fn concurrent_charges_complete_and_pace_to_cap() {
        let r = RateLimit::new(Some(100_000), None);
        r.acquire_upload(100_000).await; // drain the burst
        let r2 = r.clone();
        let start = Instant::now();
        let h1 = tokio::spawn(async move { r.acquire_upload(50_000).await });
        let h2 = tokio::spawn(async move { r2.acquire_upload(50_000).await });
        h1.await.unwrap();
        h2.await.unwrap();
        // 100_000 bytes of debt at 100_000 B/s → the later charger waits ~1s;
        // both sleep concurrently, so total ≈ 1s (bounded, no deadlock).
        let elapsed = start.elapsed();
        assert!(
            (Duration::from_millis(800)..Duration::from_secs(3)).contains(&elapsed),
            "aggregate must pace to the cap, got {:?}",
            elapsed
        );
    }
}
