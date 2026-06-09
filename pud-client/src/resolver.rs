//! Multipath resolver pool.
//!
//! Tunnel queries are spread across many resolvers to multiply throughput and
//! beat per-resolver rate limits. Each resolver tracks a smoothed RTT and a
//! failure count; repeatedly failing resolvers are temporarily benched so the
//! pool routes around dead paths during a shutdown.

use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct ResolverStat {
    addr: SocketAddr,
    rtt_ms: f64,
    /// Smoothed RTT mean deviation (Jacobson/Karels), for adaptive RTO.
    rttvar_ms: f64,
    samples: u64,
    consecutive_fails: u32,
    disabled_until: Option<Instant>,
    /// How many times this resolver has been benched; drives exponential
    /// backoff so chronically bad paths are rested longer.
    disable_count: u32,
    /// Discovered downlink (response) MTU for this resolver; 0 = not yet set,
    /// in which case callers substitute the configured floor.
    down_mtu: u16,
}

/// A pool of resolvers with round-robin selection and health tracking.
pub struct ResolverPool {
    stats: Mutex<Vec<ResolverStat>>,
    cursor: AtomicUsize,
}

const FAIL_THRESHOLD: u32 = 3;
const BENCH_TIME: Duration = Duration::from_secs(8);
/// Never auto-disable a resolver if doing so would leave fewer than this many
/// active — better a lossy path than no path at all during a shutdown.
const MIN_ACTIVE: usize = 1;
/// Cap on the backoff exponent (BENCH_TIME * 2^n).
const MAX_BACKOFF_SHIFT: u32 = 4;

impl ResolverPool {
    pub fn new(resolvers: Vec<SocketAddr>) -> Self {
        let stats = resolvers
            .into_iter()
            .map(|addr| ResolverStat {
                addr,
                rtt_ms: 0.0,
                rttvar_ms: 0.0,
                samples: 0,
                consecutive_fails: 0,
                disabled_until: None,
                disable_count: 0,
                down_mtu: 0,
            })
            .collect();
        ResolverPool {
            stats: Mutex::new(stats),
            cursor: AtomicUsize::new(0),
        }
    }

    /// Pick the next resolver, skipping benched ones. If all are benched, clear
    /// the benches and pick anyway (better to try than to stall).
    pub fn pick(&self) -> SocketAddr {
        let now = Instant::now();
        let mut stats = self.stats.lock();
        let len = stats.len();
        debug_assert!(len > 0);

        for stat in stats.iter_mut() {
            if let Some(until) = stat.disabled_until {
                if until <= now {
                    stat.disabled_until = None;
                    stat.consecutive_fails = 0;
                }
            }
        }

        for _ in 0..len {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
            if stats[idx].disabled_until.is_none() {
                return stats[idx].addr;
            }
        }

        // Everyone is benched: reset and use the round-robin slot.
        for stat in stats.iter_mut() {
            stat.disabled_until = None;
            stat.consecutive_fails = 0;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
        stats[idx].addr
    }

    /// Refresh benches that have expired (called under the stats lock).
    fn unbench_expired(stats: &mut [ResolverStat], now: Instant) {
        for stat in stats.iter_mut() {
            if let Some(until) = stat.disabled_until {
                if until <= now {
                    stat.disabled_until = None;
                    stat.consecutive_fails = 0;
                }
            }
        }
    }

    /// Effective RTT used for weighting; unsampled resolvers get an optimistic
    /// default so they are explored.
    fn effective_rtt(stat: &ResolverStat) -> f64 {
        if stat.samples == 0 {
            100.0
        } else {
            stat.rtt_ms.max(1.0)
        }
    }

    /// Pick a resolver with probability inversely proportional to its smoothed
    /// RTT, so faster resolvers are favored while all healthy ones still rotate.
    pub fn pick_weighted(&self) -> SocketAddr {
        let now = Instant::now();
        let mut stats = self.stats.lock();
        let len = stats.len();
        debug_assert!(len > 0);
        Self::unbench_expired(&mut stats, now);

        let healthy: Vec<usize> = (0..len)
            .filter(|&i| stats[i].disabled_until.is_none())
            .collect();
        if healthy.is_empty() {
            // All benched: fall back to round-robin (pick clears benches there).
            drop(stats);
            return self.pick();
        }

        let total: f64 = healthy.iter().map(|&i| 1.0 / Self::effective_rtt(&stats[i])).sum();
        let mut dart = rand::random::<f64>() * total;
        for &i in &healthy {
            let w = 1.0 / Self::effective_rtt(&stats[i]);
            if dart < w {
                return stats[i].addr;
            }
            dart -= w;
        }
        stats[*healthy.last().unwrap()].addr
    }

    /// Pick a primary resolver plus a distinct fast secondary for stall-racing.
    /// The secondary is the lowest-RTT healthy resolver other than the primary,
    /// or `None` when only one healthy resolver exists.
    pub fn pick_pair(&self) -> (SocketAddr, Option<SocketAddr>) {
        let primary = self.pick_weighted();
        let now = Instant::now();
        let mut stats = self.stats.lock();
        Self::unbench_expired(&mut stats, now);
        let secondary = stats
            .iter()
            .filter(|s| s.addr != primary && s.disabled_until.is_none())
            .min_by(|a, b| {
                Self::effective_rtt(a)
                    .partial_cmp(&Self::effective_rtt(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.addr);
        (primary, secondary)
    }

    /// Smoothed RTT and variance (milliseconds) for a resolver, if sampled.
    pub fn stats_for(&self, addr: SocketAddr) -> Option<(f64, f64)> {
        let stats = self.stats.lock();
        stats
            .iter()
            .find(|s| s.addr == addr && s.samples > 0)
            .map(|s| (s.rtt_ms, s.rttvar_ms))
    }

    /// The list of configured resolver addresses (for per-resolver tasks).
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.stats.lock().iter().map(|s| s.addr).collect()
    }

    /// Discovered downlink MTU for `addr`, or `floor` if none discovered yet.
    pub fn down_mtu(&self, addr: SocketAddr, floor: u16) -> u16 {
        let stats = self.stats.lock();
        match stats.iter().find(|s| s.addr == addr) {
            Some(s) if s.down_mtu > 0 => s.down_mtu,
            _ => floor,
        }
    }

    /// Record a discovered downlink MTU for `addr`.
    pub fn set_down_mtu(&self, addr: SocketAddr, mtu: u16) {
        let mut stats = self.stats.lock();
        if let Some(s) = stats.iter_mut().find(|s| s.addr == addr) {
            s.down_mtu = mtu;
        }
    }

    /// Adaptive retransmit timeout for `addr` = srtt + 4·rttvar, clamped to
    /// `[min, max]`. Unsampled resolvers get the ceiling.
    pub fn rto(&self, addr: SocketAddr, min: Duration, max: Duration) -> Duration {
        match self.stats_for(addr) {
            Some((srtt, rttvar)) => {
                let ms = srtt + 4.0 * rttvar;
                let dur = Duration::from_secs_f64((ms / 1000.0).max(0.0));
                dur.clamp(min, max)
            }
            None => max,
        }
    }

    pub fn record_ok(&self, addr: SocketAddr, rtt: Duration) {
        let mut stats = self.stats.lock();
        if let Some(stat) = stats.iter_mut().find(|s| s.addr == addr) {
            let sample = rtt.as_secs_f64() * 1000.0;
            if stat.samples == 0 {
                stat.rtt_ms = sample;
                stat.rttvar_ms = sample / 2.0;
            } else {
                // Jacobson/Karels smoothing, as in TCP RTO estimation.
                let err = (sample - stat.rtt_ms).abs();
                stat.rttvar_ms = 0.75 * stat.rttvar_ms + 0.25 * err;
                stat.rtt_ms = 0.875 * stat.rtt_ms + 0.125 * sample;
            }
            stat.samples += 1;
            stat.consecutive_fails = 0;
            stat.disabled_until = None;
            stat.disable_count = 0;
        }
    }

    pub fn record_fail(&self, addr: SocketAddr) {
        let mut stats = self.stats.lock();
        // Confirmation: never disable if it would leave too few active paths.
        let active = stats.iter().filter(|s| s.disabled_until.is_none()).count();
        if let Some(stat) = stats.iter_mut().find(|s| s.addr == addr) {
            stat.consecutive_fails += 1;
            if stat.consecutive_fails >= FAIL_THRESHOLD && active > MIN_ACTIVE {
                let backoff = BENCH_TIME * (1 << stat.disable_count.min(MAX_BACKOFF_SHIFT));
                stat.disabled_until = Some(Instant::now() + backoff);
                stat.disable_count = stat.disable_count.saturating_add(1);
            }
        }
    }

    /// Number of resolvers not currently benched.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        self.stats
            .lock()
            .iter()
            .filter(|s| s.disabled_until.map(|u| u <= now).unwrap_or(true))
            .count()
    }

    /// Addresses currently benched (for background health checks).
    pub fn benched(&self) -> Vec<SocketAddr> {
        let now = Instant::now();
        self.stats
            .lock()
            .iter()
            .filter(|s| s.disabled_until.map(|u| u > now).unwrap_or(false))
            .map(|s| s.addr)
            .collect()
    }

    /// Bring a benched resolver back after a successful background health check.
    pub fn revive(&self, addr: SocketAddr) {
        let mut stats = self.stats.lock();
        if let Some(stat) = stats.iter_mut().find(|s| s.addr == addr) {
            stat.disabled_until = None;
            stat.consecutive_fails = 0;
        }
    }

    /// Snapshot of (addr, smoothed rtt ms, samples, benched) for logging.
    pub fn snapshot(&self) -> Vec<(SocketAddr, f64, u64, bool)> {
        let now = Instant::now();
        self.stats
            .lock()
            .iter()
            .map(|s| {
                (
                    s.addr,
                    s.rtt_ms,
                    s.samples,
                    s.disabled_until.map(|u| u > now).unwrap_or(false),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn round_robins() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
        let first = pool.pick();
        let second = pool.pick();
        assert_ne!(first, second);
    }

    #[test]
    fn benches_after_failures() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
        for _ in 0..FAIL_THRESHOLD {
            pool.record_fail(a("1.1.1.1:53"));
        }
        // The benched resolver should not be returned (the other one is healthy).
        for _ in 0..10 {
            assert_eq!(pool.pick(), a("8.8.8.8:53"));
        }
    }

    #[test]
    fn recovers_when_all_benched() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53")]);
        for _ in 0..FAIL_THRESHOLD {
            pool.record_fail(a("1.1.1.1:53"));
        }
        // Only resolver is benched; pick must still return it.
        assert_eq!(pool.pick(), a("1.1.1.1:53"));
    }

    #[test]
    fn rtt_smoothing() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53")]);
        pool.record_ok(a("1.1.1.1:53"), Duration::from_millis(100));
        pool.record_ok(a("1.1.1.1:53"), Duration::from_millis(100));
        let snap = pool.snapshot();
        assert!((snap[0].1 - 100.0).abs() < 1.0);
        assert_eq!(snap[0].2, 2);
    }

    #[test]
    fn rto_unsampled_is_ceiling_and_clamps() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53")]);
        let min = Duration::from_millis(300);
        let max = Duration::from_millis(4000);
        // No samples yet -> the ceiling.
        assert_eq!(pool.rto(a("1.1.1.1:53"), min, max), max);
        // After steady ~100ms samples, RTO settles well under the ceiling and
        // never below the floor.
        for _ in 0..10 {
            pool.record_ok(a("1.1.1.1:53"), Duration::from_millis(100));
        }
        let rto = pool.rto(a("1.1.1.1:53"), min, max);
        assert!(rto >= min && rto < max, "rto={rto:?}");
    }

    #[test]
    fn pick_pair_gives_distinct_resolvers() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
        let (primary, secondary) = pool.pick_pair();
        assert!(secondary.is_some());
        assert_ne!(primary, secondary.unwrap());
    }

    #[test]
    fn pick_pair_single_resolver_has_no_secondary() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53")]);
        let (_primary, secondary) = pool.pick_pair();
        assert!(secondary.is_none());
    }

    #[test]
    fn down_mtu_defaults_to_floor_then_remembers() {
        let a1 = a("1.1.1.1:53");
        let a2 = a("8.8.8.8:53");
        let pool = ResolverPool::new(vec![a1, a2]);
        // Unset -> floor for each resolver.
        assert_eq!(pool.down_mtu(a1, 1232), 1232);
        assert_eq!(pool.down_mtu(a2, 1232), 1232);
        // Set one; the other is unaffected (per-resolver, not global).
        pool.set_down_mtu(a1, 2048);
        assert_eq!(pool.down_mtu(a1, 1232), 2048);
        assert_eq!(pool.down_mtu(a2, 1232), 1232);
        // Unknown resolver falls back to floor.
        assert_eq!(pool.down_mtu(a("9.9.9.9:53"), 1232), 1232);
    }

    #[test]
    fn addrs_lists_all_resolvers() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
        let mut got = pool.addrs();
        got.sort();
        assert_eq!(got, vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
    }

    #[test]
    fn never_disables_the_last_active_resolver() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53")]);
        for _ in 0..FAIL_THRESHOLD * 3 {
            pool.record_fail(a("1.1.1.1:53"));
        }
        // The only resolver must stay active rather than be benched.
        assert_eq!(pool.active_count(), 1);
        assert!(pool.benched().is_empty());
    }

    #[test]
    fn revive_brings_back_a_benched_resolver() {
        let pool = ResolverPool::new(vec![a("1.1.1.1:53"), a("8.8.8.8:53")]);
        for _ in 0..FAIL_THRESHOLD {
            pool.record_fail(a("1.1.1.1:53"));
        }
        assert_eq!(pool.benched(), vec![a("1.1.1.1:53")]);
        pool.revive(a("1.1.1.1:53"));
        assert!(pool.benched().is_empty());
        assert_eq!(pool.active_count(), 2);
    }
}
