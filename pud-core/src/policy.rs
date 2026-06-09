//! Adaptive FEC policy and online loss estimation.
//!
//! Fixed redundancy wastes bandwidth on clean links and is too weak on bad
//! ones. We estimate the per-path loss rate with an exponentially weighted
//! moving average and size the parity to comfortably cover it.

use parking_lot::Mutex;

/// Exponentially weighted moving average loss estimator.
///
/// Feed it one sample per delivery attempt: `true` for a lost packet, `false`
/// for a delivered one. `rate()` returns the smoothed loss probability in
/// `[0, 1]`.
pub struct LossEstimator {
    inner: Mutex<f64>,
    alpha: f64,
}

impl LossEstimator {
    /// `alpha` is the smoothing factor (0 < alpha <= 1); larger reacts faster.
    pub fn new(alpha: f64) -> Self {
        LossEstimator {
            inner: Mutex::new(0.0),
            alpha: alpha.clamp(0.001, 1.0),
        }
    }

    /// Record one outcome.
    pub fn record(&self, lost: bool) {
        let sample = if lost { 1.0 } else { 0.0 };
        let mut r = self.inner.lock();
        *r = self.alpha * sample + (1.0 - self.alpha) * *r;
    }

    /// Record a batch: `lost` of `total` packets were lost.
    pub fn record_batch(&self, lost: u32, total: u32) {
        if total == 0 {
            return;
        }
        let sample = lost as f64 / total as f64;
        let mut r = self.inner.lock();
        *r = self.alpha * sample + (1.0 - self.alpha) * *r;
    }

    /// Current smoothed loss rate in `[0, 1]`.
    pub fn rate(&self) -> f64 {
        (*self.inner.lock()).clamp(0.0, 1.0)
    }
}

impl Default for LossEstimator {
    fn default() -> Self {
        LossEstimator::new(0.2)
    }
}

/// Bounds for adaptive parity selection.
#[derive(Debug, Clone, Copy)]
pub struct FecPolicy {
    /// Number of data shards per block.
    pub data_shards: u16,
    /// Minimum parity shards even on a clean link (covers sporadic loss).
    pub min_parity: u16,
    /// Hard cap on parity shards.
    pub max_parity: u16,
    /// Extra safety margin added on top of the loss-implied parity.
    pub safety_margin: u16,
}

impl Default for FecPolicy {
    fn default() -> Self {
        FecPolicy {
            data_shards: 8,
            min_parity: 1,
            max_parity: 16,
            safety_margin: 1,
        }
    }
}

impl FecPolicy {
    /// Choose how many parity shards to add for a given loss rate.
    ///
    /// To deliver `k` data shards across a link with loss `p`, we expect to need
    /// to send about `k / (1 - p)` shards, i.e. roughly `k * p / (1 - p)` parity
    /// shards, plus a safety margin. Clamped to `[min_parity, max_parity]`.
    pub fn parity_for_loss(&self, loss: f64) -> u16 {
        let p = loss.clamp(0.0, 0.95);
        let k = self.data_shards as f64;
        let implied = (k * p / (1.0 - p)).ceil() as i64 + self.safety_margin as i64;
        let clamped = implied.clamp(self.min_parity as i64, self.max_parity as i64);
        clamped as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimator_converges() {
        let est = LossEstimator::new(0.3);
        for _ in 0..200 {
            est.record(true);
        }
        assert!(est.rate() > 0.95);
        for _ in 0..200 {
            est.record(false);
        }
        assert!(est.rate() < 0.05);
    }

    #[test]
    fn estimator_batch() {
        let est = LossEstimator::new(1.0); // fully reactive
        est.record_batch(3, 10);
        assert!((est.rate() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn parity_scales_with_loss() {
        let pol = FecPolicy::default();
        let clean = pol.parity_for_loss(0.0);
        let mid = pol.parity_for_loss(0.2);
        let bad = pol.parity_for_loss(0.5);
        assert!(clean <= mid);
        assert!(mid <= bad);
        assert_eq!(clean, pol.min_parity.max(pol.safety_margin).min(pol.max_parity));
        assert!(bad <= pol.max_parity);
    }

    #[test]
    fn parity_never_exceeds_max() {
        let pol = FecPolicy::default();
        assert!(pol.parity_for_loss(0.99) <= pol.max_parity);
    }
}
