//! Fixed-memory timing summaries. Bucket quantiles are upper bounds, not exact
//! sampled percentiles; all durations are recorded after the named phase ends.
use serde_json::{Value, json};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

pub struct Histogram {
    buckets: [AtomicU64; 32],
    total_us: AtomicU64,
    max_us: AtomicU64,
}
impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            total_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }
}
impl Histogram {
    pub fn record(&self, duration: Duration) {
        let us = duration.as_micros().min(u64::MAX as u128) as u64;
        let bucket = (64 - us.leading_zeros()).min(31) as usize;
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
    }
    pub(crate) fn has_samples(&self) -> bool {
        self.buckets
            .iter()
            .any(|bucket| bucket.load(Ordering::Relaxed) != 0)
    }
    pub fn snapshot(&self) -> Value {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let count: u64 = counts.iter().sum();
        let quantile = |percent: u64| -> Option<u64> {
            if count == 0 {
                return None;
            }
            let threshold = count.saturating_mul(percent).div_ceil(100);
            let mut total = 0;
            for (index, n) in counts.iter().enumerate() {
                total += n;
                if total >= threshold {
                    return Some(if index == 31 {
                        u64::MAX
                    } else {
                        (1_u64 << index) - 1
                    });
                }
            }
            None
        };
        json!({"samples":count,"total_us":self.total_us.load(Ordering::Relaxed),"max_us":self.max_us.load(Ordering::Relaxed),"p50_upper_us":quantile(50),"p95_upper_us":quantile(95),"p99_upper_us":quantile(99),"buckets":counts})
    }
}
#[derive(Default)]
pub struct Timings {
    pub admission: Histogram,
    pub queue: Histogram,
    pub network: Histogram,
    pub receipt: Histogram,
    pub receipt_commit: Histogram,
    pub end_to_end: Histogram,
}
impl Timings {
    pub fn snapshot(&self) -> Value {
        json!({"admission":self.admission.snapshot(),"queue":self.queue.snapshot(),"network":self.network.snapshot(),"receipt":self.receipt.snapshot(),"receipt_commit":self.receipt_commit.snapshot(),"end_to_end":self.end_to_end.snapshot(),"quantile_semantics":"log2 microsecond bucket upper bounds; end_to_end ends after durable receipt commit; queue ends before provider credential/network execution"})
    }
}
