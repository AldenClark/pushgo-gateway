//! One process-wide request budget per external Provider. Ordinary delivery
//! reserves before claim and retains its permit until the receipt commits.
//! Other business paths borrow the same fair semaphore for their owned attempt.
use std::sync::Arc;

use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct ProviderBudgets {
    pub(crate) apns: Arc<Semaphore>,
    pub(crate) fcm: Arc<Semaphore>,
    pub(crate) wns: Arc<Semaphore>,
    limits: [usize; 3],
}

impl ProviderBudgets {
    #[cfg(feature = "qa")]
    pub(crate) fn resource_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "order": ["FCM", "APNS", "WNS"],
            "limits": self.limits,
            "available": [self.fcm.available_permits(), self.apns.available_permits(), self.wns.available_permits()],
            "scope": "one shared product budget; ordinary claims, network and receipt waits plus retained business users"
        })
    }

    pub(crate) fn new(apns: usize, fcm: usize, wns: usize) -> Self {
        assert!(
            [apns, fcm, wns]
                .iter()
                .all(|limit| *limit > 0 && *limit <= Semaphore::MAX_PERMITS)
        );
        Self {
            apns: Arc::new(Semaphore::new(apns)),
            fcm: Arc::new(Semaphore::new(fcm)),
            wns: Arc::new(Semaphore::new(wns)),
            limits: [fcm, apns, wns],
        }
    }

    pub(crate) fn for_provider(&self, provider: &str) -> Arc<Semaphore> {
        match provider {
            "APNS" | "APNS_LIVE_ACTIVITY" | "APNS_WIDGETS" => Arc::clone(&self.apns),
            "FCM" => Arc::clone(&self.fcm),
            "WNS" => Arc::clone(&self.wns),
            _ => unreachable!("unknown Provider budget"),
        }
    }

    pub(crate) fn limit(&self, provider: &str) -> usize {
        self.limits[match provider {
            "FCM" => 0,
            "APNS" | "APNS_LIVE_ACTIVITY" | "APNS_WIDGETS" => 1,
            "WNS" => 2,
            _ => unreachable!("unknown Provider budget"),
        }]
    }
}
