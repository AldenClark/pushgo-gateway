//! Fixed-cardinality profiling for QA/tests. Normal product builds retain only
//! zero-sized pass-through guards; they do not read clocks or update these
//! histograms. Observed wall times include executor/worker queues and SQLite
//! trigger work, never trigger-exclusive time.
#[cfg(any(test, feature = "qa"))]
use crate::ordinary::metrics::Histogram;
#[cfg(any(test, feature = "qa"))]
use serde_json::Map;
use serde_json::{Value, json};
use std::future::Future;
#[cfg(any(test, feature = "qa"))]
use std::time::Instant;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Path {
    Accept,
    Fanout,
    Claim,
    Ack,
    Receipt,
    Maintenance,
    Control,
    Read,
}
#[cfg(any(test, feature = "qa"))]
const PATHS: [&str; 8] = [
    "accept",
    "fanout",
    "claim",
    "ack",
    "receipt",
    "maintenance",
    "control",
    "read",
];

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Phase {
    GateWait,
    GateHold,
    PoolAcquire,
    Begin,
    StatementInclusive,
    Commit,
    Auth,
    Compute,
}
#[cfg(any(test, feature = "qa"))]
const PHASES: [&str; 8] = [
    "gate_wait",
    "gate_hold",
    "pool_acquire",
    "begin",
    "statement_inclusive",
    "commit",
    "auth",
    "compute",
];

/// Fixed labels, never SQL text, identities, parameters, or request data.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Statement {
    Auth,
    Dedupe,
    Usage,
    FanoutCount,
    MessageInsert,
    FanoutInsert,
    MaintenanceRetired,
    MaintenanceSubscriptions,
    MaintenanceTargets,
    MaintenanceDevice,
    MaintenanceAliases,
    MaintenanceExpiryCount,
    MaintenanceExpiryAck,
    MaintenanceExpiryStatus,
    MaintenanceExpiryDelete,
    MaintenanceExpiryPayload,
    MaintenanceRetention,
    ClaimCooldown,
    ClaimSelect,
    ClaimUpdate,
    ClaimNextDue,
    ClaimRetiring,
    AckUpdate,
    ReleaseStatus,
    ReleaseTarget,
    ReleasePayload,
    ReceiptTarget,
    ReceiptCooldown,
    ReceiptSubscription,
    ReceiptCounts,
    ReceiptStatus,
    Control,
    Read,
}
#[cfg(any(test, feature = "qa"))]
const STATEMENTS: [&str; 33] = [
    "auth",
    "dedupe",
    "usage",
    "fanout_count",
    "message_insert",
    "fanout_insert",
    "maintenance_retired",
    "maintenance_subscriptions",
    "maintenance_targets",
    "maintenance_device",
    "maintenance_aliases",
    "maintenance_expiry_count",
    "maintenance_expiry_ack",
    "maintenance_expiry_status",
    "maintenance_expiry_delete",
    "maintenance_expiry_payload",
    "maintenance_retention",
    "claim_cooldown",
    "claim_select",
    "claim_update",
    "claim_next_due",
    "claim_retiring",
    "ack_update",
    "release_status",
    "release_target",
    "release_payload",
    "receipt_target",
    "receipt_cooldown",
    "receipt_subscription",
    "receipt_counts",
    "receipt_status",
    "control",
    "read",
];

pub struct Profile {
    #[cfg(any(test, feature = "qa"))]
    phases: [[Histogram; PHASES.len()]; PATHS.len()],
    #[cfg(any(test, feature = "qa"))]
    statements: [[Histogram; STATEMENTS.len()]; PATHS.len()],
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            #[cfg(any(test, feature = "qa"))]
            phases: std::array::from_fn(|_| std::array::from_fn(|_| Histogram::default())),
            #[cfg(any(test, feature = "qa"))]
            statements: std::array::from_fn(|_| std::array::from_fn(|_| Histogram::default())),
        }
    }
}
/// Records on all exits, including errors and cancellation. A cancelled operation
/// can continue on SQLx's worker; this is caller lifetime, not worker completion.
pub struct Timer<'a> {
    #[cfg(any(test, feature = "qa"))]
    histogram: &'a Histogram,
    #[cfg(any(test, feature = "qa"))]
    started: Instant,
    #[cfg(not(any(test, feature = "qa")))]
    lifetime: std::marker::PhantomData<&'a ()>,
}
impl Drop for Timer<'_> {
    #[cfg_attr(not(any(test, feature = "qa")), inline)]
    fn drop(&mut self) {
        #[cfg(any(test, feature = "qa"))]
        self.histogram.record(self.started.elapsed());
    }
}

// Keep the normal-build resource promise mechanically checked by every
// non-QA product compilation, not just by a QA-flavoured unit test.
#[cfg(not(any(test, feature = "qa")))]
const _: () = {
    assert!(std::mem::size_of::<Profile>() == 0);
    assert!(std::mem::size_of::<Timer<'static>>() == 0);
};

impl Profile {
    #[cfg_attr(not(any(test, feature = "qa")), inline)]
    pub fn timer(&self, path: Path, phase: Phase) -> Timer<'_> {
        #[cfg(not(any(test, feature = "qa")))]
        let _ = (path, phase);
        Timer {
            #[cfg(any(test, feature = "qa"))]
            histogram: &self.phases[path as usize][phase as usize],
            #[cfg(any(test, feature = "qa"))]
            started: Instant::now(),
            #[cfg(not(any(test, feature = "qa")))]
            lifetime: std::marker::PhantomData,
        }
    }
    #[cfg_attr(not(any(test, feature = "qa")), inline)]
    pub async fn phase<F: Future>(&self, path: Path, phase: Phase, future: F) -> F::Output {
        #[cfg(any(test, feature = "qa"))]
        let _timer = self.timer(path, phase);
        #[cfg(not(any(test, feature = "qa")))]
        let _ = (path, phase);
        future.await
    }
    #[cfg_attr(not(any(test, feature = "qa")), inline)]
    pub async fn sql<F: Future>(&self, path: Path, statement: Statement, future: F) -> F::Output {
        #[cfg(any(test, feature = "qa"))]
        let _phase = self.timer(path, Phase::StatementInclusive);
        #[cfg(any(test, feature = "qa"))]
        let _statement = Timer {
            histogram: &self.statements[path as usize][statement as usize],
            started: Instant::now(),
        };
        #[cfg(not(any(test, feature = "qa")))]
        let _ = (path, statement);
        future.await
    }
    #[cfg(any(test, feature = "qa"))]
    pub fn snapshot(&self) -> Value {
        let mut paths = Map::new();
        for (p, name) in PATHS.iter().enumerate() {
            let phases: Map<String, Value> = PHASES
                .iter()
                .enumerate()
                .map(|(n, label)| (label.to_string(), self.phases[p][n].snapshot()))
                .collect();
            let statements: Map<String, Value> = STATEMENTS
                .iter()
                .enumerate()
                .filter(|(n, _)| self.statements[p][*n].has_samples())
                .map(|(n, label)| (label.to_string(), self.statements[p][n].snapshot()))
                .collect();
            paths.insert(
                name.to_string(),
                json!({"phases": phases, "statements": statements}),
            );
        }
        json!({"paths": paths, "semantics": "fixed log2 microsecond histograms; unused statement labels omitted from snapshot; samples count observed calls, including error/cancel exits; statement_inclusive includes trigger work and SQLx dispatch/results; pool_acquire is pool queue plus checkout; begin is worker queue plus BEGIN after checkout; commit is worker queue plus COMMIT; gate_hold can contain nested fanout/maintenance timers, never sum nested totals as independent time"})
    }

    #[cfg(not(any(test, feature = "qa")))]
    pub fn snapshot(&self) -> Value {
        json!({"enabled": false, "scope": "per-statement profiling exists only in QA/test builds"})
    }
}
