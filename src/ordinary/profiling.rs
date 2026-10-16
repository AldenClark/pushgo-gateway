//! Fixed-cardinality profiling. These wall times include executor/worker queues;
//! statement time includes SQLite triggers and is never trigger-exclusive time.
use crate::ordinary::metrics::Histogram;
use serde_json::{Map, Value, json};
use std::{future::Future, time::Instant};

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
    phases: [[Histogram; PHASES.len()]; PATHS.len()],
    statements: [[Histogram; STATEMENTS.len()]; PATHS.len()],
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            phases: std::array::from_fn(|_| std::array::from_fn(|_| Histogram::default())),
            statements: std::array::from_fn(|_| std::array::from_fn(|_| Histogram::default())),
        }
    }
}
/// Records on all exits, including errors and cancellation. A cancelled operation
/// can continue on SQLx's worker; this is caller lifetime, not worker completion.
pub struct Timer<'a> {
    histogram: &'a Histogram,
    started: Instant,
}
impl Drop for Timer<'_> {
    fn drop(&mut self) {
        self.histogram.record(self.started.elapsed());
    }
}
impl Profile {
    pub fn timer(&self, path: Path, phase: Phase) -> Timer<'_> {
        Timer {
            histogram: &self.phases[path as usize][phase as usize],
            started: Instant::now(),
        }
    }
    pub async fn phase<F: Future>(&self, path: Path, phase: Phase, future: F) -> F::Output {
        let _timer = self.timer(path, phase);
        future.await
    }
    pub async fn sql<F: Future>(&self, path: Path, statement: Statement, future: F) -> F::Output {
        let _phase = self.timer(path, Phase::StatementInclusive);
        let _statement = Timer {
            histogram: &self.statements[path as usize][statement as usize],
            started: Instant::now(),
        };
        future.await
    }
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
}
