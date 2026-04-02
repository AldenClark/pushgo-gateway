use std::collections::{BTreeMap, BinaryHeap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use flume::{Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use tokio::time::Instant as TokioInstant;
use warp_link::warp_link_core::{SessionControl, SessionCoordinator, TransportKind};
use warp_link_coordination::InMemoryCoordinator;

use crate::{
    dispatch::{ApnsJob, DispatchChannels, FcmJob, WnsJob},
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    routing::DeviceRegistry,
    stats::StatsCollector,
    storage::{
        DeviceId, MaintenanceCleanupStats, Platform, PrivateMessage, PrivateOutboxEntry, Storage,
    },
    util::{SharedStringMap, decode_lower_hex_128, encode_lower_hex_128},
};

pub mod metrics;
pub mod protocol;
pub mod quic;
pub mod tcp;
pub mod warp_engine;
pub mod ws;

#[path = "hub.rs"]
mod hub;
#[path = "state/mod.rs"]
mod state;

pub use hub::{ConnectionMode, PrivateHub, ResumeHandshake};
use state::EnqueuePrivateMessageOutcome;
pub use state::PrivateState;
pub(crate) use state::{BootstrapQueues, RegisterConnectionOutcome, RetransmitPollResult};

const MAINTENANCE_INTERVAL_SECS: i64 = 60;
const FALLBACK_TASK_COMMAND_CAPACITY: usize = 65_536;
const CLAIM_ACK_ACTIVE_MAX_ROUNDS: usize = 4;
const CLAIM_ACK_IDLE_MAX_ROUNDS: usize = 1;
const CLAIM_ACK_ACTIVE_PROCESS_BUDGET: usize = 4_096;
const CLAIM_ACK_IDLE_PROCESS_BUDGET: usize = 256;
const FALLBACK_SCHEDULER_COMPACT_MIN_HEAP: usize = 8_192;
const FALLBACK_SCHEDULER_COMPACT_MIN_STALE: usize = 2_048;
const FALLBACK_SCHEDULER_COMPACT_RATIO: usize = 3;
const PRIVATE_DRAINING_DELIVERY_WINDOW_MIN: Duration = Duration::from_secs(8);
const PRIVATE_DRAINING_DELIVERY_WINDOW_MAX: Duration = Duration::from_secs(30);
const PRIVATE_DRAINING_DELIVERY_WINDOW_DEFAULT: Duration = Duration::from_secs(12);
const PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_MULTIPLIER: f64 = 4.0;
const PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_PADDING_MS: f64 = 2_000.0;
const PRIVATE_DEFAULT_TTL_SECONDS_MAX: i64 = 30 * 24 * 60 * 60;
const PROVIDER_WAKEUP_PULL_ENABLED: bool = false;

#[inline]
const fn provider_wakeup_pull_enabled() -> bool {
    PROVIDER_WAKEUP_PULL_ENABLED
}

#[derive(Debug, Clone)]
pub struct PrivateConfig {
    pub private_quic_bind: Option<String>,
    pub private_tcp_bind: Option<String>,
    pub tcp_tls_offload: bool,
    pub tcp_proxy_protocol: bool,
    pub private_tls_cert_path: Option<String>,
    pub private_tls_key_path: Option<String>,
    pub session_ttl_secs: i64,
    pub grace_window_secs: u64,
    pub max_pending_per_device: usize,
    pub global_max_pending: usize,
    pub pull_limit: usize,
    pub ack_timeout_secs: u64,
    pub fallback_max_attempts: u32,
    pub fallback_max_backoff_secs: u64,
    pub retransmit_window_secs: u64,
    pub retransmit_max_per_window: u32,
    pub retransmit_max_per_tick: usize,
    pub retransmit_max_retries: u8,
    pub hot_cache_capacity: usize,
    pub default_ttl_secs: i64,
    pub gateway_token: Option<String>,
}

impl PrivateConfig {
    pub fn normalized(mut self) -> Self {
        self.default_ttl_secs = Self::normalize_default_ttl_secs(self.default_ttl_secs);
        self
    }

    pub fn normalize_default_ttl_secs(ttl_secs: i64) -> i64 {
        if ttl_secs <= 0 {
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        } else {
            ttl_secs.min(PRIVATE_DEFAULT_TTL_SECONDS_MAX)
        }
    }

    fn require_tls_identity(
        &self,
        missing_cert_message: &'static str,
        missing_key_message: &'static str,
    ) -> Result<(String, String), crate::Error> {
        let cert_path = self
            .private_tls_cert_path
            .clone()
            .ok_or_else(|| crate::Error::Internal(missing_cert_message.to_string()))?;
        let key_path = self
            .private_tls_key_path
            .clone()
            .ok_or_else(|| crate::Error::Internal(missing_key_message.to_string()))?;
        Ok((cert_path, key_path))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptBudget, FallbackAttemptPolicy, PRIVATE_DEFAULT_TTL_SECONDS_MAX, PrivateConfig,
    };

    #[test]
    fn private_default_ttl_is_clamped_to_max() {
        assert_eq!(
            PrivateConfig::normalize_default_ttl_secs(PRIVATE_DEFAULT_TTL_SECONDS_MAX + 1),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
        assert_eq!(
            PrivateConfig::normalize_default_ttl_secs(90 * 24 * 60 * 60),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn private_default_ttl_uses_max_for_non_positive_values() {
        assert_eq!(
            PrivateConfig::normalize_default_ttl_secs(0),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
        assert_eq!(
            PrivateConfig::normalize_default_ttl_secs(-1),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn private_default_ttl_keeps_valid_small_values() {
        assert_eq!(PrivateConfig::normalize_default_ttl_secs(1), 1);
        assert_eq!(
            PrivateConfig::normalize_default_ttl_secs(PRIVATE_DEFAULT_TTL_SECONDS_MAX),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn retry_attempt_budget_can_be_disabled() {
        let policy = FallbackAttemptPolicy {
            max_attempts: 5,
            ack_timeout_secs: 1,
            max_backoff_secs: 1,
        };
        assert!(!policy.should_drop_attempt(5, AttemptBudget::Unlimited));
        assert!(!policy.should_drop_attempt(50, AttemptBudget::Unlimited));
    }

    #[test]
    fn retry_attempt_budget_applies_when_enabled() {
        let policy = FallbackAttemptPolicy {
            max_attempts: 5,
            ack_timeout_secs: 1,
            max_backoff_secs: 1,
        };
        assert!(!policy.should_drop_attempt(4, AttemptBudget::Enforced));
        assert!(policy.should_drop_attempt(5, AttemptBudget::Enforced));
    }

    #[test]
    fn retry_attempt_budget_zero_means_unbounded() {
        let policy = FallbackAttemptPolicy {
            max_attempts: 0,
            ack_timeout_secs: 1,
            max_backoff_secs: 1,
        };
        assert!(!policy.should_drop_attempt(10_000, AttemptBudget::Enforced));
    }
}

#[derive(Debug)]
struct FallbackTaskEngine {
    tx: Sender<FallbackTaskCommand>,
    rx: Mutex<Option<Receiver<FallbackTaskCommand>>>,
    depth: AtomicUsize,
    resync_requested: AtomicBool,
    resync_notify: tokio::sync::Notify,
}

impl FallbackTaskEngine {
    fn new() -> Arc<Self> {
        let (tx, rx) = flume::bounded(FALLBACK_TASK_COMMAND_CAPACITY);
        Arc::new(Self {
            tx,
            rx: Mutex::new(Some(rx)),
            depth: AtomicUsize::new(0),
            resync_requested: AtomicBool::new(false),
            resync_notify: tokio::sync::Notify::new(),
        })
    }

    fn take_receiver(&self) -> Option<Receiver<FallbackTaskCommand>> {
        self.rx.lock().take()
    }

    fn schedule(&self, device_id: DeviceId, delivery_id: String, due_at_unix_secs: i64) -> bool {
        let sent = self
            .tx
            .try_send(FallbackTaskCommand::schedule(
                FallbackTaskKey::new(device_id, delivery_id),
                due_at_unix_secs,
            ))
            .is_ok();
        if !sent {
            self.request_resync();
        }
        sent
    }

    fn cancel(&self, device_id: DeviceId, delivery_id: &str) -> bool {
        let sent = self
            .tx
            .try_send(FallbackTaskCommand::cancel(FallbackTaskKey::new(
                device_id,
                delivery_id.to_string(),
            )))
            .is_ok();
        if !sent {
            self.request_resync();
        }
        sent
    }

    fn mark_depth(&self, value: usize) {
        self.depth.store(value, Ordering::Relaxed);
    }

    fn depth(&self) -> usize {
        self.depth.load(Ordering::Relaxed)
    }

    fn request_resync(&self) {
        self.resync_requested.store(true, Ordering::Relaxed);
        self.resync_notify.notify_one();
    }

    fn consume_resync_request(&self) -> bool {
        self.resync_requested.swap(false, Ordering::Relaxed)
    }

    fn sync_scheduler_depth(&self, state: &PrivateState, scheduler: &FallbackScheduler) {
        let depth = scheduler.depth();
        self.mark_depth(depth);
        state.metrics.mark_task_queue_depth(depth);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FallbackTaskKey {
    device_id: DeviceId,
    delivery_id: String,
}

impl FallbackTaskKey {
    fn new(device_id: DeviceId, delivery_id: impl Into<String>) -> Self {
        Self {
            device_id,
            delivery_id: delivery_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SchedulerTaskKey {
    Fallback(FallbackTaskKey),
    Maintenance,
}

#[derive(Debug, Clone)]
enum FallbackTaskCommand {
    Schedule {
        key: FallbackTaskKey,
        due_at_unix_secs: i64,
    },
    Cancel {
        key: FallbackTaskKey,
    },
}

impl FallbackTaskCommand {
    fn schedule(key: FallbackTaskKey, due_at_unix_secs: i64) -> Self {
        Self::Schedule {
            key,
            due_at_unix_secs,
        }
    }

    fn cancel(key: FallbackTaskKey) -> Self {
        Self::Cancel { key }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FallbackTaskEntry {
    due_at_unix_secs: i64,
    sequence: u64,
    key: SchedulerTaskKey,
}

impl Ord for FallbackTaskEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .due_at_unix_secs
            .cmp(&self.due_at_unix_secs)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for FallbackTaskEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PrivateState {
    pub(crate) fn spawn_persistent_fallback_worker(self: &Arc<Self>, dispatch: DispatchChannels) {
        let Some(engine) = self.fallback_tasks.clone() else {
            return;
        };
        let Some(rx) = engine.take_receiver() else {
            return;
        };
        let state = Arc::clone(self);

        tokio::spawn(async move {
            let runtime = FallbackRuntime::new(Arc::clone(&state), dispatch);
            let mut scheduler = FallbackScheduler::default();
            runtime.seed_fallback_tasks(&mut scheduler).await;
            scheduler.schedule_maintenance(
                chrono::Utc::now()
                    .timestamp()
                    .saturating_add(MAINTENANCE_INTERVAL_SECS),
            );
            engine.sync_scheduler_depth(&state, &scheduler);

            loop {
                if state.is_shutting_down() {
                    break;
                }
                if engine.consume_resync_request() {
                    if let Err(_err) = runtime.resync_fallback_tasks(&mut scheduler, 200_000).await
                    {
                    }
                    engine.sync_scheduler_depth(&state, &scheduler);
                }
                let wake_at =
                    FallbackRuntime::wake_at(scheduler.next_due_unix_secs().unwrap_or(i64::MAX));

                tokio::select! {
                    maybe_cmd = rx.recv_async() => {
                        let Ok(cmd) = maybe_cmd else {
                            break;
                        };
                        scheduler.apply(cmd);
                        engine.sync_scheduler_depth(&state, &scheduler);
                    }
                    _ = engine.resync_notify.notified() => {}
                    _ = state.wait_for_shutdown() => break,
                    _ = tokio::time::sleep_until(wake_at) => {
                        let now = chrono::Utc::now().timestamp();
                        let due_tasks = scheduler.pop_due(now, 1024);
                        if !due_tasks.is_empty() {
                            let mut max_lag_ms = 0u64;
                            let mut run_claim_worker = false;
                            for (key, due_at_unix_secs) in due_tasks {
                                let lag_secs = now.saturating_sub(due_at_unix_secs);
                                max_lag_ms = max_lag_ms.max((lag_secs as u64).saturating_mul(1000));
                                match key {
                                    SchedulerTaskKey::Maintenance => {
                                        if let Err(_err) = runtime.run_maintenance_tick().await {}
                                        scheduler.schedule_maintenance(
                                            now.saturating_add(MAINTENANCE_INTERVAL_SECS),
                                        );
                                        run_claim_worker = true;
                                    }
                                    SchedulerTaskKey::Fallback(_) => run_claim_worker = true,
                                }
                            }
                            if run_claim_worker
                                && let Err(_err) =
                                    runtime.run_claim_ack_drain(
                                        &mut scheduler,
                                        1024,
                                        CLAIM_ACK_ACTIVE_MAX_ROUNDS,
                                        CLAIM_ACK_ACTIVE_PROCESS_BUDGET,
                                    )
                                    .await
                            {
                            }
                            if max_lag_ms > 0 {
                                state.metrics.mark_task_lag_ms(max_lag_ms);
                            }
                        } else if let Err(_err) =
                            runtime.run_claim_ack_drain(
                                &mut scheduler,
                                256,
                                CLAIM_ACK_IDLE_MAX_ROUNDS,
                                CLAIM_ACK_IDLE_PROCESS_BUDGET,
                            )
                            .await
                        {
                        }
                        engine.sync_scheduler_depth(&state, &scheduler);
                    }
                }
            }
        });
    }
}

include!("runtime_tasks.rs");
