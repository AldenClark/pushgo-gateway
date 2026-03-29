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
    device_registry::DeviceRegistry,
    dispatch::{ApnsJob, DispatchChannels, FcmJob, WnsJob},
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    stats::StatsCollector,
    storage::{
        DeviceId, MaintenanceCleanupStats, Platform, PrivateMessage, PrivateOutboxEntry, Storage,
    },
    util::{SharedStringMap, build_wakeup_data, decode_lower_hex_128, encode_lower_hex_128},
};

pub mod metrics;
pub mod protocol;
pub mod quic;
pub mod tcp;
pub mod warp_engine;
pub mod ws;

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
const PRIVATE_PROVIDER_WAKEUP_PULL_ENABLED: bool = false;

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        private_quic_bind: Option<String>,
        private_tcp_bind: Option<String>,
        tcp_tls_offload: bool,
        tcp_proxy_protocol: bool,
        private_tls_cert_path: Option<String>,
        private_tls_key_path: Option<String>,
        session_ttl_secs: i64,
        grace_window_secs: u64,
        max_pending_per_device: usize,
        global_max_pending: usize,
        pull_limit: usize,
        ack_timeout_secs: u64,
        fallback_max_attempts: u32,
        fallback_max_backoff_secs: u64,
        retransmit_window_secs: u64,
        retransmit_max_per_window: u32,
        retransmit_max_per_tick: usize,
        retransmit_max_retries: u8,
        hot_cache_capacity: usize,
        default_ttl_secs: i64,
        gateway_token: Option<String>,
    ) -> Self {
        PrivateConfig {
            private_quic_bind,
            private_tcp_bind,
            tcp_tls_offload,
            tcp_proxy_protocol,
            private_tls_cert_path,
            private_tls_key_path,
            session_ttl_secs,
            grace_window_secs,
            max_pending_per_device,
            global_max_pending,
            pull_limit,
            ack_timeout_secs,
            fallback_max_attempts,
            fallback_max_backoff_secs,
            retransmit_window_secs,
            retransmit_max_per_window,
            retransmit_max_per_tick,
            retransmit_max_retries,
            hot_cache_capacity,
            default_ttl_secs: normalize_private_default_ttl_secs(default_ttl_secs),
            gateway_token,
        }
    }
}

#[inline]
fn normalize_private_default_ttl_secs(ttl_secs: i64) -> i64 {
    if ttl_secs <= 0 {
        PRIVATE_DEFAULT_TTL_SECONDS_MAX
    } else {
        ttl_secs.min(PRIVATE_DEFAULT_TTL_SECONDS_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PRIVATE_DEFAULT_TTL_SECONDS_MAX, normalize_private_default_ttl_secs,
        should_attempt_fallback_for_device, should_drop_retry_attempt,
    };

    #[test]
    fn private_default_ttl_is_clamped_to_max() {
        assert_eq!(
            normalize_private_default_ttl_secs(PRIVATE_DEFAULT_TTL_SECONDS_MAX + 1),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
        assert_eq!(
            normalize_private_default_ttl_secs(90 * 24 * 60 * 60),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn private_default_ttl_uses_max_for_non_positive_values() {
        assert_eq!(
            normalize_private_default_ttl_secs(0),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
        assert_eq!(
            normalize_private_default_ttl_secs(-1),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn private_default_ttl_keeps_valid_small_values() {
        assert_eq!(normalize_private_default_ttl_secs(1), 1);
        assert_eq!(
            normalize_private_default_ttl_secs(PRIVATE_DEFAULT_TTL_SECONDS_MAX),
            PRIVATE_DEFAULT_TTL_SECONDS_MAX
        );
    }

    #[test]
    fn retry_attempt_budget_can_be_disabled() {
        assert!(!should_drop_retry_attempt(5, 5, false));
        assert!(!should_drop_retry_attempt(5, 50, false));
    }

    #[test]
    fn retry_attempt_budget_applies_when_enabled() {
        assert!(!should_drop_retry_attempt(5, 4, true));
        assert!(should_drop_retry_attempt(5, 5, true));
    }

    #[test]
    fn retry_attempt_budget_zero_means_unbounded() {
        assert!(!should_drop_retry_attempt(0, 10_000, true));
    }

    #[test]
    fn fallback_attempt_requires_online_device() {
        assert!(should_attempt_fallback_for_device(true));
        assert!(!should_attempt_fallback_for_device(false));
    }
}

pub struct PrivateState {
    pub hub: Arc<PrivateHub>,
    pub config: PrivateConfig,
    pub device_registry: Arc<DeviceRegistry>,
    pub stats: Arc<StatsCollector>,
    pub metrics: Arc<metrics::PrivateMetrics>,
    fallback_tasks: Option<Arc<FallbackTaskEngine>>,
    session_coordinator: Arc<InMemoryCoordinator>,
    session_coord_owner: String,
    revoked_devices: RwLock<HashMap<DeviceId, ()>>,
    session_controls: RwLock<HashMap<String, SessionControl>>,
    session_devices: RwLock<HashMap<String, DeviceId>>,
    shutting_down: AtomicBool,
    shutdown_notify: tokio::sync::Notify,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrivateAutomationStats {
    pub revoked_device_count: usize,
    pub session_count: usize,
    pub device_bound_session_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RegisterConnectionOutcome {
    pub superseded_conn_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalDeliveryDisposition {
    Acked,
    Dropped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EnqueuePrivateMessageOutcome {
    private_outbox_pruned: usize,
}

#[derive(Debug, Default)]
pub(crate) struct BootstrapQueues {
    pub inflight: VecDeque<(u64, protocol::DeliverEnvelope)>,
    pub pending: VecDeque<protocol::DeliverEnvelope>,
}

#[derive(Debug)]
pub(crate) struct PreparedSessionBootstrap {
    pub resume: ResumeHandshake,
    pub bootstrap: BootstrapQueues,
}

#[derive(Debug, Default)]
pub(crate) struct RetransmitPollResult {
    pub exhausted_count: usize,
    pub outbound: Option<(u64, protocol::DeliverEnvelope)>,
}

impl PrivateState {
    pub fn new(
        store: Storage,
        config: PrivateConfig,
        device_registry: Arc<DeviceRegistry>,
        stats: Arc<StatsCollector>,
    ) -> Self {
        let hub = Arc::new(PrivateHub::new(store, &config));
        let owner = format!("gateway-{}", std::process::id());
        let fallback_tasks = (config.ack_timeout_secs > 0).then(FallbackTaskEngine::new);
        PrivateState {
            hub,
            config,
            device_registry,
            stats,
            metrics: Arc::new(metrics::PrivateMetrics::default()),
            fallback_tasks,
            session_coordinator: Arc::new(InMemoryCoordinator::new()),
            session_coord_owner: owner,
            revoked_devices: RwLock::new(HashMap::new()),
            session_controls: RwLock::new(HashMap::new()),
            session_devices: RwLock::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            shutdown_notify: tokio::sync::Notify::new(),
        }
    }

    pub fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }

        for control in self.session_controls.read().values() {
            control.expire_now();
        }

        self.shutdown_notify.notify_waiters();
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        self.shutdown_notify.notified().await;
    }

    pub fn revoke_device_key(&self, device_key: &str) {
        let device_id = DeviceRegistry::derive_private_device_id(device_key);
        self.revoked_devices.write().insert(device_id, ());
        let _ = self.set_device_auth_expiry_by_id(device_id, Some(0), 0, None);
    }

    pub fn unrevoke_device_key(&self, device_key: &str) {
        let device_id = DeviceRegistry::derive_private_device_id(device_key);
        self.revoked_devices.write().remove(&device_id);
    }

    pub fn is_device_revoked(&self, device_id: DeviceId) -> bool {
        self.revoked_devices.read().contains_key(&device_id)
    }

    pub fn register_session_control(
        &self,
        session_id: &str,
        device_id: DeviceId,
        control: SessionControl,
    ) {
        self.session_controls
            .write()
            .insert(session_id.to_string(), control);
        self.session_devices
            .write()
            .insert(session_id.to_string(), device_id);
    }

    pub fn unregister_session_control(&self, session_id: &str) {
        self.session_controls.write().remove(session_id);
        self.session_devices.write().remove(session_id);
    }

    pub fn expire_other_device_sessions(
        &self,
        device_id: DeviceId,
        keep_session_id: &str,
    ) -> usize {
        self.set_device_auth_expiry_by_id(device_id, Some(0), 0, Some(keep_session_id))
    }

    pub fn set_device_auth_expiry(
        &self,
        device_key: &str,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) -> usize {
        let device_id = DeviceRegistry::derive_private_device_id(device_key);
        self.set_device_auth_expiry_by_id(
            device_id,
            auth_expires_at_unix_secs,
            auth_refresh_before_secs,
            None,
        )
    }

    pub fn set_session_auth_expiry(
        &self,
        session_id: &str,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) -> bool {
        let Some(control) = self.session_controls.read().get(session_id).cloned() else {
            return false;
        };
        control.set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
        true
    }

    pub fn session_coordinator(&self) -> Arc<dyn SessionCoordinator> {
        self.session_coordinator.clone()
    }

    pub fn session_coord_owner(&self) -> String {
        self.session_coord_owner.clone()
    }

    pub fn automation_reset(&self) {
        self.metrics.reset();
        self.revoked_devices.write().clear();
        self.session_controls.write().clear();
        self.session_devices.write().clear();
    }

    pub fn automation_stats(&self) -> PrivateAutomationStats {
        PrivateAutomationStats {
            revoked_device_count: self.revoked_devices.read().len(),
            session_count: self.session_controls.read().len(),
            device_bound_session_count: self.session_devices.read().len(),
        }
    }

    pub fn schedule_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: impl Into<String>,
        due_at_unix_secs: i64,
    ) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
        if let Some(engine) = &self.fallback_tasks {
            if !engine.schedule(device_id, delivery_id.into(), due_at_unix_secs) {
                self.metrics.mark_enqueue_failure();
            }
            self.metrics.mark_task_queue_depth(engine.depth());
        }
    }

    pub fn request_fallback_resync(&self) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
        if let Some(engine) = &self.fallback_tasks {
            engine.request_resync();
        }
    }

    pub fn cancel_fallback(&self, device_id: DeviceId, delivery_id: &str) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
        if let Some(engine) = &self.fallback_tasks {
            if !engine.cancel(device_id, delivery_id) {
                self.metrics.mark_enqueue_failure();
            }
            self.metrics.mark_task_queue_depth(engine.depth());
        }
    }

    pub async fn enqueue_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        payload: Vec<u8>,
        sent_at: i64,
        expires_at: i64,
    ) -> Result<(), crate::Error> {
        let outcome = self
            .hub
            .enqueue_private_message(device_id, delivery_id, payload, sent_at, expires_at)
            .await?;
        if outcome.private_outbox_pruned > 0
            && let Some(engine) = &self.fallback_tasks
        {
            engine.request_resync();
        }
        if private_provider_wakeup_pull_enabled() && self.hub.is_online(device_id) {
            self.schedule_fallback(
                device_id,
                delivery_id.to_string(),
                sent_at + self.config.ack_timeout_secs.max(1) as i64,
            );
        }
        Ok(())
    }

    pub async fn complete_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        seq: Option<u64>,
    ) -> Result<bool, crate::Error> {
        self.settle_terminal_delivery(
            device_id,
            delivery_id,
            seq,
            TerminalDeliveryDisposition::Acked,
        )
        .await
    }

    pub async fn drop_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<bool, crate::Error> {
        self.settle_terminal_delivery(
            device_id,
            delivery_id,
            None,
            TerminalDeliveryDisposition::Dropped,
        )
        .await
    }

    async fn settle_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        seq: Option<u64>,
        disposition: TerminalDeliveryDisposition,
    ) -> Result<bool, crate::Error> {
        let resolved_delivery_id = if let Some(seq) = seq {
            self.hub
                .ack_by_seq(device_id, seq, Some(delivery_id))
                .await?
        } else {
            Some(delivery_id.to_owned())
        };
        let Some(resolved_delivery_id) = resolved_delivery_id else {
            return Ok(false);
        };
        let channel_id = self
            .resolve_channel_id_for_delivery(resolved_delivery_id.as_str())
            .await;
        self.hub
            .ack_delivery(device_id, resolved_delivery_id.as_str())
            .await?;
        let cleared = true;
        if cleared {
            self.cancel_fallback(device_id, resolved_delivery_id.as_str());
            if disposition == TerminalDeliveryDisposition::Acked {
                self.stats.record_private_ack_with_channel(
                    format!("private:{}", encode_lower_hex_128(&device_id)),
                    channel_id,
                    1,
                    chrono::Utc::now().timestamp(),
                );
            }
        }
        Ok(cleared)
    }

    async fn resolve_channel_id_for_delivery(&self, delivery_id: &str) -> Option<[u8; 16]> {
        if let Ok(Some(context)) = self
            .hub
            .store()
            .load_private_payload_context(delivery_id)
            .await
            && context.channel_id.is_some()
        {
            return context.channel_id;
        }

        let message = self
            .hub
            .load_private_message(delivery_id)
            .await
            .ok()
            .flatten()?;
        let envelope =
            postcard::from_bytes::<protocol::PrivatePayloadEnvelope>(&message.payload).ok()?;
        if envelope.payload_version != protocol::PRIVATE_PAYLOAD_VERSION_V1 {
            return None;
        }
        let raw_channel_id = envelope
            .data
            .get("channel_id")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())?;
        crate::api::parse_channel_id(raw_channel_id).ok()
    }

    pub async fn start_or_resume_session(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> ResumeHandshake {
        self.stats
            .record_private_connected(format!("private:{}", encode_lower_hex_128(&device_id)));
        let resume = self
            .hub
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        self.settle_resume_acked_deliveries(device_id, &resume.acked_delivery_ids)
            .await;
        resume
    }

    pub(crate) async fn prepare_session_bootstrap(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> Result<PreparedSessionBootstrap, crate::Error> {
        let resume = self
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        let bootstrap = self
            .hub
            .build_bootstrap_queues(device_id, self.config.pull_limit)
            .await?;
        Ok(PreparedSessionBootstrap { resume, bootstrap })
    }

    async fn settle_resume_acked_deliveries(&self, device_id: DeviceId, delivery_ids: &[String]) {
        for delivery_id in delivery_ids {
            match self
                .complete_terminal_delivery(device_id, delivery_id.as_str(), None)
                .await
            {
                Ok(true) | Ok(false) => {}
                Err(_err) => {}
            }
        }
    }

    pub async fn mark_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        next_attempt_at: i64,
    ) -> Result<(), crate::Error> {
        self.hub
            .mark_fallback_sent(device_id, delivery_id, next_attempt_at)
            .await?;
        self.schedule_fallback(device_id, delivery_id.to_string(), next_attempt_at);
        Ok(())
    }

    pub async fn defer_fallback_retry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        retry_at: i64,
    ) -> Result<(), crate::Error> {
        self.hub
            .defer_fallback_retry(device_id, delivery_id, retry_at)
            .await?;
        self.schedule_fallback(device_id, delivery_id.to_string(), retry_at);
        Ok(())
    }

    pub async fn clear_device_outbox(&self, device_id: DeviceId) -> Result<usize, crate::Error> {
        let delivery_ids = self.hub.clear_device_outbox(device_id).await?;
        if delivery_ids.is_empty() {
            return Ok(0);
        }
        for delivery_id in &delivery_ids {
            self.cancel_fallback(device_id, delivery_id.as_str());
        }
        if let Some(engine) = &self.fallback_tasks {
            engine.request_resync();
        }
        Ok(delivery_ids.len())
    }

    async fn resolve_system_target(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> Option<SystemTarget> {
        let devices = self.hub.list_channel_devices(channel_id).await.ok()?;
        for item in devices {
            let registry_match = self
                .device_registry
                .find_device_key_by_provider_token(
                    platform_name(item.platform),
                    item.token_str.as_ref(),
                )
                .map(|device_key| DeviceRegistry::derive_private_device_id(device_key.as_str()))
                .is_some_and(|mapped_device_id| mapped_device_id == device_id);
            if registry_match {
                return Some(SystemTarget {
                    platform: item.platform,
                    token: Arc::clone(&item.token_str),
                });
            }
            let mapped = self
                .hub
                .lookup_device_for_token(item.platform, item.token_str.as_ref())
                .await
                .ok()?;
            if mapped == Some(device_id) {
                return Some(SystemTarget {
                    platform: item.platform,
                    token: Arc::clone(&item.token_str),
                });
            }
        }
        None
    }

    fn set_device_auth_expiry_by_id(
        &self,
        device_id: DeviceId,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
        skip_session_id: Option<&str>,
    ) -> usize {
        let mut target_sessions = Vec::new();
        let session_devices = self.session_devices.read();
        for (session_id, bound_device_id) in session_devices.iter() {
            if *bound_device_id != device_id {
                continue;
            }
            if skip_session_id.is_some_and(|skip| skip == session_id.as_str()) {
                continue;
            }
            target_sessions.push(session_id.clone());
        }
        drop(session_devices);
        let mut affected = 0usize;
        let session_controls = self.session_controls.read();
        for session_id in target_sessions {
            if let Some(control) = session_controls.get(session_id.as_str()) {
                control
                    .clone()
                    .set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
                affected = affected.saturating_add(1);
            }
        }
        affected
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
            .try_send(FallbackTaskCommand::Schedule {
                key: FallbackTaskKey {
                    device_id,
                    delivery_id,
                },
                due_at_unix_secs,
            })
            .is_ok();
        if !sent {
            self.request_resync();
        }
        sent
    }

    fn cancel(&self, device_id: DeviceId, delivery_id: &str) -> bool {
        let sent = self
            .tx
            .try_send(FallbackTaskCommand::Cancel {
                key: FallbackTaskKey {
                    device_id,
                    delivery_id: delivery_id.to_string(),
                },
            })
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FallbackTaskKey {
    device_id: DeviceId,
    delivery_id: String,
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

pub struct PrivateHub {
    store: Storage,
    presence: DashMap<DeviceId, Presence>,
    grace_window: Duration,
    resume_ttl: Duration,
    ack_timeout_secs: i64,
    max_pending_per_device: usize,
    global_max_pending: usize,
    hot_cache_capacity: usize,
    retransmit_window: Duration,
    retransmit_max_per_window: u32,
    retransmit_max_per_tick: usize,
    retransmit_max_retries: u8,
    hot_messages: DashMap<String, PrivateMessage>,
    hot_order: Mutex<VecDeque<String>>,
    resume_state: DashMap<DeviceId, ResumeState>,
}

#[derive(Debug, Clone)]
struct Presence {
    quic_active: Option<ActiveConn>,
    tcp_active: Option<ActiveConn>,
    wss_active: Option<ActiveConn>,
    draining: Vec<DrainingConn>,
}

#[derive(Debug, Clone)]
struct ActiveConn {
    conn_id: u64,
    sender: Sender<protocol::DeliverEnvelope>,
}

#[derive(Debug, Clone)]
struct DrainingConn {
    conn_id: u64,
    #[allow(dead_code)]
    sender: Sender<protocol::DeliverEnvelope>,
    delivery_until: Instant,
    drain_until: Instant,
}

impl Presence {
    fn slot_mut(&mut self, transport: TransportKind) -> &mut Option<ActiveConn> {
        match transport {
            TransportKind::Quic => &mut self.quic_active,
            TransportKind::Tcp => &mut self.tcp_active,
            TransportKind::Wss => &mut self.wss_active,
        }
    }

    fn active_conn_ids(&self) -> [Option<u64>; 3] {
        [
            self.quic_active.as_ref().map(|active| active.conn_id),
            self.tcp_active.as_ref().map(|active| active.conn_id),
            self.wss_active.as_ref().map(|active| active.conn_id),
        ]
    }

    fn delivery_senders(&self, now: Instant) -> Vec<Sender<protocol::DeliverEnvelope>> {
        let mut senders = Vec::with_capacity(3 + self.draining.len());
        if let Some(active) = self.quic_active.as_ref() {
            senders.push(active.sender.clone());
        }
        if let Some(active) = self.tcp_active.as_ref() {
            senders.push(active.sender.clone());
        }
        if let Some(active) = self.wss_active.as_ref() {
            senders.push(active.sender.clone());
        }
        for draining in &self.draining {
            if draining.delivery_until > now {
                senders.push(draining.sender.clone());
            }
        }
        senders
    }

    fn has_active(&self) -> bool {
        self.quic_active.is_some() || self.tcp_active.is_some() || self.wss_active.is_some()
    }
}

#[derive(Debug, Clone)]
struct ResumeInflight {
    delivery: protocol::DeliverEnvelope,
    sent_at: Instant,
    retries: u8,
}

#[derive(Debug, Clone)]
struct ResumeState {
    token: String,
    next_seq: u64,
    inflight: BTreeMap<u64, ResumeInflight>,
    rtt_ewma_ms: Option<f64>,
    retransmit_window_started: Instant,
    retransmit_in_window: u32,
    updated_at: Instant,
}

impl ResumeState {
    fn fresh(now: Instant) -> Self {
        Self {
            token: new_resume_token(),
            next_seq: 1,
            inflight: BTreeMap::new(),
            rtt_ewma_ms: None,
            retransmit_window_started: now,
            retransmit_in_window: 0,
            updated_at: now,
        }
    }

    fn reset(&mut self, now: Instant) {
        *self = Self::fresh(now);
    }

    fn ack_up_to(&mut self, last_acked_seq: u64, now: Instant) -> Vec<String> {
        if last_acked_seq == 0 {
            self.updated_at = now;
            return Vec::new();
        }
        let acked: Vec<u64> = self
            .inflight
            .iter()
            .filter_map(|(seq, _)| (*seq <= last_acked_seq).then_some(*seq))
            .collect();
        let mut acked_delivery_ids = Vec::with_capacity(acked.len());
        for seq in acked {
            if let Some(inflight) = self.inflight.remove(&seq) {
                acked_delivery_ids.push(inflight.delivery.delivery_id);
            }
        }
        self.updated_at = now;
        acked_delivery_ids
    }

    fn track_outbound(
        &mut self,
        envelope: protocol::DeliverEnvelope,
        now: Instant,
    ) -> (u64, protocol::DeliverEnvelope) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        self.inflight.insert(
            seq,
            ResumeInflight {
                delivery: envelope.clone(),
                sent_at: now,
                retries: 0,
            },
        );
        self.updated_at = now;
        (seq, envelope)
    }

    fn mark_sent(&mut self, seq: u64, now: Instant) {
        if let Some(inflight) = self.inflight.get_mut(&seq) {
            inflight.sent_at = now;
            self.updated_at = now;
        }
    }

    fn ack_by_seq(
        &mut self,
        seq: u64,
        expected_delivery_id: Option<&str>,
        now: Instant,
    ) -> Option<String> {
        let inflight = self.inflight.get(&seq)?;
        if let Some(expected) = expected_delivery_id
            && inflight.delivery.delivery_id != expected
        {
            return None;
        }
        let inflight = self.inflight.remove(&seq)?;
        let rtt_ms = now.duration_since(inflight.sent_at).as_secs_f64() * 1000.0;
        let ewma = match self.rtt_ewma_ms {
            Some(prev) => (0.8 * prev) + (0.2 * rtt_ms),
            None => rtt_ms,
        };
        self.rtt_ewma_ms = Some(ewma);
        self.updated_at = now;
        Some(inflight.delivery.delivery_id)
    }

    fn inflight_snapshot(&self) -> Vec<(u64, protocol::DeliverEnvelope)> {
        self.inflight
            .iter()
            .map(|(seq, state)| (*seq, state.delivery.clone()))
            .collect()
    }

    fn next_retransmit_due_in(
        &self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_window: Duration,
        retransmit_max_per_window: u32,
        retransmit_max_retries: u8,
    ) -> Option<Duration> {
        let adaptive_timeout = adaptive_retransmit_timeout(ack_timeout, self.rtt_ewma_ms);

        let window_wait = if self.retransmit_in_window >= retransmit_max_per_window {
            let window_end = self.retransmit_window_started + retransmit_window;
            Some(window_end.saturating_duration_since(now))
        } else {
            None
        };

        let mut due_wait = window_wait;
        for state in self.inflight.values() {
            if state.retries >= retransmit_max_retries {
                continue;
            }
            let due_at = state.sent_at + adaptive_timeout;
            let wait = due_at.saturating_duration_since(now);
            due_wait = Some(match due_wait {
                Some(current) => current.min(wait),
                None => wait,
            });
        }
        due_wait
    }

    fn collect_retransmit_due(
        &mut self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_window: Duration,
        retransmit_max_per_window: u32,
        retransmit_max_per_tick: usize,
        retransmit_max_retries: u8,
    ) -> Vec<(u64, protocol::DeliverEnvelope)> {
        if now.duration_since(self.retransmit_window_started) >= retransmit_window {
            self.retransmit_window_started = now;
            self.retransmit_in_window = 0;
        }
        let adaptive_timeout = adaptive_retransmit_timeout(ack_timeout, self.rtt_ewma_ms);
        let mut out = Vec::new();
        let mut retransmit_in_window = self.retransmit_in_window;
        for (seq, state) in &mut self.inflight {
            if out.len() >= retransmit_max_per_tick {
                break;
            }
            if retransmit_in_window >= retransmit_max_per_window {
                break;
            }
            if now.duration_since(state.sent_at) >= adaptive_timeout {
                if state.retries >= retransmit_max_retries {
                    continue;
                }
                state.sent_at = now;
                state.retries = state.retries.saturating_add(1);
                retransmit_in_window = retransmit_in_window.saturating_add(1);
                out.push((*seq, state.delivery.clone()));
            }
        }
        self.retransmit_in_window = retransmit_in_window;
        if !out.is_empty() {
            self.updated_at = now;
        }
        out
    }

    fn drop_exhausted(
        &mut self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_max_retries: u8,
    ) -> usize {
        let adaptive_timeout = adaptive_retransmit_timeout(ack_timeout, self.rtt_ewma_ms);
        let stale: Vec<u64> = self
            .inflight
            .iter()
            .filter_map(|(seq, state)| {
                if state.retries >= retransmit_max_retries
                    && now.duration_since(state.sent_at) >= adaptive_timeout
                {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();
        for seq in &stale {
            self.inflight.remove(seq);
        }
        if !stale.is_empty() {
            self.updated_at = now;
        }
        stale.len()
    }
}

#[derive(Debug, Clone)]
pub struct ResumeHandshake {
    pub resume_token: String,
    pub acked_delivery_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    Active,
    Draining,
    Stale,
}

impl PrivateHub {
    fn compute_draining_delivery_window(&self, device_id: DeviceId) -> Duration {
        let min_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_MIN.as_millis() as u64;
        let max_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_MAX.as_millis() as u64;
        let default_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_DEFAULT.as_millis() as u64;
        let computed_ms = self
            .with_resume_state(device_id, |entry| entry.rtt_ewma_ms)
            .flatten()
            .map(|rtt_ms| {
                (rtt_ms * PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_MULTIPLIER
                    + PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_PADDING_MS)
                    .round() as u64
            })
            .unwrap_or(default_ms)
            .clamp(min_ms, max_ms);
        Duration::from_millis(computed_ms)
    }

    pub fn new(store: Storage, config: &PrivateConfig) -> Self {
        PrivateHub {
            store,
            presence: DashMap::new(),
            grace_window: Duration::from_secs(config.grace_window_secs),
            resume_ttl: Duration::from_secs(config.session_ttl_secs.max(60) as u64),
            ack_timeout_secs: config.ack_timeout_secs.max(1) as i64,
            max_pending_per_device: config.max_pending_per_device,
            global_max_pending: config.global_max_pending,
            hot_cache_capacity: config.hot_cache_capacity.max(1),
            retransmit_window: Duration::from_secs(config.retransmit_window_secs.max(1)),
            retransmit_max_per_window: config.retransmit_max_per_window.max(1),
            retransmit_max_per_tick: config.retransmit_max_per_tick.max(1),
            retransmit_max_retries: config.retransmit_max_retries.max(1),
            hot_messages: DashMap::new(),
            hot_order: Mutex::new(VecDeque::new()),
            resume_state: DashMap::new(),
        }
    }

    pub fn store(&self) -> &Storage {
        &self.store
    }

    pub fn encode_device_id(device_id: DeviceId) -> String {
        encode_lower_hex_128(&device_id)
    }

    pub fn decode_device_id(raw: &str) -> Result<DeviceId, crate::util::HexDecodeError> {
        decode_lower_hex_128(raw)
    }

    pub(crate) fn register_connection(
        &self,
        device_id: DeviceId,
        conn_id: u64,
        transport: TransportKind,
        sender: Sender<protocol::DeliverEnvelope>,
    ) -> RegisterConnectionOutcome {
        let now = Instant::now();
        let mut superseded_conn_id = None;
        self.presence
            .entry(device_id)
            .and_modify(|presence| {
                presence.draining.retain(|item| item.drain_until > now);
                let slot = presence.slot_mut(transport);
                if let Some(previous) = slot.replace(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }) {
                    let delivery_window = self
                        .compute_draining_delivery_window(device_id)
                        .min(self.grace_window);
                    presence.draining.push(DrainingConn {
                        conn_id: previous.conn_id,
                        sender: previous.sender,
                        delivery_until: now + delivery_window,
                        drain_until: now + self.grace_window,
                    });
                    superseded_conn_id = Some(previous.conn_id);
                    const MAX_DRAINING_CONN: usize = 16;
                    if presence.draining.len() > MAX_DRAINING_CONN {
                        let overflow = presence.draining.len() - MAX_DRAINING_CONN;
                        presence.draining.drain(0..overflow);
                    }
                }
            })
            .or_insert_with(|| Presence {
                quic_active: matches!(transport, TransportKind::Quic).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                tcp_active: matches!(transport, TransportKind::Tcp).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                wss_active: matches!(transport, TransportKind::Wss).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                draining: Vec::new(),
            });
        RegisterConnectionOutcome { superseded_conn_id }
    }

    pub fn collapse_draining_delivery_window_if_active(&self, device_id: DeviceId, conn_id: u64) {
        if let Some(mut presence) = self.presence.get_mut(&device_id) {
            let is_active = presence
                .active_conn_ids()
                .into_iter()
                .flatten()
                .any(|active_id| active_id == conn_id);
            if !is_active {
                return;
            }
            let now = Instant::now();
            for draining in &mut presence.draining {
                draining.delivery_until = now;
            }
        }
    }

    pub fn connection_mode(&self, device_id: DeviceId, conn_id: u64) -> ConnectionMode {
        let Some(presence) = self.presence.get(&device_id) else {
            return ConnectionMode::Stale;
        };
        if presence
            .active_conn_ids()
            .into_iter()
            .flatten()
            .any(|id| id == conn_id)
        {
            return ConnectionMode::Active;
        }
        let now = Instant::now();
        for draining in &presence.draining {
            if draining.conn_id == conn_id {
                if draining.drain_until > now {
                    return ConnectionMode::Draining;
                }
                return ConnectionMode::Stale;
            }
        }
        ConnectionMode::Stale
    }

    pub fn is_online(&self, device_id: DeviceId) -> bool {
        self.presence
            .get(&device_id)
            .map(|presence| presence.has_active())
            .unwrap_or(false)
    }

    pub fn online_device_ids(&self) -> Vec<DeviceId> {
        self.presence
            .iter()
            .filter_map(|entry| entry.value().has_active().then_some(*entry.key()))
            .collect()
    }

    pub fn sweep_draining(&self, device_id: DeviceId) {
        let mut remove_presence = false;
        if let Some(mut entry) = self.presence.get_mut(&device_id) {
            let now = Instant::now();
            entry.draining.retain(|item| item.drain_until > now);
            remove_presence = !entry.has_active() && entry.draining.is_empty();
        }
        if remove_presence {
            self.presence.remove(&device_id);
        }
    }

    pub fn unregister_connection(&self, device_id: DeviceId, conn_id: u64) {
        let mut remove_presence = false;
        if let Some(mut entry) = self.presence.get_mut(&device_id) {
            if entry
                .quic_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.quic_active = None;
            }
            if entry
                .tcp_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.tcp_active = None;
            }
            if entry
                .wss_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.wss_active = None;
            }
            entry.draining.retain(|item| item.conn_id != conn_id);
            if !entry.has_active() && entry.draining.is_empty() {
                remove_presence = true;
            }
        }
        if remove_presence {
            self.presence.remove(&device_id);
        }
    }

    fn ensure_resume_state_mut<R>(
        &self,
        device_id: DeviceId,
        now: Instant,
        f: impl FnOnce(&mut ResumeState) -> R,
    ) -> R {
        let mut entry = self
            .resume_state
            .entry(device_id)
            .or_insert_with(|| ResumeState::fresh(now));
        f(&mut entry)
    }

    fn with_resume_state_mut<R>(
        &self,
        device_id: DeviceId,
        f: impl FnOnce(&mut ResumeState) -> R,
    ) -> Option<R> {
        let mut entry = self.resume_state.get_mut(&device_id)?;
        Some(f(&mut entry))
    }

    fn with_resume_state<R>(
        &self,
        device_id: DeviceId,
        f: impl FnOnce(&ResumeState) -> R,
    ) -> Option<R> {
        let entry = self.resume_state.get(&device_id)?;
        Some(f(&entry))
    }

    pub async fn start_or_resume_session(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> ResumeHandshake {
        let now = Instant::now();
        self.prune_stale_resume_state(now);
        let incoming = client_resume_token
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or_default();
        let (resume_token, acked_delivery_ids) =
            self.ensure_resume_state_mut(device_id, now, |entry| {
                let token_mismatch = incoming.is_empty() || incoming != entry.token;
                let ack_watermark_out_of_range =
                    !token_mismatch && last_acked_seq > entry.next_seq.saturating_sub(1);
                if token_mismatch || ack_watermark_out_of_range {
                    entry.reset(now);
                }
                let acked_delivery_ids = entry.ack_up_to(last_acked_seq, now);
                (entry.token.clone(), acked_delivery_ids)
            });

        ResumeHandshake {
            resume_token,
            acked_delivery_ids,
        }
    }

    pub fn track_outbound_delivery(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> (u64, protocol::DeliverEnvelope) {
        let now = Instant::now();
        self.prune_stale_resume_state(now);
        self.ensure_resume_state_mut(device_id, now, |entry| entry.track_outbound(envelope, now))
    }

    pub fn track_sent_outbound(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> (u64, protocol::DeliverEnvelope) {
        let (seq, tracked) = self.track_outbound_delivery(device_id, envelope);
        self.mark_delivery_sent(device_id, seq);
        (seq, tracked)
    }

    pub fn mark_delivery_sent(&self, device_id: DeviceId, seq: u64) {
        let now = Instant::now();
        let _ = self.with_resume_state_mut(device_id, |entry| entry.mark_sent(seq, now));
    }

    pub async fn ack_by_seq(
        &self,
        device_id: DeviceId,
        seq: u64,
        expected_delivery_id: Option<&str>,
    ) -> Result<Option<String>, crate::Error> {
        Ok(self
            .with_resume_state_mut(device_id, |entry| {
                entry.ack_by_seq(seq, expected_delivery_id, Instant::now())
            })
            .flatten())
    }

    fn snapshot_inflight(&self, device_id: DeviceId) -> Vec<(u64, protocol::DeliverEnvelope)> {
        self.with_resume_state(device_id, ResumeState::inflight_snapshot)
            .unwrap_or_default()
    }

    pub(crate) fn next_retransmit_due_in(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Option<Duration> {
        self.with_resume_state(device_id, |entry| {
            entry.next_retransmit_due_in(
                Instant::now(),
                ack_timeout,
                self.retransmit_window,
                self.retransmit_max_per_window,
                self.retransmit_max_retries,
            )
        })
        .flatten()
    }

    fn collect_retransmit_due(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Vec<(u64, protocol::DeliverEnvelope)> {
        let now = Instant::now();
        self.with_resume_state_mut(device_id, |entry| {
            entry.collect_retransmit_due(
                now,
                ack_timeout,
                self.retransmit_window,
                self.retransmit_max_per_window,
                self.retransmit_max_per_tick,
                self.retransmit_max_retries,
            )
        })
        .unwrap_or_default()
    }

    pub(crate) fn take_retransmit_outbound(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Option<(u64, protocol::DeliverEnvelope)> {
        let due = self.collect_retransmit_due(device_id, ack_timeout);
        let (seq, envelope) = due.into_iter().next()?;
        self.mark_delivery_sent(device_id, seq);
        Some((seq, envelope))
    }

    pub(crate) fn poll_retransmit_outbound(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> RetransmitPollResult {
        let exhausted_count = self.drop_exhausted_inflight(device_id, ack_timeout);
        let outbound = self.take_retransmit_outbound(device_id, ack_timeout);
        RetransmitPollResult {
            exhausted_count,
            outbound,
        }
    }

    pub(crate) fn drop_exhausted_inflight(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> usize {
        self.with_resume_state_mut(device_id, |entry| {
            entry.drop_exhausted(Instant::now(), ack_timeout, self.retransmit_max_retries)
        })
        .unwrap_or(0)
    }

    pub async fn deliver_to_device(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> bool {
        if let Some(presence) = self.presence.get(&device_id) {
            let senders = presence.delivery_senders(Instant::now());
            drop(presence);
            let mut delivered = false;
            for sender in senders {
                if sender.send_async(envelope.clone()).await.is_ok() {
                    delivered = true;
                }
            }
            return delivered;
        }
        false
    }

    pub fn try_deliver_to_device(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> bool {
        if let Some(presence) = self.presence.get(&device_id) {
            let senders = presence.delivery_senders(Instant::now());
            drop(presence);
            let mut delivered = false;
            for sender in senders {
                if sender.try_send(envelope.clone()).is_ok() {
                    delivered = true;
                }
            }
            return delivered;
        }
        false
    }

    async fn enqueue_private_message(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        payload: Vec<u8>,
        sent_at: i64,
        expires_at: i64,
    ) -> Result<EnqueuePrivateMessageOutcome, crate::Error> {
        let now = chrono::Utc::now().timestamp();
        let device_pending = self
            .store
            .count_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        if device_pending >= self.max_pending_per_device {
            return Err(crate::Error::TooBusy);
        }
        let mut total_pending = self
            .store
            .count_private_outbox_total()
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        let mut private_outbox_pruned = 0usize;
        if total_pending >= self.global_max_pending {
            private_outbox_pruned = self
                .store
                .cleanup_private_expired_data(now, 4096)
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            total_pending = self
                .store
                .count_private_outbox_total()
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            if total_pending >= self.global_max_pending {
                return Err(crate::Error::TooBusy);
            }
        }

        let should_persist_message = !self.hot_messages.contains_key(delivery_id);
        if should_persist_message {
            let size = payload.len();
            let message = PrivateMessage {
                payload,
                size,
                sent_at,
                expires_at,
            };
            self.store
                .insert_private_message(delivery_id, &message)
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            self.cache_put(delivery_id, &message);
        }

        let entry = PrivateOutboxEntry {
            delivery_id: delivery_id.to_string(),
            status: "pending".to_string(),
            attempts: 0,
            occurred_at: sent_at,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: sent_at.saturating_add(self.ack_timeout_secs.max(1)),
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        self.store
            .enqueue_private_outbox(device_id, &entry)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        Ok(EnqueuePrivateMessageOutcome {
            private_outbox_pruned,
        })
    }

    pub async fn pull_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> Result<Vec<(PrivateOutboxEntry, PrivateMessage)>, crate::Error> {
        let entries = self
            .store
            .list_private_outbox(device_id, limit)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        let mut out = Vec::new();
        for entry in entries {
            if let Some(message) = self.load_message_cached(entry.delivery_id.as_str()).await? {
                out.push((entry, message));
            }
        }
        Ok(out)
    }

    pub(crate) async fn build_bootstrap_queues(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> Result<BootstrapQueues, crate::Error> {
        let inflight_snapshot = self.snapshot_inflight(device_id);
        let mut inflight = VecDeque::new();
        let mut inflight_delivery_ids = HashSet::new();
        for (seq, item) in inflight_snapshot {
            inflight_delivery_ids.insert(item.delivery_id.clone());
            inflight.push_back((
                seq,
                protocol::DeliverEnvelope {
                    delivery_id: item.delivery_id,
                    payload: item.payload,
                },
            ));
        }

        let rows = self.pull_outbox(device_id, limit).await?;
        let mut pending = VecDeque::new();
        for (entry, msg) in rows {
            if inflight_delivery_ids.contains(entry.delivery_id.as_str()) {
                continue;
            }
            pending.push_back(protocol::DeliverEnvelope {
                delivery_id: entry.delivery_id,
                payload: msg.payload,
            });
        }

        Ok(BootstrapQueues { inflight, pending })
    }

    pub async fn count_pending_outbox_total(&self) -> Result<usize, crate::Error> {
        self.store
            .count_private_outbox_total()
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn count_pending_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> Result<usize, crate::Error> {
        self.store
            .count_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn list_due_outbox(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> Result<Vec<(DeviceId, PrivateOutboxEntry)>, crate::Error> {
        self.store
            .list_private_outbox_due(before_ts, limit)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn claim_due_outbox(
        &self,
        now: i64,
        limit: usize,
        claim_until: i64,
    ) -> Result<Vec<(DeviceId, PrivateOutboxEntry)>, crate::Error> {
        self.store
            .claim_private_outbox_due(now, limit, claim_until)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn claim_due_outbox_for_device(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
        claim_until: i64,
    ) -> Result<Vec<PrivateOutboxEntry>, crate::Error> {
        self.store
            .claim_private_outbox_due_for_device(device_id, now, limit, claim_until)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn ack_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<(), crate::Error> {
        self.store
            .ack_private_delivery(device_id, delivery_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn mark_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        next_attempt_at: i64,
    ) -> Result<(), crate::Error> {
        self.store
            .mark_private_fallback_sent(device_id, delivery_id, next_attempt_at)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn defer_fallback_retry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        retry_at: i64,
    ) -> Result<(), crate::Error> {
        self.store
            .defer_private_fallback(device_id, delivery_id, retry_at)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn clear_device_outbox(
        &self,
        device_id: DeviceId,
    ) -> Result<Vec<String>, crate::Error> {
        self.store
            .clear_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn run_maintenance_cleanup(
        &self,
        now: i64,
        dedupe_before: i64,
    ) -> Result<MaintenanceCleanupStats, crate::Error> {
        self.store
            .run_maintenance_cleanup(now, dedupe_before)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn is_delivery_pending(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<bool, crate::Error> {
        self.store
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .map(|item| item.is_some())
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn bind_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> Result<(), crate::Error> {
        self.store
            .bind_private_token(device_id, platform, token)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn list_channel_devices(
        &self,
        channel_id: [u8; 16],
    ) -> Result<Vec<crate::storage::DeviceInfo>, crate::Error> {
        self.store
            .list_channel_devices(channel_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn lookup_device_for_token(
        &self,
        platform: Platform,
        token: &str,
    ) -> Result<Option<DeviceId>, crate::Error> {
        self.store
            .lookup_private_device(platform, token)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> Result<Option<PrivateMessage>, crate::Error> {
        self.load_message_cached(delivery_id).await
    }

    async fn load_message_cached(
        &self,
        delivery_id: &str,
    ) -> Result<Option<PrivateMessage>, crate::Error> {
        if let Some(item) = self.hot_messages.get(delivery_id) {
            return Ok(Some(item.clone()));
        }
        let message = self
            .store
            .load_private_message(delivery_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        if let Some(value) = message.as_ref() {
            self.cache_put(delivery_id, value);
        }
        Ok(message)
    }

    fn prune_stale_resume_state(&self, now: Instant) {
        if self.resume_state.len() < 128 {
            return;
        }
        let stale: Vec<DeviceId> = self
            .resume_state
            .iter()
            .filter_map(|item| {
                if now.duration_since(item.value().updated_at) >= self.resume_ttl
                    && !self.is_online(*item.key())
                {
                    Some(*item.key())
                } else {
                    None
                }
            })
            .collect();
        for device_id in stale {
            self.resume_state.remove(&device_id);
        }
    }

    pub fn hot_cache_target_for_pending(&self, pending_outbox: usize) -> usize {
        let floor = self.hot_cache_capacity.clamp(1, 256);
        pending_outbox
            .saturating_mul(2)
            .clamp(floor, self.hot_cache_capacity)
    }

    pub fn compact_hot_cache(&self, target_capacity: usize) {
        let target_capacity = target_capacity.clamp(1, self.hot_cache_capacity);
        let retained_ids = {
            let mut order = self.hot_order.lock();
            if order.len() > 1 {
                let mut seen = HashSet::with_capacity(order.len());
                let mut deduped = VecDeque::with_capacity(order.len());
                for delivery_id in order.iter().rev() {
                    if seen.insert(delivery_id.clone()) {
                        deduped.push_front(delivery_id.clone());
                    }
                }
                *order = deduped;
            }
            self.trim_hot_cache_locked(&mut order, target_capacity);
            let shrink_threshold = target_capacity.saturating_mul(4).max(1024);
            if order.capacity() > shrink_threshold {
                order.shrink_to_fit();
            }
            order.iter().cloned().collect::<HashSet<String>>()
        };

        if self.hot_messages.len() <= retained_ids.len() {
            return;
        }
        let stale_keys: Vec<String> = self
            .hot_messages
            .iter()
            .filter_map(|entry| {
                (!retained_ids.contains(entry.key().as_str())).then(|| entry.key().clone())
            })
            .collect();
        for key in stale_keys {
            self.hot_messages.remove(key.as_str());
        }
    }

    fn cache_put(&self, delivery_id: &str, message: &PrivateMessage) {
        let inserted = self
            .hot_messages
            .insert(delivery_id.to_string(), message.clone())
            .is_none();
        if !inserted {
            return;
        }
        let mut order = self.hot_order.lock();
        order.push_back(delivery_id.to_string());
        self.trim_hot_cache_locked(&mut order, self.hot_cache_capacity);
    }

    fn trim_hot_cache_locked(&self, order: &mut VecDeque<String>, target_capacity: usize) {
        while order.len() > target_capacity {
            if let Some(stale) = order.pop_front() {
                self.hot_messages.remove(stale.as_str());
            }
        }
    }
}

pub fn spawn_quic_if_configured(state: Arc<PrivateState>) -> Result<(), crate::Error> {
    let Some(bind_addr) = state.config.private_quic_bind.clone() else {
        return Ok(());
    };
    let Some(cert_path) = state.config.private_tls_cert_path.clone() else {
        return Err(crate::Error::Internal(
            "PUSHGO_PRIVATE_TLS_CERT is required when QUIC is enabled".to_string(),
        ));
    };
    let Some(key_path) = state.config.private_tls_key_path.clone() else {
        return Err(crate::Error::Internal(
            "PUSHGO_PRIVATE_TLS_KEY is required when QUIC is enabled".to_string(),
        ));
    };
    tokio::spawn(async move {
        let mut restart_delay_secs = 1u64;
        loop {
            match quic::serve_quic(&bind_addr, &cert_path, &key_path, Arc::clone(&state)).await {
                Ok(()) | Err(_) => {}
            }
            if state.is_shutting_down() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(restart_delay_secs)) => {}
                _ = state.wait_for_shutdown() => break,
            }
            restart_delay_secs = restart_delay_secs.saturating_mul(2).min(30);
        }
    });
    Ok(())
}

pub fn spawn_tcp_if_configured(state: Arc<PrivateState>) -> Result<(), crate::Error> {
    let Some(bind_addr) = state.config.private_tcp_bind.clone() else {
        return Ok(());
    };
    if state.config.tcp_tls_offload {
        let proxy_protocol_enabled = state.config.tcp_proxy_protocol;
        tokio::spawn(async move {
            let mut restart_delay_secs = 1u64;
            loop {
                match tcp::serve_tcp_plain(&bind_addr, Arc::clone(&state), proxy_protocol_enabled)
                    .await
                {
                    Ok(()) | Err(_) => {}
                }
                if state.is_shutting_down() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(restart_delay_secs)) => {}
                    _ = state.wait_for_shutdown() => break,
                }
                restart_delay_secs = restart_delay_secs.saturating_mul(2).min(30);
            }
        });
        return Ok(());
    }
    let Some(cert_path) = state.config.private_tls_cert_path.clone() else {
        return Err(crate::Error::Internal(
            "PUSHGO_PRIVATE_TLS_CERT is required when private TCP is enabled".to_string(),
        ));
    };
    let Some(key_path) = state.config.private_tls_key_path.clone() else {
        return Err(crate::Error::Internal(
            "PUSHGO_PRIVATE_TLS_KEY is required when private TCP is enabled".to_string(),
        ));
    };
    let proxy_protocol_enabled = state.config.tcp_proxy_protocol;
    tokio::spawn(async move {
        let mut restart_delay_secs = 1u64;
        loop {
            match tcp::serve_tcp_tls(
                &bind_addr,
                &cert_path,
                &key_path,
                Arc::clone(&state),
                proxy_protocol_enabled,
            )
            .await
            {
                Ok(()) | Err(_) => {}
            }
            if state.is_shutting_down() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(restart_delay_secs)) => {}
                _ = state.wait_for_shutdown() => break,
            }
            restart_delay_secs = restart_delay_secs.saturating_mul(2).min(30);
        }
    });
    Ok(())
}

pub(crate) fn spawn_persistent_fallback_worker(
    state: Arc<PrivateState>,
    dispatch: DispatchChannels,
) {
    let Some(engine) = state.fallback_tasks.clone() else {
        return;
    };
    let Some(rx) = engine.take_receiver() else {
        return;
    };

    tokio::spawn(async move {
        let mut scheduler = FallbackScheduler::default();
        seed_fallback_tasks(&state, &mut scheduler).await;
        scheduler.schedule_maintenance(
            chrono::Utc::now()
                .timestamp()
                .saturating_add(MAINTENANCE_INTERVAL_SECS),
        );
        engine.mark_depth(scheduler.depth());
        state.metrics.mark_task_queue_depth(scheduler.depth());

        loop {
            if state.is_shutting_down() {
                break;
            }
            if engine.consume_resync_request() {
                if let Err(_err) = resync_fallback_tasks(&state, &mut scheduler, 200_000).await {}
                let depth = scheduler.depth();
                engine.mark_depth(depth);
                state.metrics.mark_task_queue_depth(depth);
            }
            let wake_at =
                unix_secs_to_tokio_instant(scheduler.next_due_unix_secs().unwrap_or(i64::MAX));

            tokio::select! {
                maybe_cmd = rx.recv_async() => {
                    let Ok(cmd) = maybe_cmd else {
                        break;
                    };
                    scheduler.apply(cmd);
                    let depth = scheduler.depth();
                    engine.mark_depth(depth);
                    state.metrics.mark_task_queue_depth(depth);
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
                                    if let Err(_err) = run_maintenance_tick(&state).await {
                                    }
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
                                run_claim_ack_drain(
                                    &state,
                                    &dispatch,
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
                        run_claim_ack_drain(
                            &state,
                            &dispatch,
                            &mut scheduler,
                            256,
                            CLAIM_ACK_IDLE_MAX_ROUNDS,
                            CLAIM_ACK_IDLE_PROCESS_BUDGET,
                        )
                        .await
                    {
                    }
                    let depth = scheduler.depth();
                    engine.mark_depth(depth);
                    state.metrics.mark_task_queue_depth(depth);
                }
            }
        }
    });
}

include!("runtime_tasks.rs");
