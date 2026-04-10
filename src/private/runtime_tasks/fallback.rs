use super::*;

#[derive(Clone, Copy)]
pub(super) struct FallbackAttemptPolicy {
    pub(super) max_attempts: u32,
    pub(super) ack_timeout_secs: u64,
    pub(super) max_backoff_secs: u64,
}

impl FallbackAttemptPolicy {
    pub(super) fn from_config(config: &PrivateConfig) -> Self {
        Self {
            max_attempts: config.fallback_max_attempts,
            ack_timeout_secs: config.ack_timeout_secs.max(1),
            max_backoff_secs: config.fallback_max_backoff_secs.max(config.ack_timeout_secs.max(1)),
        }
    }

    pub(super) fn should_drop_attempt(
        self,
        next_attempt: u32,
        budget: AttemptBudget,
    ) -> bool {
        matches!(budget, AttemptBudget::Enforced)
            && self.max_attempts > 0
            && next_attempt >= self.max_attempts
    }

    pub(super) fn should_drop_outbox(self, outbox: &PrivateOutboxEntry) -> bool {
        self.should_drop_attempt(outbox.attempts, AttemptBudget::Enforced)
    }

    pub(super) fn retry_at(self, now: i64, next_attempt: u32) -> i64 {
        let exp = next_attempt.saturating_sub(1).min(8);
        let mut delay_secs = self.ack_timeout_secs.saturating_mul(1u64 << exp);
        delay_secs = delay_secs.min(self.max_backoff_secs);
        now + delay_secs as i64
    }
}

pub(super) struct FallbackRuntime {
    pub(super) state: Arc<PrivateState>,
    pub(super) attempt_policy: FallbackAttemptPolicy,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum AttemptBudget {
    Enforced,
    Unlimited,
}

struct FallbackPayloadContext {
    payload: Vec<u8>,
}

impl FallbackPayloadContext {
    fn parse(message: &PrivateMessage, now: i64) -> Option<Self> {
        if message.expires_at <= now {
            return None;
        }
        let envelope =
            crate::private::protocol::PrivatePayloadEnvelope::decode_postcard(&message.payload)?;
        if !envelope.is_supported_version() {
            return None;
        }
        Some(Self {
            payload: message.payload.clone(),
        })
    }

    async fn dispatch_to(
        &self,
        state: &PrivateState,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> bool {
        state.hub
            .deliver_to_device(
                device_id,
                crate::private::protocol::DeliverEnvelope {
                    delivery_id: delivery_id.to_string(),
                    payload: self.payload.clone(),
                },
            )
            .await
    }
}

impl FallbackRuntime {
    pub(super) fn new(state: Arc<PrivateState>) -> Self {
        Self {
            attempt_policy: FallbackAttemptPolicy::from_config(&state.config),
            state,
        }
    }

    pub(super) fn wake_at(unix_secs: i64) -> TokioInstant {
        let now_unix = chrono::Utc::now().timestamp();
        if unix_secs <= now_unix {
            TokioInstant::now()
        } else {
            TokioInstant::now() + Duration::from_secs((unix_secs - now_unix) as u64)
        }
    }

    fn try_trim_allocator(&self) {}

    pub(super) async fn run_claim_ack_drain(
        &self,
        _scheduler: &mut FallbackScheduler,
        batch_size: usize,
        max_rounds: usize,
        max_processed_total: usize,
    ) -> Result<(), crate::Error> {
        let batch_size = batch_size.max(1);
        let max_rounds = max_rounds.max(1);
        let max_processed_total = max_processed_total.max(batch_size);
        let mut processed_total = 0usize;
        for round in 0..max_rounds {
            let online_devices = self.state.hub.online_device_ids();
            if online_devices.is_empty() {
                break;
            }
            let now = chrono::Utc::now().timestamp();
            let claim_until =
                now.saturating_add(self.state.config.ack_timeout_secs.clamp(5, 120) as i64);
            let remaining_budget = max_processed_total.saturating_sub(processed_total);
            if remaining_budget == 0 {
                break;
            }
            let round_budget = batch_size.min(remaining_budget);
            if round_budget == 0 {
                break;
            }

            let mut processed = 0usize;
            let per_device_limit = (round_budget / online_devices.len().max(1)).max(1);
            for device_id in online_devices {
                if processed >= round_budget || processed_total >= max_processed_total {
                    break;
                }
                let device_limit = per_device_limit.min(round_budget.saturating_sub(processed));
                if device_limit == 0 {
                    break;
                }
                let claimed = self
                    .state
                    .hub
                    .claim_due_outbox_for_device(device_id, now, device_limit, claim_until)
                    .await?;
                if claimed.is_empty() {
                    continue;
                }
                for outbox in claimed {
                    processed = processed.saturating_add(1);
                    processed_total = processed_total.saturating_add(1);
                    self.run_claimed_fallback_task(device_id, &outbox, now).await?;
                    if processed >= round_budget || processed_total >= max_processed_total {
                        break;
                    }
                }
            }

            if processed == 0 || processed < round_budget {
                break;
            }
            if round + 1 < max_rounds {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }

    pub(super) async fn resync_fallback_tasks(
        &self,
        scheduler: &mut FallbackScheduler,
        limit: usize,
    ) -> Result<(), crate::Error> {
        let online_device_ids: HashSet<DeviceId> =
            self.state.hub.online_device_ids().into_iter().collect();
        if online_device_ids.is_empty() {
            scheduler.replace_fallback_tasks(std::iter::empty());
            return Ok(());
        }
        let total_pending = self.state.hub.count_pending_outbox_total().await?;
        let entries = self.state.hub.list_due_outbox(i64::MAX, limit).await?;
        let snapshot = entries.into_iter().filter_map(|(device_id, entry)| {
            online_device_ids.contains(&device_id).then_some((
                FallbackTaskKey {
                    device_id,
                    delivery_id: entry.delivery_id,
                },
                entry.next_attempt_at,
            ))
        });
        if total_pending > limit {
            scheduler.merge_fallback_tasks(snapshot);
        } else {
            scheduler.replace_fallback_tasks(snapshot);
        }
        Ok(())
    }

    pub(super) async fn run_maintenance_tick(&self) -> Result<(), crate::Error> {
        const DELIVERY_DEDUPE_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
        let now = chrono::Utc::now().timestamp();
        let dedupe_before = now - DELIVERY_DEDUPE_RETENTION_SECS;
        let cleanup: MaintenanceCleanupStats = self
            .state
            .hub
            .run_maintenance_cleanup(now, dedupe_before)
            .await?;
        if cleanup.private_outbox_pruned > 0
            && let Some(engine) = &self.state.fallback_tasks
        {
            engine.request_resync();
        }

        let pending_outbox = self.state.hub.count_pending_outbox_total().await?;
        let target_hot_cache = self.state.hub.hot_cache_target_for_pending(pending_outbox);
        self.state.hub.compact_hot_cache(target_hot_cache);
        self.try_trim_allocator();
        Ok(())
    }

    pub(super) async fn seed_fallback_tasks(&self, scheduler: &mut FallbackScheduler) {
        let online_device_ids: HashSet<DeviceId> =
            self.state.hub.online_device_ids().into_iter().collect();
        if online_device_ids.is_empty() {
            return;
        }
        let total_pending = match self.state.hub.count_pending_outbox_total().await {
            Ok(value) => value,
            Err(_err) => return,
        };
        if total_pending == 0 {
            return;
        }
        let seed_limit = total_pending.min(200_000);
        let entries = match self.state.hub.list_due_outbox(i64::MAX, seed_limit).await {
            Ok(value) => value,
            Err(_err) => return,
        };
        let mut seeded = 0usize;
        for (device_id, entry) in entries {
            if !online_device_ids.contains(&device_id) {
                continue;
            }
            scheduler.schedule(
                FallbackTaskKey {
                    device_id,
                    delivery_id: entry.delivery_id,
                },
                entry.next_attempt_at,
            );
            seeded = seeded.saturating_add(1);
        }
        if seeded > 0 {
            self.state.metrics.mark_replay_bootstrap_enqueued(seeded);
        }
    }

    async fn run_claimed_fallback_task(
        &self,
        device_id: DeviceId,
        outbox: &PrivateOutboxEntry,
        now: i64,
    ) -> Result<(), crate::Error> {
        let Some(message) = self
            .state
            .hub
            .load_private_message(outbox.delivery_id.as_str())
            .await?
        else {
            self.drop_fallback_delivery(device_id, outbox.delivery_id.as_str())
                .await?;
            return Ok(());
        };
        let Some(context) = FallbackPayloadContext::parse(&message, now) else {
            self.drop_fallback_delivery(device_id, outbox.delivery_id.as_str())
                .await?;
            return Ok(());
        };

        if !self.state.hub.is_online(device_id) {
            return Ok(());
        }

        if self.attempt_policy.should_drop_outbox(outbox) {
            self.drop_fallback_delivery(device_id, outbox.delivery_id.as_str())
                .await?;
            return Ok(());
        }

        let sent = context
            .dispatch_to(&self.state, device_id, outbox.delivery_id.as_str())
            .await;

        if sent {
            let next_attempt_at =
                now.saturating_add(self.state.config.ack_timeout_secs.max(1) as i64);
            let _ = self
                .state
                .mark_fallback_sent(device_id, outbox.delivery_id.as_str(), next_attempt_at)
                .await;
            self.state.metrics.mark_fallback_tick(1, 1, 0, 0);
            return Ok(());
        }

        self.state.metrics.mark_deliver_send_failure();
        self.schedule_fallback_retry(device_id, outbox, now, 0, AttemptBudget::Enforced)
            .await?;
        Ok(())
    }

    async fn schedule_fallback_retry(
        &self,
        device_id: DeviceId,
        outbox: &PrivateOutboxEntry,
        now: i64,
        sent: usize,
        budget: AttemptBudget,
    ) -> Result<i64, crate::Error> {
        let next_attempt = outbox.attempts.saturating_add(1);
        if self.attempt_policy.should_drop_attempt(next_attempt, budget) {
            self.drop_fallback_delivery(device_id, outbox.delivery_id.as_str())
                .await?;
            return Ok(now);
        }
        let retry_at = self.attempt_policy.retry_at(now, next_attempt);
        let _ = self
            .state
            .defer_fallback_retry(device_id, outbox.delivery_id.as_str(), retry_at)
            .await;
        self.state.metrics.mark_fallback_tick(1, sent, 1, 0);
        Ok(retry_at)
    }

    async fn drop_fallback_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<(), crate::Error> {
        let _ = self.state.drop_terminal_delivery(device_id, delivery_id).await?;
        self.state.metrics.mark_fallback_tick(1, 0, 0, 1);
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{AttemptBudget, FallbackAttemptPolicy, FallbackPayloadContext, FallbackRuntime};
    use crate::{
        private::{PrivateConfig, PrivateState, protocol::PrivatePayloadEnvelope},
        routing::{DeviceRegistry, derive_private_device_id},
        stats::StatsCollector,
        storage::{
            OUTBOX_STATUS_PENDING, OUTBOX_STATUS_SENT, PrivateMessage, Storage,
        },
    };
    use flume::bounded;
    use hashbrown::HashMap;
    use tempfile::{TempDir, tempdir};
    use warp_link::warp_link_core::TransportKind;

    struct RuntimeTestContext {
        _dir: TempDir,
        state: Arc<PrivateState>,
    }

    impl RuntimeTestContext {
        async fn new() -> Self {
            let dir = tempdir().expect("tempdir should be created");
            let db_path = dir.path().join("fallback-runtime.sqlite");
            let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
            let storage = Storage::new(Some(db_url.as_str()))
                .await
                .expect("storage should initialize");
            let stats = StatsCollector::spawn(storage.clone());
            let state = Arc::new(PrivateState::new(
                storage,
                test_private_config(),
                Arc::new(DeviceRegistry::new()),
                stats,
            ));
            Self { _dir: dir, state }
        }
    }

    fn test_private_config() -> PrivateConfig {
        PrivateConfig {
            private_quic_bind: None,
            private_tcp_bind: None,
            tcp_tls_offload: false,
            tcp_proxy_protocol: false,
            private_tls_cert_path: None,
            private_tls_key_path: None,
            session_ttl_secs: 60,
            grace_window_secs: 10,
            max_pending_per_device: 16,
            global_max_pending: 64,
            pull_limit: 32,
            ack_timeout_secs: 1,
            fallback_max_attempts: 3,
            fallback_max_backoff_secs: 8,
            retransmit_window_secs: 30,
            retransmit_max_per_window: 10,
            retransmit_max_per_tick: 16,
            retransmit_max_retries: 3,
            hot_cache_capacity: 64,
            default_ttl_secs: 60,
            gateway_token: None,
        }
        .normalized()
    }

    fn private_message_with_data(data: HashMap<String, String>, expires_at: i64) -> PrivateMessage {
        PrivateMessage {
            payload: postcard::to_allocvec(&PrivatePayloadEnvelope {
                payload_version: crate::private::protocol::PRIVATE_PAYLOAD_VERSION_V1,
                data,
            })
            .expect("payload should encode"),
            size: 0,
            sent_at: 0,
            expires_at,
        }
    }

    #[test]
    fn fallback_payload_context_parses_valid_payload() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("ttl".to_string(), "120".to_string());
        let context = FallbackPayloadContext::parse(&private_message_with_data(data, 120), 60)
            .expect("valid payload should parse");
        assert!(!context.payload.is_empty());
    }

    #[test]
    fn fallback_payload_context_accepts_private_payload_without_provider_metadata() {
        let minimal = private_message_with_data(HashMap::new(), 120);
        assert!(FallbackPayloadContext::parse(&minimal, 60).is_some());

        let mut data = HashMap::new();
        data.insert("channel_id".to_string(), "bad".to_string());
        let invalid_channel = private_message_with_data(data, 120);
        assert!(FallbackPayloadContext::parse(&invalid_channel, 60).is_some());
    }

    #[test]
    fn fallback_payload_context_rejects_expired_payload() {
        let expired = private_message_with_data(HashMap::new(), 10);
        assert!(FallbackPayloadContext::parse(&expired, 60).is_none());
    }

    #[test]
    fn attempt_budget_can_disable_drop_logic() {
        let policy = FallbackAttemptPolicy {
            max_attempts: 3,
            ack_timeout_secs: 1,
            max_backoff_secs: 1,
        };
        assert!(!policy.should_drop_attempt(10, AttemptBudget::Unlimited));
        assert!(policy.should_drop_attempt(3, AttemptBudget::Enforced));
    }

    #[tokio::test]
    async fn claimed_fallback_redelivers_over_private_transport_and_marks_sent() {
        let ctx = RuntimeTestContext::new().await;
        let runtime = FallbackRuntime::new(Arc::clone(&ctx.state));
        let device_key = "fallback-runtime-device";
        let device_id = derive_private_device_id(device_key);
        let delivery_id = "delivery-redeliver-1";
        let now = chrono::Utc::now().timestamp();
        let sent_at = now - 3;
        let expires_at = now + 60;
        let channel_id = crate::api::format_channel_id(&[0x42; 16]);
        let payload = private_message_with_data(
            HashMap::from([
                ("channel_id".to_string(), channel_id),
                ("ttl".to_string(), expires_at.to_string()),
                ("title".to_string(), "Redelivery Title".to_string()),
            ]),
            expires_at,
        )
        .payload;

        ctx.state
            .enqueue_private_delivery(device_id, delivery_id, payload.clone(), sent_at, expires_at)
            .await
            .expect("delivery should enqueue");

        let (tx, rx) = bounded(4);
        ctx.state
            .hub
            .register_connection(device_id, 1, TransportKind::Wss, tx);

        let mut scheduler = crate::private::FallbackScheduler::default();
        runtime
            .run_claim_ack_drain(&mut scheduler, 8, 1, 8)
            .await
            .expect("fallback drain should succeed");

        let delivered = tokio::time::timeout(Duration::from_secs(1), rx.recv_async())
            .await
            .expect("delivery should arrive before timeout")
            .expect("delivery channel should stay open");
        assert_eq!(delivered.delivery_id, delivery_id);
        assert_eq!(delivered.payload, payload);

        let entry = ctx
            .state
            .hub
            .store()
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("outbox lookup should succeed")
            .expect("outbox entry should remain pending for ack");
        assert_eq!(entry.status, OUTBOX_STATUS_SENT);
        assert_eq!(entry.attempts, 1);
        assert!(entry.first_sent_at.is_some());
        assert!(entry.fallback_sent_at.is_some());
    }

    #[tokio::test]
    async fn claimed_fallback_send_failure_defers_private_retry() {
        let ctx = RuntimeTestContext::new().await;
        let runtime = FallbackRuntime::new(Arc::clone(&ctx.state));
        let device_key = "fallback-runtime-failure-device";
        let device_id = derive_private_device_id(device_key);
        let delivery_id = "delivery-redeliver-failure-1";
        let now = chrono::Utc::now().timestamp();
        let sent_at = now - 3;
        let expires_at = now + 60;
        let channel_id = crate::api::format_channel_id(&[0x24; 16]);
        let payload = private_message_with_data(
            HashMap::from([
                ("channel_id".to_string(), channel_id),
                ("ttl".to_string(), expires_at.to_string()),
            ]),
            expires_at,
        )
        .payload;

        ctx.state
            .enqueue_private_delivery(device_id, delivery_id, payload, sent_at, expires_at)
            .await
            .expect("delivery should enqueue");

        let (tx, rx) = bounded(1);
        drop(rx);
        ctx.state
            .hub
            .register_connection(device_id, 2, TransportKind::Wss, tx);

        let mut scheduler = crate::private::FallbackScheduler::default();
        runtime
            .run_claim_ack_drain(&mut scheduler, 8, 1, 8)
            .await
            .expect("fallback drain should complete");

        let entry = ctx
            .state
            .hub
            .store()
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("outbox lookup should succeed")
            .expect("outbox entry should stay queued for retry");
        assert_eq!(entry.status, OUTBOX_STATUS_PENDING);
        assert_eq!(entry.attempts, 1);
        assert!(entry.fallback_sent_at.is_none());
        assert!(entry.next_attempt_at > sent_at);
    }
}
