use super::*;
use crate::util::build_provider_wakeup_data;

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
    pub(super) dispatch: DispatchChannels,
    pub(super) attempt_policy: FallbackAttemptPolicy,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum AttemptBudget {
    Enforced,
    Unlimited,
}

struct FallbackPayloadContext {
    channel_id: [u8; 16],
    channel_id_raw: String,
    wakeup_data: HashMap<String, String>,
    wakeup_title: Option<String>,
    ttl: Option<i64>,
    ttl_seconds: Option<u32>,
}

impl FallbackPayloadContext {
    fn parse(message: &PrivateMessage, now: i64) -> Option<Self> {
        if message.expires_at <= now {
            return None;
        }
        let envelope = crate::private::protocol::PrivatePayloadEnvelope::decode_postcard(
            &message.payload,
        )?;
        if !envelope.is_supported_version() {
            return None;
        }
        let channel_id_raw = envelope.channel_id_raw()?.to_string();
        let channel_id = envelope.parsed_channel_id()?;
        let ttl = envelope.ttl();
        let ttl_seconds = envelope.ttl_seconds_remaining(now);
        Some(Self {
            channel_id,
            wakeup_data: build_provider_wakeup_data(&envelope.data),
            wakeup_title: crate::api::handlers::message::wakeup_notification_title_from_private_payload(
                &message.payload,
            ),
            channel_id_raw,
            ttl,
            ttl_seconds,
        })
    }

    fn dispatch_to(
        &self,
        dispatch: &DispatchChannels,
        delivery_id: &str,
        target: &SystemTarget,
    ) -> bool {
        target.dispatch_wakeup_pull(dispatch, delivery_id, self)
    }
}

impl FallbackRuntime {
    pub(super) fn new(state: Arc<PrivateState>, dispatch: DispatchChannels) -> Self {
        Self {
            attempt_policy: FallbackAttemptPolicy::from_config(&state.config),
            state,
            dispatch,
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

    fn wakeup_pull_enabled(&self) -> bool {
        PROVIDER_WAKEUP_PULL_ENABLED
    }

    fn try_trim_allocator(&self) {}

    pub(super) async fn run_claim_ack_drain(
        &self,
        _scheduler: &mut FallbackScheduler,
        batch_size: usize,
        max_rounds: usize,
        max_processed_total: usize,
    ) -> Result<(), crate::Error> {
        if !self.wakeup_pull_enabled() {
            return Ok(());
        }
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
        if !self.wakeup_pull_enabled() {
            scheduler.replace_fallback_tasks(std::iter::empty::<(FallbackTaskKey, i64)>());
            return Ok(());
        }
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
        if !self.wakeup_pull_enabled() {
            return;
        }
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

        let Some(target) = self.resolve_system_target(context.channel_id, device_id).await else {
            return Ok(());
        };

        if self.attempt_policy.should_drop_outbox(outbox) {
            self.drop_fallback_delivery(device_id, outbox.delivery_id.as_str())
                .await?;
            return Ok(());
        }

        let sent = context.dispatch_to(&self.dispatch, outbox.delivery_id.as_str(), &target);

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

    async fn resolve_system_target(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> Option<SystemTarget> {
        self.state.resolve_system_target(channel_id, device_id).await
    }
}

impl SystemTarget {
    fn dispatch_wakeup_pull(
        &self,
        dispatch: &DispatchChannels,
        delivery_id: &str,
        context: &FallbackPayloadContext,
    ) -> bool {
        match self.platform {
            Platform::ANDROID => {
                let correlation_id: Arc<str> = Arc::from(delivery_id.to_string());
                let payload = Arc::new(FcmPayload::new(
                    SharedStringMap::from(context.wakeup_data.clone()),
                    "HIGH",
                    context.ttl_seconds,
                ));
                let body = match payload.encoded_body(self.token.as_ref()) {
                    Ok(body) => body,
                    Err(_) => return false,
                };
                dispatch
                    .try_send_fcm(FcmJob {
                        channel_id: context.channel_id,
                        correlation_id: correlation_id.clone(),
                        delivery_id: correlation_id,
                        device_token: Arc::clone(&self.token),
                        direct_payload: Arc::clone(&payload),
                        direct_body: Arc::clone(&body),
                        wakeup_payload: Some(Arc::clone(&payload)),
                        wakeup_body: Some(body),
                        initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                        wakeup_payload_within_limit: true,
                        provider_pull_delivery: None,
                    })
                    .is_ok()
            }
            Platform::WINDOWS => {
                let correlation_id: Arc<str> = Arc::from(delivery_id.to_string());
                let payload = Arc::new(WnsPayload::new(
                    SharedStringMap::from(context.wakeup_data.clone()),
                    "high",
                    context.ttl_seconds,
                ));
                dispatch
                    .try_send_wns(WnsJob {
                        channel_id: context.channel_id,
                        correlation_id: correlation_id.clone(),
                        delivery_id: correlation_id,
                        device_token: Arc::clone(&self.token),
                        direct_payload: Arc::clone(&payload),
                        wakeup_payload: Some(Arc::clone(&payload)),
                        initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                        wakeup_payload_within_limit: true,
                        provider_pull_delivery: None,
                    })
                    .is_ok()
            }
            _ => {
                let correlation_id: Arc<str> = Arc::from(delivery_id.to_string());
                let collapse_id: Arc<str> =
                    Arc::from(format!("private-wakeup:{}", context.channel_id_raw));
                let payload = Arc::new(ApnsPayload::wakeup(
                    context.wakeup_title.clone(),
                    Some(context.channel_id_raw.clone()),
                    context.ttl,
                    SharedStringMap::from(context.wakeup_data.clone()),
                ));
                dispatch
                    .try_send_apns(ApnsJob {
                        channel_id: context.channel_id,
                        correlation_id: correlation_id.clone(),
                        delivery_id: correlation_id,
                        device_token: Arc::clone(&self.token),
                        platform: self.platform,
                        direct_payload: Arc::clone(&payload),
                        wakeup_payload: Some(Arc::clone(&payload)),
                        initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                        wakeup_payload_within_limit: true,
                        provider_pull_delivery: None,
                        collapse_id: Some(collapse_id),
                    })
                    .is_ok()
            }
        }
    }
}

pub(super) struct SystemTarget {
    pub(super) platform: Platform,
    pub(super) token: Arc<str>,
}

#[cfg(test)]
mod tests {
    use super::{AttemptBudget, FallbackAttemptPolicy, FallbackPayloadContext};
    use crate::{private::protocol::PrivatePayloadEnvelope, storage::PrivateMessage};
    use hashbrown::HashMap;

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
        assert_eq!(context.channel_id_raw, "06J0FZG1Y8XGG14VTQ4Y3G10MR");
        assert_eq!(context.ttl, Some(120));
        assert_eq!(context.ttl_seconds, Some(60));
        assert!(context.wakeup_data.contains_key("provider_wakeup"));
    }

    #[test]
    fn fallback_payload_context_rejects_missing_or_invalid_channel() {
        let invalid = private_message_with_data(HashMap::new(), 120);
        assert!(FallbackPayloadContext::parse(&invalid, 60).is_none());

        let mut data = HashMap::new();
        data.insert("channel_id".to_string(), "bad".to_string());
        let invalid = private_message_with_data(data, 120);
        assert!(FallbackPayloadContext::parse(&invalid, 60).is_none());
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
}
