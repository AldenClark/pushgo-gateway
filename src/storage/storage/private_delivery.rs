use super::*;
use crate::{
    private::protocol::PrivatePayloadEnvelope,
    storage::database::{
        PrivateChannelDatabaseAccess, PrivateMessageDatabaseAccess, ProviderPullDatabaseAccess,
    },
    value::ProviderTokenRef,
};
use std::sync::atomic::{AtomicU64, Ordering};

impl Storage {
    pub async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        self.db
            .load_private_outbox_entry(device_id, delivery_id)
            .await
    }

    pub async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        self.db.insert_private_message(delivery_id, message).await
    }

    pub async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        self.db.enqueue_private_outbox(device_id, entry).await
    }

    pub async fn enqueue_private_outbox_batch(
        &self,
        entries: &[PrivateOutboxBatchEntry],
        max_pending_per_device: usize,
        global_max_pending: usize,
        protected_delivery_id: Option<&str>,
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        self.db
            .enqueue_private_outbox_batch(
                entries,
                max_pending_per_device,
                global_max_pending,
                protected_delivery_id,
            )
            .await
    }

    pub async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        self.db.list_private_outbox(device_id, limit).await
    }

    pub async fn evict_oldest_pending_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Option<String>> {
        self.db
            .evict_oldest_pending_private_outbox_for_device(device_id)
            .await
    }

    pub async fn evict_oldest_pending_private_outbox_global(
        &self,
    ) -> StoreResult<Option<(DeviceId, String)>> {
        self.db.evict_oldest_pending_private_outbox_global().await
    }

    pub async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize> {
        self.db.count_private_outbox_for_device(device_id).await
    }

    pub async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db.ack_private_delivery(device_id, delivery_id).await
    }

    pub async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>> {
        self.db.load_private_message(delivery_id).await
    }

    pub async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        if let Some(msg) = self.db.load_private_message(delivery_id).await? {
            return Ok(PrivatePayloadContext::decode(msg.payload.as_ref()));
        }
        Ok(None)
    }

    pub async fn enqueue_provider_pull_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        self.db
            .enqueue_provider_pull_item(device_id, delivery_id, message, platform, provider_token)
            .await
    }

    pub async fn pull_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let item = self
            .db
            .pull_provider_item(device_id, delivery_id, now)
            .await?;
        let Some(item) = item else {
            return Ok(None);
        };

        self.clear_private_outbox_after_provider_delivery(&item)
            .await;
        Ok(Some(item))
    }

    pub async fn pull_provider_items(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullItem>> {
        let items = self.db.pull_provider_items(device_id, now, limit).await?;
        for item in &items {
            self.clear_private_outbox_after_provider_delivery(item)
                .await;
        }
        Ok(items)
    }

    pub async fn ack_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let item = self
            .db
            .ack_provider_item(device_id, delivery_id, now)
            .await?;
        let Some(item) = item else {
            return Ok(None);
        };
        self.clear_private_outbox_after_provider_delivery(&item)
            .await;
        Ok(Some(item))
    }

    pub async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        at_delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        self.db
            .mark_private_fallback_sent(device_id, at_delivery_id, at_ts)
            .await
    }

    pub async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        self.db
            .defer_private_fallback(device_id, delivery_id, at_ts)
            .await
    }

    pub async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        self.db.clear_private_outbox_for_device(device_id).await
    }

    pub async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        self.db.list_private_outbox_due(before_ts, limit).await
    }

    pub async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        self.db
            .claim_private_outbox_due(before_ts, limit, claim_until_ts)
            .await
    }

    pub async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        self.db
            .claim_private_outbox_due_for_device(device_id, before_ts, limit, claim_until_ts)
            .await
    }

    pub async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        self.db.count_private_outbox_total().await
    }

    pub async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        self.db.lookup_private_device(platform, token).await
    }

    pub async fn migrate_private_pending_to_provider_queue(
        &self,
        device_id: DeviceId,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<usize> {
        let Some(normalized_token) = ProviderTokenRef::optional(Some(provider_token)) else {
            return Ok(0);
        };
        let pending = self.db.count_private_outbox_for_device(device_id).await?;
        if pending == 0 {
            return Ok(0);
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pending_migration_started",
            direction = %("private_to_provider"),
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            platform = %(platform.name()),
            pending = (pending as u64)
        );
        let entries = self.db.list_private_outbox(device_id, pending).await?;
        let mut migrated = 0usize;
        let mut missing_messages = 0usize;
        for entry in entries {
            let Some(message) = self
                .db
                .load_private_message(entry.delivery_id.as_str())
                .await?
            else {
                missing_messages = missing_messages.saturating_add(1);
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::INFO,
                    event = "provider.pending_migration_message_missing",
                    direction = %("private_to_provider"),
                    device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                    delivery_id = %(crate::util::redact_text(entry.delivery_id.as_str()))
                );
                continue;
            };
            self.db
                .enqueue_provider_pull_item(
                    device_id,
                    entry.delivery_id.as_str(),
                    &message,
                    platform,
                    normalized_token.as_str(),
                )
                .await?;
            migrated = migrated.saturating_add(1);
        }
        if migrated > 0 {
            let _cleared = self.db.clear_private_outbox_for_device(device_id).await?;
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pending_migration_finished",
            direction = %("private_to_provider"),
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            pending = (pending as u64),
            migrated = (migrated as u64),
            missing_messages = (missing_messages as u64)
        );
        Ok(migrated)
    }

    pub async fn migrate_provider_pending_to_private_outbox(
        &self,
        device_id: DeviceId,
        ack_timeout_secs: u64,
        max_pending_per_device: usize,
    ) -> StoreResult<usize> {
        const BATCH_SIZE: usize = 512;
        let existing_pending = self.db.count_private_outbox_for_device(device_id).await?;
        let mut remaining_capacity = max_pending_per_device.saturating_sub(existing_pending);
        if remaining_capacity == 0 {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "provider.pending_migration_skipped",
                direction = %("provider_to_private"),
                device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                reason = %("no_remaining_capacity"),
                existing_pending = (existing_pending as u64),
                max_pending_per_device = (max_pending_per_device as u64)
            );
            return Ok(0);
        }
        let now = chrono::Utc::now().timestamp_millis();
        let next_attempt_at = now.saturating_add(ack_timeout_secs.max(1) as i64 * 1000);
        let mut migrated = 0usize;
        let mut source_pulled = 0usize;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pending_migration_started",
            direction = %("provider_to_private"),
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            existing_pending = (existing_pending as u64),
            remaining_capacity = (remaining_capacity as u64),
            ack_timeout_secs = (ack_timeout_secs)
        );

        loop {
            let batch_size = remaining_capacity.min(BATCH_SIZE);
            if batch_size == 0 {
                break;
            }
            let items = self
                .db
                .pull_provider_items(device_id, now, batch_size)
                .await?;
            if items.is_empty() {
                break;
            }
            source_pulled = source_pulled.saturating_add(items.len());
            for item in &items {
                let message = PrivateMessage {
                    payload: item.payload.clone(),
                    size: item.payload.len(),
                    sent_at: item.sent_at,
                    expires_at: item.expires_at,
                };
                self.db
                    .insert_private_message(item.delivery_id.as_str(), &message)
                    .await?;
                let entry = PrivateOutboxEntry {
                    delivery_id: item.delivery_id.clone(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: item.sent_at,
                    created_at: now,
                    claimed_at: None,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now,
                };
                self.db.enqueue_private_outbox(device_id, &entry).await?;
                migrated = migrated.saturating_add(1);
                remaining_capacity = remaining_capacity.saturating_sub(1);
                if remaining_capacity == 0 {
                    break;
                }
            }
            if items.len() < batch_size || remaining_capacity == 0 {
                break;
            }
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pending_migration_finished",
            direction = %("provider_to_private"),
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            source_pulled = (source_pulled as u64),
            migrated = (migrated as u64),
            remaining_capacity = (remaining_capacity as u64)
        );
        Ok(migrated)
    }

    async fn clear_private_outbox_after_provider_delivery(&self, item: &ProviderPullItem) {
        let Some(envelope) = PrivatePayloadEnvelope::decode_postcard(item.payload.as_ref()) else {
            emit_provider_pull_ack_skip(
                "decode_failed",
                item.device_id,
                item.delivery_id.as_str(),
                None,
            );
            return;
        };
        if !envelope.is_supported_version() {
            emit_provider_pull_ack_skip(
                "unsupported_payload_version",
                item.device_id,
                item.delivery_id.as_str(),
                None,
            );
            return;
        }
        let Some(original_delivery_id) = envelope
            .data
            .get("delivery_id")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            emit_provider_pull_ack_skip(
                "missing_original_delivery_id",
                item.device_id,
                item.delivery_id.as_str(),
                None,
            );
            return;
        };
        if let Err(err) = self
            .ack_private_delivery(item.device_id, original_delivery_id)
            .await
        {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "provider.pull_private_outbox_ack_failed",
                delivery_id = %(crate::util::redact_text(item.delivery_id.as_str())),
                original_delivery_id = %(crate::util::redact_text(original_delivery_id)),
                device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&item.device_id))),
                error = %(err.to_string())
            );
        } else {
            emit_provider_pull_ack_skip(
                "acked_linked_private_outbox",
                item.device_id,
                item.delivery_id.as_str(),
                Some(original_delivery_id),
            );
        }
    }
}

fn emit_provider_pull_ack_skip(
    reason: &'static str,
    device_id: DeviceId,
    delivery_id: &str,
    original_delivery_id: Option<&str>,
) {
    static PROVIDER_PULL_ACK_OBS_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = PROVIDER_PULL_ACK_OBS_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !(count <= 8 || count.is_power_of_two()) {
        return;
    }
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "provider.pull_private_outbox_ack_observed",
        reason = %(reason),
        count = (count),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
        original_delivery_id = ?original_delivery_id.map(crate::util::redact_text)
    );
}
