use super::*;
use crate::{
    private::protocol::PrivatePayloadEnvelope,
    storage::database::{
        PrivateChannelDatabaseAccess, PrivateMessageDatabaseAccess, ProviderPullDatabaseAccess,
    },
};

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

    pub async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        self.db.list_private_outbox(device_id, limit).await
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
            return Ok(PrivatePayloadContext::decode(&msg.payload));
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
            .enqueue_provider_pull_item(
                device_id,
                delivery_id,
                message,
                platform,
                provider_token,
            )
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

        self.clear_private_outbox_after_provider_delivery(&item).await;
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
            self.clear_private_outbox_after_provider_delivery(item).await;
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
        self.clear_private_outbox_after_provider_delivery(&item).await;
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
        let normalized_token = provider_token.trim();
        if normalized_token.is_empty() {
            return Ok(0);
        }
        let pending = self.db.count_private_outbox_for_device(device_id).await?;
        if pending == 0 {
            return Ok(0);
        }
        let entries = self.db.list_private_outbox(device_id, pending).await?;
        let mut migrated = 0usize;
        for entry in entries {
            let Some(message) = self.db.load_private_message(entry.delivery_id.as_str()).await? else {
                continue;
            };
            self.db
                .enqueue_provider_pull_item(
                    device_id,
                    entry.delivery_id.as_str(),
                    &message,
                    platform,
                    normalized_token,
                )
                .await?;
            migrated = migrated.saturating_add(1);
        }
        Ok(migrated)
    }

    pub async fn migrate_provider_pending_to_private_outbox(
        &self,
        device_id: DeviceId,
        ack_timeout_secs: u64,
    ) -> StoreResult<usize> {
        const BATCH_SIZE: usize = 512;
        let now = chrono::Utc::now().timestamp();
        let next_attempt_at = now.saturating_add(ack_timeout_secs.max(1) as i64);
        let mut migrated = 0usize;

        loop {
            let items = self.db.pull_provider_items(device_id, now, BATCH_SIZE).await?;
            if items.is_empty() {
                break;
            }
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
            }
            if items.len() < BATCH_SIZE {
                break;
            }
        }
        Ok(migrated)
    }

    async fn clear_private_outbox_after_provider_delivery(&self, item: &ProviderPullItem) {
        let Some(envelope) = PrivatePayloadEnvelope::decode_postcard(&item.payload) else {
            return;
        };
        if !envelope.is_supported_version() {
            return;
        }
        let Some(original_delivery_id) = envelope
            .data
            .get("delivery_id")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        if let Err(err) = self
            .ack_private_delivery(item.device_id, original_delivery_id)
            .await
        {
            crate::util::diagnostics_log(format_args!(
                "provider pull cleanup private outbox ack failed delivery_id={} original_delivery_id={} device_id={} error={}",
                item.delivery_id,
                original_delivery_id,
                crate::util::encode_crockford_base32_128(&item.device_id),
                err,
            ));
        }
    }
}
