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
