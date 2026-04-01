use super::*;
use crate::storage::database::{
    PrivateChannelDatabaseAccess, PrivateMessageDatabaseAccess, ProviderPullDatabaseAccess,
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
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        self.db
            .enqueue_provider_pull_item(
                delivery_id,
                message,
                platform,
                provider_token,
                next_retry_at,
            )
            .await
    }

    pub async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        self.db.pull_provider_item(delivery_id, now).await
    }

    pub async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        self.db.list_provider_pull_retry_due(now, limit).await
    }

    pub async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        self.db
            .bump_provider_pull_retry(delivery_id, next_retry_at, now)
            .await
    }

    pub async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        self.db.clear_provider_pull_retry(delivery_id).await
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
}
