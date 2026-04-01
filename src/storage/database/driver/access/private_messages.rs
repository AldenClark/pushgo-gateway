use super::*;
use async_trait::async_trait;

#[async_trait]
impl PrivateMessageDatabaseAccess for DatabaseDriver {
    async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        delegate_db_async!(self, load_private_outbox_entry(device_id, delivery_id))
    }

    async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        delegate_db_async!(self, delete_private_device_state(device_id))
    }

    async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        delegate_db_async!(self, insert_private_message(delivery_id, message))
    }

    async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        delegate_db_async!(self, enqueue_private_outbox(device_id, entry))
    }

    async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        delegate_db_async!(self, list_private_outbox(device_id, limit))
    }

    async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize> {
        delegate_db_async!(self, count_private_outbox_for_device(device_id))
    }

    async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_private_expired_data(before_ts, limit))
    }

    async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_private_sessions(before_ts))
    }

    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, bind_private_token(device_id, platform, token))
    }

    async fn load_private_message(&self, delivery_id: &str) -> StoreResult<Option<PrivateMessage>> {
        delegate_db_async!(self, load_private_message(delivery_id))
    }

    async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        delegate_db_async!(self, load_private_payload_context(delivery_id))
    }

    async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            mark_private_fallback_sent(device_id, delivery_id, at_ts)
        )
    }

    async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(self, defer_private_fallback(device_id, delivery_id, at_ts))
    }

    async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, ack_private_delivery(device_id, delivery_id))
    }

    async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        delegate_db_async!(self, clear_private_outbox_for_device(device_id))
    }

    async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        delegate_db_async!(self, list_private_outbox_due(before_ts, limit))
    }

    async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        delegate_db_async!(
            self,
            claim_private_outbox_due(before_ts, limit, claim_until_ts)
        )
    }

    async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        delegate_db_async!(
            self,
            claim_private_outbox_due_for_device(device_id, before_ts, limit, claim_until_ts)
        )
    }

    async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        delegate_db_async!(self, count_private_outbox_total())
    }
}
