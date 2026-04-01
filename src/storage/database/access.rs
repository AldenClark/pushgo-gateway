use super::*;
use async_trait::async_trait;

#[async_trait]
pub trait ChannelQueryDatabaseAccess: Send + Sync {
    async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>>;
    async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>>;
    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>>;
    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<(ChannelInfo, String)>>;
    async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()>;
}

#[async_trait]
pub trait ProviderSubscriptionDatabaseAccess: Send + Sync {
    async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome>;
    async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool>;
    async fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize>;
    async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize>;
    async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>>;
}

#[async_trait]
pub trait PrivateChannelDatabaseAccess: Send + Sync {
    async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>>;
    async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
    ) -> StoreResult<SubscribeOutcome>;
    async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()>;
    async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()>;
    async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>>;
    async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>>;
}

pub trait ChannelDatabaseAccess:
    ChannelQueryDatabaseAccess
    + ProviderSubscriptionDatabaseAccess
    + PrivateChannelDatabaseAccess
    + Send
    + Sync
{
}

impl<T> ChannelDatabaseAccess for T where
    T: ChannelQueryDatabaseAccess
        + ProviderSubscriptionDatabaseAccess
        + PrivateChannelDatabaseAccess
        + Send
        + Sync
{
}

#[async_trait]
pub trait PrivateMessageDatabaseAccess: Send + Sync {
    async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>>;
    async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()>;
    async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()>;
    async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()>;
    async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>>;
    async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize>;
    async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize>;
    async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize>;
    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()>;
    async fn load_private_message(&self, delivery_id: &str) -> StoreResult<Option<PrivateMessage>>;
    async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>>;
    async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()>;
    async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()>;
    async fn ack_private_delivery(&self, device_id: DeviceId, delivery_id: &str)
    -> StoreResult<()>;
    async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>>;
    async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>>;
    async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>>;
    async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>>;
    async fn count_private_outbox_total(&self) -> StoreResult<usize>;
}

#[async_trait]
pub trait DeviceRouteDatabaseAccess: Send + Sync {
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>>;
    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()>;
    async fn apply_route_snapshot(&self, snapshot: &DeviceRouteSnapshot) -> StoreResult<()>;
    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()>;
    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()>;
}

#[async_trait]
pub trait DeliveryAuditDatabaseAccess: Send + Sync {
    async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()>;

    async fn append_delivery_audit_batch(&self, entries: &[DeliveryAuditWrite]) -> StoreResult<()> {
        for entry in entries {
            self.append_delivery_audit(entry).await?;
        }
        Ok(())
    }

    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()>;
}

#[async_trait]
pub trait ProviderPullDatabaseAccess: Send + Sync {
    async fn enqueue_provider_pull_item(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()>;
    async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>>;
    async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>>;
    async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool>;
    async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()>;
}

#[async_trait]
pub trait DedupeDatabaseAccess: Send + Sync {
    async fn cleanup_pending_op_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn cleanup_semantic_id_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn cleanup_delivery_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool>;
    async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation>;
    async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation>;
    async fn mark_op_dedupe_sent(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<bool>;
    async fn clear_op_dedupe_pending(&self, dedupe_key: &str, delivery_id: &str)
    -> StoreResult<()>;
    async fn confirm_delivery_dedupe(&self, dedupe_key: &str, delivery_id: &str)
    -> StoreResult<()>;
}

#[async_trait]
pub trait SystemStateDatabaseAccess: Send + Sync {
    async fn automation_reset(&self) -> StoreResult<()>;
    async fn automation_counts(&self) -> StoreResult<AutomationCounts>;
    async fn load_mcp_state_json(&self) -> StoreResult<Option<String>>;
    async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()>;
}

pub trait DatabaseAccess:
    ChannelDatabaseAccess
    + PrivateMessageDatabaseAccess
    + DeviceRouteDatabaseAccess
    + DeliveryAuditDatabaseAccess
    + ProviderPullDatabaseAccess
    + DedupeDatabaseAccess
    + SystemStateDatabaseAccess
    + Send
    + Sync
{
}

impl<T> DatabaseAccess for T where
    T: ChannelDatabaseAccess
        + PrivateMessageDatabaseAccess
        + DeviceRouteDatabaseAccess
        + DeliveryAuditDatabaseAccess
        + ProviderPullDatabaseAccess
        + DedupeDatabaseAccess
        + SystemStateDatabaseAccess
        + Send
        + Sync
{
}
