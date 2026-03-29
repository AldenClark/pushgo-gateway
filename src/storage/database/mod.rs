use crate::storage::{
    database::{mysql::MySqlDb, pg::PostgresDb, sqlite::SqliteDb},
    types::*,
};
use async_trait::async_trait;

pub mod mysql;
pub mod pg;
pub mod sqlite;

#[derive(Debug, Clone)]
pub enum DatabaseDriver {
    Sqlite(SqliteDb),
    MySql(MySqlDb),
    Postgres(PostgresDb),
}

const DEFAULT_SQLITE_DB_URL: &str = "sqlite://./pushgo-gateway.db?mode=rwc";

impl DatabaseDriver {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        let normalized_db_url = normalize_db_url(db_url);
        let db_kind = DatabaseKind::from_url(normalized_db_url.as_str())?;
        match db_kind {
            DatabaseKind::Sqlite => Ok(DatabaseDriver::Sqlite(
                SqliteDb::new(normalized_db_url.as_str()).await?,
            )),
            DatabaseKind::Postgres => Ok(DatabaseDriver::Postgres(
                PostgresDb::new(normalized_db_url.as_str()).await?,
            )),
            DatabaseKind::Mysql => Ok(DatabaseDriver::MySql(
                MySqlDb::new(normalized_db_url.as_str()).await?,
            )),
        }
    }
}

fn normalize_db_url(db_url: Option<&str>) -> String {
    let trimmed = db_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .unwrap_or(DEFAULT_SQLITE_DB_URL);
    if !trimmed.starts_with("sqlite://") {
        return trimmed.to_string();
    }
    if trimmed.contains("mode=") {
        return trimmed.to_string();
    }
    if trimmed.contains('?') {
        format!("{trimmed}&mode=rwc")
    } else {
        format!("{trimmed}?mode=rwc")
    }
}
macro_rules! delegate_db_async {
    ($self:ident, $method:ident ( $($arg:expr),* $(,)? )) => {
        match $self {
            DatabaseDriver::Sqlite(inner) => inner.$method($($arg),*).await,
            DatabaseDriver::MySql(inner) => inner.$method($($arg),*).await,
            DatabaseDriver::Postgres(inner) => inner.$method($($arg),*).await,
        }
    };
}

#[async_trait]
impl DatabaseAccess for DatabaseDriver {
    async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        delegate_db_async!(self, load_private_outbox_entry(device_id, delivery_id))
    }

    async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        delegate_db_async!(self, channel_info(channel_id))
    }

    async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        delegate_db_async!(
            self,
            subscribe_channel(channel_id, alias, password_hash, device_token, platform)
        )
    }

    async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            unsubscribe_channel(channel_id, device_token, platform)
        )
    }

    async fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize> {
        delegate_db_async!(self, retire_device(device_token, platform))
    }

    async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            migrate_device_subscriptions(old_device_token, new_device_token, platform)
        )
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

    async fn cleanup_pending_op_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_pending_op_dedupe(before_ts, limit))
    }

    async fn cleanup_semantic_id_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_semantic_id_dedupe(before_ts, limit))
    }

    async fn cleanup_delivery_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_delivery_dedupe(before_ts, limit))
    }

    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, bind_private_token(device_id, platform, token))
    }

    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        delegate_db_async!(self, load_device_routes())
    }

    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        delegate_db_async!(self, upsert_device_route(route))
    }

    async fn apply_route_snapshot(
        &self,
        device_id: &[u8],
        device_key: &str,
        platform: &str,
        channel_type: &str,
        provider_token: Option<&str>,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            apply_route_snapshot(
                device_id,
                device_key,
                platform,
                channel_type,
                provider_token
            )
        )
    }

    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_device_route_audit(entry))
    }

    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_subscription_audit(entry))
    }

    async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_delivery_audit(entry))
    }

    async fn append_delivery_audit_batch(&self, entries: &[DeliveryAuditWrite]) -> StoreResult<()> {
        delegate_db_async!(self, append_delivery_audit_batch(entries))
    }

    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        delegate_db_async!(self, apply_stats_batch(batch))
    }

    async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        delegate_db_async!(self, list_channel_devices(channel_id))
    }

    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        delegate_db_async!(
            self,
            list_channel_dispatch_targets(channel_id, effective_at)
        )
    }

    async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        delegate_db_async!(
            self,
            list_subscribed_channels_for_device(device_token, platform)
        )
    }

    async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        delegate_db_async!(self, list_private_subscribed_channels_for_device(device_id))
    }

    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<(ChannelInfo, String)>> {
        delegate_db_async!(self, channel_info_with_password(channel_id))
    }

    async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()> {
        delegate_db_async!(self, rename_channel(channel_id, alias))
    }

    async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
    ) -> StoreResult<SubscribeOutcome> {
        delegate_db_async!(
            self,
            upsert_private_channel(channel_id, alias, password_hash)
        )
    }

    async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        delegate_db_async!(self, private_subscribe_channel(channel_id, device_id))
    }

    async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        delegate_db_async!(self, private_unsubscribe_channel(channel_id, device_id))
    }

    async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        delegate_db_async!(
            self,
            list_private_subscribers(channel_id, subscribed_at_or_before)
        )
    }

    async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        delegate_db_async!(self, lookup_private_device(platform, token))
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

    async fn enqueue_provider_pull_item(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            enqueue_provider_pull_item(
                delivery_id,
                message,
                platform,
                provider_token,
                next_retry_at
            )
        )
    }

    async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        delegate_db_async!(self, pull_provider_item(delivery_id, now))
    }

    async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        delegate_db_async!(self, list_provider_pull_retry_due(now, limit))
    }

    async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            bump_provider_pull_retry(delivery_id, next_retry_at, now)
        )
    }

    async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        delegate_db_async!(self, clear_provider_pull_retry(delivery_id))
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

    async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            reserve_delivery_dedupe(dedupe_key, delivery_id, created_at)
        )
    }

    async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        delegate_db_async!(
            self,
            reserve_semantic_id(dedupe_key, semantic_id, created_at)
        )
    }

    async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        delegate_db_async!(
            self,
            reserve_op_dedupe_pending(dedupe_key, delivery_id, created_at)
        )
    }

    async fn mark_op_dedupe_sent(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<bool> {
        delegate_db_async!(self, mark_op_dedupe_sent(dedupe_key, delivery_id))
    }

    async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, clear_op_dedupe_pending(dedupe_key, delivery_id))
    }

    async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, confirm_delivery_dedupe(dedupe_key, delivery_id))
    }

    async fn automation_reset(&self) -> StoreResult<()> {
        delegate_db_async!(self, automation_reset())
    }

    async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        delegate_db_async!(self, automation_counts())
    }
}

#[async_trait]
pub trait DatabaseAccess: Send + Sync {
    async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>>;
    async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>>;
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
    async fn cleanup_pending_op_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn cleanup_semantic_id_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn cleanup_delivery_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()>;
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>>;
    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()>;
    async fn apply_route_snapshot(
        &self,
        device_id: &[u8],
        device_key: &str,
        platform: &str,
        channel_type: &str,
        provider_token: Option<&str>,
    ) -> StoreResult<()>;
    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()>;
    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()>;
    async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()>;
    async fn append_delivery_audit_batch(&self, entries: &[DeliveryAuditWrite]) -> StoreResult<()> {
        for entry in entries {
            self.append_delivery_audit(entry).await?;
        }
        Ok(())
    }
    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()>;
    async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>>;
    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>>;
    async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>>;
    async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>>;
    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<(ChannelInfo, String)>>;
    async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()>;
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
    async fn load_private_message(&self, delivery_id: &str) -> StoreResult<Option<PrivateMessage>>;
    async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>>;
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
    async fn automation_reset(&self) -> StoreResult<()>;
    async fn automation_counts(&self) -> StoreResult<AutomationCounts>;
}
