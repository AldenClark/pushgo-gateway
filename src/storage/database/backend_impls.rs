#![allow(unused_imports)]

use crate::storage::{
    database::{mysql::MySqlDb, pg::PostgresDb, sqlite::SqliteDb},
    types::*,
};
use async_trait::async_trait;

macro_rules! impl_backend_channel_query_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::ChannelQueryDatabaseAccess for $backend {
            async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
                <$backend>::channel_info(self, channel_id).await
            }

            async fn list_channel_devices(
                &self,
                channel_id: [u8; 16],
            ) -> StoreResult<Vec<DeviceInfo>> {
                <$backend>::list_channel_devices(self, channel_id).await
            }

            async fn list_channel_dispatch_targets(
                &self,
                channel_id: [u8; 16],
                effective_at: i64,
            ) -> StoreResult<Vec<DispatchTarget>> {
                <$backend>::list_channel_dispatch_targets(self, channel_id, effective_at).await
            }

            async fn channel_info_with_password(
                &self,
                channel_id: [u8; 16],
            ) -> StoreResult<Option<(ChannelInfo, String)>> {
                <$backend>::channel_info_with_password(self, channel_id).await
            }

            async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()> {
                <$backend>::rename_channel(self, channel_id, alias).await
            }

            async fn update_channel_password_hash(
                &self,
                channel_id: [u8; 16],
                password_hash: &str,
            ) -> StoreResult<()> {
                <$backend>::update_channel_password_hash(self, channel_id, password_hash).await
            }
        }
    };
}

macro_rules! impl_backend_provider_subscription_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::ProviderSubscriptionDatabaseAccess for $backend {
            async fn subscribe_channel_for_device_key(
                &self,
                channel_id: Option<[u8; 16]>,
                alias: Option<&str>,
                password_hash: &str,
                device_key: &str,
                provider_token: &str,
                platform: Platform,
            ) -> StoreResult<SubscribeOutcome> {
                <$backend>::subscribe_channel_for_device_key(
                    self,
                    channel_id,
                    alias,
                    password_hash,
                    device_key,
                    provider_token,
                    platform,
                )
                .await
            }

            async fn unsubscribe_channel_for_device_key(
                &self,
                channel_id: [u8; 16],
                device_key: &str,
            ) -> StoreResult<bool> {
                <$backend>::unsubscribe_channel_for_device_key(self, channel_id, device_key).await
            }

            async fn unsubscribe_channel_if_provider_route_current(
                &self,
                channel_id: [u8; 16],
                device_key: &str,
                platform: Platform,
                provider_token: &str,
                route_updated_at: i64,
            ) -> StoreResult<bool> {
                <$backend>::unsubscribe_channel_if_provider_route_current(
                    self,
                    channel_id,
                    device_key,
                    platform,
                    provider_token,
                    route_updated_at,
                )
                .await
            }

            async fn list_subscribed_channels_for_device_key(
                &self,
                device_key: &str,
            ) -> StoreResult<Vec<[u8; 16]>> {
                <$backend>::list_subscribed_channels_for_device_key(self, device_key).await
            }
        }
    };
}

macro_rules! impl_backend_private_channel_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::PrivateChannelDatabaseAccess for $backend {
            async fn list_private_subscribed_channels_for_device(
                &self,
                device_id: DeviceId,
            ) -> StoreResult<Vec<[u8; 16]>> {
                <$backend>::list_private_subscribed_channels_for_device(self, device_id).await
            }

            async fn upsert_private_channel(
                &self,
                channel_id: Option<[u8; 16]>,
                alias: Option<&str>,
                password_hash: &str,
            ) -> StoreResult<SubscribeOutcome> {
                <$backend>::upsert_private_channel(self, channel_id, alias, password_hash).await
            }

            async fn private_subscribe_channel(
                &self,
                channel_id: [u8; 16],
                device_id: DeviceId,
            ) -> StoreResult<()> {
                <$backend>::private_subscribe_channel(self, channel_id, device_id).await
            }

            async fn private_unsubscribe_channel(
                &self,
                channel_id: [u8; 16],
                device_id: DeviceId,
            ) -> StoreResult<()> {
                <$backend>::private_unsubscribe_channel(self, channel_id, device_id).await
            }

            async fn list_private_subscribers(
                &self,
                channel_id: [u8; 16],
                subscribed_at_or_before: i64,
            ) -> StoreResult<Vec<DeviceId>> {
                <$backend>::list_private_subscribers(self, channel_id, subscribed_at_or_before)
                    .await
            }

            async fn lookup_private_device(
                &self,
                platform: Platform,
                token: &str,
            ) -> StoreResult<Option<DeviceId>> {
                <$backend>::lookup_private_device(self, platform, token).await
            }
        }
    };
}

macro_rules! impl_backend_private_message_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::PrivateMessageDatabaseAccess for $backend {
            async fn load_private_outbox_entry(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
            ) -> StoreResult<Option<PrivateOutboxEntry>> {
                <$backend>::load_private_outbox_entry(self, device_id, delivery_id).await
            }

            async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
                <$backend>::delete_private_device_state(self, device_id).await
            }

            async fn insert_private_message(
                &self,
                delivery_id: &str,
                message: &PrivateMessage,
            ) -> StoreResult<()> {
                <$backend>::insert_private_message(self, delivery_id, message).await
            }

            async fn enqueue_private_outbox(
                &self,
                device_id: DeviceId,
                entry: &PrivateOutboxEntry,
            ) -> StoreResult<()> {
                <$backend>::enqueue_private_outbox(self, device_id, entry).await
            }

            async fn enqueue_private_outbox_batch(
                &self,
                entries: &[PrivateOutboxBatchEntry],
                max_pending_per_device: usize,
                global_max_pending: usize,
                protected_delivery_id: Option<&str>,
            ) -> StoreResult<usize> {
                <$backend>::enqueue_private_outbox_batch(
                    self,
                    entries,
                    max_pending_per_device,
                    global_max_pending,
                    protected_delivery_id,
                )
                .await
            }

            async fn list_private_outbox(
                &self,
                device_id: DeviceId,
                limit: usize,
            ) -> StoreResult<Vec<PrivateOutboxEntry>> {
                <$backend>::list_private_outbox(self, device_id, limit).await
            }

            async fn evict_oldest_pending_private_outbox_for_device(
                &self,
                device_id: DeviceId,
            ) -> StoreResult<Option<String>> {
                <$backend>::evict_oldest_pending_private_outbox_for_device(self, device_id).await
            }

            async fn evict_oldest_pending_private_outbox_global(
                &self,
            ) -> StoreResult<Option<(DeviceId, String)>> {
                <$backend>::evict_oldest_pending_private_outbox_global(self).await
            }

            async fn count_private_outbox_for_device(
                &self,
                device_id: DeviceId,
            ) -> StoreResult<usize> {
                <$backend>::count_private_outbox_for_device(self, device_id).await
            }

            async fn cleanup_private_expired_data(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_private_expired_data(self, before_ts, limit).await
            }

            async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
                <$backend>::cleanup_private_sessions(self, before_ts).await
            }

            async fn bind_private_token(
                &self,
                device_id: DeviceId,
                platform: Platform,
                token: &str,
            ) -> StoreResult<()> {
                <$backend>::bind_private_token(self, device_id, platform, token).await
            }

            async fn load_private_message(
                &self,
                delivery_id: &str,
            ) -> StoreResult<Option<PrivateMessage>> {
                <$backend>::load_private_message(self, delivery_id).await
            }

            async fn load_private_payload_context(
                &self,
                delivery_id: &str,
            ) -> StoreResult<Option<PrivatePayloadContext>> {
                <$backend>::load_private_payload_context(self, delivery_id).await
            }

            async fn mark_private_fallback_sent(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                at_ts: i64,
            ) -> StoreResult<()> {
                <$backend>::mark_private_fallback_sent(self, device_id, delivery_id, at_ts).await
            }

            async fn mark_private_fallback_sent_if_claimed(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                worker_id: &str,
                claim_generation: u64,
                at_ts: i64,
            ) -> StoreResult<bool> {
                <$backend>::mark_private_fallback_sent_if_claimed(
                    self,
                    device_id,
                    delivery_id,
                    worker_id,
                    claim_generation,
                    at_ts,
                )
                .await
            }

            async fn defer_private_fallback(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                at_ts: i64,
            ) -> StoreResult<()> {
                <$backend>::defer_private_fallback(self, device_id, delivery_id, at_ts).await
            }

            async fn defer_private_fallback_if_claimed(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                worker_id: &str,
                claim_generation: u64,
                at_ts: i64,
            ) -> StoreResult<bool> {
                <$backend>::defer_private_fallback_if_claimed(
                    self,
                    device_id,
                    delivery_id,
                    worker_id,
                    claim_generation,
                    at_ts,
                )
                .await
            }

            async fn drop_private_delivery_if_claimed(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                worker_id: &str,
                claim_generation: u64,
            ) -> StoreResult<bool> {
                <$backend>::drop_private_delivery_if_claimed(
                    self,
                    device_id,
                    delivery_id,
                    worker_id,
                    claim_generation,
                )
                .await
            }

            async fn ack_private_delivery(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
            ) -> StoreResult<()> {
                <$backend>::ack_private_delivery(self, device_id, delivery_id).await
            }

            async fn clear_private_outbox_for_device(
                &self,
                device_id: DeviceId,
            ) -> StoreResult<Vec<String>> {
                <$backend>::clear_private_outbox_for_device(self, device_id).await
            }

            async fn list_private_outbox_due(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
                <$backend>::list_private_outbox_due(self, before_ts, limit).await
            }

            async fn claim_private_outbox_due(
                &self,
                before_ts: i64,
                limit: usize,
                claim_until_ts: i64,
                worker_id: &str,
            ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
                <$backend>::claim_private_outbox_due(
                    self,
                    before_ts,
                    limit,
                    claim_until_ts,
                    worker_id,
                )
                .await
            }

            async fn claim_private_outbox_due_for_device(
                &self,
                device_id: DeviceId,
                before_ts: i64,
                limit: usize,
                claim_until_ts: i64,
                worker_id: &str,
            ) -> StoreResult<Vec<PrivateOutboxEntry>> {
                <$backend>::claim_private_outbox_due_for_device(
                    self,
                    device_id,
                    before_ts,
                    limit,
                    claim_until_ts,
                    worker_id,
                )
                .await
            }

            async fn count_private_outbox_total(&self) -> StoreResult<usize> {
                <$backend>::count_private_outbox_total(self).await
            }
        }
    };
}

macro_rules! impl_backend_device_route_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::DeviceRouteDatabaseAccess for $backend {
            async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
                <$backend>::load_device_routes(self).await
            }

            async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
                <$backend>::upsert_device_route(self, route).await
            }

            async fn touch_device_activity(
                &self,
                device_id: DeviceId,
                at_ts: i64,
            ) -> StoreResult<()> {
                <$backend>::touch_device_activity(self, device_id, at_ts).await
            }

            async fn persist_device_route_change(
                &self,
                route: &DeviceRouteRecordRow,
            ) -> StoreResult<()> {
                <$backend>::persist_device_route_change(self, route).await
            }

            async fn transition_device_route(
                &self,
                route: &DeviceRouteRecordRow,
                previous_channel_type: RouteChannelType,
                ack_timeout_secs: u64,
                max_pending_per_device: usize,
            ) -> StoreResult<usize> {
                <$backend>::transition_device_route(
                    self,
                    route,
                    previous_channel_type,
                    ack_timeout_secs,
                    max_pending_per_device,
                )
                .await
            }

            async fn replace_device_identity(
                &self,
                route: &DeviceRouteRecordRow,
                old_device_key: Option<&str>,
            ) -> StoreResult<()> {
                <$backend>::replace_device_identity(self, route, old_device_key).await
            }

            async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
                <$backend>::revoke_device_identity(self, device_key).await
            }

            async fn retire_provider_token(
                &self,
                platform: Platform,
                provider_token: &str,
            ) -> StoreResult<()> {
                <$backend>::retire_provider_token(self, platform, provider_token).await
            }
        }
    };
}

macro_rules! impl_backend_provider_pull_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::ProviderPullDatabaseAccess for $backend {
            async fn enqueue_provider_pull_item(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                message: &PrivateMessage,
                platform: Platform,
                provider_token: &str,
            ) -> StoreResult<()> {
                <$backend>::enqueue_provider_pull_item(
                    self,
                    device_id,
                    delivery_id,
                    message,
                    platform,
                    provider_token,
                )
                .await
            }

            async fn pull_provider_item(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                now: i64,
            ) -> StoreResult<Option<ProviderPullItem>> {
                <$backend>::pull_provider_item(self, device_id, delivery_id, now).await
            }

            async fn pull_provider_items(
                &self,
                device_id: DeviceId,
                now: i64,
                limit: usize,
            ) -> StoreResult<Vec<ProviderPullItem>> {
                <$backend>::pull_provider_items(self, device_id, now, limit).await
            }

            async fn peek_provider_item(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                now: i64,
            ) -> StoreResult<Option<ProviderPullItem>> {
                <$backend>::peek_provider_item(self, device_id, delivery_id, now).await
            }

            async fn peek_provider_items(
                &self,
                device_id: DeviceId,
                now: i64,
                limit: usize,
            ) -> StoreResult<Vec<ProviderPullItem>> {
                <$backend>::peek_provider_items(self, device_id, now, limit).await
            }

            async fn peek_provider_candidate(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                now: i64,
            ) -> StoreResult<Option<ProviderPullCandidate>> {
                <$backend>::peek_provider_candidate(self, device_id, delivery_id, now).await
            }

            async fn peek_provider_candidates(
                &self,
                device_id: DeviceId,
                now: i64,
                limit: usize,
            ) -> StoreResult<Vec<ProviderPullCandidate>> {
                <$backend>::peek_provider_candidates(self, device_id, now, limit).await
            }

            async fn ack_provider_item(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                now: i64,
            ) -> StoreResult<Option<ProviderPullItem>> {
                <$backend>::ack_provider_item(self, device_id, delivery_id, now).await
            }

            async fn ack_provider_items(
                &self,
                device_id: DeviceId,
                delivery_ids: &[String],
                now: i64,
            ) -> StoreResult<Vec<ProviderPullItem>> {
                <$backend>::ack_provider_items(self, device_id, delivery_ids, now).await
            }

            async fn discard_provider_items_by_outer_ids(
                &self,
                device_id: DeviceId,
                delivery_ids: &[String],
                now: i64,
            ) -> StoreResult<usize> {
                <$backend>::discard_provider_items_by_outer_ids(self, device_id, delivery_ids, now)
                    .await
            }
        }
    };
}

macro_rules! impl_backend_dedupe_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::DedupeDatabaseAccess for $backend {
            async fn cleanup_pending_op_dedupe(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_pending_op_dedupe(self, before_ts, limit).await
            }

            async fn cleanup_semantic_id_dedupe(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_semantic_id_dedupe(self, before_ts, limit).await
            }

            async fn cleanup_delivery_dedupe(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_delivery_dedupe(self, before_ts, limit).await
            }

            async fn reserve_delivery_dedupe(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
                created_at: i64,
            ) -> StoreResult<bool> {
                <$backend>::reserve_delivery_dedupe(self, dedupe_key, delivery_id, created_at).await
            }

            async fn reserve_semantic_id(
                &self,
                dedupe_key: &str,
                semantic_id: &str,
                created_at: i64,
            ) -> StoreResult<SemanticIdReservation> {
                <$backend>::reserve_semantic_id(self, dedupe_key, semantic_id, created_at).await
            }

            async fn reserve_op_dedupe_pending(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
                request_fingerprint: Option<&str>,
                created_at: i64,
            ) -> StoreResult<OpDedupeReservation> {
                <$backend>::reserve_op_dedupe_pending(
                    self,
                    dedupe_key,
                    delivery_id,
                    request_fingerprint,
                    created_at,
                )
                .await
            }

            async fn mark_op_dedupe_sent(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
                state: DedupeState,
            ) -> StoreResult<bool> {
                <$backend>::mark_op_dedupe_sent(self, dedupe_key, delivery_id, state).await
            }

            async fn clear_op_dedupe_pending(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
            ) -> StoreResult<()> {
                <$backend>::clear_op_dedupe_pending(self, dedupe_key, delivery_id).await
            }

            async fn confirm_delivery_dedupe(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
            ) -> StoreResult<()> {
                <$backend>::confirm_delivery_dedupe(self, dedupe_key, delivery_id).await
            }
        }
    };
}

macro_rules! impl_backend_system_state_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::SystemStateDatabaseAccess for $backend {
            async fn automation_reset(&self) -> StoreResult<()> {
                <$backend>::automation_reset(self).await
            }

            async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
                <$backend>::automation_counts(self).await
            }

            async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
                <$backend>::load_mcp_state_json(self).await
            }

            async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
                <$backend>::save_mcp_state_json(self, state_json).await
            }

            async fn upsert_live_activity_token(
                &self,
                record: &LiveActivityTokenRecord,
            ) -> StoreResult<()> {
                <$backend>::upsert_live_activity_token(self, record).await
            }

            async fn delete_live_activity_token(
                &self,
                activity_key: &str,
                token: Option<&str>,
            ) -> StoreResult<usize> {
                <$backend>::delete_live_activity_token(self, activity_key, token).await
            }

            async fn list_live_activity_tokens(
                &self,
                activity_key: &str,
            ) -> StoreResult<Vec<LiveActivityTokenRecord>> {
                <$backend>::list_live_activity_tokens(self, activity_key).await
            }

            async fn upsert_widget_push_subscriptions(
                &self,
                device_key: &str,
                platform: Platform,
                token: &str,
                widgets: &[WidgetPushSubscriptionRecord],
                schema_version: i32,
                now: i64,
            ) -> StoreResult<()> {
                <$backend>::upsert_widget_push_subscriptions(
                    self,
                    device_key,
                    platform,
                    token,
                    widgets,
                    schema_version,
                    now,
                )
                .await
            }

            async fn delete_widget_push_token(
                &self,
                platform: Platform,
                token: &str,
            ) -> StoreResult<usize> {
                <$backend>::delete_widget_push_token(self, platform, token).await
            }

            async fn list_widget_push_targets_for_channel(
                &self,
                channel_id: [u8; 16],
            ) -> StoreResult<Vec<WidgetPushSubscriptionRecord>> {
                <$backend>::list_widget_push_targets_for_channel(self, channel_id).await
            }

            async fn insert_sender_submit_status_if_absent(
                &self,
                record: &SenderSubmitStatusRecord,
            ) -> StoreResult<bool> {
                <$backend>::insert_sender_submit_status_if_absent(self, record).await
            }

            async fn update_sender_submit_status(
                &self,
                op_id: &str,
                status: SenderSubmitStatusKind,
                dispatch_status: Option<&str>,
                updated_at: i64,
            ) -> StoreResult<()> {
                <$backend>::update_sender_submit_status(
                    self,
                    op_id,
                    status,
                    dispatch_status,
                    updated_at,
                )
                .await
            }

            async fn finalize_provider_dispatch_outcome(
                &self,
                op_id: &str,
                delivery_id: &str,
                success: bool,
            ) -> StoreResult<()> {
                <$backend>::finalize_provider_dispatch_outcome(self, op_id, delivery_id, success)
                    .await
            }

            async fn recover_interrupted_provider_dispatches(
                &self,
                updated_at: i64,
            ) -> StoreResult<usize> {
                <$backend>::recover_interrupted_provider_dispatches(self, updated_at).await
            }

            async fn load_sender_submit_status(
                &self,
                op_id: &str,
            ) -> StoreResult<Option<SenderSubmitStatusRecord>> {
                <$backend>::load_sender_submit_status(self, op_id).await
            }

            async fn cleanup_sender_submit_status(
                &self,
                now: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_sender_submit_status(self, now, limit).await
            }

            async fn cleanup_expired_provider_pull_queue(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_expired_provider_pull_queue(self, before_ts, limit).await
            }

            async fn cleanup_stale_private_outbox(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_stale_private_outbox(self, before_ts, limit).await
            }

            async fn cleanup_orphan_devices(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_orphan_devices(self, before_ts, limit).await
            }

            async fn cleanup_stale_subscriptions(
                &self,
                before_ts: i64,
                now: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_stale_subscriptions(self, before_ts, now, limit).await
            }

            async fn cleanup_inactive_subscriptions(
                &self,
                before_ts: i64,
                now: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_inactive_subscriptions(self, before_ts, now, limit).await
            }

            async fn cleanup_soft_deleted_devices(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_soft_deleted_devices(self, before_ts, limit).await
            }

            async fn cleanup_orphan_channels(
                &self,
                before_ts: i64,
                limit: usize,
            ) -> StoreResult<usize> {
                <$backend>::cleanup_orphan_channels(self, before_ts, limit).await
            }
        }
    };
}

macro_rules! impl_backend_database_access {
    ($backend:ty) => {
        impl_backend_channel_query_access!($backend);
        impl_backend_provider_subscription_access!($backend);
        impl_backend_private_channel_access!($backend);
        impl_backend_private_message_access!($backend);
        impl_backend_device_route_access!($backend);
        impl_backend_provider_pull_access!($backend);
        impl_backend_dedupe_access!($backend);
        impl_backend_system_state_access!($backend);
    };
}
