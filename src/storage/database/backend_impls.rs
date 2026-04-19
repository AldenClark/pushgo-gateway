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

            async fn list_private_outbox(
                &self,
                device_id: DeviceId,
                limit: usize,
            ) -> StoreResult<Vec<PrivateOutboxEntry>> {
                <$backend>::list_private_outbox(self, device_id, limit).await
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

            async fn defer_private_fallback(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                at_ts: i64,
            ) -> StoreResult<()> {
                <$backend>::defer_private_fallback(self, device_id, delivery_id, at_ts).await
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
            ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
                <$backend>::claim_private_outbox_due(self, before_ts, limit, claim_until_ts).await
            }

            async fn claim_private_outbox_due_for_device(
                &self,
                device_id: DeviceId,
                before_ts: i64,
                limit: usize,
                claim_until_ts: i64,
            ) -> StoreResult<Vec<PrivateOutboxEntry>> {
                <$backend>::claim_private_outbox_due_for_device(
                    self,
                    device_id,
                    before_ts,
                    limit,
                    claim_until_ts,
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

            async fn persist_device_route_change(
                &self,
                route: &DeviceRouteRecordRow,
                audit: &DeviceRouteAuditWrite,
            ) -> StoreResult<()> {
                <$backend>::persist_device_route_change(self, route, audit).await
            }

            async fn replace_device_identity(
                &self,
                route: &DeviceRouteRecordRow,
                old_device_key: Option<&str>,
                audit: &DeviceRouteAuditWrite,
            ) -> StoreResult<()> {
                <$backend>::replace_device_identity(self, route, old_device_key, audit).await
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

            async fn append_device_route_audit(
                &self,
                entry: &DeviceRouteAuditWrite,
            ) -> StoreResult<()> {
                <$backend>::append_device_route_audit(self, entry).await
            }

            async fn append_subscription_audit(
                &self,
                entry: &SubscriptionAuditWrite,
            ) -> StoreResult<()> {
                <$backend>::append_subscription_audit(self, entry).await
            }
        }
    };
}

macro_rules! impl_backend_delivery_audit_access {
    ($backend:ty) => {
        #[async_trait]
        impl crate::storage::database::DeliveryAuditDatabaseAccess for $backend {
            async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
                <$backend>::append_delivery_audit(self, entry).await
            }

            async fn append_delivery_audit_batch(
                &self,
                entries: &[DeliveryAuditWrite],
            ) -> StoreResult<()> {
                <$backend>::append_delivery_audit_batch(self, entries).await
            }

            async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
                <$backend>::apply_stats_batch(self, batch).await
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

            async fn ack_provider_item(
                &self,
                device_id: DeviceId,
                delivery_id: &str,
                now: i64,
            ) -> StoreResult<Option<ProviderPullItem>> {
                <$backend>::ack_provider_item(self, device_id, delivery_id, now).await
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
                created_at: i64,
            ) -> StoreResult<OpDedupeReservation> {
                <$backend>::reserve_op_dedupe_pending(self, dedupe_key, delivery_id, created_at)
                    .await
            }

            async fn mark_op_dedupe_sent(
                &self,
                dedupe_key: &str,
                delivery_id: &str,
            ) -> StoreResult<bool> {
                <$backend>::mark_op_dedupe_sent(self, dedupe_key, delivery_id).await
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
        impl_backend_delivery_audit_access!($backend);
        impl_backend_provider_pull_access!($backend);
        impl_backend_dedupe_access!($backend);
        impl_backend_system_state_access!($backend);
    };
}
