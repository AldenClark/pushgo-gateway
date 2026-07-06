use super::*;
use crate::storage::database::{
    DeviceRouteDatabaseAccess, PrivateMessageDatabaseAccess, SystemStateDatabaseAccess,
};
use std::time::Instant;

impl Storage {
    pub async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        self.db.automation_counts().await
    }

    pub async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        self.db.load_mcp_state_json().await
    }

    pub async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        self.db.save_mcp_state_json(state_json).await
    }

    pub async fn upsert_live_activity_token(
        &self,
        record: &LiveActivityTokenRecord,
    ) -> StoreResult<()> {
        self.db.upsert_live_activity_token(record).await
    }

    pub async fn delete_live_activity_token(
        &self,
        activity_key: &str,
        token: Option<&str>,
    ) -> StoreResult<usize> {
        self.db
            .delete_live_activity_token(activity_key, token)
            .await
    }

    pub async fn list_live_activity_tokens(
        &self,
        activity_key: &str,
    ) -> StoreResult<Vec<LiveActivityTokenRecord>> {
        self.db.list_live_activity_tokens(activity_key).await
    }

    pub async fn automation_reset(&self) -> StoreResult<()> {
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        self.db.automation_reset().await
    }

    pub async fn upsert_sender_submit_status(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<()> {
        self.db.upsert_sender_submit_status(record).await
    }

    pub async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()> {
        self.db
            .update_sender_submit_status(op_id, status, dispatch_status, updated_at)
            .await
    }

    pub async fn load_sender_submit_status(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<SenderSubmitStatusRecord>> {
        self.db.load_sender_submit_status(op_id).await
    }

    pub async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        self.db.delete_private_device_state(device_id).await?;
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        self.db.bind_private_token(device_id, platform, token).await
    }

    pub async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        self.db.load_device_routes().await
    }

    pub async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        self.db.upsert_device_route(route).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn touch_device_activity(&self, device_id: DeviceId, at_ts: i64) -> StoreResult<()> {
        self.db.touch_device_activity(device_id, at_ts).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn record_device_activity_best_effort(
        &self,
        device_id: DeviceId,
        at_ts: i64,
        reason: &'static str,
    ) {
        if let Err(err) = self.touch_device_activity(device_id, at_ts).await {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "storage.device_activity_touch_failed",
                device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                reason = %(reason),
                error = %(err.to_string())
            );
        }
    }

    pub async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
    ) -> StoreResult<()> {
        self.db.persist_device_route_change(route).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
    ) -> StoreResult<()> {
        self.db
            .replace_device_identity(route, old_device_key)
            .await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        self.db.revoke_device_identity(device_key).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn retire_provider_token(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        self.db
            .retire_provider_token(platform, provider_token)
            .await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn run_maintenance_cleanup(
        &self,
        now: i64,
        config: MaintenanceCleanupConfig,
    ) -> StoreResult<MaintenanceCleanupStats> {
        let config = config.normalized();
        let cleanup_started = Instant::now();
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.maintenance_cleanup_started",
            now = (now),
            dry_run = (config.dry_run)
        );
        if config.dry_run {
            emit_maintenance_cleanup_dry_run(now, config);
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "storage.maintenance_cleanup_finished",
                dry_run = true,
                private_sessions_pruned = 0_u64,
                private_outbox_pruned = 0_u64,
                provider_pull_pruned = 0_u64,
                sender_status_pruned = 0_u64,
                orphan_devices_pruned = 0_u64,
                stale_subscriptions_pruned = 0_u64,
                frozen_subscriptions_pruned = 0_u64,
                soft_deleted_devices_pruned = 0_u64,
                orphan_channels_pruned = 0_u64,
                elapsed_ms = (cleanup_started.elapsed().as_millis() as u64)
            );
            return Ok(MaintenanceCleanupStats::default());
        }
        let mut phase_started = Instant::now();
        let private_sessions_pruned = self.db.cleanup_private_sessions(now).await?;
        let private_sessions_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let private_outbox_pruned = self
            .cleanup_private_expired_data(now, config.delete_batch)
            .await?;
        let private_expired_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let stale_private_outbox_pruned = self
            .db
            .cleanup_stale_private_outbox(
                config.private_stale_outbox_before(now),
                config.delete_batch,
            )
            .await?;
        let stale_outbox_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let provider_pull_pruned = self
            .db
            .cleanup_expired_provider_pull_queue(now, config.provider_pull_expired_batch)
            .await?;
        let provider_pull_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let _pending_dedupe_pruned = self
            .cleanup_pending_op_dedupe(now - OP_DEDUPE_PENDING_STALE_MILLIS, config.delete_batch)
            .await?;
        let pending_dedupe_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let dedupe_before = config.dedupe_before(now);
        let _semantic_dedupe_pruned = self
            .cleanup_semantic_id_dedupe(dedupe_before, config.delete_batch)
            .await?;
        let _delivery_dedupe_pruned = self
            .cleanup_delivery_dedupe(dedupe_before, config.delete_batch)
            .await?;
        let dedupe_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let sender_status_pruned = self
            .db
            .cleanup_sender_submit_status(now, config.delete_batch)
            .await?;
        let sender_status_elapsed_ms = phase_started.elapsed().as_millis() as u64;

        phase_started = Instant::now();
        let orphan_devices_pruned = self
            .db
            .cleanup_orphan_devices(config.orphan_device_before(now), config.delete_batch)
            .await?;
        let orphan_devices_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let stale_subscriptions_pruned = if config.stale_subscription_cleanup_enabled {
            self.db
                .cleanup_stale_subscriptions(
                    config.stale_subscription_before(now),
                    now,
                    config.delete_batch,
                )
                .await?
        } else {
            0
        };
        let stale_subscriptions_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let frozen_subscriptions_pruned = if config.stale_subscription_cleanup_enabled {
            self.db
                .cleanup_inactive_subscriptions(
                    config.frozen_subscription_before(now),
                    now,
                    config.delete_batch,
                )
                .await?
        } else {
            0
        };
        let frozen_subscriptions_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let soft_deleted_devices_pruned = if config.soft_deleted_device_cleanup_enabled {
            self.db
                .cleanup_soft_deleted_devices(
                    config.soft_deleted_device_before(now),
                    config.delete_batch,
                )
                .await?
        } else {
            0
        };
        let soft_deleted_devices_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        phase_started = Instant::now();
        let orphan_channels_pruned = if config.orphan_channel_cleanup_enabled {
            self.db
                .cleanup_orphan_channels(config.orphan_channel_before(now), config.delete_batch)
                .await?
        } else {
            0
        };
        let orphan_channels_elapsed_ms = phase_started.elapsed().as_millis() as u64;
        let private_outbox_pruned =
            private_outbox_pruned.saturating_add(stale_private_outbox_pruned);
        if stale_subscriptions_pruned > 0
            || frozen_subscriptions_pruned > 0
            || soft_deleted_devices_pruned > 0
            || orphan_devices_pruned > 0
            || orphan_channels_pruned > 0
        {
            self.cache.clear_devices();
            self.cache.invalidate_all_channel_devices();
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.maintenance_cleanup_finished",
            private_sessions_pruned = (private_sessions_pruned as u64),
            private_outbox_pruned = (private_outbox_pruned as u64),
            provider_pull_pruned = (provider_pull_pruned as u64),
            sender_status_pruned = (sender_status_pruned as u64),
            orphan_devices_pruned = (orphan_devices_pruned as u64),
            stale_subscriptions_pruned = (stale_subscriptions_pruned as u64),
            frozen_subscriptions_pruned = (frozen_subscriptions_pruned as u64),
            soft_deleted_devices_pruned = (soft_deleted_devices_pruned as u64),
            orphan_channels_pruned = (orphan_channels_pruned as u64),
            elapsed_ms = (cleanup_started.elapsed().as_millis() as u64),
            private_sessions_elapsed_ms = (private_sessions_elapsed_ms),
            private_expired_elapsed_ms = (private_expired_elapsed_ms),
            stale_outbox_elapsed_ms = (stale_outbox_elapsed_ms),
            provider_pull_elapsed_ms = (provider_pull_elapsed_ms),
            pending_dedupe_elapsed_ms = (pending_dedupe_elapsed_ms),
            dedupe_elapsed_ms = (dedupe_elapsed_ms),
            sender_status_elapsed_ms = (sender_status_elapsed_ms),
            orphan_devices_elapsed_ms = (orphan_devices_elapsed_ms),
            stale_subscriptions_elapsed_ms = (stale_subscriptions_elapsed_ms),
            frozen_subscriptions_elapsed_ms = (frozen_subscriptions_elapsed_ms),
            soft_deleted_devices_elapsed_ms = (soft_deleted_devices_elapsed_ms),
            orphan_channels_elapsed_ms = (orphan_channels_elapsed_ms)
        );
        Ok(MaintenanceCleanupStats {
            private_sessions_pruned,
            private_outbox_pruned,
            provider_pull_pruned,
            sender_status_pruned,
            orphan_devices_pruned,
            stale_subscriptions_pruned,
            frozen_subscriptions_pruned,
            soft_deleted_devices_pruned,
            orphan_channels_pruned,
        })
    }
}

fn emit_maintenance_cleanup_dry_run(now: i64, config: MaintenanceCleanupConfig) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "storage.maintenance_cleanup_dry_run",
        now = (now),
        provider_pull_expired_before = (now),
        private_session_expired_before = (now),
        private_message_expired_before = (now),
        private_stale_outbox_before = (config.private_stale_outbox_before(now)),
        pending_op_dedupe_before = (now - OP_DEDUPE_PENDING_STALE_MILLIS),
        dedupe_before = (config.dedupe_before(now)),
        sender_status_expired_before = (now),
        orphan_device_before = (config.orphan_device_before(now)),
        stale_subscription_before = (config.stale_subscription_before(now)),
        frozen_subscription_before = (config.frozen_subscription_before(now)),
        soft_deleted_device_before = (config.soft_deleted_device_before(now)),
        orphan_channel_before = (config.orphan_channel_before(now)),
        provider_pull_expired_batch = (config.provider_pull_expired_batch as u64),
        delete_batch = (config.delete_batch as u64),
        stale_subscription_cleanup_enabled = (config.stale_subscription_cleanup_enabled),
        soft_deleted_device_cleanup_enabled = (config.soft_deleted_device_cleanup_enabled),
        orphan_channel_cleanup_enabled = (config.orphan_channel_cleanup_enabled)
    );
}
