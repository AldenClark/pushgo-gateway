use super::*;
use crate::storage::database::{
    DeviceRouteDatabaseAccess, PrivateMessageDatabaseAccess, StatsDatabaseAccess,
    SystemStateDatabaseAccess,
};

impl Storage {
    pub async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        self.db.apply_stats_batch(batch).await
    }

    pub async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        self.db.automation_counts().await
    }

    pub async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        self.db.load_mcp_state_json().await
    }

    pub async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        self.db.save_mcp_state_json(state_json).await
    }

    pub async fn automation_reset(&self) -> StoreResult<()> {
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        self.db.automation_reset().await
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

    pub async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        self.db.persist_device_route_change(route, audit).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        self.db
            .replace_device_identity(route, old_device_key, audit)
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

    pub async fn append_subscription_audit(
        &self,
        entry: &SubscriptionAuditWrite,
    ) -> StoreResult<()> {
        self.db.append_subscription_audit(entry).await
    }

    pub async fn append_device_route_audit(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        self.db.append_device_route_audit(entry).await
    }

    pub async fn run_maintenance_cleanup(
        &self,
        now: i64,
        config: MaintenanceCleanupConfig,
    ) -> StoreResult<MaintenanceCleanupStats> {
        let config = config.normalized();
        let private_sessions_pruned = self.db.cleanup_private_sessions(now).await?;
        let private_outbox_pruned = self.cleanup_private_expired_data(now, 2048).await?;
        let stale_private_outbox_pruned = self
            .db
            .cleanup_stale_private_outbox(
                config.private_stale_outbox_before(now),
                config.delete_batch,
            )
            .await?;
        let provider_pull_pruned = self
            .db
            .cleanup_expired_provider_pull_queue(now, config.provider_pull_expired_batch)
            .await?;
        let _pending_dedupe_pruned = self
            .cleanup_pending_op_dedupe(now - OP_DEDUPE_PENDING_STALE_SECS, 2048)
            .await?;
        let dedupe_before = config.dedupe_before(now);
        let _semantic_dedupe_pruned = self.cleanup_semantic_id_dedupe(dedupe_before, 2048).await?;
        let _delivery_dedupe_pruned = self.cleanup_delivery_dedupe(dedupe_before, 2048).await?;

        let orphan_devices_pruned = self
            .db
            .cleanup_orphan_devices(config.orphan_device_before(now), config.delete_batch)
            .await?;
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
        let orphan_channels_pruned = if config.orphan_channel_cleanup_enabled {
            self.db
                .cleanup_orphan_channels(config.orphan_channel_before(now), config.delete_batch)
                .await?
        } else {
            0
        };
        let audit_rows_pruned = if config.audit_retention_cleanup_enabled {
            self.db
                .cleanup_audit_rows(config.audit_before(now), config.delete_batch)
                .await?
        } else {
            0
        };
        let (hourly_stats_pruned, daily_stats_pruned) = if config.stats_retention_cleanup_enabled {
            let hourly = self
                .db
                .cleanup_hourly_stats(
                    config.hourly_stats_before(now).as_str(),
                    config.delete_batch,
                )
                .await?;
            let daily = self
                .db
                .cleanup_daily_stats(config.daily_stats_before(now).as_str(), config.delete_batch)
                .await?;
            (hourly, daily)
        } else {
            (0, 0)
        };
        let private_outbox_pruned =
            private_outbox_pruned.saturating_add(stale_private_outbox_pruned);
        if stale_subscriptions_pruned > 0
            || soft_deleted_devices_pruned > 0
            || orphan_devices_pruned > 0
            || orphan_channels_pruned > 0
        {
            self.cache.clear_devices();
            self.cache.invalidate_all_channel_devices();
        }
        Ok(MaintenanceCleanupStats {
            private_sessions_pruned,
            private_outbox_pruned,
            provider_pull_pruned,
            orphan_devices_pruned,
            stale_subscriptions_pruned,
            soft_deleted_devices_pruned,
            orphan_channels_pruned,
            audit_rows_pruned,
            hourly_stats_pruned,
            daily_stats_pruned,
        })
    }
}
