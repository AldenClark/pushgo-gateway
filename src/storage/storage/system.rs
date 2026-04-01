use super::*;
use crate::storage::database::{
    DeliveryAuditDatabaseAccess, DeviceRouteDatabaseAccess, PrivateMessageDatabaseAccess,
    ProviderSubscriptionDatabaseAccess, SystemStateDatabaseAccess,
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

    pub async fn retire_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_info.device_id();
        let count = self.db.retire_device(device_token, platform).await?;
        self.cache.remove_device(&device_id);
        self.cache.invalidate_all_channel_devices();
        Ok(count)
    }

    pub async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let old_device_info = DeviceInfo::from_token(platform, old_device_token)?;
        let old_device_id = old_device_info.device_id();
        let count = self
            .db
            .migrate_device_subscriptions(old_device_token, new_device_token, platform)
            .await?;
        self.cache.remove_device(&old_device_id);
        self.cache.invalidate_all_channel_devices();
        Ok(count)
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
        let snapshot = route.route_snapshot()?;
        self.db.upsert_device_route(route).await?;
        self.db.apply_route_snapshot(&snapshot).await?;
        Ok(())
    }

    pub async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
        let normalized = entry.normalized();
        self.db.append_delivery_audit(&normalized).await
    }

    pub async fn append_delivery_audit_batch(
        &self,
        entries: &[DeliveryAuditWrite],
    ) -> StoreResult<()> {
        self.db.append_delivery_audit_batch(entries).await
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
        dedupe_before: i64,
    ) -> StoreResult<MaintenanceCleanupStats> {
        let _ = self.db.cleanup_private_sessions(now).await?;
        let private_outbox_pruned = self.cleanup_private_expired_data(now, 2048).await?;
        let _ = self
            .cleanup_pending_op_dedupe(now - OP_DEDUPE_PENDING_STALE_SECS, 2048)
            .await?;
        let _ = self.cleanup_semantic_id_dedupe(dedupe_before, 2048).await?;
        let _ = self.cleanup_delivery_dedupe(dedupe_before, 2048).await?;
        Ok(MaintenanceCleanupStats {
            private_outbox_pruned,
        })
    }
}
