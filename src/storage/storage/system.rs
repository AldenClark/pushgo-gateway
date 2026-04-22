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
        Ok(())
    }

    pub async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        self.db.persist_device_route_change(route, audit).await?;
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
