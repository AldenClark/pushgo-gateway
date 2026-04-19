use super::*;
use async_trait::async_trait;

#[async_trait]
impl DeviceRouteDatabaseAccess for DatabaseDriver {
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        delegate_db_async!(self, load_device_routes())
    }

    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        delegate_db_async!(self, upsert_device_route(route))
    }

    async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        delegate_db_async!(self, persist_device_route_change(route, audit))
    }

    async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        delegate_db_async!(self, replace_device_identity(route, old_device_key, audit))
    }

    async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        delegate_db_async!(self, revoke_device_identity(device_key))
    }

    async fn retire_provider_token(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, retire_provider_token(platform, provider_token))
    }

    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_device_route_audit(entry))
    }

    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_subscription_audit(entry))
    }
}
