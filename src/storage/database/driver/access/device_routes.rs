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

    async fn apply_route_snapshot(&self, snapshot: &DeviceRouteSnapshot) -> StoreResult<()> {
        delegate_db_async!(self, apply_route_snapshot(snapshot))
    }

    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_device_route_audit(entry))
    }

    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_subscription_audit(entry))
    }
}
