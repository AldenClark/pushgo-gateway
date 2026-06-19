use async_trait::async_trait;

use crate::storage::{DeviceRouteRecordRow, Storage, StoreResult};

#[async_trait]
pub(crate) trait DeviceRouteStore {
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>>;
    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()>;
    async fn persist_device_route_change(&self, route: &DeviceRouteRecordRow) -> StoreResult<()>;
    async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
    ) -> StoreResult<()>;
    async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()>;
}

#[async_trait]
impl DeviceRouteStore for Storage {
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        self.load_device_routes().await
    }

    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        self.upsert_device_route(route).await
    }

    async fn persist_device_route_change(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        self.persist_device_route_change(route).await
    }

    async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
    ) -> StoreResult<()> {
        self.replace_device_identity(route, old_device_key).await
    }

    async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        self.revoke_device_identity(device_key).await
    }
}
