use super::*;
use async_trait::async_trait;

#[async_trait]
impl DeviceRouteDatabaseAccess for DatabaseDriver {
    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        delegate_db_async!(self, load_device_routes())
    }

    async fn provider_route_is_current(
        &self,
        device_key: &str,
        platform: Platform,
        channel_type: RouteChannelType,
        provider_token: &str,
        route_updated_at: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            provider_route_is_current(
                device_key,
                platform,
                channel_type,
                provider_token,
                route_updated_at
            )
        )
    }

    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        delegate_db_async!(self, upsert_device_route(route))
    }

    async fn touch_device_activity(&self, device_id: DeviceId, at_ts: i64) -> StoreResult<()> {
        delegate_db_async!(self, touch_device_activity(device_id, at_ts))
    }

    async fn persist_device_route_change(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        delegate_db_async!(self, persist_device_route_change(route))
    }

    async fn transition_device_route(
        &self,
        route: &DeviceRouteRecordRow,
        previous_channel_type: RouteChannelType,
        ack_timeout_secs: u64,
        max_pending_per_device: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            transition_device_route(
                route,
                previous_channel_type,
                ack_timeout_secs,
                max_pending_per_device
            )
        )
    }

    async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
    ) -> StoreResult<()> {
        delegate_db_async!(self, replace_device_identity(route, old_device_key))
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
}
