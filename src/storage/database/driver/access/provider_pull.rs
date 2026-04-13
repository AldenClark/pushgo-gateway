use super::*;
use async_trait::async_trait;

#[async_trait]
impl ProviderPullDatabaseAccess for DatabaseDriver {
    async fn enqueue_provider_pull_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            enqueue_provider_pull_item(
                device_id,
                delivery_id,
                message,
                platform,
                provider_token
            )
        )
    }

    async fn pull_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        delegate_db_async!(self, pull_provider_item(device_id, delivery_id, now))
    }

    async fn pull_provider_items(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullItem>> {
        delegate_db_async!(self, pull_provider_items(device_id, now, limit))
    }

    async fn ack_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        delegate_db_async!(self, ack_provider_item(device_id, delivery_id, now))
    }
}
