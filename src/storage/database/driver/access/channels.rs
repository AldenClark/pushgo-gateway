use super::*;
use async_trait::async_trait;

#[async_trait]
impl ChannelQueryDatabaseAccess for DatabaseDriver {
    async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        delegate_db_async!(self, channel_info(channel_id))
    }

    async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        delegate_db_async!(self, list_channel_devices(channel_id))
    }

    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        delegate_db_async!(
            self,
            list_channel_dispatch_targets(channel_id, effective_at)
        )
    }

    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<(ChannelInfo, String)>> {
        delegate_db_async!(self, channel_info_with_password(channel_id))
    }

    async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()> {
        delegate_db_async!(self, rename_channel(channel_id, alias))
    }
}

#[async_trait]
impl ProviderSubscriptionDatabaseAccess for DatabaseDriver {
    async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        delegate_db_async!(
            self,
            subscribe_channel(channel_id, alias, password_hash, device_token, platform)
        )
    }

    async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            unsubscribe_channel(channel_id, device_token, platform)
        )
    }

    async fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize> {
        delegate_db_async!(self, retire_device(device_token, platform))
    }

    async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            migrate_device_subscriptions(old_device_token, new_device_token, platform)
        )
    }

    async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        delegate_db_async!(
            self,
            list_subscribed_channels_for_device(device_token, platform)
        )
    }
}

#[async_trait]
impl PrivateChannelDatabaseAccess for DatabaseDriver {
    async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        delegate_db_async!(self, list_private_subscribed_channels_for_device(device_id))
    }

    async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
    ) -> StoreResult<SubscribeOutcome> {
        delegate_db_async!(
            self,
            upsert_private_channel(channel_id, alias, password_hash)
        )
    }

    async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        delegate_db_async!(self, private_subscribe_channel(channel_id, device_id))
    }

    async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        delegate_db_async!(self, private_unsubscribe_channel(channel_id, device_id))
    }

    async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        delegate_db_async!(
            self,
            list_private_subscribers(channel_id, subscribed_at_or_before)
        )
    }

    async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        delegate_db_async!(self, lookup_private_device(platform, token))
    }
}
