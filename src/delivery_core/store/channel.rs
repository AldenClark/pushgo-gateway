use async_trait::async_trait;

use crate::storage::{ChannelInfo, DispatchTarget, Storage, StoreResult};

#[async_trait]
pub(crate) trait ChannelStore {
    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>>;

    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>>;
}

#[async_trait]
impl ChannelStore for Storage {
    async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        self.channel_info_with_password(channel_id, password).await
    }

    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        self.list_channel_dispatch_targets(channel_id, effective_at)
            .await
    }
}
