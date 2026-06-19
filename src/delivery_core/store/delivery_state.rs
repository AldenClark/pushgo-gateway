use async_trait::async_trait;

use crate::storage::{Storage, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryState {
    Accepted,
    Planned,
    Queued,
    Sent,
    Acked,
    FailedRetryable,
    FailedPermanent,
}

#[async_trait]
pub(crate) trait DeliveryStateStore {
    async fn reserve_delivery_state(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool>;

    async fn confirm_delivery_state(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<()>;

    async fn cleanup_delivery_state(&self, before_ts: i64, limit: usize) -> StoreResult<usize>;
}

#[async_trait]
impl DeliveryStateStore for Storage {
    async fn reserve_delivery_state(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        self.reserve_delivery_dedupe(dedupe_key, delivery_id, created_at)
            .await
    }

    async fn confirm_delivery_state(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<()> {
        self.confirm_delivery_dedupe(dedupe_key, delivery_id).await
    }

    async fn cleanup_delivery_state(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        self.cleanup_delivery_dedupe(before_ts, limit).await
    }
}
