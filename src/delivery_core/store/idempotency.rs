use async_trait::async_trait;

use crate::storage::{OpDedupeReservation, SemanticIdReservation, Storage, StoreResult};

#[async_trait]
pub(crate) trait IdempotencyStore {
    async fn reserve_semantic_id(
        &self,
        key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation>;

    async fn reserve_op_pending(
        &self,
        key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation>;

    async fn mark_op_sent(&self, key: &str, delivery_id: &str) -> StoreResult<bool>;
    async fn clear_op_pending(&self, key: &str, delivery_id: &str) -> StoreResult<()>;
}

#[async_trait]
impl IdempotencyStore for Storage {
    async fn reserve_semantic_id(
        &self,
        key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        self.reserve_semantic_id(key, semantic_id, created_at).await
    }

    async fn reserve_op_pending(
        &self,
        key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        self.reserve_op_dedupe_pending(key, delivery_id, created_at)
            .await
    }

    async fn mark_op_sent(&self, key: &str, delivery_id: &str) -> StoreResult<bool> {
        self.mark_op_dedupe_sent(key, delivery_id).await
    }

    async fn clear_op_pending(&self, key: &str, delivery_id: &str) -> StoreResult<()> {
        self.clear_op_dedupe_pending(key, delivery_id).await
    }
}
