use super::*;
use async_trait::async_trait;

#[async_trait]
impl DedupeDatabaseAccess for DatabaseDriver {
    async fn cleanup_pending_op_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_pending_op_dedupe(before_ts, limit))
    }

    async fn cleanup_semantic_id_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_semantic_id_dedupe(before_ts, limit))
    }

    async fn cleanup_delivery_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_delivery_dedupe(before_ts, limit))
    }

    async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            reserve_delivery_dedupe(dedupe_key, delivery_id, created_at)
        )
    }

    async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        delegate_db_async!(
            self,
            reserve_semantic_id(dedupe_key, semantic_id, created_at)
        )
    }

    async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        delegate_db_async!(
            self,
            reserve_op_dedupe_pending(dedupe_key, delivery_id, created_at)
        )
    }

    async fn mark_op_dedupe_sent(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<bool> {
        delegate_db_async!(self, mark_op_dedupe_sent(dedupe_key, delivery_id))
    }

    async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, clear_op_dedupe_pending(dedupe_key, delivery_id))
    }

    async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, confirm_delivery_dedupe(dedupe_key, delivery_id))
    }
}
