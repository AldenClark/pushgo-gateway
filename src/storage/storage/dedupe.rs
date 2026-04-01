use super::*;
use crate::storage::database::{DedupeDatabaseAccess, PrivateMessageDatabaseAccess};

impl Storage {
    pub async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_private_expired_data(before_ts, limit).await
    }

    pub async fn cleanup_pending_op_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_pending_op_dedupe(before_ts, limit).await
    }

    pub async fn cleanup_semantic_id_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_semantic_id_dedupe(before_ts, limit).await
    }

    pub async fn cleanup_delivery_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_delivery_dedupe(before_ts, limit).await
    }

    pub async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        self.db
            .reserve_delivery_dedupe(dedupe_key, delivery_id, created_at)
            .await
    }

    pub async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        self.db
            .reserve_semantic_id(dedupe_key, semantic_id, created_at)
            .await
    }

    pub async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db
            .confirm_delivery_dedupe(dedupe_key, delivery_id)
            .await
    }

    pub async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        self.db
            .reserve_op_dedupe_pending(dedupe_key, delivery_id, created_at)
            .await
    }

    pub async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        self.db.mark_op_dedupe_sent(dedupe_key, delivery_id).await
    }

    pub async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db
            .clear_op_dedupe_pending(dedupe_key, delivery_id)
            .await
    }
}
