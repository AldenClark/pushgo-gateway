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
        request_fingerprint: Option<&str>,
        created_at: i64,
        submission: Option<&DispatchSubmissionRecord>,
        submission_hard_capacity: usize,
    ) -> StoreResult<OpDedupeReservation> {
        delegate_db_async!(
            self,
            reserve_op_dedupe_pending(
                dedupe_key,
                delivery_id,
                request_fingerprint,
                created_at,
                submission,
                submission_hard_capacity
            )
        )
    }

    async fn list_pending_dispatch_submissions(
        &self,
        limit: usize,
        now: i64,
    ) -> StoreResult<Vec<DispatchSubmissionRecord>> {
        delegate_db_async!(self, list_pending_dispatch_submissions(limit, now))
    }

    async fn load_dispatch_submission_acceptance_order(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<Option<i64>> {
        delegate_db_async!(
            self,
            load_dispatch_submission_acceptance_order(dedupe_key, delivery_id)
        )
    }

    async fn claim_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            claim_dispatch_submission_materialization(
                dedupe_key,
                delivery_id,
                owner,
                now,
                lease_until
            )
        )
    }

    async fn renew_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            renew_dispatch_submission_materialization(
                dedupe_key,
                delivery_id,
                owner,
                now,
                lease_until
            )
        )
    }

    async fn release_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            release_dispatch_submission_materialization(dedupe_key, delivery_id, owner, now)
        )
    }

    async fn terminalize_unrecoverable_dispatch_submission(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        op_id: &str,
        reason: &str,
        now: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            terminalize_unrecoverable_dispatch_submission(
                dedupe_key,
                delivery_id,
                op_id,
                reason,
                now
            )
        )
    }

    async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        state: DedupeState,
    ) -> StoreResult<bool> {
        delegate_db_async!(self, mark_op_dedupe_sent(dedupe_key, delivery_id, state))
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
