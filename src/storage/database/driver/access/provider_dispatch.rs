use super::*;
use async_trait::async_trait;

#[async_trait]
impl ProviderDispatchDatabaseAccess for DatabaseDriver {
    async fn enqueue_provider_dispatch_job(
        &self,
        record: &ProviderDispatchOutboxRecord,
        hard_capacity: usize,
    ) -> StoreResult<bool> {
        delegate_db_async!(self, enqueue_provider_dispatch_job(record, hard_capacity))
    }

    async fn activate_provider_dispatch_jobs(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, activate_provider_dispatch_jobs(delivery_id, now))
    }

    async fn cancel_preparing_provider_dispatch_jobs(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            cancel_preparing_provider_dispatch_jobs(delivery_id, now)
        )
    }

    async fn reconcile_preparing_provider_dispatch_jobs(&self, now: i64) -> StoreResult<usize> {
        delegate_db_async!(self, reconcile_preparing_provider_dispatch_jobs(now))
    }

    async fn claim_provider_dispatch_job(
        &self,
        provider: &str,
        job_id: Option<&str>,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        delegate_db_async!(
            self,
            claim_provider_dispatch_job(provider, job_id, owner, now, lease_until)
        )
    }

    async fn renew_provider_dispatch_job_lease(
        &self,
        lease: &ProviderDispatchOutboxLease,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            renew_provider_dispatch_job_lease(lease, now, lease_until)
        )
    }

    async fn claim_due_provider_dispatch_retry_job(
        &self,
        provider: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        delegate_db_async!(
            self,
            claim_due_provider_dispatch_retry_job(provider, owner, now, lease_until)
        )
    }

    async fn settle_provider_dispatch_job(
        &self,
        lease: &ProviderDispatchOutboxLease,
        settlement: ProviderDispatchSettlement,
        next_attempt_at: i64,
        status_code: u16,
        error_code: Option<&str>,
        now: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            settle_provider_dispatch_job(
                lease,
                settlement,
                next_attempt_at,
                status_code,
                error_code,
                now
            )
        )
    }

    async fn count_pending_provider_dispatch_jobs(&self, provider: &str) -> StoreResult<usize> {
        delegate_db_async!(self, count_pending_provider_dispatch_jobs(provider))
    }

    async fn provider_dispatch_terminal_success(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<bool>> {
        delegate_db_async!(self, provider_dispatch_terminal_success(delivery_id))
    }

    async fn has_durable_dispatch_side_effects(&self, delivery_id: &str) -> StoreResult<bool> {
        delegate_db_async!(self, has_durable_dispatch_side_effects(delivery_id))
    }

    async fn recover_expired_provider_dispatch_leases(&self, now: i64) -> StoreResult<usize> {
        delegate_db_async!(self, recover_expired_provider_dispatch_leases(now))
    }

    async fn cleanup_terminal_provider_dispatch_jobs(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            cleanup_terminal_provider_dispatch_jobs(before_ts, limit)
        )
    }
}
