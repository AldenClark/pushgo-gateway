use super::*;
use crate::storage::database::ProviderDispatchDatabaseAccess;

const PROVIDER_DISPATCH_HARD_CAPACITY: usize = 1_000_000;

impl Storage {
    pub(crate) async fn enqueue_provider_dispatch_job(
        &self,
        record: &ProviderDispatchOutboxRecord,
    ) -> StoreResult<bool> {
        #[cfg(test)]
        if record.provider == "APNS_LIVE_ACTIVITY" && self.consume_live_activity_enqueue_failure() {
            return Err(StoreError::InjectedTestFailure(
                "Live Activity durable enqueue",
            ));
        }
        let _admission = self.durable_write_gate.lock().await;
        self.db
            .enqueue_provider_dispatch_job(record, PROVIDER_DISPATCH_HARD_CAPACITY)
            .await
    }

    pub(crate) async fn activate_provider_dispatch_jobs(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<usize> {
        self.db
            .activate_provider_dispatch_jobs(delivery_id, now)
            .await
    }

    pub(crate) async fn reconcile_preparing_provider_dispatch_jobs(
        &self,
        now: i64,
    ) -> StoreResult<usize> {
        self.db
            .reconcile_preparing_provider_dispatch_jobs(now)
            .await
    }

    pub(crate) async fn claim_provider_dispatch_job(
        &self,
        provider: &str,
        job_id: Option<&str>,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        self.db
            .claim_provider_dispatch_job(provider, job_id, owner, now, lease_until)
            .await
    }

    pub(crate) async fn renew_provider_dispatch_job_lease(
        &self,
        lease: &ProviderDispatchOutboxLease,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        self.db
            .renew_provider_dispatch_job_lease(lease, now, lease_until)
            .await
    }

    pub(crate) async fn claim_due_provider_dispatch_retry_job(
        &self,
        provider: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        self.db
            .claim_due_provider_dispatch_retry_job(provider, owner, now, lease_until)
            .await
    }

    pub(crate) async fn settle_provider_dispatch_job(
        &self,
        lease: &ProviderDispatchOutboxLease,
        settlement: ProviderDispatchSettlement,
        next_attempt_at: i64,
        status_code: u16,
        error_code: Option<&str>,
        now: i64,
    ) -> StoreResult<bool> {
        self.db
            .settle_provider_dispatch_job(
                lease,
                settlement,
                next_attempt_at,
                status_code,
                error_code,
                now,
            )
            .await
    }

    pub(crate) async fn count_pending_provider_dispatch_jobs(
        &self,
        provider: &str,
    ) -> StoreResult<usize> {
        self.db.count_pending_provider_dispatch_jobs(provider).await
    }

    pub(crate) async fn provider_dispatch_terminal_success(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<bool>> {
        self.db
            .provider_dispatch_terminal_success(delivery_id)
            .await
    }

    pub(crate) async fn has_durable_dispatch_side_effects(
        &self,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        self.db.has_durable_dispatch_side_effects(delivery_id).await
    }

    pub(crate) async fn recover_expired_provider_dispatch_leases(
        &self,
        now: i64,
    ) -> StoreResult<usize> {
        self.db.recover_expired_provider_dispatch_leases(now).await
    }

    pub(crate) async fn cleanup_terminal_provider_dispatch_jobs(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db
            .cleanup_terminal_provider_dispatch_jobs(before_ts, limit.min(100_000))
            .await
    }
}
