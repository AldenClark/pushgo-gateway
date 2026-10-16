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
        self.enqueue_provider_dispatch_job_under_gate(record).await
    }

    /// A Widget invalidation is a derived latest-state job, not another
    /// ordinary acceptance. Hold the existing shared write gate across the
    /// order check and native enqueue so replay cannot reset a committed job,
    /// including a terminal job whose earlier COMMIT result was unknown.
    pub(crate) async fn enqueue_ordinary_widget_refresh(
        &self,
        record: &ProviderDispatchOutboxRecord,
    ) -> StoreResult<bool> {
        let _admission = self.durable_write_gate.lock().await;
        self.ensure_ordinary_health()?;
        if record.provider != "APNS_WIDGETS"
            || record.op_id.is_some()
            || record.dedupe_key.is_some()
            || !record.coalescible
            || record.coalesce_order <= 0
        {
            return Err(StoreError::UnsafeDurabilityConfiguration(
                "invalid ordinary derived Widget job".into(),
            ));
        }
        let ordinary = self
            .ordinary_handle()
            .ok_or(crate::ordinary::KernelError::Unavailable)?;
        if ordinary
            .widget_refresh_job_order(&record.job_id)
            .await?
            .is_some_and(|existing| existing >= record.coalesce_order)
        {
            return Ok(false);
        }
        self.enqueue_provider_dispatch_job_under_gate(record).await
    }

    async fn enqueue_provider_dispatch_job_under_gate(
        &self,
        record: &ProviderDispatchOutboxRecord,
    ) -> StoreResult<bool> {
        self.ensure_ordinary_health()?;
        let ordinary_pending = if let Some(ordinary) = self.ordinary_handle() {
            usize::try_from(
                ordinary.active_provider_count().await.map_err(|error| {
                    StoreError::UnsafeDurabilityConfiguration(error.to_string())
                })?,
            )
            .map_err(|_| {
                StoreError::UnsafeDurabilityConfiguration("invalid ordinary Provider usage".into())
            })?
        } else {
            0
        };
        // All ordinary and retained-feature admission shares this write gate.
        // Preserve the native old-path transaction and replay/coalescing rules.
        self.db
            .enqueue_provider_dispatch_job(
                record,
                PROVIDER_DISPATCH_HARD_CAPACITY.saturating_sub(ordinary_pending),
            )
            .await
            .map_err(|error| match error {
                StoreError::ProviderDispatchCapacityExceeded { pending, .. } => {
                    StoreError::ProviderDispatchCapacityExceeded {
                        pending: pending.saturating_add(ordinary_pending),
                        capacity: PROVIDER_DISPATCH_HARD_CAPACITY,
                    }
                }
                other => other,
            })
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
