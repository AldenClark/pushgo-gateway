use super::*;
use crate::storage::database::{DedupeDatabaseAccess, PrivateMessageDatabaseAccess};
use crate::storage::storage::private_capacity_recovery::BlockedPrivateSubmission;

// This bounds only unresolved frozen manifests. Completed submissions are
// compacted to the dedupe/status rows as part of finalization.
const DISPATCH_SUBMISSION_HARD_CAPACITY: usize = 10_000;

impl Storage {
    pub async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let removed = self
            .db
            .cleanup_private_expired_data(before_ts, limit)
            .await?;
        if removed > 0
            && let Err(err) = self.note_private_capacity_released(None, removed).await
        {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "dispatch.private_capacity_recovery_signal_failed",
                error = %(err.to_string())
            );
        }
        Ok(removed)
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
        self.reserve_op_dedupe_pending_with_fingerprint(dedupe_key, delivery_id, None, created_at)
            .await
    }

    pub async fn reserve_op_dedupe_pending_with_fingerprint(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        request_fingerprint: Option<&str>,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        self.db
            .reserve_op_dedupe_pending(
                dedupe_key,
                delivery_id,
                request_fingerprint,
                created_at,
                None,
                DISPATCH_SUBMISSION_HARD_CAPACITY,
            )
            .await
    }

    pub(crate) async fn reserve_dispatch_submission(
        &self,
        request_fingerprint: Option<&str>,
        submission: &DispatchSubmissionRecord,
    ) -> StoreResult<OpDedupeReservation> {
        let _admission = self.durable_write_gate.lock().await;
        self.db
            .reserve_op_dedupe_pending(
                submission.dedupe_key.as_str(),
                submission.delivery_id.as_str(),
                request_fingerprint,
                submission.accepted_at,
                Some(submission),
                DISPATCH_SUBMISSION_HARD_CAPACITY,
            )
            .await
    }

    pub(crate) async fn list_pending_dispatch_submissions(
        &self,
        limit: usize,
        now: i64,
    ) -> StoreResult<Vec<DispatchSubmissionRecord>> {
        self.db.list_pending_dispatch_submissions(limit, now).await
    }

    #[cfg(test)]
    pub(crate) async fn load_dispatch_submission_acceptance_order(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<Option<i64>> {
        self.db
            .load_dispatch_submission_acceptance_order(dedupe_key, delivery_id)
            .await
    }

    pub(crate) async fn claim_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        self.db
            .claim_dispatch_submission_materialization(
                dedupe_key,
                delivery_id,
                owner,
                now,
                lease_until,
            )
            .await
    }

    pub(crate) async fn renew_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        self.db
            .renew_dispatch_submission_materialization(
                dedupe_key,
                delivery_id,
                owner,
                now,
                lease_until,
            )
            .await
    }

    pub(crate) async fn release_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
    ) -> StoreResult<bool> {
        #[cfg(test)]
        if self.consume_submission_release_failure() {
            return Err(StoreError::Upgrade(
                "injected dispatch submission lease release failure".into(),
            ));
        }
        self.db
            .release_dispatch_submission_materialization(dedupe_key, delivery_id, owner, now)
            .await
    }

    pub(crate) async fn terminalize_unrecoverable_dispatch_submission(
        &self,
        record: &DispatchSubmissionRecord,
        reason: &str,
        now: i64,
    ) -> StoreResult<bool> {
        self.db
            .terminalize_unrecoverable_dispatch_submission(
                record.dedupe_key.as_str(),
                record.delivery_id.as_str(),
                record.op_id.as_str(),
                reason,
                now,
            )
            .await
    }

    pub(crate) fn private_capacity_epoch(&self) -> u64 {
        self.private_capacity_recovery.epoch()
    }

    pub(crate) fn private_capacity_recovery_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.private_capacity_recovery.notifier()
    }

    pub(crate) fn register_private_capacity_blocked_submission(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        devices: &[DeviceId],
    ) {
        self.private_capacity_recovery.register(
            BlockedPrivateSubmission {
                dedupe_key: dedupe_key.to_string(),
                delivery_id: delivery_id.to_string(),
                owner: owner.to_string(),
            },
            devices,
        );
    }

    pub(crate) fn clear_private_capacity_blocked_submission(&self, dedupe_key: &str) {
        self.private_capacity_recovery.clear(dedupe_key);
    }

    pub(crate) async fn expedite_private_capacity_recovery(
        &self,
        device_id: Option<DeviceId>,
        released_slots: usize,
    ) -> StoreResult<usize> {
        if released_slots == 0 {
            return Ok(0);
        }
        let selected = self.private_capacity_recovery.select_for_release(
            device_id,
            released_slots.min(DISPATCH_SUBMISSION_HARD_CAPACITY),
        );
        let now = chrono::Utc::now().timestamp_millis();
        let mut expedited = 0usize;
        for blocked in selected {
            match self
                .release_dispatch_submission_materialization(
                    blocked.dedupe_key.as_str(),
                    blocked.delivery_id.as_str(),
                    blocked.owner.as_str(),
                    now,
                )
                .await
            {
                Ok(released) => {
                    // `false` means the durable lease moved or the submission
                    // already finished; either way this registration is stale.
                    self.private_capacity_recovery
                        .clear(blocked.dedupe_key.as_str());
                    if released {
                        expedited = expedited.saturating_add(1);
                    }
                }
                Err(err) => {
                    // Do not consume the in-memory accelerator on a transient
                    // database failure. The recovery worker and the next
                    // capacity event can retry the same durable lease.
                    return Err(err);
                }
            }
        }
        if expedited > 0 {
            self.private_capacity_recovery.notifier().notify_one();
        }
        Ok(expedited)
    }

    pub(crate) async fn note_private_capacity_released(
        &self,
        device_id: Option<DeviceId>,
        released_slots: usize,
    ) -> StoreResult<usize> {
        if released_slots == 0 {
            return Ok(0);
        }
        self.private_capacity_recovery.note_capacity_released();
        // Wake the owned recovery worker even if the eager database release
        // below encounters a transient error.
        self.private_capacity_recovery.notifier().notify_one();
        self.expedite_private_capacity_recovery(device_id, released_slots)
            .await
    }

    pub async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        self.mark_op_dedupe_finalized(dedupe_key, delivery_id, DedupeState::Sent)
            .await
    }

    pub async fn mark_op_dedupe_finalized(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        state: DedupeState,
    ) -> StoreResult<bool> {
        self.db
            .mark_op_dedupe_sent(dedupe_key, delivery_id, state)
            .await
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
