use async_trait::async_trait;

use crate::{
    api::Error,
    app::AppState,
    delivery_core::{
        execution::dedupe::{
            DispatchDedupeError, DispatchDedupeResult, DispatchDedupeStore,
            DispatchOpGuard as CoreDispatchOpGuard,
        },
        response::{DeliveryDispatchStatus, DeliverySummary},
    },
    storage::{DedupeState, DispatchSubmissionRecord, OpDedupeReservation},
};

pub(crate) type NotificationDispatchSummary = DeliverySummary;

pub(crate) struct DispatchOpGuard(CoreDispatchOpGuard);

pub(crate) enum DispatchOpGuardStart {
    Proceed(DispatchOpGuard),
    Complete(NotificationDispatchSummary),
}

#[async_trait]
impl DispatchDedupeStore for AppState {
    async fn reserve_op_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        request_fingerprint: Option<&str>,
        created_at: i64,
    ) -> DispatchDedupeResult<OpDedupeReservation> {
        self.store
            .reserve_op_dedupe_pending_with_fingerprint(
                dedupe_key,
                delivery_id,
                request_fingerprint,
                created_at,
            )
            .await
            .map_err(DispatchDedupeError::from)
    }

    async fn reserve_submission(
        &self,
        request_fingerprint: Option<&str>,
        submission: &DispatchSubmissionRecord,
    ) -> DispatchDedupeResult<OpDedupeReservation> {
        self.store
            .reserve_dispatch_submission(request_fingerprint, submission)
            .await
            .map_err(DispatchDedupeError::from)
    }

    async fn mark_op_finalized(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        dispatch_status: DeliveryDispatchStatus,
    ) -> DispatchDedupeResult<bool> {
        let state = match dispatch_status {
            DeliveryDispatchStatus::ProviderQueued => DedupeState::ProviderQueued,
            DeliveryDispatchStatus::AttemptedAccepted => DedupeState::Sent,
            DeliveryDispatchStatus::AttemptedPartialFailure => DedupeState::PartialFailure,
            DeliveryDispatchStatus::MaterializationPending
            | DeliveryDispatchStatus::NotAttempted
            | DeliveryDispatchStatus::PrivateQueueTooBusy => {
                return Err(DispatchDedupeError::new(
                    "only attempted dispatches can be finalized",
                ));
            }
        };
        self.store
            .mark_op_dedupe_finalized(dedupe_key, delivery_id, state)
            .await
            .map_err(DispatchDedupeError::from)
    }

    async fn clear_op_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> DispatchDedupeResult<()> {
        self.store
            .clear_op_dedupe_pending(dedupe_key, delivery_id)
            .await
            .map_err(DispatchDedupeError::from)
    }

    async fn has_durable_dispatch_side_effects(
        &self,
        delivery_id: &str,
    ) -> DispatchDedupeResult<bool> {
        self.store
            .has_durable_dispatch_side_effects(delivery_id)
            .await
            .map_err(DispatchDedupeError::from)
    }
}

impl DispatchOpGuard {
    pub(crate) fn acceptance_order(&self) -> i64 {
        self.0.acceptance_order()
    }

    pub(crate) async fn begin_submission(
        state: &AppState,
        submission: &DispatchSubmissionRecord,
        request_fingerprint: Option<&str>,
        channel_id: String,
        op_id: String,
    ) -> Result<DispatchOpGuardStart, Error> {
        match CoreDispatchOpGuard::begin_submission(
            state,
            submission,
            request_fingerprint,
            channel_id,
            op_id,
        )
        .await
        .map_err(api_error_from_dedupe)?
        {
            crate::delivery_core::execution::dedupe::DispatchOpGuardStart::Proceed(guard) => {
                Ok(DispatchOpGuardStart::Proceed(Self(guard)))
            }
            crate::delivery_core::execution::dedupe::DispatchOpGuardStart::Complete(summary) => {
                Ok(DispatchOpGuardStart::Complete(summary))
            }
        }
    }

    pub(crate) async fn finish_submission(
        self,
        state: &AppState,
        dispatch_result: Result<NotificationDispatchSummary, Error>,
    ) -> Result<NotificationDispatchSummary, Error> {
        self.0.finish_recoverable(state, dispatch_result).await
    }

    pub(crate) fn resume_submission(dedupe_key: String, delivery_id: String) -> Self {
        Self(CoreDispatchOpGuard::resume(dedupe_key, delivery_id))
    }
}

fn api_error_from_dedupe(err: DispatchDedupeError) -> Error {
    if err.is_too_busy() {
        return Error::TooBusy;
    }
    if err.is_fingerprint_conflict() {
        return Error::Conflict {
            message: err.into_message().into(),
            code: "op_id_payload_conflict".into(),
        };
    }
    Error::Internal(err.into_message())
}

impl From<DispatchDedupeError> for Error {
    fn from(value: DispatchDedupeError) -> Self {
        api_error_from_dedupe(value)
    }
}

#[cfg(test)]
mod tests {
    use super::NotificationDispatchSummary;
    use crate::delivery_core::response::{
        DeliveryDedupeSettleAction, DeliveryDedupeStatus, DeliveryDispatchStatus,
    };

    #[test]
    fn notification_summary_reports_partial_failure_message() {
        let partial = NotificationDispatchSummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::AttemptedPartialFailure,
        );
        assert_eq!(
            partial.failure_error_message(),
            Some("notification dispatch completed with partial failure")
        );

        let busy = NotificationDispatchSummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::PrivateQueueTooBusy,
        );
        assert_eq!(
            busy.failure_error_message(),
            Some("private enqueue failures exceeded safety threshold")
        );
    }

    #[test]
    fn notification_summary_selects_dedupe_action() {
        let success = NotificationDispatchSummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::AttemptedAccepted,
        );
        assert_eq!(
            success.dedupe_settle_action(),
            DeliveryDedupeSettleAction::FinalizeSent
        );

        let partial = NotificationDispatchSummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::AttemptedPartialFailure,
        );
        assert_eq!(
            partial.dedupe_settle_action(),
            DeliveryDedupeSettleAction::FinalizeSent
        );

        let no_attempt = NotificationDispatchSummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::NotAttempted,
        );
        assert_eq!(
            no_attempt.dedupe_settle_action(),
            DeliveryDedupeSettleAction::ClearPending
        );
    }
}
