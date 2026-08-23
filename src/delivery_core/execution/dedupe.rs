use async_trait::async_trait;

use crate::{
    delivery_core::response::{
        DeliveryDedupeSettleAction, DeliveryDedupeStatus, DeliveryDispatchStatus, DeliverySummary,
    },
    storage::{DispatchSubmissionRecord, OpDedupeReservation, StoreError},
};

pub(crate) type DispatchDedupeResult<T> = Result<T, DispatchDedupeError>;

#[derive(Debug)]
pub(crate) struct DispatchDedupeError {
    message: String,
    fingerprint_conflict: bool,
    too_busy: bool,
}

impl DispatchDedupeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fingerprint_conflict: false,
            too_busy: false,
        }
    }

    fn fingerprint_conflict(delivery_id: &str) -> Self {
        Self {
            message: format!("op_id payload conflicts with delivery {delivery_id}"),
            fingerprint_conflict: true,
            too_busy: false,
        }
    }

    pub(crate) fn is_fingerprint_conflict(&self) -> bool {
        self.fingerprint_conflict
    }

    pub(crate) fn is_too_busy(&self) -> bool {
        self.too_busy
    }

    pub(crate) fn into_message(self) -> String {
        self.message
    }
}

impl From<StoreError> for DispatchDedupeError {
    fn from(value: StoreError) -> Self {
        let too_busy = matches!(
            value,
            StoreError::DispatchSubmissionCapacityExceeded { .. }
                | StoreError::ProviderDispatchCapacityExceeded { .. }
                | StoreError::PrivateOutboxCapacityExceeded { .. }
        );
        Self {
            message: value.to_string(),
            fingerprint_conflict: false,
            too_busy,
        }
    }
}

#[async_trait]
pub(crate) trait DispatchDedupeStore: Send + Sync {
    async fn reserve_op_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        request_fingerprint: Option<&str>,
        created_at: i64,
    ) -> DispatchDedupeResult<OpDedupeReservation>;

    async fn reserve_submission(
        &self,
        request_fingerprint: Option<&str>,
        submission: &DispatchSubmissionRecord,
    ) -> DispatchDedupeResult<OpDedupeReservation>;

    async fn mark_op_finalized(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        dispatch_status: DeliveryDispatchStatus,
    ) -> DispatchDedupeResult<bool>;

    async fn clear_op_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> DispatchDedupeResult<()>;

    async fn has_durable_dispatch_side_effects(
        &self,
        delivery_id: &str,
    ) -> DispatchDedupeResult<bool>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchOpGuard {
    dedupe_key: String,
    reserved_delivery_id: String,
    acceptance_order: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchOpGuardDecision {
    Proceed(DispatchOpGuard),
    AlreadyFinalized {
        delivery_id: String,
        dispatch_status: DeliveryDispatchStatus,
    },
    Pending {
        delivery_id: String,
    },
}

pub(crate) enum DispatchOpGuardStart {
    Proceed(DispatchOpGuard),
    Complete(DeliverySummary),
}

impl DispatchOpGuard {
    pub(crate) fn resume(dedupe_key: String, reserved_delivery_id: String) -> Self {
        Self {
            dedupe_key,
            reserved_delivery_id,
            acceptance_order: 0,
        }
    }

    pub(crate) fn acceptance_order(&self) -> i64 {
        self.acceptance_order
    }

    fn already_finalized_summary(
        channel_id: String,
        op_id: String,
        delivery_id: String,
        dispatch_status: DeliveryDispatchStatus,
    ) -> DeliverySummary {
        DeliverySummary::new(
            channel_id,
            op_id,
            delivery_id,
            DeliveryDedupeStatus::DuplicateCompleted,
            dispatch_status,
        )
    }

    fn pending_summary(channel_id: String, op_id: String, delivery_id: String) -> DeliverySummary {
        DeliverySummary::new(
            channel_id,
            op_id,
            delivery_id,
            DeliveryDedupeStatus::DuplicatePending,
            DeliveryDispatchStatus::NotAttempted,
        )
    }

    async fn reserve(
        store: &(dyn DispatchDedupeStore + Send + Sync),
        dedupe_key: String,
        reserved_delivery_id: String,
        request_fingerprint: Option<&str>,
        created_at: i64,
    ) -> DispatchDedupeResult<DispatchOpGuardDecision> {
        let reservation = store
            .reserve_op_pending(
                dedupe_key.as_str(),
                reserved_delivery_id.as_str(),
                request_fingerprint,
                created_at,
            )
            .await
            .inspect_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "dispatch.dedupe_reserve_failed",
                    dedupe_key = %(crate::util::redact_text(dedupe_key.as_str())),
                    reserved_delivery_id = %(crate::util::redact_text(reserved_delivery_id.as_str())),
                    error = %(err.message.as_str())
                );
            })?;

        let decision =
            Self::decision_from_reservation(reservation, dedupe_key, reserved_delivery_id)?;
        emit_dispatch_reservation_trace(&decision);

        Ok(decision)
    }

    fn decision_from_reservation(
        reservation: OpDedupeReservation,
        dedupe_key: String,
        reserved_delivery_id: String,
    ) -> DispatchDedupeResult<DispatchOpGuardDecision> {
        let decision = match reservation {
            OpDedupeReservation::Sent { delivery_id } => {
                DispatchOpGuardDecision::AlreadyFinalized {
                    delivery_id,
                    dispatch_status: DeliveryDispatchStatus::AttemptedAccepted,
                }
            }
            OpDedupeReservation::ProviderQueued { delivery_id } => {
                DispatchOpGuardDecision::AlreadyFinalized {
                    delivery_id,
                    dispatch_status: DeliveryDispatchStatus::ProviderQueued,
                }
            }
            OpDedupeReservation::PartialFailure { delivery_id } => {
                DispatchOpGuardDecision::AlreadyFinalized {
                    delivery_id,
                    dispatch_status: DeliveryDispatchStatus::AttemptedPartialFailure,
                }
            }
            OpDedupeReservation::Pending { delivery_id } => {
                DispatchOpGuardDecision::Pending { delivery_id }
            }
            OpDedupeReservation::FingerprintConflict { delivery_id } => {
                return Err(DispatchDedupeError::fingerprint_conflict(&delivery_id));
            }
            OpDedupeReservation::ReservedSubmission { acceptance_order } => {
                DispatchOpGuardDecision::Proceed(Self {
                    dedupe_key,
                    reserved_delivery_id,
                    acceptance_order,
                })
            }
            OpDedupeReservation::Reserved => DispatchOpGuardDecision::Proceed(Self {
                dedupe_key,
                reserved_delivery_id,
                acceptance_order: 0,
            }),
        };
        Ok(decision)
    }

    fn start_from_decision(
        decision: DispatchOpGuardDecision,
        channel_id: String,
        op_id: String,
    ) -> DispatchOpGuardStart {
        match decision {
            DispatchOpGuardDecision::AlreadyFinalized {
                delivery_id,
                dispatch_status,
            } => DispatchOpGuardStart::Complete(Self::already_finalized_summary(
                channel_id,
                op_id,
                delivery_id,
                dispatch_status,
            )),
            DispatchOpGuardDecision::Pending { delivery_id } => DispatchOpGuardStart::Complete(
                Self::pending_summary(channel_id, op_id, delivery_id),
            ),
            DispatchOpGuardDecision::Proceed(guard) => DispatchOpGuardStart::Proceed(guard),
        }
    }

    pub(crate) async fn begin(
        store: &(dyn DispatchDedupeStore + Send + Sync),
        dedupe_key: String,
        reserved_delivery_id: String,
        request_fingerprint: Option<&str>,
        created_at: i64,
        channel_id: String,
        op_id: String,
    ) -> DispatchDedupeResult<DispatchOpGuardStart> {
        let decision = Self::reserve(
            store,
            dedupe_key,
            reserved_delivery_id,
            request_fingerprint,
            created_at,
        )
        .await?;
        Ok(Self::start_from_decision(decision, channel_id, op_id))
    }

    pub(crate) async fn begin_submission(
        store: &(dyn DispatchDedupeStore + Send + Sync),
        submission: &DispatchSubmissionRecord,
        request_fingerprint: Option<&str>,
        channel_id: String,
        op_id: String,
    ) -> DispatchDedupeResult<DispatchOpGuardStart> {
        let reservation = store
            .reserve_submission(request_fingerprint, submission)
            .await?;
        let decision = Self::decision_from_reservation(
            reservation,
            submission.dedupe_key.clone(),
            submission.delivery_id.clone(),
        )?;
        emit_dispatch_reservation_trace(&decision);
        Ok(Self::start_from_decision(decision, channel_id, op_id))
    }

    async fn settle_summary(
        &self,
        store: &(dyn DispatchDedupeStore + Send + Sync),
        summary: &DeliverySummary,
    ) -> DispatchDedupeResult<()> {
        self.settle(
            store,
            summary.dedupe_settle_action(),
            Some(summary.delivery_id.as_str()),
            Some(summary.dispatch_status),
        )
        .await
    }

    async fn clear_pending(
        &self,
        store: &(dyn DispatchDedupeStore + Send + Sync),
    ) -> DispatchDedupeResult<()> {
        self.settle(store, DeliveryDedupeSettleAction::ClearPending, None, None)
            .await
    }

    async fn settle(
        &self,
        store: &(dyn DispatchDedupeStore + Send + Sync),
        action: DeliveryDedupeSettleAction,
        finalized_delivery_id: Option<&str>,
        finalized_status: Option<DeliveryDispatchStatus>,
    ) -> DispatchDedupeResult<()> {
        match action {
            DeliveryDedupeSettleAction::FinalizeSent => {
                let delivery_id =
                    finalized_delivery_id.unwrap_or(self.reserved_delivery_id.as_str());
                let dispatch_status =
                    finalized_status.unwrap_or(DeliveryDispatchStatus::AttemptedAccepted);
                let marked = store
                    .mark_op_finalized(self.dedupe_key.as_str(), delivery_id, dispatch_status)
                    .await
                    .inspect_err(|err| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::ERROR,
                            event = "dispatch.dedupe_finalize_failed",
                            dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                            reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                            finalized_delivery_id = %(crate::util::redact_text(delivery_id)),
                            error = %(err.message.as_str())
                        );
                    })?;
                if !marked {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "dispatch.dedupe_settle_failed",
                        action = %("finalize_sent"),
                        dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                        reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                        finalized_delivery_id = %(crate::util::redact_text(delivery_id)),
                        reason = %("mark_op_dedupe_sent_returned_false")
                    );
                    return Err(DispatchDedupeError::new("failed to finalize op dedupe"));
                }
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::INFO,
                    event = "dispatch.dedupe_settled",
                    action = %("finalize_sent"),
                    dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                    reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                    finalized_delivery_id = %(crate::util::redact_text(delivery_id))
                );
            }
            DeliveryDedupeSettleAction::ClearPending => {
                store
                    .clear_op_pending(self.dedupe_key.as_str(), self.reserved_delivery_id.as_str())
                    .await
                    .inspect_err(|err| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::ERROR,
                            event = "dispatch.dedupe_clear_pending_failed",
                            dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                            reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                            error = %(err.message.as_str())
                        );
                    })?;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::INFO,
                    event = "dispatch.dedupe_settled",
                    action = %("clear_pending"),
                    dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                    reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str()))
                );
            }
            DeliveryDedupeSettleAction::KeepPending => {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::INFO,
                    event = "dispatch.dedupe_settled",
                    action = %("keep_pending"),
                    dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                    reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str()))
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn finish<E>(
        self,
        store: &(dyn DispatchDedupeStore + Send + Sync),
        dispatch_result: Result<DeliverySummary, E>,
    ) -> Result<DeliverySummary, E>
    where
        E: From<DispatchDedupeError>,
    {
        match dispatch_result {
            Ok(summary) => {
                self.settle_summary(store, &summary).await?;
                Ok(summary)
            }
            Err(err) => {
                let has_side_effects = store
                    .has_durable_dispatch_side_effects(&self.reserved_delivery_id)
                    .await
                    .unwrap_or(true);
                if has_side_effects {
                    let _ = self
                        .settle(
                            store,
                            DeliveryDedupeSettleAction::FinalizeSent,
                            Some(&self.reserved_delivery_id),
                            Some(DeliveryDispatchStatus::AttemptedPartialFailure),
                        )
                        .await;
                } else {
                    let _ = self.clear_pending(store).await;
                }
                Err(err)
            }
        }
    }

    /// A committed submission manifest is the retry source of truth. A
    /// transient materialization error must leave both it and the pending
    /// dedupe identity intact so a restart can replay the frozen target set.
    pub(crate) async fn finish_recoverable<E>(
        self,
        store: &(dyn DispatchDedupeStore + Send + Sync),
        dispatch_result: Result<DeliverySummary, E>,
    ) -> Result<DeliverySummary, E>
    where
        E: From<DispatchDedupeError>,
    {
        match dispatch_result {
            Ok(summary) => {
                self.settle_summary(store, &summary).await?;
                Ok(summary)
            }
            Err(err) => Err(err),
        }
    }
}

fn emit_dispatch_reservation_trace(decision: &DispatchOpGuardDecision) {
    match decision {
        DispatchOpGuardDecision::Proceed(guard) => {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "dispatch.dedupe_reserved",
                dedupe_key = %(crate::util::redact_text(guard.dedupe_key.as_str())),
                reserved_delivery_id = %(crate::util::redact_text(guard.reserved_delivery_id.as_str()))
            );
        }
        DispatchOpGuardDecision::AlreadyFinalized {
            delivery_id,
            dispatch_status,
        } => {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "dispatch.dedupe_already_finalized",
                delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                dispatch_status = %(dispatch_status.as_str())
            );
        }
        DispatchOpGuardDecision::Pending { delivery_id } => {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "dispatch.dedupe_pending",
                delivery_id = %(crate::util::redact_text(delivery_id.as_str()))
            );
        }
    }
}
