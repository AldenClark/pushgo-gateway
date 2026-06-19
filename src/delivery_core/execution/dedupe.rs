use async_trait::async_trait;

use crate::{
    delivery_core::response::{
        DeliveryDedupeSettleAction, DeliveryDedupeStatus, DeliveryDispatchStatus, DeliverySummary,
    },
    storage::{OpDedupeReservation, StoreError},
};

pub(crate) type DispatchDedupeResult<T> = Result<T, DispatchDedupeError>;

#[derive(Debug)]
pub(crate) struct DispatchDedupeError {
    message: String,
}

impl DispatchDedupeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn into_message(self) -> String {
        self.message
    }
}

impl From<StoreError> for DispatchDedupeError {
    fn from(value: StoreError) -> Self {
        Self::new(value.to_string())
    }
}

#[async_trait]
pub(crate) trait DispatchDedupeStore: Send + Sync {
    async fn reserve_op_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchOpGuard {
    dedupe_key: String,
    reserved_delivery_id: String,
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
        created_at: i64,
    ) -> DispatchDedupeResult<DispatchOpGuardDecision> {
        let reservation = store
            .reserve_op_pending(
                dedupe_key.as_str(),
                reserved_delivery_id.as_str(),
                created_at,
            )
            .await
            .map_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "dispatch.dedupe_reserve_failed",
                    dedupe_key = %(crate::util::redact_text(dedupe_key.as_str())),
                    reserved_delivery_id = %(crate::util::redact_text(reserved_delivery_id.as_str())),
                    error = %(err.message.as_str())
                );
                err
            })?;

        let decision = match reservation {
            OpDedupeReservation::Sent { delivery_id } => {
                DispatchOpGuardDecision::AlreadyFinalized {
                    delivery_id,
                    dispatch_status: DeliveryDispatchStatus::AttemptedAccepted,
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
            OpDedupeReservation::Reserved => DispatchOpGuardDecision::Proceed(Self {
                dedupe_key,
                reserved_delivery_id,
            }),
        };
        emit_dispatch_reservation_trace(&decision);

        Ok(decision)
    }

    pub(crate) async fn begin(
        store: &(dyn DispatchDedupeStore + Send + Sync),
        dedupe_key: String,
        reserved_delivery_id: String,
        created_at: i64,
        channel_id: String,
        op_id: String,
    ) -> DispatchDedupeResult<DispatchOpGuardStart> {
        match Self::reserve(store, dedupe_key, reserved_delivery_id, created_at).await? {
            DispatchOpGuardDecision::AlreadyFinalized {
                delivery_id,
                dispatch_status,
            } => Ok(DispatchOpGuardStart::Complete(
                Self::already_finalized_summary(channel_id, op_id, delivery_id, dispatch_status),
            )),
            DispatchOpGuardDecision::Pending { delivery_id } => Ok(DispatchOpGuardStart::Complete(
                Self::pending_summary(channel_id, op_id, delivery_id),
            )),
            DispatchOpGuardDecision::Proceed(guard) => Ok(DispatchOpGuardStart::Proceed(guard)),
        }
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
                    .map_err(|err| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::ERROR,
                            event = "dispatch.dedupe_finalize_failed",
                            dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                            reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                            finalized_delivery_id = %(crate::util::redact_text(delivery_id)),
                            error = %(err.message.as_str())
                        );
                        err
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
                    .map_err(|err| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::ERROR,
                            event = "dispatch.dedupe_clear_pending_failed",
                            dedupe_key = %(crate::util::redact_text(self.dedupe_key.as_str())),
                            reserved_delivery_id = %(crate::util::redact_text(self.reserved_delivery_id.as_str())),
                            error = %(err.message.as_str())
                        );
                        err
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
                let _ = self.clear_pending(store).await;
                Err(err)
            }
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
