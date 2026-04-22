use crate::{api::Error, app::AppState, storage::OpDedupeReservation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchOpDedupeAction {
    FinalizeSent,
    ClearPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchOpGuard {
    dedupe_key: String,
    reserved_delivery_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchOpGuardDecision {
    Proceed(DispatchOpGuard),
    AlreadySent { delivery_id: String },
    Pending { delivery_id: String },
}

pub(crate) enum DispatchOpGuardStart {
    Proceed(DispatchOpGuard),
    Complete(NotificationDispatchSummary),
}

#[derive(Debug, Clone)]
pub(crate) struct NotificationDispatchSummary {
    pub channel_id: String,
    pub op_id: String,
    pub delivery_id: String,
    pub partial_failure: bool,
    pub private_enqueue_too_busy: bool,
    pub has_dispatch_attempt: bool,
}

impl NotificationDispatchSummary {
    pub(crate) fn failure_error_message(&self) -> Option<&'static str> {
        if !self.partial_failure {
            return None;
        }
        if self.private_enqueue_too_busy {
            Some("private enqueue failures exceeded safety threshold")
        } else {
            Some("notification dispatch completed with partial failure")
        }
    }

    fn dedupe_action(&self) -> DispatchOpDedupeAction {
        if !self.has_dispatch_attempt && (self.partial_failure || self.private_enqueue_too_busy) {
            DispatchOpDedupeAction::ClearPending
        } else {
            DispatchOpDedupeAction::FinalizeSent
        }
    }
}

impl DispatchOpGuard {
    fn already_sent_summary(
        channel_id: String,
        op_id: String,
        delivery_id: String,
    ) -> NotificationDispatchSummary {
        NotificationDispatchSummary {
            channel_id,
            op_id,
            delivery_id,
            partial_failure: false,
            private_enqueue_too_busy: false,
            has_dispatch_attempt: true,
        }
    }

    async fn reserve(
        state: &AppState,
        dedupe_key: String,
        reserved_delivery_id: String,
        created_at: i64,
    ) -> Result<DispatchOpGuardDecision, Error> {
        let reservation = state
            .store
            .reserve_op_dedupe_pending(
                dedupe_key.as_str(),
                reserved_delivery_id.as_str(),
                created_at,
            )
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;

        let decision = match reservation {
            OpDedupeReservation::Sent { delivery_id } => {
                DispatchOpGuardDecision::AlreadySent { delivery_id }
            }
            OpDedupeReservation::Pending { delivery_id } => {
                DispatchOpGuardDecision::Pending { delivery_id }
            }
            OpDedupeReservation::Reserved => DispatchOpGuardDecision::Proceed(Self {
                dedupe_key,
                reserved_delivery_id,
            }),
        };

        Ok(decision)
    }

    pub(crate) async fn begin(
        state: &AppState,
        dedupe_key: String,
        reserved_delivery_id: String,
        created_at: i64,
        channel_id: String,
        op_id: String,
    ) -> Result<DispatchOpGuardStart, Error> {
        match Self::reserve(state, dedupe_key, reserved_delivery_id, created_at).await? {
            DispatchOpGuardDecision::AlreadySent { delivery_id } => {
                Ok(DispatchOpGuardStart::Complete(Self::already_sent_summary(
                    channel_id,
                    op_id,
                    delivery_id,
                )))
            }
            DispatchOpGuardDecision::Pending { .. } => Err(Error::TooBusy),
            DispatchOpGuardDecision::Proceed(guard) => Ok(DispatchOpGuardStart::Proceed(guard)),
        }
    }

    async fn settle_summary(
        &self,
        state: &AppState,
        summary: &NotificationDispatchSummary,
    ) -> Result<(), Error> {
        self.settle(
            state,
            summary.dedupe_action(),
            Some(summary.delivery_id.as_str()),
        )
        .await
    }

    async fn clear_pending(&self, state: &AppState) -> Result<(), Error> {
        self.settle(state, DispatchOpDedupeAction::ClearPending, None)
            .await
    }

    async fn settle(
        &self,
        state: &AppState,
        action: DispatchOpDedupeAction,
        finalized_delivery_id: Option<&str>,
    ) -> Result<(), Error> {
        match action {
            DispatchOpDedupeAction::FinalizeSent => {
                let delivery_id =
                    finalized_delivery_id.unwrap_or(self.reserved_delivery_id.as_str());
                let marked = state
                    .store
                    .mark_op_dedupe_sent(self.dedupe_key.as_str(), delivery_id)
                    .await
                    .map_err(|err| Error::Internal(err.to_string()))?;
                if !marked {
                    return Err(Error::Internal("failed to finalize op dedupe".to_string()));
                }
            }
            DispatchOpDedupeAction::ClearPending => {
                state
                    .store
                    .clear_op_dedupe_pending(
                        self.dedupe_key.as_str(),
                        self.reserved_delivery_id.as_str(),
                    )
                    .await
                    .map_err(|err| Error::Internal(err.to_string()))?;
            }
        }
        Ok(())
    }

    pub(crate) async fn finish(
        self,
        state: &AppState,
        dispatch_result: Result<NotificationDispatchSummary, Error>,
    ) -> Result<NotificationDispatchSummary, Error> {
        match dispatch_result {
            Ok(summary) => {
                self.settle_summary(state, &summary).await?;
                Ok(summary)
            }
            Err(err) => {
                let _ = self.clear_pending(state).await;
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DispatchOpDedupeAction, NotificationDispatchSummary};

    #[test]
    fn notification_summary_reports_partial_failure_message() {
        let partial = NotificationDispatchSummary {
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            delivery_id: "delivery".to_string(),
            partial_failure: true,
            private_enqueue_too_busy: false,
            has_dispatch_attempt: true,
        };
        assert_eq!(
            partial.failure_error_message(),
            Some("notification dispatch completed with partial failure")
        );

        let busy = NotificationDispatchSummary {
            private_enqueue_too_busy: true,
            ..partial
        };
        assert_eq!(
            busy.failure_error_message(),
            Some("private enqueue failures exceeded safety threshold")
        );
    }

    #[test]
    fn notification_summary_selects_dedupe_action() {
        let success = NotificationDispatchSummary {
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            delivery_id: "delivery".to_string(),
            partial_failure: false,
            private_enqueue_too_busy: false,
            has_dispatch_attempt: true,
        };
        assert_eq!(
            success.dedupe_action(),
            DispatchOpDedupeAction::FinalizeSent
        );

        let partial = NotificationDispatchSummary {
            partial_failure: true,
            ..success
        };
        assert_eq!(
            partial.dedupe_action(),
            DispatchOpDedupeAction::FinalizeSent
        );

        let no_attempt_partial = NotificationDispatchSummary {
            has_dispatch_attempt: false,
            ..partial
        };
        assert_eq!(
            no_attempt_partial.dedupe_action(),
            DispatchOpDedupeAction::ClearPending
        );
    }
}
