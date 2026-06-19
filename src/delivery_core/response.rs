#[derive(Debug, Clone)]
pub(crate) struct SubmitResult {
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) entity: EntityRef,
    pub(crate) delivery_id: String,
    pub(crate) acceptance: SubmitAcceptance,
    pub(crate) summary: DeliverySummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubmitAcceptance {
    New,
    DuplicateCompleted,
    DuplicatePending,
}

#[derive(Debug, Clone)]
pub(crate) enum EntityRef {
    Message {
        message_id: String,
        thing_id: Option<String>,
    },
    Event {
        event_id: String,
        thing_id: Option<String>,
    },
    Thing {
        thing_id: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct DeliverySummary {
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) delivery_id: String,
    pub(crate) dedupe_status: DeliveryDedupeStatus,
    pub(crate) dispatch_status: DeliveryDispatchStatus,
    pub(crate) partial_failure: bool,
    pub(crate) private_enqueue_too_busy: bool,
    pub(crate) has_dispatch_attempt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryDedupeStatus {
    New,
    DuplicateCompleted,
    DuplicatePending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryDedupeSettleAction {
    FinalizeSent,
    ClearPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryDispatchStatus {
    NotAttempted,
    AttemptedAccepted,
    AttemptedPartialFailure,
    PrivateQueueTooBusy,
}

impl DeliveryDispatchStatus {
    pub(crate) fn from_execution(
        has_dispatch_attempt: bool,
        partial_failure: bool,
        private_enqueue_too_busy: bool,
    ) -> Self {
        if private_enqueue_too_busy {
            Self::PrivateQueueTooBusy
        } else if !has_dispatch_attempt {
            Self::NotAttempted
        } else if partial_failure {
            Self::AttemptedPartialFailure
        } else {
            Self::AttemptedAccepted
        }
    }

    pub(crate) fn has_dispatch_attempt(self) -> bool {
        !matches!(self, Self::NotAttempted)
    }

    pub(crate) fn is_operational_failure(self) -> bool {
        matches!(
            self,
            Self::AttemptedPartialFailure | Self::PrivateQueueTooBusy
        )
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::AttemptedAccepted => "attempted_accepted",
            Self::AttemptedPartialFailure => "attempted_partial_failure",
            Self::PrivateQueueTooBusy => "private_queue_too_busy",
        }
    }
}

impl DeliverySummary {
    pub(crate) fn new(
        channel_id: String,
        op_id: String,
        delivery_id: String,
        dedupe_status: DeliveryDedupeStatus,
        dispatch_status: DeliveryDispatchStatus,
    ) -> Self {
        Self {
            channel_id,
            op_id,
            delivery_id,
            dedupe_status,
            dispatch_status,
            partial_failure: matches!(
                dispatch_status,
                DeliveryDispatchStatus::AttemptedPartialFailure
                    | DeliveryDispatchStatus::PrivateQueueTooBusy
            ),
            private_enqueue_too_busy: matches!(
                dispatch_status,
                DeliveryDispatchStatus::PrivateQueueTooBusy
            ),
            has_dispatch_attempt: dispatch_status.has_dispatch_attempt(),
        }
    }

    pub(crate) fn failure_error_message(&self) -> Option<&'static str> {
        if self.dedupe_status == DeliveryDedupeStatus::DuplicatePending {
            return Some("notification dispatch is already pending");
        }
        match self.dispatch_status {
            DeliveryDispatchStatus::AttemptedAccepted => None,
            DeliveryDispatchStatus::AttemptedPartialFailure => {
                Some("notification dispatch completed with partial failure")
            }
            DeliveryDispatchStatus::PrivateQueueTooBusy => {
                Some("private enqueue failures exceeded safety threshold")
            }
            DeliveryDispatchStatus::NotAttempted => Some("notification dispatch was not attempted"),
        }
    }

    pub(crate) fn submit_acceptance(&self) -> SubmitAcceptance {
        match self.dedupe_status {
            DeliveryDedupeStatus::New => SubmitAcceptance::New,
            DeliveryDedupeStatus::DuplicateCompleted => SubmitAcceptance::DuplicateCompleted,
            DeliveryDedupeStatus::DuplicatePending => SubmitAcceptance::DuplicatePending,
        }
    }

    pub(crate) fn dedupe_settle_action(&self) -> DeliveryDedupeSettleAction {
        match self.dispatch_status {
            DeliveryDispatchStatus::NotAttempted | DeliveryDispatchStatus::PrivateQueueTooBusy => {
                DeliveryDedupeSettleAction::ClearPending
            }
            DeliveryDispatchStatus::AttemptedAccepted
            | DeliveryDispatchStatus::AttemptedPartialFailure => {
                DeliveryDedupeSettleAction::FinalizeSent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_summary_maps_duplicate_completed_outcome() {
        let summary = DeliverySummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::DuplicateCompleted,
            DeliveryDispatchStatus::AttemptedAccepted,
        );

        assert_eq!(
            summary.submit_acceptance(),
            SubmitAcceptance::DuplicateCompleted
        );
    }

    #[test]
    fn delivery_summary_maps_duplicate_pending_outcome() {
        let summary = DeliverySummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::DuplicatePending,
            DeliveryDispatchStatus::NotAttempted,
        );

        assert_eq!(
            summary.submit_acceptance(),
            SubmitAcceptance::DuplicatePending
        );
    }

    #[test]
    fn delivery_summary_reports_private_enqueue_too_busy_failure_message() {
        let summary = DeliverySummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::DuplicateCompleted,
            DeliveryDispatchStatus::PrivateQueueTooBusy,
        );

        assert_eq!(summary.channel_id, "channel");
        assert_eq!(
            summary.dedupe_status,
            DeliveryDedupeStatus::DuplicateCompleted
        );
        assert_eq!(
            summary.failure_error_message(),
            Some("private enqueue failures exceeded safety threshold")
        );
    }

    #[test]
    fn delivery_summary_keeps_acceptance_separate_from_dispatch_failure() {
        let summary = DeliverySummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::NotAttempted,
        );

        assert_eq!(
            summary.failure_error_message(),
            Some("notification dispatch was not attempted")
        );
        assert_eq!(summary.submit_acceptance(), SubmitAcceptance::New);
    }

    #[test]
    fn delivery_summary_selects_dedupe_settle_action() {
        let success = DeliverySummary::new(
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

        let partial = DeliverySummary::new(
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

        let no_attempt = DeliverySummary::new(
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

        let busy = DeliverySummary::new(
            "channel".to_string(),
            "op".to_string(),
            "delivery".to_string(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::PrivateQueueTooBusy,
        );
        assert_eq!(
            busy.dedupe_settle_action(),
            DeliveryDedupeSettleAction::ClearPending
        );
    }
}
