//! Product application seam. Every ordinary ingress reaches this operation
//! after the existing channel authorization path; no old identity reservation
//! or dispatch submission is performed first.
use crate::domain_model::message::MessageInput;

use super::{AcceptRequest, Accepted, KernelError, OrdinaryStore, store::Result};

/// Project the committed ordinary facts into the existing submit summary.
/// Counts survive body/target release, so completed replay never invents queued
/// work from the original recipient kind.
pub(crate) fn accepted_dispatch_status(
    status: &str,
    provider_targets: i64,
    private_targets: i64,
) -> Result<&'static str> {
    match status {
        "provider_queued" => Ok("provider_queued"),
        "sent" => Ok("attempted_accepted"),
        "partially_failed" => Ok("attempted_partial_failure"),
        "failed" if provider_targets > 0 || private_targets > 0 => Ok("attempted_partial_failure"),
        "failed" => Ok("not_attempted"),
        // Persisted corruption or an unimplemented state is not evidence of
        // successful/queued dispatch. Let the existing unavailable response win.
        _ => Err(KernelError::Unavailable),
    }
}

impl OrdinaryStore {
    pub(crate) async fn accept_authorized(
        &self,
        channel_id: [u8; 16],
        input: MessageInput,
        now_millis: i64,
    ) -> Result<Accepted> {
        self.accept(AcceptRequest {
            channel_id: crate::value::ChannelId::from(channel_id).to_string(),
            authorized_channel: Some(channel_id),
            submit_clock: Some(now_millis),
            op_id: input.op_id,
            thing_id: input.thing_id,
            occurred_at: input.occurred_at,
            title: input.title,
            body: input.body,
            severity: input.severity,
            ttl: input.ttl,
            url: input.url,
            images: input.images,
            ciphertext: input.ciphertext,
            tags: input.tags,
            metadata: input.metadata,
            ..AcceptRequest::default()
        })
        .await
    }
}

impl From<KernelError> for crate::api::Error {
    fn from(error: KernelError) -> Self {
        use crate::api::Error;
        match error {
            KernelError::Control {
                status: 409,
                code,
                message,
            } => Error::Conflict {
                message: message.into(),
                code: code.into(),
            },
            KernelError::Control {
                status: 400,
                code,
                message,
            } => Error::validation_code(message, code),
            KernelError::Control { status: 401, .. } | KernelError::Unauthorized => {
                Error::Unauthorized
            }
            KernelError::Invalid(message) => Error::validation(message),
            KernelError::Conflict => Error::Conflict {
                message: "operation fingerprint conflict".into(),
                code: "op_id_payload_conflict".into(),
            },
            KernelError::ScopeConflict => Error::Conflict {
                message: "op_id is already used by a different operation".into(),
                code: "op_id_scope_conflict".into(),
            },
            KernelError::Capacity | KernelError::Unavailable => Error::TooBusy,
            other => Error::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
#[path = "application_expiry_tests.rs"]
mod expiry_tests;

#[cfg(test)]
mod response_tests {
    use super::accepted_dispatch_status;

    #[test]
    fn replay_uses_committed_outcome_after_body_and_targets_are_released() {
        assert_eq!(
            accepted_dispatch_status("sent", 2, 0).unwrap(),
            "attempted_accepted"
        );
        assert_eq!(
            accepted_dispatch_status("sent", 0, 2).unwrap(),
            "attempted_accepted"
        );
        assert_eq!(
            accepted_dispatch_status("provider_queued", 2, 1).unwrap(),
            "provider_queued"
        );
        assert_eq!(
            accepted_dispatch_status("partially_failed", 2, 1).unwrap(),
            "attempted_partial_failure"
        );
        assert_eq!(
            accepted_dispatch_status("failed", 2, 0).unwrap(),
            "attempted_partial_failure"
        );
    }

    #[test]
    fn zero_target_and_expired_acceptance_never_report_queued_or_attempted() {
        assert_eq!(
            accepted_dispatch_status("failed", 0, 0).unwrap(),
            "not_attempted"
        );
        assert!(accepted_dispatch_status("unrecognized", 1, 0).is_err());
    }
}
