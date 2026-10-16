use async_trait::async_trait;

use crate::{
    api::{Error, handlers::message::dispatch_entity_notification},
    app::AppState,
    delivery_core::{
        error::CoreError,
        execution::request::{
            DispatchAlert, DispatchEntityPayload, DispatchEventInput, DispatchRequest,
            DispatchThingInput,
        },
        response::{
            DeliveryDedupeStatus, DeliveryDispatchStatus, DeliverySummary, EntityRef, SubmitResult,
        },
        store::{idempotency::IdempotencyStore, sender_status::SenderStatusStore},
        submit::{AuthorizedSubmitChannel, SubmitRuntime},
    },
    storage::MaintenanceCleanupConfig,
};

#[async_trait]
impl SubmitRuntime for AppState {
    fn idempotency_store(&self) -> &(dyn IdempotencyStore + Send + Sync) {
        &self.store
    }

    fn sender_status_store(&self) -> &(dyn SenderStatusStore + Send + Sync) {
        &self.store
    }

    fn sender_status_retention_millis(&self) -> i64 {
        self.private
            .as_ref()
            .map(|private| private.config.maintenance_cleanup.dedupe_retention_secs)
            .unwrap_or_else(|| MaintenanceCleanupConfig::default().dedupe_retention_secs)
            .saturating_mul(1000)
    }

    async fn authorize_channel_by_password(
        &self,
        channel_id: &str,
        password: &str,
    ) -> Result<AuthorizedSubmitChannel, CoreError> {
        crate::api::handlers::channel_auth::authorize_channel_by_password(
            self, channel_id, password,
        )
        .await
        .map(|authorized| AuthorizedSubmitChannel {
            channel_id: authorized.channel_id,
            channel_id_text: authorized.channel_scope,
        })
        .map_err(core_error_from_api)
    }

    async fn accept_ordinary_message(
        &self,
        channel: AuthorizedSubmitChannel,
        message: crate::domain_model::message::MessageInput,
        now_millis: i64,
    ) -> Result<SubmitResult, CoreError> {
        let thing_id = message
            .thing_id
            .as_deref()
            .map(|raw| {
                crate::value::EntityId::parse(raw, "thing_id")
                    .map(crate::value::EntityId::into_inner)
            })
            .transpose()?;
        let ordinary = self.store.ordinary_handle().ok_or_else(|| {
            CoreError::internal("ordinary authority was not initialized before ingress")
        })?;
        let accepted = ordinary
            .accept_authorized(channel.channel_id, message, now_millis)
            .await
            .map_err(CoreError::from)?;
        // accept committed the recoverable Widget invalidation and notified
        // the existing recovery worker. The HTTP/MCP/MQTT caller must not own
        // another cancellable post-commit outbox write or wait on its fanout.
        ordinary_submit_result(channel, thing_id, accepted)
    }

    async fn dispatch_event(
        &self,
        input: DispatchEventInput,
    ) -> Result<DeliverySummary, CoreError> {
        dispatch_entity_notification(
            self,
            input.authorized_channel.channel_id,
            DispatchRequest::new(
                input.op_id,
                None,
                input.occurred_at,
                DispatchAlert::new(input.title, input.body, None, None),
                DispatchEntityPayload::event(input.event_id, input.custom_data, input.extra_fields),
                input.delivery_policy,
            )
            .with_live_activity(input.live_activity),
        )
        .await
        .map_err(core_error_from_api)
    }

    async fn dispatch_thing(
        &self,
        input: DispatchThingInput,
    ) -> Result<DeliverySummary, CoreError> {
        dispatch_entity_notification(
            self,
            input.authorized_channel.channel_id,
            DispatchRequest::new(
                input.op_id,
                None,
                input.occurred_at,
                DispatchAlert::new(input.title, input.body, None, None),
                DispatchEntityPayload::thing(input.thing_id, input.custom_data, input.extra_fields),
                input.delivery_policy,
            ),
        )
        .await
        .map_err(core_error_from_api)
    }
}

fn ordinary_submit_result(
    channel: AuthorizedSubmitChannel,
    thing_id: Option<String>,
    accepted: crate::ordinary::Accepted,
) -> Result<SubmitResult, CoreError> {
    let dedupe = match accepted.acceptance {
        "new" => DeliveryDedupeStatus::New,
        "duplicate_pending" => DeliveryDedupeStatus::DuplicatePending,
        "duplicate_completed" => DeliveryDedupeStatus::DuplicateCompleted,
        value => {
            return Err(CoreError::internal(format!(
                "unknown ordinary acceptance: {value}"
            )));
        }
    };
    let dispatch = match accepted.dispatch_status {
        "not_attempted" => DeliveryDispatchStatus::NotAttempted,
        "attempted_accepted" => DeliveryDispatchStatus::AttemptedAccepted,
        "provider_queued" => DeliveryDispatchStatus::ProviderQueued,
        "attempted_partial_failure" => DeliveryDispatchStatus::AttemptedPartialFailure,
        value => {
            return Err(CoreError::internal(format!(
                "unknown ordinary dispatch status: {value}"
            )));
        }
    };
    let summary = DeliverySummary::new(
        channel.channel_id_text,
        accepted.op_id,
        accepted.delivery_id,
        dedupe,
        dispatch,
    );
    Ok(SubmitResult {
        channel_id: summary.channel_id.clone(),
        op_id: summary.op_id.clone(),
        entity: EntityRef::Message {
            message_id: accepted.message_id,
            thing_id,
        },
        delivery_id: summary.delivery_id.clone(),
        acceptance: summary.submit_acceptance(),
        summary,
    })
}

pub(crate) fn core_error_to_api_error(value: CoreError) -> Error {
    match value {
        CoreError::Validation { message, code } => Error::validation_code(message, code),
        CoreError::Conflict { message, code } => Error::Conflict {
            message: message.into(),
            code: code.into(),
        },
        CoreError::Auth { message, code } => Error::validation_code(message, code),
        CoreError::TooBusy => Error::TooBusy,
        CoreError::Store(message) | CoreError::Internal(message) => Error::Internal(message),
    }
}

fn core_error_from_api(error: Error) -> CoreError {
    match error {
        Error::Validation { message, code } => CoreError::Validation {
            message: message.into_owned(),
            code: code
                .as_deref()
                .and_then(stable_error_code)
                .unwrap_or("validation_failed"),
        },
        Error::Conflict { message, code } => CoreError::conflict(
            message.into_owned(),
            stable_error_code(code.as_ref()).unwrap_or("request_conflict"),
        ),
        Error::StoreError(crate::storage::StoreError::ChannelNotFound)
        | Error::StoreError(crate::storage::StoreError::ChannelPasswordMismatch) => {
            CoreError::auth("channel not authorized", "channel_not_authorized")
        }
        Error::StoreError(crate::storage::StoreError::PasswordKdfBusy) | Error::TooBusy => {
            CoreError::TooBusy
        }
        Error::StoreError(err) => CoreError::Store(err.to_string()),
        Error::Internal(message) => CoreError::Internal(message),
        Error::Unauthorized => CoreError::auth("authentication failed", "authentication_failed"),
        Error::RateLimited => CoreError::internal("request rate limited"),
        Error::Upstream { message, .. } => CoreError::internal(message),
    }
}

fn stable_error_code(code: &str) -> Option<&'static str> {
    match code {
        "authorized_channel_context_mismatch" => Some("authorized_channel_context_mismatch"),
        "submit_auth_channel_mismatch" => Some("submit_auth_channel_mismatch"),
        "authentication_failed" => Some("authentication_failed"),
        "channel_not_authorized" => Some("channel_not_authorized"),
        "op_id_not_allowed" => Some("op_id_not_allowed"),
        "op_id_payload_conflict" => Some("op_id_payload_conflict"),
        "op_id_scope_conflict" => Some("op_id_scope_conflict"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreError;

    fn ordinary_result(acceptance: &'static str, dispatch_status: &'static str) -> SubmitResult {
        ordinary_submit_result(
            AuthorizedSubmitChannel {
                channel_id: [7; 16],
                channel_id_text: crate::value::ChannelId::from([7; 16]).to_string(),
            },
            None,
            crate::ordinary::Accepted {
                delivery_id: "accepted-delivery".into(),
                message_id: "accepted-message".into(),
                op_id: "accepted-op".into(),
                acceptance,
                dispatch_status,
            },
        )
        .unwrap()
    }

    #[test]
    fn accepted_without_targets_stays_a_successful_identity_ack_with_failed_dispatch() {
        let result = ordinary_result("new", "not_attempted");
        assert_eq!(
            result.summary.dispatch_status,
            DeliveryDispatchStatus::NotAttempted
        );
        assert_eq!(
            crate::delivery_core::submit::sender_status_from_dispatch(
                result.summary.dispatch_status
            ),
            crate::storage::SenderSubmitStatusKind::Failed
        );
        let wire = serde_json::to_value(
            crate::api::handlers::send_ack::SendAck::from_submit_result(result).unwrap(),
        )
        .unwrap();
        assert_eq!(wire["op_id"], "accepted-op");
        assert_eq!(wire["message_id"], "accepted-message");
        assert!(wire.get("dispatch_status").is_none());
        assert!(wire.get("status").is_none());
    }

    #[test]
    fn completed_replay_keeps_the_committed_summary_instead_of_inventing_queue_work() {
        let result = ordinary_result("duplicate_completed", "attempted_accepted");
        assert_eq!(
            result.acceptance,
            crate::delivery_core::response::SubmitAcceptance::DuplicateCompleted
        );
        assert_eq!(
            result.summary.dispatch_status,
            DeliveryDispatchStatus::AttemptedAccepted
        );
        assert_eq!(
            crate::delivery_core::submit::sender_status_from_dispatch(
                result.summary.dispatch_status
            ),
            crate::storage::SenderSubmitStatusKind::Sent
        );
        let result = ordinary_result("duplicate_completed", "attempted_partial_failure");
        assert_eq!(
            result.summary.dispatch_status,
            DeliveryDispatchStatus::AttemptedPartialFailure
        );
        assert!(result.summary.partial_failure);
    }

    #[test]
    fn password_kdf_overload_survives_the_delivery_core_adapter_round_trip() {
        let core = core_error_from_api(Error::StoreError(StoreError::PasswordKdfBusy));
        assert!(matches!(core, CoreError::TooBusy));
        assert!(matches!(core_error_to_api_error(core), Error::TooBusy));
    }

    #[test]
    fn direct_store_conversion_preserves_password_kdf_overload() {
        assert!(matches!(
            CoreError::from(StoreError::PasswordKdfBusy),
            CoreError::TooBusy
        ));
    }

    #[test]
    fn ordinary_scope_conflict_survives_the_storage_adapter() {
        let core = CoreError::from(StoreError::OperationScopeConflict);
        assert!(
            matches!(core_error_to_api_error(core), Error::Conflict { code, .. }
            if code == "op_id_scope_conflict")
        );
    }

    #[test]
    fn native_route_capacity_conflict_keeps_its_http_status_and_code() {
        use axum::response::IntoResponse;
        let error = Error::StoreError(StoreError::Ordinary(
            crate::ordinary::KernelError::Control {
                status: 409,
                code: "route_transition_pending_capacity_exceeded",
                message: "pending deliveries exceed private route capacity".into(),
            },
        ));
        assert_eq!(
            error.into_response().status(),
            axum::http::StatusCode::CONFLICT
        );
        let core = CoreError::from(StoreError::Ordinary(
            crate::ordinary::KernelError::Control {
                status: 409,
                code: "route_transition_pending_capacity_exceeded",
                message: "pending deliveries exceed private route capacity".into(),
            },
        ));
        assert!(
            matches!(core_error_to_api_error(core), Error::Conflict { code, .. }
            if code == "route_transition_pending_capacity_exceeded")
        );
    }
}
