use async_trait::async_trait;

use crate::{
    api::{Error, handlers::message::dispatch_entity_notification},
    app::AppState,
    delivery_core::{
        error::CoreError,
        execution::request::{
            DispatchAlert, DispatchEntityPayload, DispatchEventInput, DispatchMessageInput,
            DispatchRequest, DispatchThingInput,
        },
        response::DeliverySummary,
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

    async fn dispatch_message(
        &self,
        input: DispatchMessageInput,
    ) -> Result<DeliverySummary, CoreError> {
        let request_fingerprint = input.idempotency_fingerprint();
        let message_id = input.message_id;
        dispatch_entity_notification(
            self,
            input.authorized_channel.channel_id,
            DispatchRequest::new(
                input.op_id.unwrap_or_default(),
                Some(request_fingerprint),
                input.occurred_at.unwrap_or_default(),
                DispatchAlert::new(Some(input.title), input.body, input.severity, input.ttl),
                DispatchEntityPayload::message(message_id, input.custom_data, input.extra_fields),
                input.delivery_policy,
            ),
        )
        .await
        .map_err(core_error_from_api)
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreError;

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
}
