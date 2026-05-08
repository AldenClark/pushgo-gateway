use axum::extract::State;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    routing::derive_private_device_id,
    value::DeviceKeyRef,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AckRequest {
    pub device_key: String,
    pub delivery_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AckResponse {
    pub removed: bool,
}

pub(crate) async fn messages_ack(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<AckRequest>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.messages.ack");
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        let delivery_id = payload.delivery_id.trim();
        if delivery_id.is_empty() {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "provider.ack_rejected",
                device_key = %(crate::util::redact_text(device_key.as_str())),
                reason = %("delivery_id_required")
            );
            return Err(Error::validation_code(
                "delivery_id is required",
                "delivery_id_required",
            ));
        }
        let device_id = derive_private_device_id(device_key.as_str());
        let now = chrono::Utc::now().timestamp_millis();
        let removed = state
            .store
            .ack_provider_item(device_id, delivery_id, now)
            .await?
            .is_some();
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.ack_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            removed = (removed)
        );
        Ok(crate::api::ok(AckResponse { removed }))
    }
    .instrument(span)
    .await
}
