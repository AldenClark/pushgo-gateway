use axum::extract::State;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    private::protocol::PrivatePayloadEnvelope as ProviderPullEnvelope,
    routing::derive_private_device_id,
    value::DeviceKeyRef,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PullRequest {
    pub device_key: String,
    pub delivery_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PullItem {
    pub delivery_id: String,
    pub payload: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PullResponse {
    pub items: Vec<PullItem>,
}

pub(crate) async fn messages_pull(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<PullRequest>,
) -> HttpResult {
    let span = tracing::info_span!(
        "gateway.messages.pull",
        has_delivery_id = payload.delivery_id.is_some()
    );
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        let device_id = derive_private_device_id(device_key.as_str());
        let now = chrono::Utc::now().timestamp_millis();

        let raw_items = if let Some(delivery_id) = payload.delivery_id.as_deref() {
            let delivery_id = delivery_id.trim();
            if delivery_id.is_empty() {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "provider.pull_rejected",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    reason = %("delivery_id_required")
                );
                return Err(Error::validation_code(
                    "delivery_id must not be empty",
                    "delivery_id_required",
                ));
            }
            match state
                .store
                .pull_provider_item(device_id, delivery_id, now)
                .await?
            {
                Some(item) => vec![item],
                None => Vec::new(),
            }
        } else {
            state.store.pull_provider_items(device_id, now, 512).await?
        };

        let mut items = Vec::with_capacity(raw_items.len());
        let mut dropped_decode = 0u64;
        let mut dropped_version = 0u64;
        for item in raw_items {
            let Some(envelope) = ProviderPullEnvelope::decode_postcard(item.payload.as_ref())
            else {
                dropped_decode += 1;
                continue;
            };
            if !envelope.is_supported_version() {
                dropped_version += 1;
                continue;
            }
            items.push(PullItem {
                delivery_id: item.delivery_id,
                payload: envelope.data,
            });
        }

        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pull_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            items_returned = (items.len() as u64),
            dropped_decode = (dropped_decode),
            dropped_version = (dropped_version)
        );

        Ok(crate::api::ok(PullResponse { items }))
    }
    .instrument(span)
    .await
}
