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
pub(crate) struct LegacyPullRequest {
    pub device_key: String,
    pub delivery_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct V2PullRequest {
    pub device_key: String,
    pub delivery_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PullItem {
    pub delivery_id: String,
    pub payload: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub(super) struct LegacyPullResponse {
    pub items: Vec<PullItem>,
}

#[derive(Debug, Serialize)]
pub(super) struct V2PullResponse {
    pub items: Vec<PullItem>,
    pub has_more: bool,
}

const V2_PULL_LIMIT: usize = 200;
const V2_PULL_SCAN_LIMIT: usize = V2_PULL_LIMIT + 1;

pub(crate) async fn messages_pull(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<LegacyPullRequest>,
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
        let raw_item_count = raw_items.len() as u64;
        for item in raw_items {
            let delivery_id = item.delivery_id;
            let payload_size = item.payload.len() as u64;
            let Some(envelope) = ProviderPullEnvelope::decode_postcard(item.payload.as_ref())
            else {
                dropped_decode += 1;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "provider.pull_item_dropped",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                    encoded_bytes = payload_size,
                    reason = %("payload_decode_failed")
                );
                continue;
            };
            if !envelope.is_supported_version() {
                dropped_version += 1;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "provider.pull_item_dropped",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                    encoded_bytes = payload_size,
                    wire_version = envelope.payload_version,
                    supported_wire_version = ProviderPullEnvelope::CURRENT_VERSION,
                    reason = %("payload_version_unsupported")
                );
                continue;
            }
            items.push(PullItem {
                delivery_id,
                payload: envelope.data,
            });
        }

        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pull_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            requested_delivery_id = payload.delivery_id.is_some(),
            raw_items = raw_item_count,
            items_returned = (items.len() as u64),
            dropped_decode = (dropped_decode),
            dropped_version = (dropped_version)
        );

        Ok(crate::api::ok(LegacyPullResponse { items }))
    }
    .instrument(span)
    .await
}

pub(crate) async fn messages_pull_v2(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V2PullRequest>,
) -> HttpResult {
    let span = tracing::info_span!(
        "gateway.messages.pull_v2",
        has_delivery_id = payload.delivery_id.is_some()
    );
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        let device_id = derive_private_device_id(device_key.as_str());
        let now = chrono::Utc::now().timestamp_millis();
        let requested_delivery_id = payload.delivery_id.is_some();
        let raw_items = if let Some(delivery_id) = payload.delivery_id.as_deref() {
            let delivery_id = delivery_id.trim();
            if delivery_id.is_empty() {
                return Err(Error::validation_code(
                    "delivery_id must not be empty",
                    "delivery_id_required",
                ));
            }
            match state
                .store
                .peek_provider_candidate(device_id, delivery_id, now)
                .await?
            {
                Some(item) => vec![item],
                None => Vec::new(),
            }
        } else {
            state
                .store
                .peek_provider_candidates(device_id, now, V2_PULL_SCAN_LIMIT)
                .await?
        };

        let raw_item_count = raw_items.len() as u64;
        let mut items = Vec::with_capacity(raw_items.len());
        let mut invalid_candidates = Vec::new();
        let mut has_unreturned_valid = false;
        for item in raw_items {
            let delivery_id = item.delivery_id.as_str();
            let Some(envelope) = ProviderPullEnvelope::decode_postcard(item.payload.as_ref())
            else {
                invalid_candidates.push(item);
                continue;
            };
            if !envelope.is_supported_version() {
                invalid_candidates.push(item);
                continue;
            }
            let mut response_payload = envelope.data;
            let embedded_delivery_id = response_payload
                .get("delivery_id")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty());
            if embedded_delivery_id != Some(delivery_id) {
                invalid_candidates.push(item);
                continue;
            }
            if items.len() < V2_PULL_LIMIT {
                response_payload.remove("delivery_id");
                items.push(PullItem {
                    delivery_id: item.delivery_id,
                    payload: response_payload,
                });
            } else {
                has_unreturned_valid = true;
            }
        }

        let discarded = state
            .store
            .discard_invalid_provider_candidates(device_id, &invalid_candidates, now)
            .await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "provider.pull_v2_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            requested_delivery_id = requested_delivery_id,
            raw_items = raw_item_count,
            items_returned = (items.len() as u64),
            discarded_invalid = (discarded as u64),
            has_more = (!requested_delivery_id
                && (has_unreturned_valid || raw_item_count >= V2_PULL_SCAN_LIMIT as u64))
        );
        let has_more = !requested_delivery_id
            && (has_unreturned_valid || raw_item_count >= V2_PULL_SCAN_LIMIT as u64);
        Ok(crate::api::ok(V2PullResponse { items, has_more }))
    }
    .instrument(span)
    .await
}
