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

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PullItem {
    pub delivery_id: String,
    pub payload: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub(super) struct LegacyPullResponse {
    pub items: Vec<PullItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct V2PullResponse {
    pub items: Vec<PullItem>,
    #[serde(default)]
    pub has_more: bool,
}

const V2_PULL_LIMIT: usize = 200;
const LEGACY_PULL_LIMIT: usize = 512;

pub(crate) async fn messages_pull(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<LegacyPullRequest>,
) -> HttpResult {
    let span = tracing::info_span!(
        "gateway.messages.pull",
        has_delivery_id = payload.delivery_id.is_some()
    );
    async move {
        let page = pull_sources(
            &state,
            &payload.device_key,
            payload.delivery_id.as_deref(),
            true,
        )
        .await?;
        Ok(crate::api::ok(LegacyPullResponse { items: page.items }))
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
        Ok(crate::api::ok(
            pull_sources(
                &state,
                &payload.device_key,
                payload.delivery_id.as_deref(),
                false,
            )
            .await?,
        ))
    }
    .instrument(span)
    .await
}

/// Ordinary records have exactly one source. The remaining queue is read only
/// for other model types; a pre-cutover ordinary record is not a fallback.
async fn pull_sources(
    state: &AppState,
    raw_device: &str,
    raw_delivery: Option<&str>,
    legacy: bool,
) -> Result<V2PullResponse, Error> {
    let device = DeviceKeyRef::parse(raw_device)?;
    let delivery = raw_delivery.map(str::trim);
    if delivery.is_some_and(str::is_empty) {
        return Err(Error::validation_code(
            "delivery_id must not be empty",
            "delivery_id_required",
        ));
    }
    let ordinary = state
        .store
        .ordinary_handle()
        .ok_or_else(|| Error::Internal("ordinary authority is not initialized".into()))?;
    let value = if legacy {
        ordinary.pull_legacy(device.as_str(), delivery).await?
    } else {
        ordinary.pull(device.as_str(), delivery).await?
    };
    let mut page: V2PullResponse = serde_json::from_value(value)
        .map_err(|error| Error::Internal(format!("ordinary Pull result: {error}")))?;
    let limit = if legacy {
        LEGACY_PULL_LIMIT
    } else {
        V2_PULL_LIMIT
    };
    if page.items.len() > limit {
        return Err(Error::Internal(
            "ordinary Pull exceeded its bounded page".into(),
        ));
    }
    if delivery.is_some() && !page.items.is_empty() {
        return Ok(page);
    }
    let remaining = limit - page.items.len();
    let device_id = derive_private_device_id(device.as_str());
    let now = chrono::Utc::now().timestamp_millis();
    let candidates = if let Some(id) = delivery {
        state
            .store
            .peek_provider_candidate(device_id, id, now)
            .await?
            .into_iter()
            .collect()
    } else {
        state
            .store
            .peek_provider_candidates(device_id, now, remaining + 1)
            .await?
    };
    let scanned = candidates.len();
    let mut invalid = Vec::new();
    let mut retained_items = Vec::new();
    for candidate in candidates {
        let Some(envelope) = ProviderPullEnvelope::decode_postcard(candidate.payload.as_ref())
        else {
            invalid.push(candidate);
            continue;
        };
        if !envelope.is_supported_version() {
            invalid.push(candidate);
            continue;
        }
        // Do not acknowledge, delete or return any legacy ordinary body.
        if !is_retained_model(&envelope.data) {
            continue;
        }
        if envelope.data.get("delivery_id").map(String::as_str)
            != Some(candidate.delivery_id.as_str())
        {
            invalid.push(candidate);
            continue;
        }
        if retained_items.len() < remaining {
            retained_items.push(PullItem {
                delivery_id: candidate.delivery_id,
                payload: envelope.data,
            });
        } else {
            page.has_more = true;
        }
    }
    state
        .store
        .discard_invalid_provider_candidates(device_id, &invalid, now)
        .await?;
    if legacy && !retained_items.is_empty() {
        let ids = retained_items
            .iter()
            .map(|item| item.delivery_id.clone())
            .collect::<Vec<_>>();
        let removed = state.store.ack_provider_items(device_id, &ids, now).await?;
        // Return the committed ACK result, including its current authorization
        // decision, rather than the earlier read if a route changed meanwhile.
        retained_items = removed
            .into_iter()
            .filter_map(|item| {
                let envelope = ProviderPullEnvelope::decode_postcard(item.payload.as_ref())?;
                (envelope.is_supported_version() && is_retained_model(&envelope.data)).then_some(
                    PullItem {
                        delivery_id: item.delivery_id,
                        payload: envelope.data,
                    },
                )
            })
            .collect();
    }
    if !legacy {
        for item in &mut retained_items {
            item.payload.remove("delivery_id");
        }
    }
    page.items.extend(retained_items);
    page.has_more = delivery.is_none() && (page.has_more || scanned > remaining);
    Ok(page)
}

pub(super) fn is_retained_model(payload: &HashMap<String, String>) -> bool {
    matches!(
        payload.get("entity_type").map(String::as_str),
        Some("event" | "thing")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_queue_is_only_a_source_for_retained_nonordinary_models() {
        let mut fields = HashMap::new();
        assert!(!is_retained_model(&fields));
        for model in ["message", "", "unknown"] {
            fields.insert("entity_type".into(), model.into());
            assert!(!is_retained_model(&fields));
        }
        for model in ["event", "thing"] {
            fields.insert("entity_type".into(), model.into());
            assert!(is_retained_model(&fields));
        }
    }
}
