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
pub(crate) struct LegacyAckRequest {
    pub device_key: String,
    pub delivery_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BatchAckRequest {
    pub device_key: String,
    pub delivery_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LegacyAckResponse {
    pub removed: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchAckResponse {
    pub requested_count: usize,
    pub removed_count: usize,
}

const MAX_ACK_ITEMS: usize = 200;
const MAX_DELIVERY_ID_LEN: usize = 128;

pub(crate) async fn messages_ack(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<LegacyAckRequest>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.messages.ack");
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?.into_owned();
        let delivery_id = payload.delivery_id.trim();
        if delivery_id.is_empty() {
            return Err(Error::validation_code(
                "delivery_id must not be empty",
                "delivery_id_required",
            ));
        }
        let ids = vec![delivery_id.to_owned()];
        let ordinary = state
            .store
            .ordinary_handle()
            .ok_or_else(|| Error::Internal("ordinary authority is not initialized".into()))?;
        // Existing single-ACK accepted unknown identifiers of any length. A
        // generated ordinary ID cannot exceed the kernel's parser boundary.
        let ordinary_removed = if delivery_id.len() <= MAX_DELIVERY_ID_LEN {
            ordinary.ack(&device_key, ids.clone()).await?
        } else {
            0
        };
        let retained_removed = if ordinary_removed == ids.len() {
            0
        } else {
            ack_retained_provider_items(&state, &device_key, &ids).await?
        };
        let removed = ordinary_removed + retained_removed > 0;
        Ok(crate::api::ok(LegacyAckResponse { removed }))
    }
    .instrument(span)
    .await
}

pub(crate) async fn messages_ack_v2(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<BatchAckRequest>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.messages.ack_v2");
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?.into_owned();
        let delivery_ids = normalize_delivery_ids(payload.delivery_ids)?;
        ack_provider_items(
            &state,
            &device_key,
            delivery_ids,
            "provider.ack_v2_completed",
        )
        .await
    }
    .instrument(span)
    .await
}

async fn ack_provider_items(
    state: &AppState,
    device_key: &str,
    delivery_ids: Vec<String>,
    event: &'static str,
) -> HttpResult {
    let ordinary = state
        .store
        .ordinary_handle()
        .ok_or_else(|| Error::Internal("ordinary authority is not initialized".into()))?;
    let ordinary_removed = ordinary.ack(device_key, delivery_ids.clone()).await?;
    let retained_removed = if ordinary_removed == delivery_ids.len() {
        0
    } else {
        ack_retained_provider_items(state, device_key, &delivery_ids).await?
    };
    let removed_count = ordinary_removed + retained_removed;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = event,
        device_key = %(crate::util::redact_text(device_key)),
        requested = (delivery_ids.len() as u64),
        removed = (removed_count as u64)
    );
    Ok(crate::api::ok(BatchAckResponse {
        requested_count: delivery_ids.len(),
        removed_count,
    }))
}

async fn ack_retained_provider_items(
    state: &AppState,
    device_key: &str,
    delivery_ids: &[String],
) -> Result<usize, Error> {
    let device_id = derive_private_device_id(device_key);
    let now = chrono::Utc::now().timestamp_millis();
    let mut retained = Vec::with_capacity(delivery_ids.len());
    for id in delivery_ids {
        let Some(candidate) = state
            .store
            .peek_provider_candidate(device_id, id, now)
            .await?
        else {
            continue;
        };
        let Some(envelope) = crate::private::protocol::PrivatePayloadEnvelope::decode_postcard(
            candidate.payload.as_ref(),
        ) else {
            continue;
        };
        if envelope.is_supported_version()
            && super::pull::is_retained_model(&envelope.data)
            && envelope.data.get("delivery_id").map(String::as_str) == Some(id.as_str())
        {
            retained.push(id.clone());
        }
    }
    if retained.is_empty() {
        return Ok(0);
    }
    Ok(state
        .store
        .ack_provider_items(device_id, &retained, now)
        .await?
        .len())
}

fn normalize_delivery_ids(mut delivery_ids: Vec<String>) -> Result<Vec<String>, Error> {
    for delivery_id in &mut delivery_ids {
        *delivery_id = delivery_id.trim().to_string();
        if delivery_id.is_empty() || delivery_id.len() > MAX_DELIVERY_ID_LEN {
            return Err(Error::validation_code(
                "delivery_id must contain between 1 and 128 bytes",
                "delivery_id_invalid",
            ));
        }
    }
    delivery_ids.sort_unstable();
    delivery_ids.dedup();
    if delivery_ids.is_empty() || delivery_ids.len() > MAX_ACK_ITEMS {
        return Err(Error::validation_code(
            "delivery_ids must contain between 1 and 200 unique items",
            "delivery_ack_batch_invalid",
        ));
    }
    Ok(delivery_ids)
}

#[cfg(test)]
mod tests {
    use super::normalize_delivery_ids;

    #[test]
    fn batch_ack_limit_counts_unique_normalized_delivery_ids() {
        let duplicates = vec![" repeated ".to_string(); 201];
        assert_eq!(
            normalize_delivery_ids(duplicates).expect("one unique ID should be accepted"),
            vec!["repeated".to_string()]
        );

        let two_hundred = (0..200)
            .map(|index| format!("delivery-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            normalize_delivery_ids(two_hundred)
                .expect("200 unique IDs should be accepted")
                .len(),
            200
        );

        let two_hundred_and_one = (0..201)
            .map(|index| format!("delivery-{index}"))
            .collect::<Vec<_>>();
        assert!(normalize_delivery_ids(two_hundred_and_one).is_err());
    }
}
