use axum::extract::State;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

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
    let device_key = DeviceKeyRef::parse(&payload.device_key)?;
    let device_id = derive_private_device_id(device_key.as_str());
    let now = chrono::Utc::now().timestamp_millis();

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
    for item in raw_items {
        let Some(envelope) = ProviderPullEnvelope::decode_postcard(&item.payload) else {
            continue;
        };
        if !envelope.is_supported_version() {
            continue;
        }
        items.push(PullItem {
            delivery_id: item.delivery_id,
            payload: envelope.data,
        });
    }

    Ok(crate::api::ok(PullResponse { items }))
}
