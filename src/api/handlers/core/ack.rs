use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    routing::derive_private_device_id,
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
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    let delivery_id = payload.delivery_id.trim();
    if delivery_id.is_empty() {
        return Err(Error::validation("delivery_id is required"));
    }
    let device_id = derive_private_device_id(device_key);
    let now = chrono::Utc::now().timestamp_millis();
    let removed = state
        .store
        .ack_provider_item(device_id, delivery_id, now)
        .await?
        .is_some();
    Ok(crate::api::ok(AckResponse { removed }))
}
