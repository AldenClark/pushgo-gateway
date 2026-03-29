use axum::extract::State;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    private::protocol::{
        PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope as ProviderPullEnvelope,
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub delivery_id: String,
}

#[derive(Debug, Serialize)]
pub struct PullItem {
    pub delivery_id: String,
    pub payload: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct PullResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<PullItem>,
}

pub(crate) async fn messages_pull(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<PullRequest>,
) -> HttpResult {
    let delivery_id = payload.delivery_id.trim();
    if delivery_id.is_empty() {
        return Err(Error::validation("delivery_id is required"));
    }
    let now = chrono::Utc::now().timestamp();
    let item = state.store.pull_provider_item(delivery_id, now).await?;
    let Some(item) = item else {
        return Ok(crate::api::ok(PullResponse { item: None }));
    };
    let envelope = match postcard::from_bytes::<ProviderPullEnvelope>(&item.payload) {
        Ok(v) => v,
        Err(_) => return Ok(crate::api::ok(PullResponse { item: None })),
    };
    if envelope.payload_version != PRIVATE_PAYLOAD_VERSION_V1 {
        return Ok(crate::api::ok(PullResponse { item: None }));
    }
    Ok(crate::api::ok(PullResponse {
        item: Some(PullItem {
            delivery_id: item.delivery_id,
            payload: envelope.data,
        }),
    }))
}
