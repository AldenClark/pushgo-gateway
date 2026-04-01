use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{api::deserialize_empty_as_none, app::AppState};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelSyncRequest {
    pub(super) device_key: String,
    pub(super) channels: Vec<ChannelSyncItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelSyncItem {
    pub(super) channel_id: String,
    pub(super) password: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSyncResponse {
    pub(super) total: usize,
    pub(super) success: usize,
    pub(super) failed: usize,
    pub(super) channels: Vec<ChannelSyncResult>,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSyncResult {
    pub(super) channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) channel_name: Option<String>,
    pub(super) subscribed: bool,
    pub(super) created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelSubscribeRequest {
    pub(super) device_key: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) channel_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) channel_name: Option<String>,
    pub(super) password: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSubscribeResponse {
    pub(super) channel_id: String,
    pub(super) channel_name: String,
    pub(super) created: bool,
    pub(super) subscribed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelUnsubscribeRequest {
    pub(super) device_key: String,
    pub(super) channel_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelUnsubscribeResponse {
    pub(super) channel_id: String,
    pub(super) removed: bool,
}

#[allow(dead_code)]
type _StateMarker = State<AppState>;
