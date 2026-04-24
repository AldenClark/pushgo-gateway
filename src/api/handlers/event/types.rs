use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::api::{deserialize_empty_as_none, deserialize_unix_ts_millis_lenient};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct EventProfile {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) message: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) severity: Option<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
    #[serde(default)]
    pub(super) images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) started_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) ended_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventCommonFields {
    pub(super) channel_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) op_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventPayloadFields {
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) event_time: Option<i64>,
    pub(super) title: Option<String>,
    pub(super) description: Option<String>,
    pub(super) status: Option<String>,
    pub(super) message: Option<String>,
    pub(super) severity: Option<String>,
    #[serde(default)]
    pub(super) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(super) images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) ciphertext: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) started_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) ended_at: Option<i64>,
    #[serde(default)]
    pub(super) attrs: JsonMap<String, JsonValue>,
    #[serde(
        default,
        deserialize_with = "super::super::message::deserialize_metadata_map"
    )]
    pub(super) metadata: JsonMap<String, JsonValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCreateRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(flatten)]
    pub(super) payload: EventPayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventUpdateRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    pub(super) event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(flatten)]
    pub(super) payload: EventPayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCloseRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    pub(super) event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(flatten)]
    pub(super) payload: EventPayloadFields,
}

#[derive(Debug, Serialize)]
pub(crate) struct EventSummary {
    pub(super) channel_id: String,
    pub(super) op_id: String,
    pub(super) event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) thing_id: Option<String>,
    pub(super) accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EventRouteAction {
    Create,
    Update,
    Close,
}

impl EventRouteAction {
    pub(super) fn requested_state(self) -> crate::storage::EventState {
        self.target_state()
    }
}
