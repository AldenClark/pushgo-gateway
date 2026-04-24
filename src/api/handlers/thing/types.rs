use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::api::{deserialize_empty_as_none, deserialize_unix_ts_millis_lenient};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ThingLocation {
    #[serde(rename = "type")]
    pub(super) location_type: String,
    pub(super) value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ThingProfile {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) primary_image: Option<String>,
    #[serde(default)]
    pub(super) images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) created_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) state: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) deleted_at: Option<i64>,
    #[serde(default)]
    pub(super) external_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) location: Option<ThingLocation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ThingCommonFields {
    pub(super) channel_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) op_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ThingMutablePayloadFields {
    pub(super) title: Option<String>,
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(super) external_ids: JsonMap<String, JsonValue>,
    pub(super) location_type: Option<String>,
    pub(super) location_value: Option<String>,
    #[serde(default)]
    pub(super) primary_image: Option<String>,
    #[serde(default)]
    pub(super) images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) ciphertext: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) observed_at: Option<i64>,
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
pub(crate) struct ThingCreateRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) created_at: Option<i64>,
    #[serde(flatten)]
    pub(super) payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingUpdateRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(flatten)]
    pub(super) payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingArchiveRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(flatten)]
    pub(super) payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingDeleteRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) deleted_at: Option<i64>,
    #[serde(flatten)]
    pub(super) payload: ThingMutablePayloadFields,
}

#[derive(Debug)]
pub(super) struct ThingPayloadFields {
    pub(super) created_at: Option<i64>,
    pub(super) deleted_at: Option<i64>,
    pub(super) mutable: ThingMutablePayloadFields,
}

#[derive(Debug, Serialize)]
pub(crate) struct ThingSummary {
    pub(super) channel_id: String,
    pub(super) op_id: String,
    pub(super) thing_id: String,
    pub(super) accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ThingRouteAction {
    Create,
    Update,
    Archive,
    Delete,
}
