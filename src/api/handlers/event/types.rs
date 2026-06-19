use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::api::{deserialize_empty_as_none, deserialize_unix_ts_millis_lenient};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventCommonFields {
    pub(super) channel_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) op_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventPatchFields {
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) severity: Option<String>,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) images: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(crate) ciphertext: Option<String>,
    #[serde(default)]
    pub(crate) attrs: Option<JsonMap<String, JsonValue>>,
    #[serde(default, deserialize_with = "deserialize_optional_metadata_map")]
    pub(crate) metadata: Option<JsonMap<String, JsonValue>>,
}

fn deserialize_optional_metadata_map<'de, D>(
    deserializer: D,
) -> Result<Option<JsonMap<String, JsonValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<JsonValue>::deserialize(deserializer)?;
    raw.map(super::super::message::parse_metadata_map_value)
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCreateRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) event_time: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) started_at: Option<i64>,
    #[serde(flatten)]
    pub(super) patch: EventPatchFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventUpdateRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    pub(super) event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) event_time: Option<i64>,
    #[serde(flatten)]
    pub(super) patch: EventPatchFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCloseRequest {
    #[serde(flatten)]
    pub(super) common: EventCommonFields,
    pub(super) event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) event_time: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) ended_at: Option<i64>,
    #[serde(flatten)]
    pub(super) patch: EventPatchFields,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::EventUpdateRequest;

    #[test]
    fn event_update_preserves_missing_patch_field_presence() {
        let request: EventUpdateRequest = serde_json::from_value(json!({
            "channel_id": "channel",
            "event_id": "event-1",
            "event_time": 1_700_000_000_000i64,
            "metadata": { "source": "sensor" }
        }))
        .expect("event update should parse");

        assert!(request.patch.images.is_none());
        assert!(request.patch.attrs.is_none());
        assert_eq!(
            request
                .patch
                .metadata
                .as_ref()
                .and_then(|value| value.get("source"))
                .and_then(|value| value.as_str()),
            Some("sensor")
        );
    }
}
