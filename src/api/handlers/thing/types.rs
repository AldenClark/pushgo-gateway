use serde::{Deserialize, Deserializer, de::IgnoredAny};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::api::{deserialize_empty_as_none, deserialize_unix_ts_millis_lenient};

#[derive(Debug, Deserialize)]
pub(super) struct ThingCommonFields {
    pub(super) channel_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(super) op_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ThingPatchFields {
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) external_ids: Option<JsonMap<String, JsonValue>>,
    pub(crate) location_type: Option<String>,
    pub(crate) location_value: Option<String>,
    #[serde(default)]
    pub(crate) primary_image: Option<String>,
    #[serde(default)]
    pub(crate) images: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub(crate) ciphertext: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(crate) observed_at: Option<i64>,
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

fn reject_forbidden_thing_field<'de, D>(deserializer: D) -> Result<Option<JsonValue>, D::Error>
where
    D: Deserializer<'de>,
{
    let _ = IgnoredAny::deserialize(deserializer)?;
    Err(serde::de::Error::custom(
        "field is not allowed for this thing action",
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ThingCreateRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) created_at: Option<i64>,
    #[serde(flatten)]
    pub(super) patch: ThingPatchFields,
    #[serde(
        default,
        rename = "thing_id",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _thing_id: Option<JsonValue>,
    #[serde(
        default,
        rename = "state",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _state: Option<JsonValue>,
    #[serde(
        default,
        rename = "deleted_at",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _deleted_at: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ThingUpdateRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(flatten)]
    pub(super) patch: ThingPatchFields,
    #[serde(
        default,
        rename = "state",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _state: Option<JsonValue>,
    #[serde(
        default,
        rename = "deleted_at",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _deleted_at: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ThingArchiveRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(flatten)]
    pub(super) patch: ThingPatchFields,
    #[serde(
        default,
        rename = "state",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _state: Option<JsonValue>,
    #[serde(
        default,
        rename = "deleted_at",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _deleted_at: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ThingDeleteRequest {
    #[serde(flatten)]
    pub(super) common: ThingCommonFields,
    pub(super) thing_id: String,
    #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
    pub(super) deleted_at: Option<i64>,
    #[serde(flatten)]
    pub(super) patch: ThingPatchFields,
    #[serde(
        default,
        rename = "state",
        deserialize_with = "reject_forbidden_thing_field"
    )]
    pub(super) _state: Option<JsonValue>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::ThingUpdateRequest;

    #[test]
    fn thing_update_preserves_missing_patch_field_presence() {
        let request: ThingUpdateRequest = serde_json::from_value(json!({
            "channel_id": "channel",
            "thing_id": "thing-1",
            "observed_at": 1_700_000_000_000i64,
            "metadata": { "source": "sensor" }
        }))
        .expect("thing update should parse");

        assert!(request.patch.images.is_none());
        assert!(request.patch.attrs.is_none());
        assert!(request.patch.external_ids.is_none());
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
