use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::api::Error;
use crate::delivery_core::domain::{
    event::{EventCloseCommand, EventCommand, EventCreateCommand, EventPatch, EventUpdateCommand},
    thing::{
        ThingArchiveCommand, ThingCommand, ThingCreateCommand, ThingDeleteCommand, ThingPatch,
        ThingUpdateCommand,
    },
};

const MQTT_MODEL_MESSAGE: &str = "message";
const MQTT_MODEL_EVENT: &str = "event";
const MQTT_MODEL_THING: &str = "thing";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MqttPublishEnvelope {
    #[serde(rename = "type")]
    pub model_type: String,
    #[serde(default)]
    pub action: Option<String>,
    pub data: JsonValue,
}

impl MqttPublishEnvelope {
    pub(crate) fn decode(payload: &[u8]) -> Result<MqttPublishCommand, Error> {
        let envelope: Self = serde_json::from_slice(payload).map_err(|_| {
            Error::validation_code("invalid MQTT publish payload", "payload_invalid")
        })?;
        match envelope.model_type.trim() {
            MQTT_MODEL_MESSAGE => {
                let data = deserialize_mqtt_data(envelope.data)?;
                Ok(MqttPublishCommand::Message(data))
            }
            MQTT_MODEL_EVENT => {
                let action = required_mqtt_action(envelope.action.as_deref())?;
                let command = decode_event_command(action, envelope.data)?;
                Ok(MqttPublishCommand::Event(command))
            }
            MQTT_MODEL_THING => {
                let action = required_mqtt_action(envelope.action.as_deref())?;
                let command = decode_thing_command(action, envelope.data)?;
                Ok(MqttPublishCommand::Thing(command))
            }
            _ => Err(Error::validation_code(
                "MQTT publish type must be message, event, or thing",
                "mqtt_model_not_supported",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum MqttPublishCommand {
    Message(MqttMessagePublish),
    Event(EventCommand<EventPatch>),
    Thing(ThingCommand<ThingPatch>),
}

impl MqttPublishCommand {
    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            Self::Message(payload) => payload.op_id.as_deref(),
            Self::Event(command) => command.op_id(),
            Self::Thing(command) => command.op_id(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MqttMessagePublish {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    pub ttl: Option<i64>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub images: Vec<String>,
    #[serde(default)]
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub op_id: Option<String>,
    #[serde(default)]
    pub thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    pub occurred_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttEventPatchFields {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    attrs: Option<JsonMap<String, JsonValue>>,
    #[serde(default, deserialize_with = "deserialize_optional_metadata_map")]
    metadata: Option<JsonMap<String, JsonValue>>,
}

impl MqttEventPatchFields {
    fn into_patch(self) -> EventPatch {
        EventPatch {
            title: self.title,
            description: self.description,
            status: self.status,
            message: self.message,
            severity: self.severity,
            tags: self.tags,
            images: self.images,
            ciphertext: self.ciphertext,
            attrs: self.attrs,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttEventCreatePublish {
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    started_at: Option<i64>,
    #[serde(flatten)]
    patch: MqttEventPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttEventUpdatePublish {
    #[serde(default)]
    op_id: Option<String>,
    event_id: String,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(flatten)]
    patch: MqttEventPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttEventClosePublish {
    #[serde(default)]
    op_id: Option<String>,
    event_id: String,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    ended_at: Option<i64>,
    #[serde(flatten)]
    patch: MqttEventPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttThingPatchFields {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    external_ids: Option<JsonMap<String, JsonValue>>,
    #[serde(default)]
    location_type: Option<String>,
    #[serde(default)]
    location_value: Option<String>,
    #[serde(default)]
    primary_image: Option<String>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    observed_at: Option<i64>,
    #[serde(default)]
    attrs: Option<JsonMap<String, JsonValue>>,
    #[serde(default, deserialize_with = "deserialize_optional_metadata_map")]
    metadata: Option<JsonMap<String, JsonValue>>,
}

impl MqttThingPatchFields {
    fn into_patch(self) -> ThingPatch {
        ThingPatch {
            title: self.title,
            description: self.description,
            tags: self.tags,
            external_ids: self.external_ids,
            location_type: self.location_type,
            location_value: self.location_value,
            primary_image: self.primary_image,
            images: self.images,
            ciphertext: self.ciphertext,
            observed_at: self.observed_at,
            attrs: self.attrs,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttThingCreatePublish {
    #[serde(default)]
    op_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    created_at: Option<i64>,
    #[serde(flatten)]
    patch: MqttThingPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttThingUpdatePublish {
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(flatten)]
    patch: MqttThingPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttThingArchivePublish {
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(flatten)]
    patch: MqttThingPatchFields,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttThingDeletePublish {
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    deleted_at: Option<i64>,
    #[serde(flatten)]
    patch: MqttThingPatchFields,
}

fn required_mqtt_action(action: Option<&str>) -> Result<&str, Error> {
    let Some(action) = action.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(Error::validation_code(
            "MQTT publish action is required for event and thing payloads",
            "mqtt_action_required",
        ));
    };
    Ok(action)
}

fn deserialize_mqtt_data<T: for<'de> Deserialize<'de>>(value: JsonValue) -> Result<T, Error> {
    serde_json::from_value(value)
        .map_err(|_| Error::validation_code("invalid MQTT publish payload", "payload_invalid"))
}

fn decode_event_command(action: &str, data: JsonValue) -> Result<EventCommand<EventPatch>, Error> {
    match action {
        "create" => {
            let data: MqttEventCreatePublish = deserialize_mqtt_data(data)?;
            Ok(EventCommand::Create(EventCreateCommand {
                op_id: data.op_id,
                thing_id: data.thing_id,
                event_time: data.event_time,
                started_at: data.started_at,
                patch: data.patch.into_patch(),
            }))
        }
        "update" => {
            let data: MqttEventUpdatePublish = deserialize_mqtt_data(data)?;
            Ok(EventCommand::Update(EventUpdateCommand {
                op_id: data.op_id,
                event_id: data.event_id,
                thing_id: data.thing_id,
                event_time: data.event_time,
                patch: data.patch.into_patch(),
            }))
        }
        "close" => {
            let data: MqttEventClosePublish = deserialize_mqtt_data(data)?;
            Ok(EventCommand::Close(EventCloseCommand {
                op_id: data.op_id,
                event_id: data.event_id,
                thing_id: data.thing_id,
                event_time: data.event_time,
                ended_at: data.ended_at,
                patch: data.patch.into_patch(),
            }))
        }
        _ => Err(Error::validation_code(
            "MQTT event action must be create, update, or close",
            "mqtt_action_not_supported",
        )),
    }
}

fn decode_thing_command(action: &str, data: JsonValue) -> Result<ThingCommand<ThingPatch>, Error> {
    match action {
        "create" => {
            let data: MqttThingCreatePublish = deserialize_mqtt_data(data)?;
            Ok(ThingCommand::Create(ThingCreateCommand {
                op_id: data.op_id,
                created_at: data.created_at,
                patch: data.patch.into_patch(),
            }))
        }
        "update" => {
            let data: MqttThingUpdatePublish = deserialize_mqtt_data(data)?;
            Ok(ThingCommand::Update(ThingUpdateCommand {
                op_id: data.op_id,
                thing_id: data.thing_id,
                patch: data.patch.into_patch(),
            }))
        }
        "archive" => {
            let data: MqttThingArchivePublish = deserialize_mqtt_data(data)?;
            Ok(ThingCommand::Archive(ThingArchiveCommand {
                op_id: data.op_id,
                thing_id: data.thing_id,
                patch: data.patch.into_patch(),
            }))
        }
        "delete" => {
            let data: MqttThingDeletePublish = deserialize_mqtt_data(data)?;
            Ok(ThingCommand::Delete(ThingDeleteCommand {
                op_id: data.op_id,
                thing_id: data.thing_id,
                deleted_at: data.deleted_at,
                patch: data.patch.into_patch(),
            }))
        }
        _ => Err(Error::validation_code(
            "MQTT thing action must be create, update, archive, or delete",
            "mqtt_action_not_supported",
        )),
    }
}

fn deserialize_optional_metadata_map<'de, D>(
    deserializer: D,
) -> Result<Option<JsonMap<String, JsonValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<JsonValue>::deserialize(deserializer)?;
    raw.map(crate::value::MetadataEntries::parse_value)
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MqttDeliveryEnvelope {
    pub schema: &'static str,
    #[serde(rename = "type")]
    pub model_type: String,
    pub delivery_id: String,
    pub channel_id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
}

impl MqttDeliveryEnvelope {
    pub(crate) fn from_private_payload(delivery_id: String, payload: &[u8]) -> Result<Self, Error> {
        let envelope =
            crate::private::protocol::PrivatePayloadEnvelope::decode_postcard(payload)
                .ok_or_else(|| Error::Internal("failed to decode private payload".to_string()))?;
        if !envelope.is_supported_version() {
            return Err(Error::Internal(
                "unsupported private payload version".to_string(),
            ));
        }
        let channel_id = envelope
            .channel_id()
            .map(|channel_id| channel_id.to_string())
            .ok_or_else(|| Error::Internal("private payload missing channel_id".to_string()))?;
        let data = envelope.data;
        let entity_type = data
            .get("entity_type")
            .map(String::as_str)
            .unwrap_or("message")
            .trim();
        Ok(Self {
            schema: "pushgo.mqtt.delivery.v1",
            model_type: entity_type.to_string(),
            delivery_id,
            channel_id,
            data: mqtt_delivery_data(data),
        })
    }
}

fn mqtt_delivery_data(
    data: hashbrown::HashMap<String, String>,
) -> serde_json::Map<String, serde_json::Value> {
    data.into_iter()
        .map(|(key, value)| {
            let json_value = match key.as_str() {
                "images" | "tags" | "metadata" | "attrs" | "external_ids" => {
                    serde_json::from_str(&value)
                        .unwrap_or_else(|_| serde_json::Value::String(value.clone()))
                }
                "occurred_at" | "ingested_at" | "sent_at" | "ttl" | "event_time"
                | "observed_at" | "started_at" | "ended_at" | "created_at" | "deleted_at" => value
                    .parse::<i64>()
                    .map(|number| serde_json::Value::Number(number.into()))
                    .unwrap_or_else(|_| serde_json::Value::String(value.clone())),
                _ => serde_json::Value::String(value.clone()),
            };
            (key, json_value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use super::{MqttDeliveryEnvelope, MqttPublishCommand, MqttPublishEnvelope};
    use crate::private::protocol::{PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope};

    #[test]
    fn decodes_message_publish_envelope() {
        let payload = br#"{"type":"message","data":{"title":"Hello","thing_id":"thing-1"}}"#;
        let MqttPublishCommand::Message(message) =
            MqttPublishEnvelope::decode(payload).expect("message envelope should decode")
        else {
            panic!("expected message command");
        };
        assert_eq!(message.title, "Hello");
        assert_eq!(message.thing_id.as_deref(), Some("thing-1"));
    }

    #[test]
    fn message_publish_normalizes_time_fields_to_millis() {
        let payload = br#"{"type":"message","data":{"title":"Hello","ttl":1710000000,"occurred_at":"1710000001"}}"#;
        let MqttPublishCommand::Message(message) =
            MqttPublishEnvelope::decode(payload).expect("message envelope should decode")
        else {
            panic!("expected message command");
        };
        assert_eq!(message.ttl, Some(1_710_000_000_000));
        assert_eq!(message.occurred_at, Some(1_710_000_001_000));
    }

    #[test]
    fn decodes_event_publish_envelope() {
        let payload = br#"{"type":"event","action":"create","data":{"op_id":"op-1","thing_id":"thing-1","event_time":1710000000,"title":"Event","description":"  keep  ","images":["a","a"]}}"#;
        let MqttPublishCommand::Event(command) =
            MqttPublishEnvelope::decode(payload).expect("event envelope should decode")
        else {
            panic!("expected event command");
        };
        assert_eq!(command.op_id(), Some("op-1"));
        assert_eq!(command.thing_id(), Some("thing-1"));
        assert_eq!(command.event_time(), Some(1_710_000_000_000));
    }

    #[test]
    fn decodes_thing_publish_envelope() {
        let payload = br#"{"type":"thing","action":"update","data":{"op_id":"op-1","thing_id":"thing-1","observed_at":"1710000001","primary_image":"  https://example.com/a.png  "}}"#;
        let MqttPublishCommand::Thing(command) =
            MqttPublishEnvelope::decode(payload).expect("thing envelope should decode")
        else {
            panic!("expected thing command");
        };
        assert_eq!(command.op_id(), Some("op-1"));
        assert_eq!(command.thing_id(), Some("thing-1"));
    }

    #[test]
    fn rejects_unknown_publish_model() {
        let payload = br#"{"type":"unknown","data":{"title":"Event"}}"#;
        let err = MqttPublishEnvelope::decode(payload).expect_err("model should be unsupported");
        assert!(
            err.to_string().contains("message, event, or thing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_event_publish_without_action() {
        let payload = br#"{"type":"event","data":{"title":"Event"}}"#;
        let err = MqttPublishEnvelope::decode(payload).expect_err("action should be required");
        assert!(
            err.to_string().contains("action is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decodes_private_message_payload_for_mqtt_delivery() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("entity_type".to_string(), "message".to_string());
        data.insert("message_id".to_string(), "msg-1".to_string());
        data.insert("op_id".to_string(), "op-1".to_string());
        data.insert("title".to_string(), "Hello".to_string());
        data.insert("body".to_string(), "World".to_string());
        data.insert("tags".to_string(), r#"["mqtt"]"#.to_string());
        data.insert("metadata".to_string(), r#"{"source":"test"}"#.to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("payload should encode");

        let delivery =
            MqttDeliveryEnvelope::from_private_payload("delivery-1".to_string(), &payload)
                .expect("delivery should decode");
        assert_eq!(delivery.schema, "pushgo.mqtt.delivery.v1");
        assert_eq!(delivery.model_type, "message");
        assert_eq!(delivery.delivery_id, "delivery-1");
        assert_eq!(delivery.channel_id, "06J0FZG1Y8XGG14VTQ4Y3G10MR");
        assert_eq!(
            delivery
                .data
                .get("message_id")
                .and_then(|value| value.as_str()),
            Some("msg-1")
        );
        assert_eq!(
            delivery.data.get("tags").and_then(|value| value.as_array()),
            Some(&vec![serde_json::Value::String("mqtt".to_string())])
        );
        assert_eq!(
            delivery
                .data
                .get("metadata")
                .and_then(|value| value.as_object())
                .and_then(|metadata| metadata.get("source"))
                .and_then(|value| value.as_str()),
            Some("test")
        );
    }

    #[test]
    fn decodes_private_event_payload_for_mqtt_delivery() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("entity_type".to_string(), "event".to_string());
        data.insert("event_id".to_string(), "event-1".to_string());
        data.insert("event_time".to_string(), "1710000000000".to_string());
        data.insert("attrs".to_string(), r#"{"temperature":21}"#.to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("payload should encode");

        let delivery =
            MqttDeliveryEnvelope::from_private_payload("delivery-1".to_string(), &payload)
                .expect("event delivery should decode");
        assert_eq!(delivery.model_type, "event");
        assert_eq!(
            delivery
                .data
                .get("event_id")
                .and_then(|value| value.as_str()),
            Some("event-1")
        );
        assert_eq!(
            delivery
                .data
                .get("event_time")
                .and_then(|value| value.as_i64()),
            Some(1_710_000_000_000)
        );
        assert_eq!(
            delivery
                .data
                .get("attrs")
                .and_then(|value| value.as_object())
                .and_then(|attrs| attrs.get("temperature"))
                .and_then(|value| value.as_i64()),
            Some(21)
        );
    }

    #[test]
    fn decodes_private_thing_payload_for_mqtt_delivery() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("entity_type".to_string(), "thing".to_string());
        data.insert("thing_id".to_string(), "thing-1".to_string());
        data.insert("observed_at".to_string(), "1710000000000".to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("payload should encode");

        let delivery =
            MqttDeliveryEnvelope::from_private_payload("delivery-1".to_string(), &payload)
                .expect("thing delivery should decode");
        assert_eq!(delivery.model_type, "thing");
        assert_eq!(
            delivery
                .data
                .get("thing_id")
                .and_then(|value| value.as_str()),
            Some("thing-1")
        );
    }

    #[test]
    fn rejects_private_payload_without_channel_for_mqtt_delivery() {
        let mut data = HashMap::new();
        data.insert("entity_type".to_string(), "message".to_string());
        data.insert("message_id".to_string(), "msg-1".to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("payload should encode");

        let err = MqttDeliveryEnvelope::from_private_payload("delivery-1".to_string(), &payload)
            .expect_err("channel_id should be required");
        assert!(
            err.to_string().contains("channel_id"),
            "unexpected error: {err}"
        );
    }
}
