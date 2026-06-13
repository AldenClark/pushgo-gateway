use serde::{Deserialize, Serialize};

use crate::api::Error;

const MQTT_MODEL_MESSAGE: &str = "message";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MqttPublishEnvelope {
    #[serde(rename = "type")]
    pub model_type: String,
    pub data: MqttMessagePublish,
}

impl MqttPublishEnvelope {
    pub(crate) fn decode(payload: &[u8]) -> Result<MqttMessagePublish, Error> {
        let envelope: Self = serde_json::from_slice(payload).map_err(|_| {
            Error::validation_code("invalid MQTT publish payload", "payload_invalid")
        })?;
        if envelope.model_type.trim() != MQTT_MODEL_MESSAGE {
            return Err(Error::validation_code(
                "MQTT publish currently supports message payloads only",
                "mqtt_model_not_supported",
            ));
        }
        Ok(envelope.data)
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
    #[serde(default)]
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
    #[serde(default)]
    pub occurred_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MqttDeliveryEnvelope {
    pub schema: &'static str,
    #[serde(rename = "type")]
    pub model_type: &'static str,
    pub delivery_id: String,
    pub channel_id: String,
    pub data: MqttMessageDelivery,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MqttMessageDelivery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
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
        if entity_type != "message" {
            return Err(Error::validation_code(
                "MQTT downlink supports message payloads only",
                "mqtt_message_model_required",
            ));
        }
        Ok(Self {
            schema: "pushgo.mqtt.delivery.v1",
            model_type: MQTT_MODEL_MESSAGE,
            delivery_id,
            channel_id,
            data: MqttMessageDelivery {
                message_id: data.get("message_id").cloned(),
                op_id: data.get("op_id").cloned(),
                occurred_at: data.get("occurred_at").and_then(|raw| raw.parse().ok()),
                title: data.get("title").cloned(),
                body: data.get("body").cloned(),
                severity: data.get("severity").cloned(),
                ttl: data.get("ttl").and_then(|raw| raw.parse().ok()),
                url: data.get("url").cloned(),
                images: data
                    .get("images")
                    .and_then(|raw| serde_json::from_str(raw).ok())
                    .unwrap_or_default(),
                ciphertext: data.get("ciphertext").cloned(),
                tags: data
                    .get("tags")
                    .and_then(|raw| serde_json::from_str(raw).ok())
                    .unwrap_or_default(),
                metadata: data
                    .get("metadata")
                    .and_then(|raw| serde_json::from_str(raw).ok())
                    .unwrap_or_default(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use super::{MqttDeliveryEnvelope, MqttPublishEnvelope};
    use crate::private::protocol::{PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope};

    #[test]
    fn decodes_message_publish_envelope() {
        let payload = br#"{"type":"message","data":{"title":"Hello","thing_id":"thing-1"}}"#;
        let message = MqttPublishEnvelope::decode(payload).expect("message envelope should decode");
        assert_eq!(message.title, "Hello");
        assert_eq!(message.thing_id.as_deref(), Some("thing-1"));
    }

    #[test]
    fn rejects_unsupported_publish_model() {
        let payload = br#"{"type":"event","data":{"title":"Event"}}"#;
        let err = MqttPublishEnvelope::decode(payload).expect_err("event should be unsupported");
        assert!(
            err.to_string().contains("message payloads only"),
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
        assert_eq!(delivery.data.message_id.as_deref(), Some("msg-1"));
        assert_eq!(delivery.data.tags, vec!["mqtt"]);
        assert_eq!(
            delivery
                .data
                .metadata
                .get("source")
                .and_then(|value| value.as_str()),
            Some("test")
        );
    }

    #[test]
    fn rejects_non_message_private_payload_for_mqtt_delivery() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("entity_type".to_string(), "event".to_string());
        data.insert("event_id".to_string(), "event-1".to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("payload should encode");

        let err = MqttDeliveryEnvelope::from_private_payload("delivery-1".to_string(), &payload)
            .expect_err("event payload should not be exposed over MQTT message topic");
        assert!(
            err.to_string().contains("message payloads only"),
            "unexpected error: {err}"
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
