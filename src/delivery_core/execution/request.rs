use hashbrown::HashMap;

use crate::{
    delivery_core::{payload::EntityKind, submit::AuthorizedSubmitChannel},
    domain_model::projection::DomainDeliveryPolicy,
};

pub(crate) struct DispatchEventInput {
    pub(crate) authorized_channel: AuthorizedSubmitChannel,
    pub(crate) op_id: String,
    pub(crate) occurred_at: i64,
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) custom_data: HashMap<String, String>,
    pub(crate) extra_fields: HashMap<String, String>,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
    pub(crate) event_id: String,
    pub(crate) live_activity: Option<DispatchLiveActivityUpdate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DispatchLiveActivityAction {
    Update,
    End,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DispatchLiveActivityIntent {
    pub(crate) action: DispatchLiveActivityAction,
    pub(crate) title: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) updated_at_millis: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DispatchLiveActivityUpdate {
    pub(crate) event_id: String,
    pub(crate) action: DispatchLiveActivityAction,
    pub(crate) title: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) accepted_at_millis: i64,
    pub(crate) updated_at_millis: i64,
}

pub(crate) struct DispatchThingInput {
    pub(crate) authorized_channel: AuthorizedSubmitChannel,
    pub(crate) op_id: String,
    pub(crate) occurred_at: i64,
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) custom_data: HashMap<String, String>,
    pub(crate) extra_fields: HashMap<String, String>,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
    pub(crate) thing_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DispatchAlert {
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) ttl: Option<i64>,
}

impl DispatchAlert {
    pub(crate) fn new(
        title: Option<String>,
        body: Option<String>,
        severity: Option<String>,
        ttl: Option<i64>,
    ) -> Self {
        Self {
            title,
            body,
            severity,
            ttl,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DispatchRequest {
    pub(crate) op_id: String,
    pub(crate) request_fingerprint: Option<String>,
    pub(crate) occurred_at: i64,
    pub(crate) alert: DispatchAlert,
    pub(crate) payload: DispatchEntityPayload,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
    #[serde(default)]
    pub(crate) live_activity: Option<DispatchLiveActivityUpdate>,
}

impl DispatchRequest {
    pub(crate) fn new(
        op_id: String,
        request_fingerprint: Option<String>,
        occurred_at: i64,
        alert: DispatchAlert,
        payload: DispatchEntityPayload,
        delivery_policy: DomainDeliveryPolicy,
    ) -> Self {
        Self {
            op_id,
            request_fingerprint,
            occurred_at,
            alert,
            payload,
            delivery_policy,
            live_activity: None,
        }
    }

    pub(crate) fn with_live_activity(mut self, value: Option<DispatchLiveActivityUpdate>) -> Self {
        self.live_activity = value;
        self
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum DispatchEntityPayload {
    Message {
        message_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    },
    Thing {
        thing_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    },
    Event {
        event_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    },
}

impl DispatchEntityPayload {
    pub(crate) fn message(
        message_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    ) -> Self {
        Self::Message {
            message_id,
            custom_data,
            fields,
        }
    }

    pub(crate) fn thing(
        thing_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    ) -> Self {
        Self::Thing {
            thing_id,
            custom_data,
            fields,
        }
    }

    pub(crate) fn event(
        event_id: String,
        custom_data: HashMap<String, String>,
        fields: HashMap<String, String>,
    ) -> Self {
        Self::Event {
            event_id,
            custom_data,
            fields,
        }
    }

    pub(crate) fn kind(&self) -> EntityKind {
        match self {
            Self::Message { .. } => EntityKind::Message,
            Self::Thing { .. } => EntityKind::Thing,
            Self::Event { .. } => EntityKind::Event,
        }
    }

    pub(crate) fn entity_id(&self) -> &str {
        match self {
            Self::Message { message_id, .. } => message_id,
            Self::Thing { thing_id, .. } => thing_id,
            Self::Event { event_id, .. } => event_id,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        EntityKind,
        String,
        HashMap<String, String>,
        HashMap<String, String>,
    ) {
        match self {
            Self::Message {
                message_id,
                custom_data,
                fields,
            } => {
                let mut fields = retain_allowed(fields, MESSAGE_FIELD_KEYS);
                fields.insert("message_id".to_string(), message_id.clone());
                (
                    EntityKind::Message,
                    message_id,
                    retain_allowed(custom_data, MESSAGE_CUSTOM_KEYS),
                    fields,
                )
            }
            Self::Thing {
                thing_id,
                custom_data,
                fields,
            } => {
                let mut fields = retain_allowed(fields, THING_FIELD_KEYS);
                fields.insert("thing_id".to_string(), thing_id.clone());
                (
                    EntityKind::Thing,
                    thing_id,
                    retain_allowed(custom_data, ENTITY_CUSTOM_KEYS),
                    fields,
                )
            }
            Self::Event {
                event_id,
                custom_data,
                fields,
            } => {
                let mut fields = retain_allowed(fields, EVENT_FIELD_KEYS);
                fields.insert("event_id".to_string(), event_id.clone());
                (
                    EntityKind::Event,
                    event_id,
                    retain_allowed(custom_data, ENTITY_CUSTOM_KEYS),
                    fields,
                )
            }
        }
    }
}

const MESSAGE_CUSTOM_KEYS: &[&str] = &["url", "images", "ciphertext", "metadata"];
const ENTITY_CUSTOM_KEYS: &[&str] = &["ciphertext", "metadata"];
const MESSAGE_FIELD_KEYS: &[&str] = &["message_id", "tags", "thing_id"];
const THING_FIELD_KEYS: &[&str] = &[
    "domain_action",
    "state",
    "occurred_at",
    "observed_at",
    "thing_id",
    "attrs",
    "tags",
    "images",
    "external_ids",
    "title",
    "description",
    "primary_image",
    "created_at",
    "deleted_at",
    "location_type",
    "location_value",
    "location",
];
const EVENT_FIELD_KEYS: &[&str] = &[
    "domain_action",
    "event_state",
    "event_id",
    "occurred_at",
    "event_time",
    "thing_id",
    "attrs",
    "tags",
    "images",
    "title",
    "description",
    "status",
    "message",
    "severity",
    "started_at",
    "ended_at",
];

fn retain_allowed(
    input: HashMap<String, String>,
    allowed_keys: &[&str],
) -> HashMap<String, String> {
    input
        .into_iter()
        .filter(|(key, _)| allowed_keys.contains(&key.as_str()))
        .collect()
}

#[cfg(test)]
mod lifecycle_payload_tests {
    use super::*;

    #[test]
    fn authoritative_thing_lifecycle_survives_dispatch_filtering() {
        for (action, state) in [
            ("create", "active"),
            ("update", "active"),
            ("archive", "archived"),
            ("delete", "deleted"),
        ] {
            let (_, entity_id, custom, fields) = DispatchEntityPayload::thing(
                "thing-1".to_string(),
                HashMap::from([
                    ("state".to_string(), "spoofed".to_string()),
                    ("domain_action".to_string(), "spoofed".to_string()),
                ]),
                HashMap::from([
                    ("state".to_string(), state.to_string()),
                    ("domain_action".to_string(), action.to_string()),
                    ("unrecognized".to_string(), "discard".to_string()),
                ]),
            )
            .into_parts();

            assert_eq!(entity_id, "thing-1");
            assert!(custom.is_empty());
            assert_eq!(fields.get("state").map(String::as_str), Some(state));
            assert_eq!(
                fields.get("domain_action").map(String::as_str),
                Some(action)
            );
            assert!(!fields.contains_key("unrecognized"));
        }
    }

    #[test]
    fn authoritative_event_lifecycle_survives_dispatch_filtering() {
        for (action, state) in [
            ("create", "ongoing"),
            ("update", "ongoing"),
            ("close", "closed"),
        ] {
            let (_, entity_id, custom, fields) = DispatchEntityPayload::event(
                "event-1".to_string(),
                HashMap::from([
                    ("event_state".to_string(), "spoofed".to_string()),
                    ("domain_action".to_string(), "spoofed".to_string()),
                ]),
                HashMap::from([
                    ("event_state".to_string(), state.to_string()),
                    ("domain_action".to_string(), action.to_string()),
                    ("unrecognized".to_string(), "discard".to_string()),
                ]),
            )
            .into_parts();

            assert_eq!(entity_id, "event-1");
            assert!(custom.is_empty());
            assert_eq!(fields.get("event_state").map(String::as_str), Some(state));
            assert_eq!(
                fields.get("domain_action").map(String::as_str),
                Some(action)
            );
            assert!(!fields.contains_key("unrecognized"));
        }
    }
}
