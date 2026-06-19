use hashbrown::HashMap;

use crate::{
    delivery_core::{payload::EntityKind, submit::AuthorizedSubmitChannel},
    domain_model::projection::DomainDeliveryPolicy,
};

pub(crate) struct DispatchMessageInput {
    pub(crate) authorized_channel: AuthorizedSubmitChannel,
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: Option<String>,
    pub(crate) occurred_at: Option<i64>,
    pub(crate) title: String,
    pub(crate) body: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) ttl: Option<i64>,
    pub(crate) custom_data: HashMap<String, String>,
    pub(crate) extra_fields: HashMap<String, String>,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
    pub(crate) message_id: String,
}

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

pub(crate) struct DispatchRequest {
    pub(crate) op_id: String,
    pub(crate) occurred_at: i64,
    pub(crate) alert: DispatchAlert,
    pub(crate) payload: DispatchEntityPayload,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
}

impl DispatchRequest {
    pub(crate) fn new(
        op_id: String,
        occurred_at: i64,
        alert: DispatchAlert,
        payload: DispatchEntityPayload,
        delivery_policy: DomainDeliveryPolicy,
    ) -> Self {
        Self {
            op_id,
            occurred_at,
            alert,
            payload,
            delivery_policy,
        }
    }
}

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
