use hashbrown::HashMap;

use crate::delivery_core::payload::EntityKind;

use super::common::DomainAction;

#[derive(Debug, Clone)]
pub(crate) struct DomainPayloadProjection {
    pub(crate) entity: EntityRef,
    pub(crate) alert: AlertHint,
    pub(crate) custom_data: HashMap<String, String>,
    pub(crate) extra_fields: HashMap<String, String>,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
}

#[derive(Debug, Clone)]
pub(crate) enum EntityRef {
    Message {
        message_id: String,
        thing_id: Option<String>,
    },
    Event {
        event_id: String,
        thing_id: Option<String>,
    },
    Thing {
        thing_id: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct AlertHint {
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) ttl: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DomainDeliveryPolicy {
    pub(crate) allow_private_realtime: bool,
    pub(crate) allow_private_outbox: bool,
    pub(crate) allow_provider_inline: bool,
    pub(crate) allow_provider_wakeup_pull: bool,
    pub(crate) allow_mqtt_receiver: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedEnvelope<T> {
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_text: String,
    pub(crate) op_id: String,
    pub(crate) occurred_at: i64,
    pub(crate) action: DomainAction,
    pub(crate) command: T,
}

impl DomainDeliveryPolicy {
    pub(crate) fn fanout_default() -> Self {
        Self {
            allow_private_realtime: true,
            allow_private_outbox: true,
            allow_provider_inline: true,
            allow_provider_wakeup_pull: true,
            allow_mqtt_receiver: true,
        }
    }

    pub(crate) fn for_model_action(entity_kind: EntityKind, action: DomainAction) -> Self {
        match (entity_kind, action) {
            (EntityKind::Message, DomainAction::Send) => Self::fanout_default(),
            _ => Self::fanout_default(),
        }
    }
}
