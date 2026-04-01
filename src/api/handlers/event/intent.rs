use super::types::{EventCloseRequest, EventCreateRequest, EventPayloadFields, EventUpdateRequest};

#[derive(Debug)]
pub(super) struct EventIntent {
    pub(super) channel_id: String,
    pub(super) op_id: Option<String>,
    pub(super) event_id: Option<String>,
    pub(super) thing_id: Option<String>,
    pub(super) payload: EventPayloadFields,
}

impl EventIntent {
    pub(super) fn from_create(request: EventCreateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: None,
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }

    pub(super) fn from_update(request: EventUpdateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: Some(request.event_id),
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }

    pub(super) fn from_close(request: EventCloseRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: Some(request.event_id),
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }
}
