use super::types::{EventCloseRequest, EventCreateRequest, EventPatchFields, EventUpdateRequest};

pub(crate) type EventCommand = crate::domain_model::event::EventCommand<EventPatch>;
pub(crate) type EventCreateCommand = crate::domain_model::event::EventCreateCommand<EventPatch>;
pub(crate) type EventUpdateCommand = crate::domain_model::event::EventUpdateCommand<EventPatch>;
pub(crate) type EventCloseCommand = crate::domain_model::event::EventCloseCommand<EventPatch>;

pub(crate) use crate::domain_model::event::EventPatch;

impl From<EventPatchFields> for EventPatch {
    fn from(value: EventPatchFields) -> Self {
        Self {
            title: value.title,
            description: value.description,
            status: value.status,
            message: value.message,
            severity: value.severity,
            tags: value.tags,
            images: value.images,
            ciphertext: value.ciphertext,
            attrs: value.attrs,
            metadata: value.metadata,
        }
    }
}

impl From<EventCreateRequest> for EventCommand {
    fn from(request: EventCreateRequest) -> Self {
        EventCommand::Create(EventCreateCommand {
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            started_at: request.started_at,
            patch: EventPatch::from(request.patch),
        })
    }
}

impl From<EventUpdateRequest> for EventCommand {
    fn from(request: EventUpdateRequest) -> Self {
        EventCommand::Update(EventUpdateCommand {
            op_id: request.common.op_id,
            event_id: request.event_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            patch: EventPatch::from(request.patch),
        })
    }
}

impl From<EventCloseRequest> for EventCommand {
    fn from(request: EventCloseRequest) -> Self {
        EventCommand::Close(EventCloseCommand {
            op_id: request.common.op_id,
            event_id: request.event_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            ended_at: request.ended_at,
            patch: EventPatch::from(request.patch),
        })
    }
}
