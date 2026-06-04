use super::types::{EventCloseRequest, EventCreateRequest, EventPatchFields, EventUpdateRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventCommandKind {
    Create,
    Update,
    Close,
}

#[derive(Debug, Clone)]
pub(crate) struct EventCreateCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) started_at: Option<i64>,
    pub(crate) patch: EventPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) struct EventUpdateCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) event_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) patch: EventPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) struct EventCloseCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) event_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) ended_at: Option<i64>,
    pub(crate) patch: EventPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) enum EventCommand {
    Create(EventCreateCommand),
    Update(EventUpdateCommand),
    Close(EventCloseCommand),
}

impl EventCommand {
    pub(crate) fn kind(&self) -> EventCommandKind {
        match self {
            EventCommand::Create(_) => EventCommandKind::Create,
            EventCommand::Update(_) => EventCommandKind::Update,
            EventCommand::Close(_) => EventCommandKind::Close,
        }
    }

    pub(crate) fn action_name(&self) -> &'static str {
        match self.kind() {
            EventCommandKind::Create => "create",
            EventCommandKind::Update => "update",
            EventCommandKind::Close => "close",
        }
    }

    pub(crate) fn channel_id(&self) -> &str {
        match self {
            EventCommand::Create(command) => &command.channel_id,
            EventCommand::Update(command) => &command.channel_id,
            EventCommand::Close(command) => &command.channel_id,
        }
    }

    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(command) => command.op_id.as_deref(),
            EventCommand::Update(command) => command.op_id.as_deref(),
            EventCommand::Close(command) => command.op_id.as_deref(),
        }
    }

    pub(crate) fn event_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(_) => None,
            EventCommand::Update(command) => Some(command.event_id.as_str()),
            EventCommand::Close(command) => Some(command.event_id.as_str()),
        }
    }

    pub(crate) fn thing_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(command) => command.thing_id.as_deref(),
            EventCommand::Update(command) => command.thing_id.as_deref(),
            EventCommand::Close(command) => command.thing_id.as_deref(),
        }
    }

    pub(crate) fn event_time(&self) -> Option<i64> {
        match self {
            EventCommand::Create(command) => command.event_time,
            EventCommand::Update(command) => command.event_time,
            EventCommand::Close(command) => command.event_time,
        }
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        match self {
            EventCommand::Create(command) => command.started_at,
            EventCommand::Update(_) | EventCommand::Close(_) => None,
        }
    }

    pub(crate) fn ended_at(&self) -> Option<i64> {
        match self {
            EventCommand::Close(command) => command.ended_at,
            EventCommand::Create(_) | EventCommand::Update(_) => None,
        }
    }

    pub(crate) fn patch(&self) -> &EventPatchFields {
        match self {
            EventCommand::Create(command) => &command.patch,
            EventCommand::Update(command) => &command.patch,
            EventCommand::Close(command) => &command.patch,
        }
    }
}

impl From<EventCreateRequest> for EventCommand {
    fn from(request: EventCreateRequest) -> Self {
        EventCommand::Create(EventCreateCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            started_at: request.started_at,
            patch: request.patch,
        })
    }
}

impl From<EventUpdateRequest> for EventCommand {
    fn from(request: EventUpdateRequest) -> Self {
        EventCommand::Update(EventUpdateCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: request.event_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            patch: request.patch,
        })
    }
}

impl From<EventCloseRequest> for EventCommand {
    fn from(request: EventCloseRequest) -> Self {
        EventCommand::Close(EventCloseCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: request.event_id,
            thing_id: request.thing_id,
            event_time: request.event_time,
            ended_at: request.ended_at,
            patch: request.patch,
        })
    }
}
