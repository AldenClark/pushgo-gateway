use super::types::{
    ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingPatchFields,
    ThingUpdateRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThingCommandKind {
    Create,
    Update,
    Archive,
    Delete,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingCreateCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) created_at: Option<i64>,
    pub(crate) patch: ThingPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingUpdateCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) patch: ThingPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingArchiveCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) patch: ThingPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingDeleteCommand {
    pub(crate) channel_id: String,
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) deleted_at: Option<i64>,
    pub(crate) patch: ThingPatchFields,
}

#[derive(Debug, Clone)]
pub(crate) enum ThingCommand {
    Create(ThingCreateCommand),
    Update(ThingUpdateCommand),
    Archive(ThingArchiveCommand),
    Delete(ThingDeleteCommand),
}

impl ThingCommand {
    pub(crate) fn kind(&self) -> ThingCommandKind {
        match self {
            ThingCommand::Create(_) => ThingCommandKind::Create,
            ThingCommand::Update(_) => ThingCommandKind::Update,
            ThingCommand::Archive(_) => ThingCommandKind::Archive,
            ThingCommand::Delete(_) => ThingCommandKind::Delete,
        }
    }

    pub(crate) fn action_name(&self) -> &'static str {
        match self.kind() {
            ThingCommandKind::Create => "create",
            ThingCommandKind::Update => "update",
            ThingCommandKind::Archive => "archive",
            ThingCommandKind::Delete => "delete",
        }
    }

    pub(crate) fn channel_id(&self) -> &str {
        match self {
            ThingCommand::Create(command) => &command.channel_id,
            ThingCommand::Update(command) => &command.channel_id,
            ThingCommand::Archive(command) => &command.channel_id,
            ThingCommand::Delete(command) => &command.channel_id,
        }
    }

    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            ThingCommand::Create(command) => command.op_id.as_deref(),
            ThingCommand::Update(command) => command.op_id.as_deref(),
            ThingCommand::Archive(command) => command.op_id.as_deref(),
            ThingCommand::Delete(command) => command.op_id.as_deref(),
        }
    }

    pub(crate) fn thing_id(&self) -> Option<&str> {
        match self {
            ThingCommand::Create(_) => None,
            ThingCommand::Update(command) => Some(command.thing_id.as_str()),
            ThingCommand::Archive(command) => Some(command.thing_id.as_str()),
            ThingCommand::Delete(command) => Some(command.thing_id.as_str()),
        }
    }

    pub(crate) fn created_at(&self) -> Option<i64> {
        match self {
            ThingCommand::Create(command) => command.created_at,
            ThingCommand::Update(_) | ThingCommand::Archive(_) | ThingCommand::Delete(_) => None,
        }
    }

    pub(crate) fn deleted_at(&self) -> Option<i64> {
        match self {
            ThingCommand::Delete(command) => command.deleted_at,
            ThingCommand::Create(_) | ThingCommand::Update(_) | ThingCommand::Archive(_) => None,
        }
    }

    pub(crate) fn patch(&self) -> &ThingPatchFields {
        match self {
            ThingCommand::Create(command) => &command.patch,
            ThingCommand::Update(command) => &command.patch,
            ThingCommand::Archive(command) => &command.patch,
            ThingCommand::Delete(command) => &command.patch,
        }
    }
}

impl From<ThingCreateRequest> for ThingCommand {
    fn from(request: ThingCreateRequest) -> Self {
        ThingCommand::Create(ThingCreateCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            created_at: request.created_at,
            patch: request.patch,
        })
    }
}

impl From<ThingUpdateRequest> for ThingCommand {
    fn from(request: ThingUpdateRequest) -> Self {
        ThingCommand::Update(ThingUpdateCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            patch: request.patch,
        })
    }
}

impl From<ThingArchiveRequest> for ThingCommand {
    fn from(request: ThingArchiveRequest) -> Self {
        ThingCommand::Archive(ThingArchiveCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            patch: request.patch,
        })
    }
}

impl From<ThingDeleteRequest> for ThingCommand {
    fn from(request: ThingDeleteRequest) -> Self {
        ThingCommand::Delete(ThingDeleteCommand {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            deleted_at: request.deleted_at,
            patch: request.patch,
        })
    }
}
