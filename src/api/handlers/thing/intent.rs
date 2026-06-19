use super::types::{
    ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingPatchFields,
    ThingUpdateRequest,
};

pub(crate) use crate::delivery_core::domain::thing::ThingPatch;

pub(crate) type ThingCommand = crate::delivery_core::domain::thing::ThingCommand<ThingPatch>;
pub(crate) type ThingCreateCommand =
    crate::delivery_core::domain::thing::ThingCreateCommand<ThingPatch>;
pub(crate) type ThingUpdateCommand =
    crate::delivery_core::domain::thing::ThingUpdateCommand<ThingPatch>;
pub(crate) type ThingArchiveCommand =
    crate::delivery_core::domain::thing::ThingArchiveCommand<ThingPatch>;
pub(crate) type ThingDeleteCommand =
    crate::delivery_core::domain::thing::ThingDeleteCommand<ThingPatch>;

impl From<ThingPatchFields> for ThingPatch {
    fn from(value: ThingPatchFields) -> Self {
        Self {
            title: value.title,
            description: value.description,
            tags: value.tags,
            external_ids: value.external_ids,
            location_type: value.location_type,
            location_value: value.location_value,
            primary_image: value.primary_image,
            images: value.images,
            ciphertext: value.ciphertext,
            observed_at: value.observed_at,
            attrs: value.attrs,
            metadata: value.metadata,
        }
    }
}

impl From<ThingCreateRequest> for ThingCommand {
    fn from(request: ThingCreateRequest) -> Self {
        ThingCommand::Create(ThingCreateCommand {
            op_id: request.common.op_id,
            created_at: request.created_at,
            patch: ThingPatch::from(request.patch),
        })
    }
}

impl From<ThingUpdateRequest> for ThingCommand {
    fn from(request: ThingUpdateRequest) -> Self {
        ThingCommand::Update(ThingUpdateCommand {
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            patch: ThingPatch::from(request.patch),
        })
    }
}

impl From<ThingArchiveRequest> for ThingCommand {
    fn from(request: ThingArchiveRequest) -> Self {
        ThingCommand::Archive(ThingArchiveCommand {
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            patch: ThingPatch::from(request.patch),
        })
    }
}

impl From<ThingDeleteRequest> for ThingCommand {
    fn from(request: ThingDeleteRequest) -> Self {
        ThingCommand::Delete(ThingDeleteCommand {
            op_id: request.common.op_id,
            thing_id: request.thing_id,
            deleted_at: request.deleted_at,
            patch: ThingPatch::from(request.patch),
        })
    }
}
