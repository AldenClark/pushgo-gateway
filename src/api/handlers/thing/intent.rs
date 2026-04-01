use super::types::{
    ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingPayloadFields,
    ThingUpdateRequest,
};

#[derive(Debug)]
pub(super) struct ThingIntent {
    pub(super) channel_id: String,
    pub(super) op_id: Option<String>,
    pub(super) thing_id: Option<String>,
    pub(super) payload: ThingPayloadFields,
}

impl ThingIntent {
    pub(super) fn from_create(request: ThingCreateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: None,
            payload: ThingPayloadFields {
                created_at: request.created_at,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    pub(super) fn from_update(request: ThingUpdateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    pub(super) fn from_archive(request: ThingArchiveRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    pub(super) fn from_delete(request: ThingDeleteRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: request.deleted_at,
                mutable: request.payload,
            },
        }
    }
}
