use axum::response::Response;
use serde::Serialize;

use crate::{
    api::Error,
    delivery_core::response::{EntityRef, SubmitResult},
};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SendAck {
    pub(crate) op_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thing_id: Option<String>,
}

impl SendAck {
    pub(crate) fn from_submit_result(result: SubmitResult) -> Result<Self, Error> {
        let (message_id, event_id, thing_id) = match result.entity {
            EntityRef::Message { message_id, .. } => (Some(message_id), None, None),
            EntityRef::Event { event_id, .. } => (None, Some(event_id), None),
            EntityRef::Thing { thing_id } => (None, None, Some(thing_id)),
        };
        Ok(Self {
            op_id: result.summary.op_id,
            message_id,
            event_id,
            thing_id,
        })
    }

    pub(crate) fn into_http_response(self) -> Response {
        crate::api::ok(self)
    }
}
