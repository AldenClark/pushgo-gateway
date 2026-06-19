use axum::extract::{Path, State};
use serde::Serialize;

use crate::{
    api::{HttpResult, err_with_code, ok},
    app::AppState,
    storage::SenderSubmitStatusRecord,
    value::OpId,
};

#[derive(Debug, Serialize)]
struct SendStatusResponse {
    op_id: String,
    status: String,
    model: String,
    entity_id: String,
    accepted_at: i64,
    updated_at: i64,
    expires_at: i64,
}

impl From<SenderSubmitStatusRecord> for SendStatusResponse {
    fn from(record: SenderSubmitStatusRecord) -> Self {
        Self {
            op_id: record.op_id,
            status: record.status.as_str().to_string(),
            model: record.model,
            entity_id: record.entity_id,
            accepted_at: record.accepted_at,
            updated_at: record.updated_at,
            expires_at: record.expires_at,
        }
    }
}

pub(crate) async fn send_status(
    State(state): State<AppState>,
    Path(op_id): Path<String>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.send.status");
    let fut = async move {
        let op_id = OpId::parse(&op_id)?;
        let op_id_text = op_id.into_inner();
        match state.store.load_sender_submit_status(&op_id_text).await? {
            Some(record) => {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::INFO,
                    event = "send.status_completed",
                    op_id = %(crate::util::redact_text(op_id_text.as_str())),
                    status = %(record.status.as_str()),
                    model = %(record.model.as_str())
                );
                Ok(ok(SendStatusResponse::from(record)))
            }
            None => Ok(err_with_code(
                axum::http::StatusCode::NOT_FOUND,
                "send status not found",
                "send_status_not_found",
            )),
        }
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &crate::api::Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "send.status_failed",
                error = %(err.to_string())
            );
        })
}
