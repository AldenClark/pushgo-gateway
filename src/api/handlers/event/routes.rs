use axum::extract::State;

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    delivery_core::{
        auth::SubmitAuth,
        source::IngressSource,
        submit::{
            ChannelSelector, DomainCommandInput, EventInput, ResponseMode, SubmitCommand,
            SubmitContext, submit_command,
        },
    },
};

use super::{
    super::channel_auth::{AuthorizedChannel, authorize_channel_by_password},
    super::delivery_core_adapter::{authorized_channel_context, core_error_to_api_error},
    EventCloseRequest, EventCommand, EventCreateRequest, EventUpdateRequest,
};

async fn event_to_channel_with_command(
    state: AppState,
    authorized_channel: AuthorizedChannel,
    command: EventCommand,
) -> HttpResult {
    let action_name = command.action_name();
    let has_thing_id = command.thing_id().is_some();
    let span = tracing::info_span!(
        "gateway.api.event.request",
        action = action_name,
        has_thing_id
    );
    let fut = async move {
        let authorized_context = authorized_channel_context(authorized_channel);
        let result = submit_command(
            SubmitContext {
                runtime: &state,
                now_millis: chrono::Utc::now().timestamp_millis(),
            },
            SubmitCommand {
                source: IngressSource::HttpEvent,
                auth: SubmitAuth::AuthorizedChannel(authorized_context.clone()),
                channel: ChannelSelector::Authorized(authorized_context),
                command: DomainCommandInput::Event(Box::new(EventInput { command })),
                response_mode: ResponseMode::HttpJson,
            },
        )
        .await
        .map_err(core_error_to_api_error)?;
        event_submit_result_to_http(action_name, result)
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "event.route_failed",
                action = %(action_name),
                error = %(err.to_string())
            );
        })
}

pub(crate) fn event_submit_result_to_http(
    action_name: &'static str,
    result: crate::delivery_core::response::SubmitResult,
) -> HttpResult {
    let summary = result.summary.clone();
    let ack = super::super::send_ack::SendAck::from_submit_result(result)?;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "event.route_completed",
        action = %(action_name),
        channel_id = %(crate::util::redact_text(summary.channel_id.as_str())),
        event_id = %(crate::util::redact_text(ack.event_id.as_deref().unwrap_or("")))
    );
    Ok(ack.into_http_response())
}

pub(crate) async fn event_create_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventCreateRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "event.route_rejected",
            action = %("create"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_command(state, authorized_channel, EventCommand::from(payload)).await
}

pub(crate) async fn event_update_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventUpdateRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "event.route_rejected",
            action = %("update"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_command(state, authorized_channel, EventCommand::from(payload)).await
}

pub(crate) async fn event_close_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventCloseRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "event.route_rejected",
            action = %("close"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_command(state, authorized_channel, EventCommand::from(payload)).await
}
