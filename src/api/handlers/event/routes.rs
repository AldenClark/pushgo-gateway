use axum::extract::{Path, State};

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    delivery_core::{
        auth::SubmitAuth,
        response::EntityRef,
        source::IngressSource,
        submit::{
            ChannelSelector, DomainCommandInput, EventInput, ResponseMode, SubmitCommand,
            SubmitContext, submit_command,
        },
    },
};

use super::{
    super::activity::{
        EventActivityAction, EventActivityUpdate, dispatch_event_activity_update, json_scalar_text,
    },
    super::channel_auth::{AuthorizedChannel, authorize_channel_by_password},
    super::delivery_core_adapter::{authorized_channel_context, core_error_to_api_error},
    EventCloseRequest, EventCommand, EventCreateRequest, EventUpdateRequest,
    types::EventPatchFields,
};

fn scoped_thing_id_from_path(
    path_thing_id: String,
    body_thing_id: Option<&str>,
) -> Result<String, Error> {
    let scoped = crate::value::EntityId::parse(&path_thing_id, "thing_id")?.into_inner();
    if let Some(body_thing_id) = body_thing_id {
        let body = crate::value::EntityId::parse(body_thing_id, "thing_id")?.into_inner();
        if body != scoped {
            return Err(Error::validation_code(
                "thing_id in path and body must match",
                "thing_id_mismatch",
            ));
        }
    }
    Ok(scoped)
}

async fn event_to_channel_with_command(
    state: AppState,
    authorized_channel: AuthorizedChannel,
    command: EventCommand,
    activity: Option<PendingEventActivityUpdate>,
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
        if let Some(activity) = activity
            && let EntityRef::Event { event_id, .. } = &result.entity
        {
            let update = activity.into_update(event_id.clone());
            tokio::spawn(dispatch_event_activity_update(state.clone(), update));
        }
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

#[derive(Clone)]
struct PendingEventActivityUpdate {
    action: EventActivityAction,
    title: Option<String>,
    state: Option<String>,
    severity: Option<String>,
    updated_at_millis: i64,
}

impl PendingEventActivityUpdate {
    fn create(payload: &EventCreateRequest) -> Option<Self> {
        Self::from_patch(
            EventActivityAction::Update,
            &payload.patch,
            payload.event_time,
        )
    }

    fn update(payload: &EventUpdateRequest) -> Option<Self> {
        Self::from_patch(
            EventActivityAction::Update,
            &payload.patch,
            payload.event_time,
        )
    }

    fn close(payload: &EventCloseRequest) -> Option<Self> {
        Self::from_patch(EventActivityAction::End, &payload.patch, payload.event_time)
    }

    fn from_patch(
        action: EventActivityAction,
        patch: &EventPatchFields,
        updated_at_millis: Option<i64>,
    ) -> Option<Self> {
        let updated_at_millis = updated_at_millis?;
        let state = patch
            .status
            .clone()
            .or_else(|| json_scalar_text(patch.attrs.as_ref().and_then(|attrs| attrs.get("state"))))
            .or_else(|| (action == EventActivityAction::End).then(|| "closed".to_string()));
        Some(Self {
            action,
            title: patch.title.clone(),
            state,
            severity: patch.severity.clone(),
            updated_at_millis,
        })
    }

    fn into_update(self, event_id: String) -> EventActivityUpdate {
        EventActivityUpdate {
            event_id,
            action: self.action,
            title: self.title,
            state: self.state,
            severity: self.severity,
            updated_at_millis: self.updated_at_millis,
        }
    }
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
    let activity = PendingEventActivityUpdate::create(&payload);
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
    event_to_channel_with_command(
        state,
        authorized_channel,
        EventCommand::from(payload),
        activity,
    )
    .await
}

pub(crate) async fn thing_event_create_to_channel(
    State(state): State<AppState>,
    Path(thing_id): Path<String>,
    ApiJson(mut payload): ApiJson<EventCreateRequest>,
) -> HttpResult {
    payload.thing_id = Some(scoped_thing_id_from_path(
        thing_id,
        payload.thing_id.as_deref(),
    )?);
    event_create_to_channel(State(state), ApiJson(payload)).await
}

pub(crate) async fn event_update_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventUpdateRequest>,
) -> HttpResult {
    let activity = PendingEventActivityUpdate::update(&payload);
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
    event_to_channel_with_command(
        state,
        authorized_channel,
        EventCommand::from(payload),
        activity,
    )
    .await
}

pub(crate) async fn thing_event_update_to_channel(
    State(state): State<AppState>,
    Path(thing_id): Path<String>,
    ApiJson(mut payload): ApiJson<EventUpdateRequest>,
) -> HttpResult {
    payload.thing_id = Some(scoped_thing_id_from_path(
        thing_id,
        payload.thing_id.as_deref(),
    )?);
    event_update_to_channel(State(state), ApiJson(payload)).await
}

pub(crate) async fn event_close_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventCloseRequest>,
) -> HttpResult {
    let activity = PendingEventActivityUpdate::close(&payload);
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
    event_to_channel_with_command(
        state,
        authorized_channel,
        EventCommand::from(payload),
        activity,
    )
    .await
}

pub(crate) async fn thing_event_close_to_channel(
    State(state): State<AppState>,
    Path(thing_id): Path<String>,
    ApiJson(mut payload): ApiJson<EventCloseRequest>,
) -> HttpResult {
    payload.thing_id = Some(scoped_thing_id_from_path(
        thing_id,
        payload.thing_id.as_deref(),
    )?);
    event_close_to_channel(State(state), ApiJson(payload)).await
}
