use axum::extract::State;
use axum::http::StatusCode;
use hashbrown::HashMap;

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    value::{EventMessageText, EventSeverity, EventStatusText},
};

use super::{
    super::{
        channel_auth::{AuthorizedChannel, authorize_channel_by_password},
        entity_input::{
            EntityId, ExtensionObjectRef, MetadataEntries, NormalizedImageUrls, NormalizedTags,
            ObjectPatchRef, OptionalText,
        },
        message::{OpId, ResolvedSemanticId, SemanticScope, dispatch_entity_notification},
    },
    EventCloseRequest, EventCommand, EventCreateRequest, EventProfile, EventSummary,
    EventUpdateRequest,
};

async fn event_to_channel_with_command(
    state: AppState,
    authorized_channel: AuthorizedChannel,
    command: EventCommand,
) -> HttpResult {
    let action_name = command.action_name();
    let span = tracing::info_span!(
        "gateway.api.event.request",
        action = action_name,
        has_thing_id = command.thing_id().is_some()
    );
    let fut = async move {
        let kind = command.kind();
        let patch = command.patch();
        if command.channel_id().trim().is_empty() {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "event.route_rejected",
                action = %(action_name),
                reason = %("channel_id_required")
            );
            return Err(Error::validation_code(
                "channel id must not be empty",
                "channel_id_required",
            ));
        }
        let channel_id = authorized_channel.channel_id;
        let channel_scope = authorized_channel.channel_scope.clone();

        let op_id = OpId::resolve(command.op_id())?.into_inner();
        let thing_id = command
            .thing_id()
            .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
            .transpose()?;
        let resolved_event_id = match command.event_id() {
            None => {
                ResolvedSemanticId::resolve_create(
                    &state,
                    SemanticScope::semantic_create_key(
                        &channel_scope,
                        "event",
                        thing_id.as_deref(),
                        &OpId::parse(&op_id)?,
                    )
                    .as_str(),
                )
                .await?
            }
            Some(raw_event_id) => ResolvedSemanticId {
                semantic_id: { EntityId::parse(raw_event_id, "event_id")?.into_inner() },
            },
        };
        let event_id = resolved_event_id.semantic_id;
        let normalized_tags = patch
            .tags
            .as_deref()
            .map(|tags| NormalizedTags::parse(tags, "tags").map(NormalizedTags::into_inner))
            .transpose()?;
        let normalized_severity = patch
            .severity
            .as_deref()
            .map(EventSeverity::parse)
            .map(|result| result.map(|value| value.as_str().to_string()))
            .transpose()?;
        let normalized_status = patch
            .status
            .as_deref()
            .map(EventStatusText::parse)
            .map(|result| result.map(EventStatusText::into_inner))
            .transpose()?;
        let normalized_message = patch
            .message
            .as_deref()
            .map(EventMessageText::parse)
            .map(|result| result.map(EventMessageText::into_inner))
            .transpose()?;
        let normalized_images = patch
            .images
            .as_deref()
            .map(|images| {
                NormalizedImageUrls::parse(images, "images").map(NormalizedImageUrls::into_inner)
            })
            .transpose()?;
        let normalized_ciphertext = OptionalText::normalize(patch.ciphertext.as_deref());
        let normalized_description = OptionalText::normalize(patch.description.as_deref());

        if let Some(attrs) = patch.attrs.as_ref() {
            ExtensionObjectRef::new(attrs, "attrs").validate()?;
        }
        if let Some(metadata) = patch.metadata.as_ref() {
            MetadataEntries::new(metadata).validate()?;
        }
        kind.validate_required_fields(
            patch.title.as_deref(),
            &normalized_status,
            &normalized_message,
            &normalized_severity,
        )?;

        let mut custom_data = HashMap::with_capacity(2);
        if let Some(metadata) = patch.metadata.as_ref().filter(|value| !value.is_empty()) {
            custom_data.insert(
                "metadata".to_string(),
                MetadataEntries::new(metadata).encode()?,
            );
        }
        if let Some(ciphertext) = normalized_ciphertext.as_ref() {
            custom_data.insert("ciphertext".to_string(), ciphertext.clone());
        }

        let event_time = command.event_time().ok_or_else(|| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "event.route_rejected",
                action = %(action_name),
                reason = %("event_time_required")
            );
            Error::validation_code("event_time is required", "event_time_required")
        })?;

        let mut merged_profile = EventProfile::default();
        if let Some(title) = patch.title.as_ref() {
            merged_profile.title = Some(title.clone());
        }
        if let Some(description) = normalized_description.as_ref() {
            merged_profile.description = Some(description.clone());
        }
        if let Some(status) = normalized_status.as_ref() {
            merged_profile.status = Some(status.clone());
        }
        if let Some(message) = normalized_message.as_ref() {
            merged_profile.message = Some(message.clone());
        }
        if let Some(severity) = normalized_severity.as_ref() {
            merged_profile.severity = Some(severity.clone());
        }
        if let Some(tags) = normalized_tags.as_ref() {
            merged_profile.tags = tags.clone();
        }
        merged_profile.started_at = kind.resolve_started_at(command.started_at(), None, event_time);
        merged_profile.ended_at = kind.resolve_ended_at(command.ended_at(), None, event_time);
        if let Some(images) = normalized_images.as_ref() {
            for value in images {
                if !merged_profile.images.iter().any(|item| item == value) {
                    merged_profile.images.push(value.clone());
                }
            }
        }
        let merged_profile = if merged_profile.is_empty() {
            None
        } else {
            Some(merged_profile)
        };
        let effective_state = kind.state_patch();
        let resolved_thing_id = thing_id.clone();

        let attrs_json_in = patch
            .attrs
            .as_ref()
            .map(|attrs| {
                let mut validated_attrs = serde_json::Map::new();
                ObjectPatchRef::new(attrs).apply_to(&mut validated_attrs);
                serde_json::to_string(attrs).map_err(|_| {
                    Error::validation_code(
                        "event attrs format is invalid",
                        "event_attrs_format_invalid",
                    )
                })
            })
            .transpose()?;

        let notification_title = patch.title.clone().or_else(|| {
            merged_profile
                .as_ref()
                .and_then(|profile| profile.title.clone())
        });
        let notification_body = normalized_message
            .clone()
            .or(normalized_description.clone());

        let dispatch_summary = {
            let mut extra = HashMap::with_capacity(16);
            extra.insert("event_id".to_string(), event_id.clone());
            if let Some(state) = effective_state {
                extra.insert("event_state".to_string(), state.as_api_str().to_string());
            }
            extra.insert("occurred_at".to_string(), event_time.to_string());
            extra.insert("event_time".to_string(), event_time.to_string());
            if let Some(value) = resolved_thing_id.as_deref() {
                extra.insert("thing_id".to_string(), value.to_string());
            }
            if let Some(tags) = normalized_tags.as_ref()
                && let Ok(serialized) = serde_json::to_string(tags)
            {
                extra.insert("tags".to_string(), serialized);
            }
            if let Some(images) = normalized_images.as_ref()
                && let Ok(serialized) = serde_json::to_string(images)
            {
                extra.insert("images".to_string(), serialized);
            }
            if let Some(profile) = merged_profile.as_ref() {
                if let Some(value) = profile.title.as_deref() {
                    extra.insert("title".to_string(), value.to_string());
                }
                if let Some(value) = profile.description.as_deref() {
                    extra.insert("description".to_string(), value.to_string());
                }
                if let Some(value) = profile.status.as_deref() {
                    extra.insert("status".to_string(), value.to_string());
                }
                if let Some(value) = profile.message.as_deref() {
                    extra.insert("message".to_string(), value.to_string());
                }
                if let Some(value) = profile.severity.as_deref() {
                    extra.insert("severity".to_string(), value.to_string());
                }
                if let Some(value) = profile.started_at {
                    extra.insert("started_at".to_string(), value.to_string());
                }
                if let Some(value) = profile.ended_at {
                    extra.insert("ended_at".to_string(), value.to_string());
                }
            }
            if let Some(value) = attrs_json_in.as_deref() {
                extra.insert("attrs".to_string(), value.to_string());
            }

            Some(
                dispatch_entity_notification(
                    &state,
                    channel_id,
                    op_id.clone(),
                    event_time,
                    notification_title.clone(),
                    notification_body.clone(),
                    None,
                    None,
                    custom_data.clone(),
                    "event",
                    &event_id,
                    extra,
                )
                .await?,
            )
        };

        let mut response = EventSummary {
            channel_id: channel_scope,
            op_id,
            event_id,
            thing_id: resolved_thing_id,
            accepted: true,
        };
        if let Some(summary) = dispatch_summary.as_ref()
            && let Some(error_message) = summary.failure_error_message()
        {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "event.route_dispatch_rejected",
                action = %(action_name),
                channel_id = %(crate::util::redact_text(response.channel_id.as_str())),
                event_id = %(crate::util::redact_text(response.event_id.as_str())),
                reason = %(error_message)
            );
            response.accepted = false;
            return Ok(
                crate::api::StatusResponse::err_with_data(error_message, response)
                    .with_status(StatusCode::SERVICE_UNAVAILABLE),
            );
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "event.route_completed",
            action = %(action_name),
            channel_id = %(crate::util::redact_text(response.channel_id.as_str())),
            event_id = %(crate::util::redact_text(response.event_id.as_str())),
            accepted = (response.accepted)
        );
        Ok(crate::api::ok(response))
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

pub(crate) async fn event_create_authorized(
    state: &AppState,
    command: EventCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_command(state.clone(), authorized_channel, command).await
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

pub(crate) async fn event_update_authorized(
    state: &AppState,
    command: EventCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_command(state.clone(), authorized_channel, command).await
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

pub(crate) async fn event_close_authorized(
    state: &AppState,
    command: EventCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_command(state.clone(), authorized_channel, command).await
}
