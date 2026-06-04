use axum::extract::State;
use axum::http::StatusCode;
use hashbrown::HashMap;

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
};

use super::{
    super::{
        channel_auth::{AuthorizedChannel, authorize_channel_by_password},
        entity_input::{
            EntityId, ExtensionObjectRef, MetadataEntries, NormalizedImageUrls, NormalizedTags,
            OptionalText, OptionalUrl,
        },
        message::{
            DispatchAlert, DispatchEntityPayload, DispatchRequest, OpId, ResolvedSemanticId,
            SemanticScope, dispatch_entity_notification,
        },
    },
    ThingArchiveRequest, ThingCommand, ThingCommandKind, ThingCreateRequest, ThingDeleteRequest,
    ThingProfile, ThingSummary, ThingUpdateRequest,
    helpers::{ExternalIdPatchRef, thing_state_api_text, validate_manufacturer_attrs},
};

async fn thing_to_channel_with_command(
    state: AppState,
    authorized_channel: AuthorizedChannel,
    command: ThingCommand,
) -> HttpResult {
    let action_name = command.action_name();
    let span = tracing::info_span!("gateway.api.thing.request", action = action_name);
    let fut = async move {
        let kind = command.kind();
        let patch = command.patch();
        if command.channel_id().trim().is_empty() {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "thing.route_rejected",
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
        let resolved_thing_id = match command.thing_id() {
            None => {
                ResolvedSemanticId::resolve_create(
                    &state,
                    SemanticScope::semantic_create_key(
                        &channel_scope,
                        "thing",
                        None,
                        &OpId::parse(&op_id)?,
                    )
                    .as_str(),
                )
                .await?
            }
            Some(raw_thing_id) => ResolvedSemanticId {
                semantic_id: EntityId::parse(raw_thing_id, "thing_id")?.into_inner(),
            },
        };
        let thing_id = resolved_thing_id.semantic_id;

        let normalized_tags = patch
            .tags
            .as_deref()
            .map(|tags| NormalizedTags::parse(tags, "tags").map(NormalizedTags::into_inner))
            .transpose()?;
        let normalized_images = patch
            .images
            .as_deref()
            .map(|images| {
                NormalizedImageUrls::parse(images, "images").map(NormalizedImageUrls::into_inner)
            })
            .transpose()?;
        let normalized_primary_image =
            OptionalUrl::normalize(patch.primary_image.as_deref(), "primary_image")?;
        let normalized_ciphertext = OptionalText::normalize(patch.ciphertext.as_deref());
        let normalized_description = OptionalText::normalize(patch.description.as_deref());
        if let Some(attrs) = patch.attrs.as_ref() {
            ExtensionObjectRef::new(attrs, "attrs").validate()?;
            validate_manufacturer_attrs(attrs)?;
        }
        if let Some(external_ids) = patch.external_ids.as_ref() {
            ExternalIdPatchRef::new(external_ids).validate()?;
        }
        let normalized_location = super::ThingLocation::parse_patch(
            patch.location_type.as_deref(),
            patch.location_value.as_deref(),
        )?;
        if let Some(metadata) = patch.metadata.as_ref() {
            MetadataEntries::new(metadata).validate()?;
        }

        let observed_at = patch.observed_at.ok_or_else(|| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "thing.route_rejected",
                action = %(action_name),
                reason = %("observed_at_required")
            );
            Error::validation_code("observed_at is required", "observed_at_required")
        })?;

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

        let mut merged_profile = ThingProfile::default();
        if let Some(title) = patch.title.clone() {
            merged_profile.title = Some(title);
        }
        if let Some(description) = normalized_description.clone() {
            merged_profile.description = Some(description);
        }
        if let Some(tags) = normalized_tags.as_ref() {
            merged_profile.tags = tags.clone();
        }
        let resolved_created_at = command
            .created_at()
            .or(if kind == ThingCommandKind::Create {
                Some(observed_at)
            } else {
                None
            });
        merged_profile.created_at = resolved_created_at;
        if let Some(image) = normalized_primary_image {
            merged_profile.primary_image = Some(image);
        }
        if let Some(images) = normalized_images.as_ref() {
            for image in images {
                merged_profile.push_unique_image(image);
            }
        }

        if let Some(resolved_state) = kind.state_patch() {
            merged_profile.state = Some(thing_state_api_text(resolved_state).to_string());
            if kind == ThingCommandKind::Delete {
                merged_profile.deleted_at = command.deleted_at().or(Some(observed_at));
            }
        }

        if let Some(external_ids) = patch.external_ids.as_ref() {
            ExternalIdPatchRef::new(external_ids).apply_to(&mut merged_profile.external_ids)?;
        }
        if let Some(location) = normalized_location {
            merged_profile.location = Some(location);
        }

        let merged_profile = if merged_profile.is_empty() {
            None
        } else {
            Some(merged_profile)
        };
        let attrs_json = patch
            .attrs
            .as_ref()
            .map(|attrs| {
                serde_json::to_string(attrs).map_err(|_| {
                    Error::validation_code(
                        "thing attrs format is invalid",
                        "thing_attrs_format_invalid",
                    )
                })
            })
            .transpose()?;

        let (notification_title, notification_body) =
            kind.build_notification_content(patch, merged_profile.as_ref(), normalized_description);

        let dispatch_summary = {
            let mut extra = HashMap::with_capacity(20);
            extra.insert("occurred_at".to_string(), observed_at.to_string());
            extra.insert("thing_id".to_string(), thing_id.clone());
            if let Some(value) = attrs_json.as_deref() {
                extra.insert("attrs".to_string(), value.to_string());
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
            if let Some(external_ids) = patch.external_ids.as_ref()
                && let Ok(serialized) = serde_json::to_string(external_ids)
            {
                extra.insert("external_ids".to_string(), serialized);
            }
            if let Some(profile) = merged_profile.as_ref() {
                if let Some(value) = profile.title.as_deref() {
                    extra.insert("title".to_string(), value.to_string());
                }
                if let Some(value) = profile.description.as_deref() {
                    extra.insert("description".to_string(), value.to_string());
                }
                if let Some(value) = profile.primary_image.as_deref() {
                    extra.insert("primary_image".to_string(), value.to_string());
                }
                if let Some(value) = profile.created_at {
                    extra.insert("created_at".to_string(), value.to_string());
                }
                if let Some(value) = profile.state.as_deref() {
                    extra.insert("state".to_string(), value.to_string());
                }
                if let Some(value) = profile.deleted_at {
                    extra.insert("deleted_at".to_string(), value.to_string());
                }
                if let Some(location) = profile.location.as_ref() {
                    extra.insert(
                        "location_type".to_string(),
                        location.location_type().to_string(),
                    );
                    extra.insert("location_value".to_string(), location.value_text());
                    if let Ok(serialized) = serde_json::to_string(location) {
                        extra.insert("location".to_string(), serialized);
                    }
                }
            }

            Some(
                dispatch_entity_notification(
                    &state,
                    channel_id,
                    DispatchRequest::new(
                        op_id.clone(),
                        observed_at,
                        DispatchAlert::new(notification_title, notification_body, None, None),
                        DispatchEntityPayload::thing(thing_id.clone(), custom_data, extra),
                    ),
                )
                .await?,
            )
        };

        let mut response = ThingSummary {
            channel_id: channel_scope,
            op_id,
            thing_id,
            accepted: true,
        };
        if let Some(summary) = dispatch_summary.as_ref()
            && let Some(error_message) = summary.failure_error_message()
        {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "thing.route_dispatch_rejected",
                action = %(action_name),
                channel_id = %(crate::util::redact_text(response.channel_id.as_str())),
                thing_id = %(crate::util::redact_text(response.thing_id.as_str())),
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
            event = "thing.route_completed",
            action = %(action_name),
            channel_id = %(crate::util::redact_text(response.channel_id.as_str())),
            thing_id = %(crate::util::redact_text(response.thing_id.as_str())),
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
                event = "thing.route_failed",
                action = %(action_name),
                error = %(err.to_string())
            );
        })
}

pub(crate) async fn thing_create_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingCreateRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "thing.route_rejected",
            action = %("create"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    thing_to_channel_with_command(state, authorized_channel, ThingCommand::from(payload)).await
}

pub(crate) async fn thing_create_authorized(
    state: &AppState,
    command: ThingCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    thing_to_channel_with_command(state.clone(), authorized_channel, command).await
}

pub(crate) async fn thing_update_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingUpdateRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "thing.route_rejected",
            action = %("update"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    thing_to_channel_with_command(state, authorized_channel, ThingCommand::from(payload)).await
}

pub(crate) async fn thing_update_authorized(
    state: &AppState,
    command: ThingCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    thing_to_channel_with_command(state.clone(), authorized_channel, command).await
}

pub(crate) async fn thing_archive_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingArchiveRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "thing.route_rejected",
            action = %("archive"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    thing_to_channel_with_command(state, authorized_channel, ThingCommand::from(payload)).await
}

pub(crate) async fn thing_archive_authorized(
    state: &AppState,
    command: ThingCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    thing_to_channel_with_command(state.clone(), authorized_channel, command).await
}

pub(crate) async fn thing_delete_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingDeleteRequest>,
) -> HttpResult {
    let password = payload.common.password.as_deref().ok_or_else(|| {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "thing.route_rejected",
            action = %("delete"),
            reason = %("password_required")
        );
        Error::validation_code("password is required", "password_required")
    })?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    thing_to_channel_with_command(state, authorized_channel, ThingCommand::from(payload)).await
}

pub(crate) async fn thing_delete_authorized(
    state: &AppState,
    command: ThingCommand,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    thing_to_channel_with_command(state.clone(), authorized_channel, command).await
}
