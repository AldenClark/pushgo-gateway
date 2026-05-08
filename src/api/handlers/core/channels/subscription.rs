use axum::{extract::State, http::StatusCode};

use crate::{
    api::{ApiJson, ChannelAlias, ChannelId, ChannelPassword, Error, HttpResult},
    app::AppState,
    routing::{DeviceChannelType, derive_private_device_id},
    storage::DeviceRouteRecordRow,
    value::DeviceKeyRef,
};

use super::{
    audit::append_subscription_audit,
    private_cleanup::clear_private_pending_for_channel,
    types::{
        ChannelSubscribeRequest, ChannelSubscribeResponse, ChannelUnsubscribeRequest,
        ChannelUnsubscribeResponse,
    },
};

pub(crate) async fn channel_subscribe(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ChannelSubscribeRequest>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.channel.subscribe");
    let fut = async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        let route = state
            .device_registry
            .get(device_key.as_str())
            .ok_or_else(|| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "channel.subscribe_rejected",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    reason = %("device_key_not_found")
                );
                Error::validation_code("device_key not found", "device_key_not_found")
            })?;
        state
            .store
            .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
                device_key.as_str(),
                &route,
            ))
            .await?;

        let channel_id = match payload.channel_id.as_deref() {
            Some(raw) => Some(ChannelId::parse(raw)?),
            None => None,
        };
        let channel_name = match payload.channel_name.as_deref() {
            Some(raw) => Some(ChannelAlias::parse(raw)?),
            None => None,
        };
        if channel_id.is_some() == channel_name.is_some() {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.subscribe_rejected",
                device_key = %(crate::util::redact_text(device_key.as_str())),
                reason = %("channel_binding_invalid")
            );
            return Err(Error::validation_code(
                "must provide either channel_id or channel_name",
                "channel_binding_invalid",
            ));
        }
        let password = ChannelPassword::parse(&payload.password)?;

        let outcome = match route.channel_type {
            DeviceChannelType::Private => {
                if !state.private_channel_enabled {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.subscribe_rejected",
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        reason = %("private_channel_disabled")
                    );
                    return Ok(crate::api::err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "private channel is disabled",
                    ));
                }
                let out = state
                    .store
                    .upsert_private_channel(
                        channel_id.map(ChannelId::into_inner),
                        channel_name.map(ChannelAlias::as_str),
                        password.as_str(),
                    )
                    .await?;
                let device_id = derive_private_device_id(device_key.as_str());
                state
                    .store
                    .private_subscribe_channel(out.channel_id, device_id)
                    .await?;
                out
            }
            _ => {
                let provider_token = route
                .provider_token
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.subscribe_rejected",
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        reason = %("provider_token_required")
                    );
                    Error::validation_code(
                        "device route is provider; provider_token required (switch route to private for private channel ops)",
                        "provider_token_required",
                    )
                })?;
                let platform = route.platform;
                state
                    .store
                    .subscribe_channel_for_device_key(
                        channel_id.map(ChannelId::into_inner),
                        channel_name.map(ChannelAlias::as_str),
                        password.as_str(),
                        device_key.as_str(),
                        provider_token,
                        platform,
                    )
                    .await?
            }
        };

        append_subscription_audit(
            &state,
            outcome.channel_id,
            device_key.as_str(),
            "subscribe",
            &route,
        )
        .await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.subscribe_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            channel_id = %(crate::util::redact_text(ChannelId::from(outcome.channel_id).to_string())),
            created = (outcome.created),
            channel_type = %(route.channel_type.as_str())
        );

        Ok(crate::api::ok(ChannelSubscribeResponse {
            channel_id: ChannelId::from(outcome.channel_id).to_string(),
            channel_name: outcome.alias,
            created: outcome.created,
            subscribed: true,
        }))
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.subscribe_failed",
                error = %(err.to_string())
            );
        })
}

pub(crate) async fn channel_unsubscribe(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ChannelUnsubscribeRequest>,
) -> HttpResult {
    let span = tracing::info_span!("gateway.channel.unsubscribe");
    let fut = async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        let route = state
            .device_registry
            .get(device_key.as_str())
            .ok_or_else(|| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "channel.unsubscribe_rejected",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    reason = %("device_key_not_found")
                );
                Error::validation_code("device_key not found", "device_key_not_found")
            })?;
        let channel_id = ChannelId::parse(&payload.channel_id)?;

        let removed = match route.channel_type {
            DeviceChannelType::Private => {
                if !state.private_channel_enabled {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.unsubscribe_rejected",
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        reason = %("private_channel_disabled")
                    );
                    return Ok(crate::api::err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "private channel is disabled",
                    ));
                }
                let Some(private_state) = state.private.as_ref() else {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.unsubscribe_rejected",
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        reason = %("private_runtime_unavailable")
                    );
                    return Ok(crate::api::err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "private channel runtime is unavailable",
                    ));
                };
                let device_id = derive_private_device_id(device_key.as_str());
                state
                    .store
                    .private_unsubscribe_channel(channel_id.into_inner(), device_id)
                    .await?;
                let _cleared = clear_private_pending_for_channel(
                    &state,
                    private_state,
                    device_id,
                    channel_id.into_inner(),
                )
                .await?;
                true
            }
            _ => {
                state
                    .store
                    .unsubscribe_channel_for_device_key(
                        channel_id.into_inner(),
                        device_key.as_str(),
                    )
                    .await?
            }
        };

        if removed {
            append_subscription_audit(
                &state,
                channel_id.into_inner(),
                device_key.as_str(),
                "unsubscribe",
                &route,
            )
            .await?;
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.unsubscribe_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            channel_id = %(crate::util::redact_text(channel_id.to_string())),
            removed = (removed),
            channel_type = %(route.channel_type.as_str())
        );

        Ok(crate::api::ok(ChannelUnsubscribeResponse {
            channel_id: channel_id.to_string(),
            removed,
        }))
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.unsubscribe_failed",
                error = %(err.to_string())
            );
        })
}
