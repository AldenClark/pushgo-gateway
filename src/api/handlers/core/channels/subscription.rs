use axum::{extract::State, http::StatusCode};

use crate::{
    api::{ApiJson, ChannelAlias, ChannelId, ChannelPassword, Error, HttpResult},
    app::AppState,
    routing::{DeviceChannelType, derive_private_device_id},
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
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;

    let channel_id = match payload.channel_id.as_deref() {
        Some(raw) => Some(ChannelId::parse(raw)?),
        None => None,
    };
    let channel_name = match payload.channel_name.as_deref() {
        Some(raw) => Some(ChannelAlias::parse(raw)?),
        None => None,
    };
    if channel_id.is_some() == channel_name.is_some() {
        return Err(Error::validation(
            "must provide either channel_id or channel_name",
        ));
    }
    let password = ChannelPassword::parse(&payload.password)?;

    let outcome = match route.channel_type {
        DeviceChannelType::Private => {
            if !state.private_channel_enabled {
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
            let device_id = derive_private_device_id(device_key);
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
                    Error::validation(
                        "device route is provider; provider_token required (switch route to private for private channel ops)",
                    )
                })?;
            let platform = route.platform;
            state
                .store
                .subscribe_channel(
                    channel_id.map(ChannelId::into_inner),
                    channel_name.map(ChannelAlias::as_str),
                    password.as_str(),
                    provider_token,
                    platform,
                )
                .await?
        }
    };

    append_subscription_audit(&state, outcome.channel_id, device_key, "subscribe", &route).await?;

    Ok(crate::api::ok(ChannelSubscribeResponse {
        channel_id: ChannelId::from(outcome.channel_id).to_string(),
        channel_name: outcome.alias,
        created: outcome.created,
        subscribed: true,
    }))
}

pub(crate) async fn channel_unsubscribe(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ChannelUnsubscribeRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    let channel_id = ChannelId::parse(&payload.channel_id)?;

    let removed = match route.channel_type {
        DeviceChannelType::Private => {
            if !state.private_channel_enabled {
                return Ok(crate::api::err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "private channel is disabled",
                ));
            }
            let Some(private_state) = state.private.as_ref() else {
                return Ok(crate::api::err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "private channel runtime is unavailable",
                ));
            };
            let device_id = derive_private_device_id(device_key);
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
            let provider_token = route
                .provider_token
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| Error::validation("provider_token required for provider channel"))?;
            let platform = route.platform;
            state
                .store
                .unsubscribe_channel(channel_id.into_inner(), provider_token, platform)
                .await?
        }
    };

    if removed {
        append_subscription_audit(
            &state,
            channel_id.into_inner(),
            device_key,
            "unsubscribe",
            &route,
        )
        .await?;
    }

    Ok(crate::api::ok(ChannelUnsubscribeResponse {
        channel_id: channel_id.to_string(),
        removed,
    }))
}
