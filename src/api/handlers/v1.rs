use std::collections::HashSet;

use axum::{extract::State, http::StatusCode};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        ApiJson, Error, HttpResult, deserialize_empty_as_none, deserialize_platform,
        format_channel_id, normalize_channel_alias, parse_channel_id, validate_channel_password,
    },
    app::AppState,
    device_registry::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord},
    private::protocol::{PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope},
    storage::{DeviceInfo, DeviceRegistryRoute, Platform, StoreError},
};

use super::watch_light::quantize_watch_payload;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegisterRequest {
    #[serde(deserialize_with = "deserialize_platform")]
    pub platform: Platform,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub device_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceRegisterResponse {
    pub device_key: String,
}

pub(crate) async fn v1_device_register(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceRegisterRequest>,
) -> HttpResult {
    if let Some(device_key) = payload.device_key.as_deref()
        && !state.api_rate_limiter.allow_device(device_key)
    {
        return Err(Error::TooBusy);
    }
    let platform = platform_str(payload.platform);
    let device_key = state
        .device_registry
        .register_device(platform, payload.device_key.as_deref())
        .map_err(Error::Internal)?;
    let route = state
        .device_registry
        .get(&device_key)
        .ok_or_else(|| Error::Internal("device route missing after register".to_string()))?;
    persist_device_registry_route(&state, &device_key, &route).await?;
    Ok(crate::api::ok(DeviceRegisterResponse { device_key }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceChannelUpsertRequest {
    pub device_key: String,
    pub channel_type: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub provider_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceChannelDeleteRequest {
    pub device_key: String,
    pub channel_type: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceChannelResponse {
    pub device_key: String,
    pub channel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_token: Option<String>,
}

pub(crate) async fn v1_device_channel_upsert(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceChannelUpsertRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    let next_type = DeviceChannelType::parse(&payload.channel_type)
        .ok_or_else(|| Error::validation("invalid channel_type"))?;

    let (resolved_device_key, previous) =
        ensure_device_key_for_channel_upsert(&state, device_key, next_type).await?;
    let next_provider_token = normalize_provider_token_for_route(
        next_type,
        previous.platform.as_str(),
        payload.provider_token.as_deref(),
    )?;
    let previous_provider_token = normalized_optional_token(previous.provider_token.as_deref());
    let next_provider_token_ref = normalized_optional_token(next_provider_token.as_deref());
    if previous.channel_type == next_type && previous_provider_token == next_provider_token_ref {
        return Ok(crate::api::ok(DeviceChannelResponse {
            device_key: resolved_device_key.to_string(),
            channel_type: previous.channel_type.as_str().to_string(),
            provider_token: previous.provider_token,
        }));
    }

    cleanup_old_channel_state(
        &state,
        resolved_device_key.as_str(),
        previous.platform.as_str(),
        &previous.channel_type,
        Some(&next_type),
        previous.provider_token.as_deref(),
        next_provider_token.as_deref(),
    )
    .await?;

    let updated = state
        .device_registry
        .update_channel(resolved_device_key.as_str(), next_type, next_provider_token)
        .map_err(Error::Internal)?;
    persist_device_registry_route(&state, resolved_device_key.as_str(), &updated).await?;

    Ok(crate::api::ok(DeviceChannelResponse {
        device_key: resolved_device_key,
        channel_type: updated.channel_type.as_str().to_string(),
        provider_token: updated.provider_token,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1ChannelSyncRequest {
    pub device_key: String,
    pub channels: Vec<V1ChannelSyncItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1ChannelSyncItem {
    pub channel_id: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct V1ChannelSyncResponse {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub channels: Vec<V1ChannelSyncResult>,
}

#[derive(Debug, Serialize)]
pub struct V1ChannelSyncResult {
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_name: Option<String>,
    pub subscribed: bool,
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

pub(crate) async fn v1_channel_sync(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1ChannelSyncRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if payload.channels.len() > 2000 {
        return Err(Error::validation("channels exceeds max limit 2000"));
    }

    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    let mut channels = Vec::with_capacity(payload.channels.len());
    let mut desired_channels = HashSet::with_capacity(payload.channels.len());
    let mut success = 0usize;

    for item in payload.channels {
        let raw_channel_id = item.channel_id.trim();
        if !state.api_rate_limiter.allow_channel(raw_channel_id) {
            channels.push(V1ChannelSyncResult {
                channel_id: raw_channel_id.to_string(),
                channel_name: None,
                subscribed: false,
                created: false,
                error: Some("channel is temporarily rate limited".to_string()),
                error_code: Some("channel_rate_limited".to_string()),
            });
            continue;
        }
        if raw_channel_id.is_empty() {
            channels.push(V1ChannelSyncResult {
                channel_id: String::new(),
                channel_name: None,
                subscribed: false,
                created: false,
                error: Some("channel_id is required".to_string()),
                error_code: Some("invalid_channel_id".to_string()),
            });
            continue;
        }
        let channel_id = match parse_channel_id(raw_channel_id) {
            Ok(value) => value,
            Err(err) => {
                channels.push(V1ChannelSyncResult {
                    channel_id: raw_channel_id.to_string(),
                    channel_name: None,
                    subscribed: false,
                    created: false,
                    error: Some(err.to_string()),
                    error_code: Some("invalid_channel_id".to_string()),
                });
                continue;
            }
        };
        let channel_id_text = format_channel_id(&channel_id);
        let password = match validate_channel_password(&item.password) {
            Ok(value) => value,
            Err(err) => {
                channels.push(V1ChannelSyncResult {
                    channel_id: channel_id_text,
                    channel_name: None,
                    subscribed: false,
                    created: false,
                    error: Some(err.to_string()),
                    error_code: Some("invalid_password".to_string()),
                });
                continue;
            }
        };

        match sync_single_channel(&state, device_key, &route, channel_id, password).await {
            Ok((channel_name, created)) => {
                success += 1;
                desired_channels.insert(channel_id);
                channels.push(V1ChannelSyncResult {
                    channel_id: channel_id_text,
                    channel_name: Some(channel_name),
                    subscribed: true,
                    created,
                    error: None,
                    error_code: None,
                });
            }
            Err((error_code, message)) => {
                channels.push(V1ChannelSyncResult {
                    channel_id: channel_id_text,
                    channel_name: None,
                    subscribed: false,
                    created: false,
                    error: Some(message),
                    error_code: Some(error_code.to_string()),
                });
            }
        }
    }

    let failed = channels.len().saturating_sub(success);
    if failed == 0 {
        reconcile_synced_channels(&state, device_key, &route, &desired_channels).await?;
    }

    Ok(crate::api::ok(V1ChannelSyncResponse {
        total: channels.len(),
        success,
        failed,
        channels,
    }))
}

async fn reconcile_synced_channels(
    state: &AppState,
    device_key: &str,
    route: &DeviceRouteRecord,
    desired_channels: &HashSet<[u8; 16]>,
) -> Result<(), Error> {
    match route.channel_type {
        DeviceChannelType::Private => {
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            let existing_channels = state
                .store
                .list_private_subscribed_channels_for_device_async(device_id)
                .await
                .map_err(|err| Error::Internal(err.to_string()))?;
            let mut removed_channels = HashSet::new();
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .private_unsubscribe_channel_async(channel_id, device_id)
                    .await
                    .map_err(|err| Error::Internal(err.to_string()))?;
                removed_channels.insert(channel_id);
            }
            if let Some(private_state) = state.private.as_ref()
                && !removed_channels.is_empty()
            {
                clear_private_pending_for_channels(
                    state,
                    private_state,
                    device_id,
                    &removed_channels,
                )
                .await
                .map_err(|err| Error::Internal(err.to_string()))?;
            }
        }
        DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns => {
            let provider_token = route
                .provider_token
                .as_deref()
                .filter(|token| !token.trim().is_empty())
                .ok_or_else(|| Error::validation("provider channel requires provider_token"))?;
            let platform = platform_from_str(route.platform.as_str())?;
            let existing_channels = state
                .store
                .list_subscribed_channels_for_device_async(provider_token, platform)
                .await
                .map_err(|err| Error::Internal(err.to_string()))?;
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .unsubscribe_channel_async(channel_id, provider_token, platform)
                    .await
                    .map_err(|err| Error::Internal(err.to_string()))?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn v1_device_channel_delete(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceChannelDeleteRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    let current_type = DeviceChannelType::parse(&payload.channel_type)
        .ok_or_else(|| Error::validation("invalid channel_type"))?;
    let current = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;

    cleanup_old_channel_state(
        &state,
        device_key,
        current.platform.as_str(),
        &current_type,
        None,
        current.provider_token.as_deref(),
        None,
    )
    .await?;

    let updated = state
        .device_registry
        .clear_channel(device_key, current_type)
        .map_err(Error::Internal)?;
    persist_device_registry_route(&state, device_key, &updated).await?;

    Ok(crate::api::ok(DeviceChannelResponse {
        device_key: device_key.to_string(),
        channel_type: updated.channel_type.as_str().to_string(),
        provider_token: updated.provider_token,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1ChannelSubscribeRequest {
    pub device_key: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub channel_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub channel_name: Option<String>,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct V1ChannelSubscribeResponse {
    pub channel_id: String,
    pub channel_name: String,
    pub created: bool,
    pub subscribed: bool,
}

pub(crate) async fn v1_channel_subscribe(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1ChannelSubscribeRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if let Some(channel_id) = payload.channel_id.as_deref()
        && !state.api_rate_limiter.allow_channel(channel_id)
    {
        return Err(Error::TooBusy);
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;

    let channel_id = match payload.channel_id.as_deref() {
        Some(raw) => Some(parse_channel_id(raw)?),
        None => None,
    };
    let channel_name = match payload.channel_name.as_deref() {
        Some(raw) => Some(normalize_channel_alias(raw)?),
        None => None,
    };
    if channel_id.is_some() == channel_name.is_some() {
        return Err(Error::validation(
            "must provide either channel_id or channel_name",
        ));
    }
    let password = validate_channel_password(&payload.password)?;

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
                .upsert_private_channel_async(channel_id, channel_name.as_deref(), password)
                .await?;
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            state
                .store
                .private_subscribe_channel_async(out.channel_id, device_id)
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
            let platform = platform_from_str(route.platform.as_str())?;
            state
                .store
                .subscribe_channel_async(
                    channel_id,
                    channel_name.as_deref(),
                    password,
                    provider_token,
                    platform,
                )
                .await?
        }
    };

    Ok(crate::api::ok(V1ChannelSubscribeResponse {
        channel_id: format_channel_id(&outcome.channel_id),
        channel_name: outcome.alias,
        created: outcome.created,
        subscribed: true,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1ChannelUnsubscribeRequest {
    pub device_key: String,
    pub channel_id: String,
}

#[derive(Debug, Serialize)]
pub struct V1ChannelUnsubscribeResponse {
    pub channel_id: String,
    pub removed: bool,
}

pub(crate) async fn v1_channel_unsubscribe(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1ChannelUnsubscribeRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if !state
        .api_rate_limiter
        .allow_channel(payload.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    let channel_id = parse_channel_id(&payload.channel_id)?;

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
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            state
                .store
                .private_unsubscribe_channel_async(channel_id, device_id)
                .await?;
            let _cleared =
                clear_private_pending_for_channel(&state, private_state, device_id, channel_id)
                    .await?;
            true
        }
        _ => {
            let provider_token = route
                .provider_token
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| Error::validation("provider_token required for provider channel"))?;
            let platform = platform_from_str(route.platform.as_str())?;
            state
                .store
                .unsubscribe_channel_async(channel_id, provider_token, platform)
                .await?
        }
    };

    Ok(crate::api::ok(V1ChannelUnsubscribeResponse {
        channel_id: format_channel_id(&channel_id),
        removed,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1PullRequest {
    pub device_key: String,
    pub channel_id: String,
    pub password: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct V1PullItem {
    pub delivery_id: String,
    pub payload: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct V1PullResponse {
    pub items: Vec<V1PullItem>,
}

pub(crate) async fn v1_messages_pull(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1PullRequest>,
) -> HttpResult {
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
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if !state
        .api_rate_limiter
        .allow_channel(payload.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    ensure_private_route(&route)?;

    let channel_id = parse_channel_id(&payload.channel_id)?;
    let password = validate_channel_password(&payload.password)?;
    let channel_exists = state
        .store
        .channel_info_with_password_async(channel_id, password)
        .await?
        .is_some();
    if !channel_exists {
        return Err(Error::validation("invalid channel credentials"));
    }

    let device_id = DeviceRegistry::derive_private_device_id(device_key);
    let limit = payload.limit.unwrap_or(200).clamp(1, 200);
    let rows = private_state.hub.pull_outbox(device_id, limit).await?;
    let expected_channel_id = format_channel_id(&channel_id);
    let mut items = Vec::new();
    for (entry, msg) in rows {
        let envelope = match postcard::from_bytes::<PrivatePayloadEnvelope>(&msg.payload) {
            Ok(v) => v,
            Err(_) => {
                ack_delivery_if_pending(private_state, device_id, entry.delivery_id.as_str())
                    .await?;
                continue;
            }
        };
        if envelope.payload_version != PRIVATE_PAYLOAD_VERSION_V1 {
            ack_delivery_if_pending(private_state, device_id, entry.delivery_id.as_str()).await?;
            continue;
        }
        let payload_map = envelope.data;
        let channel_id = payload_map
            .get("channel_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if channel_id != expected_channel_id {
            continue;
        }
        let output_payload = if route.platform.eq_ignore_ascii_case("watchos") {
            quantize_watch_payload(&payload_map)
        } else {
            payload_map
        };
        items.push(V1PullItem {
            delivery_id: entry.delivery_id,
            payload: output_payload,
        });
    }

    Ok(crate::api::ok(V1PullResponse { items }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1AckRequest {
    pub device_key: String,
    pub delivery_id: String,
}

#[derive(Debug, Serialize)]
pub struct V1AckResponse {
    pub acked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1AckBatchRequest {
    pub device_key: String,
    pub delivery_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct V1AckBatchResponse {
    pub acked_count: usize,
    pub acked_delivery_ids: Vec<String>,
}

pub(crate) async fn v1_messages_ack(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1AckRequest>,
) -> HttpResult {
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
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if payload.delivery_id.trim().is_empty() {
        return Err(Error::validation("delivery_id is required"));
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    ensure_private_route(&route)?;
    let device_id = DeviceRegistry::derive_private_device_id(device_key);
    ack_delivery_if_pending(private_state, device_id, &payload.delivery_id).await?;
    Ok(crate::api::ok(V1AckResponse { acked: true }))
}

pub(crate) async fn v1_messages_ack_batch(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<V1AckBatchRequest>,
) -> HttpResult {
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
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    if !state.api_rate_limiter.allow_device(device_key) {
        return Err(Error::TooBusy);
    }
    if payload.delivery_ids.len() > 2_000 {
        return Err(Error::validation("delivery_ids exceeds max limit 2000"));
    }
    let mut unique = HashSet::with_capacity(payload.delivery_ids.len());
    let mut delivery_ids = Vec::with_capacity(payload.delivery_ids.len());
    for raw in payload.delivery_ids {
        let delivery_id = raw.trim();
        if delivery_id.is_empty() {
            continue;
        }
        if unique.insert(delivery_id.to_string()) {
            delivery_ids.push(delivery_id.to_string());
        }
    }
    if delivery_ids.is_empty() {
        return Err(Error::validation("delivery_ids is required"));
    }
    let route = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    ensure_private_route(&route)?;
    let device_id = DeviceRegistry::derive_private_device_id(device_key);
    let mut acked_delivery_ids = Vec::with_capacity(delivery_ids.len());
    for delivery_id in delivery_ids {
        ack_delivery_if_pending(private_state, device_id, &delivery_id).await?;
        acked_delivery_ids.push(delivery_id);
    }
    Ok(crate::api::ok(V1AckBatchResponse {
        acked_count: acked_delivery_ids.len(),
        acked_delivery_ids,
    }))
}

async fn ack_delivery_if_pending(
    private_state: &crate::private::PrivateState,
    device_id: [u8; 16],
    delivery_id: &str,
) -> Result<(), Error> {
    let _ = private_state
        .complete_terminal_delivery(device_id, delivery_id, None)
        .await?;
    Ok(())
}

async fn clear_private_pending_for_channel(
    state: &AppState,
    private_state: &crate::private::PrivateState,
    device_id: [u8; 16],
    channel_id: [u8; 16],
) -> Result<usize, Error> {
    let mut singleton = HashSet::with_capacity(1);
    singleton.insert(channel_id);
    clear_private_pending_for_channels(state, private_state, device_id, &singleton).await
}

async fn clear_private_pending_for_channels(
    state: &AppState,
    private_state: &crate::private::PrivateState,
    device_id: [u8; 16],
    channel_ids: &HashSet<[u8; 16]>,
) -> Result<usize, Error> {
    if channel_ids.is_empty() {
        return Ok(0);
    }
    const MAX_PENDING_SCAN_PER_UNSUBSCRIBE: usize = 200_000;
    let expected_channel_ids: HashSet<String> = channel_ids.iter().map(format_channel_id).collect();
    let entries = state
        .store
        .list_private_outbox_async(device_id, MAX_PENDING_SCAN_PER_UNSUBSCRIBE)
        .await?;
    let mut cleared = 0usize;
    for entry in entries {
        let Some(message) = state
            .store
            .load_private_message_async(entry.delivery_id.as_str())
            .await?
        else {
            continue;
        };
        let envelope = match postcard::from_bytes::<PrivatePayloadEnvelope>(&message.payload) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if envelope.payload_version != PRIVATE_PAYLOAD_VERSION_V1 {
            continue;
        }
        let payload_channel_id = envelope
            .data
            .get("channel_id")
            .map(String::as_str)
            .map(str::trim)
            .unwrap_or_default();
        if !expected_channel_ids.contains(payload_channel_id) {
            continue;
        }
        let _ = private_state
            .complete_terminal_delivery(device_id, entry.delivery_id.as_str(), None)
            .await?;
        cleared = cleared.saturating_add(1);
    }
    Ok(cleared)
}

async fn cleanup_old_channel_state(
    state: &AppState,
    device_key: &str,
    device_platform: &str,
    old_channel_type: &DeviceChannelType,
    next_channel_type: Option<&DeviceChannelType>,
    old_provider_token: Option<&str>,
    next_provider_token: Option<&str>,
) -> Result<(), Error> {
    if let Some(next_type) = next_channel_type {
        if next_type == old_channel_type {
            // No route transition; keep existing channel state intact.
            // For provider channels, only retire old token if the token actually changed.
            if matches!(
                old_channel_type,
                DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns
            ) {
                let old_token = old_provider_token
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let new_token = next_provider_token
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                if old_token.is_some()
                    && old_token != new_token
                    && let Some(token) = old_token
                {
                    let platform = platform_from_channel_type(*old_channel_type)?;
                    let result = if let Some(next_token) = new_token {
                        state
                            .store
                            .migrate_device_subscriptions_async(token, next_token, platform)
                            .await
                    } else {
                        state.store.retire_device_async(token, platform).await
                    };
                    match result {
                        Ok(_removed) => {}
                        Err(_err) => {}
                    }
                }
            }
            return Ok(());
        }

        // Provider/private切换只在 Android/Windows 设备上执行历史订阅清理。
        // Apple 平台在 upsert 切换时不做自动清理，避免误删订阅。
        let platform = platform_from_str(device_platform)?;
        if !matches!(platform, Platform::ANDROID | Platform::WINDOWS) {
            return Ok(());
        }
    }

    match old_channel_type {
        DeviceChannelType::Private => {
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            let result = state
                .store
                .delete_private_device_state_async(device_id)
                .await;
            match result {
                Ok(()) => {}
                Err(_err) => {}
            }
        }
        DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns => {
            if let Some(token) = old_provider_token {
                let platform = platform_from_channel_type(*old_channel_type)?;
                let result = state.store.retire_device_async(token, platform).await;
                match result {
                    Ok(_removed) => {}
                    Err(_err) => {}
                }
            }
        }
    }
    Ok(())
}

async fn sync_single_channel(
    state: &AppState,
    device_key: &str,
    route: &DeviceRouteRecord,
    channel_id: [u8; 16],
    password: &str,
) -> Result<(String, bool), (&'static str, String)> {
    match route.channel_type {
        DeviceChannelType::Private => {
            if !state.private_channel_enabled {
                return Err((
                    "private_channel_disabled",
                    "private channel is disabled".to_string(),
                ));
            }
            let outcome = state
                .store
                .upsert_private_channel_async(Some(channel_id), None, password)
                .await
                .map_err(map_sync_store_error)?;
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            state
                .store
                .private_subscribe_channel_async(channel_id, device_id)
                .await
                .map_err(map_sync_store_error)?;
            Ok((outcome.alias, outcome.created))
        }
        _ => {
            let provider_token = route
                .provider_token
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    (
                        "provider_token_missing",
                        "provider channel requires provider_token".to_string(),
                    )
                })?;
            let platform = platform_from_str(route.platform.as_str())
                .map_err(|err| ("invalid_platform", err.to_string()))?;
            let outcome = state
                .store
                .subscribe_channel_async(Some(channel_id), None, password, provider_token, platform)
                .await
                .map_err(map_sync_store_error)?;
            Ok((outcome.alias, outcome.created))
        }
    }
}

fn map_sync_store_error(err: StoreError) -> (&'static str, String) {
    match err {
        StoreError::InvalidDeviceToken => (
            "invalid_provider_token",
            "provider token is invalid for the current platform".to_string(),
        ),
        StoreError::ChannelPasswordMismatch => (
            "password_mismatch",
            "channel exists but password mismatch".to_string(),
        ),
        StoreError::ChannelNotFound => (
            "channel_not_found",
            "channel not found on gateway".to_string(),
        ),
        other => ("store_error", other.to_string()),
    }
}

fn ensure_private_route(route: &DeviceRouteRecord) -> Result<(), Error> {
    if route.channel_type != DeviceChannelType::Private {
        return Err(Error::validation_code(
            "private channel route required for this endpoint",
            "private_route_required",
        ));
    }
    Ok(())
}

fn normalized_optional_token(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|item| !item.is_empty())
}

fn normalize_provider_token_for_route(
    channel_type: DeviceChannelType,
    platform: &str,
    provider_token: Option<&str>,
) -> Result<Option<String>, Error> {
    match channel_type {
        DeviceChannelType::Private => {
            if normalized_optional_token(provider_token).is_some() {
                return Err(Error::validation(
                    "provider_token is not allowed for private channel",
                ));
            }
            Ok(None)
        }
        _ => {
            let token = normalized_optional_token(provider_token)
                .ok_or_else(|| Error::validation("provider_token required for provider channel"))?;
            let route_platform = platform_from_str(platform)?;
            match channel_type {
                DeviceChannelType::Apns
                    if !matches!(
                        route_platform,
                        Platform::IOS | Platform::MACOS | Platform::WATCHOS
                    ) =>
                {
                    return Err(Error::validation(
                        "channel_type apns requires apple platform",
                    ));
                }
                DeviceChannelType::Fcm if route_platform != Platform::ANDROID => {
                    return Err(Error::validation(
                        "channel_type fcm requires android platform",
                    ));
                }
                DeviceChannelType::Wns if route_platform != Platform::WINDOWS => {
                    return Err(Error::validation(
                        "channel_type wns requires windows platform",
                    ));
                }
                _ => {}
            }
            DeviceInfo::from_token(route_platform, token)
                .map_err(|_| Error::validation("invalid provider_token"))?;
            Ok(Some(token.to_string()))
        }
    }
}

async fn ensure_device_key_for_channel_upsert(
    state: &AppState,
    requested_device_key: &str,
    channel_type: DeviceChannelType,
) -> Result<(String, DeviceRouteRecord), Error> {
    if let Some(route) = state.device_registry.get(requested_device_key) {
        return Ok((requested_device_key.to_string(), route));
    }

    let bootstrap_platform = bootstrap_platform_for_channel_type(channel_type);
    let resolved_device_key = state
        .device_registry
        .register_device(bootstrap_platform, Some(requested_device_key))
        .map_err(Error::Internal)?;
    let route = state
        .device_registry
        .get(&resolved_device_key)
        .ok_or_else(|| Error::Internal("device route missing after register".to_string()))?;
    persist_device_registry_route(state, &resolved_device_key, &route).await?;
    Ok((resolved_device_key, route))
}

fn bootstrap_platform_for_channel_type(channel_type: DeviceChannelType) -> &'static str {
    match channel_type {
        DeviceChannelType::Apns | DeviceChannelType::Private => "ios",
        DeviceChannelType::Fcm => "android",
        DeviceChannelType::Wns => "windows",
    }
}

fn platform_from_channel_type(channel_type: DeviceChannelType) -> Result<Platform, Error> {
    match channel_type {
        DeviceChannelType::Apns => Ok(Platform::IOS),
        DeviceChannelType::Fcm => Ok(Platform::ANDROID),
        DeviceChannelType::Wns => Ok(Platform::WINDOWS),
        DeviceChannelType::Private => Err(Error::validation("private has no provider platform")),
    }
}

fn platform_from_str(raw: &str) -> Result<Platform, Error> {
    raw.parse()
        .map_err(|_| Error::validation("invalid platform"))
}

fn platform_str(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

async fn persist_device_registry_route(
    state: &AppState,
    device_key: &str,
    route: &DeviceRouteRecord,
) -> Result<(), Error> {
    state
        .store
        .upsert_device_registry_route_async(&DeviceRegistryRoute {
            device_key: device_key.to_string(),
            platform: route.platform.clone(),
            channel_type: route.channel_type.as_str().to_string(),
            provider_token: route.provider_token.clone(),
            updated_at: route.updated_at,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DeviceChannelDeleteRequest, DeviceChannelUpsertRequest, Error, V1ChannelSyncRequest,
        ensure_private_route,
    };
    use crate::device_registry::{DeviceChannelType, DeviceRouteRecord};

    #[test]
    fn device_channel_delete_rejects_provider_token() {
        let raw = r#"{
            "device_key":"dev-1",
            "channel_type":"apns",
            "provider_token":"should-not-be-here"
        }"#;
        let parsed = serde_json::from_str::<DeviceChannelDeleteRequest>(raw);
        assert!(
            parsed.is_err(),
            "delete request should reject provider_token"
        );
    }

    #[test]
    fn device_channel_upsert_accepts_provider_token() {
        let raw = r#"{
            "device_key":"dev-1",
            "channel_type":"apns",
            "provider_token":"token-1"
        }"#;
        let parsed = serde_json::from_str::<DeviceChannelUpsertRequest>(raw)
            .expect("upsert request should accept provider_token");
        assert_eq!(parsed.provider_token.as_deref(), Some("token-1"));
    }

    #[test]
    fn channel_sync_item_rejects_unknown_fields() {
        let raw = r#"{
            "device_key":"dev-1",
            "channels":[{"channel_id":"abc","password":"12345678","extra":"x"}]
        }"#;
        let parsed = serde_json::from_str::<V1ChannelSyncRequest>(raw);
        assert!(
            parsed.is_err(),
            "channel sync item should reject unknown fields"
        );
    }

    #[test]
    fn ensure_private_route_accepts_private_channel_type() {
        let route = DeviceRouteRecord {
            platform: "android".to_string(),
            channel_type: DeviceChannelType::Private,
            provider_token: None,
            updated_at: 0,
        };
        ensure_private_route(&route).expect("private route should be accepted");
    }

    #[test]
    fn ensure_private_route_rejects_provider_channel_type() {
        let route = DeviceRouteRecord {
            platform: "ios".to_string(),
            channel_type: DeviceChannelType::Apns,
            provider_token: Some("token".to_string()),
            updated_at: 0,
        };
        let err = ensure_private_route(&route).expect_err("provider route should be rejected");
        match err {
            Error::Validation {
                code: Some(code), ..
            } => assert_eq!(code.as_ref(), "private_route_required"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
