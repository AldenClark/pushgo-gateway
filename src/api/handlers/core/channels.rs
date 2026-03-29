use std::collections::HashSet;

use axum::{extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        ApiJson, Error, HttpResult, deserialize_empty_as_none, format_channel_id,
        normalize_channel_alias, parse_channel_id, validate_channel_password,
    },
    app::AppState,
    device_registry::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord},
    private::protocol::{
        PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope as ProviderPullEnvelope,
    },
    storage::{StoreError, SubscriptionAuditWrite},
};

use super::shared::platform_from_str;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSyncRequest {
    pub device_key: String,
    pub channels: Vec<ChannelSyncItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSyncItem {
    pub channel_id: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelSyncResponse {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub channels: Vec<ChannelSyncResult>,
}

#[derive(Debug, Serialize)]
pub struct ChannelSyncResult {
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

pub(crate) async fn channel_sync(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ChannelSyncRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
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
        if raw_channel_id.is_empty() {
            channels.push(ChannelSyncResult {
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
                channels.push(ChannelSyncResult {
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
                channels.push(ChannelSyncResult {
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
                channels.push(ChannelSyncResult {
                    channel_id: channel_id_text,
                    channel_name: Some(channel_name),
                    subscribed: true,
                    created,
                    error: None,
                    error_code: None,
                });
            }
            Err((error_code, message)) => {
                channels.push(ChannelSyncResult {
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

    Ok(crate::api::ok(ChannelSyncResponse {
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
                .list_private_subscribed_channels_for_device(device_id)
                .await
                .map_err(|err| Error::Internal(err.to_string()))?;
            let mut removed_channels = HashSet::new();
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .private_unsubscribe_channel(channel_id, device_id)
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
                .list_subscribed_channels_for_device(provider_token, platform)
                .await
                .map_err(|err| Error::Internal(err.to_string()))?;
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .unsubscribe_channel(channel_id, provider_token, platform)
                    .await
                    .map_err(|err| Error::Internal(err.to_string()))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscribeRequest {
    pub device_key: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub channel_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub channel_name: Option<String>,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelSubscribeResponse {
    pub channel_id: String,
    pub channel_name: String,
    pub created: bool,
    pub subscribed: bool,
}

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
                .upsert_private_channel(channel_id, channel_name.as_deref(), password)
                .await?;
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
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
            let platform = platform_from_str(route.platform.as_str())?;
            state
                .store
                .subscribe_channel(
                    channel_id,
                    channel_name.as_deref(),
                    password,
                    provider_token,
                    platform,
                )
                .await?
        }
    };

    append_subscription_audit(&state, outcome.channel_id, device_key, "subscribe", &route).await?;

    Ok(crate::api::ok(ChannelSubscribeResponse {
        channel_id: format_channel_id(&outcome.channel_id),
        channel_name: outcome.alias,
        created: outcome.created,
        subscribed: true,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelUnsubscribeRequest {
    pub device_key: String,
    pub channel_id: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelUnsubscribeResponse {
    pub channel_id: String,
    pub removed: bool,
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
                .private_unsubscribe_channel(channel_id, device_id)
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
                .unsubscribe_channel(channel_id, provider_token, platform)
                .await?
        }
    };

    if removed {
        append_subscription_audit(&state, channel_id, device_key, "unsubscribe", &route).await?;
    }

    Ok(crate::api::ok(ChannelUnsubscribeResponse {
        channel_id: format_channel_id(&channel_id),
        removed,
    }))
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
        .list_private_outbox(device_id, MAX_PENDING_SCAN_PER_UNSUBSCRIBE)
        .await?;
    let mut cleared = 0usize;
    for entry in entries {
        let Some(message) = state
            .store
            .load_private_message(entry.delivery_id.as_str())
            .await?
        else {
            continue;
        };
        let envelope = match postcard::from_bytes::<ProviderPullEnvelope>(&message.payload) {
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
                .upsert_private_channel(Some(channel_id), None, password)
                .await
                .map_err(map_sync_store_error)?;
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            state
                .store
                .private_subscribe_channel(channel_id, device_id)
                .await
                .map_err(map_sync_store_error)?;
            append_subscription_audit(state, channel_id, device_key, "sync_subscribe", route)
                .await
                .map_err(|err| ("audit_error", err.to_string()))?;
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
                .subscribe_channel(Some(channel_id), None, password, provider_token, platform)
                .await
                .map_err(map_sync_store_error)?;
            append_subscription_audit(state, channel_id, device_key, "sync_subscribe", route)
                .await
                .map_err(|err| ("audit_error", err.to_string()))?;
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

async fn append_subscription_audit(
    state: &AppState,
    channel_id: [u8; 16],
    device_key: &str,
    action: &str,
    route: &DeviceRouteRecord,
) -> Result<(), Error> {
    let now = chrono::Utc::now().timestamp();
    state
        .store
        .append_subscription_audit(&SubscriptionAuditWrite {
            channel_id,
            device_key: device_key.to_string(),
            action: action.to_string(),
            platform: route.platform.clone(),
            channel_type: route.channel_type.as_str().to_string(),
            created_at: now,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ChannelSyncRequest;

    #[test]
    fn channel_sync_item_rejects_unknown_fields() {
        let raw = r#"{
            "device_key":"dev-1",
            "channels":[{"channel_id":"abc","password":"12345678","extra":"x"}]
        }"#;
        let parsed = serde_json::from_str::<ChannelSyncRequest>(raw);
        assert!(
            parsed.is_err(),
            "channel sync item should reject unknown fields"
        );
    }
}
