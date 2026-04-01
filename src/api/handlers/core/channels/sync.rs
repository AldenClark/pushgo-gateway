use std::collections::HashSet;

use axum::extract::State;

use crate::{
    api::{ApiJson, ChannelId, ChannelPassword, Error, HttpResult},
    app::AppState,
    routing::{DeviceChannelType, DeviceRouteRecord, derive_private_device_id},
    storage::StoreError,
};

use super::{
    audit::append_subscription_audit,
    private_cleanup::clear_private_pending_for_channels,
    types::{ChannelSyncRequest, ChannelSyncResponse, ChannelSyncResult},
};

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
        let channel_id = match ChannelId::parse(raw_channel_id) {
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
        let channel_id_text = channel_id.to_string();
        let password = match ChannelPassword::parse(&item.password) {
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

        match sync_single_channel(
            &state,
            device_key,
            &route,
            channel_id.into_inner(),
            password.as_str(),
        )
        .await
        {
            Ok((channel_name, created)) => {
                success += 1;
                desired_channels.insert(channel_id.into_inner());
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
            let device_id = derive_private_device_id(device_key);
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
            let platform = route.platform;
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
            let device_id = derive_private_device_id(device_key);
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
            let platform = route.platform;
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
