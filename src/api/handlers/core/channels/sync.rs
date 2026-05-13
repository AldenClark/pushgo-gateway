use std::collections::HashSet;

use axum::{extract::State, http::StatusCode};
use tracing::Instrument;

use crate::{
    api::{ApiJson, ApiProblem, ChannelId, ChannelPassword, Error, HttpResult},
    app::AppState,
    routing::{DeviceChannelType, DeviceRouteRecord, derive_private_device_id},
    storage::{DeviceRouteRecordRow, StoreError},
    value::DeviceKeyRef,
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
    let span = tracing::info_span!(
        "gateway.channel.sync",
        channels_total = payload.channels.len()
    );
    async move {
        let device_key = DeviceKeyRef::parse(&payload.device_key)?;
        if payload.channels.len() > 2000 {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.sync_rejected",
                device_key = %(crate::util::redact_text(device_key.as_str())),
                reason = %("channels_limit_exceeded"),
                channels_total = (payload.channels.len() as u64)
            );
            return Err(Error::validation_code(
                "channels exceeds max limit 2000",
                "channels_limit_exceeded",
            ));
        }

        let route = match state.device_registry.get(device_key.as_str()) {
            Some(route) => route,
            None => {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "channel.sync_rejected",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    reason = %("device_key_not_found")
                );
                return Err(Error::validation_code(
                    "device_key not found",
                    "device_key_not_found",
                ));
            }
        };
        state
            .store
            .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
                device_key.as_str(),
                &route,
            ))
            .await
            .map_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "channel.sync_route_upsert_failed",
                    device_key = %(crate::util::redact_text(device_key.as_str())),
                    error = %(err.to_string())
                );
                Error::Internal(err.to_string())
            })?;
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
                    problem: ApiProblem::from_legacy(
                        StatusCode::BAD_REQUEST,
                        Some("channel_id is required"),
                        Some("invalid_channel_id"),
                    ),
                });
                continue;
            }
            let channel_id = match ChannelId::parse(raw_channel_id) {
                Ok(value) => value,
                Err(err) => {
                    let detail = err.to_string();
                    channels.push(ChannelSyncResult {
                        channel_id: raw_channel_id.to_string(),
                        channel_name: None,
                        subscribed: false,
                        created: false,
                        error: Some(detail.clone()),
                        error_code: Some("invalid_channel_id".to_string()),
                        problem: ApiProblem::from_legacy(
                            StatusCode::BAD_REQUEST,
                            Some(detail.as_str()),
                            Some("invalid_channel_id"),
                        ),
                    });
                    continue;
                }
            };
            let channel_id_text = channel_id.to_string();
            let password = match ChannelPassword::parse(&item.password) {
                Ok(value) => value,
                Err(err) => {
                    let detail = err.to_string();
                    channels.push(ChannelSyncResult {
                        channel_id: channel_id_text,
                        channel_name: None,
                        subscribed: false,
                        created: false,
                        error: Some(detail.clone()),
                        error_code: Some("invalid_password".to_string()),
                        problem: ApiProblem::from_legacy(
                            StatusCode::BAD_REQUEST,
                            Some(detail.as_str()),
                            Some("invalid_password"),
                        ),
                    });
                    continue;
                }
            };

            match sync_single_channel(
                &state,
                device_key.as_str(),
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
                        problem: None,
                    });
                }
                Err((error_code, message)) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_failed",
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        channel_id = %(crate::util::redact_text(channel_id_text.as_str())),
                        error_code = %(error_code),
                        error = %(message.as_str())
                    );
                    let item_status = match error_code {
                        "channel_not_found" => StatusCode::NOT_FOUND,
                        "password_mismatch" => StatusCode::FORBIDDEN,
                        "private_channel_disabled" => StatusCode::SERVICE_UNAVAILABLE,
                        "provider_token_missing" => StatusCode::BAD_REQUEST,
                        "channel_subscriber_limit_exceeded" => StatusCode::BAD_REQUEST,
                        _ => StatusCode::BAD_REQUEST,
                    };
                    channels.push(ChannelSyncResult {
                        channel_id: channel_id_text,
                        channel_name: None,
                        subscribed: false,
                        created: false,
                        problem: ApiProblem::from_legacy(
                            item_status,
                            Some(message.as_str()),
                            Some(error_code),
                        ),
                        error: Some(message),
                        error_code: Some(error_code.to_string()),
                    });
                }
            }
        }

        let failed = channels.len().saturating_sub(success);
        if failed == 0 {
            reconcile_synced_channels(&state, device_key.as_str(), &route, &desired_channels)
                .await?;
        }

        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.sync_completed",
            device_key = %(crate::util::redact_text(device_key.as_str())),
            total = (channels.len() as u64),
            success = (success as u64),
            failed = (failed as u64)
        );

        Ok(crate::api::ok(ChannelSyncResponse {
            total: channels.len(),
            success,
            failed,
            channels,
        }))
    }
    .instrument(span)
    .await
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
                .map_err(|err| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_reconcile_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        stage = %("list_private_subscribed_channels"),
                        error = %(err.to_string())
                    );
                    Error::Internal(err.to_string())
                })?;
            let mut removed_channels = HashSet::new();
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .private_unsubscribe_channel(channel_id, device_id)
                    .await
                    .map_err(|err| {
                                                ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "channel.sync_reconcile_failed",
                            device_key = %(crate::util::redact_text(device_key)),
                            stage = %("private_unsubscribe_channel"),
                            channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                            error = %(err.to_string())
                        );
                        Error::Internal(err.to_string())
                    })?;
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
                .map_err(|err| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_reconcile_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        stage = %("clear_private_pending_for_channels"),
                        error = %(err.to_string())
                    );
                    Error::Internal(err.to_string())
                })?;
            }
        }
        DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns => {
            let existing_channels = state
                .store
                .list_subscribed_channels_for_device_key(device_key)
                .await
                .map_err(|err| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_reconcile_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        stage = %("list_subscribed_channels"),
                        error = %(err.to_string())
                    );
                    Error::Internal(err.to_string())
                })?;
            for channel_id in existing_channels {
                if desired_channels.contains(&channel_id) {
                    continue;
                }
                state
                    .store
                    .unsubscribe_channel_for_device_key(channel_id, device_key)
                    .await
                    .map_err(|err| {
                                                ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "channel.sync_reconcile_failed",
                            device_key = %(crate::util::redact_text(device_key)),
                            stage = %("unsubscribe_channel_for_device_key"),
                            channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                            error = %(err.to_string())
                        );
                        Error::Internal(err.to_string())
                    })?;
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
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "channel.sync_item_rejected",
                    device_key = %(crate::util::redact_text(device_key)),
                    channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                    reason = %("private_channel_disabled")
                );
                return Err((
                    "private_channel_disabled",
                    "private channel is disabled".to_string(),
                ));
            }
            let outcome = state
                .store
                .upsert_private_channel(Some(channel_id), None, password)
                .await
                .map_err(|err| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_store_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        stage = %("upsert_private_channel"),
                        error = %(err.to_string())
                    );
                    map_sync_store_error(err)
                })?;
            let device_id = derive_private_device_id(device_key);
            state
                .store
                .private_subscribe_channel(channel_id, device_id)
                .await
                .map_err(|err| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_store_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        stage = %("private_subscribe_channel"),
                        error = %(err.to_string())
                    );
                    map_sync_store_error(err)
                })?;
            append_subscription_audit(state, channel_id, device_key, "sync_subscribe", route)
                .await
                .map_err(|err| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_audit_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        error = %(err.to_string())
                    );
                    ("audit_error", err.to_string())
                })?;
            Ok((outcome.alias, outcome.created))
        }
        _ => {
            let provider_token = route
                .provider_token
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_rejected",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        reason = %("provider_token_missing")
                    );
                    (
                        "provider_token_missing",
                        "provider channel requires provider_token".to_string(),
                    )
                })?;
            let platform = route.platform;
            let outcome = state
                .store
                .subscribe_channel_for_device_key(
                    Some(channel_id),
                    None,
                    password,
                    device_key,
                    provider_token,
                    platform,
                )
                .await
                .map_err(|err| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_store_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        stage = %("subscribe_channel_for_device_key"),
                        error = %(err.to_string())
                    );
                    map_sync_store_error(err)
                })?;
            append_subscription_audit(state, channel_id, device_key, "sync_subscribe", route)
                .await
                .map_err(|err| {
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "channel.sync_item_audit_failed",
                        device_key = %(crate::util::redact_text(device_key)),
                        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                        error = %(err.to_string())
                    );
                    ("audit_error", err.to_string())
                })?;
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
        StoreError::DeviceNotFound => (
            "device_not_found",
            "device route is missing on gateway".to_string(),
        ),
        StoreError::ChannelPasswordMismatch => (
            "password_mismatch",
            "channel exists but password mismatch".to_string(),
        ),
        StoreError::ChannelNotFound => (
            "channel_not_found",
            "channel not found on gateway".to_string(),
        ),
        StoreError::ChannelSubscriberLimitExceeded => (
            "channel_subscriber_limit_exceeded",
            "channel subscriber limit exceeded".to_string(),
        ),
        other => ("store_error", other.to_string()),
    }
}
