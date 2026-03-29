use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, Error, HttpResult, deserialize_empty_as_none},
    app::AppState,
    device_registry::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord},
    storage::{DeviceInfo, DeviceRouteAuditWrite, DeviceRouteRecordRow},
};

use super::shared::{
    normalized_optional_token, platform_from_channel_type, platform_from_str, platform_str,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceChannelUpsertRequest {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub device_key: Option<String>,
    pub channel_type: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub platform: Option<String>,
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
    pub issued_new_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_reason: Option<String>,
}

pub(crate) async fn device_channel_upsert(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceChannelUpsertRequest>,
) -> HttpResult {
    let next_type = DeviceChannelType::parse(&payload.channel_type)
        .ok_or_else(|| Error::validation("invalid channel_type"))?;

    let resolved = ensure_device_key_for_channel_upsert(
        &state,
        payload.device_key.as_deref(),
        payload.platform.as_deref(),
        Some(next_type),
    )
    .await?;
    let resolved_device_key = resolved.resolved_device_key;
    let previous = resolved.previous;
    let next_provider_token = normalize_provider_token_for_route(
        next_type,
        previous.platform.as_str(),
        payload.provider_token.as_deref(),
    )?;
    let previous_provider_token = normalized_optional_token(previous.provider_token.as_deref());
    let next_provider_token_ref = normalized_optional_token(next_provider_token.as_deref());
    if previous.channel_type == next_type && previous_provider_token == next_provider_token_ref {
        bind_private_binding_for_provider_route(&state, resolved_device_key.as_str(), &previous)
            .await?;
        return Ok(crate::api::ok(DeviceChannelResponse {
            device_key: resolved_device_key.to_string(),
            channel_type: previous.channel_type.as_str().to_string(),
            provider_token: previous.provider_token,
            issued_new_key: resolved.issued_new_key,
            issue_reason: resolved.issue_reason.map(ToString::to_string),
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
    persist_device_route(
        &state,
        resolved_device_key.as_str(),
        Some(&previous),
        &updated,
        "route_upsert",
        resolved.issue_reason,
    )
    .await?;
    bind_private_binding_for_provider_route(&state, resolved_device_key.as_str(), &updated).await?;

    Ok(crate::api::ok(DeviceChannelResponse {
        device_key: resolved_device_key,
        channel_type: updated.channel_type.as_str().to_string(),
        provider_token: updated.provider_token,
        issued_new_key: resolved.issued_new_key,
        issue_reason: resolved.issue_reason.map(ToString::to_string),
    }))
}

pub(crate) async fn device_channel_delete(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceChannelDeleteRequest>,
) -> HttpResult {
    let device_key = payload.device_key.trim();
    if device_key.is_empty() {
        return Err(Error::validation("device_key is required"));
    }
    let current_type = DeviceChannelType::parse(&payload.channel_type)
        .ok_or_else(|| Error::validation("invalid channel_type"))?;
    let current = state
        .device_registry
        .get(device_key)
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    if current.channel_type != current_type {
        return Err(Error::validation_code(
            "channel_type does not match current device route",
            "channel_type_mismatch",
        ));
    }

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
    persist_device_route(
        &state,
        device_key,
        Some(&current),
        &updated,
        "route_delete_channel",
        None,
    )
    .await?;

    Ok(crate::api::ok(DeviceChannelResponse {
        device_key: device_key.to_string(),
        channel_type: updated.channel_type.as_str().to_string(),
        provider_token: updated.provider_token,
        issued_new_key: false,
        issue_reason: None,
    }))
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
                        crate::storage::Platform::IOS
                            | crate::storage::Platform::MACOS
                            | crate::storage::Platform::WATCHOS
                    ) =>
                {
                    return Err(Error::validation(
                        "channel_type apns requires apple platform",
                    ));
                }
                DeviceChannelType::Fcm if route_platform != crate::storage::Platform::ANDROID => {
                    return Err(Error::validation(
                        "channel_type fcm requires android platform",
                    ));
                }
                DeviceChannelType::Wns if route_platform != crate::storage::Platform::WINDOWS => {
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
                    let platform = platform_from_channel_type(*old_channel_type, device_platform)?;
                    if let Some(next_token) = new_token {
                        state
                            .store
                            .migrate_device_subscriptions(token, next_token, platform)
                            .await
                    } else {
                        state.store.retire_device(token, platform).await
                    }
                    .map_err(|err| {
                        Error::Internal(format!(
                            "failed to cleanup old provider channel state: {err}"
                        ))
                    })?;
                }
            }
            return Ok(());
        }

        // Provider/private切换只在 Android/Windows 设备上执行历史订阅清理。
        // Apple 平台在 upsert 切换时不做自动清理，避免误删订阅。
        let platform = platform_from_str(device_platform)?;
        if !matches!(
            platform,
            crate::storage::Platform::ANDROID | crate::storage::Platform::WINDOWS
        ) {
            return Ok(());
        }
    }

    match old_channel_type {
        DeviceChannelType::Private => {
            let device_id = DeviceRegistry::derive_private_device_id(device_key);
            state
                .store
                .delete_private_device_state(device_id)
                .await
                .map_err(|err| {
                    Error::Internal(format!(
                        "failed to cleanup old private channel state: {err}"
                    ))
                })?;
        }
        DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns => {
            if let Some(token) = old_provider_token {
                let platform = platform_from_channel_type(*old_channel_type, device_platform)?;
                state
                    .store
                    .retire_device(token, platform)
                    .await
                    .map_err(|err| {
                        Error::Internal(format!(
                            "failed to retire old provider subscriptions: {err}"
                        ))
                    })?;
            }
        }
    }
    Ok(())
}

struct DeviceKeyResolution {
    resolved_device_key: String,
    previous: DeviceRouteRecord,
    issued_new_key: bool,
    issue_reason: Option<&'static str>,
}

async fn ensure_device_key_for_channel_upsert(
    state: &AppState,
    requested_device_key: Option<&str>,
    requested_platform: Option<&str>,
    _requested_channel_type: Option<DeviceChannelType>,
) -> Result<DeviceKeyResolution, Error> {
    let requested_device_key = requested_device_key
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let requested_platform = requested_platform
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(device_key) = requested_device_key
        && let Some(route) = state.device_registry.get(device_key)
    {
        if let Some(raw_platform) = requested_platform {
            let canonical_platform = platform_str(platform_from_str(raw_platform)?);
            if !route.platform.eq_ignore_ascii_case(canonical_platform) {
                return issue_new_device_key(
                    state,
                    requested_platform,
                    Some(device_key),
                    Some(route.platform.as_str()),
                    "platform_mismatch",
                )
                .await;
            }
        }
        return Ok(DeviceKeyResolution {
            resolved_device_key: device_key.to_string(),
            previous: route,
            issued_new_key: false,
            issue_reason: None,
        });
    }

    issue_new_device_key(
        state,
        requested_platform,
        requested_device_key,
        None,
        if requested_device_key.is_some() {
            "device_key_not_found"
        } else {
            "device_key_missing"
        },
    )
    .await
}

async fn issue_new_device_key(
    state: &AppState,
    requested_platform: Option<&str>,
    requested_device_key: Option<&str>,
    existing_platform: Option<&str>,
    issue_reason: &'static str,
) -> Result<DeviceKeyResolution, Error> {
    let platform = requested_platform
        .ok_or_else(|| Error::validation("platform is required when issuing a new device_key"))?;
    let canonical_platform = platform_str(platform_from_str(platform)?);
    let resolved_device_key = state
        .device_registry
        .register_device(canonical_platform, None)
        .map_err(Error::Internal)?;
    let route = state
        .device_registry
        .get(&resolved_device_key)
        .ok_or_else(|| {
            Error::Internal("device route missing after channel upsert auto-register".to_string())
        })?;
    persist_device_route(
        state,
        resolved_device_key.as_str(),
        None,
        &route,
        "route_issue_new_key",
        Some(issue_reason),
    )
    .await?;

    if state.diagnostics_api_enabled && issue_reason == "platform_mismatch" {
        let old_key = requested_device_key.unwrap_or("");
        let old_platform = existing_platform.unwrap_or("");
        crate::util::diagnostics_log(format_args!(
            "device_key reissued: reason={} old_device_key={} old_platform={} requested_platform={} new_device_key={}",
            issue_reason, old_key, old_platform, canonical_platform, resolved_device_key
        ));
    }

    Ok(DeviceKeyResolution {
        resolved_device_key,
        previous: route,
        issued_new_key: true,
        issue_reason: Some(issue_reason),
    })
}

async fn persist_device_route(
    state: &AppState,
    device_key: &str,
    previous: Option<&DeviceRouteRecord>,
    route: &DeviceRouteRecord,
    action: &str,
    issue_reason: Option<&str>,
) -> Result<(), Error> {
    state
        .store
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: route.platform.clone(),
            channel_type: route.channel_type.as_str().to_string(),
            provider_token: route.provider_token.clone(),
            updated_at: route.updated_at,
        })
        .await?;
    let now = chrono::Utc::now().timestamp();
    state
        .store
        .append_device_route_audit(&DeviceRouteAuditWrite {
            device_key: device_key.to_string(),
            action: action.to_string(),
            old_platform: previous.map(|value| value.platform.clone()),
            new_platform: Some(route.platform.clone()),
            old_channel_type: previous.map(|value| value.channel_type.as_str().to_string()),
            new_channel_type: Some(route.channel_type.as_str().to_string()),
            old_provider_token: previous.and_then(|value| value.provider_token.clone()),
            new_provider_token: route.provider_token.clone(),
            issue_reason: issue_reason.map(ToString::to_string),
            created_at: now,
        })
        .await?;
    Ok(())
}

async fn bind_private_binding_for_provider_route(
    state: &AppState,
    device_key: &str,
    route: &DeviceRouteRecord,
) -> Result<(), Error> {
    if route.channel_type == DeviceChannelType::Private {
        return Ok(());
    }
    let Some(provider_token) = normalized_optional_token(route.provider_token.as_deref()) else {
        return Ok(());
    };
    let platform = platform_from_str(route.platform.as_str())?;
    let device_id = DeviceRegistry::derive_private_device_id(device_key);
    state
        .store
        .bind_private_token(device_id, platform, provider_token)
        .await
        .map_err(|err| Error::Internal(format!("failed to bind private token mapping: {err}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DeviceChannelDeleteRequest, DeviceChannelUpsertRequest};

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
            "platform":"ios",
            "provider_token":"token-1"
        }"#;
        let parsed = serde_json::from_str::<DeviceChannelUpsertRequest>(raw)
            .expect("upsert request should accept provider_token");
        assert_eq!(parsed.platform.as_deref(), Some("ios"));
        assert_eq!(parsed.provider_token.as_deref(), Some("token-1"));
    }

    #[test]
    fn device_channel_upsert_allows_missing_device_key() {
        let raw = r#"{
            "channel_type":"private",
            "platform":"android"
        }"#;
        let parsed = serde_json::from_str::<DeviceChannelUpsertRequest>(raw)
            .expect("upsert request should allow missing device_key");
        assert_eq!(parsed.device_key, None);
    }
}
