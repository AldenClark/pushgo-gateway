use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, Error, HttpResult, deserialize_empty_as_none},
    app::AppState,
    routing::{DeviceChannelType, DeviceRouteRecord, derive_private_device_id},
    storage::{DeviceInfo, DeviceRouteAuditWrite, DeviceRouteRecordRow, Platform},
};

use super::shared::{normalized_optional_token, platform_from_channel_type, platform_from_str};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceChannelUpsertRequest {
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
pub(crate) struct DeviceChannelDeleteRequest {
    pub device_key: String,
    pub channel_type: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceChannelResponse {
    pub device_key: String,
    pub channel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_token: Option<String>,
    pub issued_new_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_reason: Option<String>,
}

impl DeviceChannelUpsertRequest {
    fn requested_platform(&self) -> Result<Option<Platform>, Error> {
        self.platform.as_deref().map(platform_from_str).transpose()
    }

    fn requested_channel_type(&self) -> Result<DeviceChannelType, Error> {
        DeviceChannelType::parse(&self.channel_type)
            .ok_or_else(|| Error::validation("invalid channel_type"))
    }

    fn normalized_provider_token(
        &self,
        platform: Platform,
        channel_type: DeviceChannelType,
    ) -> Result<Option<String>, Error> {
        match channel_type {
            DeviceChannelType::Private => {
                if normalized_optional_token(self.provider_token.as_deref()).is_some() {
                    return Err(Error::validation(
                        "provider_token is not allowed for private channel",
                    ));
                }
                Ok(None)
            }
            _ => {
                let token =
                    normalized_optional_token(self.provider_token.as_deref()).ok_or_else(|| {
                        Error::validation("provider_token required for provider channel")
                    })?;
                match channel_type {
                    DeviceChannelType::Apns
                        if !matches!(
                            platform,
                            Platform::IOS | Platform::MACOS | Platform::WATCHOS
                        ) =>
                    {
                        return Err(Error::validation(
                            "channel_type apns requires apple platform",
                        ));
                    }
                    DeviceChannelType::Fcm if platform != Platform::ANDROID => {
                        return Err(Error::validation(
                            "channel_type fcm requires android platform",
                        ));
                    }
                    DeviceChannelType::Wns if platform != Platform::WINDOWS => {
                        return Err(Error::validation(
                            "channel_type wns requires windows platform",
                        ));
                    }
                    _ => {}
                }
                DeviceInfo::from_token(platform, token)
                    .map_err(|_| Error::validation("invalid provider_token"))?;
                Ok(Some(token.to_string()))
            }
        }
    }
}

impl DeviceChannelDeleteRequest {
    fn device_key(&self) -> Result<&str, Error> {
        let device_key = self.device_key.trim();
        if device_key.is_empty() {
            return Err(Error::validation("device_key is required"));
        }
        Ok(device_key)
    }

    fn requested_channel_type(&self) -> Result<DeviceChannelType, Error> {
        DeviceChannelType::parse(&self.channel_type)
            .ok_or_else(|| Error::validation("invalid channel_type"))
    }
}

impl DeviceRouteRecord {
    fn as_route_row(&self, device_key: &str) -> DeviceRouteRecordRow {
        DeviceRouteRecordRow::from_registry_record(device_key, self)
    }

    fn provider_token_ref(&self) -> Option<&str> {
        normalized_optional_token(self.provider_token.as_deref())
    }

    fn cleanup<'a>(
        &'a self,
        device_key: &'a str,
        next_channel_type: Option<DeviceChannelType>,
        next_provider_token: Option<&'a str>,
    ) -> DeviceRouteCleanup<'a> {
        DeviceRouteCleanup {
            device_key,
            device_platform: self.platform,
            old_channel_type: self.channel_type,
            next_channel_type,
            old_provider_token: self.provider_token_ref(),
            next_provider_token,
        }
    }

    fn persisted_change<'a>(
        &'a self,
        device_key: &'a str,
        previous: Option<&'a DeviceRouteRecord>,
        issue_reason: Option<&'a str>,
    ) -> DeviceRouteChange<'a> {
        DeviceRouteChange {
            device_key,
            previous,
            next: self,
            issue_reason,
        }
    }
}

struct DeviceRouteCleanup<'a> {
    device_key: &'a str,
    device_platform: Platform,
    old_channel_type: DeviceChannelType,
    next_channel_type: Option<DeviceChannelType>,
    old_provider_token: Option<&'a str>,
    next_provider_token: Option<&'a str>,
}

impl DeviceRouteCleanup<'_> {
    async fn apply(self, state: &AppState) -> Result<(), Error> {
        if let Some(next_type) = self.next_channel_type {
            if next_type == self.old_channel_type {
                return self.cleanup_same_provider_route(state).await;
            }
            self.migrate_pending_deliveries(state, next_type).await?;
        }

        match self.old_channel_type {
            DeviceChannelType::Private => {
                let device_id = derive_private_device_id(self.device_key);
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
                if let Some(token) = self.old_provider_token {
                    let platform =
                        platform_from_channel_type(self.old_channel_type, self.device_platform)?;
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

    async fn cleanup_same_provider_route(self, state: &AppState) -> Result<(), Error> {
        if !matches!(
            self.old_channel_type,
            DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns
        ) {
            return Ok(());
        }
        if self.old_provider_token.is_none() || self.old_provider_token == self.next_provider_token
        {
            return Ok(());
        }
        let Some(old_token) = self.old_provider_token else {
            return Ok(());
        };
        let platform = platform_from_channel_type(self.old_channel_type, self.device_platform)?;
        if let Some(next_token) = self.next_provider_token {
            state
                .store
                .migrate_device_subscriptions(old_token, next_token, platform)
                .await
        } else {
            state.store.retire_device(old_token, platform).await
        }
        .map_err(|err| {
            Error::Internal(format!(
                "failed to cleanup old provider channel state: {err}"
            ))
        })?;
        Ok(())
    }

    async fn migrate_pending_deliveries(
        &self,
        state: &AppState,
        next_type: DeviceChannelType,
    ) -> Result<(), Error> {
        let device_id = derive_private_device_id(self.device_key);
        match (self.old_channel_type, next_type) {
            (
                DeviceChannelType::Private,
                DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns,
            ) => {
                let Some(next_provider_token) = self.next_provider_token else {
                    return Err(Error::Internal(
                        "provider token missing when migrating private pending deliveries"
                            .to_string(),
                    ));
                };
                let platform = platform_from_channel_type(next_type, self.device_platform)?;
                state
                    .store
                    .migrate_private_pending_to_provider_queue(
                        device_id,
                        platform,
                        next_provider_token,
                    )
                    .await
                    .map_err(|err| {
                        Error::Internal(format!(
                            "failed to migrate private pending deliveries to provider queue: {err}"
                        ))
                    })?;
            }
            (
                DeviceChannelType::Apns | DeviceChannelType::Fcm | DeviceChannelType::Wns,
                DeviceChannelType::Private,
            ) => {
                let ack_timeout_secs = state
                    .private
                    .as_ref()
                    .map(|private| private.config.ack_timeout_secs)
                    .unwrap_or(30);
                let migrated = state
                    .store
                    .migrate_provider_pending_to_private_outbox(device_id, ack_timeout_secs)
                    .await
                    .map_err(|err| {
                        Error::Internal(format!(
                            "failed to migrate provider pending deliveries to private outbox: {err}"
                        ))
                    })?;
                if migrated > 0
                    && let Some(private_state) = state.private.as_deref()
                {
                    private_state.request_fallback_resync();
                }
            }
            _ => {}
        }
        Ok(())
    }
}

struct DeviceRouteChange<'a> {
    device_key: &'a str,
    previous: Option<&'a DeviceRouteRecord>,
    next: &'a DeviceRouteRecord,
    issue_reason: Option<&'a str>,
}

impl DeviceRouteChange<'_> {
    async fn persist(self, state: &AppState, action: &str) -> Result<(), Error> {
        state
            .store
            .upsert_device_route(&self.next.as_route_row(self.device_key))
            .await?;
        let now = chrono::Utc::now().timestamp();
        state
            .store
            .append_device_route_audit(&DeviceRouteAuditWrite {
                device_key: self.device_key.to_string(),
                action: action.to_string(),
                old_platform: self.previous.map(|value| value.platform.name().to_string()),
                new_platform: Some(self.next.platform.name().to_string()),
                old_channel_type: self
                    .previous
                    .map(|value| value.channel_type.as_str().to_string()),
                new_channel_type: Some(self.next.channel_type.as_str().to_string()),
                old_provider_token: self.previous.and_then(|value| value.provider_token.clone()),
                new_provider_token: self.next.provider_token.clone(),
                issue_reason: self.issue_reason.map(ToString::to_string),
                created_at: now,
            })
            .await?;
        Ok(())
    }

    async fn bind_private_mapping(self, state: &AppState) -> Result<(), Error> {
        if self.next.channel_type == DeviceChannelType::Private {
            return Ok(());
        }
        let Some(provider_token) = self.next.provider_token_ref() else {
            return Ok(());
        };
        let device_id = derive_private_device_id(self.device_key);
        state
            .store
            .bind_private_token(device_id, self.next.platform, provider_token)
            .await
            .map_err(|err| {
                Error::Internal(format!("failed to bind private token mapping: {err}"))
            })?;
        Ok(())
    }
}

pub(crate) async fn device_channel_upsert(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<DeviceChannelUpsertRequest>,
) -> HttpResult {
    let next_type = payload.requested_channel_type()?;
    let requested_platform = payload.requested_platform()?;

    let resolved = DeviceKeyResolution::ensure_for_upsert(
        &state,
        payload.device_key.as_deref(),
        requested_platform,
    )
    .await?;
    let resolved_device_key = resolved.resolved_device_key;
    let previous = resolved.previous;
    let next_provider_token = payload.normalized_provider_token(previous.platform, next_type)?;
    let next_provider_token_ref = normalized_optional_token(next_provider_token.as_deref());
    if previous.channel_type == next_type
        && previous.provider_token_ref() == next_provider_token_ref
    {
        previous
            .persisted_change(
                resolved_device_key.as_str(),
                Some(&previous),
                resolved.issue_reason,
            )
            .bind_private_mapping(&state)
            .await?;
        return Ok(crate::api::ok(DeviceChannelResponse {
            device_key: resolved_device_key.to_string(),
            channel_type: previous.channel_type.as_str().to_string(),
            provider_token: previous.provider_token,
            issued_new_key: resolved.issued_new_key,
            issue_reason: resolved.issue_reason.map(ToString::to_string),
        }));
    }

    previous
        .cleanup(
            resolved_device_key.as_str(),
            Some(next_type),
            next_provider_token_ref,
        )
        .apply(&state)
        .await?;

    let updated = state
        .device_registry
        .update_channel(resolved_device_key.as_str(), next_type, next_provider_token)
        .map_err(Error::Internal)?;
    updated
        .persisted_change(
            resolved_device_key.as_str(),
            Some(&previous),
            resolved.issue_reason,
        )
        .persist(&state, "route_upsert")
        .await?;
    updated
        .persisted_change(
            resolved_device_key.as_str(),
            Some(&previous),
            resolved.issue_reason,
        )
        .bind_private_mapping(&state)
        .await?;

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
    let device_key = payload.device_key()?;
    let current_type = payload.requested_channel_type()?;
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

    current
        .cleanup(device_key, None, None)
        .apply(&state)
        .await?;

    let updated = state
        .device_registry
        .clear_channel(device_key, current_type)
        .map_err(Error::Internal)?;
    updated
        .persisted_change(device_key, Some(&current), None)
        .persist(&state, "route_delete_channel")
        .await?;

    Ok(crate::api::ok(DeviceChannelResponse {
        device_key: device_key.to_string(),
        channel_type: updated.channel_type.as_str().to_string(),
        provider_token: updated.provider_token,
        issued_new_key: false,
        issue_reason: None,
    }))
}

struct DeviceKeyResolution {
    resolved_device_key: String,
    previous: DeviceRouteRecord,
    issued_new_key: bool,
    issue_reason: Option<&'static str>,
}

impl DeviceKeyResolution {
    async fn ensure_for_upsert(
        state: &AppState,
        requested_device_key: Option<&str>,
        requested_platform: Option<Platform>,
    ) -> Result<Self, Error> {
        let requested_device_key = requested_device_key
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(device_key) = requested_device_key
            && let Some(route) = state.device_registry.get(device_key)
        {
            if let Some(requested_platform) = requested_platform
                && route.platform != requested_platform
            {
                return Self::issue_new(
                    state,
                    Some(requested_platform),
                    Some(device_key),
                    Some(route.platform.name()),
                    "platform_mismatch",
                )
                .await;
            }
            return Ok(Self {
                resolved_device_key: device_key.to_string(),
                previous: route,
                issued_new_key: false,
                issue_reason: None,
            });
        }

        Self::issue_new(
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

    async fn issue_new(
        state: &AppState,
        requested_platform: Option<Platform>,
        requested_device_key: Option<&str>,
        existing_platform: Option<&str>,
        issue_reason: &'static str,
    ) -> Result<Self, Error> {
        let platform = requested_platform.ok_or_else(|| {
            Error::validation("platform is required when issuing a new device_key")
        })?;
        let resolved_device_key = state
            .device_registry
            .register_device(platform, None)
            .map_err(Error::Internal)?;
        let route = state
            .device_registry
            .get(&resolved_device_key)
            .ok_or_else(|| {
                Error::Internal(
                    "device route missing after channel upsert auto-register".to_string(),
                )
            })?;
        route
            .persisted_change(resolved_device_key.as_str(), None, Some(issue_reason))
            .persist(state, "route_issue_new_key")
            .await?;

        if state.diagnostics_api_enabled && issue_reason == "platform_mismatch" {
            let old_key = requested_device_key.unwrap_or("");
            let old_platform = existing_platform.unwrap_or("");
            crate::util::diagnostics_log(format_args!(
                "device_key reissued: reason={} old_device_key={} old_platform={} requested_platform={} new_device_key={}",
                issue_reason,
                old_key,
                old_platform,
                platform.name(),
                resolved_device_key
            ));
        }

        Ok(Self {
            resolved_device_key,
            previous: route,
            issued_new_key: true,
            issue_reason: Some(issue_reason),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{api::Error, routing::DeviceChannelType, storage::Platform};

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

    #[test]
    fn device_channel_delete_requires_non_empty_device_key() {
        let payload = DeviceChannelDeleteRequest {
            device_key: "   ".to_string(),
            channel_type: "apns".to_string(),
        };
        let err = payload
            .device_key()
            .expect_err("empty device key should be rejected");
        match err {
            Error::Validation { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn device_channel_delete_parses_channel_type() {
        let payload = DeviceChannelDeleteRequest {
            device_key: "dev-1".to_string(),
            channel_type: "wns".to_string(),
        };
        assert_eq!(
            payload
                .requested_channel_type()
                .expect("channel type should parse"),
            DeviceChannelType::Wns
        );
    }

    #[test]
    fn device_channel_upsert_private_rejects_provider_token() {
        let payload = DeviceChannelUpsertRequest {
            device_key: None,
            channel_type: "private".to_string(),
            platform: Some("android".to_string()),
            provider_token: Some("token-1".to_string()),
        };
        let err = payload
            .normalized_provider_token(Platform::ANDROID, DeviceChannelType::Private)
            .expect_err("private route should reject provider token");
        match err {
            Error::Validation { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
