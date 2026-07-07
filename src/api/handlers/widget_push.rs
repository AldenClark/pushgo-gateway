use std::collections::HashSet;

use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, Error, HttpResult, ok},
    app::AppState,
    storage::{Platform, WidgetPushSubscriptionRecord},
    value::DeviceKeyRef,
};

const WIDGET_PUSH_SCHEMA_VERSION: i32 = 1;
const WIDGET_PUSH_TOKEN_MAX_LEN: usize = 128;
const WIDGET_KIND_MAX_LEN: usize = 128;
const WIDGET_FAMILY_MAX_LEN: usize = 64;

pub(crate) const WIDGET_KIND_UNREAD: &str = "io.ethan.pushgo.widgets.unread";
pub(crate) const WIDGET_KIND_CRITICAL_EVENTS: &str = "io.ethan.pushgo.widgets.critical-events";
pub(crate) const WIDGET_KIND_OBJECT_STATUS: &str = "io.ethan.pushgo.widgets.object-status";
pub(crate) const WIDGET_KIND_WATCH_SUMMARY: &str = "io.ethan.pushgo.widgets.watch-summary";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WidgetPushSubscriptionRequest {
    device_key: String,
    platform: String,
    token: String,
    widgets: Vec<WidgetPushWidgetRequest>,
    schema_version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WidgetPushWidgetRequest {
    kind: String,
    family: String,
}

#[derive(Debug, Serialize)]
struct WidgetPushSubscriptionResponse {
    updated: bool,
    widget_count: usize,
}

pub(crate) async fn widget_push_subscription_upsert(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<WidgetPushSubscriptionRequest>,
) -> HttpResult {
    let now = chrono::Utc::now().timestamp_millis();
    let (device_key, platform, token, widgets) = payload.into_records(now)?;
    state
        .store
        .upsert_widget_push_subscriptions(
            device_key.as_str(),
            platform,
            token.as_str(),
            widgets.as_slice(),
            WIDGET_PUSH_SCHEMA_VERSION,
            now,
        )
        .await?;
    Ok(ok(WidgetPushSubscriptionResponse {
        updated: true,
        widget_count: widgets.len(),
    }))
}

impl WidgetPushSubscriptionRequest {
    fn into_records(
        self,
        now: i64,
    ) -> Result<(String, Platform, String, Vec<WidgetPushSubscriptionRecord>), Error> {
        validate_schema_version(self.schema_version)?;
        let device_key = DeviceKeyRef::parse(self.device_key.as_str())
            .map(DeviceKeyRef::into_owned)
            .map_err(|_| {
                Error::validation_code("device_key is invalid", "widget_push_device_key_invalid")
            })?;
        let platform = validate_platform(self.platform.as_str())?;
        let token = validate_token(self.token.as_str())?;
        let mut seen = HashSet::new();
        let mut widgets = Vec::new();
        for widget in self.widgets {
            let kind = validate_widget_kind(widget.kind.as_str())?;
            let family = validate_widget_family(widget.family.as_str())?;
            if !seen.insert((kind.clone(), family.clone())) {
                continue;
            }
            widgets.push(WidgetPushSubscriptionRecord {
                device_key: device_key.clone(),
                platform: platform.name().to_string(),
                token: token.clone(),
                widget_kind: kind,
                family,
                schema_version: WIDGET_PUSH_SCHEMA_VERSION,
                created_at: now,
                updated_at: now,
            });
        }
        Ok((device_key, platform, token, widgets))
    }
}

fn validate_schema_version(value: i32) -> Result<(), Error> {
    if value != WIDGET_PUSH_SCHEMA_VERSION {
        return Err(Error::validation_code(
            "unsupported widget push schema_version",
            "widget_push_schema_version_unsupported",
        ));
    }
    Ok(())
}

fn validate_platform(value: &str) -> Result<Platform, Error> {
    let platform: Platform = value.parse().map_err(|_| {
        Error::validation_code(
            "widget push platform is invalid",
            "widget_push_platform_invalid",
        )
    })?;
    match platform {
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => Ok(platform),
        Platform::ANDROID | Platform::WINDOWS | Platform::MQTT => Err(Error::validation_code(
            "widget push platform must be ios, macos, or watchos",
            "widget_push_platform_invalid",
        )),
    }
}

fn validate_token(value: &str) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > WIDGET_PUSH_TOKEN_MAX_LEN {
        return Err(Error::validation_code(
            "widget push token must be non-empty and at most 128 bytes",
            "widget_push_token_invalid",
        ));
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::validation_code(
            "widget push token must be hex encoded",
            "widget_push_token_invalid",
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn validate_widget_kind(value: &str) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > WIDGET_KIND_MAX_LEN
        || !is_supported_widget_kind(trimmed)
    {
        return Err(Error::validation_code(
            "widget kind is unsupported",
            "widget_push_widget_kind_invalid",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_widget_family(value: &str) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > WIDGET_FAMILY_MAX_LEN {
        return Err(Error::validation_code(
            "widget family is invalid",
            "widget_push_widget_family_invalid",
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn is_supported_widget_kind(value: &str) -> bool {
    matches!(
        value,
        WIDGET_KIND_UNREAD
            | WIDGET_KIND_CRITICAL_EVENTS
            | WIDGET_KIND_OBJECT_STATUS
            | WIDGET_KIND_WATCH_SUMMARY
    )
}
