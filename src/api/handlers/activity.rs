use std::sync::Arc;

use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    api::{ApiJson, Error, HttpResult, ok, parse_channel_id},
    app::AppState,
    dispatch::{ApnsJob, ProviderDeliveryPath},
    providers::apns::ApnsPayload,
    storage::{LiveActivityTokenRecord, Platform},
};

const ACTIVITY_KEY_MAX_LEN: usize = 255;
const ACTIVITY_TOKEN_MAX_LEN: usize = 512;
const IOS_LIVE_ACTIVITY_TOPIC: &str = "io.ethan.pushgo.push-type.liveactivity";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivityRegisterRequest {
    activity_key: String,
    #[serde(default)]
    channel_id: Option<String>,
    token: String,
    platform: String,
    schema_version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivityUnregisterRequest {
    activity_key: String,
    #[serde(default)]
    token: Option<String>,
    platform: String,
    schema_version: i32,
}

#[derive(Debug, Serialize)]
struct ActivityRegisterResponse {
    registered: bool,
}

#[derive(Debug, Serialize)]
struct ActivityUnregisterResponse {
    deleted: usize,
}

pub(crate) async fn activity_register(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ActivityRegisterRequest>,
) -> HttpResult {
    let record = payload.into_record(chrono::Utc::now().timestamp_millis())?;
    state.store.upsert_live_activity_token(&record).await?;
    Ok(ok(ActivityRegisterResponse { registered: true }))
}

pub(crate) async fn activity_unregister(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ActivityUnregisterRequest>,
) -> HttpResult {
    payload.validate()?;
    let deleted = state
        .store
        .delete_live_activity_token(&payload.activity_key, payload.token.as_deref())
        .await?;
    Ok(ok(ActivityUnregisterResponse { deleted }))
}

#[derive(Debug, Clone)]
pub(crate) struct EventActivityUpdate {
    pub(crate) event_id: String,
    pub(crate) action: EventActivityAction,
    pub(crate) title: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) updated_at_millis: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventActivityAction {
    Update,
    End,
}

pub(crate) async fn dispatch_event_activity_update(state: AppState, update: EventActivityUpdate) {
    let activity_key = format!("event:{}", update.event_id);
    let tokens = match state.store.list_live_activity_tokens(&activity_key).await {
        Ok(tokens) => tokens,
        Err(err) => {
            emit_activity_dispatch_skipped(&activity_key, "store_error", Some(err.to_string()));
            return;
        }
    };
    if tokens.is_empty() {
        emit_activity_dispatch_skipped(&activity_key, "no_registered_tokens", None);
        return;
    }
    let title = normalized_text(update.title.as_deref()).unwrap_or_else(|| update.event_id.clone());
    let state_text = normalized_text(update.state.as_deref());
    let severity = normalized_text(update.severity.as_deref());
    let payload = match update.action {
        EventActivityAction::Update => Arc::new(ApnsPayload::live_activity(
            title,
            state_text,
            severity,
            update.updated_at_millis,
            "update",
            IOS_LIVE_ACTIVITY_TOPIC,
        )),
        EventActivityAction::End => Arc::new(ApnsPayload::live_activity_end(
            title,
            state_text,
            severity,
            update.updated_at_millis,
            IOS_LIVE_ACTIVITY_TOPIC,
            Some(update.updated_at_millis / 1000 + 60),
        )),
    };
    for token in tokens {
        dispatch_activity_token(&state, &activity_key, token, Arc::clone(&payload));
    }
}

impl ActivityRegisterRequest {
    fn into_record(self, now_millis: i64) -> Result<LiveActivityTokenRecord, Error> {
        validate_activity_key(&self.activity_key)?;
        validate_schema_version(self.schema_version)?;
        validate_platform(&self.platform)?;
        validate_token(&self.token)?;
        let channel_id = self
            .channel_id
            .as_deref()
            .map(parse_channel_id)
            .transpose()?;
        Ok(LiveActivityTokenRecord {
            activity_key: self.activity_key,
            channel_id,
            token: self.token,
            platform: self.platform,
            schema_version: self.schema_version,
            created_at: now_millis,
            updated_at: now_millis,
            expires_at: None,
        })
    }
}

impl ActivityUnregisterRequest {
    fn validate(&self) -> Result<(), Error> {
        validate_activity_key(&self.activity_key)?;
        validate_schema_version(self.schema_version)?;
        validate_platform(&self.platform)?;
        if let Some(token) = self.token.as_deref() {
            validate_token(token)?;
        }
        Ok(())
    }
}

fn validate_activity_key(value: &str) -> Result<(), Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > ACTIVITY_KEY_MAX_LEN {
        return Err(Error::validation_code(
            "activity_key must be non-empty and at most 255 bytes",
            "activity_key_invalid",
        ));
    }
    if !trimmed.contains(':') {
        return Err(Error::validation_code(
            "activity_key must include a scope prefix",
            "activity_key_invalid",
        ));
    }
    Ok(())
}

fn validate_schema_version(value: i32) -> Result<(), Error> {
    if value != 1 {
        return Err(Error::validation_code(
            "unsupported activity schema_version",
            "activity_schema_version_unsupported",
        ));
    }
    Ok(())
}

fn validate_platform(value: &str) -> Result<(), Error> {
    if !value.eq_ignore_ascii_case("ios") {
        return Err(Error::validation_code(
            "activity platform must be ios",
            "activity_platform_invalid",
        ));
    }
    Ok(())
}

fn validate_token(value: &str) -> Result<(), Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > ACTIVITY_TOKEN_MAX_LEN {
        return Err(Error::validation_code(
            "activity token must be non-empty and at most 512 bytes",
            "activity_token_invalid",
        ));
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::validation_code(
            "activity token must be hex encoded",
            "activity_token_invalid",
        ));
    }
    Ok(())
}

fn dispatch_activity_token(
    state: &AppState,
    activity_key: &str,
    record: LiveActivityTokenRecord,
    payload: Arc<ApnsPayload>,
) {
    let platform = match record.platform.parse::<Platform>() {
        Ok(Platform::IOS) => Platform::IOS,
        _ => {
            emit_activity_dispatch_skipped(activity_key, "unsupported_platform", None);
            return;
        }
    };
    let channel_id = record.channel_id.unwrap_or([0_u8; 16]);
    let correlation_id = Arc::<str>::from(format!("{activity_key}:{}", record.updated_at));
    let delivery_id = Arc::<str>::from(format!("liveactivity:{activity_key}"));
    let device_key = Arc::<str>::from(format!("liveactivity:{activity_key}"));
    let device_token = Arc::<str>::from(record.token);
    let job = ApnsJob {
        channel_id,
        correlation_id,
        delivery_id,
        device_key,
        device_token,
        platform,
        direct_payload: payload,
        wakeup_payload: None,
        initial_path: ProviderDeliveryPath::Direct,
        wakeup_payload_within_limit: false,
        collapse_id: Some(Arc::from(activity_key.to_string())),
    };
    if let Err(err) = state.dispatch.try_send_apns(job) {
        emit_activity_dispatch_skipped(activity_key, dispatch_error_reason(&err), None);
    }
}

fn dispatch_error_reason(err: &crate::dispatch::DispatchError) -> &'static str {
    match err {
        crate::dispatch::DispatchError::QueueFull => "apns_queue_full",
        crate::dispatch::DispatchError::ChannelClosed => "apns_queue_closed",
    }
}

fn normalized_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn emit_activity_dispatch_skipped(activity_key: &str, reason: &'static str, error: Option<String>) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "activity.dispatch_skipped",
        activity_key = %(crate::util::redact_text(activity_key)),
        reason = %(reason),
        error = %(error.as_deref().unwrap_or(""))
    );
}

pub(crate) fn json_scalar_text(value: Option<&JsonValue>) -> Option<String> {
    match value {
        Some(JsonValue::String(value)) => normalized_text(Some(value)),
        Some(JsonValue::Number(value)) => Some(value.to_string()),
        Some(JsonValue::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}
