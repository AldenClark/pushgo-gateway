use hashbrown::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{
    api::{ApiJson, Error, HttpResult, deserialize_empty_as_none, deserialize_i64_lenient},
    app::AppState,
    storage::EventState,
};

use super::{
    channel_auth::{AuthorizedChannel, authorize_channel_by_password},
    dispatch_lifecycle::dispatch_failure_error_message,
    message::{
        build_semantic_create_dedupe_key, deserialize_metadata_map, dispatch_entity_notification,
        encode_metadata, resolve_create_semantic_id, resolve_op_id, validate_metadata_entries,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EventProfile {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    message: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    severity: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    started_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    ended_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventCommonFields {
    channel_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    op_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventPayloadFields {
    event_time: Option<i64>,
    title: Option<String>,
    description: Option<String>,
    status: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    images: Vec<String>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
    #[serde(default)]
    attrs: JsonMap<String, JsonValue>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    metadata: JsonMap<String, JsonValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCreateRequest {
    #[serde(flatten)]
    common: EventCommonFields,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    thing_id: Option<String>,
    #[serde(flatten)]
    payload: EventPayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventUpdateRequest {
    #[serde(flatten)]
    common: EventCommonFields,
    event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    thing_id: Option<String>,
    #[serde(flatten)]
    payload: EventPayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventCloseRequest {
    #[serde(flatten)]
    common: EventCommonFields,
    event_id: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    thing_id: Option<String>,
    #[serde(flatten)]
    payload: EventPayloadFields,
}

#[derive(Debug)]
struct EventIntent {
    channel_id: String,
    op_id: Option<String>,
    event_id: Option<String>,
    thing_id: Option<String>,
    payload: EventPayloadFields,
}

impl EventIntent {
    fn from_create(request: EventCreateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: None,
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }

    fn from_update(request: EventUpdateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: Some(request.event_id),
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }

    fn from_close(request: EventCloseRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            op_id: request.common.op_id,
            event_id: Some(request.event_id),
            thing_id: request.thing_id,
            payload: request.payload,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct EventSummary {
    channel_id: String,
    op_id: String,
    event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thing_id: Option<String>,
    accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventRouteAction {
    Create,
    Update,
    Close,
}

impl EventRouteAction {
    fn requested_state(self) -> EventState {
        match self {
            EventRouteAction::Create => EventState::Ongoing,
            EventRouteAction::Update => EventState::Ongoing,
            EventRouteAction::Close => EventState::Closed,
        }
    }
}

async fn event_to_channel_with_action(
    state: AppState,
    authorized_channel: AuthorizedChannel,
    payload: EventIntent,
    route_action: EventRouteAction,
) -> HttpResult {
    let requested_state = route_action.requested_state();
    if payload.channel_id.trim().is_empty() {
        return Err(Error::validation("channel id must not be empty"));
    }
    let channel_id = authorized_channel.channel_id;
    let channel_scope = authorized_channel.channel_scope.clone();

    let op_id = resolve_op_id(payload.op_id.as_deref())?;
    let thing_id = payload
        .thing_id
        .as_deref()
        .map(|raw| normalize_entity_id(raw, "thing_id"))
        .transpose()?;
    if route_action == EventRouteAction::Create
        && payload
            .event_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(Error::validation(
            "event_id is generated by gateway on /event/create",
        ));
    }
    let resolved_event_id = match route_action {
        EventRouteAction::Create => {
            resolve_create_semantic_id(
                &state,
                build_semantic_create_dedupe_key(
                    &channel_scope,
                    "event",
                    thing_id.as_deref(),
                    &op_id,
                )
                .as_str(),
            )
            .await?
        }
        EventRouteAction::Update | EventRouteAction::Close => super::message::ResolvedSemanticId {
            semantic_id: {
                let raw = payload
                    .event_id
                    .as_deref()
                    .ok_or_else(|| Error::validation("event_id is required"))?;
                normalize_entity_id(raw, "event_id")?
            },
        },
    };
    let event_id = resolved_event_id.semantic_id;
    let normalized_tags = payload
        .payload
        .tags
        .as_deref()
        .map(|tags| normalize_tags(tags, "tags"))
        .transpose()?;
    let normalized_severity = payload
        .payload
        .severity
        .as_deref()
        .map(normalize_event_severity)
        .transpose()?;
    let normalized_status = payload
        .payload
        .status
        .as_deref()
        .map(normalize_event_status)
        .transpose()?;
    let normalized_message = payload
        .payload
        .message
        .as_deref()
        .map(normalize_event_message)
        .transpose()?;
    let normalized_images = normalize_image_urls(&payload.payload.images, "images")?;
    let normalized_description =
        normalize_optional_event_text(payload.payload.description.as_deref());

    validate_extension_object(&payload.payload.attrs, "attrs")?;
    validate_metadata_entries(&payload.payload.metadata)?;
    validate_event_temporal_fields(
        route_action,
        payload.payload.started_at,
        payload.payload.ended_at,
    )?;
    validate_event_required_fields(
        route_action,
        payload.payload.title.as_deref(),
        &normalized_status,
        &normalized_message,
        &normalized_severity,
    )?;

    let mut custom_data = HashMap::with_capacity(1);
    if !payload.payload.metadata.is_empty() {
        custom_data.insert(
            "metadata".to_string(),
            encode_metadata(&payload.payload.metadata)?,
        );
    }

    let event_time = payload
        .payload
        .event_time
        .ok_or_else(|| Error::validation_code("event_time is required", "event_time_required"))?;

    let mut merged_profile = EventProfile::default();
    if let Some(title) = payload.payload.title.as_ref() {
        merged_profile.title = Some(title.clone());
    }
    if let Some(description) = normalized_description.as_ref() {
        merged_profile.description = Some(description.clone());
    }
    if let Some(status) = normalized_status.as_ref() {
        merged_profile.status = Some(status.clone());
    }
    if let Some(message) = normalized_message.as_ref() {
        merged_profile.message = Some(message.clone());
    }
    if let Some(severity) = normalized_severity.as_ref() {
        merged_profile.severity = Some(severity.clone());
    }
    if let Some(tags) = normalized_tags {
        merged_profile.tags = tags;
    }
    merged_profile.started_at =
        resolve_started_at(route_action, payload.payload.started_at, None, event_time);
    merged_profile.ended_at =
        resolve_ended_at(route_action, payload.payload.ended_at, None, event_time);
    for value in &normalized_images {
        if !merged_profile.images.iter().any(|item| item == value) {
            merged_profile.images.push(value.clone());
        }
    }
    let merged_profile = if event_profile_is_empty(&merged_profile) {
        None
    } else {
        Some(merged_profile)
    };
    let resolved_profile_json = merged_profile
        .as_ref()
        .map(|profile| {
            serde_json::to_string(profile).map_err(|err| Error::validation(err.to_string()))
        })
        .transpose()?;

    let effective_state = requested_state;
    let resolved_thing_id = thing_id.clone();

    let mut final_attrs = JsonMap::new();
    apply_attrs_patch(&mut final_attrs, &payload.payload.attrs);
    let attrs_json_in = if payload.payload.attrs.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&payload.payload.attrs)
                .map_err(|err| Error::validation(err.to_string()))?,
        )
    };

    let notification_title = payload.payload.title.clone().or_else(|| {
        merged_profile
            .as_ref()
            .and_then(|profile| profile.title.clone())
    });
    let notification_body = normalized_message
        .clone()
        .or(normalized_description.clone());

    let dispatch_summary = {
        let mut extra = HashMap::with_capacity(7);
        extra.insert("event_id".to_string(), event_id.clone());
        extra.insert(
            "event_state".to_string(),
            effective_state.as_api_str().to_string(),
        );
        extra.insert("occurred_at".to_string(), event_time.to_string());
        extra.insert("event_time".to_string(), event_time.to_string());
        if let Some(value) = resolved_thing_id.as_deref() {
            extra.insert("thing_id".to_string(), value.to_string());
        }
        if let Some(value) = resolved_profile_json.as_deref() {
            extra.insert("event_profile_json".to_string(), value.to_string());
        }
        if let Some(value) = attrs_json_in.as_deref() {
            extra.insert("event_attrs_json".to_string(), value.to_string());
        }

        Some(
            dispatch_entity_notification(
                &state,
                channel_id,
                op_id.clone(),
                event_time,
                notification_title.clone(),
                notification_body.clone(),
                None,
                None,
                custom_data.clone(),
                "event",
                &event_id,
                extra,
            )
            .await?,
        )
    };

    let mut response = EventSummary {
        channel_id: channel_scope,
        op_id,
        event_id,
        thing_id: resolved_thing_id,
        accepted: true,
    };
    if let Some(summary) = dispatch_summary.as_ref()
        && let Some(error_message) = dispatch_failure_error_message(summary)
    {
        response.accepted = false;
        return Ok(crate::api::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "success": false,
                "error": error_message,
                "data": response,
            }),
        ));
    }
    Ok(crate::api::ok(response))
}

pub(crate) async fn event_create_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventCreateRequest>,
) -> HttpResult {
    let password = payload
        .common
        .password
        .as_deref()
        .ok_or_else(|| Error::validation("password is required"))?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_action(
        state,
        authorized_channel,
        EventIntent::from_create(payload),
        EventRouteAction::Create,
    )
    .await
}

pub(crate) async fn event_create_authorized(
    state: &AppState,
    payload: EventCreateRequest,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_action(
        state.clone(),
        authorized_channel,
        EventIntent::from_create(payload),
        EventRouteAction::Create,
    )
    .await
}

pub(crate) async fn event_update_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventUpdateRequest>,
) -> HttpResult {
    let password = payload
        .common
        .password
        .as_deref()
        .ok_or_else(|| Error::validation("password is required"))?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_action(
        state,
        authorized_channel,
        EventIntent::from_update(payload),
        EventRouteAction::Update,
    )
    .await
}

pub(crate) async fn event_update_authorized(
    state: &AppState,
    payload: EventUpdateRequest,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_action(
        state.clone(),
        authorized_channel,
        EventIntent::from_update(payload),
        EventRouteAction::Update,
    )
    .await
}

pub(crate) async fn event_close_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<EventCloseRequest>,
) -> HttpResult {
    let password = payload
        .common
        .password
        .as_deref()
        .ok_or_else(|| Error::validation("password is required"))?;
    let authorized_channel =
        authorize_channel_by_password(&state, &payload.common.channel_id, password).await?;
    event_to_channel_with_action(
        state,
        authorized_channel,
        EventIntent::from_close(payload),
        EventRouteAction::Close,
    )
    .await
}

pub(crate) async fn event_close_authorized(
    state: &AppState,
    payload: EventCloseRequest,
    authorized_channel: AuthorizedChannel,
) -> HttpResult {
    event_to_channel_with_action(
        state.clone(),
        authorized_channel,
        EventIntent::from_close(payload),
        EventRouteAction::Close,
    )
    .await
}

fn validate_event_temporal_fields(
    route_action: EventRouteAction,
    started_at: Option<i64>,
    ended_at: Option<i64>,
) -> Result<(), Error> {
    match route_action {
        EventRouteAction::Create => {
            if ended_at.is_some() {
                return Err(Error::validation(
                    "ended_at is only allowed on /event/close",
                ));
            }
        }
        EventRouteAction::Update => {
            if started_at.is_some() || ended_at.is_some() {
                return Err(Error::validation(
                    "started_at and ended_at are not allowed on /event/update",
                ));
            }
        }
        EventRouteAction::Close => {
            if started_at.is_some() {
                return Err(Error::validation(
                    "started_at is only allowed on /event/create",
                ));
            }
        }
    }
    Ok(())
}

fn normalize_event_severity(raw: &str) -> Result<String, Error> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "critical" | "high" | "normal" | "low" => Ok(normalized),
        _ => Err(Error::validation(
            "severity must be one of critical/high/normal/low",
        )),
    }
}

fn normalize_event_status(raw: &str) -> Result<String, Error> {
    const MAX_STATUS_LEN: usize = 24;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("status must not be empty"));
    }
    if trimmed.chars().count() > MAX_STATUS_LEN {
        return Err(Error::validation("status is too long"));
    }
    Ok(trimmed.to_string())
}

fn normalize_event_message(raw: &str) -> Result<String, Error> {
    const MAX_MESSAGE_LEN: usize = 512;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("message must not be empty"));
    }
    if trimmed.chars().count() > MAX_MESSAGE_LEN {
        return Err(Error::validation("message is too long"));
    }
    Ok(trimmed.to_string())
}

fn validate_event_required_fields(
    action: EventRouteAction,
    title: Option<&str>,
    status: &Option<String>,
    message: &Option<String>,
    severity: &Option<String>,
) -> Result<(), Error> {
    match action {
        EventRouteAction::Create => {
            if title.is_none() || status.is_none() || message.is_none() || severity.is_none() {
                return Err(Error::validation(
                    "title, status, message and severity are required on /event/create",
                ));
            }
        }
        EventRouteAction::Update | EventRouteAction::Close => {
            if status.is_none() || message.is_none() || severity.is_none() {
                return Err(Error::validation(
                    "status, message and severity are required on /event/update and /event/close",
                ));
            }
        }
    }
    Ok(())
}

fn resolve_started_at(
    route_action: EventRouteAction,
    incoming: Option<i64>,
    existing: Option<i64>,
    event_time: i64,
) -> Option<i64> {
    match route_action {
        EventRouteAction::Create => incoming.or(existing).or(Some(event_time)),
        EventRouteAction::Update | EventRouteAction::Close => existing,
    }
}

fn resolve_ended_at(
    route_action: EventRouteAction,
    incoming: Option<i64>,
    existing: Option<i64>,
    event_time: i64,
) -> Option<i64> {
    match route_action {
        EventRouteAction::Close => incoming.or(existing).or(Some(event_time)),
        EventRouteAction::Create | EventRouteAction::Update => existing,
    }
}

fn normalize_entity_id(raw: &str, field: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation(format!("{field} must not be empty")));
    }
    if trimmed.len() > 64 {
        return Err(Error::validation(format!("{field} is too long")));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
    {
        return Err(Error::validation(format!("{field} format is invalid")));
    }
    Ok(trimmed.to_string())
}

fn apply_attrs_patch(target: &mut JsonMap<String, JsonValue>, patch: &JsonMap<String, JsonValue>) {
    for (key, value) in patch {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn normalize_tags(values: &[String], field: &str) -> Result<Vec<String>, Error> {
    const MAX_TAGS: usize = 32;
    const MAX_TAG_LEN: usize = 64;
    if values.len() > MAX_TAGS {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!("{field} contains empty tag")));
        }
        if trimmed.len() > MAX_TAG_LEN {
            return Err(Error::validation(format!("{field} contains oversized tag")));
        }
        if !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn normalize_image_urls(values: &[String], field: &str) -> Result<Vec<String>, Error> {
    const MAX_IMAGES: usize = 32;
    const MAX_IMAGE_LEN: usize = 2048;
    if values.len() > MAX_IMAGES {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!("{field} contains empty url")));
        }
        if trimmed.len() > MAX_IMAGE_LEN {
            return Err(Error::validation(format!("{field} contains oversized url")));
        }
        if !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn normalize_optional_event_text(raw: Option<&str>) -> Option<String> {
    raw.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed.to_string())
    })
}

fn event_profile_is_empty(profile: &EventProfile) -> bool {
    profile.title.is_none()
        && profile.description.is_none()
        && profile.status.is_none()
        && profile.message.is_none()
        && profile.severity.is_none()
        && profile.tags.is_empty()
        && profile.images.is_empty()
        && profile.started_at.is_none()
        && profile.ended_at.is_none()
}

fn validate_extension_object(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<(), Error> {
    for (key, value) in object {
        if key.trim().is_empty() {
            return Err(Error::validation(format!("{field} contains empty key")));
        }
        match value {
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
            JsonValue::Object(inner) => {
                for inner_value in inner.values() {
                    match inner_value {
                        JsonValue::Null
                        | JsonValue::Bool(_)
                        | JsonValue::Number(_)
                        | JsonValue::String(_) => {}
                        _ => {
                            return Err(Error::validation(format!(
                                "{field} only supports one-level objects"
                            )));
                        }
                    }
                }
            }
            JsonValue::Array(_) => {
                return Err(Error::validation(format!(
                    "{field} does not support arrays"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EventCreateRequest, EventUpdateRequest};

    #[test]
    fn event_create_rejects_event_id_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "event_id":"should-not-exist",
            "title":"t",
            "status":"open",
            "message":"m",
            "severity":"normal"
        }"#;
        let parsed = serde_json::from_str::<EventCreateRequest>(raw);
        assert!(
            parsed.is_err(),
            "event create should reject event_id in payload"
        );
    }

    #[test]
    fn event_create_accepts_optional_thing_id() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"thing-in-body",
            "title":"t",
            "status":"open",
            "message":"m",
            "severity":"normal"
        }"#;
        let parsed = serde_json::from_str::<EventCreateRequest>(raw);
        assert!(
            parsed.is_ok(),
            "event create should accept optional thing_id in body"
        );
    }

    #[test]
    fn event_update_accepts_expected_fields() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "event_id":"evt-1",
            "status":"open",
            "message":"m",
            "severity":"normal"
        }"#;
        let parsed = serde_json::from_str::<EventUpdateRequest>(raw);
        assert!(parsed.is_ok(), "event update should parse valid payload");
    }

    #[test]
    fn event_create_accepts_missing_op_id() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "title":"t",
            "status":"open",
            "message":"m",
            "severity":"normal"
        }"#;
        let parsed = serde_json::from_str::<EventCreateRequest>(raw);
        assert!(parsed.is_ok(), "event create should accept missing op_id");
    }
}
