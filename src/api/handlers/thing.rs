use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{
    api::{
        ApiJson, Error, HttpResult, deserialize_empty_as_none, deserialize_i64_lenient,
        format_channel_id, parse_channel_id, validate_channel_password,
    },
    app::AppState,
    storage::{StoreError, ThingHead, ThingState},
};

use super::{
    dispatch_lifecycle::dispatch_failure_error_message,
    message::{
        build_semantic_create_dedupe_key, deserialize_metadata_map, dispatch_entity_notification,
        encode_metadata, normalize_op_id, resolve_create_semantic_id, validate_metadata_entries,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ThingLocation {
    #[serde(rename = "type")]
    location_type: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ThingProfile {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    primary_image: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    created_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    state: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    deleted_at: Option<i64>,
    #[serde(default)]
    external_ids: BTreeMap<String, String>,
    #[serde(default)]
    location: Option<ThingLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ThingMetaPayload {
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    profile_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingCommonFields {
    channel_id: String,
    password: String,
    op_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingMutablePayloadFields {
    title: Option<String>,
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    external_ids: JsonMap<String, JsonValue>,
    location_type: Option<String>,
    location_value: Option<String>,
    #[serde(default)]
    primary_image: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    observed_at: Option<i64>,
    #[serde(default)]
    attrs: JsonMap<String, JsonValue>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    metadata: JsonMap<String, JsonValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingCreateRequest {
    #[serde(flatten)]
    common: ThingCommonFields,
    created_at: Option<i64>,
    #[serde(flatten)]
    payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingUpdateRequest {
    #[serde(flatten)]
    common: ThingCommonFields,
    thing_id: String,
    #[serde(flatten)]
    payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingArchiveRequest {
    #[serde(flatten)]
    common: ThingCommonFields,
    thing_id: String,
    #[serde(flatten)]
    payload: ThingMutablePayloadFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThingDeleteRequest {
    #[serde(flatten)]
    common: ThingCommonFields,
    thing_id: String,
    deleted_at: Option<i64>,
    #[serde(flatten)]
    payload: ThingMutablePayloadFields,
}

#[derive(Debug)]
struct ThingPayloadFields {
    created_at: Option<i64>,
    deleted_at: Option<i64>,
    mutable: ThingMutablePayloadFields,
}

#[derive(Debug)]
struct ThingIntent {
    channel_id: String,
    password: String,
    op_id: String,
    thing_id: Option<String>,
    payload: ThingPayloadFields,
}

impl ThingIntent {
    fn from_create(request: ThingCreateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            password: request.common.password,
            op_id: request.common.op_id,
            thing_id: None,
            payload: ThingPayloadFields {
                created_at: request.created_at,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    fn from_update(request: ThingUpdateRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            password: request.common.password,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    fn from_archive(request: ThingArchiveRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            password: request.common.password,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: None,
                mutable: request.payload,
            },
        }
    }

    fn from_delete(request: ThingDeleteRequest) -> Self {
        Self {
            channel_id: request.common.channel_id,
            password: request.common.password,
            op_id: request.common.op_id,
            thing_id: Some(request.thing_id),
            payload: ThingPayloadFields {
                created_at: None,
                deleted_at: request.deleted_at,
                mutable: request.payload,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ThingSummary {
    channel_id: String,
    op_id: String,
    thing_id: String,
    accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThingRouteAction {
    Create,
    Update,
    Archive,
    Delete,
}

async fn thing_to_channel_with_action(
    state: AppState,
    payload: ThingIntent,
    route_action: ThingRouteAction,
) -> HttpResult {
    if payload.channel_id.trim().is_empty() {
        return Err(Error::validation("channel id must not be empty"));
    }
    if !state
        .api_rate_limiter
        .allow_channel(payload.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let channel_scope = format_channel_id(&channel_id);
    let password = validate_channel_password(&payload.password)?;
    state
        .store
        .channel_info_with_password_async(channel_id, password)
        .await?
        .ok_or(StoreError::ChannelNotFound)?;

    let op_id = normalize_op_id(&payload.op_id)?;
    if route_action == ThingRouteAction::Create
        && payload
            .thing_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(Error::validation(
            "thing_id is generated by gateway on /thing/create",
        ));
    }
    let resolved_thing_id = match route_action {
        ThingRouteAction::Create => {
            resolve_create_semantic_id(
                &state,
                build_semantic_create_dedupe_key(&channel_scope, "thing", None, &op_id).as_str(),
            )
            .await?
        }
        ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
            super::message::ResolvedSemanticId {
                semantic_id: {
                    let raw = payload
                        .thing_id
                        .as_deref()
                        .ok_or_else(|| Error::validation("thing_id is required"))?;
                    normalize_entity_id(raw, "thing_id")?
                },
                reused: false,
            }
        }
    };
    let thing_id = resolved_thing_id.semantic_id;
    let scoped_thing_id = scoped_entity_key(&channel_scope, &thing_id);

    let normalized_tags = payload
        .payload
        .mutable
        .tags
        .as_deref()
        .map(|tags| normalize_tags(tags, "tags"))
        .transpose()?;
    let normalized_images = normalize_image_urls(&payload.payload.mutable.images, "images")?;
    let normalized_primary_image = normalize_optional_url(
        payload.payload.mutable.primary_image.as_deref(),
        "primary_image",
    )?;
    let normalized_description =
        normalize_optional_text(payload.payload.mutable.description.as_deref());
    validate_extension_object(&payload.payload.mutable.attrs, "attrs")?;
    validate_manufacturer_attrs(&payload.payload.mutable.attrs)?;
    validate_external_id_patch(&payload.payload.mutable.external_ids)?;
    let normalized_location = normalize_location_patch(
        payload.payload.mutable.location_type.as_deref(),
        payload.payload.mutable.location_value.as_deref(),
    )?;
    validate_metadata_entries(&payload.payload.mutable.metadata)?;

    let now = Utc::now().timestamp();
    let observed_at = payload.payload.mutable.observed_at.unwrap_or(now);
    let existing = state.store.load_thing_head_async(&scoped_thing_id).await?;
    match route_action {
        ThingRouteAction::Create if existing.is_some() && !resolved_thing_id.reused => {
            return Err(Error::validation("thing already exists; use /thing/update"));
        }
        ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete
            if existing.is_none() =>
        {
            return Err(Error::validation(
                "thing not found; use /thing/create first",
            ));
        }
        _ => {}
    }
    let existing_meta = existing
        .as_ref()
        .and_then(|head| parse_thing_meta(head.meta_json.as_deref()).ok())
        .unwrap_or_default();

    let mut custom_data = HashMap::with_capacity(1);
    if !payload.payload.mutable.metadata.is_empty() {
        custom_data.insert(
            "metadata".to_string(),
            encode_metadata(&payload.payload.mutable.metadata)?,
        );
    }

    let mut merged_profile = existing_meta
        .profile_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<ThingProfile>(raw).ok())
        .unwrap_or_default();
    if let Some(title) = payload.payload.mutable.title.clone() {
        merged_profile.title = Some(title);
    }
    if let Some(description) = normalized_description.clone() {
        merged_profile.description = Some(description);
    }
    if let Some(tags) = normalized_tags {
        merged_profile.tags = tags;
    }
    let resolved_created_at = match route_action {
        ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
            if payload.payload.created_at.is_some() {
                return Err(Error::validation(
                    "created_at is only allowed on /thing/create",
                ));
            }
            merged_profile.created_at
        }
        ThingRouteAction::Create => payload
            .payload
            .created_at
            .or(merged_profile.created_at)
            .or(Some(observed_at)),
    };
    merged_profile.created_at = resolved_created_at;
    if let Some(image) = normalized_primary_image {
        merged_profile.primary_image = Some(image);
    }
    if !normalized_images.is_empty() {
        for image in &normalized_images {
            push_unique_image(&mut merged_profile, image);
        }
    }

    let existing_state = existing
        .as_ref()
        .map(|head| head.state)
        .unwrap_or(ThingState::Active);
    let resolved_state = match route_action {
        ThingRouteAction::Create => ThingState::Active,
        ThingRouteAction::Update => existing_state,
        ThingRouteAction::Archive => ThingState::Inactive,
        ThingRouteAction::Delete => ThingState::Decommissioned,
    };
    merged_profile.state = Some(thing_state_api_text(resolved_state).to_string());
    merged_profile.deleted_at = if resolved_state == ThingState::Decommissioned {
        payload
            .payload
            .deleted_at
            .or(merged_profile.deleted_at)
            .or(Some(observed_at))
    } else {
        None
    };

    if !payload.payload.mutable.external_ids.is_empty() {
        apply_external_id_patch(
            &mut merged_profile.external_ids,
            &payload.payload.mutable.external_ids,
        )?;
    }
    if let Some(location) = normalized_location {
        merged_profile.location = Some(location);
    }

    let merged_profile = if thing_profile_is_empty(&merged_profile) {
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

    let applied = existing
        .as_ref()
        .map(|head| observed_at >= head.updated_at)
        .unwrap_or(true);

    let mut final_attrs = existing
        .as_ref()
        .and_then(|head| parse_attrs_json(&head.attrs_json).ok())
        .unwrap_or_default();
    for (key, value) in &payload.payload.mutable.attrs {
        if value.is_null() {
            final_attrs.remove(key);
        } else {
            final_attrs.insert(key.clone(), value.clone());
        }
    }
    let final_attrs_json =
        serde_json::to_string(&final_attrs).map_err(|err| Error::validation(err.to_string()))?;

    let thing_meta_json = encode_thing_meta(resolved_profile_json.as_deref())?;

    let (notification_title, notification_body) = build_thing_notification_content(
        route_action,
        &payload,
        merged_profile.as_ref(),
        normalized_description,
    );

    if applied {
        let existing_latest_event_id = existing
            .as_ref()
            .and_then(|head| head.latest_event_id.clone());
        let existing_latest_event_time = existing.as_ref().and_then(|head| head.latest_event_time);

        let head = ThingHead {
            thing_id: scoped_thing_id.clone(),
            state: resolved_state,
            attrs_json: final_attrs_json.clone(),
            meta_json: Some(thing_meta_json),
            updated_at: observed_at,
            latest_event_id: existing_latest_event_id,
            latest_event_time: existing_latest_event_time,
        };
        state.store.upsert_thing_head_async(&head).await?;
    }

    let dispatch_summary = if applied {
        let mut extra = HashMap::with_capacity(4);
        extra.insert("occurred_at".to_string(), observed_at.to_string());
        extra.insert("thing_id".to_string(), thing_id.clone());
        extra.insert("thing_attrs_json".to_string(), final_attrs_json.clone());
        if let Some(value) = resolved_profile_json.as_ref() {
            extra.insert("thing_profile_json".to_string(), value.clone());
        }

        Some(
            dispatch_entity_notification(
                &state,
                channel_id,
                op_id.clone(),
                notification_title,
                notification_body,
                None,
                None,
                custom_data,
                "thing",
                &thing_id,
                extra,
            )
            .await?,
        )
    } else {
        None
    };

    let mut response = ThingSummary {
        channel_id: channel_scope,
        op_id,
        thing_id,
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

pub(crate) async fn thing_create_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingCreateRequest>,
) -> HttpResult {
    thing_to_channel_with_action(
        state,
        ThingIntent::from_create(payload),
        ThingRouteAction::Create,
    )
    .await
}

pub(crate) async fn thing_update_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingUpdateRequest>,
) -> HttpResult {
    thing_to_channel_with_action(
        state,
        ThingIntent::from_update(payload),
        ThingRouteAction::Update,
    )
    .await
}

pub(crate) async fn thing_archive_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingArchiveRequest>,
) -> HttpResult {
    thing_to_channel_with_action(
        state,
        ThingIntent::from_archive(payload),
        ThingRouteAction::Archive,
    )
    .await
}

pub(crate) async fn thing_delete_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ThingDeleteRequest>,
) -> HttpResult {
    thing_to_channel_with_action(
        state,
        ThingIntent::from_delete(payload),
        ThingRouteAction::Delete,
    )
    .await
}

fn parse_attrs_json(raw: &str) -> Result<JsonMap<String, JsonValue>, serde_json::Error> {
    serde_json::from_str::<JsonMap<String, JsonValue>>(raw)
}

fn parse_thing_meta(raw: Option<&str>) -> Result<ThingMetaPayload, serde_json::Error> {
    let Some(raw) = raw else {
        return Ok(ThingMetaPayload::default());
    };
    if raw.trim().is_empty() {
        return Ok(ThingMetaPayload::default());
    }
    serde_json::from_str::<ThingMetaPayload>(raw)
}

fn build_thing_notification_content(
    route_action: ThingRouteAction,
    payload: &ThingIntent,
    profile: Option<&ThingProfile>,
    normalized_description: Option<String>,
) -> (Option<String>, Option<String>) {
    let operation = thing_operation_label(route_action);
    let requested_title = payload
        .payload
        .mutable
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let requested_body = normalized_description;
    let fallback_title = profile
        .and_then(|current| current.title.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let title_raw = match route_action {
        ThingRouteAction::Create => requested_title,
        ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
            requested_title.or(fallback_title)
        }
    };
    let title = title_raw.map(|value| format!("{operation}: {value}"));
    let body = match route_action {
        ThingRouteAction::Create => requested_body,
        ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
            requested_body.or_else(|| attrs_summary_lines(&payload.payload.mutable.attrs))
        }
    };
    (title, body)
}

fn thing_operation_label(action: ThingRouteAction) -> &'static str {
    match action {
        ThingRouteAction::Create => "创建",
        ThingRouteAction::Update => "更新",
        ThingRouteAction::Archive => "存档",
        ThingRouteAction::Delete => "删除",
    }
}

fn attrs_summary_lines(attrs: &JsonMap<String, JsonValue>) -> Option<String> {
    if attrs.is_empty() {
        return None;
    }
    let mut keys: Vec<&String> = attrs.keys().collect();
    keys.sort();
    let mut lines = Vec::with_capacity(attrs.len());
    for key in keys {
        let Some(value) = attrs.get(key) else {
            continue;
        };
        lines.push(format!("{key}={}", attr_value_text(value)));
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn attr_value_text(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(v) => v.to_string(),
        JsonValue::Number(v) => v.to_string(),
        JsonValue::String(v) => v.to_string(),
        JsonValue::Object(_) | JsonValue::Array(_) => {
            serde_json::to_string(value).unwrap_or_default()
        }
    }
}

fn encode_thing_meta(profile_json: Option<&str>) -> Result<String, Error> {
    #[derive(Serialize)]
    struct ThingMetaPayloadRef<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile_json: Option<&'a str>,
    }

    serde_json::to_string(&ThingMetaPayloadRef { profile_json })
        .map_err(|err| Error::validation(err.to_string()))
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

fn scoped_entity_key(channel_scope: &str, id: &str) -> String {
    format!("{channel_scope}:{id}")
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

fn thing_state_api_text(state: ThingState) -> &'static str {
    match state {
        ThingState::Active => "active",
        ThingState::Inactive => "archived",
        ThingState::Decommissioned => "deleted",
    }
}

fn normalize_optional_url(raw: Option<&str>, field: &str) -> Result<Option<String>, Error> {
    const MAX_URL_LEN: usize = 2048;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_URL_LEN {
        return Err(Error::validation(format!("{field} contains oversized url")));
    }
    Ok(Some(trimmed.to_string()))
}

fn push_unique_image(profile: &mut ThingProfile, value: &str) {
    if profile.primary_image.as_deref() == Some(value) {
        return;
    }
    if !profile.images.iter().any(|item| item == value) {
        profile.images.push(value.to_string());
    }
}

fn thing_profile_is_empty(profile: &ThingProfile) -> bool {
    profile.title.is_none()
        && profile.description.is_none()
        && profile.tags.is_empty()
        && profile.primary_image.is_none()
        && profile.images.is_empty()
        && profile.created_at.is_none()
        && profile.state.is_none()
        && profile.deleted_at.is_none()
        && profile.external_ids.is_empty()
        && profile.location.is_none()
}

fn normalize_image_urls(images: &[String], field: &str) -> Result<Vec<String>, Error> {
    const MAX_IMAGES: usize = 32;
    const MAX_IMAGE_LEN: usize = 2048;
    if images.len() > MAX_IMAGES {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(images.len());
    for image in images {
        let trimmed = image.trim();
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

fn normalize_optional_text(raw: Option<&str>) -> Option<String> {
    raw.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed.to_string())
    })
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

fn validate_manufacturer_attrs(object: &JsonMap<String, JsonValue>) -> Result<(), Error> {
    let Some(value) = object.get("manufacturer") else {
        return Ok(());
    };
    match value {
        JsonValue::Null => Ok(()),
        JsonValue::Object(inner) => {
            for key in inner.keys() {
                let trimmed = key.trim();
                if trimmed.is_empty() {
                    return Err(Error::validation("attrs.manufacturer contains empty key"));
                }
                if trimmed.len() > 64 {
                    return Err(Error::validation(
                        "attrs.manufacturer contains oversized key",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(Error::validation(
            "attrs.manufacturer must be object or null",
        )),
    }
}

fn validate_external_id_patch(patch: &JsonMap<String, JsonValue>) -> Result<(), Error> {
    for (key, value) in patch {
        normalize_external_id_key(key)?;
        match value {
            JsonValue::Null => {}
            JsonValue::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(Error::validation("external_ids contains empty value"));
                }
                if trimmed.len() > 256 {
                    return Err(Error::validation("external_ids contains oversized value"));
                }
            }
            _ => {
                return Err(Error::validation(
                    "external_ids only supports string or null values",
                ));
            }
        }
    }
    Ok(())
}

fn apply_external_id_patch(
    target: &mut BTreeMap<String, String>,
    patch: &JsonMap<String, JsonValue>,
) -> Result<(), Error> {
    for (key, value) in patch {
        let normalized_key = normalize_external_id_key(key)?;
        match value {
            JsonValue::Null => {
                target.remove(&normalized_key);
            }
            JsonValue::String(raw) => {
                target.insert(normalized_key, raw.trim().to_string());
            }
            _ => {
                return Err(Error::validation(
                    "external_ids only supports string or null values",
                ));
            }
        }
    }
    Ok(())
}

fn normalize_external_id_key(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("external_ids contains empty key"));
    }
    if trimmed.len() > 64 {
        return Err(Error::validation("external_ids contains oversized key"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == ':' || ch == '.')
    {
        return Err(Error::validation("external_ids key format is invalid"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_location_patch(
    location_type: Option<&str>,
    location_value: Option<&str>,
) -> Result<Option<ThingLocation>, Error> {
    match (location_type, location_value) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(Error::validation(
            "location_type and location_value must be provided together",
        )),
        (Some(raw_type), Some(raw_value)) => {
            let normalized_type = raw_type.trim().to_ascii_lowercase();
            let normalized_value = match normalized_type.as_str() {
                "physical" => normalize_location_physical(raw_value)?,
                "geo" => normalize_location_geo(raw_value)?,
                "cloud" => normalize_location_cloud(raw_value)?,
                "datacenter" => normalize_location_datacenter(raw_value)?,
                "logical" => normalize_location_logical(raw_value)?,
                _ => {
                    return Err(Error::validation(
                        "location_type must be one of physical|geo|cloud|datacenter|logical",
                    ));
                }
            };
            Ok(Some(ThingLocation {
                location_type: normalized_type,
                value: normalized_value,
            }))
        }
    }
}

fn normalize_location_physical(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("location_value must not be empty"));
    }
    if trimmed.len() > 256 {
        return Err(Error::validation("location_value is too long"));
    }
    Ok(trimmed.to_string())
}

fn normalize_location_geo(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    let Some((raw_lat, raw_lng)) = trimmed.split_once(',') else {
        return Err(Error::validation(
            "geo location_value must be formatted as <lat>,<lng>",
        ));
    };
    let lat = raw_lat
        .trim()
        .parse::<f64>()
        .map_err(|_| Error::validation("geo lat must be a number"))?;
    let lng = raw_lng
        .trim()
        .parse::<f64>()
        .map_err(|_| Error::validation("geo lng must be a number"))?;
    if !((-90.0)..=90.0).contains(&lat) {
        return Err(Error::validation("geo lat out of range"));
    }
    if !((-180.0)..=180.0).contains(&lng) {
        return Err(Error::validation("geo lng out of range"));
    }
    Ok(format!("{lat:.6},{lng:.6}"))
}

fn normalize_location_cloud(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(Error::validation(
            "cloud location_value must be provider:region[:zone]",
        ));
    }
    if parts.iter().any(|part| !is_location_token(part)) {
        return Err(Error::validation(
            "cloud location_value token format is invalid",
        ));
    }
    Ok(parts.join(":").to_ascii_lowercase())
}

fn normalize_location_datacenter(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if !(1..=3).contains(&parts.len()) {
        return Err(Error::validation(
            "datacenter location_value must be site[:room[:rack]]",
        ));
    }
    if parts.iter().any(|part| !is_location_token(part)) {
        return Err(Error::validation(
            "datacenter location_value token format is invalid",
        ));
    }
    Ok(parts.join(":").to_ascii_lowercase())
}

fn normalize_location_logical(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("location_value must not be empty"));
    }
    if trimmed.len() > 256 {
        return Err(Error::validation("location_value is too long"));
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.iter().any(|part| !is_location_token(part)) {
        return Err(Error::validation(
            "logical location_value must be slash-separated tokens",
        ));
    }
    Ok(parts.join("/").to_ascii_lowercase())
}

fn is_location_token(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return false;
    }
    trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
}

#[cfg(test)]
mod tests {
    use super::{ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingUpdateRequest};

    #[test]
    fn thing_create_rejects_thing_id_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"should-not-exist",
            "title":"name"
        }"#;
        let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
        assert!(
            parsed.is_err(),
            "thing create should reject thing_id in payload"
        );
    }

    #[test]
    fn thing_archive_rejects_state_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"thing-1",
            "state":"deleted"
        }"#;
        let parsed = serde_json::from_str::<ThingArchiveRequest>(raw);
        assert!(parsed.is_err(), "thing archive should reject state field");
    }

    #[test]
    fn thing_create_rejects_state_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "state":"deleted"
        }"#;
        let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
        assert!(parsed.is_err(), "thing create should reject state field");
    }

    #[test]
    fn thing_update_rejects_state_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"thing-1",
            "state":"archived"
        }"#;
        let parsed = serde_json::from_str::<ThingUpdateRequest>(raw);
        assert!(parsed.is_err(), "thing update should reject state field");
    }

    #[test]
    fn thing_create_rejects_deleted_at_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "deleted_at":123
        }"#;
        let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
        assert!(
            parsed.is_err(),
            "thing create should reject deleted_at field"
        );
    }

    #[test]
    fn thing_update_rejects_deleted_at_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"thing-1",
            "deleted_at":123
        }"#;
        let parsed = serde_json::from_str::<ThingUpdateRequest>(raw);
        assert!(
            parsed.is_err(),
            "thing update should reject deleted_at field"
        );
    }

    #[test]
    fn thing_delete_accepts_deleted_at_field() {
        let raw = r#"{
            "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password":"12345678",
            "op_id":"op-1",
            "thing_id":"thing-1",
            "deleted_at":123
        }"#;
        let parsed = serde_json::from_str::<ThingDeleteRequest>(raw);
        assert!(parsed.is_ok(), "thing delete should accept deleted_at");
    }
}
