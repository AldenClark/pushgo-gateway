use axum::{extract::State, http::StatusCode};
use chrono::Utc;
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::{
    api::{
        ApiJson, Error, HttpResult, deserialize_empty_as_none, deserialize_i64_lenient,
        validate_channel_password,
    },
    app::AppState,
};

use super::channel_auth::{AuthorizedChannel, authorize_channel_by_password};
use super::entity_input::{EntityId, MetadataEntries, NormalizedImageUrls, NormalizedTags};

mod compat;
#[path = "dispatch/mod.rs"]
mod dispatch;
mod ids;
mod payload;
mod stats;

pub(crate) use compat::{
    compat_bark_v1_body, compat_bark_v1_title_body, compat_bark_v2_push, compat_ntfy_get,
    compat_ntfy_post, compat_ntfy_put, compat_serverchan_get, compat_serverchan_post,
    message_to_channel_get,
};
pub(crate) use dispatch::dispatch_entity_notification;
pub(crate) use ids::{OpId, ProviderPullDeliveryId, ResolvedSemanticId, SemanticScope};
use payload::OptionalText;
pub(crate) use payload::wakeup_notification_title_from_private_payload;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageIntent {
    pub channel_id: String,
    pub password: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub op_id: Option<String>,
    pub thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    pub occurred_at: Option<i64>,
    pub title: String,
    pub body: Option<String>,
    pub severity: Option<String>,
    pub ttl: Option<i64>,
    pub url: Option<String>,
    #[serde(default)]
    pub images: Vec<String>,
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    pub metadata: JsonMap<String, Value>,
}

impl MessageIntent {
    pub(crate) fn validate_payload(&self) -> Result<(), Error> {
        if self.channel_id.trim().is_empty() {
            return Err(Error::validation("channel id must not be empty"));
        }
        validate_channel_password(&self.password)?;
        if let Some(op_id) = self.op_id.as_deref() {
            OpId::parse(op_id)?;
        }
        if self.title.trim().is_empty() {
            return Err(Error::validation("title must not be empty"));
        }
        MetadataEntries::new(&self.metadata).validate()?;
        Ok(())
    }

    fn into_dispatch(self) -> MessageDispatchIntent {
        MessageDispatchIntent {
            op_id: self.op_id,
            occurred_at: self.occurred_at,
            title: self.title,
            body: self.body,
            severity: self.severity,
            ttl: self.ttl,
            url: self.url,
            images: self.images,
            ciphertext: self.ciphertext,
            tags: self.tags,
            metadata: self.metadata,
        }
    }
}

pub(super) fn deserialize_metadata_map<'de, D>(
    deserializer: D,
) -> Result<JsonMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<Value>::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(JsonMap::new());
    };
    parse_metadata_map_value(raw).map_err(serde::de::Error::custom)
}

pub(super) fn parse_metadata_map_value(raw: Value) -> Result<JsonMap<String, Value>, String> {
    MetadataEntries::parse_value(raw)
}

#[derive(Serialize)]
pub(crate) struct MessageSummary {
    channel_id: String,
    op_id: String,
    message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thing_id: Option<String>,
    accepted: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MessageDispatchIntent {
    pub op_id: Option<String>,
    pub occurred_at: Option<i64>,
    pub title: String,
    pub body: Option<String>,
    pub severity: Option<String>,
    pub ttl: Option<i64>,
    pub url: Option<String>,
    pub images: Vec<String>,
    pub ciphertext: Option<String>,
    pub tags: Vec<String>,
    pub metadata: JsonMap<String, Value>,
}

pub(crate) async fn message_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<MessageIntent>,
) -> HttpResult {
    let scoped_thing_id = payload
        .thing_id
        .as_deref()
        .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
        .transpose()?;
    dispatch_message_intent(&state, payload, scoped_thing_id).await
}

pub(super) async fn dispatch_message_intent(
    state: &AppState,
    payload: MessageIntent,
    scoped_thing_id: Option<String>,
) -> HttpResult {
    payload.validate_payload()?;
    let authorized =
        authorize_channel_by_password(state, &payload.channel_id, &payload.password).await?;
    dispatch_message_authorized_intent(state, authorized, payload.into_dispatch(), scoped_thing_id)
        .await
}

pub(crate) async fn dispatch_message_authorized_intent(
    state: &AppState,
    authorized_channel: AuthorizedChannel,
    payload: MessageDispatchIntent,
    scoped_thing_id: Option<String>,
) -> HttpResult {
    let channel_id = authorized_channel.channel_id;
    let channel_id_value = authorized_channel.channel_scope;

    let MessageDispatchIntent {
        op_id,
        occurred_at,
        title,
        body,
        severity,
        ttl,
        url,
        images,
        ciphertext,
        tags,
        metadata,
    } = payload;
    let occurred_at = if scoped_thing_id.is_some() {
        occurred_at.ok_or_else(|| {
            Error::validation_code(
                "occurred_at is required when message is scoped to thing_id",
                "occurred_at_required_for_thing_scoped_message",
            )
        })?
    } else {
        occurred_at.unwrap_or_else(|| Utc::now().timestamp())
    };
    let normalized_body = OptionalText::normalize_owned(body);
    let normalized_url = OptionalText::normalize_owned(url);
    let normalized_images = NormalizedImageUrls::parse(&images, "images")?.into_inner();

    let op_id = OpId::resolve(op_id.as_deref())?;
    let message_id = ResolvedSemanticId::resolve_create(
        state,
        SemanticScope::semantic_create_key(
            &channel_id_value,
            "message",
            scoped_thing_id.as_deref(),
            &op_id,
        )
        .as_str(),
    )
    .await?
    .semantic_id;
    let mut custom_data = HashMap::with_capacity(4);
    if let Some(url) = normalized_url {
        custom_data.insert("url".to_string(), url);
    }
    if !normalized_images.is_empty() {
        let encoded = serde_json::to_string(&normalized_images)
            .map_err(|_| Error::validation("images format is invalid"))?;
        custom_data.insert("images".to_string(), encoded);
    }
    if let Some(ciphertext) = OptionalText::normalize_owned(ciphertext) {
        custom_data.insert("ciphertext".to_string(), ciphertext);
    }
    let normalized_tags = NormalizedTags::parse(&tags, "tags")?.into_inner();
    if !metadata.is_empty() {
        let encoded = MetadataEntries::new(&metadata).encode()?;
        custom_data.insert("metadata".to_string(), encoded);
    }
    let mut extra_fields = HashMap::with_capacity(3);
    extra_fields.insert("message_id".to_string(), message_id.clone());
    if !normalized_tags.is_empty() {
        let encoded = serde_json::to_string(&normalized_tags)
            .map_err(|_| Error::validation("tags format is invalid"))?;
        extra_fields.insert("tags".to_string(), encoded);
    }
    if let Some(thing_id) = scoped_thing_id.clone() {
        extra_fields.insert("thing_id".to_string(), thing_id);
    }

    let summary = dispatch_entity_notification(
        state,
        channel_id,
        op_id.into_inner(),
        occurred_at,
        Some(title),
        normalized_body,
        severity,
        ttl,
        custom_data,
        "message",
        &message_id,
        extra_fields,
    )
    .await?;

    let error_message = summary.failure_error_message();
    let mut response_data = MessageSummary {
        channel_id: summary.channel_id,
        op_id: summary.op_id,
        message_id,
        thing_id: scoped_thing_id,
        accepted: true,
    };
    if let Some(error_message) = error_message {
        response_data.accepted = false;
        return Ok(
            crate::api::StatusResponse::err_with_data(error_message, response_data)
                .with_status(StatusCode::SERVICE_UNAVAILABLE),
        );
    }
    Ok(crate::api::ok(response_data))
}

#[cfg(test)]
mod tests;
