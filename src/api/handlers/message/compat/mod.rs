use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value};

use super::*;
use crate::api::handlers::entity_input::EntityId;

mod bark;
mod ntfy;
mod serverchan;

pub(crate) use bark::{compat_bark_v1_body, compat_bark_v1_title_body, compat_bark_v2_push};
pub(crate) use ntfy::{compat_ntfy_get, compat_ntfy_post, compat_ntfy_put};
pub(crate) use serverchan::{compat_serverchan_get, compat_serverchan_post};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageGetQuery {
    channel_id: String,
    password: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    op_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    occurred_at: Option<i64>,
    title: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    body: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    severity: Option<String>,
    ttl: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    url: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    images: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    ciphertext: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    tags: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatNtfyPath {
    pub topic: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatNtfyQuery {
    pub message: Option<String>,
    pub body: Option<String>,
    pub title: Option<String>,
    pub priority: Option<String>,
    pub severity: Option<String>,
    pub url: Option<String>,
    pub op_id: Option<String>,
    pub thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    pub occurred_at: Option<i64>,
    pub ttl: Option<i64>,
    pub images: Option<String>,
    pub tags: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatServerChanPath {
    pub sendkey: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatServerChanPayload {
    pub title: Option<String>,
    pub text: Option<String>,
    pub desp: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub op_id: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatBarkV1PathBodyOnly {
    pub device_key: String,
    pub body: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatBarkV1PathTitleBody {
    pub device_key: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatBarkV1Query {
    pub url: Option<String>,
    pub op_id: Option<String>,
    pub level: Option<String>,
    pub sound: Option<String>,
    pub icon: Option<String>,
    pub group: Option<String>,
    pub images: Option<String>,
    pub tags: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatBarkV2Payload {
    pub device_key: String,
    pub title: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub op_id: Option<String>,
    pub level: Option<String>,
    pub sound: Option<String>,
    pub icon: Option<String>,
    pub group: Option<String>,
    #[serde(default)]
    pub images: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    pub metadata: JsonMap<String, Value>,
}

#[derive(Debug, Clone)]
pub(super) struct CompatKey {
    pub channel_id: String,
    pub password: String,
}

impl CompatKey {
    pub(super) fn parse(raw: &str) -> Result<Self, Error> {
        let Some((channel_id, password)) = raw.trim().split_once(':') else {
            return Err(Error::validation(
                "compat key must be '<channel_id>:<password>'",
            ));
        };
        let channel_id = channel_id.trim();
        let password = password.trim();
        if channel_id.is_empty() || password.is_empty() {
            return Err(Error::validation(
                "compat key must be '<channel_id>:<password>'",
            ));
        }
        Ok(Self {
            channel_id: channel_id.to_string(),
            password: password.to_string(),
        })
    }
}

pub(super) struct CompatHeaders<'a> {
    headers: &'a HeaderMap,
}

impl<'a> CompatHeaders<'a> {
    pub(super) fn new(headers: &'a HeaderMap) -> Self {
        Self { headers }
    }

    pub(super) fn value(&self, name: &'static str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    }
}

impl MessageGetQuery {
    fn scoped_thing_id(&self) -> Result<Option<String>, Error> {
        self.thing_id
            .as_deref()
            .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
            .transpose()
    }

    fn into_intent(self) -> Result<MessageIntent, Error> {
        Ok(MessageIntent {
            channel_id: self.channel_id,
            password: self.password,
            op_id: self.op_id,
            thing_id: None,
            occurred_at: self.occurred_at,
            title: self.title,
            body: self.body,
            severity: self.severity,
            ttl: self.ttl,
            url: self.url,
            images: split_query_list(self.images.as_deref()),
            ciphertext: self.ciphertext,
            tags: split_query_list(self.tags.as_deref()),
            metadata: parse_query_metadata(self.metadata.as_deref())?,
        })
    }
}

pub(crate) async fn message_to_channel_get(
    State(state): State<AppState>,
    Query(query): Query<MessageGetQuery>,
) -> HttpResult {
    let scoped_thing_id = query.scoped_thing_id()?;
    let payload = query.into_intent()?;
    dispatch_message_intent(&state, payload, scoped_thing_id).await
}

pub(super) fn split_query_list(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

pub(super) fn parse_query_metadata(raw: Option<&str>) -> Result<JsonMap<String, Value>, Error> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(JsonMap::new());
    };
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|_| Error::validation("metadata must be a JSON object"))?;
    parse_metadata_map_value(parsed).map_err(Error::validation)
}

pub(super) fn insert_metadata_string(
    metadata: &mut JsonMap<String, Value>,
    key: &str,
    raw: Option<&str>,
) {
    if let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) {
        metadata.insert(key.to_string(), Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;

    #[test]
    fn compat_key_requires_channel_and_password() {
        assert!(CompatKey::parse("channel:secret").is_ok());
        assert!(CompatKey::parse("channel").is_err());
        assert!(CompatKey::parse("channel:").is_err());
    }

    #[test]
    fn compat_ntfy_query_prefers_headers_and_body_when_fields_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("Title", "Header Title".parse().unwrap());
        headers.insert("Message", "Header Body".parse().unwrap());
        let query = CompatNtfyQuery::default();
        let intent = query
            .into_intent(
                CompatKey::parse("channel:secret").unwrap(),
                &headers,
                Some(Bytes::from_static(b"fallback body")),
            )
            .unwrap();
        assert_eq!(intent.title, "Header Title");
        assert_eq!(intent.body.as_deref(), Some("Header Body"));
    }

    #[test]
    fn compat_bark_v1_query_collects_metadata_and_severity() {
        let query = CompatBarkV1Query {
            level: Some("time-sensitive".to_string()),
            sound: Some("ring".to_string()),
            ..Default::default()
        };
        let intent = query
            .into_intent(
                CompatKey::parse("channel:secret").unwrap(),
                Some("body".to_string()),
                None,
            )
            .unwrap();
        assert_eq!(intent.severity.as_deref(), Some("warning"));
        assert_eq!(
            intent.metadata.get("compat.bark.sound"),
            Some(&Value::String("ring".to_string()))
        );
    }
}
