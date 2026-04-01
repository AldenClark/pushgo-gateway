use axum::{body::Bytes, extract::Query};

use super::*;

impl CompatNtfyQuery {
    fn scoped_thing_id(&self) -> Result<Option<String>, Error> {
        if self.thing_id.is_none() {
            return Ok(None);
        }
        Err(Error::validation(
            "thing_id is not supported on this endpoint",
        ))
    }

    pub(super) fn into_intent(
        self,
        key: CompatKey,
        headers: &HeaderMap,
        body: Option<Bytes>,
    ) -> Result<MessageIntent, Error> {
        let headers = CompatHeaders::new(headers);
        let body_text = body
            .as_ref()
            .map(|value| String::from_utf8_lossy(value).trim().to_string())
            .filter(|value| !value.is_empty());
        Ok(MessageIntent {
            channel_id: key.channel_id,
            password: key.password,
            op_id: self.op_id,
            thing_id: None,
            occurred_at: self.occurred_at,
            title: self
                .title
                .or_else(|| headers.value("Title"))
                .unwrap_or_else(|| "Notification".to_string()),
            body: self
                .message
                .or(self.body)
                .or_else(|| headers.value("Message"))
                .or(body_text),
            severity: self
                .severity
                .or_else(|| Self::severity_for_priority(self.priority.as_deref())),
            ttl: self.ttl,
            url: self.url,
            images: split_query_list(self.images.as_deref()),
            ciphertext: None,
            tags: split_query_list(self.tags.as_deref()),
            metadata: parse_query_metadata(self.metadata.as_deref())?,
        })
    }

    fn severity_for_priority(raw: Option<&str>) -> Option<String> {
        match raw.map(str::trim) {
            Some("1") | Some("2") => Some("info".to_string()),
            Some("3") => Some("warning".to_string()),
            Some("4") | Some("5") => Some("critical".to_string()),
            _ => None,
        }
    }
}

pub(crate) async fn compat_ntfy_post(
    State(state): State<AppState>,
    Path(path): Path<CompatNtfyPath>,
    headers: HeaderMap,
    Query(query): Query<CompatNtfyQuery>,
    body: Bytes,
) -> HttpResult {
    compat_ntfy_dispatch(&state, path.topic, headers, query, Some(body)).await
}

pub(crate) async fn compat_ntfy_put(
    State(state): State<AppState>,
    Path(path): Path<CompatNtfyPath>,
    headers: HeaderMap,
    Query(query): Query<CompatNtfyQuery>,
    body: Bytes,
) -> HttpResult {
    compat_ntfy_dispatch(&state, path.topic, headers, query, Some(body)).await
}

pub(crate) async fn compat_ntfy_get(
    State(state): State<AppState>,
    Path(path): Path<CompatNtfyPath>,
    headers: HeaderMap,
    Query(query): Query<CompatNtfyQuery>,
) -> HttpResult {
    compat_ntfy_dispatch(&state, path.topic, headers, query, None).await
}

async fn compat_ntfy_dispatch(
    state: &AppState,
    topic: String,
    headers: HeaderMap,
    query: CompatNtfyQuery,
    body: Option<Bytes>,
) -> HttpResult {
    let scoped_thing_id = query.scoped_thing_id()?;
    let payload = query.into_intent(CompatKey::parse(&topic)?, &headers, body)?;
    dispatch_message_intent(state, payload, scoped_thing_id).await
}
