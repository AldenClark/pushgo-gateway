use super::*;

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
    topic: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatNtfyQuery {
    message: Option<String>,
    body: Option<String>,
    title: Option<String>,
    priority: Option<String>,
    severity: Option<String>,
    url: Option<String>,
    op_id: Option<String>,
    thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    occurred_at: Option<i64>,
    ttl: Option<i64>,
    images: Option<String>,
    tags: Option<String>,
    metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatServerChanPath {
    sendkey: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatServerChanPayload {
    title: Option<String>,
    text: Option<String>,
    desp: Option<String>,
    body: Option<String>,
    url: Option<String>,
    op_id: Option<String>,
    metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatBarkV1PathBodyOnly {
    device_key: String,
    body: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompatBarkV1PathTitleBody {
    device_key: String,
    title: String,
    body: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatBarkV1Query {
    url: Option<String>,
    op_id: Option<String>,
    level: Option<String>,
    sound: Option<String>,
    icon: Option<String>,
    group: Option<String>,
    images: Option<String>,
    tags: Option<String>,
    metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatBarkV2Payload {
    device_key: String,
    title: Option<String>,
    body: Option<String>,
    url: Option<String>,
    op_id: Option<String>,
    level: Option<String>,
    sound: Option<String>,
    icon: Option<String>,
    group: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    metadata: JsonMap<String, Value>,
}

pub(crate) async fn message_to_channel_get(
    State(state): State<AppState>,
    Query(query): Query<MessageGetQuery>,
) -> HttpResult {
    let scoped_thing_id = resolve_scoped_thing_id(query.thing_id.as_deref(), false)?;
    let payload = MessageIntent {
        channel_id: query.channel_id,
        password: query.password,
        op_id: query.op_id,
        thing_id: None,
        occurred_at: query.occurred_at,
        title: query.title,
        body: query.body,
        severity: query.severity,
        ttl: query.ttl,
        url: query.url,
        images: split_query_list(query.images.as_deref()),
        ciphertext: query.ciphertext,
        tags: split_query_list(query.tags.as_deref()),
        metadata: parse_query_metadata(query.metadata.as_deref())?,
    };
    dispatch_message_intent(&state, payload, scoped_thing_id).await
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
    let scoped_thing_id = resolve_scoped_thing_id(query.thing_id.as_deref(), false)?;
    let (channel_id, password) = parse_compat_key(&topic)?;
    let body_text = body
        .as_ref()
        .map(|value| String::from_utf8_lossy(value).trim().to_string())
        .filter(|value| !value.is_empty());
    let payload = MessageIntent {
        channel_id,
        password,
        op_id: query.op_id,
        thing_id: None,
        occurred_at: query.occurred_at,
        title: query
            .title
            .or_else(|| header_value(&headers, "Title"))
            .unwrap_or_else(|| "Notification".to_string()),
        body: query
            .message
            .or(query.body)
            .or_else(|| header_value(&headers, "Message"))
            .or(body_text),
        severity: query
            .severity
            .or_else(|| ntfy_priority_to_severity(query.priority.as_deref())),
        ttl: query.ttl,
        url: query.url,
        images: split_query_list(query.images.as_deref()),
        ciphertext: None,
        tags: split_query_list(query.tags.as_deref()),
        metadata: parse_query_metadata(query.metadata.as_deref())?,
    };
    dispatch_message_intent(state, payload, scoped_thing_id).await
}

pub(crate) async fn compat_serverchan_get(
    State(state): State<AppState>,
    Path(path): Path<CompatServerChanPath>,
    Query(payload): Query<CompatServerChanPayload>,
) -> HttpResult {
    compat_serverchan_dispatch(&state, path.sendkey, payload).await
}

pub(crate) async fn compat_serverchan_post(
    State(state): State<AppState>,
    Path(path): Path<CompatServerChanPath>,
    Form(payload): Form<CompatServerChanPayload>,
) -> HttpResult {
    compat_serverchan_dispatch(&state, path.sendkey, payload).await
}

async fn compat_serverchan_dispatch(
    state: &AppState,
    sendkey: String,
    payload: CompatServerChanPayload,
) -> HttpResult {
    let (channel_id, password) = parse_compat_key(&sendkey)?;
    let mut metadata = parse_query_metadata(payload.metadata.as_deref())?;
    insert_metadata_string(
        &mut metadata,
        "compat.serverchan.url",
        payload.url.as_deref(),
    );
    let intent = MessageIntent {
        channel_id,
        password,
        op_id: payload.op_id,
        thing_id: None,
        occurred_at: Some(Utc::now().timestamp()),
        title: payload
            .title
            .or(payload.text)
            .unwrap_or_else(|| "Notification".to_string()),
        body: payload.desp.or(payload.body),
        severity: None,
        ttl: None,
        url: payload.url,
        images: Vec::new(),
        ciphertext: None,
        tags: Vec::new(),
        metadata,
    };
    dispatch_message_intent(state, intent, None).await
}

pub(crate) async fn compat_bark_v1_body(
    State(state): State<AppState>,
    Path(path): Path<CompatBarkV1PathBodyOnly>,
    Query(query): Query<CompatBarkV1Query>,
) -> HttpResult {
    compat_bark_v1_dispatch(&state, path.device_key, Some(path.body), None, query).await
}

pub(crate) async fn compat_bark_v1_title_body(
    State(state): State<AppState>,
    Path(path): Path<CompatBarkV1PathTitleBody>,
    Query(query): Query<CompatBarkV1Query>,
) -> HttpResult {
    compat_bark_v1_dispatch(
        &state,
        path.device_key,
        Some(path.body),
        Some(path.title),
        query,
    )
    .await
}

async fn compat_bark_v1_dispatch(
    state: &AppState,
    device_key: String,
    body: Option<String>,
    title: Option<String>,
    query: CompatBarkV1Query,
) -> HttpResult {
    let (channel_id, password) = parse_compat_key(&device_key)?;
    let mut metadata = parse_query_metadata(query.metadata.as_deref())?;
    insert_metadata_string(&mut metadata, "compat.bark.sound", query.sound.as_deref());
    insert_metadata_string(&mut metadata, "compat.bark.icon", query.icon.as_deref());
    insert_metadata_string(&mut metadata, "compat.bark.group", query.group.as_deref());
    let intent = MessageIntent {
        channel_id,
        password,
        op_id: query.op_id,
        thing_id: None,
        occurred_at: Some(Utc::now().timestamp()),
        title: title.unwrap_or_else(|| "Notification".to_string()),
        body,
        severity: bark_level_to_severity(query.level.as_deref()),
        ttl: None,
        url: query.url,
        images: split_query_list(query.images.as_deref()),
        ciphertext: None,
        tags: split_query_list(query.tags.as_deref()),
        metadata,
    };
    dispatch_message_intent(state, intent, None).await
}

pub(crate) async fn compat_bark_v2_push(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<CompatBarkV2Payload>,
) -> HttpResult {
    let (channel_id, password) = parse_compat_key(&payload.device_key)?;
    let mut metadata = payload.metadata;
    insert_metadata_string(&mut metadata, "compat.bark.sound", payload.sound.as_deref());
    insert_metadata_string(&mut metadata, "compat.bark.icon", payload.icon.as_deref());
    insert_metadata_string(&mut metadata, "compat.bark.group", payload.group.as_deref());
    let intent = MessageIntent {
        channel_id,
        password,
        op_id: payload.op_id,
        thing_id: None,
        occurred_at: Some(Utc::now().timestamp()),
        title: payload.title.unwrap_or_else(|| "Notification".to_string()),
        body: payload.body,
        severity: bark_level_to_severity(payload.level.as_deref()),
        ttl: None,
        url: payload.url,
        images: payload.images,
        ciphertext: None,
        tags: payload.tags,
        metadata,
    };
    dispatch_message_intent(&state, intent, None).await
}

fn resolve_scoped_thing_id(
    raw: Option<&str>,
    allow_for_post: bool,
) -> Result<Option<String>, Error> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !allow_for_post {
        return Err(Error::validation(
            "thing_id is not supported on this endpoint",
        ));
    }
    Ok(Some(normalize_thing_id(raw)?.to_string()))
}

fn parse_compat_key(raw: &str) -> Result<(String, String), Error> {
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
    Ok((channel_id.to_string(), password.to_string()))
}

fn split_query_list(raw: Option<&str>) -> Vec<String> {
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

fn parse_query_metadata(raw: Option<&str>) -> Result<JsonMap<String, Value>, Error> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(JsonMap::new());
    };
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|_| Error::validation("metadata must be a JSON object"))?;
    parse_metadata_map_value(parsed).map_err(Error::validation)
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn insert_metadata_string(metadata: &mut JsonMap<String, Value>, key: &str, raw: Option<&str>) {
    if let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) {
        metadata.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn ntfy_priority_to_severity(raw: Option<&str>) -> Option<String> {
    match raw.map(str::trim) {
        Some("1") | Some("2") => Some("info".to_string()),
        Some("3") => Some("warning".to_string()),
        Some("4") | Some("5") => Some("critical".to_string()),
        _ => None,
    }
}

fn bark_level_to_severity(raw: Option<&str>) -> Option<String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("active") | Some("critical") => Some("critical".to_string()),
        Some("time-sensitive") | Some("timesensitive") | Some("warning") => {
            Some("warning".to_string())
        }
        Some("passive") | Some("info") => Some("info".to_string()),
        _ => None,
    }
}
