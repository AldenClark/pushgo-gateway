use super::*;

impl CompatBarkV1Query {
    pub(super) fn into_intent(
        self,
        key: CompatKey,
        body: Option<String>,
        title: Option<String>,
    ) -> Result<MessageIntent, Error> {
        let mut metadata = parse_query_metadata(self.metadata.as_deref())?;
        insert_metadata_string(&mut metadata, "compat.bark.sound", self.sound.as_deref());
        insert_metadata_string(&mut metadata, "compat.bark.icon", self.icon.as_deref());
        insert_metadata_string(&mut metadata, "compat.bark.group", self.group.as_deref());
        Ok(MessageIntent {
            channel_id: key.channel_id,
            password: key.password,
            op_id: self.op_id,
            thing_id: None,
            occurred_at: Some(Utc::now().timestamp()),
            title: title.unwrap_or_else(|| "Notification".to_string()),
            body,
            severity: Self::severity_for_level(self.level.as_deref()),
            ttl: None,
            url: self.url,
            images: split_query_list(self.images.as_deref()),
            ciphertext: None,
            tags: split_query_list(self.tags.as_deref()),
            metadata,
        })
    }

    fn severity_for_level(raw: Option<&str>) -> Option<String> {
        match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("active") | Some("critical") => Some("critical".to_string()),
            Some("time-sensitive") | Some("timesensitive") | Some("warning") => {
                Some("warning".to_string())
            }
            Some("passive") | Some("info") => Some("info".to_string()),
            _ => None,
        }
    }
}

impl CompatBarkV2Payload {
    fn into_intent(self, key: CompatKey) -> MessageIntent {
        let mut metadata = self.metadata;
        insert_metadata_string(&mut metadata, "compat.bark.sound", self.sound.as_deref());
        insert_metadata_string(&mut metadata, "compat.bark.icon", self.icon.as_deref());
        insert_metadata_string(&mut metadata, "compat.bark.group", self.group.as_deref());
        MessageIntent {
            channel_id: key.channel_id,
            password: key.password,
            op_id: self.op_id,
            thing_id: None,
            occurred_at: Some(Utc::now().timestamp()),
            title: self.title.unwrap_or_else(|| "Notification".to_string()),
            body: self.body,
            severity: CompatBarkV1Query::severity_for_level(self.level.as_deref()),
            ttl: None,
            url: self.url,
            images: self.images,
            ciphertext: None,
            tags: self.tags,
            metadata,
        }
    }
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
    let intent = query.into_intent(CompatKey::parse(&device_key)?, body, title)?;
    dispatch_message_intent(state, intent, None).await
}

pub(crate) async fn compat_bark_v2_push(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<CompatBarkV2Payload>,
) -> HttpResult {
    let key = CompatKey::parse(&payload.device_key)?;
    let intent = payload.into_intent(key);
    dispatch_message_intent(&state, intent, None).await
}
