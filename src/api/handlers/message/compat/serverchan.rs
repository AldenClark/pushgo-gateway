use super::*;

impl CompatServerChanPayload {
    fn into_intent(self, key: CompatKey) -> Result<MessageIntent, Error> {
        let mut metadata = parse_query_metadata(self.metadata.as_deref())?;
        insert_metadata_string(&mut metadata, "compat.serverchan.url", self.url.as_deref());
        Ok(MessageIntent {
            channel_id: key.channel_id,
            password: key.password,
            op_id: self.op_id,
            thing_id: None,
            occurred_at: Some(Utc::now().timestamp()),
            title: self
                .title
                .or(self.text)
                .unwrap_or_else(|| "Notification".to_string()),
            body: self.desp.or(self.body),
            severity: None,
            ttl: None,
            url: self.url,
            images: Vec::new(),
            ciphertext: None,
            tags: Vec::new(),
            metadata,
        })
    }
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
    let intent = payload.into_intent(CompatKey::parse(&sendkey)?)?;
    dispatch_message_intent(state, intent, None).await
}
