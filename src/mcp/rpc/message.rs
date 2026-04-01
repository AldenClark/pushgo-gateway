use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(default)]
    occurred_at: Option<i64>,
    title: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    ttl: Option<i64>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    metadata: serde_json::Map<String, Value>,
}

impl McpRpcService<'_> {
    pub(super) async fn call_message_send(&self, args: Value) -> Result<Value, String> {
        let parsed: MessageArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;

        let scoped_thing_id = parsed
            .thing_id
            .as_deref()
            .map(|raw| {
                crate::api::handlers::entity_input::EntityId::parse(raw, "thing_id")
                    .map(crate::api::handlers::entity_input::EntityId::into_inner)
            })
            .transpose()
            .map_err(|err| err.to_string())?;

        let intent = crate::api::handlers::message::MessageDispatchIntent {
            op_id: parsed.op_id,
            occurred_at: parsed.occurred_at,
            title: parsed.title,
            body: parsed.body,
            severity: parsed.severity,
            ttl: parsed.ttl,
            url: parsed.url,
            images: parsed.images,
            ciphertext: parsed.ciphertext,
            tags: parsed.tags,
            metadata: parsed.metadata,
        };

        let response = crate::api::handlers::message::dispatch_message_authorized_intent(
            self.state,
            authorized_channel,
            intent,
            scoped_thing_id,
        )
        .await;

        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }
}
