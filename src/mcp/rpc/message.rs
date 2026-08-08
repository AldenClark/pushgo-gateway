use super::*;
use crate::api::handlers::send_ack::SendAck;

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
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    occurred_at: Option<i64>,
    title: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
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
    #[tracing::instrument(name = "gateway.mcp.rpc.message_send", skip_all)]
    pub(super) async fn call_message_send(&self, args: Value) -> Result<Value, String> {
        let parsed: MessageArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("message_send_parse_args", &err.to_string());
            err.to_string()
        })?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;

        let authorized_context =
            crate::api::handlers::delivery_core_adapter::authorized_channel_context(
                authorized_channel,
            );
        let result = crate::delivery_core::submit::submit_command(
            crate::delivery_core::submit::SubmitContext {
                runtime: self.state,
                now_millis: chrono::Utc::now().timestamp_millis(),
            },
            crate::delivery_core::submit::SubmitCommand {
                source: crate::delivery_core::source::IngressSource::McpTool,
                auth: crate::delivery_core::auth::SubmitAuth::AuthorizedChannel(
                    authorized_context.clone(),
                ),
                channel: crate::delivery_core::submit::ChannelSelector::Authorized(
                    authorized_context,
                ),
                command: crate::delivery_core::submit::DomainCommandInput::Message(Box::new(
                    crate::domain_model::message::MessageInput {
                        op_id: parsed.op_id,
                        thing_id: parsed.thing_id,
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
                    },
                )),
                response_mode: crate::delivery_core::submit::ResponseMode::McpJson,
            },
        )
        .await
        .map_err(crate::api::handlers::delivery_core_adapter::core_error_to_api_error)
        .map_err(|err| err.client_safe_message().into_owned())?;

        let value = mcp_send_ack_value(result)?;
        self.emit_rpc_completed("message_send");
        Ok(value)
    }
}

pub(super) fn mcp_send_ack_value(
    result: crate::delivery_core::response::SubmitResult,
) -> Result<Value, String> {
    let ack = SendAck::from_submit_result(result).map_err(|err| err.to_string())?;
    serde_json::to_value(ack).map_err(|err| err.to_string())
}
