use super::*;

const CHANNEL_RECENT_SUMMARY_LIMIT: usize = 20;

type SchemaProperties = serde_json::Map<String, Value>;

#[derive(Debug, Deserialize)]
struct ToolCallEnvelope {
    name: String,
    #[serde(default)]
    arguments: Value,
}

pub(super) struct McpRpcService<'a> {
    pub(super) state: &'a AppState,
    pub(super) mcp: &'a McpState,
    pub(super) auth: &'a McpAuthContext,
}

fn schema_object(required: &[&str], properties: SchemaProperties) -> Value {
    let required = required
        .iter()
        .map(|field| Value::String((*field).to_string()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn string_property() -> Value {
    json!({"type": "string"})
}

fn integer_property() -> Value {
    json!({"type": "integer"})
}

fn object_property() -> Value {
    json!({"type": "object"})
}

fn string_array_property() -> Value {
    json!({"type": "array", "items": {"type": "string"}})
}

fn ciphertext_property() -> Value {
    json!({"type": "string", "description": "可选密文(JSON字符串)，仅使用当前接口同名业务字段"})
}

fn insert_auth_properties(properties: &mut SchemaProperties) {
    properties.insert("channel_id".to_string(), string_property());
    properties.insert("password".to_string(), string_property());
    properties.insert("op_id".to_string(), string_property());
}

fn insert_event_patch_properties(properties: &mut SchemaProperties) {
    properties.insert("thing_id".to_string(), string_property());
    properties.insert("event_time".to_string(), integer_property());
    properties.insert("title".to_string(), string_property());
    properties.insert("description".to_string(), string_property());
    properties.insert("status".to_string(), string_property());
    properties.insert("message".to_string(), string_property());
    properties.insert("severity".to_string(), string_property());
    properties.insert("tags".to_string(), string_array_property());
    properties.insert("images".to_string(), string_array_property());
    properties.insert("ciphertext".to_string(), ciphertext_property());
    properties.insert("attrs".to_string(), object_property());
    properties.insert("metadata".to_string(), object_property());
}

fn event_create_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    insert_event_patch_properties(&mut properties);
    properties.insert("started_at".to_string(), integer_property());
    schema_object(&["channel_id"], properties)
}

fn event_update_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    properties.insert("event_id".to_string(), string_property());
    insert_event_patch_properties(&mut properties);
    schema_object(&["channel_id", "event_id"], properties)
}

fn event_close_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    properties.insert("event_id".to_string(), string_property());
    insert_event_patch_properties(&mut properties);
    properties.insert("ended_at".to_string(), integer_property());
    schema_object(&["channel_id", "event_id"], properties)
}

fn insert_thing_patch_properties(properties: &mut SchemaProperties) {
    properties.insert("title".to_string(), string_property());
    properties.insert("description".to_string(), string_property());
    properties.insert("tags".to_string(), string_array_property());
    properties.insert("external_ids".to_string(), object_property());
    properties.insert("location_type".to_string(), string_property());
    properties.insert("location_value".to_string(), string_property());
    properties.insert("primary_image".to_string(), string_property());
    properties.insert("images".to_string(), string_array_property());
    properties.insert("ciphertext".to_string(), ciphertext_property());
    properties.insert("observed_at".to_string(), integer_property());
    properties.insert("attrs".to_string(), object_property());
    properties.insert("metadata".to_string(), object_property());
}

fn thing_create_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    properties.insert("created_at".to_string(), integer_property());
    insert_thing_patch_properties(&mut properties);
    schema_object(&["channel_id"], properties)
}

fn thing_update_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    properties.insert("thing_id".to_string(), string_property());
    insert_thing_patch_properties(&mut properties);
    schema_object(&["channel_id", "thing_id"], properties)
}

fn thing_archive_schema() -> Value {
    thing_update_schema()
}

fn thing_delete_schema() -> Value {
    let mut properties = SchemaProperties::new();
    insert_auth_properties(&mut properties);
    properties.insert("thing_id".to_string(), string_property());
    properties.insert("deleted_at".to_string(), integer_property());
    insert_thing_patch_properties(&mut properties);
    schema_object(&["channel_id", "thing_id"], properties)
}

impl<'a> McpRpcService<'a> {
    pub(super) fn new(state: &'a AppState, mcp: &'a McpState, auth: &'a McpAuthContext) -> Self {
        Self { state, mcp, auth }
    }
}

impl McpRpcService<'_> {
    pub(super) fn emit_rpc_rejected(&self, reason: &str) {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "mcp.rpc.rejected",
            reason = %(reason)
        );
    }

    pub(super) fn emit_rpc_failed(&self, stage: &str, error: &str) {
        let error_fingerprint = McpState::token_hash(error);
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "mcp.rpc.failed",
            stage = %(stage),
            error_fingerprint = %(&error_fingerprint[..16])
        );
    }

    pub(super) fn emit_rpc_completed(&self, op: &str) {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "mcp.rpc.completed",
            op = %(op)
        );
    }

    pub(super) async fn channel_name(&self, channel_id: &str) -> Option<String> {
        let channel_id = parse_channel_id(channel_id).ok()?;
        self.state
            .store
            .channel_info(channel_id)
            .await
            .ok()
            .flatten()
            .map(|info| info.alias)
    }

    pub(super) fn channel_display(channel_id: &str, channel_name: Option<&str>) -> String {
        match channel_name.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name) => format!("{name} ({channel_id})"),
            None => channel_id.to_string(),
        }
    }

    fn recent_channel_summaries(&self, channel_id: &str) -> Value {
        json!({
            "recent_limit": CHANNEL_RECENT_SUMMARY_LIMIT,
            "source": "trace_and_runtime_counters",
            "recent_summaries": [],
            "message_summaries": [],
            "event_summaries": [],
            "note": format!(
                "channel {} recent timeline moved to trace logs and runtime counters",
                channel_id
            )
        })
    }

    pub(super) async fn load_authorized_channels(&self) -> Result<Vec<Value>, String> {
        let McpAuthContext::OAuth { principal_id, .. } = self.auth else {
            self.emit_rpc_rejected("auth_mode_not_supported");
            return Err("auth_mode_not_supported".to_string());
        };
        let grants = self.mcp.list_grants(principal_id).await;
        let mut channels = Vec::with_capacity(grants.len());
        for grant in grants {
            let channel_name = match parse_channel_id(&grant.channel_id) {
                Ok(channel_id) => self
                    .state
                    .store
                    .channel_info(channel_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|info| info.alias),
                Err(_) => {
                    self.emit_rpc_rejected("invalid_channel_id_in_grants");
                    None
                }
            };
            channels.push(json!({
                "channel_id": grant.channel_id,
                "channel_name": channel_name,
                "channel_display": Self::channel_display(
                    &grant.channel_id,
                    channel_name.as_deref()
                ),
                "granted_at": grant.granted_at,
                "expires_at": grant.expires_at,
                "status": "active"
            }));
        }
        Ok(channels)
    }

    pub(super) async fn resources_list_result(&self) -> Result<Value, String> {
        let channels = self.load_authorized_channels().await?;
        let mut resources = vec![json!({
            "uri": "pushgo://channels",
            "name": "Authorized Channels",
            "description": "All channels authorized for current OAuth principal",
            "mimeType": "application/json"
        })];
        for item in channels {
            let channel_id = item
                .get("channel_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if channel_id.is_empty() {
                continue;
            }
            let channel_name = item
                .get("channel_name")
                .and_then(Value::as_str)
                .unwrap_or("Unnamed Channel");
            resources.push(json!({
                "uri": format!("pushgo://channels/{channel_id}"),
                "name": channel_name,
                "mimeType": "application/json"
            }));
        }
        Ok(json!({ "resources": resources }))
    }

    pub(super) async fn resources_read_result(&self, uri: Option<&str>) -> Result<Value, String> {
        let uri = uri.ok_or_else(|| "uri required".to_string())?;
        let channels = self.load_authorized_channels().await?;
        if uri == "pushgo://channels" {
            let text = serde_json::to_string(&json!({ "channels": channels }))
                .map_err(|err| err.to_string())?;
            return Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text
                }]
            }));
        }
        let prefix = "pushgo://channels/";
        if let Some(channel_id) = uri.strip_prefix(prefix) {
            let selected = channels.into_iter().find(|item| {
                item.get("channel_id")
                    .and_then(Value::as_str)
                    .map(|value| value == channel_id)
                    .unwrap_or(false)
            });
            if let Some(channel) = selected {
                let mut payload = channel;
                if let Some(map) = payload.as_object_mut() {
                    let recent = self.recent_channel_summaries(channel_id);
                    map.insert("recent_message_event_summary".to_string(), recent);
                }
                let text = serde_json::to_string(&payload).map_err(|err| err.to_string())?;
                return Ok(json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text
                    }]
                }));
            }
            return Err("resource_not_found".to_string());
        }
        Err("resource_not_found".to_string())
    }

    pub(super) fn tools_list_result(&self) -> Value {
        let event_create_schema = event_create_schema();
        let event_update_schema = event_update_schema();
        let event_close_schema = event_close_schema();
        let thing_create_schema = thing_create_schema();
        let thing_update_schema = thing_update_schema();
        let thing_archive_schema = thing_archive_schema();
        let thing_delete_schema = thing_delete_schema();

        json!({
          "tools": [
            {
              "name": "pushgo.message.send",
              "description": "发送普通消息到 channel。OAuth2 模式传 channel_id，legacy 模式必须传 channel_id+password。",
              "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["channel_id", "title"],
                "properties": {
                  "channel_id": {"type":"string","description":"目标频道 ID"},
                  "password": {"type":"string","description":"legacy 模式必填，OAuth2 模式禁止"},
                  "op_id": {"type":"string","description":"禁止传入；op_id 由 gateway 生成并在响应中返回"},
                  "thing_id": {"type":"string","description":"可选 thing 作用域"},
                  "occurred_at": {"type":"integer","description":"可选，支持 Unix 秒/毫秒时间戳，网关归一化为毫秒"},
                  "title": {"type":"string","description":"标题"},
                  "body": {"type":"string","description":"正文"},
                  "severity": {"type":"string","description":"等级"},
                  "ttl": {"type":"integer","description":"可选过期时间，支持 Unix 秒/毫秒时间戳，网关归一化为毫秒"},
                  "url": {"type":"string","description":"跳转链接"},
                  "images": {"type":"array","items":{"type":"string"},"description":"图片 URL 列表"},
                  "ciphertext": {"type":"string","description":"可选密文(JSON字符串)，仅使用当前接口同名业务字段"},
                  "tags": {"type":"array","items":{"type":"string"},"description":"标签列表"},
                  "metadata": {"type":"object","description":"标量 metadata map"}
                }
              }
            },
            {
              "name": "pushgo.event.create",
              "description": "创建事件（event/create）。字段与网关事件接口保持一致。",
              "inputSchema": event_create_schema
            },
            {
              "name": "pushgo.event.update",
              "description": "更新事件（event/update）。",
              "inputSchema": event_update_schema
            },
            {
              "name": "pushgo.event.close",
              "description": "关闭事件（event/close）。",
              "inputSchema": event_close_schema
            },
            {
              "name": "pushgo.thing.create",
              "description": "创建对象（thing/create）。",
              "inputSchema": thing_create_schema
            },
            {
              "name": "pushgo.thing.update",
              "description": "更新对象（thing/update）。",
              "inputSchema": thing_update_schema
            },
            {
              "name": "pushgo.thing.archive",
              "description": "归档对象（thing/archive）。",
              "inputSchema": thing_archive_schema
            },
            {
              "name": "pushgo.thing.delete",
              "description": "删除对象（thing/delete）。",
              "inputSchema": thing_delete_schema
            },
            {
              "name": "pushgo.channel.bind.start",
              "description": "创建 bind/revoke 会话，返回 bind_url。优先用于 elicitation URL mode。",
              "inputSchema": {"type":"object","additionalProperties":false,"properties":{"requested_channel_id":{"type":"string"},"redirect_uri":{"type":"string"},"action":{"type":"string","enum":["bind","revoke"]}}}
            },
            {
              "name": "pushgo.channel.bind.status",
              "description": "轮询 bind 会话状态。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["bind_session_id"],"properties":{"bind_session_id":{"type":"string"}}}
            },
            {
              "name": "pushgo.channel.list",
              "description": "列出当前 OAuth principal 已授权 channel。",
              "inputSchema": {"type":"object","additionalProperties":false}
            },
            {
              "name": "pushgo.channel.unbind",
              "description": "解绑已授权 channel（OAuth 模式）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id"],"properties":{"channel_id":{"type":"string"}}}
            }
          ]
        })
    }

    pub(super) async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value, String> {
        let payload = params.ok_or_else(|| {
            self.emit_rpc_rejected("missing_params");
            "missing params".to_string()
        })?;
        let call: ToolCallEnvelope = serde_json::from_value(payload).map_err(|err| {
            self.emit_rpc_failed("parse_tool_call_envelope", &err.to_string());
            err.to_string()
        })?;
        if Self::is_send_tool_name(call.name.as_str()) {
            ensure_scope(self.auth, McpScope::Tools).inspect_err(|err| {
                self.emit_rpc_rejected(err);
            })?;
        }

        let result = match call.name.as_str() {
            "pushgo.message.send" => self.call_message_send(call.arguments).await,
            "pushgo.event.create" => self.call_event_create(call.arguments).await,
            "pushgo.event.update" => self.call_event_update(call.arguments).await,
            "pushgo.event.close" => self.call_event_close(call.arguments).await,
            "pushgo.thing.create" => self.call_thing_create(call.arguments).await,
            "pushgo.thing.update" => self.call_thing_update(call.arguments).await,
            "pushgo.thing.archive" => self.call_thing_archive(call.arguments).await,
            "pushgo.thing.delete" => self.call_thing_delete(call.arguments).await,
            "pushgo.channel.bind.start" => self.call_bind_start(call.arguments).await,
            "pushgo.channel.bind.status" => self.call_bind_status(call.arguments).await,
            "pushgo.channel.list" => self.call_channel_list().await,
            "pushgo.channel.unbind" => self.call_channel_unbind(call.arguments).await,
            _ => {
                self.emit_rpc_rejected("unknown_tool");
                Err("unknown tool".to_string())
            }
        };
        if let Err(err) = &result {
            self.emit_rpc_failed("handle_tools_call", err);
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "mcp.rpc.tool_call_failed",
                tool_name = %(call.name.as_str()),
                error_fingerprint = %(&McpState::token_hash(err)[..16])
            );
        } else {
            self.emit_rpc_completed("handle_tools_call");
        }
        result
    }

    fn is_send_tool_name(name: &str) -> bool {
        matches!(
            name,
            "pushgo.message.send"
                | "pushgo.event.create"
                | "pushgo.event.update"
                | "pushgo.event.close"
                | "pushgo.thing.create"
                | "pushgo.thing.update"
                | "pushgo.thing.archive"
                | "pushgo.thing.delete"
        )
    }

    pub(super) async fn authorize_channel(
        &self,
        channel_id: &str,
        password: Option<String>,
    ) -> Result<crate::api::handlers::channel_auth::AuthorizedChannel, String> {
        match self.auth {
            McpAuthContext::OAuth { principal_id, .. } => {
                if password.as_deref().is_some_and(|v| !v.trim().is_empty()) {
                    self.emit_rpc_rejected("password_forbidden_in_oauth_mode");
                    return Err("password_forbidden_in_oauth_mode".to_string());
                }
                if !self.mcp.has_grant(principal_id, channel_id).await {
                    self.emit_rpc_rejected("channel_not_bound");
                    return Err("channel_not_bound".to_string());
                }
                crate::api::handlers::channel_auth::authorize_channel_exists(self.state, channel_id)
                    .await
                    .map_err(|err| {
                        self.emit_rpc_failed("authorize_channel_exists", &err.to_string());
                        err.client_safe_message().into_owned()
                    })
            }
            McpAuthContext::Legacy => {
                let password = password
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        self.emit_rpc_rejected("password_required_in_legacy_mode");
                        "password_required_in_legacy_mode".to_string()
                    })?;
                crate::api::handlers::channel_auth::authorize_channel_by_password(
                    self.state, channel_id, &password,
                )
                .await
                .map_err(|err| {
                    self.emit_rpc_failed("authorize_channel_by_password", &err.to_string());
                    err.client_safe_message().into_owned()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_property(schema: &Value, name: &str) -> bool {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("schema properties")
            .contains_key(name)
    }

    #[test]
    fn event_tool_schemas_keep_route_specific_lifecycle_fields_separate() {
        let create_schema = event_create_schema();
        assert!(has_property(&create_schema, "started_at"));
        assert!(!has_property(&create_schema, "ended_at"));

        let update_schema = event_update_schema();
        assert!(has_property(&update_schema, "event_id"));
        assert!(!has_property(&update_schema, "started_at"));
        assert!(!has_property(&update_schema, "ended_at"));

        let close_schema = event_close_schema();
        assert!(has_property(&close_schema, "event_id"));
        assert!(!has_property(&close_schema, "started_at"));
        assert!(has_property(&close_schema, "ended_at"));
    }

    #[test]
    fn thing_tool_schemas_keep_delete_fields_out_of_update_and_archive() {
        let create_schema = thing_create_schema();
        assert!(has_property(&create_schema, "created_at"));
        assert!(!has_property(&create_schema, "thing_id"));
        assert!(!has_property(&create_schema, "deleted_at"));

        let update_schema = thing_update_schema();
        assert!(has_property(&update_schema, "thing_id"));
        assert!(!has_property(&update_schema, "created_at"));
        assert!(!has_property(&update_schema, "deleted_at"));

        let archive_schema = thing_archive_schema();
        assert!(has_property(&archive_schema, "thing_id"));
        assert!(!has_property(&archive_schema, "created_at"));
        assert!(!has_property(&archive_schema, "deleted_at"));

        let delete_schema = thing_delete_schema();
        assert!(has_property(&delete_schema, "thing_id"));
        assert!(!has_property(&delete_schema, "created_at"));
        assert!(has_property(&delete_schema, "deleted_at"));
    }
}
