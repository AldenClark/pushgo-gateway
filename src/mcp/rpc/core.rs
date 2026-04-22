use super::*;

const CHANNEL_RECENT_SUMMARY_LIMIT: usize = 20;

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

impl<'a> McpRpcService<'a> {
    pub(super) fn new(state: &'a AppState, mcp: &'a McpState, auth: &'a McpAuthContext) -> Self {
        Self { state, mcp, auth }
    }
}

impl McpRpcService<'_> {
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

    pub(super) async fn attach_channel_context(
        &self,
        value: &mut Value,
        channel_id: &str,
    ) {
        let channel_name = self.channel_name(channel_id).await;
        if let Some(map) = value.as_object_mut() {
            map.insert("channel_id".to_string(), Value::String(channel_id.to_string()));
            map.insert(
                "channel_name".to_string(),
                channel_name
                    .as_ref()
                    .map(|name| Value::String(name.clone()))
                    .unwrap_or(Value::Null),
            );
            map.insert(
                "channel_display".to_string(),
                Value::String(Self::channel_display(channel_id, channel_name.as_deref())),
            );
        }
    }

    fn recent_channel_summaries(&self, channel_id: &str) -> Value {
        json!({
            "recent_limit": CHANNEL_RECENT_SUMMARY_LIMIT,
            "source": "trace_and_stats",
            "recent_summaries": [],
            "message_summaries": [],
            "event_summaries": [],
            "note": format!(
                "channel {} recent timeline moved to trace logs and ops stats",
                channel_id
            )
        })
    }

    pub(super) async fn load_authorized_channels(&self) -> Result<Vec<Value>, String> {
        let McpAuthContext::OAuth { principal_id, .. } = self.auth else {
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
                Err(_) => None,
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
                    map.insert(
                        "recent_message_event_summary".to_string(),
                        recent,
                    );
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
                  "op_id": {"type":"string","description":"可选幂等键，不传由 gateway 生成"},
                  "thing_id": {"type":"string","description":"可选 thing 作用域"},
                  "occurred_at": {"type":"integer","description":"可选，秒级时间戳"},
                  "title": {"type":"string","description":"标题"},
                  "body": {"type":"string","description":"正文"},
                  "severity": {"type":"string","description":"等级"},
                  "ttl": {"type":"integer","description":"TTL 秒"},
                  "url": {"type":"string","description":"跳转链接"},
                  "images": {"type":"array","items":{"type":"string"},"description":"图片 URL 列表"},
                  "ciphertext": {"type":"string","description":"可选密文"},
                  "tags": {"type":"array","items":{"type":"string"},"description":"标签列表"},
                  "metadata": {"type":"object","description":"标量 metadata map"}
                }
              }
            },
            {
              "name": "pushgo.event.create",
              "description": "创建事件（event/create）。字段与网关事件接口保持一致。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"thing_id":{"type":"string"},"event_time":{"type":"integer"},"title":{"type":"string"},"description":{"type":"string"},"status":{"type":"string"},"message":{"type":"string"},"severity":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"images":{"type":"array","items":{"type":"string"}},"started_at":{"type":"integer"},"ended_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.event.update",
              "description": "更新事件（event/update）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id","event_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"event_id":{"type":"string"},"thing_id":{"type":"string"},"event_time":{"type":"integer"},"title":{"type":"string"},"description":{"type":"string"},"status":{"type":"string"},"message":{"type":"string"},"severity":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"images":{"type":"array","items":{"type":"string"}},"started_at":{"type":"integer"},"ended_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.event.close",
              "description": "关闭事件（event/close）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id","event_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"event_id":{"type":"string"},"thing_id":{"type":"string"},"event_time":{"type":"integer"},"title":{"type":"string"},"description":{"type":"string"},"status":{"type":"string"},"message":{"type":"string"},"severity":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"images":{"type":"array","items":{"type":"string"}},"started_at":{"type":"integer"},"ended_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.thing.create",
              "description": "创建对象（thing/create）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"created_at":{"type":"integer"},"title":{"type":"string"},"description":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"external_ids":{"type":"object"},"location_type":{"type":"string"},"location_value":{"type":"string"},"primary_image":{"type":"string"},"images":{"type":"array","items":{"type":"string"}},"observed_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.thing.update",
              "description": "更新对象（thing/update）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id","thing_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"thing_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"external_ids":{"type":"object"},"location_type":{"type":"string"},"location_value":{"type":"string"},"primary_image":{"type":"string"},"images":{"type":"array","items":{"type":"string"}},"observed_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.thing.archive",
              "description": "归档对象（thing/archive）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id","thing_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"thing_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"external_ids":{"type":"object"},"location_type":{"type":"string"},"location_value":{"type":"string"},"primary_image":{"type":"string"},"images":{"type":"array","items":{"type":"string"}},"observed_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
            },
            {
              "name": "pushgo.thing.delete",
              "description": "删除对象（thing/delete）。",
              "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id","thing_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"},"op_id":{"type":"string"},"thing_id":{"type":"string"},"deleted_at":{"type":"integer"},"title":{"type":"string"},"description":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"external_ids":{"type":"object"},"location_type":{"type":"string"},"location_value":{"type":"string"},"primary_image":{"type":"string"},"images":{"type":"array","items":{"type":"string"}},"observed_at":{"type":"integer"},"attrs":{"type":"object"},"metadata":{"type":"object"}}}
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
        let payload = params.ok_or_else(|| "missing params".to_string())?;
        let call: ToolCallEnvelope =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        if Self::is_send_tool_name(call.name.as_str()) {
            ensure_scope(self.auth, McpScope::Tools)?;
        }

        match call.name.as_str() {
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
            _ => Err("unknown tool".to_string()),
        }
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

    pub(super) fn auth_mode_name(&self) -> &'static str {
        match self.auth {
            McpAuthContext::OAuth { .. } => "oauth2",
            McpAuthContext::Legacy => "legacy",
        }
    }

    pub(super) async fn authorize_channel(
        &self,
        channel_id: &str,
        password: Option<String>,
    ) -> Result<crate::api::handlers::channel_auth::AuthorizedChannel, String> {
        match self.auth {
            McpAuthContext::OAuth { principal_id, .. } => {
                if password.as_deref().is_some_and(|v| !v.trim().is_empty()) {
                    return Err("password_forbidden_in_oauth_mode".to_string());
                }
                if !self.mcp.has_grant(principal_id, channel_id).await {
                    return Err("channel_not_bound".to_string());
                }
                crate::api::handlers::channel_auth::authorize_channel_exists(self.state, channel_id)
                    .await
                    .map_err(|err| err.to_string())
            }
            McpAuthContext::Legacy => {
                let password = password
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| "password_required_in_legacy_mode".to_string())?;
                crate::api::handlers::channel_auth::authorize_channel_by_password(
                    self.state, channel_id, &password,
                )
                .await
                .map_err(|err| err.to_string())
            }
        }
    }

    pub(super) async fn http_result_to_value(&self, result: HttpResult) -> Result<Value, String> {
        let response = result.map_err(|err| err.to_string())?;
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .map_err(|err| err.to_string())?;
        let payload = parse_status_response(&body)?;
        Ok(json!({"status": status, "payload": payload}))
    }
}

fn parse_status_response(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Value>(body).map_err(|err| err.to_string())
}
