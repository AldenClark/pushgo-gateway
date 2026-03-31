pub(crate) async fn mcp_get(State(state): State<AppState>) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    Json(json!({
        "name": "pushgo-gateway-mcp",
        "streamable_http": true,
        "oauth_enabled": mcp.oauth_ready(),
        "legacy_auth_enabled": mcp.config.legacy_auth_enabled,
    }))
    .into_response()
}

pub(crate) async fn mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<JsonRpcRequest>,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    if request.jsonrpc != "2.0" {
        return Json(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: None,
            error: Some(json!({"code": -32600, "message": "invalid jsonrpc version"})),
        })
        .into_response();
    }

    let auth = match authenticate_mcp(&headers, mcp).await {
        Ok(auth) => auth,
        Err(_) => {
            return Json(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: None,
                error: Some(json!({"code": -32001, "message": "auth_unauthorized"})),
            })
            .into_response();
        }
    };

    if request.method == "tools/list" {
        let result = tools_list_result();
        return Json(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: Some(result),
            error: None,
        })
        .into_response();
    }

    if request.method == "tools/call" {
        let result = match handle_tools_call(&state, mcp, &auth, request.params).await {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: None,
                error: Some(json!({"code": -32010, "message": err})),
            },
        };
        return Json(result).into_response();
    }

    Json(JsonRpcResponse {
        jsonrpc: "2.0",
        id: request.id,
        result: None,
        error: Some(json!({"code": -32601, "message": "method not found"})),
    })
    .into_response()
}

fn tools_list_result() -> Value {
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
          "inputSchema": {"type":"object","additionalProperties":false,"required":["channel_id"],"properties":{"channel_id":{"type":"string"},"password":{"type":"string"}}}
        }
      ]
    })
}

#[derive(Debug, Deserialize)]
struct ToolCallEnvelope {
    name: String,
    #[serde(default)]
    arguments: Value,
}

async fn handle_tools_call(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    params: Option<Value>,
) -> Result<Value, String> {
    let payload = params.ok_or_else(|| "missing params".to_string())?;
    let call: ToolCallEnvelope = serde_json::from_value(payload).map_err(|err| err.to_string())?;
    if is_send_tool_name(call.name.as_str()) {
        ensure_scope(auth, "mcp:tools")?;
    }

    match call.name.as_str() {
        "pushgo.message.send" => call_message_send(state, mcp, auth, call.arguments).await,
        "pushgo.event.create" => call_event_create(state, mcp, auth, call.arguments).await,
        "pushgo.event.update" => call_event_update(state, mcp, auth, call.arguments).await,
        "pushgo.event.close" => call_event_close(state, mcp, auth, call.arguments).await,
        "pushgo.thing.create" => call_thing_create(state, mcp, auth, call.arguments).await,
        "pushgo.thing.update" => call_thing_update(state, mcp, auth, call.arguments).await,
        "pushgo.thing.archive" => call_thing_archive(state, mcp, auth, call.arguments).await,
        "pushgo.thing.delete" => call_thing_delete(state, mcp, auth, call.arguments).await,
        "pushgo.channel.bind.start" => call_bind_start(mcp, auth, call.arguments).await,
        "pushgo.channel.bind.status" => call_bind_status(mcp, auth, call.arguments).await,
        "pushgo.channel.list" => call_channel_list(mcp, auth).await,
        "pushgo.channel.unbind" => call_channel_unbind(state, mcp, auth, call.arguments).await,
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

fn auth_mode_name(auth: &McpAuthContext) -> &'static str {
    match auth {
        McpAuthContext::OAuth { .. } => "oauth2",
        McpAuthContext::Legacy => "legacy",
    }
}

async fn authorize_mcp_channel(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    channel_id: &str,
    password: Option<String>,
) -> Result<crate::api::handlers::channel_auth::AuthorizedChannel, String> {
    match auth {
        McpAuthContext::OAuth { principal_id, .. } => {
            if password.as_deref().is_some_and(|v| !v.trim().is_empty()) {
                return Err("password_forbidden_in_oauth_mode".to_string());
            }
            if !mcp.has_grant(principal_id, channel_id).await {
                return Err("channel_not_bound".to_string());
            }
            crate::api::handlers::channel_auth::authorize_channel_exists(state, channel_id)
                .await
                .map_err(|err| err.to_string())
        }
        McpAuthContext::Legacy => {
            let password = password
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "password_required_in_legacy_mode".to_string())?;
            crate::api::handlers::channel_auth::authorize_channel_by_password(
                state, channel_id, &password,
            )
            .await
            .map_err(|err| err.to_string())
        }
    }
}

fn parse_status_response(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Value>(body).map_err(|err| err.to_string())
}

async fn http_result_to_value(result: HttpResult) -> Result<Value, String> {
    let response = result.map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .map_err(|err| err.to_string())?;
    let payload = parse_status_response(&body)?;
    Ok(json!({"status": status, "payload": payload}))
}

async fn call_message_send(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: MessageArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;

    let scoped_thing_id = parsed
        .thing_id
        .as_deref()
        .map(crate::api::handlers::message::normalize_thing_id)
        .transpose()
        .map_err(|err| err.to_string())?
        .map(ToString::to_string);

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
        state,
        authorized_channel,
        intent,
        scoped_thing_id,
    )
    .await;

    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(default)]
    event_time: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    started_at: Option<i64>,
    #[serde(default)]
    ended_at: Option<i64>,
    #[serde(default)]
    attrs: serde_json::Map<String, Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, Value>,
}

fn event_payload_json(args: EventArgs) -> Value {
    json!({
        "channel_id": args.channel_id,
        "password": args.password,
        "op_id": args.op_id,
        "event_id": args.event_id,
        "thing_id": args.thing_id,
        "event_time": args.event_time,
        "title": args.title,
        "description": args.description,
        "status": args.status,
        "message": args.message,
        "severity": args.severity,
        "tags": args.tags,
        "images": args.images,
        "started_at": args.started_at,
        "ended_at": args.ended_at,
        "attrs": args.attrs,
        "metadata": args.metadata,
    })
}

async fn call_event_create(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    let mut payload = event_payload_json(parsed);
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("event_id");
    }
    let req: crate::api::handlers::event::EventCreateRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::event::event_create_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

async fn call_event_update(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    if parsed
        .event_id
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err("event_id required".to_string());
    }
    let payload = event_payload_json(parsed);
    let req: crate::api::handlers::event::EventUpdateRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::event::event_update_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

async fn call_event_close(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    if parsed
        .event_id
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err("event_id required".to_string());
    }
    let payload = event_payload_json(parsed);
    let req: crate::api::handlers::event::EventCloseRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::event::event_close_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(default)]
    created_at: Option<i64>,
    #[serde(default)]
    deleted_at: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    external_ids: serde_json::Map<String, Value>,
    #[serde(default)]
    location_type: Option<String>,
    #[serde(default)]
    location_value: Option<String>,
    #[serde(default)]
    primary_image: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    observed_at: Option<i64>,
    #[serde(default)]
    attrs: serde_json::Map<String, Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, Value>,
}

fn thing_payload_json(args: ThingArgs) -> Value {
    json!({
        "channel_id": args.channel_id,
        "password": args.password,
        "op_id": args.op_id,
        "thing_id": args.thing_id,
        "created_at": args.created_at,
        "deleted_at": args.deleted_at,
        "title": args.title,
        "description": args.description,
        "tags": args.tags,
        "external_ids": args.external_ids,
        "location_type": args.location_type,
        "location_value": args.location_value,
        "primary_image": args.primary_image,
        "images": args.images,
        "observed_at": args.observed_at,
        "attrs": args.attrs,
        "metadata": args.metadata,
    })
}

async fn call_thing_create(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    let mut payload = thing_payload_json(parsed);
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("thing_id");
        obj.remove("deleted_at");
    }
    let req: crate::api::handlers::thing::ThingCreateRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::thing::thing_create_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

async fn call_thing_update(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    if parsed
        .thing_id
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err("thing_id required".to_string());
    }
    let mut payload = thing_payload_json(parsed);
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("created_at");
        obj.remove("deleted_at");
    }
    let req: crate::api::handlers::thing::ThingUpdateRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::thing::thing_update_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

async fn call_thing_archive(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    if parsed
        .thing_id
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err("thing_id required".to_string());
    }
    let mut payload = thing_payload_json(parsed);
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("created_at");
        obj.remove("deleted_at");
    }
    let req: crate::api::handlers::thing::ThingArchiveRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::thing::thing_archive_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

async fn call_thing_delete(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let authorized_channel =
        authorize_mcp_channel(state, mcp, auth, &parsed.channel_id, parsed.password.clone())
            .await?;
    if parsed
        .thing_id
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err("thing_id required".to_string());
    }
    let mut payload = thing_payload_json(parsed);
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("created_at");
    }
    let req: crate::api::handlers::thing::ThingDeleteRequest =
        serde_json::from_value(payload).map_err(|err| err.to_string())?;
    let response =
        crate::api::handlers::thing::thing_delete_authorized(state, req, authorized_channel).await;
    let mut value = http_result_to_value(response).await?;
    value["auth_mode"] = Value::String(auth_mode_name(auth).to_string());
    Ok(value)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindStartArgs {
    #[serde(default)]
    requested_channel_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

async fn call_bind_start(
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let McpAuthContext::OAuth { principal_id, .. } = auth else {
        return Err("auth_mode_not_supported".to_string());
    };
    ensure_scope(auth, "mcp:channels:manage")?;
    let parsed: BindStartArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    if let Some(redirect_uri) = parsed.redirect_uri.as_deref()
        && !mcp.is_redirect_allowed(redirect_uri)
    {
        return Err("redirect_uri_not_allowed".to_string());
    }

    let action = match parsed.action.as_deref().unwrap_or("bind") {
        "bind" => BindAction::Bind,
        "revoke" => BindAction::Revoke,
        _ => return Err("invalid action".to_string()),
    };
    let bind_session_id = random_id("mcp_bind");
    let expires_at = now_ts() + mcp.config.bind_session_ttl_secs;
    let session = BindSession {
        bind_session_id: bind_session_id.clone(),
        principal_id: principal_id.clone(),
        action,
        requested_channel_id: parsed.requested_channel_id.clone(),
        redirect_uri: parsed.redirect_uri.clone(),
        status: BindStatus::Pending,
        expires_at,
        completed_channel_id: None,
        error_code: None,
        error_message: None,
    };
    mcp.bind_sessions
        .write()
        .await
        .insert(bind_session_id.clone(), session);
    mcp.persist_snapshot().await;

    let bind_url = format!(
        "/mcp/{}/session?bind_session_id={}",
        action.as_str(),
        bind_session_id
    );
    Ok(json!({
        "bind_session_id": bind_session_id,
        "bind_url": bind_url,
        "expires_at": expires_at,
        "poll_after_ms": 1500
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindStatusArgs {
    bind_session_id: String,
}

async fn call_bind_status(
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let McpAuthContext::OAuth { principal_id, .. } = auth else {
        return Err("auth_mode_not_supported".to_string());
    };
    ensure_scope(auth, "mcp:channels:manage")?;
    let parsed: BindStatusArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    let mut changed = false;
    let snapshot = {
        let mut sessions = mcp.bind_sessions.write().await;
        let Some(session) = sessions.get_mut(&parsed.bind_session_id) else {
            return Err("bind_session_invalid".to_string());
        };
        if session.principal_id != *principal_id {
            return Err("bind_session_invalid".to_string());
        }
        if session.expires_at < now_ts() && session.status == BindStatus::Pending {
            session.status = BindStatus::Expired;
            session.error_code = Some("bind_session_expired".to_string());
            changed = true;
        }
        json!({
            "status": session.status.as_str(),
            "channel_id": session.completed_channel_id,
            "action": session.action.as_str(),
            "error_code": session.error_code,
            "message": session.error_message,
        })
    };
    if changed {
        mcp.persist_snapshot().await;
    }
    Ok(snapshot)
}

async fn call_channel_list(mcp: &McpState, auth: &McpAuthContext) -> Result<Value, String> {
    let McpAuthContext::OAuth { principal_id, .. } = auth else {
        return Err("auth_mode_not_supported".to_string());
    };
    ensure_scope(auth, "mcp:channels:manage")?;
    let grants = mcp.list_grants(principal_id).await;
    Ok(json!({
        "channels": grants.into_iter().map(|g| json!({
            "channel_id": g.channel_id,
            "granted_at": g.granted_at,
            "expires_at": g.expires_at,
            "status": "active"
        })).collect::<Vec<_>>()
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbindArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
}

async fn call_channel_unbind(
    state: &AppState,
    mcp: &McpState,
    auth: &McpAuthContext,
    args: Value,
) -> Result<Value, String> {
    let McpAuthContext::OAuth { principal_id, .. } = auth else {
        return Err("auth_mode_not_supported".to_string());
    };
    ensure_scope(auth, "mcp:channels:manage")?;
    let parsed: UnbindArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
    if mcp.config.revoke_requires_password {
        let password = parsed
            .password
            .as_deref()
            .ok_or_else(|| "password required".to_string())?;
        let channel_id =
            parse_channel_id(&parsed.channel_id).map_err(|_| "invalid channel_id".to_string())?;
        let validated =
            validate_channel_password(password).map_err(|_| "invalid password".to_string())?;
        match state
            .store
            .channel_info_with_password(channel_id, validated)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => return Err("channel_password_invalid".to_string()),
            Err(_) => return Err("channel_password_invalid".to_string()),
        }
    }
    let removed = mcp.remove_grant(principal_id, &parsed.channel_id).await;
    Ok(json!({"removed": removed}))
}
