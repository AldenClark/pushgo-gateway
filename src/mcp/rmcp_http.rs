use std::{borrow::Cow, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State as AxumState},
    http::{
        Method, StatusCode as HttpStatusCode, header::WWW_AUTHENTICATE, request::Parts,
    },
    response::Response as AxumResponse,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, Implementation, ListResourcesResult,
        ListToolsResult, ReadResourceRequestParams, ReadResourceResult, ServerCapabilities,
        ServerInfo, Tool,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};

pub(crate) async fn mcp_http(
    AxumState(state): AxumState<AppState>,
    request: Request,
) -> AxumResponse {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(request.headers()) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }

    let (mut parts, body) = request.into_parts();
    let auth = match mcp.authenticate(&parts.headers).await {
        Ok(auth) => auth,
        Err(_) => {
            return auth_challenge_response(
                mcp.oauth_issuer().await,
                None,
                HttpStatusCode::UNAUTHORIZED,
            );
        }
    };

    if parts.method == Method::POST {
        let body = match to_bytes(body, 32 * 1024).await {
            Ok(body) => body,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid request body").into_response(),
        };
        if let Some(required_scope) = required_scope_for_request(&body)
            && let McpAuthContext::OAuth { scope, .. } = &auth
            && !scope.contains(required_scope)
        {
            return auth_challenge_response(
                mcp.oauth_issuer().await,
                Some(required_scope),
                HttpStatusCode::FORBIDDEN,
            );
        }
        parts.extensions.insert(auth);
        let request = Request::from_parts(parts, Body::from(body));
        return rmcp_http_service(state).handle(request).await.map(Body::new);
    }

    parts.extensions.insert(auth);
    let request = Request::from_parts(parts, body);
    rmcp_http_service(state).handle(request).await.map(Body::new)
}

fn rmcp_http_service(
    state: AppState,
) -> StreamableHttpService<PushgoRmcpServer, NeverSessionManager> {
    StreamableHttpService::new(
        move || Ok(PushgoRmcpServer::new(state.clone())),
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None),
    )
}

fn auth_challenge_response(
    issuer: String,
    required_scope: Option<McpScope>,
    status: HttpStatusCode,
) -> AxumResponse {
    let resource_metadata = absolute_url(&issuer, "/.well-known/oauth-protected-resource/mcp");
    let mut challenge = format!("Bearer resource_metadata=\"{resource_metadata}\"");
    if status == HttpStatusCode::FORBIDDEN {
        challenge.push_str(", error=\"insufficient_scope\"");
    }
    if let Some(scope) = required_scope {
        challenge.push_str(", scope=\"");
        challenge.push_str(scope.as_str());
        challenge.push('"');
    }
    (status, [(WWW_AUTHENTICATE, challenge)], "").into_response()
}

fn required_scope_for_request(body: &[u8]) -> Option<McpScope> {
    let payload: Value = serde_json::from_slice(body).ok()?;
    let method = payload.get("method")?.as_str()?;
    match method {
        "resources/list" | "resources/read" => Some(McpScope::ChannelsManage),
        "tools/call" => {
            let tool_name = payload
                .get("params")
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)?;
            if is_send_tool_name(tool_name) {
                return Some(McpScope::Tools);
            }
            if matches!(
                tool_name,
                "pushgo.channel.bind.start"
                    | "pushgo.channel.bind.status"
                    | "pushgo.channel.list"
                    | "pushgo.channel.unbind"
            ) {
                return Some(McpScope::ChannelsManage);
            }
            None
        }
        _ => None,
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

struct PushgoRmcpServer {
    state: AppState,
}

impl PushgoRmcpServer {
    fn new(state: AppState) -> Self {
        Self { state }
    }

    fn mcp(&self) -> Result<&McpState, McpError> {
        self.state
            .mcp
            .as_deref()
            .ok_or_else(|| McpError::internal_error("mcp disabled", None))
    }

    fn auth_from_context(&self, context: &RequestContext<RoleServer>) -> Result<McpAuthContext, McpError> {
        let Some(parts) = context.extensions.get::<Parts>() else {
            return Err(McpError::internal_error(
                "missing http request context",
                None,
            ));
        };
        parts
            .extensions
            .get::<McpAuthContext>()
            .cloned()
            .ok_or_else(|| McpError::internal_error("missing mcp auth context", None))
    }

    fn rpc_service<'a>(&'a self, auth: &'a McpAuthContext) -> Result<McpRpcService<'a>, McpError> {
        Ok(McpRpcService::new(&self.state, self.mcp()?, auth))
    }

    fn tool_definitions(&self) -> Result<Vec<Tool>, McpError> {
        let auth = McpAuthContext::Legacy;
        let service = self.rpc_service(&auth)?;
        let tools = service
            .tools_list_result()
            .get("tools")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        serde_json::from_value(tools)
            .map_err(|err| McpError::internal_error(format!("invalid tool schema: {err}"), None))
    }
}

impl ServerHandler for PushgoRmcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_resources_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new(
            "pushgo-gateway-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions("PushGo MCP server for channel-bound tools and resources.")
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self.tool_definitions()?;
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_definitions()
            .ok()?
            .into_iter()
            .find(|tool| tool.name.as_ref() == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth_from_context(&context)?;
        let service = self.rpc_service(&auth)?;
        let tool_name = request.name.to_string();
        let mut params = serde_json::Map::new();
        params.insert("name".to_string(), Value::String(tool_name.clone()));
        params.insert(
            "arguments".to_string(),
            Value::Object(request.arguments.unwrap_or_default()),
        );
        let value = service
            .handle_tools_call(Some(Value::Object(params)))
            .await
            .map_err(|err| map_mcp_error(err, ErrorCode::INVALID_PARAMS))?;
        if should_notify_resource_list_changed(&tool_name, &value) {
            let peer = context.peer.clone();
            tokio::spawn(async move {
                let _ = peer.notify_resource_list_changed().await;
            });
        }
        Ok(CallToolResult::structured(value))
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let auth = self.auth_from_context(&context)?;
        let service = self.rpc_service(&auth)?;
        let value = service
            .resources_list_result()
            .await
            .map_err(map_resource_error)?;
        serde_json::from_value(value)
            .map_err(|err| McpError::internal_error(format!("invalid resources payload: {err}"), None))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let auth = self.auth_from_context(&context)?;
        let service = self.rpc_service(&auth)?;
        let value = service
            .resources_read_result(Some(request.uri.as_str()))
            .await
            .map_err(map_resource_error)?;
        serde_json::from_value(value)
            .map_err(|err| McpError::internal_error(format!("invalid resource content: {err}"), None))
    }
}

fn map_mcp_error(message: String, code: ErrorCode) -> McpError {
    match code {
        ErrorCode::INVALID_PARAMS => McpError::invalid_params(message, None),
        ErrorCode::RESOURCE_NOT_FOUND => McpError::resource_not_found(message, None),
        _ => McpError::new(code, Cow::Owned(message), None),
    }
}

fn map_resource_error(message: String) -> McpError {
    if message == "resource_not_found" {
        return McpError::resource_not_found(message, Some(json!({ "uri": "unknown" })));
    }
    McpError::invalid_request(message, None)
}

fn should_notify_resource_list_changed(tool_name: &str, tool_result: &Value) -> bool {
    match tool_name {
        "pushgo.channel.unbind" => tool_result
            .get("removed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "pushgo.channel.bind.status" => tool_result
            .get("resources_changed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

#[cfg(test)]
mod rmcp_http_tests {
    use super::should_notify_resource_list_changed;
    use serde_json::json;

    #[test]
    fn bind_status_notifies_when_resources_changed() {
        assert!(should_notify_resource_list_changed(
            "pushgo.channel.bind.status",
            &json!({ "resources_changed": true })
        ));
        assert!(!should_notify_resource_list_changed(
            "pushgo.channel.bind.status",
            &json!({ "resources_changed": false })
        ));
    }
}
