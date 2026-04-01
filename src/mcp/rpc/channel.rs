use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindStartArgs {
    #[serde(default)]
    requested_channel_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    ui_locales: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindStatusArgs {
    bind_session_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbindArgs {
    channel_id: String,
    #[serde(default, rename = "password")]
    _password: Option<String>,
}

impl McpRpcService<'_> {
    pub(super) async fn call_bind_start(&self, args: Value) -> Result<Value, String> {
        let McpAuthContext::OAuth { principal_id, .. } = self.auth else {
            return Err("auth_mode_not_supported".to_string());
        };
        ensure_scope(self.auth, McpScope::ChannelsManage)?;
        let parsed: BindStartArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;

        let action = match parsed.action.as_deref().unwrap_or("bind") {
            "bind" => BindAction::Bind,
            "revoke" => BindAction::Revoke,
            _ => return Err("invalid action".to_string()),
        };
        let bind_session_id = McpState::random_id("mcp_bind");
        let expires_at = McpState::now_ts() + self.mcp.config.bind_session_ttl_secs;
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
            resource_list_change_notified: false,
        };
        self.mcp
            .bind_sessions
            .write()
            .await
            .insert(bind_session_id.clone(), session);
        self.mcp.persist_snapshot().await;

        let locale = McpLocale::from_request(parsed.lang.as_deref(), parsed.ui_locales.as_deref());
        let bind_url_path = format!(
            "/mcp/{}/session?bind_session_id={}",
            action.as_str(),
            bind_session_id
        );
        let bind_url_path = if locale.code() == MCP_UI_DEFAULT_LOCALE {
            bind_url_path
        } else {
            format!(
                "{bind_url_path}&{MCP_UI_LOCALE_QUERY_PARAMETER}={}",
                locale.code()
            )
        };
        let bind_url = absolute_url(self.mcp.oauth_issuer().await.as_str(), &bind_url_path);
        Ok(json!({
            "bind_session_id": bind_session_id,
            "bind_url": bind_url,
            "expires_at": expires_at,
            "poll_after_ms": 1500,
            "ui_locales_supported": MCP_UI_LOCALES_SUPPORTED,
            "default_ui_locale": MCP_UI_DEFAULT_LOCALE,
            "ui_locale_query_parameter": MCP_UI_LOCALE_QUERY_PARAMETER
        }))
    }

    pub(super) async fn call_bind_status(&self, args: Value) -> Result<Value, String> {
        let McpAuthContext::OAuth { principal_id, .. } = self.auth else {
            return Err("auth_mode_not_supported".to_string());
        };
        ensure_scope(self.auth, McpScope::ChannelsManage)?;
        let parsed: BindStatusArgs =
            serde_json::from_value(args).map_err(|err| err.to_string())?;
        let mut changed = false;
        let snapshot = {
            let mut sessions = self.mcp.bind_sessions.write().await;
            let Some(session) = sessions.get_mut(&parsed.bind_session_id) else {
                return Err("bind_session_invalid".to_string());
            };
            if session.principal_id != *principal_id {
                return Err("bind_session_invalid".to_string());
            }
            if session.expires_at < McpState::now_ts() && session.status == BindStatus::Pending {
                session.status = BindStatus::Expired;
                session.error_code = Some("bind_session_expired".to_string());
                changed = true;
            }
            let should_notify_resources_changed =
                session.status == BindStatus::Completed && !session.resource_list_change_notified;
            if should_notify_resources_changed {
                session.resource_list_change_notified = true;
                changed = true;
            }
            json!({
                "status": session.status.as_str(),
                "channel_id": session.completed_channel_id,
                "resources_changed": should_notify_resources_changed,
                "action": session.action.as_str(),
                "error_code": session.error_code,
                "message": session.error_message,
            })
        };
        if changed {
            self.mcp.persist_snapshot().await;
        }
        let mut snapshot = snapshot;
        if let Some(channel_id) = snapshot
            .get("channel_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
        {
            let channel_name = self.channel_name(&channel_id).await;
            if let Some(map) = snapshot.as_object_mut() {
                map.insert(
                    "channel_name".to_string(),
                    channel_name
                        .as_ref()
                        .map(|name| Value::String(name.clone()))
                        .unwrap_or(Value::Null),
                );
                map.insert(
                    "channel_display".to_string(),
                    Value::String(McpRpcService::channel_display(
                        &channel_id,
                        channel_name.as_deref(),
                    )),
                );
            }
        }
        Ok(snapshot)
    }

    pub(super) async fn call_channel_list(&self) -> Result<Value, String> {
        ensure_scope(self.auth, McpScope::ChannelsManage)?;
        let channels = self.load_authorized_channels().await?;
        Ok(json!({ "channels": channels }))
    }

    pub(super) async fn call_channel_unbind(&self, args: Value) -> Result<Value, String> {
        let McpAuthContext::OAuth { principal_id, .. } = self.auth else {
            return Err("auth_mode_not_supported".to_string());
        };
        ensure_scope(self.auth, McpScope::ChannelsManage)?;
        let parsed: UnbindArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_name = self.channel_name(&parsed.channel_id).await;
        let removed = self.mcp.remove_grant(principal_id, &parsed.channel_id).await;
        Ok(json!({
            "removed": removed,
            "channel_id": parsed.channel_id,
            "channel_name": channel_name,
            "channel_display": McpRpcService::channel_display(
                &parsed.channel_id,
                channel_name.as_deref()
            ),
            "resources_changed": removed
        }))
    }
}
