#[derive(Debug, Deserialize)]
pub(crate) struct BindSessionQuery {
    bind_session_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BindSubmitForm {
    bind_session_id: String,
    channel_id: String,
    password: String,
}

pub(crate) async fn bind_page_get(
    State(state): State<AppState>,
    Query(query): Query<BindSessionQuery>,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    let sessions = mcp.bind_sessions.read().await;
    let Some(session) = sessions.get(&query.bind_session_id) else {
        return (StatusCode::NOT_FOUND, "bind session not found").into_response();
    };

    if session.status != BindStatus::Pending {
        return Html("<html><body>Session already completed.</body></html>".to_string())
            .into_response();
    }

    let title = if session.action == BindAction::Bind {
        "Bind Channel"
    } else {
        "Revoke Channel"
    };

    let requested = session.requested_channel_id.as_deref().unwrap_or("");
    let html = format!(
        r#"<!doctype html><html><body>
<h2>{title}</h2>
<form method=\"post\" action=\"/mcp/{action}/session\">
<input type=\"hidden\" name=\"bind_session_id\" value=\"{session_id}\" />
<label>Channel ID: <input name=\"channel_id\" value=\"{requested}\" /></label><br/><br/>
<label>Password: <input type=\"password\" name=\"password\" /></label><br/><br/>
<button type=\"submit\">Submit</button>
</form>
</body></html>"#,
        title = title,
        action = if session.action == BindAction::Bind {
            "bind"
        } else {
            "revoke"
        },
        session_id = html_escape(&query.bind_session_id),
        requested = html_escape(requested),
    );

    Html(html).into_response()
}

pub(crate) async fn bind_page_post(
    State(state): State<AppState>,
    Form(form): Form<BindSubmitForm>,
) -> Response {
    bind_apply(state, form, BindAction::Bind).await
}

pub(crate) async fn revoke_page_post(
    State(state): State<AppState>,
    Form(form): Form<BindSubmitForm>,
) -> Response {
    bind_apply(state, form, BindAction::Revoke).await
}

async fn bind_apply(
    state: AppState,
    form: BindSubmitForm,
    expected_action: BindAction,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };

    let channel_id = match parse_channel_id(&form.channel_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid channel_id").into_response(),
    };
    let password = match validate_channel_password(&form.password) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid password").into_response(),
    };

    match state
        .store
        .channel_info_with_password(channel_id, password)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "channel_id/password mismatch").into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "channel validation failed",
            )
                .into_response();
        }
    }

    let (principal_id, redirect_uri) = {
        let mut sessions = mcp.bind_sessions.write().await;
        let Some(session) = sessions.get_mut(&form.bind_session_id) else {
            return (StatusCode::NOT_FOUND, "bind session not found").into_response();
        };
        if session.status != BindStatus::Pending {
            return (StatusCode::BAD_REQUEST, "bind session already completed").into_response();
        }
        if session.expires_at < now_ts() {
            session.status = BindStatus::Expired;
            session.error_code = Some("bind_session_expired".to_string());
            drop(sessions);
            mcp.persist_snapshot().await;
            return (StatusCode::BAD_REQUEST, "bind session expired").into_response();
        }
        if session.action != expected_action {
            return (StatusCode::BAD_REQUEST, "bind session action mismatch").into_response();
        }
        (session.principal_id.clone(), session.redirect_uri.clone())
    };

    if expected_action == BindAction::Bind {
        mcp.upsert_grant(&principal_id, &form.channel_id, None)
            .await;
    } else {
        mcp.remove_grant(&principal_id, &form.channel_id).await;
    }

    {
        let mut sessions = mcp.bind_sessions.write().await;
        if let Some(session) = sessions.get_mut(&form.bind_session_id) {
            session.status = BindStatus::Completed;
            session.completed_channel_id = Some(form.channel_id.clone());
        }
    }
    mcp.persist_snapshot().await;

    if let Some(redirect_uri) = redirect_uri.as_deref() && mcp.is_redirect_allowed(redirect_uri) {
        return Redirect::to(redirect_uri).into_response();
    }

    Html("<html><body>Done. You can return to MCP client.</body></html>".to_string())
        .into_response()
}
