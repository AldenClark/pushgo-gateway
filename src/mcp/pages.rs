#[derive(Debug, Deserialize)]
pub(crate) struct BindSessionQuery {
    bind_session_id: String,
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    ui_locales: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BindSubmitForm {
    bind_session_id: String,
    channel_id: String,
    password: String,
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    ui_locales: Option<String>,
}

pub(crate) async fn bind_page_get(
    State(state): State<AppState>,
    Query(query): Query<BindSessionQuery>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    let sessions = mcp.bind_sessions.read().await;
    let Some(session) = sessions.get(&query.bind_session_id) else {
        return (StatusCode::NOT_FOUND, "bind session not found").into_response();
    };
    let locale = McpLocale::from_request(query.lang.as_deref(), query.ui_locales.as_deref());
    let text = bind_page_text(locale, session.action);

    if session.status != BindStatus::Pending {
        return Html(simple_status_page(locale, text.completed)).into_response();
    }

    let requested = session.requested_channel_id.as_deref().unwrap_or("");
    let action = if session.action == BindAction::Bind {
        "bind"
    } else {
        "revoke"
    };
    let html = format!(
        r#"<!doctype html>
<html lang="{html_lang}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --card: #ffffff;
      --text: #102027;
      --muted: #5f6b76;
      --line: #d9e2ec;
      --accent: #0b7285;
      --accent-2: #0f9ab3;
      --radius: 14px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: "Noto Sans", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 500px at 10% -10%, #dcefff 0%, transparent 60%),
        radial-gradient(900px 500px at 100% 0%, #dff9ef 0%, transparent 55%),
        var(--bg);
    }}
    .card {{
      width: min(560px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: 0 12px 30px rgba(16, 32, 39, 0.12);
      overflow: hidden;
    }}
    .head {{
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(11,114,133,0.1), rgba(15,154,179,0.12));
    }}
    h1 {{ margin: 0; font-size: 22px; }}
    p {{ margin: 8px 0 0; color: var(--muted); font-size: 13px; line-height: 1.5; }}
    form {{ padding: 20px; display: grid; gap: 14px; }}
    label {{ display: block; color: var(--muted); font-size: 13px; margin-bottom: 6px; }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
      background: #fbfdff;
      outline: none;
    }}
    input:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(15,154,179,.16);
      background: #fff;
    }}
    .actions {{ display: flex; justify-content: flex-end; margin-top: 2px; }}
    button {{
      border: 0;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #fff;
      font-weight: 600;
      padding: 10px 16px;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <main class="card">
    <section class="head">
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </section>
    <form method="post" action="/mcp/{action}/session">
      <input type="hidden" name="bind_session_id" value="{session_id}" />
      <input type="hidden" name="lang" value="{locale_code}" />
      <div>
        <label for="channel_id">{channel_id_label}</label>
        <input id="channel_id" name="channel_id" value="{requested}" />
      </div>
      <div>
        <label for="password">{password_label}</label>
        <input id="password" type="password" name="password" />
      </div>
      <div class="actions">
        <button type="submit">{submit}</button>
      </div>
    </form>
  </main>
</body>
</html>"#,
        html_lang = locale.html_lang(),
        title = text.title,
        subtitle = text.subtitle,
        action = action,
        session_id = html_escape(&query.bind_session_id),
        locale_code = locale.code(),
        channel_id_label = text.channel_id_label,
        password_label = text.password_label,
        requested = html_escape(requested),
        submit = text.submit,
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
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    let locale = McpLocale::from_request(form.lang.as_deref(), form.ui_locales.as_deref());

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
        if session.expires_at < McpState::now_ts() {
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
        mcp.upsert_grant(&principal_id, &form.channel_id, None).await;
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

    if let Some(redirect_uri) = redirect_uri.as_deref() {
        return Redirect::to(redirect_uri).into_response();
    }

    Html(simple_status_page(
        locale,
        bind_page_text(locale, expected_action).finished,
    ))
    .into_response()
}

fn simple_status_page(locale: McpLocale, message: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="{html_lang}">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body{{margin:0;display:grid;place-items:center;min-height:100vh;font-family:"Noto Sans","Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif;background:#f4f7fb}}
.box{{background:#fff;border:1px solid #d9e2ec;border-radius:12px;padding:20px 22px;color:#102027;box-shadow:0 12px 30px rgba(16,32,39,.1)}}
</style></head>
<body><div class="box">{message}</div></body></html>"#,
        html_lang = locale.html_lang(),
        message = html_escape(message),
    )
}
