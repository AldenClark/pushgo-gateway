fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = raw.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?;
    if token.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(token)
}

fn enforce_gateway_token(headers: &HeaderMap, auth: &crate::app::AuthMode) -> bool {
    match auth {
        crate::app::AuthMode::Disabled => true,
        crate::app::AuthMode::SharedToken(expected) => bearer_from_headers(headers)
            .map(|token| crate::util::constant_time_eq(token.as_bytes(), expected.as_bytes()))
            .unwrap_or(false),
    }
}

fn absolute_url(issuer: &str, path: &str) -> String {
    let trimmed = issuer.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{trimmed}{path}")
    } else {
        format!("{trimmed}/{path}")
    }
}

fn valid_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn bounded_oauth_credential(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
}

fn oauth_state_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth state is temporarily unavailable",
    )
        .into_response()
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing JS string should not fail")
}

fn emit_oauth_rejected(endpoint: &str, reason: &str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "mcp.oauth_rejected",
        endpoint = %(endpoint),
        reason = %(reason)
    );
}

fn emit_oauth_failed(endpoint: &str, stage: &str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "mcp.oauth_failed",
        endpoint = %(endpoint),
        stage = %(stage)
    );
}

fn emit_oauth_completed(endpoint: &str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "mcp.oauth_completed",
        endpoint = %(endpoint)
    );
}

#[tracing::instrument(name = "gateway.mcp.oauth.authorize_get", skip_all)]
pub(crate) async fn oauth_authorize_get(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    if !mcp
        .client_redirect_allowed(query.client_id.as_str(), query.redirect_uri.as_str())
        .await
    {
        emit_oauth_rejected("authorize_get", "client_or_redirect_invalid");
        return (StatusCode::BAD_REQUEST, "client or redirect_uri invalid").into_response();
    }
    if query.code_challenge_method != Some(PkceMethod::S256)
        || !valid_s256_challenge(&query.code_challenge)
        || query
            .state
            .as_deref()
            .is_some_and(|state| state.len() > 1_024)
    {
        emit_oauth_rejected("authorize_get", "pkce_s256_required");
        return (StatusCode::BAD_REQUEST, "PKCE S256 is required").into_response();
    }
    let locale = McpLocale::from_request(query.lang.as_deref(), query.ui_locales.as_deref());
    let text = oauth_authorize_text(locale);

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
      --accent-text: #ffffff;
      --shadow: 0 12px 30px rgba(16, 32, 39, 0.12);
      --radius: 14px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Noto Sans", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 500px at 10% -10%, #dcefff 0%, transparent 60%),
        radial-gradient(900px 500px at 100% 0%, #dff9ef 0%, transparent 55%),
        var(--bg);
      display: grid;
      place-items: center;
      padding: 24px;
    }}
    .card {{
      width: min(860px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .head {{
      padding: 22px 24px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(11,114,133,0.1), rgba(15,154,179,0.12));
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: .2px;
    }}
    .sub {{
      margin: 0;
      color: var(--muted);
      line-height: 1.55;
      font-size: 14px;
    }}
    form {{
      padding: 22px 24px 24px;
      display: grid;
      gap: 16px;
    }}
    label {{
      display: block;
      font-size: 13px;
      color: var(--muted);
      margin-bottom: 6px;
    }}
    input, textarea {{
      width: 100%;
      font: inherit;
      color: var(--text);
      border: 1px solid var(--line);
      background: #fbfdff;
      border-radius: 10px;
      padding: 10px 12px;
      outline: none;
      transition: border-color .15s ease, box-shadow .15s ease;
    }}
    input:focus, textarea:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(15,154,179,.16);
      background: #fff;
    }}
    .hint {{
      margin-top: 10px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }}
    .channel-table {{
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
      background: #fff;
    }}
    .channel-head, .channel-row {{
      display: grid;
      grid-template-columns: 1.35fr 1.05fr .9fr .95fr auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
    }}
    .channel-head {{
      background: #f7fbff;
      border-bottom: 1px solid var(--line);
      font-size: 12px;
      color: var(--muted);
      font-weight: 600;
      letter-spacing: .2px;
    }}
    .channel-row + .channel-row {{ border-top: 1px solid #edf2f7; }}
    .channel-row input {{
      min-width: 0;
      padding: 8px 10px;
      font-size: 13px;
    }}
    .status {{
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .status.ok {{ color: #15803d; }}
    .status.err {{ color: #b91c1c; }}
    .btn-lite {{
      border: 1px solid var(--line);
      background: #fff;
      color: #2f3d4a;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 10px;
      cursor: pointer;
    }}
    .btn-lite:hover {{ background: #f7fbff; }}
    .actions {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 6px;
    }}
    button {{
      border: 0;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: var(--accent-text);
      font-weight: 600;
      font-size: 14px;
      padding: 10px 18px;
      cursor: pointer;
      transition: transform .12s ease, filter .12s ease;
    }}
    button:hover {{ filter: brightness(1.05); }}
    button:active {{ transform: translateY(1px); }}
  </style>
</head>
<body>
  <main class="card">
    <section class="head">
      <h1>{title}</h1>
      <p class="sub">{subtitle}</p>
    </section>
    <form id="authorize-form" method="post" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="{client_id}" />
      <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
      <input type="hidden" name="state" value="{state}" />
      <input type="hidden" name="code_challenge" value="{code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
      <input type="hidden" name="scope" value="{scope}" />
      <input type="hidden" name="lang" value="{locale_code}" />
      <textarea id="channel_bindings" name="channel_bindings" hidden></textarea>
      <div>
        <label>{channel_bindings_label}</label>
        <div class="channel-table">
          <div class="channel-head">
            <span>{channel_id_label}</span>
            <span>{password_label}</span>
            <span>{status_label}</span>
            <span>{channel_name_label}</span>
            <span>{action_label}</span>
          </div>
          <div id="channel-rows"></div>
        </div>
        <div class="hint">{hint}</div>
      </div>
      <div class="actions">
        <button id="add-row" type="button" class="btn-lite">{add_row}</button>
        <button type="submit">{submit}</button>
      </div>
    </form>
  </main>
  <script>
    const rowsEl = document.getElementById("channel-rows");
    const addRowBtn = document.getElementById("add-row");
    const formEl = document.getElementById("authorize-form");
    const hiddenBindings = document.getElementById("channel_bindings");
    const locale = {locale_json};
    const text = {{
      channelPlaceholder: {channel_placeholder},
      passwordPlaceholder: {password_placeholder},
      statusUnvalidated: {status_unvalidated},
      statusIncomplete: {status_incomplete},
      statusValidating: {status_validating},
      statusOk: {status_ok},
      statusFailed: {status_failed},
      statusNetworkError: {status_network_error},
      channelNameEmpty: {channel_name_empty},
      remove: {remove},
      alertMissingRows: {alert_missing_rows}
    }};

    function rowTemplate() {{
      const row = document.createElement("div");
      row.className = "channel-row";
      row.innerHTML = `
        <input data-field="channel_id" placeholder="${{text.channelPlaceholder}}" />
        <input data-field="password" type="password" placeholder="${{text.passwordPlaceholder}}" />
        <div class="status">${{text.statusUnvalidated}}</div>
        <div class="status" data-field="channel_name">${{text.channelNameEmpty}}</div>
        <button type="button" class="btn-lite" data-action="remove">${{text.remove}}</button>
      `;
      const [channelInput, passwordInput] = row.querySelectorAll("input");
      const statusEl = row.querySelector(".status");
      const channelNameEl = row.querySelector("[data-field='channel_name']");
      const removeBtn = row.querySelector("[data-action='remove']");

      async function validateNow() {{
        const channelId = channelInput.value.trim();
        const password = passwordInput.value.trim();
        if (!channelId && !password) {{
          statusEl.className = "status";
          statusEl.textContent = text.statusUnvalidated;
          channelNameEl.textContent = text.channelNameEmpty;
          return;
        }}
        if (!channelId || !password) {{
          statusEl.className = "status err";
          statusEl.textContent = text.statusIncomplete;
          channelNameEl.textContent = text.channelNameEmpty;
          return;
        }}
        statusEl.className = "status";
        statusEl.textContent = text.statusValidating;
        channelNameEl.textContent = text.channelNameEmpty;
        try {{
          const resp = await fetch("/oauth/channel/validate", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ channel_id: channelId, password, lang: locale }})
          }});
          const data = await resp.json();
          if (resp.ok && data.valid) {{
            statusEl.className = "status ok";
            statusEl.textContent = text.statusOk;
            channelNameEl.textContent = data.channel_name || text.channelNameEmpty;
          }} else {{
            statusEl.className = "status err";
            statusEl.textContent = data.message || text.statusFailed;
            channelNameEl.textContent = text.channelNameEmpty;
          }}
        }} catch (_) {{
          statusEl.className = "status err";
          statusEl.textContent = text.statusNetworkError;
          channelNameEl.textContent = text.channelNameEmpty;
        }}
      }}

      channelInput.addEventListener("input", () => {{
        statusEl.className = "status";
        statusEl.textContent = text.statusUnvalidated;
        channelNameEl.textContent = text.channelNameEmpty;
      }});
      passwordInput.addEventListener("input", () => {{
        statusEl.className = "status";
        statusEl.textContent = text.statusUnvalidated;
        channelNameEl.textContent = text.channelNameEmpty;
      }});
      channelInput.addEventListener("blur", validateNow);
      passwordInput.addEventListener("blur", validateNow);
      removeBtn.addEventListener("click", () => {{
        row.remove();
        if (!rowsEl.children.length) addRow();
      }});
      return row;
    }}

    function addRow() {{
      rowsEl.appendChild(rowTemplate());
    }}

    addRowBtn.addEventListener("click", addRow);
    addRow();

    formEl.addEventListener("submit", (e) => {{
      const lines = [];
      rowsEl.querySelectorAll(".channel-row").forEach((row) => {{
        const channel = row.querySelector("input[data-field='channel_id']").value.trim();
        const password = row.querySelector("input[data-field='password']").value.trim();
        if (channel && password) lines.push(`${{channel}},${{password}}`);
      }});
      if (!lines.length) {{
        e.preventDefault();
        alert(text.alertMissingRows);
        return;
      }}
      hiddenBindings.value = lines.join("\\n");
    }});
  </script>
</body>
</html>"#,
        html_lang = locale.html_lang(),
        title = text.title,
        subtitle = text.subtitle,
        client_id = html_escape(&query.client_id),
        redirect_uri = html_escape(&query.redirect_uri),
        state = html_escape(query.state.as_deref().unwrap_or("")),
        code_challenge = html_escape(&query.code_challenge),
        code_challenge_method = html_escape(PkceMethod::S256.as_str(),),
        scope = html_escape(
            query
                .scope
                .clone()
                .unwrap_or_else(McpScopeSet::tools)
                .to_string()
                .as_str(),
        ),
        locale_code = locale.code(),
        locale_json = js_string(locale.code()),
        channel_bindings_label = text.channel_bindings_label,
        channel_id_label = text.channel_id_label,
        password_label = text.password_label,
        status_label = text.status_label,
        channel_name_label = text.channel_name_label,
        action_label = text.action_label,
        hint = text.hint,
        add_row = text.add_row,
        submit = text.submit,
        channel_placeholder = js_string(text.channel_placeholder),
        password_placeholder = js_string(text.password_placeholder),
        status_unvalidated = js_string(text.status_unvalidated),
        status_incomplete = js_string(text.status_incomplete),
        status_validating = js_string(text.status_validating),
        status_ok = js_string(text.status_ok),
        status_failed = js_string(text.status_failed),
        status_network_error = js_string(text.status_network_error),
        channel_name_empty = js_string(text.channel_name_empty),
        remove = js_string(text.remove),
        alert_missing_rows = js_string(text.alert_missing_rows),
    );

    emit_oauth_completed("authorize_get");
    Html(html).into_response()
}

#[tracing::instrument(name = "gateway.mcp.oauth.authorize_post", skip_all)]
pub(crate) async fn oauth_authorize_post(
    State(state): State<AppState>,
    Form(form): Form<AuthorizeSubmit>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    if !mcp
        .client_redirect_allowed(form.client_id.as_str(), form.redirect_uri.as_str())
        .await
    {
        emit_oauth_rejected("authorize_post", "client_or_redirect_invalid");
        return (StatusCode::BAD_REQUEST, "client or redirect_uri invalid").into_response();
    }
    if form.code_challenge_method != Some(PkceMethod::S256)
        || !valid_s256_challenge(&form.code_challenge)
        || form
            .state
            .as_deref()
            .is_some_and(|state| state.len() > 1_024)
    {
        emit_oauth_rejected("authorize_post", "pkce_s256_required");
        return (StatusCode::BAD_REQUEST, "PKCE S256 is required").into_response();
    }
    let _locale = McpLocale::from_request(form.lang.as_deref(), form.ui_locales.as_deref());

    let channel_bindings = match ChannelBindingList::parse(form.channel_bindings.as_deref()) {
        Ok(bindings) => bindings,
        Err(reason) => {
            emit_oauth_rejected("authorize_post", reason);
            return (
                StatusCode::BAD_REQUEST,
                "at least one valid channel binding is required",
            )
                .into_response();
        }
    };
    for item in channel_bindings.iter() {
        match state
            .store
            .channel_info_with_password(item.channel_id.into_inner(), item.password.as_str())
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                emit_oauth_rejected("authorize_post", "channel_password_mismatch");
                return (
                    StatusCode::BAD_REQUEST,
                    "channel or password mismatch in channel_bindings",
                )
                    .into_response();
            }
            Err(_) => {
                emit_oauth_failed("authorize_post", "channel_validation");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "channel validation is temporarily unavailable",
                )
                    .into_response();
            }
        }
    }

    let _mutation = mcp.mutation.lock().await;
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let now = McpState::now_ts();
    mcp.prune_oauth_runtime_locked(now).await;
    {
        let principals = mcp.principals.read().await;
        if principals.len() >= core_snapshot::MAX_PRINCIPALS {
            emit_oauth_rejected("authorize_post", "principal_quota_exceeded");
            return (StatusCode::TOO_MANY_REQUESTS, "OAuth state quota exceeded").into_response();
        }
    }
    if mcp.auth_codes.read().await.len() >= core_snapshot::MAX_AUTH_CODES {
        emit_oauth_rejected("authorize_post", "authorization_code_quota_exceeded");
        return (StatusCode::TOO_MANY_REQUESTS, "OAuth state quota exceeded").into_response();
    }
    let principal_id = McpState::random_id("mcp_pr");
    let grants = channel_bindings
        .into_vec()
        .into_iter()
        .map(|item| {
            let channel_id = item.channel_id_text;
            (
                channel_id.clone(),
                ChannelGrant {
                    channel_id,
                    granted_at: now,
                    expires_at: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    {
        let mut principals = mcp.principals.write().await;
        principals.insert(
            principal_id.clone(),
            Principal {
                principal_id: principal_id.clone(),
                display_name: None,
                grants,
                created_at: now,
            },
        );
    }

    let code = McpState::random_id("mcp_code");
    let code_hash = McpState::token_hash(&code);
    let scope = form.scope.clone().unwrap_or_else(McpScopeSet::tools);
    {
        let mut auth_codes = mcp.auth_codes.write().await;
        auth_codes.insert(
            code_hash,
            AuthCode {
                principal_id,
                client_id: form.client_id.clone(),
                redirect_uri: form.redirect_uri.clone(),
                scope,
                code_challenge: form.code_challenge.clone(),
                code_challenge_method: PkceMethod::S256,
                expires_at: now.saturating_add(300),
            },
        );
    }
    if mcp.persist_snapshot_locked().await.is_err() {
        return oauth_state_unavailable();
    }

    let mut location = match reqwest::Url::parse(&form.redirect_uri) {
        Ok(location) => location,
        Err(_) => return (StatusCode::BAD_REQUEST, "redirect_uri invalid").into_response(),
    };
    {
        let mut query = location.query_pairs_mut();
        query.append_pair("code", &code);
        if let Some(state_param) = form.state.as_deref().filter(|value| !value.is_empty()) {
            query.append_pair("state", state_param);
        }
    }
    emit_oauth_completed("authorize_post");
    Redirect::to(location.as_str()).into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthTokenForm {
    grant_type: OAuthGrantType,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<McpScopeSet>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    scope: String,
}

#[tracing::instrument(name = "gateway.mcp.oauth.token", skip_all)]
pub(crate) async fn oauth_token(
    State(state): State<AppState>,
    Form(form): Form<OAuthTokenForm>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let signing_key = mcp.oauth_signing_key().await;
    let issuer = mcp.oauth_issuer().await;

    if form.grant_type == OAuthGrantType::AuthorizationCode {
        let (Some(code), Some(client_id), Some(redirect_uri), Some(code_verifier)) = (
            form.code.as_deref(),
            form.client_id.as_deref(),
            form.redirect_uri.as_deref(),
            form.code_verifier.as_deref(),
        ) else {
            emit_oauth_rejected("token", "invalid_authorization_code_request");
            return (
                StatusCode::BAD_REQUEST,
                "invalid authorization_code request",
            )
                .into_response();
        };
        if !bounded_oauth_credential(code)
            || !bounded_oauth_credential(client_id)
            || !valid_pkce_verifier(code_verifier)
        {
            emit_oauth_rejected("token", "invalid_authorization_code_request");
            return (
                StatusCode::BAD_REQUEST,
                "invalid authorization_code request",
            )
                .into_response();
        }
        if !mcp
            .validate_client_for_token(client_id, form.client_secret.as_deref())
            .await
        {
            emit_oauth_rejected("token", "invalid_client");
            return (StatusCode::BAD_REQUEST, "invalid client").into_response();
        }

        let _mutation = mcp.mutation.lock().await;
        if !mcp.oauth_ready() {
            return oauth_state_unavailable();
        }
        let code_hash = McpState::token_hash(code);
        let now = McpState::now_ts();
        let Some(record) = mcp.auth_codes.read().await.get(&code_hash).cloned() else {
            emit_oauth_rejected("token", "invalid_code");
            return (StatusCode::BAD_REQUEST, "invalid code").into_response();
        };
        if !record.is_active(now) {
            emit_oauth_rejected("token", "code_expired_or_consumed");
            return (StatusCode::BAD_REQUEST, "code expired or consumed").into_response();
        }
        if !record.matches_exchange_request(client_id, redirect_uri) {
            emit_oauth_rejected("token", "code_mismatch");
            return (StatusCode::BAD_REQUEST, "code mismatch").into_response();
        }
        if !record
            .code_challenge_method
            .verify(&record.code_challenge, code_verifier)
        {
            emit_oauth_rejected("token", "code_verifier_mismatch");
            return (StatusCode::BAD_REQUEST, "code_verifier mismatch").into_response();
        }
        let issued_at = now;
        let expires_at = issued_at
            .saturating_add(mcp.config.access_token_ttl_secs)
            .min(issued_at.saturating_add(mcp.config.refresh_token_absolute_ttl_secs));
        let expires_in = expires_at.saturating_sub(issued_at);
        let claims = AccessClaims {
            iss: issuer.clone(),
            sub: record.principal_id.clone(),
            aud: "mcp".to_string(),
            scope: record.scope.clone(),
            client_id: Some(client_id.to_string()),
            iat: issued_at as usize,
            exp: expires_at as usize,
        };
        let access_token = match encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(signing_key.as_bytes()),
        ) {
            Ok(token) => token,
            Err(_) => {
                emit_oauth_failed("token", "sign_authorization_code_access_token");
                return (StatusCode::INTERNAL_SERVER_ERROR, "token sign failed").into_response();
            }
        };

        let refresh_raw = McpState::random_id("mcp_rft");
        let refresh_hash = McpState::token_hash(&refresh_raw);
        let refresh_record = RefreshToken::initial(NewRefreshToken {
            token_hash: refresh_hash.clone(),
            family_id: McpState::random_id("mcp_rff"),
            principal_id: record.principal_id.clone(),
            client_id: client_id.to_string(),
            scope: record.scope.clone(),
            issued_at,
            absolute_ttl_secs: mcp.config.refresh_token_absolute_ttl_secs,
            idle_ttl_secs: mcp.config.refresh_token_idle_ttl_secs,
        });
        {
            let mut refresh_tokens = mcp.refresh_tokens.write().await;
            refresh_tokens.retain(|_, token| token.family_expires_at > now);
            if refresh_tokens.len() >= core_snapshot::MAX_REFRESH_TOKENS {
                emit_oauth_rejected("token", "refresh_token_quota_exceeded");
                return (StatusCode::TOO_MANY_REQUESTS, "OAuth state quota exceeded")
                    .into_response();
            }
            refresh_tokens.insert(refresh_hash, refresh_record);
        }
        mcp.auth_codes.write().await.remove(&code_hash);
        let response_scope = record.scope.to_string();
        if mcp.persist_snapshot_locked().await.is_err() {
            return oauth_state_unavailable();
        }

        emit_oauth_completed("token_authorization_code");
        return Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token: refresh_raw,
            scope: response_scope,
        })
        .into_response();
    }

    if form.grant_type == OAuthGrantType::RefreshToken {
        let (Some(refresh_token), Some(client_id)) =
            (form.refresh_token.as_deref(), form.client_id.as_deref())
        else {
            emit_oauth_rejected("token", "invalid_refresh_token_request");
            return (StatusCode::BAD_REQUEST, "invalid refresh_token request").into_response();
        };
        if !bounded_oauth_credential(refresh_token) || !bounded_oauth_credential(client_id) {
            emit_oauth_rejected("token", "invalid_refresh_token_request");
            return (StatusCode::BAD_REQUEST, "invalid refresh_token request").into_response();
        }
        if !mcp
            .validate_client_for_token(client_id, form.client_secret.as_deref())
            .await
        {
            emit_oauth_rejected("token", "invalid_client");
            return (StatusCode::BAD_REQUEST, "invalid client").into_response();
        }
        let _mutation = mcp.mutation.lock().await;
        if !mcp.oauth_ready() {
            return oauth_state_unavailable();
        }
        let hashed = McpState::token_hash(refresh_token);
        let Some(record) = mcp.refresh_tokens.read().await.get(&hashed).cloned() else {
            emit_oauth_rejected("token", "invalid_refresh_token");
            return (StatusCode::BAD_REQUEST, "invalid refresh_token").into_response();
        };
        let issued_at = McpState::now_ts();
        if record.revoked {
            let mut refresh_tokens = mcp.refresh_tokens.write().await;
            for token in refresh_tokens.values_mut() {
                if token.family_id == record.family_id {
                    token.revoke();
                }
            }
            drop(refresh_tokens);
            if mcp.persist_snapshot_locked().await.is_err() {
                return oauth_state_unavailable();
            }
            emit_oauth_rejected("token", "refresh_token_replay");
            return (StatusCode::BAD_REQUEST, "invalid refresh_token").into_response();
        }
        if !record.is_active_for(client_id, issued_at) {
            emit_oauth_rejected("token", "refresh_token_expired_or_revoked");
            return (StatusCode::BAD_REQUEST, "refresh_token expired or revoked").into_response();
        }
        let scope = match form.scope.clone() {
            Some(requested) => {
                if !requested.is_subset_of(&record.scope) {
                    emit_oauth_rejected("token", "invalid_scope");
                    return (StatusCode::BAD_REQUEST, "invalid scope").into_response();
                }
                requested
            }
            None => record.scope.clone(),
        };
        {
            let mut refresh_tokens = mcp.refresh_tokens.write().await;
            refresh_tokens.retain(|_, token| token.family_expires_at > issued_at);
            let family_size = refresh_tokens
                .values()
                .filter(|token| token.family_id == record.family_id)
                .count();
            if refresh_tokens.len() >= core_snapshot::MAX_REFRESH_TOKENS
                || family_size >= core_snapshot::MAX_REFRESH_TOKENS_PER_FAMILY
            {
                emit_oauth_rejected("token", "refresh_token_quota_exceeded");
                return (StatusCode::TOO_MANY_REQUESTS, "OAuth state quota exceeded")
                    .into_response();
            }
        }
        let expires_at = issued_at
            .saturating_add(mcp.config.access_token_ttl_secs)
            .min(record.family_expires_at);
        let expires_in = expires_at.saturating_sub(issued_at);
        let claims = AccessClaims {
            iss: issuer.clone(),
            sub: record.principal_id.clone(),
            aud: "mcp".to_string(),
            scope: scope.clone(),
            client_id: Some(client_id.to_string()),
            iat: issued_at as usize,
            exp: expires_at as usize,
        };

        let access_token = match encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(signing_key.as_bytes()),
        ) {
            Ok(token) => token,
            Err(_) => {
                emit_oauth_failed("token", "sign_refresh_access_token");
                return (StatusCode::INTERNAL_SERVER_ERROR, "token sign failed").into_response();
            }
        };

        let next_refresh_raw = McpState::random_id("mcp_rft");
        let next_hash = McpState::token_hash(&next_refresh_raw);
        {
            let mut refresh_tokens = mcp.refresh_tokens.write().await;
            if let Some(previous) = refresh_tokens.get_mut(&hashed) {
                previous.revoke();
            }
            refresh_tokens.insert(
                next_hash.clone(),
                RefreshToken::rotate_from(
                    &record,
                    next_hash,
                    scope.clone(),
                    issued_at,
                    mcp.config.refresh_token_idle_ttl_secs,
                ),
            );
        }
        if mcp.persist_snapshot_locked().await.is_err() {
            return oauth_state_unavailable();
        }

        emit_oauth_completed("token_refresh_token");
        return Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token: next_refresh_raw,
            scope: scope.to_string(),
        })
        .into_response();
    }

    emit_oauth_rejected("token", "unsupported_grant_type");
    (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthRevokeForm {
    token: String,
}

#[tracing::instrument(name = "gateway.mcp.oauth.revoke", skip_all)]
pub(crate) async fn oauth_revoke(
    State(state): State<AppState>,
    Form(form): Form<OAuthRevokeForm>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let hashed = McpState::token_hash(&form.token);
    let _mutation = mcp.mutation.lock().await;
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let mut changed = false;
    {
        let mut refresh_tokens = mcp.refresh_tokens.write().await;
        if let Some(record) = refresh_tokens.get(&hashed) {
            let family_id = record.family_id.clone();
            for token in refresh_tokens.values_mut() {
                if token.family_id == family_id {
                    token.revoke();
                }
            }
            changed = true;
        }
    }
    if changed && mcp.persist_snapshot_locked().await.is_err() {
        return oauth_state_unavailable();
    }
    emit_oauth_completed("revoke");
    StatusCode::NO_CONTENT.into_response()
}

#[tracing::instrument(name = "gateway.mcp.oauth.metadata", skip_all)]
pub(crate) async fn oauth_metadata(State(state): State<AppState>) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let issuer = mcp.oauth_issuer().await;
    let metadata = oauth_authorization_server_metadata(&issuer);
    emit_oauth_completed("metadata");
    Json(metadata).into_response()
}

#[tracing::instrument(name = "gateway.mcp.oauth.openid_configuration", skip_all)]
pub(crate) async fn oauth_openid_configuration(State(state): State<AppState>) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let issuer = mcp.oauth_issuer().await;
    let mut metadata = oauth_authorization_server_metadata(&issuer);
    if let Some(map) = metadata.as_object_mut() {
        map.insert("subject_types_supported".to_string(), json!(["public"]));
        map.insert(
            "id_token_signing_alg_values_supported".to_string(),
            json!(["HS256"]),
        );
    }
    emit_oauth_completed("openid_configuration");
    Json(metadata).into_response()
}

fn oauth_authorization_server_metadata(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": absolute_url(issuer, "/oauth/authorize"),
        "token_endpoint": absolute_url(issuer, "/oauth/token"),
        "revocation_endpoint": absolute_url(issuer, "/oauth/revoke"),
        "jwks_uri": absolute_url(issuer, "/oauth/jwks.json"),
        "registration_endpoint": absolute_url(issuer, "/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp:tools", "mcp:channels:manage"],
        "code_challenge_methods_supported": ["S256"],
        "ui_locales_supported": MCP_UI_LOCALES_SUPPORTED
    })
}

#[tracing::instrument(name = "gateway.mcp.oauth.jwks", skip_all)]
pub(crate) async fn oauth_jwks(State(state): State<AppState>) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let signing_key = mcp.oauth_signing_key().await;
    let kid = McpState::token_hash(&signing_key);
    let response = Json(json!({
        "keys": [{
            "kty": "oct",
            "use": "sig",
            "alg": "HS256",
            "kid": &kid[..16]
        }]
    }))
    .into_response();
    emit_oauth_completed("jwks");
    response
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthRegisterRequest {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
}

#[tracing::instrument(name = "gateway.mcp.oauth.register", skip_all)]
pub(crate) async fn oauth_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OAuthRegisterRequest>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !enforce_gateway_token(&headers, &state.auth) {
        emit_oauth_rejected("register", "unauthorized");
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if !mcp.config.dcr_enabled {
        emit_oauth_rejected("register", "dcr_disabled");
        return (
            StatusCode::NOT_FOUND,
            "dynamic client registration disabled",
        )
            .into_response();
    }
    if payload.redirect_uris.is_empty() || payload.redirect_uris.len() > 16 {
        emit_oauth_rejected("register", "redirect_uris_required");
        return (StatusCode::BAD_REQUEST, "redirect_uris required").into_response();
    }
    if payload
        .redirect_uris
        .iter()
        .any(|item| !McpState::valid_redirect_uri(item))
    {
        emit_oauth_rejected("register", "redirect_uris_must_be_https");
        return (StatusCode::BAD_REQUEST, "redirect_uris must be https").into_response();
    }
    let mut redirect_uris = payload.redirect_uris.clone();
    redirect_uris.sort_unstable();
    redirect_uris.dedup();
    if redirect_uris.len() != payload.redirect_uris.len() {
        emit_oauth_rejected("register", "redirect_uris_must_be_unique");
        return (StatusCode::BAD_REQUEST, "redirect_uris must be unique").into_response();
    }
    let auth_method = match payload
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none")
        .trim()
    {
        "none" => "none",
        "client_secret_post" => "client_secret_post",
        _ => {
            emit_oauth_rejected("register", "unsupported_token_endpoint_auth_method");
            return (
                StatusCode::BAD_REQUEST,
                "unsupported token_endpoint_auth_method",
            )
                .into_response();
        }
    };
    let _mutation = mcp.mutation.lock().await;
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let client_id = McpState::random_id("mcp_client");
    let issued_client_secret =
        (auth_method == "client_secret_post").then(|| McpState::random_id("mcp_secret"));
    let client_secret_hash = issued_client_secret.as_deref().map(McpState::token_hash);
    let now = McpState::now_ts();
    {
        let mut clients = mcp.oauth_clients.write().await;
        if clients.len() >= core_snapshot::MAX_OAUTH_CLIENTS {
            emit_oauth_rejected("register", "client_quota_exceeded");
            return (StatusCode::TOO_MANY_REQUESTS, "OAuth client quota exceeded").into_response();
        }
        clients.insert(
            client_id.clone(),
            OAuthClient {
                client_id: client_id.clone(),
                client_secret_hash,
                allow_any_https_redirect_uri: false,
                redirect_uris: redirect_uris.clone(),
                token_endpoint_auth_method: auth_method.to_string(),
                created_at: now,
            },
        );
    }
    if mcp.persist_snapshot_locked().await.is_err() {
        return oauth_state_unavailable();
    }

    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "client_name": payload.client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": auth_method
    });
    if let Some(issued_client_secret) = issued_client_secret
        && let Some(fields) = response.as_object_mut()
    {
        fields.insert("client_secret".to_string(), json!(issued_client_secret));
        fields.insert("client_secret_expires_at".to_string(), json!(0));
    }
    emit_oauth_completed("register");
    (StatusCode::CREATED, Json(response)).into_response()
}

#[tracing::instrument(name = "gateway.mcp.oauth.protected_resource_metadata", skip_all)]
pub(crate) async fn oauth_protected_resource_metadata(State(state): State<AppState>) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let issuer = mcp.oauth_issuer().await;
    let response = Json(json!({
        "resource": absolute_url(&issuer, "/mcp"),
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp:tools", "mcp:channels:manage"],
        "bearer_methods_supported": ["header"]
    }))
    .into_response();
    emit_oauth_completed("protected_resource_metadata");
    response
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthChannelValidateRequest {
    channel_id: String,
    password: String,
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    ui_locales: Option<String>,
}

#[tracing::instrument(name = "gateway.mcp.oauth.channel_validate", skip_all)]
pub(crate) async fn oauth_channel_validate(
    State(state): State<AppState>,
    Json(payload): Json<OAuthChannelValidateRequest>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if !mcp.oauth_ready() {
        return oauth_state_unavailable();
    }
    let locale = McpLocale::from_request(payload.lang.as_deref(), payload.ui_locales.as_deref());
    let channel_id = match parse_channel_id(&payload.channel_id) {
        Ok(value) => value,
        Err(_) => {
            emit_oauth_rejected("channel_validate", "invalid_channel_id");
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"valid": false, "message": channel_validate_invalid_channel_id(locale)}),
                ),
            )
                .into_response();
        }
    };
    let password = match validate_channel_password(&payload.password) {
        Ok(value) => value,
        Err(_) => {
            emit_oauth_rejected("channel_validate", "invalid_password");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"valid": false, "message": channel_validate_invalid_password(locale)})),
            )
                .into_response();
        }
    };
    let response = match state
        .store
        .channel_info_with_password(channel_id, password)
        .await
    {
        Ok(Some(info)) => (
            StatusCode::OK,
            Json(json!({
                "valid": true,
                "channel_name": info.alias
            })),
        )
            .into_response(),
        Ok(None) => {
            emit_oauth_rejected("channel_validate", "channel_password_mismatch");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"valid": false, "message": channel_validate_mismatch(locale)})),
            )
                .into_response()
        }
        Err(_) => {
            emit_oauth_failed("channel_validate", "channel_validation");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"valid": false, "message": "channel validation is temporarily unavailable"})),
            )
                .into_response()
        }
    };
    emit_oauth_completed("channel_validate");
    response
}

#[cfg(test)]
mod oauth_security_tests {
    use super::{valid_pkce_verifier, valid_s256_challenge};

    #[test]
    fn pkce_s256_requires_rfc7636_verifier_shape() {
        assert!(valid_pkce_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!valid_pkce_verifier("short"));
        assert!(!valid_pkce_verifier(&"a".repeat(129)));
        assert!(!valid_pkce_verifier(&format!("{}=", "a".repeat(42))));
        assert!(valid_s256_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}
