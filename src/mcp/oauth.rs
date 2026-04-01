fn request_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers.get("x-forwarded-host").or_else(|| headers.get("host"))?;
    let host = host.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("https")
        .trim();
    let proto = if proto.eq_ignore_ascii_case("http") {
        "http"
    } else {
        "https"
    };
    Some(format!("{proto}://{host}"))
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
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

fn js_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing JS string should not fail")
}

pub(crate) async fn oauth_authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }
    if !mcp
        .client_redirect_allowed(query.client_id.as_str(), query.redirect_uri.as_str())
        .await
    {
        return (StatusCode::BAD_REQUEST, "client or redirect_uri invalid").into_response();
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
        code_challenge_method = html_escape(
            query
                .code_challenge_method
                .unwrap_or(PkceMethod::Plain)
                .as_str(),
        ),
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

    Html(html).into_response()
}

pub(crate) async fn oauth_authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeSubmit>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }
    if !mcp
        .client_redirect_allowed(form.client_id.as_str(), form.redirect_uri.as_str())
        .await
    {
        return (StatusCode::BAD_REQUEST, "client or redirect_uri invalid").into_response();
    }
    let _locale = McpLocale::from_request(form.lang.as_deref(), form.ui_locales.as_deref());

    let channel_bindings = ChannelBindingList::parse(form.channel_bindings.as_deref());
    for item in channel_bindings.iter() {
        match state
            .store
            .channel_info_with_password(item.channel_id.into_inner(), item.password.as_str())
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "channel or password mismatch in channel_bindings",
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "channel validation failed",
                )
                    .into_response();
            }
        }
    }

    let principal_id = McpState::random_id("mcp_pr");
    {
        let mut principals = mcp.principals.write().await;
        principals.insert(
            principal_id.clone(),
            Principal {
                principal_id: principal_id.clone(),
                display_name: None,
                grants: HashMap::new(),
                created_at: McpState::now_ts(),
            },
        );
    }
    for item in channel_bindings.into_vec() {
        mcp.upsert_grant(&principal_id, &item.channel_id_text, None)
            .await;
    }

    let code = McpState::random_id("mcp_code");
    let scope = form.scope.clone().unwrap_or_else(McpScopeSet::tools);
    {
        let mut auth_codes = mcp.auth_codes.write().await;
        auth_codes.insert(
            code.clone(),
            AuthCode {
                code: code.clone(),
                principal_id,
                client_id: form.client_id.clone(),
                redirect_uri: form.redirect_uri.clone(),
                scope,
                code_challenge: form.code_challenge.clone(),
                code_challenge_method: form.code_challenge_method.unwrap_or(PkceMethod::Plain),
                expires_at: McpState::now_ts() + 300,
                consumed: false,
            },
        );
    }
    mcp.persist_snapshot().await;

    let mut location = form.redirect_uri;
    let sep = if location.contains('?') { '&' } else { '?' };
    let _ = write!(location, "{sep}code={code}");
    if let Some(state_param) = form.state
        && !state_param.is_empty()
    {
        let _ = write!(location, "&state={state_param}");
    }
    Redirect::to(&location).into_response()
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

pub(crate) async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<OAuthTokenForm>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
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
            return (
                StatusCode::BAD_REQUEST,
                "invalid authorization_code request",
            )
                .into_response();
        };
        if !mcp
            .validate_client_for_token(client_id, form.client_secret.as_deref())
            .await
        {
            return (StatusCode::BAD_REQUEST, "invalid client").into_response();
        }

        let mut auth_codes = mcp.auth_codes.write().await;
        let Some(record) = auth_codes.get_mut(code) else {
            return (StatusCode::BAD_REQUEST, "invalid code").into_response();
        };
        if !record.is_active(McpState::now_ts()) {
            return (StatusCode::BAD_REQUEST, "code expired or consumed").into_response();
        }
        if !record.matches_exchange_request(client_id, redirect_uri) {
            return (StatusCode::BAD_REQUEST, "code mismatch").into_response();
        }
        if !record
            .code_challenge_method
            .verify(&record.code_challenge, code_verifier)
        {
            return (StatusCode::BAD_REQUEST, "code_verifier mismatch").into_response();
        }
        record.consume();

        let issued_at = McpState::now_ts();
        let expires_at = issued_at + mcp.config.access_token_ttl_secs;
        let claims = AccessClaims {
            iss: issuer.clone(),
            sub: record.principal_id.clone(),
            aud: "mcp".to_string(),
            scope: record.scope.clone(),
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
                return (StatusCode::INTERNAL_SERVER_ERROR, "token sign failed").into_response();
            }
        };

        let refresh_raw = McpState::random_id("mcp_rft");
        let refresh_hash = McpState::token_hash(&refresh_raw);
        let refresh_record = RefreshToken::rotated(
            refresh_hash.clone(),
            record.principal_id.clone(),
            client_id.to_string(),
            record.scope.clone(),
            issued_at,
            mcp.config.refresh_token_absolute_ttl_secs,
            mcp.config.refresh_token_idle_ttl_secs,
        );
        mcp.refresh_tokens
            .write()
            .await
            .insert(refresh_hash, refresh_record);
        let response_scope = record.scope.to_string();
        drop(auth_codes);
        mcp.persist_snapshot().await;

        return Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: mcp.config.access_token_ttl_secs,
            refresh_token: refresh_raw,
            scope: response_scope,
        })
        .into_response();
    }

    if form.grant_type == OAuthGrantType::RefreshToken {
        let (Some(refresh_token), Some(client_id)) =
            (form.refresh_token.as_deref(), form.client_id.as_deref())
        else {
            return (StatusCode::BAD_REQUEST, "invalid refresh_token request").into_response();
        };
        if !mcp
            .validate_client_for_token(client_id, form.client_secret.as_deref())
            .await
        {
            return (StatusCode::BAD_REQUEST, "invalid client").into_response();
        }
        let hashed = McpState::token_hash(refresh_token);
        let mut refresh_tokens = mcp.refresh_tokens.write().await;
        let Some(record) = refresh_tokens.get_mut(&hashed) else {
            return (StatusCode::BAD_REQUEST, "invalid refresh_token").into_response();
        };
        if !record.is_active_for(client_id, McpState::now_ts()) {
            return (StatusCode::BAD_REQUEST, "refresh_token expired or revoked").into_response();
        }
        let scope = match form.scope.clone() {
            Some(requested) => {
                if !requested.is_subset_of(&record.scope) {
                    return (StatusCode::BAD_REQUEST, "invalid scope").into_response();
                }
                requested
            }
            None => record.scope.clone(),
        };
        let principal_id = record.principal_id.clone();
        let client_id = record.client_id.clone();
        let issued_at = McpState::now_ts();
        let expires_at = issued_at + mcp.config.access_token_ttl_secs;
        let claims = AccessClaims {
            iss: issuer.clone(),
            sub: principal_id.clone(),
            aud: "mcp".to_string(),
            scope: scope.clone(),
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
                return (StatusCode::INTERNAL_SERVER_ERROR, "token sign failed").into_response();
            }
        };

        record.revoke();
        let _ = record;
        let next_refresh_raw = McpState::random_id("mcp_rft");
        let next_hash = McpState::token_hash(&next_refresh_raw);
        refresh_tokens.insert(
            next_hash.clone(),
            RefreshToken::rotated(
                next_hash,
                principal_id,
                client_id,
                scope.clone(),
                issued_at,
                mcp.config.refresh_token_absolute_ttl_secs,
                mcp.config.refresh_token_idle_ttl_secs,
            ),
        );
        drop(refresh_tokens);
        mcp.persist_snapshot().await;

        return Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: mcp.config.access_token_ttl_secs,
            refresh_token: next_refresh_raw,
            scope: scope.to_string(),
        })
        .into_response();
    }

    (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthRevokeForm {
    token: String,
}

pub(crate) async fn oauth_revoke(
    State(state): State<AppState>,
    Form(form): Form<OAuthRevokeForm>,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    let hashed = McpState::token_hash(&form.token);
    let mut changed = false;
    {
        let mut refresh_tokens = mcp.refresh_tokens.write().await;
        if let Some(record) = refresh_tokens.get_mut(&hashed) {
            record.revoked = true;
            changed = true;
        }
    }
    if changed {
        mcp.persist_snapshot().await;
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn oauth_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }
    let issuer = mcp.oauth_issuer().await;
    let metadata = oauth_authorization_server_metadata(&issuer);
    Json(metadata).into_response()
}

pub(crate) async fn oauth_openid_configuration(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }
    let issuer = mcp.oauth_issuer().await;
    let mut metadata = oauth_authorization_server_metadata(&issuer);
    if let Some(map) = metadata.as_object_mut() {
        map.insert(
            "subject_types_supported".to_string(),
            json!(["public"]),
        );
        map.insert(
            "id_token_signing_alg_values_supported".to_string(),
            json!(["HS256"]),
        );
    }
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
        "code_challenge_methods_supported": ["plain", "S256"],
        "ui_locales_supported": MCP_UI_LOCALES_SUPPORTED
    })
}

pub(crate) async fn oauth_jwks(State(state): State<AppState>) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    let signing_key = mcp.oauth_signing_key().await;
    let kid = McpState::token_hash(&signing_key);
    Json(json!({
        "keys": [{
            "kty": "oct",
            "use": "sig",
            "alg": "HS256",
            "kid": &kid[..16]
        }]
    }))
    .into_response()
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
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if !mcp.config.dcr_enabled {
        return (StatusCode::NOT_FOUND, "dynamic client registration disabled").into_response();
    }
    if payload.redirect_uris.is_empty() {
        return (StatusCode::BAD_REQUEST, "redirect_uris required").into_response();
    }
    if payload
        .redirect_uris
        .iter()
        .any(|item| !item.starts_with("https://"))
    {
        return (StatusCode::BAD_REQUEST, "redirect_uris must be https").into_response();
    }
    let auth_method = match payload
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none")
        .trim()
    {
        "none" => "none",
        "client_secret_post" => "client_secret_post",
        _ => return (StatusCode::BAD_REQUEST, "unsupported token_endpoint_auth_method").into_response(),
    };
    let client_id = McpState::random_id("mcp_client");
    let issued_client_secret = McpState::random_id("mcp_secret");
    let client_secret_hash = if auth_method == "client_secret_post" {
        Some(McpState::token_hash(&issued_client_secret))
    } else {
        None
    };
    let now = McpState::now_ts();
    {
        let mut clients = mcp.oauth_clients.write().await;
        clients.insert(
            client_id.clone(),
            OAuthClient {
                client_id: client_id.clone(),
                client_secret_hash,
                allow_any_https_redirect_uri: false,
                redirect_uris: payload.redirect_uris.clone(),
                token_endpoint_auth_method: auth_method.to_string(),
                created_at: now,
            },
        );
    }
    mcp.persist_snapshot().await;

    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": now,
            "client_secret": issued_client_secret,
            "client_secret_expires_at": 0,
            "client_name": payload.client_name,
            "redirect_uris": payload.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": auth_method
        })),
    )
        .into_response()
}

pub(crate) async fn oauth_protected_resource_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    if let Some(origin) = request_origin(&headers) {
        mcp.maybe_update_issuer_from_origin(&origin).await;
    }
    let issuer = mcp.oauth_issuer().await;
    Json(json!({
        "resource": absolute_url(&issuer, "/mcp"),
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp:tools", "mcp:channels:manage"],
        "bearer_methods_supported": ["header"]
    }))
    .into_response()
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

pub(crate) async fn oauth_channel_validate(
    State(state): State<AppState>,
    Json(payload): Json<OAuthChannelValidateRequest>,
) -> Response {
    let _mcp = state
        .mcp
        .as_ref()
        .expect("mcp routes must only be mounted when MCP is enabled");
    let locale = McpLocale::from_request(payload.lang.as_deref(), payload.ui_locales.as_deref());
    let channel_id = match parse_channel_id(&payload.channel_id) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"valid": false, "message": channel_validate_invalid_channel_id(locale)})),
            )
                .into_response();
        }
    };
    let password = match validate_channel_password(&payload.password) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"valid": false, "message": channel_validate_invalid_password(locale)})),
            )
                .into_response();
        }
    };
    match state.store.channel_info_with_password(channel_id, password).await {
        Ok(Some(info)) => (
            StatusCode::OK,
            Json(json!({
                "valid": true,
                "channel_name": info.alias
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"valid": false, "message": channel_validate_mismatch(locale)})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"valid": false, "message": channel_validate_mismatch(locale)})),
        )
            .into_response(),
    }
}
