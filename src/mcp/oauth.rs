pub(crate) async fn oauth_authorize_get(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    if !mcp.oauth_ready() {
        return (StatusCode::BAD_REQUEST, "mcp oauth disabled").into_response();
    }
    if !mcp.is_redirect_allowed(&query.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri not allowed").into_response();
    }

    let html = format!(
        r#"<!doctype html><html><body>
<h2>PushGo MCP Authorization</h2>
<p>首次授权可绑定多个频道。每行一个: channel_id,password</p>
<form method=\"post\" action=\"/oauth/authorize\">
<input type=\"hidden\" name=\"client_id\" value=\"{client_id}\" />
<input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect_uri}\" />
<input type=\"hidden\" name=\"state\" value=\"{state}\" />
<input type=\"hidden\" name=\"code_challenge\" value=\"{code_challenge}\" />
<input type=\"hidden\" name=\"code_challenge_method\" value=\"{code_challenge_method}\" />
<input type=\"hidden\" name=\"scope\" value=\"{scope}\" />
<label>显示名(可选): <input name=\"display_name\" /></label><br/><br/>
<textarea name=\"channel_bindings\" rows=\"10\" cols=\"80\"></textarea><br/>
<button type=\"submit\">Authorize</button>
</form>
</body></html>"#,
        client_id = html_escape(&query.client_id),
        redirect_uri = html_escape(&query.redirect_uri),
        state = html_escape(query.state.as_deref().unwrap_or("")),
        code_challenge = html_escape(&query.code_challenge),
        code_challenge_method =
            html_escape(query.code_challenge_method.as_deref().unwrap_or("plain"),),
        scope = html_escape(query.scope.as_deref().unwrap_or("mcp:tools")),
    );

    Html(html).into_response()
}

pub(crate) async fn oauth_authorize_post(
    State(state): State<AppState>,
    Form(form): Form<AuthorizeSubmit>,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    if !mcp.oauth_ready() {
        return (StatusCode::BAD_REQUEST, "mcp oauth disabled").into_response();
    }
    if !mcp.is_redirect_allowed(&form.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri not allowed").into_response();
    }

    let channel_bindings = parse_channel_bindings(form.channel_bindings.as_deref());
    for item in &channel_bindings {
        let channel_id = match parse_channel_id(&item.channel_id) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid channel_id in channel_bindings",
                )
                    .into_response();
            }
        };
        let password = match validate_channel_password(&item.password) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid password in channel_bindings",
                )
                    .into_response();
            }
        };
        match state
            .store
            .channel_info_with_password(channel_id, password)
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

    let principal_id = random_id("mcp_pr");
    {
        let mut principals = mcp.principals.write().await;
        principals.insert(
            principal_id.clone(),
            Principal {
                principal_id: principal_id.clone(),
                display_name: form.display_name.clone().filter(|v| !v.trim().is_empty()),
                grants: HashMap::new(),
                created_at: now_ts(),
            },
        );
    }
    for item in channel_bindings {
        mcp.upsert_grant(&principal_id, &item.channel_id, None)
            .await;
    }

    let code = random_id("mcp_code");
    let scope = form
        .scope
        .clone()
        .unwrap_or_else(|| "mcp:tools".to_string());
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
                code_challenge_method: form
                    .code_challenge_method
                    .clone()
                    .unwrap_or_else(|| "plain".to_string()),
                expires_at: now_ts() + 300,
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
    grant_type: String,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
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
    Form(form): Form<OAuthTokenForm>,
) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    if !mcp.oauth_ready() {
        return (StatusCode::BAD_REQUEST, "mcp oauth disabled").into_response();
    }

    let Some(signing_key) = &mcp.config.oauth_signing_key else {
        return (StatusCode::BAD_REQUEST, "oauth signing key not configured").into_response();
    };

    if form.grant_type == "authorization_code" {
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

        let mut auth_codes = mcp.auth_codes.write().await;
        let Some(record) = auth_codes.get_mut(code) else {
            return (StatusCode::BAD_REQUEST, "invalid code").into_response();
        };
        if record.consumed || record.expires_at < now_ts() {
            return (StatusCode::BAD_REQUEST, "code expired or consumed").into_response();
        }
        if record.client_id != client_id || record.redirect_uri != redirect_uri {
            return (StatusCode::BAD_REQUEST, "code mismatch").into_response();
        }
        if !verify_pkce(
            &record.code_challenge,
            &record.code_challenge_method,
            code_verifier,
        ) {
            return (StatusCode::BAD_REQUEST, "code_verifier mismatch").into_response();
        }
        record.consumed = true;

        let issued_at = now_ts();
        let expires_at = issued_at + mcp.config.access_token_ttl_secs;
        let claims = AccessClaims {
            iss: mcp.config.oauth_issuer.to_string(),
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

        let refresh_raw = random_id("mcp_rft");
        let refresh_hash = token_hash(&refresh_raw);
        let refresh_record = RefreshToken {
            token_hash: refresh_hash.clone(),
            principal_id: record.principal_id.clone(),
            client_id: client_id.to_string(),
            scope: record.scope.clone(),
            expires_at: issued_at + mcp.config.refresh_token_absolute_ttl_secs,
            idle_expires_at: issued_at + mcp.config.refresh_token_idle_ttl_secs,
            revoked: false,
        };
        mcp.refresh_tokens
            .write()
            .await
            .insert(refresh_hash, refresh_record);
        let response_scope = record.scope.clone();
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

    if form.grant_type == "refresh_token" {
        let (Some(refresh_token), Some(client_id)) =
            (form.refresh_token.as_deref(), form.client_id.as_deref())
        else {
            return (StatusCode::BAD_REQUEST, "invalid refresh_token request").into_response();
        };
        let hashed = token_hash(refresh_token);
        let mut refresh_tokens = mcp.refresh_tokens.write().await;
        let Some(record) = refresh_tokens.get_mut(&hashed) else {
            return (StatusCode::BAD_REQUEST, "invalid refresh_token").into_response();
        };
        if record.revoked
            || record.expires_at < now_ts()
            || record.idle_expires_at < now_ts()
            || record.client_id != client_id
        {
            return (StatusCode::BAD_REQUEST, "refresh_token expired or revoked").into_response();
        }
        let scope = match form.scope.clone() {
            Some(requested) => {
                if !scope_is_subset(&requested, &record.scope) {
                    return (StatusCode::BAD_REQUEST, "invalid scope").into_response();
                }
                requested
            }
            None => record.scope.clone(),
        };
        let principal_id = record.principal_id.clone();
        let client_id = record.client_id.clone();
        let issued_at = now_ts();
        let expires_at = issued_at + mcp.config.access_token_ttl_secs;
        let claims = AccessClaims {
            iss: mcp.config.oauth_issuer.to_string(),
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

        record.revoked = true;
        let _ = record;
        let next_refresh_raw = random_id("mcp_rft");
        let next_hash = token_hash(&next_refresh_raw);
        refresh_tokens.insert(
            next_hash.clone(),
            RefreshToken {
                token_hash: next_hash,
                principal_id,
                client_id,
                scope: scope.clone(),
                expires_at: issued_at + mcp.config.refresh_token_absolute_ttl_secs,
                idle_expires_at: issued_at + mcp.config.refresh_token_idle_ttl_secs,
                revoked: false,
            },
        );
        drop(refresh_tokens);
        mcp.persist_snapshot().await;

        return Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: mcp.config.access_token_ttl_secs,
            refresh_token: next_refresh_raw,
            scope,
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
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    let hashed = token_hash(&form.token);
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

pub(crate) async fn oauth_metadata(State(state): State<AppState>) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    Json(json!({
        "issuer": mcp.config.oauth_issuer,
        "authorization_endpoint": "/oauth/authorize",
        "token_endpoint": "/oauth/token",
        "revocation_endpoint": "/oauth/revoke",
        "jwks_uri": "/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp:tools", "mcp:channels:manage"],
        "code_challenge_methods_supported": ["plain", "S256"]
    }))
    .into_response()
}

pub(crate) async fn oauth_jwks(State(state): State<AppState>) -> Response {
    let Some(mcp) = state.mcp.as_ref() else {
        return (StatusCode::NOT_FOUND, "mcp disabled").into_response();
    };
    let Some(signing_key) = &mcp.config.oauth_signing_key else {
        return (StatusCode::BAD_REQUEST, "mcp oauth disabled").into_response();
    };
    let kid = token_hash(signing_key);
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
pub(crate) struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

fn scope_is_subset(requested: &str, granted: &str) -> bool {
    let requested_set: HashSet<&str> = requested
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    let granted_set: HashSet<&str> = granted
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    requested_set.is_subset(&granted_set)
}
