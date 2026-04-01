use super::*;

fn extract_auth_code(location: &str) -> String {
    location
        .split('?')
        .nth(1)
        .and_then(|query| {
            query
                .split('&')
                .find(|pair| pair.starts_with("code="))
                .and_then(|pair| pair.split_once('=').map(|(_, v)| v.to_string()))
        })
        .expect("code should exist in redirect")
}

async fn oauth_access_token(app: axum::Router, channel_id: &str, signing_scope: &str) -> String {
    let register_payload = json!({
        "redirect_uris": ["https://client.example/callback"],
        "token_endpoint_auth_method": "none"
    });
    let (register_status, register_body) =
        post_json(app.clone(), "/oauth/register", register_payload).await;
    assert_eq!(register_status, StatusCode::CREATED);
    let client_id = register_body
        .get("client_id")
        .and_then(Value::as_str)
        .expect("client_id should exist");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let authorize_form = format!(
        "client_id={client_id}&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope={signing_scope}&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = extract_auth_code(location);

    let token_form = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
    );
    let (token_status, _, token_body_raw) =
        post_form(app, "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    token_body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token should exist")
        .to_string()
}

async fn raw_mcp_post(
    app: axum::Router,
    payload: Value,
    bearer: Option<&str>,
) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let response = app
        .oneshot(
            builder
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    (status, headers, body.to_vec())
}

async fn get_text(app: axum::Router, path: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    (
        status,
        String::from_utf8(body.to_vec()).expect("response body should be UTF-8"),
    )
}

#[tokio::test]
async fn mcp_legacy_send_requires_password() {
    let state = build_mcp_test_state(AuthMode::SharedToken(Arc::from("legacy-shared-token"))).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-legacy-password"),
                "password-1234",
                "android-token-mcp-legacy-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");

    let (status, body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "pushgo.message.send",
                "arguments": {
                    "channel_id": channel_id,
                    "title": "hello from mcp"
                }
            }
        }),
        "legacy-shared-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str),
        Some("password_required_in_legacy_mode")
    );
}

#[tokio::test]
async fn mcp_oauth_s256_authorize_and_send_success() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-send"),
                "password-1234",
                "android-token-mcp-oauth-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(
        app.clone(),
        channel_id.as_str(),
        "mcp:tools%20mcp:channels:manage",
    )
    .await;

    let (status, body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "pushgo.message.send",
                "arguments": {
                    "channel_id": channel_id,
                    "title": "hello from oauth"
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "mcp oauth send should succeed: {body}"
    );
    assert_eq!(
        body.get("result")
            .and_then(|v| v.get("structuredContent"))
            .and_then(|v| v.get("auth_mode"))
            .and_then(Value::as_str),
        Some("oauth2")
    );
}

#[tokio::test]
async fn mcp_channel_unbind_does_not_require_password() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-unbind"),
                "password-1234",
                "android-token-mcp-oauth-unbind-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token =
        oauth_access_token(app.clone(), channel_id.as_str(), "mcp:channels:manage").await;

    let (status, body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2001,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.unbind",
                "arguments": {
                    "channel_id": channel_id
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("error").is_none(), "unbind should succeed: {body}");
    if let Some(structured) = body.get("result").and_then(|v| v.get("structuredContent")) {
        assert_eq!(
            structured.get("removed").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            structured.get("channel_id").and_then(Value::as_str),
            Some(channel_id.as_str())
        );
        assert_eq!(
            structured.get("channel_name").and_then(Value::as_str),
            Some("mcp-oauth-unbind")
        );
        assert_eq!(
            structured.get("resources_changed").and_then(Value::as_bool),
            Some(true)
        );
    } else {
        assert_eq!(
            body.get("method").and_then(Value::as_str),
            Some("notifications/resources/list_changed"),
            "unexpected unbind payload: {body}"
        );
    }

    let (list_status, list_body) = post_json_with_auth(
        app,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2002,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.list",
                "arguments": {}
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    let channels = list_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("channels"))
        .and_then(Value::as_array)
        .expect("channel list should be array");
    assert!(
        channels.iter().all(|item| {
            item.get("channel_id")
                .and_then(Value::as_str)
                .is_none_or(|value| value != channel_id)
        }),
        "channel should be removed from authorized list: {list_body}"
    );
}

#[tokio::test]
async fn mcp_refresh_token_cannot_escalate_scope() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-refresh"),
                "password-1234",
                "android-token-mcp-oauth-refresh-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let (register_status, register_body) = post_json(
        app.clone(),
        "/oauth/register",
        json!({"redirect_uris":[redirect_uri],"token_endpoint_auth_method":"none"}),
    )
    .await;
    assert_eq!(register_status, StatusCode::CREATED);
    let client_id = register_body
        .get("client_id")
        .and_then(Value::as_str)
        .expect("client_id should exist");
    let authorize_form = format!(
        "client_id={client_id}&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = extract_auth_code(location);
    let token_form = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
    );
    let (token_status, _, token_body_raw) =
        post_form(app.clone(), "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    let refresh_token = token_body
        .get("refresh_token")
        .and_then(Value::as_str)
        .expect("refresh_token should exist");
    let refresh_form = format!(
        "grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}&scope=mcp:tools%20mcp:channels:manage"
    );
    let (status, _, body) = post_form(app, "/oauth/token", refresh_form.as_str()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(String::from_utf8(body).expect("text body"), "invalid scope");
}

#[tokio::test]
async fn mcp_send_requires_mcp_tools_scope() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-scope"),
                "password-1234",
                "android-token-mcp-oauth-scope-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token =
        oauth_access_token(app.clone(), channel_id.as_str(), "mcp:channels:manage").await;
    let (status, headers, body) = raw_mcp_post(
        app.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "pushgo.message.send",
                "arguments": {
                    "channel_id": channel_id,
                    "title": "hello scope"
                }
            }
        }),
        Some(&access_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let challenge = headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        challenge.contains("insufficient_scope"),
        "expected insufficient_scope challenge, got {challenge}"
    );
    assert!(
        challenge.contains("mcp:tools"),
        "expected tools scope in challenge, got {challenge}"
    );
    assert!(
        body.is_empty(),
        "forbidden response should not emit JSON-RPC body"
    );
}

#[tokio::test]
async fn mcp_bind_session_is_one_time() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-bind-once"),
                "password-1234",
                "android-token-mcp-oauth-bind-once-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(
        app.clone(),
        channel_id.as_str(),
        "mcp:tools%20mcp:channels:manage",
    )
    .await;
    let (start_status, start_body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.bind.start",
                "arguments": {
                    "requested_channel_id": channel_id
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(start_status, StatusCode::OK);
    let bind_session_id = start_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("bind_session_id"))
        .and_then(Value::as_str)
        .expect("bind_session_id should exist");
    let bind_url = start_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("bind_url"))
        .and_then(Value::as_str)
        .expect("bind_url should exist");
    assert!(
        bind_url.starts_with("https://sandbox.pushgo.dev/mcp/bind/session?bind_session_id="),
        "bind_url should be absolute: {bind_url}"
    );
    let bind_form =
        format!("bind_session_id={bind_session_id}&channel_id={channel_id}&password=password-1234");
    let (first_status, _, _) =
        post_form(app.clone(), "/mcp/bind/session", bind_form.as_str()).await;
    assert_eq!(first_status, StatusCode::OK);
    let (second_status, _, second_body) =
        post_form(app, "/mcp/bind/session", bind_form.as_str()).await;
    assert_eq!(second_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        String::from_utf8(second_body).expect("text body"),
        "bind session already completed"
    );
}

#[tokio::test]
async fn mcp_bind_status_marks_resources_changed_once() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-oauth-bind-status-once"),
                "password-1234",
                "android-token-mcp-oauth-bind-status-once-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(
        app.clone(),
        channel_id.as_str(),
        "mcp:tools%20mcp:channels:manage",
    )
    .await;

    let (start_status, start_body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2101,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.bind.start",
                "arguments": {
                    "requested_channel_id": channel_id
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(start_status, StatusCode::OK);
    let bind_session_id = start_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("bind_session_id"))
        .and_then(Value::as_str)
        .expect("bind_session_id should exist")
        .to_string();

    let bind_form =
        format!("bind_session_id={bind_session_id}&channel_id={channel_id}&password=password-1234");
    let (bind_status, _, _) = post_form(app.clone(), "/mcp/bind/session", bind_form.as_str()).await;
    assert_eq!(bind_status, StatusCode::OK);

    let (first_status, first_body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2102,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.bind.status",
                "arguments": {
                    "bind_session_id": bind_session_id
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    if let Some(structured) = first_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
    {
        assert_eq!(
            structured.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            structured.get("resources_changed").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            structured.get("channel_id").and_then(Value::as_str),
            Some(channel_id.as_str())
        );
        assert_eq!(
            structured.get("channel_name").and_then(Value::as_str),
            Some("mcp-oauth-bind-status-once")
        );
    } else {
        assert_eq!(
            first_body.get("method").and_then(Value::as_str),
            Some("notifications/resources/list_changed"),
            "unexpected first bind.status payload: {first_body}"
        );
    }

    let (second_status, second_body) = post_json_with_auth(
        app,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 2103,
            "method": "tools/call",
            "params": {
                "name": "pushgo.channel.bind.status",
                "arguments": {
                    "bind_session_id": bind_session_id
                }
            }
        }),
        &access_token,
    )
    .await;
    assert_eq!(second_status, StatusCode::OK);
    let structured = second_body
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .expect("second bind.status should return structured content");
    assert_eq!(
        structured.get("status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        structured.get("resources_changed").and_then(Value::as_bool),
        Some(false),
        "resources_changed should be one-shot: {second_body}"
    );
}

#[tokio::test]
async fn mcp_grant_password_not_persisted_in_snapshot() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let store = state.store.clone();
    let channel_id = crate::api::format_channel_id(
        &store
            .subscribe_channel(
                None,
                Some("mcp-oauth-encrypted-grant"),
                "password-1234",
                "android-token-mcp-oauth-encrypted-grant-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let (register_status, register_body) = post_json(
        app.clone(),
        "/oauth/register",
        json!({"redirect_uris":[redirect_uri],"token_endpoint_auth_method":"none"}),
    )
    .await;
    assert_eq!(register_status, StatusCode::CREATED);
    let client_id = register_body
        .get("client_id")
        .and_then(Value::as_str)
        .expect("client_id should exist");
    let authorize_form = format!(
        "client_id={client_id}&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools&channel_bindings={channel_id},password-1234"
    );
    let (status, _, _) = post_form(app, "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let snapshot = store
        .load_mcp_state_json()
        .await
        .expect("load mcp snapshot should succeed")
        .expect("mcp snapshot should exist");
    assert!(
        !snapshot.contains("password-1234"),
        "snapshot should not contain plaintext password"
    );
}

#[tokio::test]
async fn mcp_jwks_returns_non_empty_key_set() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = get_json(app, "/oauth/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    let keys = body
        .get("keys")
        .and_then(Value::as_array)
        .expect("jwks keys should be array");
    assert!(!keys.is_empty(), "jwks keys should not be empty");
    let kid = keys[0]
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(!kid.is_empty(), "jwks kid should not be empty");
}

#[tokio::test]
async fn oauth_register_requires_gateway_token_when_enabled() {
    let state = build_mcp_test_state(AuthMode::SharedToken(Arc::from("gateway-token-1"))).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let payload = json!({
        "redirect_uris": ["https://client.example/callback"],
        "token_endpoint_auth_method": "none"
    });

    let unauthorized_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(unauthorized_response.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_body = to_bytes(unauthorized_response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    assert_eq!(String::from_utf8_lossy(&unauthorized_body), "unauthorized");

    let (status, body) =
        post_json_with_auth(app, "/oauth/register", payload, "gateway-token-1").await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body.get("client_id").and_then(Value::as_str).is_some());
    assert!(body.get("client_secret").and_then(Value::as_str).is_some());
}

#[tokio::test]
async fn oauth_metadata_returns_absolute_endpoints() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-authorization-server")
                .header("host", "sandbox.pushgo.dev")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let json: Value = serde_json::from_slice(&body).expect("json body");
    assert_eq!(
        json.get("ui_locales_supported"),
        Some(&json!(["en", "zh-CN"]))
    );
    for key in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "revocation_endpoint",
        "jwks_uri",
        "registration_endpoint",
    ] {
        let value = json
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        assert!(
            value.starts_with("https://sandbox.pushgo.dev"),
            "{key} should be absolute https URL: {value}"
        );
    }
}

#[tokio::test]
async fn oauth_authorize_page_supports_chinese_locale() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (register_status, register_body) = post_json(
        app.clone(),
        "/oauth/register",
        json!({
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none"
        }),
    )
    .await;
    assert_eq!(register_status, StatusCode::CREATED);
    let client_id = register_body
        .get("client_id")
        .and_then(Value::as_str)
        .expect("client_id should exist");
    let (status, body) = get_text(
        app,
        &format!(
            "/oauth/authorize?client_id={client_id}&redirect_uri=https://client.example/callback&code_challenge=test&code_challenge_method=plain&lang=zh-CN"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("PushGo MCP 授权"));
    assert!(body.contains("频道名"));
    assert!(body.contains("失焦后会自动校验"));
}

#[tokio::test]
async fn oauth_register_returns_not_found_when_dcr_disabled() {
    let mut state = build_test_state().await;
    let config = McpConfig {
        bootstrap_http_addr: Arc::from("127.0.0.1:6666"),
        public_base_url: Some(Arc::from("https://sandbox.pushgo.dev")),
        access_token_ttl_secs: 900,
        refresh_token_absolute_ttl_secs: 2592000,
        refresh_token_idle_ttl_secs: 604800,
        bind_session_ttl_secs: 600,
        dcr_enabled: false,
        predefined_clients: Vec::new(),
    };
    state.mcp = Some(Arc::new(
        McpState::new(config, &state.auth, state.store.clone()).await,
    ));
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "redirect_uris": ["https://client.example/callback"],
                        "token_endpoint_auth_method": "none"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    assert_eq!(
        String::from_utf8(body.to_vec()).expect("text body"),
        "dynamic client registration disabled"
    );
}

#[tokio::test]
async fn predefined_client_can_authorize_without_registration() {
    let mut state = build_test_state().await;
    let config = McpConfig {
        bootstrap_http_addr: Arc::from("127.0.0.1:6666"),
        public_base_url: Some(Arc::from("https://sandbox.pushgo.dev")),
        access_token_ttl_secs: 900,
        refresh_token_absolute_ttl_secs: 2592000,
        refresh_token_idle_ttl_secs: 604800,
        bind_session_ttl_secs: 600,
        dcr_enabled: false,
        predefined_clients: vec![crate::mcp::McpPredefinedClientConfig {
            client_id: Arc::from("chatgpt-static"),
            client_secret: Arc::from("static-secret"),
        }],
    };
    state.mcp = Some(Arc::new(
        McpState::new(config, &state.auth, state.store.clone()).await,
    ));
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-static-client"),
                "password-1234",
                "android-token-mcp-static-client-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let code_verifier = "static-client-verifier";
    let authorize_form = format!(
        "client_id=chatgpt-static&redirect_uri=https://client.example/callback&code_challenge={code_verifier}&code_challenge_method=plain&scope=mcp:tools&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = extract_auth_code(location);
    let token_form = format!(
        "grant_type=authorization_code&client_id=chatgpt-static&client_secret=static-secret&code={code}&redirect_uri=https://client.example/callback&code_verifier={code_verifier}"
    );
    let (token_status, _, token_body_raw) =
        post_form(app, "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    assert!(
        token_body
            .get("access_token")
            .and_then(Value::as_str)
            .is_some()
    );
}

#[tokio::test]
async fn oauth_discovery_compat_endpoints_are_available() {
    let state = build_mcp_test_state(AuthMode::SharedToken(Arc::from("gateway-token-1"))).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server/oauth",
        "/oauth/.well-known/oauth-authorization-server",
        "/oauth/.well-known/openid-configuration",
        "/.well-known/openid-configuration/oauth",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("host", "sandbox.pushgo.dev")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should handle request");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "expected 200 for discovery endpoint {path}"
        );
    }
}

#[tokio::test]
async fn mcp_requires_bearer_challenge_before_initialize() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, headers, body) = raw_mcp_post(
        app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        challenge.contains("/.well-known/oauth-protected-resource/mcp"),
        "expected resource metadata challenge, got {challenge}"
    );
    assert!(
        body.is_empty(),
        "unauthorized response should not emit JSON-RPC body"
    );
}

#[tokio::test]
async fn mcp_notifications_initialized_is_accepted() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("mcp-notify-init"),
                "password-1234",
                "android-token-mcp-notify-init-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(app.clone(), channel_id.as_str(), "mcp:tools").await;

    let (init_status, init_headers, init_body) = raw_mcp_post(
        app.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }),
        Some(&access_token),
    )
    .await;
    assert_eq!(init_status, StatusCode::OK);
    let content_type = init_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.contains("application/json"),
        "expected application/json content type, got {content_type}"
    );
    let init_payload: Value = serde_json::from_slice(&init_body).expect("initialize response json");
    assert!(
        init_payload.get("result").is_some(),
        "initialize should return a result: {init_payload}"
    );

    let (notify_status, _, notify_body) = raw_mcp_post(
        app,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        Some(&access_token),
    )
    .await;
    assert_eq!(notify_status, StatusCode::ACCEPTED);
    assert!(
        notify_body.is_empty(),
        "initialized notification should not return a body"
    );
}

#[tokio::test]
async fn mcp_resources_list_contains_authorized_channels() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("resource-channel"),
                "password-1234",
                "android-token-mcp-res-list-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(
        app.clone(),
        channel_id.as_str(),
        "mcp:tools%20mcp:channels:manage",
    )
    .await;

    let (status, body) = post_json_with_auth(
        app,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 901,
            "method": "resources/list"
        }),
        &access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resources = body
        .get("result")
        .and_then(|v| v.get("resources"))
        .and_then(Value::as_array)
        .expect("resources should be array");
    assert!(
        resources.iter().any(|item| {
            item.get("uri")
                .and_then(Value::as_str)
                .is_some_and(|uri| uri == "pushgo://channels")
        }),
        "should include aggregate channels resource"
    );
    assert!(
        resources.iter().any(|item| {
            item.get("uri")
                .and_then(Value::as_str)
                .is_some_and(|uri| uri == format!("pushgo://channels/{channel_id}"))
        }),
        "should include channel-specific resource"
    );
}

#[tokio::test]
async fn mcp_resources_read_channels_returns_channel_name() {
    let state = build_mcp_test_state(AuthMode::Disabled).await;
    let channel_id = crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel(
                None,
                Some("resource-channel-name"),
                "password-1234",
                "android-token-mcp-res-read-0001",
                Platform::ANDROID,
            )
            .await
            .expect("setup channel should succeed")
            .channel_id,
    );
    let app = super::super::build_router(state, "<html>docs</html>");
    let access_token = oauth_access_token(
        app.clone(),
        channel_id.as_str(),
        "mcp:tools%20mcp:channels:manage",
    )
    .await;

    let (status, body) = post_json_with_auth(
        app.clone(),
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 902,
            "method": "resources/read",
            "params": { "uri": "pushgo://channels" }
        }),
        &access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body
        .get("result")
        .and_then(|v| v.get("contents"))
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|v| v.get("text"))
        .and_then(Value::as_str)
        .expect("resource text should exist");
    let parsed: Value = serde_json::from_str(text).expect("resource text should be json");
    let channels = parsed
        .get("channels")
        .and_then(Value::as_array)
        .expect("channels should be array");
    assert!(
        channels.iter().any(|item| {
            item.get("channel_id")
                .and_then(Value::as_str)
                .is_some_and(|value| value == channel_id)
                && item
                    .get("channel_name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name == "resource-channel-name")
        }),
        "channels payload should include channel_name"
    );

    let (detail_status, detail_body) = post_json_with_auth(
        app,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 903,
            "method": "resources/read",
            "params": { "uri": format!("pushgo://channels/{channel_id}") }
        }),
        &access_token,
    )
    .await;
    assert_eq!(detail_status, StatusCode::OK);
    let detail_text = detail_body
        .get("result")
        .and_then(|v| v.get("contents"))
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|v| v.get("text"))
        .and_then(Value::as_str)
        .expect("resource detail text should exist");
    let detail_payload: Value =
        serde_json::from_str(detail_text).expect("resource detail text should be json");
    let summary = detail_payload
        .get("recent_message_event_summary")
        .expect("summary should exist");
    assert!(
        summary
            .get("recent_limit")
            .and_then(Value::as_u64)
            .is_some(),
        "summary should include recent_limit"
    );
    assert!(
        summary
            .get("recent_summaries")
            .and_then(Value::as_array)
            .is_some(),
        "summary should include recent_summaries array"
    );
    assert!(
        summary
            .get("message_summaries")
            .and_then(Value::as_array)
            .is_some(),
        "summary should include message_summaries array"
    );
    assert!(
        summary
            .get("event_summaries")
            .and_then(Value::as_array)
            .is_some(),
        "summary should include event_summaries array"
    );
}
