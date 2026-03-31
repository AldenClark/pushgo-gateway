use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::{
    app::{AppState, AuthMode},
    delivery_audit::DeliveryAuditCollector,
    device_registry::DeviceRegistry,
    dispatch::{
        audit::{DEFAULT_DISPATCH_AUDIT_CAPACITY, DispatchAuditLog},
        create_dispatch_channels,
    },
    mcp::{McpAuthMode, McpConfig, McpState},
    stats::StatsCollector,
    storage::{Platform, Storage},
};

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn build_test_state() -> AppState {
    let unique_id = TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let db_url = format!(
        "sqlite:///tmp/pushgo-router-test-{}-{}-{}.db",
        std::process::id(),
        unique_id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    );
    let store = Storage::new(Some(db_url.as_str()))
        .await
        .expect("sqlite test store should initialize");
    let (dispatch, _apns_rx, _fcm_rx, _wns_rx) = create_dispatch_channels();
    AppState {
        dispatch,
        dispatch_audit: Arc::new(DispatchAuditLog::new(
            DEFAULT_DISPATCH_AUDIT_CAPACITY,
            false,
        )),
        delivery_audit: DeliveryAuditCollector::spawn(
            false,
            store.clone(),
            Arc::new(DispatchAuditLog::new(
                DEFAULT_DISPATCH_AUDIT_CAPACITY,
                false,
            )),
        ),
        auth: AuthMode::Disabled,
        private_channel_enabled: false,
        diagnostics_api_enabled: false,
        device_registry: Arc::new(DeviceRegistry::new()),
        stats: StatsCollector::spawn(store.clone()),
        private_transport_profile: crate::app::PrivateTransportProfile {
            quic_enabled: true,
            quic_port: Some(443),
            tcp_enabled: true,
            tcp_port: 5223,
            wss_enabled: true,
            wss_port: 6666,
            wss_path: Arc::from("/private/ws"),
            ws_subprotocol: Arc::from("pushgo-private.v1"),
        },
        private: None,
        store,
        mcp: None,
    }
}

async fn build_mcp_test_state(
    auth: AuthMode,
    mcp_auth_mode: McpAuthMode,
    oauth_enabled: bool,
    signing_key: Option<&str>,
) -> AppState {
    let mut state = build_test_state().await;
    state.auth = auth.clone();
    let config = McpConfig {
        oauth_enabled,
        legacy_auth_enabled: true,
        auth_mode: mcp_auth_mode,
        oauth_issuer: Arc::from("https://gateway.test"),
        oauth_signing_key: signing_key.map(|value| Arc::from(value.to_string().into_boxed_str())),
        access_token_ttl_secs: 900,
        refresh_token_absolute_ttl_secs: 2592000,
        refresh_token_idle_ttl_secs: 604800,
        bind_session_ttl_secs: 600,
        revoke_requires_password: true,
        allowed_redirect_uris: Arc::new(HashSet::new()),
    };
    state.mcp = Some(Arc::new(
        McpState::new(config, &auth, state.store.clone()).await,
    ));
    state
}

async fn build_private_test_state() -> AppState {
    let mut state = build_test_state().await;
    state.private_channel_enabled = true;
    state
}

async fn build_diagnostics_test_state() -> AppState {
    let mut state = build_test_state().await;
    state.diagnostics_api_enabled = true;
    state
}

async fn post_json(app: axum::Router, path: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    (status, value)
}

async fn post_json_with_auth(
    app: axum::Router,
    path: &str,
    payload: Value,
    bearer: &str,
) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    (status, value)
}

async fn post_form(
    app: axum::Router,
    path: &str,
    form: &str,
) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.as_bytes().to_vec()))
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

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, Value) {
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
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    (status, value)
}

fn response_data(body: &Value) -> &Value {
    body.get("data")
        .expect("response should contain data field for success path")
}

fn response_string_field<'a>(body: &'a Value, key: &str) -> &'a str {
    response_data(body)
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("response.data.{key} should be a string"))
}

#[tokio::test]
async fn thing_scoped_event_route_returns_not_found() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/thing/thing-1/event/update")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn thing_scoped_message_route_returns_not_found() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/thing/thing-1/message")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn event_routes_still_match_after_contract_merge() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    for path in ["/event/create", "/event/update", "/event/close"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("router should handle request");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} should be routed"
        );
    }
}

#[tokio::test]
async fn private_profile_route_is_not_available() {
    let state = build_private_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/private/profile")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn gateway_profile_route_reports_private_disabled_when_private_module_off() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/gateway/profile")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    assert_eq!(
        response_data(&value)
            .get("private_channel_enabled")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        response_data(&value).get("transport").is_none(),
        "private disabled profile should not include transport hints"
    );
}

#[tokio::test]
async fn gateway_profile_route_reports_private_transport_when_enabled() {
    let state = build_private_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/gateway/profile")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    assert_eq!(
        response_data(&value)
            .get("private_channel_enabled")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        response_data(&value).get("transport").is_some(),
        "private enabled profile should include transport hints"
    );
}

#[tokio::test]
async fn diagnostics_dispatch_route_returns_empty_entries_by_default() {
    let state = build_diagnostics_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/dispatch")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    assert_eq!(
        response_data(&value)
            .get("count")
            .and_then(Value::as_u64)
            .expect("count should be present"),
        0
    );
    assert_eq!(
        response_data(&value)
            .get("entries")
            .and_then(Value::as_array)
            .expect("entries should be present")
            .len(),
        0
    );
}

#[tokio::test]
async fn diagnostics_dispatch_route_is_locked_when_disabled() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/dispatch")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn channel_device_register_compat_route_is_not_available() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/channel/device")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "platform": "ios",
                        "channel_type": "private"
                    }))
                    .expect("payload should serialize"),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn channel_sync_with_partial_failures_does_not_reconcile_subscriptions() {
    let state = build_test_state().await;
    let store = state.store.clone();
    let app = super::build_router(state, "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android",
            "channel_type": "private"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let provider_token = "android-token-sync-partial-0001";

    let (status, _route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, a_subscribe) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channel_name": "sync-partial-a",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let channel_a = response_string_field(&a_subscribe, "channel_id").to_string();

    let (status, b_subscribe) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channel_name": "sync-partial-b",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let _channel_b = response_string_field(&b_subscribe, "channel_id").to_string();

    let (status, sync_body) = post_json(
        app.clone(),
        "/channel/sync",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channels": [
                {"channel_id": channel_a, "password": "password-1234"},
                {"channel_id": "", "password": "password-1234"}
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_data(&sync_body)
            .get("success")
            .and_then(Value::as_u64)
            .expect("sync success should be u64"),
        1
    );
    assert_eq!(
        response_data(&sync_body)
            .get("failed")
            .and_then(Value::as_u64)
            .expect("sync failed should be u64"),
        1
    );

    let subscribed = store
        .list_subscribed_channels_for_device(provider_token, Platform::ANDROID)
        .await
        .expect("list subscribed channels should succeed");
    assert_eq!(
        subscribed.len(),
        2,
        "partial failure should keep existing subscriptions unchanged"
    );
}

#[tokio::test]
async fn device_channel_upsert_auto_registers_missing_device_key_when_platform_present() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");
    let missing_device_key = "missing-device-key-0001";

    let (status, route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": missing_device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-token-auto-register-0001"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let returned_device_key = response_string_field(&route_body, "device_key").to_string();
    assert!(
        !returned_device_key.is_empty(),
        "channel/device should return an effective device_key"
    );
    assert_ne!(
        returned_device_key, missing_device_key,
        "missing device_key should be replaced with a newly issued one"
    );

    let (status, subscribe_body) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": returned_device_key,
            "channel_name": "auto-register-channel",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_string_field(&subscribe_body, "channel_name"),
        "auto-register-channel"
    );
}

#[tokio::test]
async fn device_channel_upsert_reissues_key_on_platform_mismatch() {
    let state = build_test_state().await;
    let app = super::build_router(state, "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "ios",
            "channel_type": "private"
        }),
    )
    .await;
    let original_device_key = response_string_field(&register_body, "device_key").to_string();

    let (status, route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-token-platform-mismatch-0001"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let next_device_key = response_string_field(&route_body, "device_key");
    assert_ne!(
        next_device_key, original_device_key,
        "platform mismatch should issue a fresh device_key"
    );
    assert_eq!(
        response_data(&route_body)
            .get("issued_new_key")
            .and_then(Value::as_bool),
        Some(true),
        "response should mark new key issuance"
    );
    assert_eq!(
        response_data(&route_body)
            .get("issue_reason")
            .and_then(Value::as_str),
        Some("platform_mismatch"),
        "response should expose platform_mismatch reason"
    );
}

#[tokio::test]
async fn channel_sync_with_all_success_reconciles_extra_subscriptions() {
    let state = build_test_state().await;
    let store = state.store.clone();
    let app = super::build_router(state, "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android",
            "channel_type": "private"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let provider_token = "android-token-sync-full-0001";

    let (status, _route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, a_subscribe) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channel_name": "sync-full-a",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let channel_a = response_string_field(&a_subscribe, "channel_id").to_string();

    let (status, b_subscribe) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channel_name": "sync-full-b",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let channel_b = response_string_field(&b_subscribe, "channel_id").to_string();

    let (status, _c_subscribe) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channel_name": "sync-full-c",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, sync_body) = post_json(
        app.clone(),
        "/channel/sync",
        json!({
            "device_key": response_string_field(&register_body, "device_key"),
            "channels": [
                {"channel_id": channel_a, "password": "password-1234"},
                {"channel_id": channel_b, "password": "password-1234"}
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_data(&sync_body)
            .get("failed")
            .and_then(Value::as_u64)
            .expect("sync failed should be u64"),
        0
    );

    let subscribed = store
        .list_subscribed_channels_for_device(provider_token, Platform::ANDROID)
        .await
        .expect("list subscribed channels should succeed");
    assert_eq!(
        subscribed.len(),
        2,
        "full success sync should reconcile and drop extra subscriptions"
    );
}

#[tokio::test]
async fn mcp_legacy_send_requires_password() {
    let state = build_mcp_test_state(
        AuthMode::SharedToken(Arc::from("legacy-shared-token")),
        McpAuthMode::LegacyOnly,
        false,
        None,
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");

    let (status, body) = post_json_with_auth(
        app,
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
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";

    let authorize_form = format!(
        "client_id=test-client&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools%20mcp:channels:manage&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _body) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = location
        .split('?')
        .nth(1)
        .and_then(|query| {
            query
                .split('&')
                .find(|pair| pair.starts_with("code="))
                .and_then(|pair| pair.split_once('=').map(|(_, v)| v.to_string()))
        })
        .expect("code should exist in redirect");

    let token_form = format!(
        "grant_type=authorization_code&client_id=test-client&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
    );
    let (token_status, _token_headers, token_body_raw) =
        post_form(app.clone(), "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    let access_token = token_body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token should exist");

    let (status, body) = post_json_with_auth(
        app,
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
        access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "mcp oauth send should succeed: {body}"
    );
    assert_eq!(
        body.get("result")
            .and_then(|v| v.get("auth_mode"))
            .and_then(Value::as_str),
        Some("oauth2")
    );
}

#[tokio::test]
async fn mcp_refresh_token_cannot_escalate_scope() {
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let authorize_form = format!(
        "client_id=test-client&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = location
        .split('?')
        .nth(1)
        .and_then(|query| {
            query
                .split('&')
                .find(|pair| pair.starts_with("code="))
                .and_then(|pair| pair.split_once('=').map(|(_, v)| v.to_string()))
        })
        .expect("code should exist in redirect");
    let token_form = format!(
        "grant_type=authorization_code&client_id=test-client&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
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
        "grant_type=refresh_token&client_id=test-client&refresh_token={refresh_token}&scope=mcp:tools%20mcp:channels:manage"
    );
    let (status, _, body) = post_form(app, "/oauth/token", refresh_form.as_str()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(String::from_utf8(body).expect("text body"), "invalid scope");
}

#[tokio::test]
async fn mcp_send_requires_mcp_tools_scope() {
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let authorize_form = format!(
        "client_id=test-client&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:channels:manage&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = location
        .split('?')
        .nth(1)
        .and_then(|query| {
            query
                .split('&')
                .find(|pair| pair.starts_with("code="))
                .and_then(|pair| pair.split_once('=').map(|(_, v)| v.to_string()))
        })
        .expect("code should exist in redirect");
    let token_form = format!(
        "grant_type=authorization_code&client_id=test-client&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
    );
    let (token_status, _, token_body_raw) =
        post_form(app.clone(), "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    let access_token = token_body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token should exist");
    let (status, body) = post_json_with_auth(
        app,
        "/mcp",
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
        access_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str),
        Some("auth_forbidden_scope")
    );
}

#[tokio::test]
async fn mcp_bind_session_is_one_time() {
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let authorize_form = format!(
        "client_id=test-client&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools%20mcp:channels:manage&channel_bindings={channel_id},password-1234"
    );
    let (authorize_status, authorize_headers, _) =
        post_form(app.clone(), "/oauth/authorize", authorize_form.as_str()).await;
    assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    let location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize should redirect with code");
    let code = location
        .split('?')
        .nth(1)
        .and_then(|query| {
            query
                .split('&')
                .find(|pair| pair.starts_with("code="))
                .and_then(|pair| pair.split_once('=').map(|(_, v)| v.to_string()))
        })
        .expect("code should exist in redirect");
    let token_form = format!(
        "grant_type=authorization_code&client_id=test-client&code={code}&redirect_uri={redirect_uri}&code_verifier={code_verifier}"
    );
    let (token_status, _, token_body_raw) =
        post_form(app.clone(), "/oauth/token", token_form.as_str()).await;
    assert_eq!(token_status, StatusCode::OK);
    let token_body: Value =
        serde_json::from_slice(&token_body_raw).expect("token response should be json");
    let access_token = token_body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token should exist");
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
        access_token,
    )
    .await;
    assert_eq!(start_status, StatusCode::OK);
    let bind_session_id = start_body
        .get("result")
        .and_then(|v| v.get("bind_session_id"))
        .and_then(Value::as_str)
        .expect("bind_session_id should exist");
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
async fn mcp_grant_password_not_persisted_in_snapshot() {
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
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
    let app = super::build_router(state, "<html>docs</html>");
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = "https://client.example/callback";
    let authorize_form = format!(
        "client_id=test-client&redirect_uri={redirect_uri}&state=abc&code_challenge={code_challenge}&code_challenge_method=S256&scope=mcp:tools&channel_bindings={channel_id},password-1234"
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
    let signing_key = "mcp-test-signing-key";
    let state = build_mcp_test_state(
        AuthMode::Disabled,
        McpAuthMode::OAuth2Only,
        true,
        Some(signing_key),
    )
    .await;
    let app = super::build_router(state, "<html>docs</html>");
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
