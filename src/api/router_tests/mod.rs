use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
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
    dispatch::{
        DeliveryAuditCollector, DeliveryAuditMode, DispatchChannels,
        audit::{DEFAULT_DISPATCH_AUDIT_CAPACITY, DispatchAuditLog, DispatchAuditMode},
    },
    mcp::{McpConfig, McpState},
    routing::DeviceRegistry,
    stats::StatsCollector,
    storage::{Platform, Storage},
};

mod channel_sync;
mod mcp;
mod routes;

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
    let (dispatch, _receivers) = DispatchChannels::new();
    AppState {
        dispatch,
        dispatch_audit: Arc::new(DispatchAuditLog::new(
            DEFAULT_DISPATCH_AUDIT_CAPACITY,
            DispatchAuditMode::Disabled,
        )),
        delivery_audit: DeliveryAuditCollector::spawn(
            DeliveryAuditMode::Disabled,
            store.clone(),
            Arc::new(DispatchAuditLog::new(
                DEFAULT_DISPATCH_AUDIT_CAPACITY,
                DispatchAuditMode::Disabled,
            )),
        ),
        auth: AuthMode::Disabled,
        private_channel_enabled: false,
        diagnostics_api_enabled: false,
        public_base_url: Some(Arc::from("https://sandbox.pushgo.dev")),
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

async fn build_mcp_test_state(auth: AuthMode) -> AppState {
    let mut state = build_test_state().await;
    state.auth = auth.clone();
    let config = McpConfig {
        bootstrap_http_addr: Arc::from("127.0.0.1:6666"),
        public_base_url: Some(Arc::from("https://sandbox.pushgo.dev")),
        access_token_ttl_secs: 900,
        refresh_token_absolute_ttl_secs: 2592000,
        refresh_token_idle_ttl_secs: 604800,
        bind_session_ttl_secs: 600,
        dcr_enabled: true,
        predefined_clients: Vec::new(),
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
                .header("accept", "application/json, text/event-stream")
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
                .header("accept", "application/json, text/event-stream")
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
