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
    app::{AppState, AuthMode, DeviceOperationGuards},
    dispatch::{DispatchChannels, DispatchWorkerReceivers},
    mcp::{McpConfig, McpState},
    private::{PrivateConfig, PrivateState},
    routing::{DeviceRegistry, DeviceRouteRecord},
    runtime_config::GatewayRuntimeProfile,
    runtime_counters::RuntimeCounterCollector,
    storage::{MaintenanceCleanupConfig, Platform, Storage},
};

mod activity;
mod channel_sync;
mod mcp;
mod provider_ingress;
mod release_smoke;
mod routes;
mod widget_push;

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn build_test_state() -> AppState {
    build_test_state_with_receivers().await.0
}

async fn build_test_state_with_receivers() -> (AppState, DispatchWorkerReceivers) {
    let (state, receivers, _) = build_test_state_with_receivers_and_db_url().await;
    (state, receivers)
}

async fn build_test_state_with_receivers_and_db_url() -> (AppState, DispatchWorkerReceivers, String)
{
    build_test_state_with_private_mode(false).await
}

async fn build_test_state_with_private_mode(
    private_enabled: bool,
) -> (AppState, DispatchWorkerReceivers, String) {
    let private = private_enabled.then(test_private_config);
    build_test_state_with_private_config(private.as_ref(), None).await
}

async fn build_test_state_with_private_config(
    private: Option<&PrivateConfig>,
    ordinary_target_limit: Option<i64>,
) -> (AppState, DispatchWorkerReceivers, String) {
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
    // Router tests use the same Storage-owned ordinary authority as normal
    // startup. Private-enabled cases must choose that mode before initialization.
    let mut ordinary = crate::ordinary::Config {
        public_base_url: "https://sandbox.pushgo.dev".into(),
        ..crate::ordinary::Config::default()
    };
    if let Some(private) = private {
        ordinary.private.enabled = true;
        ordinary.private.max_pending_per_device = private.max_pending_per_device;
        ordinary.private.max_pending = private.global_max_pending;
        ordinary.default_ttl_secs = private.default_ttl_secs;
    }
    if let Some(limit) = ordinary_target_limit {
        ordinary.max_targets = limit;
    }
    store
        .initialize_ordinary(ordinary, Arc::default())
        .await
        .expect("product ordinary authority should initialize");
    let (dispatch, receivers) = DispatchChannels::new();
    let runtime_counters = RuntimeCounterCollector::spawn(store.clone());
    (
        AppState {
            dispatch,
            auth: AuthMode::Disabled,
            private_channel_enabled: false,
            public_base_url: Some(Arc::from("https://sandbox.pushgo.dev")),
            device_registry: Arc::new(DeviceRegistry::new()),
            device_operation_guards: Arc::new(DeviceOperationGuards::default()),
            runtime_counters,
            private_transport_profile: crate::app::PrivateTransportProfile {
                quic_enabled: true,
                quic_port: Some(443),
                tcp_enabled: true,
                tcp_port: 5223,
                wss_enabled: true,
                wss_port: 6666,
                wss_path: Arc::from("/private/ws"),
                ws_subprotocol: Arc::from("pushgo-private.v1"),
                mqtt_enabled: false,
                mqtt_port: None,
                mqtt_tls_required: false,
            },
            private: None,
            store,
            mcp: None,
        },
        receivers,
        db_url,
    )
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

async fn seed_provider_channel_for_router_test(
    state: &AppState,
    device_key: &str,
    alias: &str,
    password: &str,
    token: &str,
    platform: Platform,
) -> String {
    let route = DeviceRouteRecord {
        platform,
        channel_type: crate::routing::DeviceChannelType::parse(platform.channel_type())
            .expect("provider platform should map to provider channel type"),
        provider_token: Some(token.to_string()),
        updated_at: chrono::Utc::now().timestamp(),
    };
    state
        .device_registry
        .restore_route(device_key, route.clone())
        .expect("provider route restore should succeed");
    state
        .store
        .upsert_device_route(&crate::storage::DeviceRouteRecordRow::from_registry_record(
            device_key, &route,
        ))
        .await
        .expect("provider route should persist");
    crate::api::format_channel_id(
        &state
            .store
            .subscribe_channel_for_device_key(
                None,
                Some(alias),
                password,
                device_key,
                token,
                platform,
            )
            .await
            .expect("provider channel seed should succeed")
            .channel_id,
    )
}

async fn build_private_test_state() -> AppState {
    build_private_test_state_with_limits(test_private_config(), None)
        .await
        .0
}

async fn build_private_test_state_with_limits(
    private_config: PrivateConfig,
    ordinary_target_limit: Option<i64>,
) -> (AppState, String) {
    let (mut state, _receivers, db_url) =
        build_test_state_with_private_config(Some(&private_config), ordinary_target_limit).await;
    let registry = Arc::clone(&state.device_registry);
    let runtime_counters = Arc::clone(&state.runtime_counters);
    let private = Arc::new(PrivateState::new(
        state.store.clone(),
        private_config,
        registry,
        runtime_counters,
    ));
    state.private_channel_enabled = true;
    state.private = Some(private);
    (state, db_url)
}

async fn build_private_without_wss_test_state() -> AppState {
    let mut state = build_private_test_state().await;
    state.private_transport_profile.wss_enabled = false;
    state
}

fn test_private_config() -> PrivateConfig {
    PrivateConfig {
        runtime_profile: GatewayRuntimeProfile::Small,
        private_quic_bind: None,
        private_tcp_bind: None,
        mqtt: None,
        tcp_tls_enabled: false,
        tcp_proxy_protocol: false,
        private_tls_cert_path: None,
        private_tls_key_path: None,
        session_ttl_secs: 60,
        grace_window_secs: 10,
        max_pending_per_device: 16,
        global_max_pending: 64,
        pull_limit: 32,
        ack_timeout_secs: 5,
        fallback_max_attempts: 3,
        fallback_max_backoff_secs: 60,
        retransmit_window_secs: 30,
        retransmit_max_per_window: 10,
        retransmit_max_per_tick: 16,
        retransmit_max_retries: 3,
        hot_cache_capacity: 64,
        default_ttl_secs: 60,
        online_fast_path_enabled: true,
        maintenance_cleanup: MaintenanceCleanupConfig::default(),
        gateway_token: None,
    }
    .normalized()
}

async fn post_json(app: axum::Router, path: &str, payload: Value) -> (StatusCode, Value) {
    post_json_with_accept_language(app, path, payload, None).await
}

fn parse_mcp_reply(
    content_type: &str,
    body: &[u8],
    request_id: &Value,
) -> Result<(Value, Vec<Value>), String> {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    let messages: Vec<Value> = if media_type.eq_ignore_ascii_case("application/json") {
        vec![serde_json::from_slice(body).map_err(|err| err.to_string())?]
    } else if media_type.eq_ignore_ascii_case("text/event-stream") {
        let text = std::str::from_utf8(body).map_err(|err| err.to_string())?;
        let normalized = text.replace("\r\n", "\n");
        let mut messages = Vec::new();
        for event in normalized.split("\n\n") {
            let data: Vec<_> = event
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("data:")
                        .map(|value| value.strip_prefix(' ').unwrap_or(value))
                })
                .collect();
            if !data.is_empty() {
                messages.push(
                    serde_json::from_str(&data.join("\n"))
                        .map_err(|err| format!("invalid MCP SSE data: {err}"))?,
                );
            }
        }
        messages
    } else {
        return Err(format!("unsupported MCP content type: {content_type}"));
    };

    let mut response = None;
    let mut notifications = Vec::new();
    for message in messages {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err("invalid MCP JSON-RPC message".into());
        }
        if let Some(id) = message.get("id") {
            if id != request_id {
                return Err(format!("unexpected MCP response id: {id}"));
            }
            if message.get("result").is_some() == message.get("error").is_some()
                || message.get("method").is_some()
            {
                return Err("invalid MCP response shape".into());
            }
            if response.replace(message).is_some() {
                return Err("duplicate MCP response id".into());
            }
        } else if message.get("method").and_then(Value::as_str).is_some()
            && message.get("result").is_none()
            && message.get("error").is_none()
        {
            notifications.push(message);
        } else {
            return Err("MCP response is missing its id".into());
        }
    }
    response
        .map(|response| (response, notifications))
        .ok_or_else(|| "missing MCP response for request id".into())
}

async fn post_json_with_accept_language(
    app: axum::Router,
    path: &str,
    payload: Value,
    accept_language: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("host", "localhost");
    if path == "/mcp" {
        builder = builder.header("mcp-protocol-version", "2025-11-25");
    }
    if let Some(accept_language) = accept_language {
        builder = builder.header("accept-language", accept_language);
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
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = if path == "/mcp" && status == StatusCode::OK {
        parse_mcp_reply(
            &content_type,
            &body,
            payload.get("id").expect("MCP request should have an id"),
        )
        .expect("MCP response should match the request")
        .0
    } else {
        serde_json::from_slice::<Value>(&body).expect("response should be valid JSON")
    };
    (status, value)
}

async fn post_json_with_auth(
    app: axum::Router,
    path: &str,
    payload: Value,
    bearer: &str,
) -> (StatusCode, Value) {
    let (status, value, _) = post_json_with_auth_events(app, path, payload, bearer).await;
    (status, value)
}

async fn post_json_with_auth_events(
    app: axum::Router,
    path: &str,
    payload: Value,
    bearer: &str,
) -> (StatusCode, Value, Vec<Value>) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("host", "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("mcp-protocol-version", "2025-11-25")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    if path == "/mcp" && status == StatusCode::OK {
        let (value, notifications) = parse_mcp_reply(
            &content_type,
            &body,
            payload.get("id").expect("MCP request should have an id"),
        )
        .unwrap_or_else(|err| {
            panic!(
                "MCP response should match request: {err} | body={}",
                String::from_utf8_lossy(&body)
            )
        });
        return (status, value, notifications);
    }
    let value = serde_json::from_slice::<Value>(&body).unwrap_or_else(|err| {
        panic!(
            "response should be valid JSON (status={}): {} | body={}",
            status,
            err,
            String::from_utf8_lossy(&body)
        )
    });
    (status, value, Vec::new())
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
                .header("host", "localhost")
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
                .header("host", "localhost")
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
