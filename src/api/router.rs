use crate::{
    api::handlers::{
        channel::{channel_exists, channel_rename},
        diagnostics::diagnostics_dispatch,
        event::{event_close_to_channel, event_create_to_channel, event_update_to_channel},
        message::message_to_channel,
        private::{
            gateway_profile, private_health, private_metrics, private_network_diagnostics,
            private_ws,
        },
        thing::{
            thing_archive_to_channel, thing_create_to_channel, thing_delete_to_channel,
            thing_update_to_channel,
        },
        v1::{
            v1_channel_subscribe, v1_channel_sync, v1_channel_unsubscribe,
            v1_device_channel_delete, v1_device_channel_upsert, v1_messages_pull,
        },
    },
    api::{Error, HttpResult},
    app::{AppState, AuthMode},
    util::constant_time_eq,
};
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::{
    Router,
    extract::{Request, State},
    middleware::{Next, from_fn_with_state},
    response::{Html, IntoResponse},
    routing::{get, post},
};

pub fn build_router(state: AppState, docs_html: &'static str) -> Router {
    let docs = docs_html;
    let private_channel_enabled = state.private_channel_enabled;
    let mut router = Router::new()
        .route("/", get(move || async move { Html(docs) }))
        .route("/message", post(message_to_channel))
        .route("/event/create", post(event_create_to_channel))
        .route("/event/update", post(event_update_to_channel))
        .route("/event/close", post(event_close_to_channel))
        .route("/thing/create", post(thing_create_to_channel))
        .route("/thing/update", post(thing_update_to_channel))
        .route("/thing/archive", post(thing_archive_to_channel))
        .route("/thing/delete", post(thing_delete_to_channel))
        .route("/device/register", post(v1_device_channel_upsert))
        .route("/channel/device/delete", post(v1_device_channel_delete))
        .route("/channel/sync", post(v1_channel_sync))
        .route("/channel/subscribe", post(v1_channel_subscribe))
        .route("/channel/unsubscribe", post(v1_channel_unsubscribe))
        .route("/messages/pull", post(v1_messages_pull))
        .route("/gateway/profile", get(gateway_profile))
        .route("/channel/exists", get(channel_exists))
        .route("/channel/rename", post(channel_rename));

    if state.diagnostics_api_enabled {
        router = router
            .route("/diagnostics/dispatch", get(diagnostics_dispatch))
            .route("/diagnostics/private/metrics", get(private_metrics))
            .route("/diagnostics/private/health", get(private_health))
            .route(
                "/diagnostics/private/network",
                get(private_network_diagnostics),
            );
    }

    if private_channel_enabled {
        router = router.route("/private/ws", get(private_ws));
    }

    router
        .layer(from_fn_with_state(state.clone(), middleware))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state)
        .fallback(async || (StatusCode::NOT_FOUND, "404 Not Found").into_response())
}

fn extract_bearer_token(req: &Request) -> Result<&str, Error> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Error::Unauthorized)?;

    let raw = header.to_str().map_err(|_| Error::Unauthorized)?;
    let mut it = raw.split_whitespace();

    let scheme = it.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Error::Unauthorized);
    }

    let token = it.next().ok_or(Error::Unauthorized)?;

    // Reject extra segments after the token.
    if it.next().is_some() {
        return Err(Error::Unauthorized);
    }

    // Reject empty or obviously malformed tokens.
    const MAX_TOKEN_LEN: usize = 4096;
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(Error::Unauthorized);
    }

    Ok(token)
}

async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> HttpResult {
    fn constant_time_equals(a: &str, b: &str) -> bool {
        constant_time_eq(a.as_bytes(), b.as_bytes())
    }
    if let AuthMode::SharedToken(token) = &state.auth {
        match extract_bearer_token(&req) {
            Ok(req_token) => {
                if !constant_time_equals(req_token, token) {
                    return Ok(Error::Unauthorized.into_response());
                }
            }
            Err(err) => {
                return Ok(err.into_response());
            }
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::{
        app::{AppState, AuthMode},
        delivery_audit::DeliveryAuditCollector,
        device_registry::DeviceRegistry,
        dispatch::{
            audit::{DEFAULT_DISPATCH_AUDIT_CAPACITY, DispatchAuditLog},
            create_dispatch_channels,
        },
        stats::StatsCollector,
        storage::{Platform, Store, new_store},
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
        let store: Store = new_store(Some(db_url.as_str()))
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
                Arc::clone(&store),
                Arc::new(DispatchAuditLog::new(
                    DEFAULT_DISPATCH_AUDIT_CAPACITY,
                    false,
                )),
            ),
            auth: AuthMode::Disabled,
            private_channel_enabled: false,
            diagnostics_api_enabled: false,
            device_registry: Arc::new(DeviceRegistry::new()),
            stats: StatsCollector::spawn(Arc::clone(&store)),
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
        }
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
            .list_subscribed_channels_for_device_async(provider_token, Platform::ANDROID)
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
            .list_subscribed_channels_for_device_async(provider_token, Platform::ANDROID)
            .await
            .expect("list subscribed channels should succeed");
        assert_eq!(
            subscribed.len(),
            2,
            "full success sync should reconcile and drop extra subscriptions"
        );
    }
}
