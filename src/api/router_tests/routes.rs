use super::*;
use crate::{
    routing::{DeviceChannelType, derive_private_device_id},
    storage::DeviceRouteRecordRow,
};

#[tokio::test]
async fn thing_scoped_event_route_returns_not_found() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
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
    assert!(
        response.headers().get("x-request-id").is_some(),
        "404 responses should carry request ids"
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice::<Value>(&body).expect("response should be valid JSON");
    assert_eq!(
        value.get("error_code").and_then(Value::as_str),
        Some("route_not_found")
    );
}

#[tokio::test]
async fn thing_scoped_message_route_returns_not_found() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
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
async fn mqtt_private_device_outbox_only_receives_channel_messages() {
    let state = build_private_test_state().await;
    let device_key = "mqtt-router-outbox-device";
    let password = "mqtt-router-password";
    let route = DeviceRouteRecord {
        platform: Platform::MQTT,
        channel_type: DeviceChannelType::Private,
        provider_token: None,
        updated_at: chrono::Utc::now().timestamp(),
    };
    state
        .device_registry
        .restore_route(device_key, route.clone())
        .expect("mqtt route restore should succeed");
    state
        .store
        .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
            device_key, &route,
        ))
        .await
        .expect("mqtt route should persist");
    let outcome = state
        .store
        .upsert_private_channel(None, Some("mqtt-router-outbox"), password)
        .await
        .expect("channel should be created");
    let channel_id = crate::api::format_channel_id(&outcome.channel_id);
    let device_id = derive_private_device_id(device_key);
    state
        .store
        .private_subscribe_channel(outcome.channel_id, device_id)
        .await
        .expect("mqtt private subscription should persist");

    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (status, _) = post_json(
        app.clone(),
        "/message",
        json!({
            "channel_id": channel_id,
            "password": password,
            "title": "channel message"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        state
            .store
            .list_private_outbox(device_id, 16)
            .await
            .expect("outbox should list")
            .len(),
        1
    );

    for (path, payload) in [
        (
            "/message",
            json!({
                "channel_id": channel_id,
                "password": password,
                "thing_id": "thing-1",
                "occurred_at": 1_700_000_000_000i64,
                "title": "thing scoped message"
            }),
        ),
        (
            "/event/create",
            json!({
                "channel_id": channel_id,
                "password": password,
                "title": "event",
                "status": "open",
                "message": "event body",
                "severity": "normal",
                "event_time": 1_700_000_000_001i64
            }),
        ),
        (
            "/event/create",
            json!({
                "channel_id": channel_id,
                "password": password,
                "thing_id": "thing-1",
                "title": "thing scoped event",
                "status": "open",
                "message": "thing scoped event body",
                "severity": "normal",
                "event_time": 1_700_000_000_002i64
            }),
        ),
        (
            "/thing/create",
            json!({
                "channel_id": channel_id,
                "password": password,
                "title": "thing",
                "observed_at": 1_700_000_000_003i64
            }),
        ),
    ] {
        let (status, body) = post_json(app.clone(), path, payload).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} should be accepted: {body:?}"
        );
    }

    let outbox = state
        .store
        .list_private_outbox(device_id, 16)
        .await
        .expect("outbox should list after non-message dispatches");
    assert_eq!(
        outbox.len(),
        1,
        "mqtt outbox should only contain channel-level message deliveries"
    );
}

#[tokio::test]
async fn event_routes_still_match_after_contract_merge() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
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
    let app = super::super::build_router(state, "<html>docs</html>");
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
async fn private_ws_route_is_not_mounted_when_wss_transport_disabled() {
    let state = build_private_without_wss_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/private/ws")
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
    let app = super::super::build_router(state, "<html>docs</html>");
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
    let app = super::super::build_router(state, "<html>docs</html>");
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
    assert_eq!(
        response_data(&value)
            .get("transport")
            .and_then(|v| v.get("wss_url"))
            .and_then(Value::as_str),
        Some("wss://sandbox.pushgo.dev/private/ws")
    );
}

#[tokio::test]
async fn diagnostics_private_metrics_route_is_locked_when_disabled() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/private/metrics")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn diagnostics_private_memory_route_is_locked_when_disabled() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/private/memory")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn diagnostics_private_metrics_route_is_available_when_enabled() {
    let state = build_diagnostics_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/private/metrics")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn diagnostics_private_memory_route_is_available_when_enabled() {
    let state = build_diagnostics_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/diagnostics/private/memory")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn channel_device_route_requires_device_key() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn channel_subscribe_returns_structured_problem_with_zh_locale() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json_with_accept_language(
        app,
        "/channel/subscribe",
        json!({
            "device_key": "missing-device-key-001",
            "channel_name": "demo-channel",
            "password": "password-1234"
        }),
        Some("zh-CN, en;q=0.8"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error_code").and_then(Value::as_str),
        Some("device_key_not_found")
    );
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("category"))
            .and_then(Value::as_str),
        Some("not_found")
    );
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("localized_message"))
            .and_then(Value::as_str),
        Some("当前设备注册已失效，请重试。")
    );
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("locale"))
            .and_then(Value::as_str),
        Some("zh-CN")
    );
}

#[tokio::test]
async fn channel_subscribe_accepts_apple_style_zh_hans_locale() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json_with_accept_language(
        app,
        "/channel/subscribe",
        json!({
            "device_key": "missing-device-key-001",
            "channel_name": "demo-channel",
            "password": "password-1234"
        }),
        Some("zh-Hans-CN, en-US;q=0.8"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("localized_message"))
            .and_then(Value::as_str),
        Some("当前设备注册已失效，请重试。")
    );
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("locale"))
            .and_then(Value::as_str),
        Some("zh-CN")
    );
}

#[tokio::test]
async fn channel_subscribe_rejects_33rd_subscriber_with_structured_limit_error() {
    let state = build_private_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let mut channel_id = String::new();
    let mut first_device_key = String::new();

    for index in 0..32 {
        let (_status, register_body) = post_json(
            app.clone(),
            "/device/register",
            json!({
                "platform": "android"
            }),
        )
        .await;
        let device_key = response_string_field(&register_body, "device_key").to_string();
        if index == 0 {
            first_device_key = device_key.clone();
        }

        let payload = if index == 0 {
            json!({
                "device_key": device_key,
                "channel_name": "subscriber-limit",
                "password": "password-1234"
            })
        } else {
            json!({
                "device_key": device_key,
                "channel_id": channel_id,
                "password": "password-1234"
            })
        };
        let (status, body) = post_json(app.clone(), "/channel/subscribe", payload).await;
        assert_eq!(status, StatusCode::OK);
        if index == 0 {
            channel_id = response_string_field(&body, "channel_id").to_string();
        }
    }

    let (status, _resubscribe_body) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": first_device_key,
            "channel_id": channel_id,
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let extra_device_key = response_string_field(&register_body, "device_key").to_string();
    let (status, body) = post_json_with_accept_language(
        app,
        "/channel/subscribe",
        json!({
            "device_key": extra_device_key,
            "channel_id": channel_id,
            "password": "password-1234"
        }),
        Some("zh-CN, en;q=0.8"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error_code").and_then(Value::as_str),
        Some("channel_subscriber_limit_exceeded")
    );
    assert_eq!(
        body.get("problem")
            .and_then(|value| value.get("localized_message"))
            .and_then(Value::as_str),
        Some("该频道已达到 32 个订阅者上限，请先移除不再使用的设备。")
    );
}
