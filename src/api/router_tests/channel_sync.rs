use super::*;

#[tokio::test]
async fn channel_sync_with_partial_failures_does_not_reconcile_subscriptions() {
    let state = build_test_state().await;
    let store = state.store.clone();
    let app = super::super::build_router(state, "<html>docs</html>");

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

    let (status, _b_subscribe) = post_json(
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
    let app = super::super::build_router(state, "<html>docs</html>");
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
    let app = super::super::build_router(state, "<html>docs</html>");

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
    let app = super::super::build_router(state, "<html>docs</html>");

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
