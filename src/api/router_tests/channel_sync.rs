use super::*;
use crate::{
    private::protocol::PrivatePayloadEnvelope,
    routing::derive_private_device_id,
    storage::{OUTBOX_STATUS_PENDING, Platform, PrivateMessage, PrivateOutboxEntry},
};

fn make_provider_payload(delivery_id: &str, title: &str) -> Vec<u8> {
    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id".to_string(), delivery_id.to_string());
    data.insert("title".to_string(), title.to_string());
    postcard::to_allocvec(&PrivatePayloadEnvelope {
        payload_version: PrivatePayloadEnvelope::CURRENT_VERSION,
        data,
    })
    .expect("provider payload should encode")
}

async fn seed_private_pending_delivery(
    state: &AppState,
    device_key: &str,
    delivery_id: &str,
    title: &str,
) {
    let now = chrono::Utc::now().timestamp();
    let payload = make_provider_payload(delivery_id, title);
    let message = PrivateMessage {
        payload: payload.clone(),
        size: payload.len(),
        sent_at: now,
        expires_at: now + 300,
    };
    state
        .store
        .insert_private_message(delivery_id, &message)
        .await
        .expect("seed private message should succeed");
    state
        .store
        .enqueue_private_outbox(
            derive_private_device_id(device_key),
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now,
            },
        )
        .await
        .expect("seed private outbox should succeed");
}

async fn seed_provider_pending_delivery(
    state: &AppState,
    device_key: &str,
    delivery_id: &str,
    title: &str,
    provider_token: &str,
) {
    let now = chrono::Utc::now().timestamp();
    let payload = make_provider_payload(delivery_id, title);
    let message = PrivateMessage {
        payload: payload.clone(),
        size: payload.len(),
        sent_at: now,
        expires_at: now + 300,
    };
    state
        .store
        .enqueue_provider_pull_item(
            derive_private_device_id(device_key),
            delivery_id,
            &message,
            Platform::ANDROID,
            provider_token,
        )
        .await
        .expect("seed provider queue should succeed");
}

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

#[tokio::test]
async fn route_switch_private_to_provider_migrates_pending_deliveries() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let provider_token = "android-token-route-switch-0001";

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
    let delivery_a = "delivery-route-switch-private-provider-001";
    let delivery_b = "delivery-route-switch-private-provider-002";
    seed_private_pending_delivery(&state, &device_key, delivery_a, "title-a").await;
    seed_private_pending_delivery(&state, &device_key, delivery_b, "title-b").await;

    let (status, _route_body) = post_json(
        app,
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

    let device_id = derive_private_device_id(&device_key);
    let pending_after_switch = state
        .store
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private outbox count should succeed");
    assert_eq!(
        pending_after_switch, 0,
        "private state should be cleared after private -> provider switch"
    );

    let mut migrated = state
        .store
        .pull_provider_items(device_id, chrono::Utc::now().timestamp(), 10)
        .await
        .expect("provider queue pull should succeed");
    migrated.sort_by(|left, right| left.delivery_id.cmp(&right.delivery_id));
    assert_eq!(migrated.len(), 2);
    assert_eq!(migrated[0].delivery_id, delivery_a);
    assert_eq!(migrated[1].delivery_id, delivery_b);
    assert!(
        migrated
            .iter()
            .all(|item| item.provider_token == provider_token && item.platform == Platform::ANDROID),
        "migrated rows should keep provider target information"
    );
}

#[tokio::test]
async fn route_switch_provider_to_private_migrates_pending_deliveries() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let provider_token = "android-token-route-switch-0002";

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let delivery_a = "delivery-route-switch-provider-private-001";
    let delivery_b = "delivery-route-switch-provider-private-002";
    seed_provider_pending_delivery(&state, &device_key, delivery_a, "title-a", provider_token)
        .await;
    seed_provider_pending_delivery(&state, &device_key, delivery_b, "title-b", provider_token)
        .await;

    let (status, _route_body) = post_json(
        app,
        "/device/register",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "private"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let device_id = derive_private_device_id(&device_key);
    let provider_after_switch = state
        .store
        .pull_provider_items(device_id, chrono::Utc::now().timestamp(), 10)
        .await
        .expect("provider queue pull should succeed");
    assert!(
        provider_after_switch.is_empty(),
        "provider queue should be drained after provider -> private switch"
    );

    let pending_private = state
        .store
        .list_private_outbox(device_id, 10)
        .await
        .expect("private outbox list should succeed");
    assert_eq!(pending_private.len(), 2);
    let mut ids = pending_private
        .into_iter()
        .map(|entry| entry.delivery_id)
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, vec![delivery_a.to_string(), delivery_b.to_string()]);
    assert!(
        state
            .store
            .load_private_message(delivery_a)
            .await
            .expect("private message load should succeed")
            .is_some(),
        "migrated private message should be materialized"
    );
    assert!(
        state
            .store
            .load_private_message(delivery_b)
            .await
            .expect("private message load should succeed")
            .is_some(),
        "migrated private message should be materialized"
    );
}
