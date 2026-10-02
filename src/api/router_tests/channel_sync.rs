use super::*;
use crate::{
    private::protocol::PrivatePayloadEnvelope,
    routing::derive_private_device_id,
    storage::{
        DeviceRouteRecordRow, OUTBOX_STATUS_PENDING, Platform, PrivateMessage, PrivateOutboxEntry,
        RouteChannelType,
    },
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
    let now = chrono::Utc::now().timestamp_millis();
    let payload = make_provider_payload(delivery_id, title);
    let message = PrivateMessage {
        payload: payload.clone().into(),
        size: payload.len(),
        sent_at: now,
        expires_at: now + 300_000,
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
                claimed_by: None,
                claim_generation: 0,
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
    let now = chrono::Utc::now().timestamp_millis();
    let payload = make_provider_payload(delivery_id, title);
    let message = PrivateMessage {
        payload: payload.clone().into(),
        size: payload.len(),
        sent_at: now,
        expires_at: now + 300_000,
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
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let provider_token = "android-token-sync-partial-0001";

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
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
        .list_subscribed_channels_for_device_key(&device_key)
        .await
        .expect("list subscribed channels should succeed");
    assert_eq!(
        subscribed.len(),
        2,
        "partial failure should keep existing subscriptions unchanged"
    );
}

#[tokio::test]
async fn device_register_issues_new_key_for_missing_device_key() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let missing_device_key = "missing-device-key-0001";

    let (status, route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": missing_device_key,
            "platform": "android"
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

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": returned_device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-token-auto-register-0001"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

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
async fn device_register_reissues_key_on_platform_mismatch() {
    let state = build_test_state().await;
    let store = state.store.clone();
    let app = super::super::build_router(state, "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let original_device_key = response_string_field(&register_body, "device_key").to_string();

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": original_device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-platform-mismatch-old-token-0001"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _subscribe_body) = post_json(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": original_device_key,
            "channel_name": "platform-mismatch-old-subscription",
            "password": "password-1234"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, route_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "ios"
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

    let routes = store
        .load_device_routes()
        .await
        .expect("routes should load after platform mismatch");
    assert!(
        routes
            .iter()
            .all(|route| route.device_key != original_device_key),
        "old device identity should be revoked immediately after issuing replacement key"
    );
    let old_subscriptions = store
        .list_subscribed_channels_for_device_key(&original_device_key)
        .await
        .expect("old identity subscription list should be queryable");
    assert!(
        old_subscriptions.is_empty(),
        "old device identity should not retain subscriptions after revocation"
    );
}

#[tokio::test]
async fn stale_platform_mismatch_register_reuses_existing_replacement_key() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let original_device_key = response_string_field(&register_body, "device_key").to_string();

    let (status, first_reissue_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "ios"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let replacement_device_key =
        response_string_field(&first_reissue_body, "device_key").to_string();

    let (status, second_reissue_body) = post_json(
        app,
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "ios"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_string_field(&second_reissue_body, "device_key"),
        replacement_device_key,
        "stale platform-mismatch requests should converge on the already issued replacement key"
    );
    assert_eq!(
        response_data(&second_reissue_body)
            .get("issue_reason")
            .and_then(Value::as_str),
        Some("platform_mismatch")
    );
}

#[tokio::test]
async fn concurrent_platform_mismatch_register_converges_on_single_replacement_key() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let original_device_key = response_string_field(&register_body, "device_key").to_string();

    let request_a = post_json(
        app.clone(),
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "ios"
        }),
    );
    let request_b = post_json(
        app,
        "/device/register",
        json!({
            "device_key": original_device_key,
            "platform": "ios"
        }),
    );
    let ((status_a, body_a), (status_b, body_b)) = tokio::join!(request_a, request_b);
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);

    let replacement_a = response_string_field(&body_a, "device_key").to_string();
    let replacement_b = response_string_field(&body_b, "device_key").to_string();
    assert_eq!(
        replacement_a, replacement_b,
        "same stale device_key should not fork into multiple replacement identities under concurrency"
    );

    let routes = state
        .store
        .load_device_routes()
        .await
        .expect("routes should load after concurrent platform mismatch");
    let matching_routes: Vec<_> = routes
        .iter()
        .filter(|route| route.platform == "ios")
        .filter(|route| route.device_key == replacement_a)
        .collect();
    assert_eq!(matching_routes.len(), 1);
    assert!(
        routes
            .iter()
            .all(|route| route.device_key != original_device_key),
        "old device identity should be revoked after concurrent replacement"
    );
}

#[tokio::test]
async fn provider_token_retire_removes_only_old_token_state() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let old_token = "android-provider-token-retire-old-0001";
    let new_token = "android-provider-token-retire-new-0001";

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": old_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    seed_provider_pending_delivery(
        &state,
        &device_key,
        "delivery-provider-token-retire-old",
        "old-title",
        old_token,
    )
    .await;

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": new_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    seed_provider_pending_delivery(
        &state,
        &device_key,
        "delivery-provider-token-retire-new",
        "new-title",
        new_token,
    )
    .await;

    let (status, _retire_body) = post_json(
        app,
        "/channel/device/provider-token/retire",
        json!({
            "platform": "android",
            "provider_token": old_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let routes = state
        .store
        .load_device_routes()
        .await
        .expect("routes should load");
    let route = routes
        .iter()
        .find(|route| route.device_key == device_key)
        .expect("current route should remain present");
    assert_eq!(route.provider_token.as_deref(), Some(new_token));
    assert_eq!(route.channel_type, "fcm");

    let device_id = derive_private_device_id(&device_key);
    let remaining = state
        .store
        .pull_provider_items(device_id, chrono::Utc::now().timestamp_millis(), 10)
        .await
        .expect("provider pull should succeed");
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].delivery_id,
        "delivery-provider-token-retire-new"
    );
    assert_eq!(remaining[0].provider_token, new_token);
}

#[tokio::test]
async fn failed_private_route_delete_preserves_pending_delivery_and_registry() {
    let (state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (status, registered) = post_json(
        app.clone(),
        "/device/register",
        json!({"platform": "android"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_key = response_string_field(&registered, "device_key").to_string();
    let revision = response_data(&registered)["route_revision"]
        .as_i64()
        .expect("route revision");
    let delivery_id = "failed-private-delete-pending";
    seed_private_pending_delivery(&state, &device_key, delivery_id, "queued").await;
    let db = sqlx::SqlitePool::connect(&db_url)
        .await
        .expect("route fault database should connect");
    sqlx::query(
        "CREATE TRIGGER fail_route_delete BEFORE UPDATE ON devices \
         BEGIN SELECT RAISE(ABORT, 'injected route persistence failure'); END",
    )
    .execute(&db)
    .await
    .expect("route fault trigger should install");

    let (status, _) = post_json(
        app.clone(),
        "/channel/device/delete",
        json!({"device_key": device_key, "channel_type": "private"}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        state
            .store
            .load_private_outbox_entry(derive_private_device_id(&device_key), delivery_id)
            .await
            .expect("pending delivery should load")
            .is_some()
    );
    assert_eq!(
        state
            .store
            .current_device_route_revision(&device_key)
            .await
            .expect("route revision after failed delete"),
        Some(revision)
    );
    assert_eq!(
        state
            .device_registry
            .get(&device_key)
            .expect("registry route should remain")
            .channel_type,
        crate::routing::DeviceChannelType::Private
    );

    sqlx::query("DROP TRIGGER fail_route_delete")
        .execute(&db)
        .await
        .expect("route fault trigger should drop");
    let (status, body) = post_json(
        app,
        "/channel/device/delete",
        json!({"device_key": device_key, "channel_type": "private"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "retry delete: {body:?}");
    assert!(
        state
            .store
            .load_private_outbox_entry(derive_private_device_id(&device_key), delivery_id)
            .await
            .expect("deleted private queue should load")
            .is_none()
    );
}

#[tokio::test]
async fn failed_provider_token_retire_preserves_durable_and_memory_owner() {
    let (state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_, registered) = post_json(
        app.clone(),
        "/device/register",
        json!({"platform": "android"}),
    )
    .await;
    let device_key = response_string_field(&registered, "device_key").to_string();
    let provider_token = "retire-failure-provider-token";
    let (status, active) = post_json(
        app.clone(),
        "/channel/device",
        json!({"device_key": device_key, "platform": "android", "channel_type": "fcm", "provider_token": provider_token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provider route: {active:?}");
    let revision = response_data(&active)["route_revision"]
        .as_i64()
        .expect("active route revision");
    let db = sqlx::SqlitePool::connect(&db_url)
        .await
        .expect("retire fault database should connect");
    sqlx::query(
        "CREATE TRIGGER fail_provider_retire BEFORE UPDATE ON devices \
         BEGIN SELECT RAISE(ABORT, 'injected token retirement failure'); END",
    )
    .execute(&db)
    .await
    .expect("retire fault trigger should install");
    let retire_request = json!({"platform": "android", "provider_token": provider_token});
    let (status, _) = post_json(
        app.clone(),
        "/channel/device/provider-token/retire",
        retire_request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        state
            .device_registry
            .resolve_provider_ingress_route(Platform::ANDROID, provider_token)
            .as_deref(),
        Some(device_key.as_str())
    );
    assert_eq!(
        state
            .store
            .active_device_route_snapshot(&device_key)
            .await
            .expect("durable route after failed retire")
            .expect("active provider route should remain")
            .route_revision,
        revision
    );
    sqlx::query("DROP TRIGGER fail_provider_retire")
        .execute(&db)
        .await
        .expect("retire fault trigger should drop");
    let (status, body) =
        post_json(app, "/channel/device/provider-token/retire", retire_request).await;
    assert_eq!(status, StatusCode::OK, "retire retry: {body:?}");
    assert!(
        state
            .device_registry
            .resolve_provider_ingress_route(Platform::ANDROID, provider_token)
            .is_none()
    );
    let route = state
        .store
        .active_device_route_snapshot(&device_key)
        .await
        .expect("retired durable route")
        .expect("device identity should remain");
    assert_eq!(route.route_revision, revision + 1);
    assert_eq!(route.channel_type, "private");
    assert!(route.provider_token.is_none());
}

#[tokio::test]
async fn concurrent_route_upserts_keep_single_current_route() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();

    let request_a = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-concurrent-route-token-a"
        }),
    );
    let request_b = post_json(
        app,
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "android-concurrent-route-token-b"
        }),
    );
    let ((status_a, _body_a), (status_b, _body_b)) = tokio::join!(request_a, request_b);
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);

    let routes = state
        .store
        .load_device_routes()
        .await
        .expect("routes should load after concurrent upserts");
    let route = routes
        .iter()
        .find(|route| route.device_key == device_key)
        .expect("device route should remain present after concurrent upserts");
    assert!(matches!(
        route.provider_token.as_deref(),
        Some("android-concurrent-route-token-a") | Some("android-concurrent-route-token-b")
    ));
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
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let provider_token = "android-token-sync-full-0001";

    let (status, _route_body) = post_json(
        app.clone(),
        "/channel/device",
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
        .list_subscribed_channels_for_device_key(&device_key)
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
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let delivery_a = "delivery-route-switch-private-provider-001";
    let delivery_b = "delivery-route-switch-private-provider-002";
    seed_private_pending_delivery(&state, &device_key, delivery_a, "title-a").await;
    seed_private_pending_delivery(&state, &device_key, delivery_b, "title-b").await;

    let (status, route_body) = post_json(
        app,
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "route response: {route_body:?}");

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
        .pull_provider_items(device_id, chrono::Utc::now().timestamp_millis(), 10)
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
            "platform": "android"
        }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let (status, route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "route response: {route_body:?}");
    let delivery_a = "delivery-route-switch-provider-private-001";
    let delivery_b = "delivery-route-switch-provider-private-002";
    seed_provider_pending_delivery(&state, &device_key, delivery_a, "title-a", provider_token)
        .await;
    seed_provider_pending_delivery(&state, &device_key, delivery_b, "title-b", provider_token)
        .await;

    let (status, _route_body) = post_json(
        app,
        "/channel/device",
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
        .pull_provider_items(device_id, chrono::Utc::now().timestamp_millis(), 10)
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

#[tokio::test]
async fn idempotent_route_upsert_reconciles_a_stale_process_cache() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let provider_token = "android-token-stale-process-cache-0001";

    let (_status, register_body) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    let device_key = response_string_field(&register_body, "device_key").to_string();
    let (status, route_body) = post_json(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "route response: {route_body:?}");

    // Simulate a second Gateway instance committing a route change. This
    // process intentionally retains its old in-memory FCM record.
    state
        .store
        .transition_device_route(
            &DeviceRouteRecordRow {
                device_key: device_key.clone(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at: chrono::Utc::now().timestamp_millis(),
            },
            RouteChannelType::Fcm,
            30,
            16,
        )
        .await
        .expect("external route transition should succeed");
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    let (status, body) = post_json(
        app,
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": provider_token
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reconcile response: {body:?}");

    let persisted = state
        .store
        .load_device_routes()
        .await
        .expect("routes should load")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("route should remain present");
    assert_eq!(persisted.channel_type, Platform::ANDROID.channel_type());
    assert_eq!(persisted.provider_token.as_deref(), Some(provider_token));
}

#[tokio::test]
async fn route_transition_prepare_has_no_active_route_or_queue_side_effects() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_status, register) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    let device_key = response_string_field(&register, "device_key").to_string();
    let revision = response_data(&register)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("register should return route revision");
    seed_private_pending_delivery(&state, &device_key, "prepare-no-effect", "queued").await;

    let (status, prepared) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "prepare-no-effect-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": revision,
            "candidate": {
                "channel_type": "fcm",
                "provider_token": "prepare-no-effect-provider-token"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prepare response: {prepared:?}");
    assert_eq!(
        state
            .device_registry
            .get(&device_key)
            .expect("registry route should remain")
            .channel_type,
        crate::routing::DeviceChannelType::Private
    );
    assert_eq!(
        state
            .store
            .list_private_outbox(derive_private_device_id(&device_key), 10)
            .await
            .expect("private queue should remain")
            .len(),
        1,
        "prepare must not migrate pending work"
    );
    let persisted = state
        .store
        .load_device_routes()
        .await
        .expect("routes should load")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("route should exist");
    assert_eq!(persisted.channel_type, "private");

    let transition_id = response_string_field(&prepared, "transition_id");
    let (status, queried) = post_json(
        app,
        "/v2/channel/device/transition/query",
        json!({ "transition_id": transition_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query response: {queried:?}");
    assert_eq!(response_string_field(&queried, "state"), "prepared");
    assert_eq!(
        response_data(&queried)
            .get("route_revision")
            .and_then(Value::as_i64),
        Some(revision)
    );
    assert_eq!(response_string_field(&queried, "channel_type"), "private");
    assert!(
        response_data(&queried).get("provider_token").is_none(),
        "query must not disclose the candidate token"
    );
}

#[tokio::test]
async fn concurrent_identical_route_transition_prepare_converges_on_one_operation() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (_status, register) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    let device_key = response_string_field(&register, "device_key").to_string();
    let revision = response_data(&register)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("register revision");
    let payload = json!({
        "operation_id": "concurrent-identical-prepare-op",
        "device_key": device_key,
        "platform": "android",
        "expected_route_revision": revision,
        "candidate": {
            "channel_type": "fcm",
            "provider_token": "concurrent-identical-provider-token"
        }
    });
    let (left, right) = tokio::join!(
        post_json(
            app.clone(),
            "/v2/channel/device/transition/prepare",
            payload.clone()
        ),
        post_json(app, "/v2/channel/device/transition/prepare", payload)
    );
    assert_eq!(left.0, StatusCode::OK, "left prepare: {:?}", left.1);
    assert_eq!(right.0, StatusCode::OK, "right prepare: {:?}", right.1);
    assert_eq!(
        response_string_field(&left.1, "transition_id"),
        response_string_field(&right.1, "transition_id"),
        "concurrent exact retries must converge on the unique operation winner"
    );
}

#[tokio::test]
async fn route_transition_commit_migrates_once_and_is_idempotent() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_status, register) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    let device_key = response_string_field(&register, "device_key").to_string();
    let revision = response_data(&register)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("register revision");
    seed_private_pending_delivery(&state, &device_key, "commit-once", "queued").await;
    let (status, prepared) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "commit-once-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": revision,
            "candidate": {"channel_type": "fcm", "provider_token": "commit-once-provider-token"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prepare: {prepared:?}");
    let transition_id = response_string_field(&prepared, "transition_id").to_string();
    let commit_request = json!({
        "transition_id": transition_id,
        "operation_id": "commit-once-op"
    });
    let (status, first) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        commit_request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first commit: {first:?}");
    assert_eq!(response_string_field(&first, "state"), "committed");
    assert_eq!(
        response_data(&first)
            .get("migrated_pending_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        state
            .store
            .list_private_outbox(derive_private_device_id(&device_key), 10)
            .await
            .expect("private outbox should load")
            .len(),
        0
    );
    assert!(
        state
            .store
            .pull_provider_item(
                derive_private_device_id(&device_key),
                "commit-once",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("provider item lookup should succeed")
            .is_some()
    );
    let (status, replayed_prepare) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "commit-once-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": revision,
            "candidate": {"channel_type": "fcm", "provider_token": "commit-once-provider-token"}
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact prepare replay after commit must converge: {replayed_prepare:?}"
    );
    assert_eq!(
        response_string_field(&replayed_prepare, "state"),
        "committed"
    );
    assert_eq!(
        response_string_field(&replayed_prepare, "transition_id"),
        transition_id
    );
    let (status, conflicting_replay) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "commit-once-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": revision,
            "candidate": {"channel_type": "private"}
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same operation with different payload must stay sensitive: {conflicting_replay:?}"
    );
    assert_eq!(
        conflicting_replay.get("error_code").and_then(Value::as_str),
        Some("route_transition_operation_conflict")
    );
    let (status, second) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        commit_request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "repeat commit: {second:?}");
    assert_eq!(response_data(&first), response_data(&second));

    let (status, queried) = post_json(
        app.clone(),
        "/v2/channel/device/transition/query",
        json!({ "transition_id": transition_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "committed query: {queried:?}");
    assert_eq!(response_string_field(&queried, "state"), "committed");
    assert_eq!(response_string_field(&queried, "channel_type"), "fcm");
    assert_eq!(
        response_string_field(&queried, "current_provider_token_sha256"),
        "8e11247bf62c4b61e61d19feecfeb3d15e751a885ca70ba0ee0df55c19ead0b0"
    );
    assert_eq!(
        response_string_field(&queried, "candidate_channel_type"),
        "fcm"
    );
    assert_eq!(
        response_data(&queried)
            .get("committed_revision")
            .and_then(Value::as_i64),
        response_data(&first)
            .get("route_revision")
            .and_then(Value::as_i64)
    );
    assert_eq!(
        response_data(&queried)
            .get("route_revision")
            .and_then(Value::as_i64),
        response_data(&first)
            .get("route_revision")
            .and_then(Value::as_i64)
    );

    let first_committed_revision = response_data(&first)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("first committed revision");
    let (status, superseding_prepare) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "superseding-private-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": first_committed_revision,
            "candidate": {"channel_type": "private"}
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superseding prepare: {superseding_prepare:?}"
    );
    let (status, superseding_commit) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        json!({
            "transition_id": response_string_field(&superseding_prepare, "transition_id"),
            "operation_id": "superseding-private-op"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superseding commit: {superseding_commit:?}"
    );
    let superseding_revision = response_data(&superseding_commit)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("superseding revision");
    assert!(superseding_revision > first_committed_revision);

    // A delayed retry belongs to the old operation. Its receipt is stable,
    // but it must not replace the newer active route in the in-memory registry.
    let (status, replayed) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        commit_request,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superseded replay: {replayed:?}");
    assert_eq!(response_data(&replayed), response_data(&first));
    let active = state
        .device_registry
        .get(&device_key)
        .expect("active route");
    assert_eq!(
        active.channel_type,
        crate::routing::DeviceChannelType::Private
    );
    assert_eq!(active.provider_token, None);

    let (status, superseded_query) = post_json(
        app,
        "/v2/channel/device/transition/query",
        json!({ "transition_id": transition_id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superseded query: {superseded_query:?}"
    );
    assert_eq!(
        response_data(&superseded_query)
            .get("committed_revision")
            .and_then(Value::as_i64),
        Some(first_committed_revision)
    );
    assert_eq!(
        response_string_field(&superseded_query, "candidate_channel_type"),
        "fcm"
    );
    assert_eq!(
        response_data(&superseded_query)
            .get("route_revision")
            .and_then(Value::as_i64),
        Some(superseding_revision)
    );
    assert_eq!(
        response_string_field(&superseded_query, "channel_type"),
        "private"
    );
    assert!(response_data(&superseded_query)["current_provider_token_sha256"].is_null());
}

#[tokio::test]
async fn route_transition_token_takeover_retires_previous_device_in_memory() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_, first) = post_json(
        app.clone(),
        "/device/register",
        json!({"platform": "android"}),
    )
    .await;
    let old_key = response_string_field(&first, "device_key").to_string();
    let token = "route-transition-token-takeover";
    let (status, original_prepare) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({"operation_id": "original-op", "device_key": old_key, "platform": "android",
            "expected_route_revision": response_data(&first)["route_revision"],
            "candidate": {"channel_type": "fcm", "provider_token": token}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first prepare: {original_prepare:?}"
    );
    let original_commit_request = json!({
        "transition_id": response_string_field(&original_prepare, "transition_id"),
        "operation_id": "original-op"
    });
    let (status, original_commit) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        original_commit_request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first commit: {original_commit:?}");

    let (_, second) = post_json(
        app.clone(),
        "/device/register",
        json!({"platform": "android"}),
    )
    .await;
    let new_key = response_string_field(&second, "device_key").to_string();
    let revision = response_data(&second)["route_revision"]
        .as_i64()
        .expect("route revision");
    let (status, prepared) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({"operation_id": "takeover-op", "device_key": new_key, "platform": "android", "expected_route_revision": revision,
            "candidate": {"channel_type": "fcm", "provider_token": token}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prepare: {prepared:?}");
    let (status, committed) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        json!({"transition_id": response_string_field(&prepared, "transition_id"), "operation_id": "takeover-op"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "commit: {committed:?}");
    assert!(
        state
            .store
            .current_device_route_revision(&old_key)
            .await
            .expect("old route lookup")
            .is_none()
    );
    assert!(
        state.device_registry.get(&old_key).is_none(),
        "coalesced identity must not survive in memory"
    );
    assert_eq!(
        state
            .device_registry
            .resolve_provider_ingress_route(Platform::ANDROID, token)
            .as_deref(),
        Some(new_key.as_str())
    );
    let (status, replay) = post_json(
        app.clone(),
        "/v2/channel/device/transition/commit",
        original_commit_request,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "retired identity receipt: {replay:?}"
    );
    assert_eq!(response_data(&replay), response_data(&original_commit));
    let (status, queried) = post_json(
        app,
        "/v2/channel/device/transition/query",
        json!({"transition_id": response_string_field(&original_prepare, "transition_id")}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "retired identity query: {queried:?}"
    );
    assert!(response_data(&queried)["route_revision"].is_null());
    assert!(response_data(&queried)["channel_type"].is_null());
    assert_eq!(response_string_field(&queried, "state"), "committed");
}

#[tokio::test]
async fn route_transition_commit_rejects_stale_revision_without_registry_pollution() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_status, register) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    let device_key = response_string_field(&register, "device_key").to_string();
    let revision = response_data(&register)
        .get("route_revision")
        .and_then(Value::as_i64)
        .expect("register revision");
    let (status, prepared) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({
            "operation_id": "stale-commit-op",
            "device_key": device_key,
            "platform": "android",
            "expected_route_revision": revision,
            "candidate": {"channel_type": "fcm", "provider_token": "stale-commit-provider-token"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prepare: {prepared:?}");
    state
        .store
        .persist_device_route_change(&DeviceRouteRecordRow {
            device_key: device_key.clone(),
            platform: "android".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: chrono::Utc::now().timestamp_millis().saturating_add(1),
        })
        .await
        .expect("concurrent route write should succeed");

    let (status, body) = post_json(
        app,
        "/v2/channel/device/transition/commit",
        json!({
            "transition_id": response_string_field(&prepared, "transition_id"),
            "operation_id": "stale-commit-op"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "stale commit: {body:?}");
    assert_eq!(
        body.get("error_code").and_then(Value::as_str),
        Some("route_transition_revision_conflict")
    );
    assert_eq!(
        state
            .device_registry
            .get(&device_key)
            .expect("registry route should remain")
            .channel_type,
        crate::routing::DeviceChannelType::Private
    );
}

#[tokio::test]
async fn provider_token_retirement_advances_route_revision_and_invalidates_prepared_transition() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (_, registered) = post_json(
        app.clone(),
        "/device/register",
        json!({"platform": "android"}),
    )
    .await;
    let device_key = response_string_field(&registered, "device_key").to_string();
    let provider_token = "retire-revision-provider-token";
    let (status, active) = post_json(
        app.clone(),
        "/channel/device",
        json!({"device_key": device_key, "platform": "android", "channel_type": "fcm", "provider_token": provider_token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provider route: {active:?}");
    let base_revision = response_data(&active)["route_revision"]
        .as_i64()
        .expect("active route revision");
    let (status, prepared) = post_json(
        app.clone(),
        "/v2/channel/device/transition/prepare",
        json!({"operation_id": "retire-revision-operation", "device_key": device_key,
            "platform": "android", "expected_route_revision": base_revision,
            "candidate": {"channel_type": "private"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prepare: {prepared:?}");

    // A second gateway process can retire a provider token without this
    // process's registry owner. The durable route revision must still fence an
    // already-prepared transition.
    state
        .store
        .retire_provider_token(Platform::ANDROID, provider_token)
        .await
        .expect("durable provider token retire");
    state
        .device_registry
        .retire_provider_token(Platform::ANDROID, provider_token);
    assert_eq!(
        state
            .store
            .current_device_route_revision(&device_key)
            .await
            .expect("retired route revision"),
        Some(base_revision + 1)
    );
    let (status, queried) = post_json(
        app.clone(),
        "/v2/channel/device/transition/query",
        json!({"transition_id": response_string_field(&prepared, "transition_id")}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query: {queried:?}");
    assert_eq!(
        response_data(&queried)["route_revision"].as_i64(),
        Some(base_revision + 1)
    );
    assert_eq!(response_string_field(&queried, "channel_type"), "private");
    assert!(response_data(&queried)["current_provider_token_sha256"].is_null());
    let (status, body) = post_json(
        app,
        "/v2/channel/device/transition/commit",
        json!({"transition_id": response_string_field(&prepared, "transition_id"),
            "operation_id": "retire-revision-operation"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "stale commit: {body:?}");
    assert_eq!(
        body.get("error_code").and_then(Value::as_str),
        Some("route_transition_revision_conflict")
    );
}

#[tokio::test]
async fn subscription_writers_wait_for_route_transition_before_reading_route() {
    for writer in ["sync", "subscribe", "mqtt-subscribe"] {
        let state = build_private_test_state().await;
        let app = super::super::build_router(state.clone(), "<html>docs</html>");
        let (status, registered) = post_json(
            app.clone(),
            "/device/register",
            json!({"platform": "android"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let key = response_string_field(&registered, "device_key").to_string();
        let operation_guard = state.device_operation_guards.guard_for(&key).unwrap();
        let operation_lock = operation_guard.lock().await;
        let pending_state = state.clone();
        let pending_key = key.clone();
        let mut pending = tokio::spawn(async move {
            match writer {
                "sync" => {
                    post_json(
                        app,
                        "/channel/sync",
                        json!({
                            "device_key": pending_key, "channels": []
                        }),
                    )
                    .await
                    .0 == StatusCode::OK
                }
                "subscribe" => {
                    post_json(
                        app,
                        "/channel/subscribe",
                        json!({
                            "device_key": pending_key, "channel_name": "route-guard-test",
                            "password": "test-password-123"
                        }),
                    )
                    .await
                    .0 == StatusCode::OK
                }
                _ => crate::services::subscribe_private_device_to_channel(
                    &pending_state,
                    crate::services::ChannelSubscribeCommand {
                        device_key: pending_key,
                        channel_id: None,
                        channel_name: Some("route-guard-test".to_string()),
                        password: "test-password-123".to_string(),
                        source: crate::services::ChannelCommandSource::Mqtt,
                        allow_create_channel: true,
                    },
                )
                .await
                .is_ok(),
            }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut pending)
                .await
                .is_err(),
            "{writer} must not publish a route snapshot while its transition is in progress"
        );
        let previous = state.device_registry.get(&key).unwrap();
        let newer = DeviceRouteRecord {
            platform: Platform::ANDROID,
            channel_type: crate::routing::DeviceChannelType::Fcm,
            provider_token: Some("new-route-provider-token".to_string()),
            updated_at: previous.next_updated_at(chrono::Utc::now().timestamp_millis()),
        };
        state
            .store
            .transition_device_route(
                &DeviceRouteRecordRow::from_registry_record(&key, &newer),
                RouteChannelType::Private,
                30,
                100,
            )
            .await
            .expect("commit newer route");
        state
            .device_registry
            .restore_route(&key, newer.clone())
            .unwrap();
        drop(operation_lock);
        let succeeded = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .expect("writer completes after transition")
            .expect("writer task");
        assert_eq!(
            succeeded,
            writer != "mqtt-subscribe",
            "writer must use the current route"
        );
        let stored = state
            .store
            .load_device_routes()
            .await
            .unwrap()
            .into_iter()
            .find(|route| route.device_key == key)
            .unwrap();
        assert_eq!(
            stored.channel_type, "fcm",
            "{writer} reverted the durable route"
        );
        assert_eq!(stored.provider_token, newer.provider_token);
        assert_eq!(
            state.device_registry.get(&key).unwrap().channel_type,
            newer.channel_type
        );
    }
}

#[tokio::test]
async fn provider_token_retirement_waits_for_route_switch_and_preserves_new_token() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let key = "retirement-race-device";
    let old_token = "retirement-old-provider-token";
    seed_provider_channel_for_router_test(
        &state,
        key,
        "retirement-guard-channel",
        "test-password-123",
        old_token,
        Platform::ANDROID,
    )
    .await;
    let guard = state.device_operation_guards.guard_for(key).unwrap();
    let lock = guard.lock().await;
    let mut retirement = tokio::spawn(async move {
        post_json(
            app,
            "/channel/device/provider-token/retire",
            json!({
                "platform": "android", "provider_token": old_token
            }),
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut retirement)
            .await
            .is_err(),
        "retirement must wait for the device route writer"
    );
    let previous = state.device_registry.get(key).unwrap();
    let newer = DeviceRouteRecord {
        platform: Platform::ANDROID,
        channel_type: crate::routing::DeviceChannelType::Fcm,
        provider_token: Some("retirement-new-provider-token".to_string()),
        updated_at: previous.next_updated_at(chrono::Utc::now().timestamp_millis()),
    };
    state
        .store
        .transition_device_route(
            &DeviceRouteRecordRow::from_registry_record(key, &newer),
            RouteChannelType::Fcm,
            30,
            100,
        )
        .await
        .expect("commit rotated token");
    state
        .device_registry
        .restore_route(key, newer.clone())
        .unwrap();
    drop(lock);
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(5), retirement)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let stored = state
        .store
        .load_device_routes()
        .await
        .unwrap()
        .into_iter()
        .find(|route| route.device_key == key)
        .unwrap();
    assert_eq!(stored.channel_type, "fcm");
    assert_eq!(stored.provider_token, newer.provider_token);
    assert_eq!(
        state.device_registry.get(key).unwrap().provider_token,
        newer.provider_token
    );
}
