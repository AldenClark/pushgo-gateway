use super::*;

use crate::{
    private::protocol::PrivatePayloadEnvelope,
    routing::derive_private_device_id,
    storage::{Platform, PrivateMessage},
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

async fn enqueue_provider_pull_item(
    state: &AppState,
    device_key: &str,
    delivery_id: &str,
    title: &str,
) {
    let now = chrono::Utc::now().timestamp_millis();
    let payload = make_provider_payload(delivery_id, title);
    let message = PrivateMessage {
        payload: payload.clone(),
        size: payload.len(),
        sent_at: now,
        expires_at: now + 300_000,
    };
    let device_id = derive_private_device_id(device_key);
    state
        .store
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "android-provider-token-test",
        )
        .await
        .expect("enqueue provider pull item should succeed");
}

#[tokio::test]
async fn messages_pull_without_delivery_id_returns_all_and_drains_queue() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-all";
    let delivery_a = "delivery-router-all-001";
    let delivery_b = "delivery-router-all-002";
    enqueue_provider_pull_item(&state, device_key, delivery_a, "title-a").await;
    enqueue_provider_pull_item(&state, device_key, delivery_b, "title-b").await;

    let (status, body) = post_json(
        app.clone(),
        "/messages/pull",
        json!({
            "device_key": device_key
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut ids = response_data(&body)
        .get("items")
        .and_then(Value::as_array)
        .expect("items should be an array")
        .iter()
        .filter_map(|item| item.get("delivery_id").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, vec![delivery_a.to_string(), delivery_b.to_string()]);

    let (second_status, second_body) = post_json(
        app,
        "/messages/pull",
        json!({
            "device_key": device_key
        }),
    )
    .await;
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(
        response_data(&second_body)
            .get("items")
            .and_then(Value::as_array)
            .expect("items should be an array")
            .len(),
        0
    );
}

#[tokio::test]
async fn messages_pull_with_delivery_id_returns_only_targeted_item() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-single";
    let delivery_a = "delivery-router-single-001";
    let delivery_b = "delivery-router-single-002";
    enqueue_provider_pull_item(&state, device_key, delivery_a, "title-a").await;
    enqueue_provider_pull_item(&state, device_key, delivery_b, "title-b").await;

    let (single_status, single_body) = post_json(
        app.clone(),
        "/messages/pull",
        json!({
            "device_key": device_key,
            "delivery_id": delivery_a
        }),
    )
    .await;
    assert_eq!(single_status, StatusCode::OK);
    let single_items = response_data(&single_body)
        .get("items")
        .and_then(Value::as_array)
        .expect("items should be an array");
    assert_eq!(single_items.len(), 1);
    assert_eq!(
        single_items[0]
            .get("delivery_id")
            .and_then(Value::as_str)
            .expect("delivery_id should be present"),
        delivery_a
    );

    let (remaining_status, remaining_body) = post_json(
        app,
        "/messages/pull",
        json!({
            "device_key": device_key
        }),
    )
    .await;
    assert_eq!(remaining_status, StatusCode::OK);
    let remaining_items = response_data(&remaining_body)
        .get("items")
        .and_then(Value::as_array)
        .expect("items should be an array");
    assert_eq!(remaining_items.len(), 1);
    assert_eq!(
        remaining_items[0]
            .get("delivery_id")
            .and_then(Value::as_str)
            .expect("delivery_id should be present"),
        delivery_b
    );
}

#[tokio::test]
async fn messages_ack_removes_delivery_and_is_idempotent() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-ack";
    let delivery_id = "delivery-router-ack-001";
    enqueue_provider_pull_item(&state, device_key, delivery_id, "title-ack").await;

    let (ack_status, ack_body) = post_json(
        app.clone(),
        "/messages/ack",
        json!({
            "device_key": device_key,
            "delivery_id": delivery_id
        }),
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK);
    assert_eq!(
        response_data(&ack_body)
            .get("removed")
            .and_then(Value::as_bool),
        Some(true)
    );

    let (ack_again_status, ack_again_body) = post_json(
        app.clone(),
        "/messages/ack",
        json!({
            "device_key": device_key,
            "delivery_id": delivery_id
        }),
    )
    .await;
    assert_eq!(ack_again_status, StatusCode::OK);
    assert_eq!(
        response_data(&ack_again_body)
            .get("removed")
            .and_then(Value::as_bool),
        Some(false)
    );

    let (pull_status, pull_body) = post_json(
        app,
        "/messages/pull",
        json!({
            "device_key": device_key
        }),
    )
    .await;
    assert_eq!(pull_status, StatusCode::OK);
    assert_eq!(
        response_data(&pull_body)
            .get("items")
            .and_then(Value::as_array)
            .expect("items should be an array")
            .len(),
        0
    );
}
