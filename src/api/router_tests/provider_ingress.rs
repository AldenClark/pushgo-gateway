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

async fn enqueue_provider_pull_item(
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

async fn enqueue_raw_provider_pull_item(
    state: &AppState,
    device_key: &str,
    delivery_id: &str,
    payload: Vec<u8>,
) {
    let now = chrono::Utc::now().timestamp_millis();
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
            "android-provider-token-raw-test",
        )
        .await
        .expect("raw provider pull item should seed");
}

fn provider_contract_fixture(name: &str) -> Value {
    let raw = match name {
        "pull_v2_request" => {
            include_str!("../../../tests/fixtures/provider_contract/pull_v2_request.json")
        }
        "pull_v2_response" => {
            include_str!("../../../tests/fixtures/provider_contract/pull_v2_response.json")
        }
        "ack_v2_request" => {
            include_str!("../../../tests/fixtures/provider_contract/ack_v2_request.json")
        }
        "ack_v2_response" => {
            include_str!("../../../tests/fixtures/provider_contract/ack_v2_response.json")
        }
        _ => panic!("unknown provider contract fixture: {name}"),
    };
    serde_json::from_str(raw).expect("provider contract fixture should be valid JSON")
}

#[tokio::test]
async fn provider_pull_and_ack_v2_match_shared_windows_fixtures() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "fixture-device-key";
    let delivery_id = "delivery-fixture-001";
    enqueue_provider_pull_item(&state, device_key, delivery_id, "Fixture notification").await;

    let (pull_status, pull_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        provider_contract_fixture("pull_v2_request"),
    )
    .await;
    assert_eq!(pull_status, StatusCode::OK);
    assert_eq!(
        pull_body,
        provider_contract_fixture("pull_v2_response"),
        "Gateway pull response must remain JSON-shape compatible with the Windows fixture"
    );

    let (ack_status, ack_body) = post_json(
        app.clone(),
        "/v2/messages/ack",
        provider_contract_fixture("ack_v2_request"),
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK);
    assert_eq!(
        ack_body,
        provider_contract_fixture("ack_v2_response"),
        "Gateway ACK response must remain compatible with the Windows fixture"
    );

    let (_, empty_body) = post_json(
        app,
        "/v2/messages/pull",
        json!({ "device_key": device_key, "delivery_id": delivery_id }),
    )
    .await;
    assert!(
        response_data(&empty_body)
            .get("items")
            .and_then(Value::as_array)
            .expect("post-ACK items should be an array")
            .is_empty(),
        "ACK fixture must remove the exact outer delivery_id"
    );
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

    let (targeted_status, targeted_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({
            "device_key": device_key,
            "delivery_id": delivery_a
        }),
    )
    .await;
    assert_eq!(targeted_status, StatusCode::OK);
    let targeted_data = response_data(&targeted_body);
    let targeted_items = targeted_data
        .get("items")
        .and_then(Value::as_array)
        .expect("targeted v2 items should be an array");
    assert_eq!(targeted_items.len(), 1);
    assert_eq!(
        targeted_items[0].get("delivery_id").and_then(Value::as_str),
        Some(delivery_a)
    );
    assert_eq!(
        targeted_data.get("has_more").and_then(Value::as_bool),
        Some(false)
    );

    let (status, body) = post_json(
        app.clone(),
        "/messages/pull",
        json!({
            "device_key": device_key
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_data(&body).get("has_more").is_none(),
        "legacy beta-compatible response must not acquire v2 fields"
    );
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
async fn messages_pull_rejects_v2_or_misspelled_fields_without_draining_legacy_queue() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-strict-legacy";
    let delivery_a = "delivery-router-strict-legacy-001";
    let delivery_b = "delivery-router-strict-legacy-002";
    enqueue_provider_pull_item(&state, device_key, delivery_a, "title-a").await;
    enqueue_provider_pull_item(&state, device_key, delivery_b, "title-b").await;

    for extra_field in [
        json!({"delivery_ids": [delivery_a]}),
        json!({"delivey_id": delivery_a}),
    ] {
        let mut request = json!({"device_key": device_key});
        request
            .as_object_mut()
            .expect("request object")
            .extend(extra_field.as_object().expect("extra field object").clone());
        let (status, _) = post_json(app.clone(), "/messages/pull", request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let device_id = derive_private_device_id(device_key);
    let now = chrono::Utc::now().timestamp_millis();
    for delivery_id in [delivery_a, delivery_b] {
        assert!(
            state
                .store
                .peek_provider_item(device_id, delivery_id, now)
                .await
                .expect("queued item lookup")
                .is_some(),
            "invalid legacy request must not drain {delivery_id}"
        );
    }
}

#[tokio::test]
async fn messages_pull_v2_keeps_items_until_batch_ack() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2";
    let delivery_a = "delivery-router-v2-001";
    let delivery_b = "delivery-router-v2-002";
    enqueue_provider_pull_item(&state, device_key, delivery_a, "title-a").await;
    enqueue_provider_pull_item(&state, device_key, delivery_b, "title-b").await;

    for _ in 0..2 {
        let (status, body) = post_json(
            app.clone(),
            "/v2/messages/pull",
            json!({
                "device_key": device_key,
                "future_client_field": { "version": 3 }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_data(&body)
                .get("items")
                .and_then(Value::as_array)
                .expect("items should be an array")
                .len(),
            2
        );
    }

    let (ack_status, ack_body) = post_json(
        app.clone(),
        "/v2/messages/ack",
        json!({
            "device_key": device_key,
            "delivery_ids": [delivery_b, delivery_a, delivery_a],
            "future_client_field": true
        }),
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK);
    assert_eq!(
        response_data(&ack_body)
            .get("requested_count")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        response_data(&ack_body)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(2)
    );

    let (_, empty_body) = post_json(
        app,
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert!(
        response_data(&empty_body)
            .get("items")
            .and_then(Value::as_array)
            .expect("items should be an array")
            .is_empty()
    );
}

#[tokio::test]
async fn messages_pull_v2_discards_invalid_payload_without_returning_it() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-invalid";
    let delivery_id = "delivery-router-v2-invalid-001";
    let unsupported_delivery_id = "delivery-router-v2-unsupported-version-001";
    let now = chrono::Utc::now().timestamp_millis();
    state
        .store
        .enqueue_provider_pull_item(
            derive_private_device_id(device_key),
            delivery_id,
            &PrivateMessage {
                payload: vec![0xff, 0x00, 0x7f].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "android-provider-token-invalid",
        )
        .await
        .expect("invalid provider payload should seed");
    let mut unsupported_data = hashbrown::HashMap::new();
    unsupported_data.insert(
        "delivery_id".to_string(),
        unsupported_delivery_id.to_string(),
    );
    let unsupported_payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
        payload_version: PrivatePayloadEnvelope::CURRENT_VERSION.saturating_add(1),
        data: unsupported_data,
    })
    .expect("unsupported provider payload should encode");
    enqueue_raw_provider_pull_item(
        &state,
        device_key,
        unsupported_delivery_id,
        unsupported_payload,
    )
    .await;

    for _ in 0..2 {
        let (status, body) = post_json(
            app.clone(),
            "/v2/messages/pull",
            json!({ "device_key": device_key }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            response_data(&body)
                .get("items")
                .and_then(Value::as_array)
                .expect("items should be an array")
                .is_empty()
        );
    }
    assert!(
        state
            .store
            .peek_provider_item(
                derive_private_device_id(device_key),
                delivery_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("provider queue should remain queryable")
            .is_none(),
        "invalid payload must be deleted, not merely hidden from the v2 response"
    );
    assert!(
        state
            .store
            .peek_provider_item(
                derive_private_device_id(device_key),
                unsupported_delivery_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("unsupported provider queue should remain queryable")
            .is_none(),
        "unsupported payload versions must be silently deleted"
    );
}

#[tokio::test]
async fn messages_pull_v2_pages_207_items_without_loss() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-207";
    for index in 0..207 {
        let delivery_id = format!("delivery-router-v2-page-{index:03}");
        enqueue_provider_pull_item(&state, device_key, &delivery_id, "paged-title").await;
    }

    let (first_status, first_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK, "first page: {first_body:?}");
    let first_data = response_data(&first_body);
    let first_items = first_data
        .get("items")
        .and_then(Value::as_array)
        .expect("first items should be an array");
    assert_eq!(first_items.len(), 200);
    assert_eq!(
        first_data.get("has_more").and_then(Value::as_bool),
        Some(true)
    );
    let first_ids = first_items
        .iter()
        .map(|item| {
            item.get("delivery_id")
                .and_then(Value::as_str)
                .expect("first page delivery id")
                .to_string()
        })
        .collect::<Vec<_>>();

    let (ack_status, ack_body) = post_json(
        app.clone(),
        "/v2/messages/ack",
        json!({ "device_key": device_key, "delivery_ids": first_ids }),
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK, "first ACK: {ack_body:?}");
    assert_eq!(
        response_data(&ack_body)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(200)
    );

    let (second_status, second_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "second page: {second_body:?}"
    );
    let second_data = response_data(&second_body);
    let second_ids = second_data
        .get("items")
        .and_then(Value::as_array)
        .expect("second items should be an array")
        .iter()
        .map(|item| {
            item.get("delivery_id")
                .and_then(Value::as_str)
                .expect("second page delivery id")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(second_ids.len(), 7);
    assert_eq!(
        second_data.get("has_more").and_then(Value::as_bool),
        Some(false)
    );

    let mut all_ids = first_ids;
    all_ids.extend(second_ids);
    all_ids.sort();
    all_ids.dedup();
    assert_eq!(
        all_ids.len(),
        207,
        "every queued delivery must appear exactly once"
    );
}

#[tokio::test]
async fn messages_pull_v2_corrupt_full_page_does_not_hide_later_valid_item() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-corrupt-page";
    for index in 0..201 {
        let delivery_id = format!("000-corrupt-{index:03}");
        enqueue_raw_provider_pull_item(
            &state,
            device_key,
            &delivery_id,
            vec![0xff, index as u8, 0x7f],
        )
        .await;
    }
    let valid_delivery_id = "zzz-valid-after-corrupt-page";
    enqueue_provider_pull_item(&state, device_key, valid_delivery_id, "survives").await;

    let (first_status, first_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK, "corrupt page: {first_body:?}");
    let first_data = response_data(&first_body);
    assert!(
        first_data
            .get("items")
            .and_then(Value::as_array)
            .expect("items should be an array")
            .is_empty()
    );
    assert_eq!(
        first_data.get("has_more").and_then(Value::as_bool),
        Some(true)
    );

    let (second_status, second_body) = post_json(
        app,
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "post-discard page: {second_body:?}"
    );
    let second_data = response_data(&second_body);
    let second_items = second_data
        .get("items")
        .and_then(Value::as_array)
        .expect("items should be an array");
    assert_eq!(second_items.len(), 1);
    assert_eq!(
        second_items[0].get("delivery_id").and_then(Value::as_str),
        Some(valid_delivery_id)
    );
    assert_eq!(
        second_data.get("has_more").and_then(Value::as_bool),
        Some(false)
    );
}

#[tokio::test]
async fn messages_pull_v2_discards_missing_and_mismatched_inner_ids_by_outer_id_only() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-id-authority";
    let missing_outer = "000-missing-inner";
    let mismatch_outer = "001-mismatch-outer";
    let innocent_outer = "002-innocent-valid";

    let mut missing_data = hashbrown::HashMap::new();
    missing_data.insert("title".to_string(), "missing".to_string());
    enqueue_raw_provider_pull_item(
        &state,
        device_key,
        missing_outer,
        postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PrivatePayloadEnvelope::CURRENT_VERSION,
            data: missing_data,
        })
        .expect("missing-id envelope should encode"),
    )
    .await;

    let mismatch_payload = make_provider_payload(innocent_outer, "mismatch");
    enqueue_raw_provider_pull_item(&state, device_key, mismatch_outer, mismatch_payload).await;
    enqueue_provider_pull_item(&state, device_key, innocent_outer, "innocent").await;
    let now = chrono::Utc::now().timestamp_millis();
    state
        .store
        .enqueue_private_outbox(
            derive_private_device_id(device_key),
            &PrivateOutboxEntry {
                delivery_id: innocent_outer.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                next_attempt_at: now,
                updated_at: now,
                ..PrivateOutboxEntry::default()
            },
        )
        .await
        .expect("innocent private outbox row should seed");

    let (status, body) = post_json(
        app,
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "id-authority page: {body:?}");
    let items = response_data(&body)
        .get("items")
        .and_then(Value::as_array)
        .expect("items should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("delivery_id").and_then(Value::as_str),
        Some(innocent_outer),
        "a mismatched embedded id must never delete or ACK that other outer delivery"
    );

    let device_id = derive_private_device_id(device_key);
    for invalid in [missing_outer, mismatch_outer] {
        assert!(
            state
                .store
                .peek_provider_item(device_id, invalid, chrono::Utc::now().timestamp_millis())
                .await
                .expect("invalid outer row lookup")
                .is_none(),
            "invalid row {invalid} should be silently deleted by its outer id"
        );
    }
    assert!(
        state
            .store
            .peek_provider_item(
                device_id,
                innocent_outer,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("innocent row lookup")
            .is_some(),
        "valid outer delivery remains pending until explicit ACK"
    );
    assert!(
        state
            .store
            .load_private_outbox_entry(device_id, innocent_outer)
            .await
            .expect("innocent private outbox lookup")
            .is_some(),
        "discarding a mismatched outer row must not ACK its embedded delivery id"
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
    assert!(
        response_data(&ack_body).get("requested_count").is_none()
            && response_data(&ack_body).get("removed_count").is_none(),
        "legacy beta-compatible ACK response must not acquire v2 count fields"
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

#[tokio::test]
async fn messages_ack_routes_keep_legacy_and_batch_contracts_separate() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");
    let (legacy_batch_status, _) = post_json(
        app.clone(),
        "/messages/ack",
        json!({
            "device_key": "router-provider-device-ack-invalid",
            "delivery_id": "one",
            "delivery_ids": ["two"]
        }),
    )
    .await;
    assert_eq!(legacy_batch_status, StatusCode::BAD_REQUEST);

    let (legacy_empty_status, legacy_empty_body) = post_json(
        app.clone(),
        "/messages/ack",
        json!({
            "device_key": "router-provider-device-ack-invalid",
            "delivery_id": ""
        }),
    )
    .await;
    assert_eq!(legacy_empty_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        legacy_empty_body.get("error_code").and_then(Value::as_str),
        Some("delivery_id_required")
    );

    let (empty_status, _) = post_json(
        app,
        "/v2/messages/ack",
        json!({
            "device_key": "router-provider-device-ack-invalid",
            "delivery_ids": []
        }),
    )
    .await;
    assert_eq!(empty_status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_ack_can_close_watch_delivery_without_closing_phone_delivery() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let phone_device_key = "router-provider-phone-ack";
    let watch_device_key = "router-provider-watch-ack";
    let phone_delivery_id = "delivery-phone-ack-001";
    let watch_delivery_id = "delivery-watch-ack-001";
    enqueue_provider_pull_item(&state, phone_device_key, phone_delivery_id, "phone-title").await;
    enqueue_provider_pull_item(&state, watch_device_key, watch_delivery_id, "watch-title").await;

    let (ack_status, ack_body) = post_json(
        app.clone(),
        "/messages/ack",
        json!({
            "device_key": watch_device_key,
            "delivery_id": watch_delivery_id
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
            "device_key": watch_device_key,
            "delivery_id": watch_delivery_id
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

    let (phone_pull_status, phone_pull_body) = post_json(
        app,
        "/messages/pull",
        json!({
            "device_key": phone_device_key
        }),
    )
    .await;
    assert_eq!(phone_pull_status, StatusCode::OK);
    assert_eq!(
        response_data(&phone_pull_body)
            .get("items")
            .and_then(Value::as_array)
            .expect("items should be an array")
            .len(),
        1
    );
}
