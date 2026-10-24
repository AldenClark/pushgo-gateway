//! Retained Event/Thing queue protocol and malformed-row regressions. Ordinary
//! messages are accepted through `/message` into C in the dedicated tests below;
//! seeding the retired ordinary cache is never an ordinary delivery fallback.
use super::*;

use crate::{
    private::protocol::PrivatePayloadEnvelope,
    routing::derive_private_device_id,
    storage::{OUTBOX_STATUS_PENDING, Platform, PrivateMessage, PrivateOutboxEntry},
};

fn make_provider_payload(delivery_id: &str, title: &str) -> Vec<u8> {
    let mut data = hashbrown::HashMap::new();
    data.insert("entity_type".to_string(), "event".to_string());
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
async fn retained_event_pull_and_ack_v2_match_shared_windows_fixtures() {
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
    let mut expected = provider_contract_fixture("pull_v2_response");
    expected["data"]["items"][0]["payload"]["entity_type"] = json!("event");
    assert_eq!(
        pull_body, expected,
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
async fn messages_pull_v2_filters_invalid_payload_without_releasing_responsibility() {
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
            .is_some(),
        "filtered invalid payload remains durable; scan is not deletion permission"
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
            .is_some(),
        "unsupported payload version remains durable and is not acknowledged by a scan"
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
async fn messages_pull_v2_without_page_token_repeats_unacked_full_page() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-unacked-page";
    let later_healthy_delivery = "delivery-unacked-page-200";

    // Model a receiver that cannot commit any valid item in the first page:
    // it intentionally sends no ACK, so every row remains durable and retryable.
    for index in 0..201 {
        let delivery_id = format!("delivery-unacked-page-{index:03}");
        enqueue_provider_pull_item(&state, device_key, &delivery_id, "valid retained item").await;
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
        .expect("first page items");
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
                .expect("delivery id")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(!first_ids.iter().any(|id| id == later_healthy_delivery));

    // A client that does not use the new page token repeats the unACKed head.
    // The additive traversal extension does not silently ACK or skip it.
    let (second_status, second_body) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(second_status, StatusCode::OK, "retry page: {second_body:?}");
    let second_data = response_data(&second_body);
    let second_items = second_data
        .get("items")
        .and_then(Value::as_array)
        .expect("retry page items");
    let second_ids = second_items
        .iter()
        .map(|item| {
            item.get("delivery_id")
                .and_then(Value::as_str)
                .expect("delivery id")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(second_ids, first_ids);
    assert_eq!(
        second_data.get("has_more").and_then(Value::as_bool),
        Some(true)
    );

    assert!(
        state
            .store
            .peek_provider_item(
                derive_private_device_id(device_key),
                later_healthy_delivery,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("later healthy durable item lookup")
            .is_some(),
        "the later item remains stored even though the no-cursor client cannot reach it"
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
        json!({ "device_key": device_key, "page_token": first_data["next_page_token"] }),
    )
    .await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "continuation after filtered head: {second_body:?}"
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
async fn messages_pull_v2_preserves_missing_and_mismatched_inner_ids_by_outer_id() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device_key = "router-provider-device-v2-id-authority";
    let missing_outer = "000-missing-inner";
    let mismatch_outer = "001-mismatch-outer";
    let innocent_outer = "002-innocent-valid";

    let mut missing_data = hashbrown::HashMap::new();
    missing_data.insert("entity_type".to_string(), "event".to_string());
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
                .is_some(),
            "filtered row {invalid} must retain its outer delivery responsibility"
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

#[tokio::test]
async fn ordinary_http_accept_pull_ack_and_replay_use_only_c_authority() {
    let state = build_test_state().await;
    let device = "ordinary-http-client";
    let password = crate::util::generate_hex_id_128();
    let channel = seed_provider_channel_for_router_test(
        &state,
        device,
        "ordinary HTTP C authority",
        &password,
        "synthetic-ordinary-provider-token",
        Platform::ANDROID,
    )
    .await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let thing = crate::util::generate_hex_id_128();
    let occurred = chrono::Utc::now().timestamp_millis() - 60_000;
    let request = json!({
        "channel_id":channel, "password":password, "op_id":"ordinary-http-idempotent",
        "title":"ordinary HTTP", "body":"完整正文 remains intact", "thing_id":thing,
        "occurred_at":occurred,
    });
    let (status, accepted) = post_json(app.clone(), "/message", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "ordinary accept: {accepted:?}");
    let identity = response_string_field(&accepted, "message_id").to_owned();
    let (status, replay) = post_json(app.clone(), "/message", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "ordinary replay: {replay:?}");
    assert_eq!(response_string_field(&replay, "message_id"), identity);
    let (status, pulled) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ordinary Pull: {pulled:?}");
    let items = response_data(&pulled)["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "idempotent replay cannot add another frozen target"
    );
    let delivery = items[0]["delivery_id"].as_str().unwrap().to_owned();
    let payload = &items[0]["payload"];
    assert_eq!(payload["entity_type"], "message");
    assert_eq!(payload["message_id"], identity);
    assert_eq!(payload["thing_id"], thing);
    assert_eq!(payload["occurred_at"], occurred.to_string());
    assert_eq!(payload["body"], "完整正文 remains intact");
    assert!(payload.get("delivery_id").is_none());
    assert_eq!(
        state
            .store
            .count_pending_provider_dispatch_jobs("FCM")
            .await
            .unwrap(),
        0
    );
    assert!(
        state
            .store
            .peek_provider_item(
                derive_private_device_id(device),
                &delivery,
                chrono::Utc::now().timestamp_millis()
            )
            .await
            .unwrap()
            .is_none(),
        "ordinary Pull must not depend on a second legacy queue copy"
    );
    for expected in [1, 0] {
        let (status, ack) = post_json(
            app.clone(),
            "/v2/messages/ack",
            json!({
                "device_key":device, "delivery_ids":[delivery,delivery],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "ordinary ACK: {ack:?}");
        assert_eq!(response_data(&ack)["requested_count"], 1);
        assert_eq!(response_data(&ack)["removed_count"], expected);
    }
    let (status, after_ack_replay) = post_json(app.clone(), "/message", request.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_string_field(&after_ack_replay, "message_id"),
        identity
    );
    let (status, empty) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_data(&empty)["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the retained identity must not resurrect released content"
    );
    let mut conflict = request;
    conflict["body"] = json!("conflicting content");
    let (status, response) = post_json(app, "/message", conflict).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "ordinary conflict: {response:?}"
    );
}

#[tokio::test]
async fn provider_scan_token_crosses_unacked_head_without_ack_and_freezes_append_ceiling() {
    let (state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device = "scan-retained-unacked-head";
    for index in 0..205 {
        enqueue_provider_pull_item(&state, device, &format!("scan-{index:03}"), "retained").await;
    }
    // Explicit equal-created_at fixture verifies the delivery-id tie breaker.
    let inspect = sqlx::SqlitePool::connect(&db_url).await.unwrap();
    sqlx::query("UPDATE provider_pull_queue SET created_at=?")
        .bind(chrono::Utc::now().timestamp_millis() - 10_000)
        .execute(&inspect)
        .await
        .unwrap();
    let (status, first) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = response_data(&first);
    assert_eq!(first["items"].as_array().unwrap().len(), 200);
    assert_eq!(first["scan_complete"], false);
    let token = first["next_page_token"].as_str().unwrap().to_owned();
    // A later append remains durable, but does not extend this captured pass.
    enqueue_provider_pull_item(&state, device, "zz-late-append", "new pass").await;
    let (status, wrong) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":"other-scan-device","page_token":token}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(wrong["error_code"], "page_token_scope_changed");
    let (status, mixed) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device,"delivery_id":"scan-000","page_token":token}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(mixed["error_code"], "page_token_delivery_id_conflict");
    let (status, invalid) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":"x".repeat(2049)}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid["error_code"], "page_token_invalid");
    let (status, tail) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tail = response_data(&tail);
    let ids = tail["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["delivery_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        ["scan-200", "scan-201", "scan-202", "scan-203", "scan-204"]
    );
    assert_eq!(tail["scan_complete"], true);
    assert!(tail["next_page_token"].is_null());
    assert_eq!(
        state
            .store
            .peek_provider_candidates(
                derive_private_device_id(device),
                chrono::Utc::now().timestamp_millis(),
                300
            )
            .await
            .unwrap()
            .len(),
        206,
        "read traversal never ACKs or deletes the failed head or later rows"
    );
    let (status, restarted) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let next = response_data(&restarted)["next_page_token"]
        .as_str()
        .unwrap();
    let (status, new_tail) = post_json(
        app,
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":next}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_data(&new_tail)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["delivery_id"] == "zz-late-append")
    );
    inspect.close().await;
}

#[tokio::test]
async fn provider_scan_filters_but_preserves_corrupt_rows_and_reaches_healthy_tail() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device = "scan-corrupt-retained-head";
    for index in 0..200 {
        enqueue_raw_provider_pull_item(&state, device, &format!("corrupt-{index:03}"), vec![0xff])
            .await;
    }
    enqueue_provider_pull_item(&state, device, "healthy-tail", "healthy").await;
    let (status, first) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = response_data(&first);
    assert!(first["items"].as_array().unwrap().is_empty());
    assert_eq!(first["scan_complete"], false);
    let (status, tail) = post_json(
        app,
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":first["next_page_token"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_data(&tail)["items"][0]["delivery_id"],
        "healthy-tail"
    );
    assert_eq!(response_data(&tail)["scan_complete"], true);
    assert_eq!(
        state
            .store
            .peek_provider_candidates(
                derive_private_device_id(device),
                chrono::Utc::now().timestamp_millis(),
                300
            )
            .await
            .unwrap()
            .len(),
        201,
        "malformed obligations remain durable; traversal is not discard permission"
    );
}

#[tokio::test]
async fn provider_scan_rotates_ordinary_and_retained_and_does_not_hide_independent_json_failure() {
    let (state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    let device = "scan-mixed-sources";
    // Synthetic per-test credentials only; no Provider is invoked by this state.
    let password = crate::util::generate_hex_id_128();
    let channel = seed_provider_channel_for_router_test(
        &state,
        device,
        "scan mixed",
        &password,
        "scan-test-provider-token",
        Platform::ANDROID,
    )
    .await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    for index in 0..201 {
        let (status, response) = post_json(app.clone(), "/message", json!({"channel_id":channel,"password":password,"op_id":format!("scan-ordinary-{index:03}"),"title":"ordinary","body":"unchanged"})).await;
        assert_eq!(status, StatusCode::OK, "{response:?}");
    }
    // Explicit fault injection into a normally accepted item, not old-version data.
    let db = sqlx::SqlitePool::connect(&db_url).await.unwrap();
    sqlx::query("UPDATE ordinary_messages SET payload_blob=X'ff',payload_bytes=1 WHERE op_id='scan-ordinary-000'").execute(&db).await.unwrap();
    for index in 0..5 {
        enqueue_provider_pull_item(&state, device, &format!("mixed-event-{index}"), "event").await;
    }
    let (status, first) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = response_data(&first);
    assert_eq!(first["items"].as_array().unwrap().len(), 199);
    assert!(
        first["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["payload"]["entity_type"] == "message")
    );
    let token = first["next_page_token"].as_str().unwrap();
    let (status, tail) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tail = response_data(&tail);
    assert_eq!(tail["items"].as_array().unwrap().len(), 6);
    assert_eq!(
        tail["items"][0]["payload"]["entity_type"], "event",
        "continuation gives retained source its turn before more ordinary work"
    );
    assert_eq!(tail["scan_complete"], true);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM ordinary_targets WHERE acked_at IS NULL"
        )
        .fetch_one(&db)
        .await
        .unwrap(),
        201
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT length(payload_blob) FROM ordinary_messages WHERE op_id='scan-ordinary-000'"
        )
        .fetch_one(&db)
        .await
        .unwrap(),
        1
    );
    // Actual canonical route change invalidates an earlier token without reassigning it.
    let route = DeviceRouteRecord {
        platform: Platform::ANDROID,
        channel_type: crate::routing::DeviceChannelType::parse(Platform::ANDROID.channel_type())
            .unwrap(),
        provider_token: Some("scan-new-provider-token".into()),
        updated_at: chrono::Utc::now().timestamp(),
    };
    state
        .store
        .upsert_device_route(&crate::storage::DeviceRouteRecordRow::from_registry_record(
            device, &route,
        ))
        .await
        .unwrap();
    let (status, changed) = post_json(
        app,
        "/v2/messages/pull",
        json!({"device_key":device,"page_token":token}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(changed["error_code"], "page_token_scope_changed");
    db.close().await;
}

#[tokio::test]
async fn provider_scan_soft_page_preserves_oversized_item_and_all_batch_boundaries() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let device = "scan-soft-response";
    // Explicit synthetic retained rows exercise serialization, not public-message acceptance.
    for index in 0..35 {
        let delivery = format!("soft-{index:03}");
        let mut data = hashbrown::HashMap::from_iter([
            ("entity_type".into(), "event".into()),
            ("delivery_id".into(), delivery.clone()),
            ("title".into(), "soft page".into()),
            (
                "body".into(),
                "x".repeat(if index == 20 {
                    1024 * 1024 + 1
                } else {
                    48 * 1024
                }),
            ),
        ]);
        data.insert(
            "test_kind".into(),
            "synthetic-retained-byte-boundary".into(),
        );
        enqueue_raw_provider_pull_item(
            &state,
            device,
            &delivery,
            postcard::to_allocvec(&PrivatePayloadEnvelope {
                payload_version: PrivatePayloadEnvelope::CURRENT_VERSION,
                data,
            })
            .unwrap(),
        )
        .await;
    }
    let mut token = None::<String>;
    let mut received = Vec::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= 6);
        let request = if let Some(value) = &token {
            json!({"device_key":device,"page_token":value})
        } else {
            json!({"device_key":device})
        };
        let (status, response) = post_json(app.clone(), "/v2/messages/pull", request).await;
        assert_eq!(status, StatusCode::OK);
        let encoded_bytes = serde_json::to_vec(&response).unwrap().len();
        let data = response_data(&response);
        let items = data["items"].as_array().unwrap();
        if encoded_bytes > 1024 * 1024 {
            assert_eq!(
                items.len(),
                1,
                "only a single item may exceed the soft aggregate target"
            );
        }
        for item in items {
            received.push(item["delivery_id"].as_str().unwrap().to_owned());
        }
        if data["scan_complete"] == true {
            assert!(data["next_page_token"].is_null());
            break;
        }
        token = Some(data["next_page_token"].as_str().unwrap().to_owned());
    }
    assert!(pages >= 3);
    assert_eq!(
        received,
        (0..35)
            .map(|index| format!("soft-{index:03}"))
            .collect::<Vec<_>>(),
        "byte-limited item and32-row read boundaries cannot skip or repeat an item"
    );
    assert_eq!(
        state
            .store
            .peek_provider_candidates(
                derive_private_device_id(device),
                chrono::Utc::now().timestamp_millis(),
                100
            )
            .await
            .unwrap()
            .len(),
        35
    );
}

#[tokio::test]
async fn provider_scan_authority_unavailable_cannot_return_success_or_a_frontier() {
    let (state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    let device = "scan-unavailable-authority";
    enqueue_provider_pull_item(&state, device, "durable-before-failstop", "intact").await;
    state
        .store
        .ordinary_handle()
        .unwrap()
        .fail("synthetic authority fail-stop");
    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json(app, "/v2/messages/pull", json!({"device_key":device})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body.get("success"), Some(&json!(true)));
    assert!(body.get("data").is_none_or(Value::is_null));
    let inspect = sqlx::SqlitePool::connect(&db_url).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM provider_pull_queue")
            .fetch_one(&inspect)
            .await
            .unwrap(),
        1
    );
    inspect.close().await;
}
