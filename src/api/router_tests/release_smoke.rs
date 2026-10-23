use super::*;

use axum::body::to_bytes;
use sqlx::{Connection, SqliteConnection};

type ExpectedOperation = (String, Option<String>, Option<(&'static str, &'static str)>);

const GATEWAY_TOKEN: &str = "release-smoke-gateway-token";
const CIPHERTEXT_FIXTURE: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj";

async fn get_json_with_auth(app: axum::Router, path: &str, bearer: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("host", "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
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

#[tokio::test]
async fn release_smoke_core_lifecycle() {
    let (mut state, _receivers, db_url) = build_test_state_with_receivers_and_db_url().await;
    state.auth = AuthMode::SharedToken(Arc::from(GATEWAY_TOKEN));
    let app = super::super::build_router(state.clone(), "<html>docs</html>");

    // The public HTTP boundary rejects unauthenticated access before touching the queue.
    let (unauthorized_status, _) = post_json(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
    )
    .await;
    assert_eq!(unauthorized_status, StatusCode::UNAUTHORIZED);

    let (status, registration) = post_json_with_auth(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register: {registration:?}");
    let device_key = response_string_field(&registration, "device_key").to_owned();
    assert!(!device_key.is_empty());

    let (status, route) = post_json_with_auth(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "release-smoke-fcm-token"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "route setup: {route:?}");

    let (status, subscription) = post_json_with_auth(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": device_key,
            "channel_name": "release-smoke-channel",
            "password": "smoke-password-123"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "subscribe: {subscription:?}");
    let channel_id = response_string_field(&subscription, "channel_id").to_owned();

    let (status, exists_before_rename) = get_json_with_auth(
        app.clone(),
        &format!("/channel/exists?channel_id={channel_id}"),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "channel exists: {exists_before_rename:?}"
    );
    assert_eq!(
        response_data(&exists_before_rename)
            .get("exists")
            .and_then(Value::as_bool),
        Some(true)
    );

    let (status, renamed) = post_json_with_auth(
        app.clone(),
        "/channel/rename",
        json!({
            "channel_id": channel_id,
            "channel_name": "release-smoke-renamed",
            "password": "smoke-password-123"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rename: {renamed:?}");
    assert_eq!(
        response_data(&renamed)
            .get("channel_name")
            .and_then(Value::as_str),
        Some("release-smoke-renamed")
    );

    let (status, second_registration) = post_json_with_auth(
        app.clone(),
        "/device/register",
        json!({ "platform": "android" }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second subscriber registration: {second_registration:?}"
    );
    let second_device_key = response_string_field(&second_registration, "device_key").to_owned();
    let (status, second_route) = post_json_with_auth(
        app.clone(),
        "/channel/device",
        json!({
            "device_key": second_device_key,
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": "release-smoke-second-fcm-token"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second route setup: {second_route:?}"
    );
    let expected_title = "release smoke payload";
    let expected_body = "accepted through the real message handler";
    let mut expected_operations: Vec<ExpectedOperation> = Vec::new();
    let (status, accepted) = post_json_with_auth(
        app.clone(),
        "/message",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "title": expected_title,
            "body": expected_body,
            "ciphertext": CIPHERTEXT_FIXTURE,
            "metadata": { "suite": "gateway-release-smoke" }
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "message submit: {accepted:?}");
    let op_id = response_data(&accepted)
        .get("op_id")
        .and_then(Value::as_str)
        .expect("accepted message should return its operation ID");
    expected_operations.push((op_id.to_owned(), Some(CIPHERTEXT_FIXTURE.to_owned()), None));
    let ordinary = state.store.ordinary_handle().unwrap();
    let ordinary_status = ordinary
        .status(op_id)
        .await
        .expect("HTTP acceptance must follow the ordinary identity COMMIT");
    assert_eq!(
        ordinary_status["entity_id"],
        response_data(&accepted)["message_id"]
    );
    assert_eq!(ordinary_status["status"], "provider_queued");
    assert!(
        state
            .store
            .load_sender_submit_status(op_id)
            .await
            .unwrap()
            .is_none(),
        "ordinary HTTP submission must not also create a legacy sender-status row"
    );

    // The second device joins after this message, so it must not gain a
    // historical delivery when it subscribes below.
    let (status, second_subscription) = post_json_with_auth(
        app.clone(),
        "/channel/subscribe",
        json!({
            "device_key": second_device_key,
            "channel_id": channel_id,
            "password": "smoke-password-123"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second subscriber channel join: {second_subscription:?}"
    );
    assert_eq!(
        response_string_field(&second_subscription, "channel_id"),
        channel_id
    );

    // Exercise the real entity handlers through positive create/update/finalize
    // lifecycles. Ciphertext is opaque to Gateway and must pass through intact.
    let (status, thing_created) = post_json_with_auth(
        app.clone(),
        "/thing/create",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "observed_at": 1_790_000_000_001i64,
            "title": "release smoke thing",
            "ciphertext": CIPHERTEXT_FIXTURE
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "thing create: {thing_created:?}");
    let thing_id = response_string_field(&thing_created, "thing_id").to_owned();
    expected_operations.push((
        response_string_field(&thing_created, "op_id").to_owned(),
        Some(CIPHERTEXT_FIXTURE.to_owned()),
        Some(("state", "active")),
    ));

    let (status, thing_updated) = post_json_with_auth(
        app.clone(),
        "/thing/update",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "thing_id": thing_id,
            "observed_at": 1_790_000_000_002i64,
            "title": "release smoke thing updated"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "thing update: {thing_updated:?}");
    assert_eq!(response_string_field(&thing_updated, "thing_id"), thing_id);
    expected_operations.push((
        response_string_field(&thing_updated, "op_id").to_owned(),
        None,
        Some(("state", "active")),
    ));

    let (status, thing_archived) = post_json_with_auth(
        app.clone(),
        "/thing/archive",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "thing_id": thing_id,
            "observed_at": 1_790_000_000_003i64
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "thing archive: {thing_archived:?}");
    assert_eq!(response_string_field(&thing_archived, "thing_id"), thing_id);
    expected_operations.push((
        response_string_field(&thing_archived, "op_id").to_owned(),
        None,
        Some(("state", "archived")),
    ));

    let (status, thing_deleted) = post_json_with_auth(
        app.clone(),
        "/thing/delete",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "thing_id": thing_id,
            "observed_at": 1_790_000_000_004i64
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "thing delete: {thing_deleted:?}");
    assert_eq!(response_string_field(&thing_deleted, "thing_id"), thing_id);
    expected_operations.push((
        response_string_field(&thing_deleted, "op_id").to_owned(),
        None,
        Some(("state", "deleted")),
    ));

    let event_time = 1_790_000_100_001i64;
    let (status, event_created) = post_json_with_auth(
        app.clone(),
        "/event/create",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "event_time": event_time,
            "title": "release smoke event",
            "status": "open",
            "message": "event created through the real handler",
            "severity": "normal",
            "ciphertext": CIPHERTEXT_FIXTURE
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "event create: {event_created:?}");
    let event_id = response_string_field(&event_created, "event_id").to_owned();
    expected_operations.push((
        response_string_field(&event_created, "op_id").to_owned(),
        Some(CIPHERTEXT_FIXTURE.to_owned()),
        Some(("event_state", "ongoing")),
    ));

    let (status, event_updated) = post_json_with_auth(
        app.clone(),
        "/event/update",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "event_id": event_id,
            "event_time": event_time + 1,
            "title": "release smoke event updated",
            "status": "active",
            "message": "event updated through the real handler",
            "severity": "high"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "event update: {event_updated:?}");
    assert_eq!(response_string_field(&event_updated, "event_id"), event_id);
    expected_operations.push((
        response_string_field(&event_updated, "op_id").to_owned(),
        None,
        Some(("event_state", "ongoing")),
    ));

    let (status, event_closed) = post_json_with_auth(
        app.clone(),
        "/event/close",
        json!({
            "channel_id": channel_id,
            "password": "smoke-password-123",
            "event_id": event_id,
            "event_time": event_time + 2,
            "ended_at": event_time + 2,
            "title": "release smoke event closed",
            "status": "closed",
            "message": "event closed through the real handler",
            "severity": "normal"
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "event close: {event_closed:?}");
    assert_eq!(response_string_field(&event_closed, "event_id"), event_id);
    expected_operations.push((
        response_string_field(&event_closed, "op_id").to_owned(),
        None,
        Some(("event_state", "closed")),
    ));

    assert_eq!(expected_operations.len(), 8);
    for (expected_op_id, _, _) in &expected_operations {
        if expected_op_id == op_id {
            assert_eq!(
                ordinary.status(expected_op_id).await.unwrap()["model"],
                "message"
            );
            continue;
        }
        assert!(
            state
                .store
                .load_sender_submit_status(expected_op_id)
                .await
                .expect("sender status lookup should work")
                .is_some(),
            "accepted operation should have durable sender status: {expected_op_id}"
        );
    }

    let (unauthorized_pull_status, _) = post_json(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
    )
    .await;
    assert_eq!(unauthorized_pull_status, StatusCode::UNAUTHORIZED);

    let (status, pull) = post_json_with_auth(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "v2 pull: {pull:?}");
    let items = response_data(&pull)
        .get("items")
        .and_then(Value::as_array)
        .expect("pull should return an item array");
    assert_eq!(
        items.len(),
        expected_operations.len(),
        "each accepted message, thing action, and event action should be pullable"
    );
    let mut delivery_ids = Vec::with_capacity(items.len());
    for (expected_op_id, expected_ciphertext, expected_lifecycle) in &expected_operations {
        let item = items
            .iter()
            .find(|item| {
                item.get("payload")
                    .and_then(|payload| payload.get("op_id"))
                    .and_then(Value::as_str)
                    == Some(expected_op_id.as_str())
            })
            .unwrap_or_else(|| panic!("pull should contain operation {expected_op_id}: {items:?}"));
        let delivery_id = item
            .get("delivery_id")
            .and_then(Value::as_str)
            .expect("pulled item should include its delivery ID");
        assert!(!delivery_id.is_empty(), "outer delivery ID must be present");
        delivery_ids.push(delivery_id.to_owned());
        let payload = item
            .get("payload")
            .and_then(Value::as_object)
            .expect("pulled item should include its canonical payload");
        if let Some(ciphertext) = expected_ciphertext {
            assert_eq!(
                payload.get("ciphertext").and_then(Value::as_str),
                Some(ciphertext.as_str()),
                "opaque ciphertext should survive accepted submit and provider pull"
            );
        }
        if let Some((field, expected_value)) = expected_lifecycle {
            assert_eq!(
                payload.get(*field).and_then(Value::as_str),
                Some(*expected_value),
                "server-derived entity lifecycle field should match its accepted action: {payload:?}"
            );
        }
    }
    let message_item = items
        .iter()
        .find(|item| {
            item.get("payload")
                .and_then(|payload| payload.get("op_id"))
                .and_then(Value::as_str)
                == Some(op_id)
        })
        .expect("pull should contain submitted message");
    let delivery_id = message_item
        .get("delivery_id")
        .and_then(Value::as_str)
        .expect("pulled message should include its delivery ID")
        .to_owned();
    let payload = message_item
        .get("payload")
        .and_then(Value::as_object)
        .expect("pulled message should include its canonical payload");
    assert_eq!(
        payload.get("title").and_then(Value::as_str),
        Some(expected_title)
    );
    assert_eq!(
        payload.get("body").and_then(Value::as_str),
        Some(expected_body)
    );
    assert_eq!(
        payload.get("metadata").and_then(Value::as_str),
        Some("{\"suite\":\"gateway-release-smoke\"}")
    );
    // A real second subscriber cannot retire the first subscriber's delivery.
    let (status, foreign_ack) = post_json_with_auth(
        app.clone(),
        "/v2/messages/ack",
        json!({
            "device_key": second_device_key,
            "delivery_ids": [delivery_id]
        }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "foreign ACK: {foreign_ack:?}");
    assert_eq!(
        response_data(&foreign_ack)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(0)
    );

    let (status, still_queued) = post_json_with_auth(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_data(&still_queued)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(expected_operations.len()),
        "subscriber ACK must leave the owner's full batch pullable"
    );

    let (status, second_subscriber_pull) = post_json_with_auth(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": second_device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second subscriber pull: {second_subscriber_pull:?}"
    );
    let second_subscriber_items = response_data(&second_subscriber_pull)
        .get("items")
        .and_then(Value::as_array)
        .expect("second subscriber pull should return an item array");
    assert_eq!(
        second_subscriber_items.len(),
        expected_operations.len() - 1,
        "the later subscriber should receive only deliveries accepted after joining"
    );
    assert!(
        second_subscriber_items.iter().all(|item| {
            item.get("payload")
                .and_then(|payload| payload.get("op_id"))
                .and_then(Value::as_str)
                != Some(op_id)
        }),
        "the later subscriber must not receive the earlier message"
    );

    let second_delivery_ids = second_subscriber_items
        .iter()
        .map(|item| {
            item.get("delivery_id")
                .and_then(Value::as_str)
                .expect("second subscriber item should include delivery id")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let second_ack_request = json!({
        "device_key": second_device_key,
        "delivery_ids": second_delivery_ids
    });
    let (status, second_owner_ack) = post_json_with_auth(
        app.clone(),
        "/v2/messages/ack",
        second_ack_request.clone(),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second subscriber ACK: {second_owner_ack:?}"
    );
    assert_eq!(
        response_data(&second_owner_ack)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some((expected_operations.len() - 1) as u64)
    );
    let (status, owner_still_queued) = post_json_with_auth(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response_data(&owner_still_queued)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(expected_operations.len()),
        "second subscriber ACK must not retire the first subscriber's deliveries"
    );

    let ack_request = json!({
        "device_key": device_key,
        "delivery_ids": delivery_ids
    });
    let (status, ack) = post_json_with_auth(
        app.clone(),
        "/v2/messages/ack",
        ack_request.clone(),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner ACK: {ack:?}");
    assert_eq!(
        response_data(&ack)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(expected_operations.len() as u64)
    );
    let (status, duplicate_ack) =
        post_json_with_auth(app.clone(), "/v2/messages/ack", ack_request, GATEWAY_TOKEN).await;
    assert_eq!(status, StatusCode::OK, "duplicate ACK: {duplicate_ack:?}");
    assert_eq!(
        response_data(&duplicate_ack)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(0),
        "ACK should be idempotent"
    );

    let (status, second_duplicate_ack) = post_json_with_auth(
        app.clone(),
        "/v2/messages/ack",
        second_ack_request,
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duplicate second ACK: {second_duplicate_ack:?}"
    );
    assert_eq!(
        response_data(&second_duplicate_ack)
            .get("removed_count")
            .and_then(Value::as_u64),
        Some(0)
    );

    let (status, empty_pull) = post_json_with_auth(
        app.clone(),
        "/v2/messages/pull",
        json!({ "device_key": device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_data(&empty_pull)
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "ACKed delivery should no longer be pullable"
    );
    let (status, second_empty_pull) = post_json_with_auth(
        app,
        "/v2/messages/pull",
        json!({ "device_key": second_device_key }),
        GATEWAY_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_data(&second_empty_pull)
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "second subscriber ACK should retire only its own deliveries"
    );
    let mut inspect = SqliteConnection::connect(&format!("{db_url}?mode=ro"))
        .await
        .expect("isolated product database should allow bounded read-only inspection");
    let payload_bytes: i64 =
        sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE op_id = ?")
            .bind(op_id)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(payload_bytes, 0, "HTTP ACK must release the ordinary body");
    let old_ordinary_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sender_submit_status WHERE model = 'message'")
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(
        old_ordinary_rows, 0,
        "normal HTTP must have one ordinary authority"
    );
    assert_eq!(
        ordinary.status(op_id).await.unwrap()["entity_id"],
        ordinary_status["entity_id"]
    );
}
