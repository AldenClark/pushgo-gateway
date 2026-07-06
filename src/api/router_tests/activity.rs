use super::*;

#[tokio::test]
async fn activity_register_and_unregister_round_trip_token_storage() {
    let state = build_test_state().await;
    let channel_id = seed_provider_channel_for_router_test(
        &state,
        "activity-device",
        "activity-channel",
        "password-1234",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        Platform::IOS,
    )
    .await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let (status, body) = post_json(
        app.clone(),
        "/v1/activity/register",
        json!({
            "activity_key": "event:event-1",
            "channel_id": channel_id,
            "token": token,
            "platform": "ios",
            "schema_version": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register body: {body:?}");

    let stored = state
        .store
        .list_live_activity_tokens("event:event-1")
        .await
        .expect("activity tokens should list");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].token, token);
    assert_eq!(stored[0].platform, "ios");
    assert_eq!(stored[0].schema_version, 1);
    assert!(stored[0].channel_id.is_some());

    let (status, body) = post_json(
        app,
        "/v1/activity/unregister",
        json!({
            "activity_key": "event:event-1",
            "token": token,
            "platform": "ios",
            "schema_version": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unregister body: {body:?}");
    assert_eq!(
        response_data(&body).get("deleted").and_then(Value::as_u64),
        Some(1)
    );

    let stored = state
        .store
        .list_live_activity_tokens("event:event-1")
        .await
        .expect("activity tokens should list after unregister");
    assert!(stored.is_empty());
}

#[tokio::test]
async fn activity_register_rejects_invalid_payloads() {
    let state = build_test_state().await;
    let app = super::super::build_router(state, "<html>docs</html>");

    for payload in [
        json!({
            "activity_key": "event:event-1",
            "token": "not-hex-token",
            "platform": "ios",
            "schema_version": 1
        }),
        json!({
            "activity_key": "event:event-1",
            "token": "0123456789abcdef",
            "platform": "watchos",
            "schema_version": 1
        }),
        json!({
            "activity_key": "event:event-1",
            "token": "0123456789abcdef",
            "platform": "ios",
            "schema_version": 2
        }),
    ] {
        let (status, body) = post_json(app.clone(), "/v1/activity/register", payload).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "invalid payload should fail validation: {body:?}"
        );
    }
}

#[tokio::test]
async fn event_update_dispatches_registered_live_activity_token() {
    let (state, receivers) = build_test_state_with_receivers().await;
    let channel_id = seed_provider_channel_for_router_test(
        &state,
        "activity-event-device",
        "activity-event-channel",
        "password-1234",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        Platform::IOS,
    )
    .await;
    let activity_token = "1111111111111111111111111111111111111111111111111111111111111111";
    state
        .store
        .upsert_live_activity_token(&crate::storage::LiveActivityTokenRecord {
            activity_key: "event:event-activity-1".to_string(),
            channel_id: Some(crate::api::parse_channel_id(&channel_id).expect("channel id")),
            token: activity_token.to_string(),
            platform: "ios".to_string(),
            schema_version: 1,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            expires_at: None,
        })
        .await
        .expect("activity token should persist");

    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json(
        app,
        "/event/update",
        json!({
            "channel_id": channel_id,
            "password": "password-1234",
            "event_id": "event-activity-1",
            "event_time": 1_700_000_000_123i64,
            "title": "Database latency",
            "status": "open",
            "severity": "critical"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "event update body: {body:?}");

    let job = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let job = receivers
                .recv_apns_for_test()
                .await
                .expect("activity APNs queue should stay open");
            if job.direct_payload.push_type_header() == "liveactivity" {
                break job;
            }
        }
    })
    .await
    .expect("activity APNs job should be queued");
    assert_eq!(job.device_token.as_ref(), activity_token);
    assert_eq!(job.direct_payload.push_type_header(), "liveactivity");
    assert_eq!(
        job.direct_payload.topic_override(),
        Some("io.ethan.pushgo.push-type.liveactivity")
    );
    let payload = serde_json::to_value(job.direct_payload.as_ref())
        .expect("live activity payload should serialize");
    assert_eq!(payload["aps"]["event"], "update");
    assert_eq!(payload["aps"]["content-state"]["title"], "Database latency");
    assert_eq!(payload["aps"]["content-state"]["state"], "open");
    assert_eq!(payload["aps"]["content-state"]["severity"], "critical");
}

#[tokio::test]
async fn thing_scoped_event_update_dispatches_registered_live_activity_token() {
    let (state, receivers) = build_test_state_with_receivers().await;
    let channel_id = seed_provider_channel_for_router_test(
        &state,
        "thing-activity-event-device",
        "thing-activity-event-channel",
        "password-1234",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        Platform::IOS,
    )
    .await;
    let activity_token = "2222222222222222222222222222222222222222222222222222222222222222";
    state
        .store
        .upsert_live_activity_token(&crate::storage::LiveActivityTokenRecord {
            activity_key: "event:thing-event-activity-1".to_string(),
            channel_id: Some(crate::api::parse_channel_id(&channel_id).expect("channel id")),
            token: activity_token.to_string(),
            platform: "ios".to_string(),
            schema_version: 1,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            expires_at: None,
        })
        .await
        .expect("activity token should persist");

    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json(
        app,
        "/thing/server-1/event/update",
        json!({
            "channel_id": channel_id,
            "password": "password-1234",
            "event_id": "thing-event-activity-1",
            "event_time": 1_700_000_000_123i64,
            "title": "Server latency",
            "status": "open",
            "severity": "high"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "thing event update body: {body:?}");

    let job = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let job = receivers
                .recv_apns_for_test()
                .await
                .expect("activity APNs queue should stay open");
            if job.direct_payload.push_type_header() == "liveactivity" {
                break job;
            }
        }
    })
    .await
    .expect("thing-scoped activity APNs job should be queued");
    assert_eq!(job.device_token.as_ref(), activity_token);
    let payload = serde_json::to_value(job.direct_payload.as_ref())
        .expect("live activity payload should serialize");
    assert_eq!(payload["aps"]["event"], "update");
    assert_eq!(payload["aps"]["content-state"]["title"], "Server latency");
}
