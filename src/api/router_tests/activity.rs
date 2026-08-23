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

    let before_request = chrono::Utc::now().timestamp_millis();
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
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
    let after_request = chrono::Utc::now().timestamp_millis();
    assert_eq!(status, StatusCode::OK, "event update body: {body:?}");

    let job = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let job = receivers
                .recv_live_activity_for_test()
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

    let lease = state
        .store
        .claim_provider_dispatch_job(
            "APNS_LIVE_ACTIVITY",
            None,
            "activity-router-test",
            after_request,
            after_request + 20_000,
        )
        .await
        .expect("durable activity job claim should succeed")
        .expect("historical event_time must not make a newly received activity job expired");
    assert!(
        (before_request..=after_request).contains(&lease.record.accepted_at),
        "durable admission must use Gateway time, not historical event_time: {:?}",
        lease.record
    );
    assert_eq!(
        lease.record.expires_at,
        lease.record.accepted_at + 60 * 60 * 1000
    );
    let durable: crate::dispatch::DurableProviderJob =
        serde_json::from_slice(&lease.record.payload_blob).expect("durable activity job decode");
    let durable_payload = durable
        .into_apns()
        .expect("durable activity job should remain APNs");
    let durable_json = serde_json::to_value(durable_payload.direct_payload.as_ref())
        .expect("durable APNs payload should serialize");
    assert_eq!(
        durable_json["aps"]["timestamp"], 1_700_000_000,
        "producer event_time remains in the ActivityKit payload"
    );
}

#[tokio::test]
async fn live_activity_enqueue_failure_after_core_commit_preserves_http_success() {
    let (state, _receivers) = build_test_state_with_receivers().await;
    let channel_id = seed_provider_channel_for_router_test(
        &state,
        "activity-post-commit-device",
        "activity-post-commit-channel",
        "password-1234",
        "abababababababababababababababababababababababababababababababab",
        Platform::IOS,
    )
    .await;
    state
        .store
        .upsert_live_activity_token(&crate::storage::LiveActivityTokenRecord {
            activity_key: "event:event-post-commit".to_string(),
            channel_id: Some(crate::api::parse_channel_id(&channel_id).expect("channel id")),
            token: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string(),
            platform: "ios".to_string(),
            schema_version: 1,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            expires_at: None,
        })
        .await
        .expect("activity token should persist");
    state.store.inject_live_activity_enqueue_failures(1);

    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let (status, body) = post_json(
        app,
        "/event/update",
        json!({
            "channel_id": channel_id,
            "password": "password-1234",
            "event_id": "event-post-commit",
            "event_time": 1_700_000_000_123i64,
            "title": "Committed core event",
            "status": "open"
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a supplemental enqueue failure after core commit must not become a retry-inducing 500: {body:?}"
    );
    assert_eq!(
        state
            .store
            .count_pending_provider_dispatch_jobs("APNS")
            .await
            .expect("core APNs jobs should count"),
        1,
        "the already committed main event delivery remains authoritative"
    );
    assert_eq!(
        state
            .store
            .count_pending_provider_dispatch_jobs("APNS_LIVE_ACTIVITY")
            .await
            .expect("activity jobs should count"),
        0,
        "fault injection must target only the supplemental Live Activity enqueue"
    );

    // The first pass fenced the frozen core manifest for a short jittered
    // backoff. Once eligible, the normal startup/maintenance recovery path
    // must replay it and fill the missing supplemental outbox row.
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;
    assert_eq!(
        crate::api::handlers::message::recover_pending_dispatch_submissions(&state)
            .await
            .expect("durable submission recovery should succeed"),
        1,
        "recovery must finalize the pending core manifest"
    );
    assert_eq!(
        state
            .store
            .count_pending_provider_dispatch_jobs("APNS_LIVE_ACTIVITY")
            .await
            .expect("recovered activity jobs should count"),
        1,
        "recovery must durably create the previously failed supplemental job"
    );
    let now = chrono::Utc::now().timestamp_millis();
    let lease = state
        .store
        .claim_provider_dispatch_job(
            "APNS_LIVE_ACTIVITY",
            None,
            "activity-recovery-test",
            now,
            now + 20_000,
        )
        .await
        .expect("recovered activity job claim should succeed")
        .expect("recovered activity job must be claimable");
    assert_eq!(lease.record.provider, "APNS_LIVE_ACTIVITY");
}

#[tokio::test]
async fn live_activity_fanout_persists_one_coalescible_job_per_registered_token() {
    let (state, _receivers) = build_test_state_with_receivers().await;
    let activity_key = "event:activity-fanout";
    for (token, updated_at) in [
        (
            "3333333333333333333333333333333333333333333333333333333333333333",
            1_700_000_000_000,
        ),
        (
            "4444444444444444444444444444444444444444444444444444444444444444",
            1_700_000_000_001,
        ),
    ] {
        state
            .store
            .upsert_live_activity_token(&crate::storage::LiveActivityTokenRecord {
                activity_key: activity_key.to_string(),
                channel_id: None,
                token: token.to_string(),
                platform: "ios".to_string(),
                schema_version: 1,
                created_at: updated_at,
                updated_at,
                expires_at: None,
            })
            .await
            .expect("activity token should persist");
    }

    crate::api::handlers::activity::dispatch_event_activity_update(
        state.clone(),
        crate::api::handlers::activity::EventActivityUpdate {
            event_id: "activity-fanout".to_string(),
            action: crate::api::handlers::activity::EventActivityAction::Update,
            title: Some("Fanout".to_string()),
            state: Some("open".to_string()),
            severity: None,
            accepted_at_millis: 1_800_000_000_000,
            updated_at_millis: 1_700_000_000_123,
        },
        10,
        "activity-fanout-submission-10",
    )
    .await
    .expect("fanout should be durably materialized");

    crate::api::handlers::activity::dispatch_event_activity_update(
        state.clone(),
        crate::api::handlers::activity::EventActivityUpdate {
            event_id: "activity-fanout".to_string(),
            action: crate::api::handlers::activity::EventActivityAction::Update,
            title: Some("Fanout".to_string()),
            state: Some("latest".to_string()),
            severity: None,
            // Simulate a restart followed by wall-clock rollback. Durable
            // acceptance order, not this timestamp, owns latest-state order.
            accepted_at_millis: 1_799_999_999_000,
            updated_at_millis: 1_700_000_000_456,
        },
        11,
        "activity-fanout-submission-11",
    )
    .await
    .expect("newer fanout state should be durably materialized");

    crate::api::handlers::activity::dispatch_event_activity_update(
        state.clone(),
        crate::api::handlers::activity::EventActivityUpdate {
            event_id: "activity-fanout".to_string(),
            action: crate::api::handlers::activity::EventActivityAction::Update,
            title: Some("Fanout".to_string()),
            state: Some("stale-replay".to_string()),
            severity: None,
            accepted_at_millis: 1_800_000_000_000,
            updated_at_millis: 1_700_000_000_100,
        },
        10,
        "activity-fanout-submission-10",
    )
    .await
    .expect("an older idempotent replay should be ignored without failing");

    assert_eq!(
        state
            .store
            .count_pending_provider_dispatch_jobs("APNS_LIVE_ACTIVITY")
            .await
            .expect("pending activity jobs should count"),
        2,
        "each registered token needs an independent durable coalescing slot"
    );
    let now = 1_800_000_000_001;
    let lease = state
        .store
        .claim_provider_dispatch_job(
            "APNS_LIVE_ACTIVITY",
            None,
            "activity-latest-state-test",
            now,
            now + 20_000,
        )
        .await
        .expect("latest activity job claim should succeed")
        .expect("one token job should be claimable");
    let durable: crate::dispatch::DurableProviderJob =
        serde_json::from_slice(&lease.record.payload_blob).expect("activity job should decode");
    let payload = durable.into_apns().expect("activity job should be APNs");
    let json = serde_json::to_value(payload.direct_payload.as_ref())
        .expect("activity payload should serialize");
    assert_eq!(json["aps"]["content-state"]["state"], "latest");
    assert_eq!(json["aps"]["timestamp"], 1_700_000_000);
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
                .recv_live_activity_for_test()
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
