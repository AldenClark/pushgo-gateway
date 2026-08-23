use super::*;

#[tokio::test]
async fn widget_push_subscription_registers_current_widgets() {
    let state = build_test_state().await;
    let app = super::super::build_router(state.clone(), "<html>docs</html>");
    let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let (status, body) = post_json(
        app,
        "/v1/widget-push/subscription",
        json!({
            "device_key": "widget-device-1",
            "platform": "ios",
            "token": token,
            "widgets": [
                {
                    "kind": "io.ethan.pushgo.widgets.unread",
                    "family": "systemMedium"
                },
                {
                    "kind": "io.ethan.pushgo.widgets.critical-events",
                    "family": "systemSmall"
                }
            ],
            "schema_version": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "subscription body: {body:?}");
    assert_eq!(
        response_data(&body)
            .get("widget_count")
            .and_then(Value::as_u64),
        Some(2)
    );
}

#[tokio::test]
async fn message_dispatch_queues_widget_push_for_matching_widgets() {
    let (state, receivers) = build_test_state_with_receivers().await;
    let storage = state.store.clone();
    let channel_id = seed_provider_channel_for_router_test(
        &state,
        "widget-message-device",
        "widget-message-channel",
        "password-1234",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        Platform::IOS,
    )
    .await;
    let widget_token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    state
        .store
        .upsert_widget_push_subscriptions(
            "widget-message-device",
            Platform::IOS,
            widget_token,
            &[crate::storage::WidgetPushSubscriptionRecord {
                device_key: "widget-message-device".to_string(),
                platform: "ios".to_string(),
                token: widget_token.to_string(),
                widget_kind: "io.ethan.pushgo.widgets.unread".to_string(),
                family: "systemMedium".to_string(),
                schema_version: 1,
                created_at: 1_700_000_000_000,
                updated_at: 1_700_000_000_000,
            }],
            1,
            1_700_000_000_000,
        )
        .await
        .expect("widget subscription should persist");

    let app = super::super::build_router(state, "<html>docs</html>");
    let (status, body) = post_json(
        app,
        "/message",
        json!({
            "channel_id": channel_id,
            "password": "password-1234",
            "title": "Widget refresh",
            "body": "Refresh unread widget"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "message body: {body:?}");

    let job = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        receivers
            .recv_widget_push_for_test()
            .await
            .expect("widget push queue should stay open")
    })
    .await
    .expect("widget push job should be queued");
    assert_eq!(job.device_token.as_ref(), widget_token);
    assert_eq!(job.platform, Platform::IOS);
    assert!(
        job.widget_kinds
            .iter()
            .any(|kind| kind == "io.ethan.pushgo.widgets.unread")
    );
    let now = chrono::Utc::now().timestamp_millis();
    let durable = storage
        .claim_provider_dispatch_job(
            "APNS_WIDGETS",
            None,
            "widget-order-observer",
            now,
            now + 20_000,
        )
        .await
        .expect("Widget durable job should be readable")
        .expect("Widget durable job should be claimable");
    assert!(
        durable.record.coalesce_order > 0,
        "Widget latest-state work must inherit the core submission order"
    );
}
