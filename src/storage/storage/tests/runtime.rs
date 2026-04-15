use super::*;

async fn seed_provider_route_snapshot(
    storage: &Storage,
    device_key: &str,
    token: &str,
    updated_at: i64,
) {
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: "fcm".to_string(),
            provider_token: Some(token.to_string()),
            updated_at,
        })
        .await
        .expect("provider route snapshot should be persisted");
}

#[tokio::test]
async fn dispatch_targets_cache_hits_within_ttl_and_expires() {
    let ctx = setup_sqlite_storage("dispatch-targets-cache").await;
    let token = "android-token-cache-hit-0000000000000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("cache-test"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");
    seed_provider_route_snapshot(
        &ctx.storage,
        "dispatch-targets-cache-device-key",
        token,
        chrono::Utc::now().timestamp(),
    )
    .await;
    let channel_id = subscribe.channel_id;
    let effective_at = chrono::Utc::now().timestamp();

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ?")
        .bind(&channel_id[..])
        .execute(&mut conn)
        .await
        .expect("direct delete should succeed");

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("cached fetch should succeed");
    assert_eq!(second.len(), 1);

    sleep(Duration::from_millis(2300)).await;

    let third = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp())
        .await
        .expect("post-ttl fetch should succeed");
    assert_eq!(third.len(), 0);
}

#[tokio::test]
async fn dispatch_targets_cache_invalidates_on_unsubscribe() {
    let ctx = setup_sqlite_storage("dispatch-targets-invalidate").await;
    let token = "android-token-cache-invalidate-000000000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("cache-invalidate"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");
    seed_provider_route_snapshot(
        &ctx.storage,
        "dispatch-targets-invalidate-device-key",
        token,
        chrono::Utc::now().timestamp(),
    )
    .await;
    let channel_id = subscribe.channel_id;
    let effective_at = chrono::Utc::now().timestamp();

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);

    let removed = ctx
        .storage
        .unsubscribe_channel(channel_id, token, Platform::ANDROID)
        .await
        .expect("unsubscribe should succeed");
    assert!(removed);

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp())
        .await
        .expect("post-invalidation fetch should succeed");
    assert_eq!(second.len(), 0);
}

#[tokio::test]
async fn dispatch_targets_respect_route_snapshot_when_present() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-snapshot").await;
    let token = "android-token-route-snapshot-000000000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("route-snapshot"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp();
    seed_provider_route_snapshot(
        &ctx.storage,
        "dispatch-targets-route-snapshot-key",
        token,
        now,
    )
    .await;
    let effective_at = now + 100;

    let initial = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("initial fetch should succeed");
    assert_eq!(initial.len(), 1);

    let device_id = DeviceInfo::from_token(Platform::ANDROID, token)
        .expect("device token should parse")
        .device_id();
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    // Route snapshot says private, so provider subscription row should be ignored.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'private', provider_token = NULL, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(now + 2)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to private should succeed");
    let filtered_private = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 101)
        .await
        .expect("fetch with private route snapshot should succeed");
    assert!(
        filtered_private.is_empty(),
        "provider rows must be filtered when route snapshot is private"
    );

    // Route snapshot says provider but token mismatch, so row should still be ignored.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'fcm', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind("android-token-route-snapshot-mismatch")
    .bind(now + 4)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to mismatched provider token should succeed");
    let filtered_token_mismatch = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 102)
        .await
        .expect("fetch with mismatched provider token should succeed");
    assert!(
        filtered_token_mismatch.is_empty(),
        "provider rows must be filtered when route snapshot token mismatches"
    );

    // Route snapshot matches provider channel and token, row should be dispatchable again.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'fcm', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(token)
    .bind(now + 6)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to matching provider token should succeed");
    let restored = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 103)
        .await
        .expect("fetch with matching route snapshot should succeed");
    assert_eq!(restored.len(), 1);
}

#[tokio::test]
async fn dispatch_targets_drop_provider_rows_without_route_snapshot() {
    let ctx = setup_sqlite_storage("dispatch-targets-no-route-snapshot").await;
    let token = "android-token-no-route-snapshot-0000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("route-missing"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp();
    let device_id = DeviceInfo::from_token(Platform::ANDROID, token)
        .expect("device token should parse")
        .device_id();

    seed_provider_route_snapshot(
        &ctx.storage,
        "dispatch-targets-no-route-snapshot-key",
        token,
        now,
    )
    .await;
    let with_snapshot = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 100)
        .await
        .expect("fetch with route snapshot should succeed");
    assert_eq!(with_snapshot.len(), 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "UPDATE devices \
         SET route_updated_at = NULL \
         WHERE device_id = ?",
    )
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route_updated_at reset should succeed");

    let without_snapshot = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 101)
        .await
        .expect("fetch without route snapshot should succeed");
    assert!(
        without_snapshot.is_empty(),
        "provider rows without route snapshot must be filtered out"
    );
}

#[tokio::test]
async fn dispatch_targets_fallback_to_route_device_key_when_subscription_key_missing() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-device-key-fallback").await;
    let token = "android-token-route-device-key-fallback-000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("route-device-key-fallback"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");
    let channel_id = subscribe.channel_id;
    let device_id = DeviceInfo::from_token(Platform::ANDROID, token)
        .expect("device token should parse")
        .device_id();

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "UPDATE devices SET device_key = ?, channel_type = 'fcm', provider_token = ?, route_updated_at = ? WHERE device_id = ?",
    )
    .bind("route-device-key-fallback")
    .bind(token)
    .bind(chrono::Utc::now().timestamp())
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("device route snapshot update should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp() + 1)
        .await
        .expect("fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider { device_key, .. } => {
            assert_eq!(device_key.as_deref(), Some("route-device-key-fallback"));
        }
        other => panic!("expected provider target, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_pull_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-pull-lifecycle").await;

    let now = chrono::Utc::now().timestamp();
    let device_id: DeviceId = [3; 16];
    let delivery_id = "delivery-provider-lifecycle-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3, 4],
        size: 4,
        sent_at: now,
        expires_at: now + 300,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-token-001",
        )
        .await
        .expect("enqueue should succeed");

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("pull should succeed");
    assert!(pulled.is_some());
    assert_eq!(
        pulled.expect("item should exist").delivery_id,
        delivery_id.to_string()
    );

    let pulled_again = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 2)
        .await
        .expect("second pull should succeed");
    assert!(pulled_again.is_none());
}

#[tokio::test]
async fn provider_ack_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-ack-lifecycle").await;

    let now = chrono::Utc::now().timestamp();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-ack-001";
    let message = PrivateMessage {
        payload: vec![8, 6, 4, 2],
        size: 4,
        sent_at: now,
        expires_at: now + 300,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-token-ack-001",
        )
        .await
        .expect("enqueue should succeed");

    let acked = ctx
        .storage
        .ack_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("ack should succeed");
    assert!(acked.is_some());
    assert_eq!(
        acked.expect("item should exist").delivery_id,
        delivery_id.to_string()
    );

    let acked_again = ctx
        .storage
        .ack_provider_item(device_id, delivery_id, now + 2)
        .await
        .expect("second ack should succeed");
    assert!(acked_again.is_none());
}

#[tokio::test]
async fn provider_pull_items_limit_and_order_works() {
    let ctx = setup_sqlite_storage("provider-pull-limit-order").await;

    let now = chrono::Utc::now().timestamp();
    let device_id: DeviceId = [5; 16];
    let ids = [
        "delivery-provider-batch-001",
        "delivery-provider-batch-002",
        "delivery-provider-batch-003",
    ];
    for (index, delivery_id) in ids.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8],
            size: 1,
            sent_at: now + index as i64,
            expires_at: now + 600,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                device_id,
                delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-batch-001",
            )
            .await
            .expect("enqueue should succeed");
    }

    let first_batch = ctx
        .storage
        .pull_provider_items(device_id, now + 1, 2)
        .await
        .expect("first pull batch should succeed");
    assert_eq!(first_batch.len(), 2);
    assert_eq!(first_batch[0].delivery_id, ids[0]);
    assert_eq!(first_batch[1].delivery_id, ids[1]);

    let second_batch = ctx
        .storage
        .pull_provider_items(device_id, now + 2, 2)
        .await
        .expect("second pull batch should succeed");
    assert_eq!(second_batch.len(), 1);
    assert_eq!(second_batch[0].delivery_id, ids[2]);
}

#[tokio::test]
async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
    let ctx = setup_sqlite_storage("private-payload-cleanup").await;

    let now = chrono::Utc::now().timestamp();
    let device_a: DeviceId = [1; 16];
    let device_b: DeviceId = [2; 16];

    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6],
        size: 4,
        sent_at: now,
        expires_at: now + 300,
    };

    let shared_delivery_id = "delivery-private-shared-001";
    ctx.storage
        .insert_private_message(shared_delivery_id, &message)
        .await
        .expect("insert shared payload should succeed");

    let entry = PrivateOutboxEntry {
        delivery_id: shared_delivery_id.to_string(),
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
    };
    ctx.storage
        .enqueue_private_outbox(device_a, &entry)
        .await
        .expect("enqueue entry a should succeed");
    ctx.storage
        .enqueue_private_outbox(device_b, &entry)
        .await
        .expect("enqueue entry b should succeed");

    ctx.storage
        .ack_private_delivery(device_a, shared_delivery_id)
        .await
        .expect("ack entry a should succeed");
    let shared_still_exists = ctx
        .storage
        .load_private_message(shared_delivery_id)
        .await
        .expect("shared payload lookup should succeed");
    assert!(shared_still_exists.is_some());

    ctx.storage
        .ack_private_delivery(device_b, shared_delivery_id)
        .await
        .expect("ack entry b should succeed");
    let shared_after_all_acked = ctx
        .storage
        .load_private_message(shared_delivery_id)
        .await
        .expect("shared payload second lookup should succeed");
    assert!(shared_after_all_acked.is_none());
}

#[tokio::test]
async fn provider_pull_clears_original_private_outbox_delivery() {
    let ctx = setup_sqlite_storage("provider-pull-original-outbox-cleanup").await;

    let now = chrono::Utc::now().timestamp();
    let device_id: DeviceId = [7; 16];
    let platform = Platform::IOS;
    let provider_token = "ios-provider-token-provider-pull-cleanup-001";
    let original_delivery_id = "delivery-original-private-001";
    let provider_delivery_id = original_delivery_id;

    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", original_delivery_id);
    let envelope = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("provider pull envelope should encode");
    let message = PrivateMessage {
        payload: envelope.clone(),
        size: envelope.len(),
        sent_at: now,
        expires_at: now + 300,
    };

    ctx.storage
        .insert_private_message(original_delivery_id, &message)
        .await
        .expect("insert original private payload should succeed");

    let original_entry = PrivateOutboxEntry {
        delivery_id: original_delivery_id.to_string(),
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
    };
    ctx.storage
        .enqueue_private_outbox(device_id, &original_entry)
        .await
        .expect("enqueue original private outbox should succeed");
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            provider_delivery_id,
            &message,
            platform,
            provider_token,
        )
        .await
        .expect("enqueue provider pull item should succeed");

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, provider_delivery_id, now + 1)
        .await
        .expect("pull provider item should succeed");
    assert!(pulled.is_some());

    let original_outbox_after_pull = ctx
        .storage
        .load_private_outbox_entry(device_id, original_delivery_id)
        .await
        .expect("load original outbox after pull should succeed");
    assert!(original_outbox_after_pull.is_none());

    let original_payload_after_pull = ctx
        .storage
        .load_private_message(original_delivery_id)
        .await
        .expect("load original payload after pull should succeed");
    assert!(original_payload_after_pull.is_none());
}

#[tokio::test]
async fn load_device_routes_uses_devices_snapshot_not_channel_subscriptions() {
    let ctx = setup_sqlite_storage("device-routes-semantics").await;
    let token = "android-route-semantics-000000000000000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("route-sem"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed");

    let routes_before = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes before upsert should succeed");
    assert!(
        routes_before.is_empty(),
        "subscription rows must not be treated as route snapshots"
    );

    let route = DeviceRouteRecordRow {
        device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
        platform: "android".to_string(),
        channel_type: "private".to_string(),
        provider_token: None,
        updated_at: chrono::Utc::now().timestamp(),
    };
    ctx.storage
        .upsert_device_route(&route)
        .await
        .expect("upsert route should succeed");

    let routes_after = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes after upsert should succeed");
    assert_eq!(routes_after.len(), 1);
    assert_eq!(routes_after[0].device_key, route.device_key);
    assert_eq!(routes_after[0].platform, route.platform);
    assert_eq!(routes_after[0].channel_type, route.channel_type);

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp())
        .await
        .expect("dispatch targets fetch should succeed");
    assert_eq!(targets.len(), 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let route_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE route_updated_at IS NOT NULL")
            .fetch_one(&mut conn)
            .await
            .expect("route row count should be queryable");
    let subscription_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM channel_subscriptions WHERE device_key IS NOT NULL",
    )
    .fetch_one(&mut conn)
    .await
    .expect("subscription row count should be queryable");
    assert_eq!(route_rows, 1);
    assert_eq!(subscription_rows, 0);
}
