use super::*;
use crate::routing::derive_private_device_id;

#[tokio::test]
async fn dispatch_targets_cache_hits_within_ttl_and_expires() {
    let ctx = setup_sqlite_storage("dispatch-targets-cache").await;
    let device_key = "dispatch-targets-cache-device-key";
    let token = "android-token-cache-hit-0000000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "cache-test",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
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
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("cached fetch should succeed");
    assert_eq!(second.len(), 1);

    sleep(Duration::from_millis(2300)).await;

    let third = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-ttl fetch should succeed");
    assert_eq!(third.len(), 0);
}

#[tokio::test]
async fn dispatch_targets_cache_invalidates_on_unsubscribe() {
    let ctx = setup_sqlite_storage("dispatch-targets-invalidate").await;
    let device_key = "dispatch-targets-invalidate-device-key";
    let token = "android-token-cache-invalidate-000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "cache-invalidate",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let effective_at = chrono::Utc::now().timestamp_millis();

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);

    let removed = ctx
        .storage
        .unsubscribe_channel_for_device_key(channel_id, device_key)
        .await
        .expect("unsubscribe should succeed");
    assert!(removed);

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-invalidation fetch should succeed");
    assert_eq!(second.len(), 0);
}

#[tokio::test]
async fn provider_subscriptions_can_be_managed_by_device_key() {
    let ctx = setup_sqlite_storage("provider-subscriptions-device-key").await;
    let device_key = "provider-subscriptions-device-key";
    let token = "android-token-device-key-management-000000000000001";
    seed_provider_route(
        &ctx.storage,
        device_key,
        Platform::ANDROID,
        token,
        chrono::Utc::now().timestamp_millis(),
    )
    .await;

    let subscribe = ctx
        .storage
        .subscribe_channel_for_device_key(
            None,
            Some("device-key-management"),
            "pw123456",
            device_key,
            token,
            Platform::ANDROID,
        )
        .await
        .expect("device-key subscribe should succeed");

    let channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(device_key)
        .await
        .expect("list subscribed channels by device key should succeed");
    assert_eq!(channels, vec![subscribe.channel_id]);

    let removed = ctx
        .storage
        .unsubscribe_channel_for_device_key(subscribe.channel_id, device_key)
        .await
        .expect("device-key unsubscribe should succeed");
    assert!(removed);

    let channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(device_key)
        .await
        .expect("list subscribed channels by device key should succeed");
    assert!(channels.is_empty());
}

#[tokio::test]
async fn dispatch_targets_follow_current_route_when_present() {
    let ctx = setup_sqlite_storage("dispatch-targets-current-route").await;
    let token = "android-token-current-route-000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "dispatch-targets-current-route-device-key",
        token,
        "current-route",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "dispatch-targets-current-route-device-key";
    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now).await;
    let effective_at = now + 100;

    let initial = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("initial fetch should succeed");
    assert_eq!(initial.len(), 1);

    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    // Membership should follow the current route and become private delivery.
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
        .expect("fetch with private current route should succeed");
    assert_eq!(filtered_private.len(), 1);
    match &filtered_private[0] {
        DispatchTarget::Private {
            device_id: private_device_id,
            device_key: private_device_key,
        } => {
            assert_eq!(private_device_id, &device_id);
            assert_eq!(private_device_key.as_deref(), Some(device_key));
        }
        other => panic!("expected private target after route switch, got {other:?}"),
    }

    // Current route says provider with a new token, so dispatch should follow the new token.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'fcm', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind("android-token-current-route-mismatch")
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
    assert_eq!(filtered_token_mismatch.len(), 1);
    match &filtered_token_mismatch[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, "android-token-current-route-mismatch");
        }
        other => panic!("expected provider target after route token update, got {other:?}"),
    }

    // Route snapshot can switch back again and dispatch should continue following devices.
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
        .expect("fetch with matching current route should succeed");
    assert_eq!(restored.len(), 1);
}

#[tokio::test]
async fn dispatch_targets_drop_provider_rows_without_current_route() {
    let ctx = setup_sqlite_storage("dispatch-targets-no-current-route").await;
    let token = "android-token-no-current-route-0000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "dispatch-targets-no-current-route-device-key",
        token,
        "route-missing",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "dispatch-targets-no-current-route-device-key";
    let device_id = derive_private_device_id(device_key);

    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now).await;
    let with_snapshot = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 100)
        .await
        .expect("fetch with current route should succeed");
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
        .expect("fetch without current route should succeed");
    assert!(
        without_snapshot.is_empty(),
        "provider rows without current route must be filtered out"
    );
}

#[tokio::test]
async fn dispatch_targets_use_route_device_key_as_single_source() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-device-key-source").await;
    let token = "android-token-route-device-key-source-000000001";
    let canonical_device_key = "route-device-key-source";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        canonical_device_key,
        token,
        "route-device-key-source",
        "pw123456",
        Platform::ANDROID,
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(
            subscribe.channel_id,
            chrono::Utc::now().timestamp_millis() + 1,
        )
        .await
        .expect("fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider { device_key, .. } => {
            assert_eq!(device_key.as_str(), canonical_device_key);
        }
        other => panic!("expected provider target, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_pull_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-pull-lifecycle").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [3; 16];
    let delivery_id = "delivery-provider-lifecycle-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3, 4],
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
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

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-ack-001";
    let message = PrivateMessage {
        payload: vec![8, 6, 4, 2],
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
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

    let now = chrono::Utc::now().timestamp_millis();
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
            expires_at: now + 600_000,
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
async fn migrate_provider_pending_to_private_outbox_respects_device_capacity() {
    let ctx = setup_sqlite_storage("provider-to-private-migration-capacity").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [6; 16];
    let provider_token = "fcm-token-migration-capacity-001";

    let existing_delivery = "delivery-private-existing-capacity-001";
    let existing_message = PrivateMessage {
        payload: vec![9, 9, 9],
        size: 3,
        sent_at: now,
        expires_at: now + 600_000,
    };
    ctx.storage
        .insert_private_message(existing_delivery, &existing_message)
        .await
        .expect("insert existing private message should succeed");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: existing_delivery.to_string(),
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
        .expect("enqueue existing private outbox should succeed");

    let provider_deliveries = [
        "delivery-provider-capacity-001",
        "delivery-provider-capacity-002",
        "delivery-provider-capacity-003",
    ];
    for (index, delivery_id) in provider_deliveries.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8, 1, 2],
            size: 3,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                device_id,
                delivery_id,
                &message,
                Platform::ANDROID,
                provider_token,
            )
            .await
            .expect("enqueue provider pull item should succeed");
    }

    let private_pending_before = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private pending count before migration should succeed");
    assert_eq!(private_pending_before, 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let provider_pending_before: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("provider pending count before migration should succeed");
    assert_eq!(provider_pending_before, 3);
    drop(conn);

    let migrated = ctx
        .storage
        .migrate_provider_pending_to_private_outbox(device_id, 30, 2)
        .await
        .expect("provider->private migration should succeed");
    assert_eq!(
        migrated, 1,
        "migration should only fill remaining private capacity"
    );

    let private_pending = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private pending count should succeed");
    assert_eq!(private_pending, 2);

    let mut migrated_provider_count = 0usize;
    for delivery_id in provider_deliveries {
        let exists = ctx
            .storage
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("private outbox lookup should succeed")
            .is_some();
        if exists {
            migrated_provider_count = migrated_provider_count.saturating_add(1);
        }
    }
    assert_eq!(migrated_provider_count, 1);

    let remaining_provider_items = ctx
        .storage
        .pull_provider_items(device_id, now + 100_000, 10)
        .await
        .expect("provider pull remaining items should succeed");
    assert_eq!(
        remaining_provider_items.len(),
        2,
        "provider queue should retain non-migrated items"
    );
}

#[tokio::test]
async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
    let ctx = setup_sqlite_storage("private-payload-cleanup").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_a: DeviceId = [1; 16];
    let device_b: DeviceId = [2; 16];

    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6],
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
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
async fn maintenance_cleanup_prunes_expired_runtime_rows_and_orphan_devices() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-defaults").await;
    let now = chrono::Utc::now().timestamp_millis();
    let stale_before = now - 120_000;
    let device_id: DeviceId = [11; 16];
    let old_route = DeviceRouteRecordRow {
        device_key: "maintenance-cleanup-orphan-device-key".to_string(),
        platform: "android".to_string(),
        channel_type: "private".to_string(),
        provider_token: None,
        updated_at: stale_before,
    };
    ctx.storage
        .upsert_device_route(&old_route)
        .await
        .expect("old orphan route should be persisted");

    let private_delivery_id = "maintenance-stale-private-outbox";
    let private_message = PrivateMessage {
        payload: vec![1, 2, 3],
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(private_delivery_id, &private_message)
        .await
        .expect("private payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: private_delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: stale_before,
                created_at: stale_before,
                claimed_at: None,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: stale_before,
                last_error_code: None,
                last_error_detail: None,
                updated_at: stale_before,
            },
        )
        .await
        .expect("stale private outbox should be inserted");

    let provider_delivery_id = "maintenance-expired-provider-pull";
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![4, 5, 6],
                size: 3,
                sent_at: stale_before,
                expires_at: stale_before,
            },
            Platform::ANDROID,
            "maintenance-expired-provider-token",
        )
        .await
        .expect("expired provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 60,
                orphan_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");

    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);
    assert_eq!(stats.orphan_devices_pruned, 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox")
        .fetch_one(&mut conn)
        .await
        .expect("outbox count should be queryable");
    let provider_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue")
        .fetch_one(&mut conn)
        .await
        .expect("provider pull count should be queryable");
    let route_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key = ?")
        .bind(&old_route.device_key)
        .fetch_one(&mut conn)
        .await
        .expect("device count should be queryable");
    assert_eq!(outbox_count, 0);
    assert_eq!(provider_count, 0);
    assert_eq!(route_count, 0);
}

#[tokio::test]
async fn maintenance_cleanup_keeps_orphan_candidates_with_live_private_references() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-live-references").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let session_device_key = "maintenance-live-session-device-key";
    let queue_device_key = "maintenance-live-queue-device-key";
    let session_device_id = derive_private_device_id(session_device_key);
    let queue_device_id = derive_private_device_id(queue_device_key);

    for device_key in [session_device_key, queue_device_key] {
        ctx.storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: "android".to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at: old,
            })
            .await
            .expect("old route should be persisted");
    }

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_sessions (session_id, device_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind("maintenance-live-session")
    .bind(&session_device_id[..])
    .bind(now + 300_000)
    .execute(&mut conn)
    .await
    .expect("live private session should be inserted");

    ctx.storage
        .enqueue_provider_pull_item(
            queue_device_id,
            "maintenance-live-provider-pull",
            &PrivateMessage {
                payload: vec![3, 2, 1],
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "maintenance-live-provider-token",
        )
        .await
        .expect("live provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");

    assert_eq!(stats.orphan_devices_pruned, 0);
    let route_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key IN (?, ?)")
            .bind(session_device_key)
            .bind(queue_device_key)
            .fetch_one(&mut conn)
            .await
            .expect("route count should be queryable");
    assert_eq!(route_count, 2);
}

#[tokio::test]
async fn maintenance_cleanup_does_not_delete_shared_delivery_for_other_devices() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-shared-delivery").await;
    let now = chrono::Utc::now().timestamp_millis();
    let stale = now - 120_000;
    let device_a: DeviceId = [21; 16];
    let device_b: DeviceId = [22; 16];
    let shared_private_delivery_id = "maintenance-shared-private-delivery";
    let private_message = PrivateMessage {
        payload: vec![7, 8, 9],
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(shared_private_delivery_id, &private_message)
        .await
        .expect("shared private payload should be inserted");
    for (device_id, updated_at) in [(device_a, stale), (device_b, now)] {
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: shared_private_delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: updated_at,
                    created_at: updated_at,
                    claimed_at: None,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: updated_at,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at,
                },
            )
            .await
            .expect("shared private outbox should be inserted");
    }

    let provider_delivery_id = "maintenance-shared-provider-delivery";
    ctx.storage
        .enqueue_provider_pull_item(
            device_a,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![1],
                size: 1,
                sent_at: stale,
                expires_at: stale,
            },
            Platform::ANDROID,
            "maintenance-shared-provider-token-a",
        )
        .await
        .expect("expired provider pull row should be inserted");
    ctx.storage
        .enqueue_provider_pull_item(
            device_b,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![2],
                size: 1,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "maintenance-shared-provider-token-b",
        )
        .await
        .expect("live provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);

    assert!(
        ctx.storage
            .load_private_outbox_entry(device_a, shared_private_delivery_id)
            .await
            .expect("device a private outbox lookup should succeed")
            .is_none()
    );
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_b, shared_private_delivery_id)
            .await
            .expect("device b private outbox lookup should succeed")
            .is_some()
    );
    assert!(
        ctx.storage
            .load_private_message(shared_private_delivery_id)
            .await
            .expect("shared private payload lookup should succeed")
            .is_some()
    );

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let live_provider_for_b: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(&device_b[..])
    .bind(provider_delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("provider pull count should be queryable");
    let expired_provider_for_a: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(&device_a[..])
    .bind(provider_delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("provider pull count should be queryable");
    assert_eq!(live_provider_for_b, 1);
    assert_eq!(expired_provider_for_a, 0);
}

#[tokio::test]
async fn maintenance_cleanup_keeps_active_subscriptions_until_switch_is_enabled() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-switches").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let device_key = "maintenance-active-subscription-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-active-subscription-0001",
        "maintenance-active-subscription",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("UPDATE devices SET route_updated_at = ? WHERE device_id = ?")
        .bind(old)
        .bind(&device_id[..])
        .execute(&mut conn)
        .await
        .expect("route timestamp should be aged");
    sqlx::query(
        "UPDATE channel_subscriptions SET updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription timestamp should be aged");

    let disabled = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(disabled.stale_subscriptions_pruned, 0);

    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, "active");

    let enabled = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_ttl_secs: 60,
                stale_subscription_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(enabled.stale_subscriptions_pruned, 1);
}

#[tokio::test]
async fn provider_pull_clears_original_private_outbox_delivery() {
    let ctx = setup_sqlite_storage("provider-pull-original-outbox-cleanup").await;

    let now = chrono::Utc::now().timestamp_millis();
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
        expires_at: now + 300_000,
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
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "device-routes-semantics-device-key",
        token,
        "route-sem",
        "pw123456",
        Platform::ANDROID,
    )
    .await;

    let routes_before = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes before upsert should succeed");
    assert_eq!(routes_before.len(), 1);

    let fallback_device_id = derive_private_device_id("device-routes-semantics-device-key");
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("DELETE FROM devices WHERE device_id = ?")
        .bind(&fallback_device_id[..])
        .execute(&mut conn)
        .await
        .expect("device snapshot delete should succeed");
    let routes_without_devices = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes after device delete should succeed");
    assert!(
        routes_without_devices.is_empty(),
        "subscription rows must not be treated as route state"
    );

    let route = DeviceRouteRecordRow {
        device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
        platform: "android".to_string(),
        channel_type: "private".to_string(),
        provider_token: None,
        updated_at: chrono::Utc::now().timestamp_millis(),
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
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp_millis())
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
    let subscription_rows: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
        .fetch_one(&mut conn)
        .await
        .expect("subscription row count should be queryable");
    assert_eq!(route_rows, 1);
    assert_eq!(subscription_rows, 1);
}
