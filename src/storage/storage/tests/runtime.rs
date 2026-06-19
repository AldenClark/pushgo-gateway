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
async fn dispatch_targets_cache_invalidates_on_device_route_update() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-update-invalidate").await;
    let device_key = "dispatch-targets-route-update-device-key";
    let old_token = "android-token-route-update-old-000000000000000001";
    let new_token = "android-token-route-update-new-000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        old_token,
        "route-update-invalidate",
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
    match &first[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, old_token);
        }
        other => panic!("expected provider target before route update, got {other:?}"),
    }

    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(new_token.to_string()),
            updated_at: effective_at + 1,
        })
        .await
        .expect("route update should succeed");

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-route-update fetch should succeed");
    assert_eq!(second.len(), 1);
    match &second[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, new_token);
        }
        other => panic!("expected provider target after route update, got {other:?}"),
    }
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
async fn channel_password_argon2_hash_is_upgraded_to_blake3_after_successful_verify() {
    let ctx = setup_sqlite_storage("channel-password-upgrade").await;
    let channel_id = [7u8; 16];
    let alias = "legacy-password-channel";
    let password = "pw123456";
    let argon2_hash = hash_channel_password_argon2(password).expect("argon2 hash should succeed");
    assert!(argon2_hash.starts_with("$argon2"));

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id[..])
    .bind(&argon2_hash)
    .bind(alias)
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("insert channel should succeed");

    let info = ctx
        .storage
        .channel_info_with_password(channel_id, password)
        .await
        .expect("channel_info_with_password should succeed");
    let info = info.expect("channel must exist");
    assert_eq!(info.alias, alias);
    assert!(info.password_hash.starts_with("$pushgo-blake3$v=1$"));

    let upgraded_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query password hash should succeed");
    assert!(upgraded_hash.starts_with("$pushgo-blake3$v=1$"));

    let cached = ctx
        .storage
        .channel_info_with_password(channel_id, password)
        .await
        .expect("cached channel_info_with_password should succeed")
        .expect("channel should stay cached");
    assert_eq!(cached.alias, alias);
    assert_eq!(cached.password_hash, upgraded_hash);
    let snapshot = ctx.storage.cache_memory_snapshot();
    assert_eq!(snapshot.channel_info_cache_entries, 1);
    assert!(snapshot.channel_info_password_hash_bytes >= upgraded_hash.len());
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
            platform,
        } => {
            assert_eq!(private_device_id, &device_id);
            assert_eq!(private_device_key.as_deref(), Some(device_key));
            assert_eq!(*platform, Platform::ANDROID);
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
async fn dispatch_targets_skip_mqtt_provider_route_rows() {
    let ctx = setup_sqlite_storage("dispatch-targets-skip-mqtt-provider-route").await;
    let token = "android-token-skip-mqtt-provider-route-000000000001";
    let device_key = "dispatch-targets-skip-mqtt-provider-route-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "skip-mqtt-provider-route",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    sqlx::query(
        "UPDATE devices \
         SET platform = 'mqtt', platform_code = ?, channel_type = 'apns', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(Platform::MQTT.to_byte() as i64)
    .bind("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    .bind(now + 1)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("direct mqtt provider route mutation should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 2)
        .await
        .expect("dispatch target fetch should succeed");
    assert!(
        targets.is_empty(),
        "mqtt provider route rows must not become provider dispatch targets"
    );
}

#[tokio::test]
async fn dispatch_targets_include_mqtt_private_platform() {
    let ctx = setup_sqlite_storage("dispatch-targets-mqtt-private-platform").await;
    let token = "android-token-mqtt-private-platform-00000000000001";
    let device_key = "dispatch-targets-mqtt-private-platform-device";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "mqtt-private-platform",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    sqlx::query(
        "UPDATE devices \
         SET platform = 'mqtt', platform_code = ?, channel_type = 'private', provider_token = NULL, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(Platform::MQTT.to_byte() as i64)
    .bind(now + 1)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("direct mqtt private route mutation should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 2)
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Private {
            device_id: target_device_id,
            device_key: target_device_key,
            platform,
        } => {
            assert_eq!(target_device_id, &device_id);
            assert_eq!(target_device_key.as_deref(), Some(device_key));
            assert_eq!(*platform, Platform::MQTT);
        }
        other => panic!("expected mqtt private target, got {other:?}"),
    }
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
async fn dispatch_targets_dedupe_duplicate_provider_token_routes() {
    let ctx = setup_sqlite_storage("dispatch-targets-dedupe-provider-token").await;
    let token = "android-token-dedupe-provider-token-0000000001";
    let canonical_device_key = "dispatch-targets-dedupe-provider-token-current";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        canonical_device_key,
        token,
        "route-token-dedupe",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let canonical_updated_at = chrono::Utc::now().timestamp_millis();
    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: canonical_device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(token.to_string()),
            updated_at: canonical_updated_at,
        })
        .await
        .expect("canonical route refresh should succeed");

    let stale_route = DeviceRouteRecordRow {
        device_key: "dispatch-targets-dedupe-provider-token-stale".to_string(),
        platform: Platform::ANDROID.name().to_string(),
        channel_type: Platform::ANDROID.channel_type().to_string(),
        provider_token: Some(token.to_string()),
        updated_at: canonical_updated_at - 1_000,
    }
    .persistence_values()
    .expect("stale route should derive persistence values");
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(stale_route.device_id.as_slice())
    .bind(stale_route.token_raw.as_slice())
    .bind(stale_route.platform_code)
    .bind(&stale_route.device_key)
    .bind(&stale_route.platform)
    .bind(&stale_route.channel_type)
    .bind(stale_route.provider_token.as_deref())
    .bind(stale_route.updated_at)
    .execute(&mut conn)
    .await
    .expect("stale duplicate route insert should succeed");
    sqlx::query(
        "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
         VALUES (?, ?, 'active', ?, ?)",
    )
    .bind(&subscribe.channel_id[..])
    .bind(stale_route.device_id.as_slice())
    .bind(stale_route.updated_at)
    .bind(stale_route.updated_at)
    .execute(&mut conn)
    .await
    .expect("stale duplicate subscription insert should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider {
            provider_token,
            device_key,
            ..
        } => {
            assert_eq!(provider_token, token);
            assert_eq!(device_key, canonical_device_key);
        }
        other => panic!("expected provider target after dedupe, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_pull_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-pull-lifecycle").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "provider-pull-activity-device";
    let provider_token = "android-token-provider-pull-activity-000000000000000001";
    let device_id = derive_private_device_id(device_key);
    let stale_activity = now - 120_000;
    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(provider_token.to_string()),
            updated_at: stale_activity,
        })
        .await
        .expect("device route should be inserted");
    let delivery_id = "delivery-provider-lifecycle-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3, 4].into(),
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
            provider_token,
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
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let refreshed_at: i64 =
        sqlx::query_scalar("SELECT route_updated_at FROM devices WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("route activity should be queryable");
    assert_eq!(refreshed_at, now + 1);

    let pulled_again = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 2)
        .await
        .expect("second pull should succeed");
    assert!(pulled_again.is_none());
}

#[tokio::test]
async fn provider_pull_uses_legacy_queue_payload_when_shared_payload_missing() {
    let ctx = setup_sqlite_storage("provider-pull-legacy-queue-payload").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [17; 16];
    let delivery_id = "delivery-provider-legacy-queue-001";
    let legacy_payload = vec![0xAB, 0xCD, 0xEF];

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO provider_pull_queue \
         (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(delivery_id)
    .bind(&legacy_payload)
    .bind(legacy_payload.len() as i64)
    .bind(now)
    .bind(now + 300_000)
    .bind(Platform::ANDROID.name())
    .bind("fcm-token-legacy-001")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("legacy provider pull row insert should succeed");
    drop(conn);

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("pull should succeed")
        .expect("item should exist");
    assert_eq!(pulled.payload, legacy_payload.into());
}

#[tokio::test]
async fn provider_ack_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-ack-lifecycle").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-ack-001";
    let message = PrivateMessage {
        payload: vec![8, 6, 4, 2].into(),
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
            payload: vec![index as u8].into(),
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
async fn provider_pull_drains_queue_and_orphan_payloads_on_read() {
    let ctx = setup_sqlite_storage("provider-pull-drains-orphan-payloads").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-drain-orphan-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 600_000,
    };

    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("insert shared private payload should succeed");

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO provider_pull_queue \
         (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
         VALUES (?, ?, X'', 0, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(delivery_id)
    .bind(message.sent_at)
    .bind(message.expires_at)
    .bind(Platform::ANDROID.name())
    .bind("fcm-token-provider-drain-orphan-001")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("provider pull queue insert should succeed");
    let payload_count_before: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("private payload count before pull should succeed");
    assert_eq!(payload_count_before, 1);
    drop(conn);

    let pulled = ctx
        .storage
        .pull_provider_items(device_id, now + 1, 10)
        .await
        .expect("provider pull should succeed");
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].delivery_id, delivery_id);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let queue_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("provider queue count after pull should succeed");
    let payload_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("private payload count after pull should succeed");
    assert_eq!(queue_count_after, 0);
    assert_eq!(payload_count_after, 0);
}

#[tokio::test]
async fn migrate_provider_pending_to_private_outbox_respects_device_capacity() {
    let ctx = setup_sqlite_storage("provider-to-private-migration-capacity").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [6; 16];
    let provider_token = "fcm-token-migration-capacity-001";

    let existing_delivery = "delivery-private-existing-capacity-001";
    let existing_message = PrivateMessage {
        payload: vec![9, 9, 9].into(),
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
                claimed_by: None,
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
            payload: vec![index as u8, 1, 2].into(),
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

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
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
async fn migrate_private_pending_to_provider_queue_batches_payloads_and_clears_outbox() {
    let ctx = setup_sqlite_storage("private-to-provider-migration-batch").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [6; 16];
    let provider_token = "fcm-token-private-to-provider-batch-001";
    let delivery_ids = [
        "delivery-private-to-provider-001",
        "delivery-private-to-provider-002",
        "delivery-private-to-provider-003",
    ];

    for (index, delivery_id) in delivery_ids.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8, 4, 5].into(),
            size: 3,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        ctx.storage
            .insert_private_message(delivery_id, &message)
            .await
            .expect("private payload should be inserted");
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + index as i64,
                    created_at: now + index as i64,
                    claimed_at: None,
                    claimed_by: None,
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
            .expect("private outbox should be inserted");
    }

    let missing_delivery_id = "delivery-private-to-provider-missing-payload";
    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(missing_delivery_id)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now + 10)
    .bind(now + 10)
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("dangling private outbox should be inserted");
    drop(conn);

    let migrated = ctx
        .storage
        .migrate_private_pending_to_provider_queue(device_id, Platform::ANDROID, provider_token)
        .await
        .expect("private->provider migration should succeed");
    assert_eq!(migrated, delivery_ids.len());

    let private_pending = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private outbox count should succeed");
    assert_eq!(private_pending, 0);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let provider_pending: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("provider pull count should be queryable");
    assert_eq!(provider_pending, delivery_ids.len() as i64);

    for delivery_id in delivery_ids {
        let payload_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
                .bind(delivery_id)
                .fetch_one(&mut conn)
                .await
                .expect("payload count should be queryable");
        assert_eq!(payload_exists, 1);
    }
    let missing_payload_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(missing_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("missing payload count should be queryable");
    assert_eq!(missing_payload_exists, 0);
}

#[tokio::test]
async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
    let ctx = setup_sqlite_storage("private-payload-cleanup").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_a: DeviceId = [1; 16];
    let device_b: DeviceId = [2; 16];

    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6].into(),
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
        claimed_by: None,
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
async fn private_outbox_claim_lease_blocks_duplicate_active_claims() {
    let ctx = setup_sqlite_storage("private-outbox-claim-lease").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [42; 16];
    let delivery_id = "delivery-claim-lease-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("private message should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
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
        .expect("private outbox should be inserted");

    let first_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now,
                16,
                now + 30_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-a"),
            ),
        )
        .await
        .expect("first claim should succeed");
    assert_eq!(first_claim.len(), 1);
    assert_eq!(first_claim[0].claimed_by.as_deref(), Some("worker-a"));

    let duplicate_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now + 1_000,
                16,
                now + 40_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-b"),
            ),
        )
        .await
        .expect("duplicate active claim should not fail");
    assert!(
        duplicate_claim.is_empty(),
        "active lease must prevent duplicate claim by another worker"
    );

    let expired_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now + 31_000,
                16,
                now + 60_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-b"),
            ),
        )
        .await
        .expect("expired lease claim should succeed");
    assert_eq!(expired_claim.len(), 1);
    assert_eq!(expired_claim[0].claimed_by.as_deref(), Some("worker-b"));
    assert_eq!(expired_claim[0].claimed_at, Some(now + 60_000));
}

#[tokio::test]
async fn private_expired_cleanup_removes_expired_payloads_and_dangling_outbox() {
    let ctx = setup_sqlite_storage("private-expired-cleanup-batch").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [3; 16];
    let expired_delivery_id = "expired-private-cleanup-delivery";
    let dangling_delivery_id = "dangling-private-cleanup-delivery";

    ctx.storage
        .insert_private_message(
            expired_delivery_id,
            &PrivateMessage {
                payload: vec![1, 2, 3].into(),
                size: 3,
                sent_at: now - 10_000,
                expires_at: now - 1_000,
            },
        )
        .await
        .expect("expired payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: expired_delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now - 10_000,
                created_at: now - 10_000,
                claimed_at: None,
                claimed_by: None,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now - 10_000,
            },
        )
        .await
        .expect("expired outbox should be inserted");

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(dangling_delivery_id)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now - 9_000)
    .bind(now - 9_000)
    .bind(now)
    .bind(now - 9_000)
    .execute(&mut conn)
    .await
    .expect("dangling outbox should be inserted");
    drop(conn);

    let removed = ctx
        .storage
        .cleanup_private_expired_data(now, 16)
        .await
        .expect("private cleanup should succeed");
    assert_eq!(removed, 2);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let remaining_payloads: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(expired_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("payload count should be queryable");
    let remaining_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE delivery_id IN (?, ?)")
            .bind(expired_delivery_id)
            .bind(dangling_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("outbox count should be queryable");
    assert_eq!(remaining_payloads, 0);
    assert_eq!(remaining_outbox, 0);
}

#[tokio::test]
async fn orphan_channel_cleanup_ignores_historical_stats_rows() {
    let ctx = setup_sqlite_storage("orphan-channel-cleanup-ignores-stats").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 10 * 60 * 1000;
    let stats_channel_id = [8u8; 16];
    let removable_channel_id = [9u8; 16];

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    for (channel_id, alias) in [
        (stats_channel_id, "orphan-with-historical-stats"),
        (removable_channel_id, "orphan-removable-without-stats"),
    ] {
        sqlx::query(
            "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
             VALUES (?, 'test-password-hash', ?, ?, ?)",
        )
        .bind(&channel_id[..])
        .bind(alias)
        .bind(old)
        .bind(old)
        .execute(&mut conn)
        .await
        .expect("test channel should be inserted");
    }
    sqlx::query("CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BLOB NOT NULL, bucket_date TEXT NOT NULL, messages_routed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))")
        .execute(&mut conn)
        .await
        .expect("legacy stats table should be created");
    sqlx::query("INSERT INTO channel_stats_daily (channel_id, bucket_date, messages_routed) VALUES (?, '2026-05-25', 1)")
        .bind(&stats_channel_id[..])
        .execute(&mut conn)
        .await
        .expect("legacy stats row should be inserted");
    drop(conn);

    let cleanup = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(cleanup.orphan_channels_pruned, 2);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let stats_channel_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&stats_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("stats channel count should be queryable");
    let removable_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&removable_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("removable channel count should be queryable");
    assert_eq!(stats_channel_exists, 0);
    assert_eq!(removable_exists, 0);
}

#[tokio::test]
async fn maintenance_cleanup_dry_run_does_not_remove_orphan_channels() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-dry-run-orphan-channel").await;
    let now = 1_700_000_000_000_i64;
    let removable_channel_id = [0x73; 16];
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, 'hash', 'dry-run-orphan-channel', ?, ?)",
    )
    .bind(&removable_channel_id[..])
    .bind(now - 600_000)
    .bind(now - 600_000)
    .execute(&mut conn)
    .await
    .expect("orphan channel should be inserted");
    drop(conn);

    let dry_run = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                dry_run: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("dry-run cleanup should succeed");
    assert_eq!(dry_run.orphan_channels_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let still_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&removable_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("orphan channel should be queryable after dry-run");
    assert_eq!(still_exists, 1);
    drop(conn);

    let cleanup = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("real cleanup should succeed");
    assert_eq!(cleanup.orphan_channels_pruned, 1);
}

#[tokio::test]
async fn private_outbox_batch_prunes_device_overflow_and_orphan_payloads() {
    let ctx = setup_sqlite_storage("private-outbox-batch-prunes-device").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [3; 16];
    let mut batch = Vec::new();

    for index in 0_i64..3 {
        let delivery_id = format!("delivery-batch-prune-{index}");
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index,
            expires_at: now + 300_000,
        };
        ctx.storage
            .insert_private_message(&delivery_id, &message)
            .await
            .expect("insert private message should succeed");
        batch.push(PrivateOutboxBatchEntry {
            device_id,
            entry: PrivateOutboxEntry {
                delivery_id,
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now + index,
                created_at: now + index,
                claimed_at: None,
                claimed_by: None,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now + index,
            },
        });
    }

    let pruned = ctx
        .storage
        .enqueue_private_outbox_batch(&batch, 2, 100, None)
        .await
        .expect("batch enqueue should succeed");
    assert_eq!(pruned, 1);
    assert_eq!(
        ctx.storage
            .count_private_outbox_for_device(device_id)
            .await
            .expect("count should succeed"),
        2
    );
    assert!(
        ctx.storage
            .load_private_message("delivery-batch-prune-0")
            .await
            .expect("payload lookup should succeed")
            .is_none()
    );
    assert!(
        ctx.storage
            .load_private_message("delivery-batch-prune-2")
            .await
            .expect("payload lookup should succeed")
            .is_some()
    );
}

#[tokio::test]
async fn private_outbox_batch_protects_current_delivery_when_pruning() {
    let ctx = setup_sqlite_storage("private-outbox-batch-protects-current").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];

    for index in 0_i64..2 {
        let delivery_id = format!("delivery-batch-protected-old-{index}");
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index,
            expires_at: now + 300_000,
        };
        ctx.storage
            .insert_private_message(&delivery_id, &message)
            .await
            .expect("insert old private message should succeed");
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id,
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + index,
                    created_at: now + index,
                    claimed_at: None,
                    claimed_by: None,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now + index,
                },
            )
            .await
            .expect("enqueue old outbox should succeed");
    }

    let current_delivery_id = "delivery-batch-protected-current";
    let current_message = PrivateMessage {
        payload: vec![9].into(),
        size: 1,
        sent_at: now + 3,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(current_delivery_id, &current_message)
        .await
        .expect("insert current private message should succeed");
    let pruned = ctx
        .storage
        .enqueue_private_outbox_batch(
            &[PrivateOutboxBatchEntry {
                device_id,
                entry: PrivateOutboxEntry {
                    delivery_id: current_delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + 3,
                    created_at: now + 3,
                    claimed_at: None,
                    claimed_by: None,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now + 3,
                },
            }],
            2,
            100,
            Some(current_delivery_id),
        )
        .await
        .expect("batch enqueue should succeed");

    assert_eq!(pruned, 1);
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, current_delivery_id)
            .await
            .expect("current outbox lookup should succeed")
            .is_some()
    );
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, "delivery-batch-protected-old-0")
            .await
            .expect("old outbox lookup should succeed")
            .is_none()
    );
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
        payload: vec![1, 2, 3].into(),
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
                claimed_by: None,
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
                payload: vec![4, 5, 6].into(),
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

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
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
    drop(conn);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
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
async fn maintenance_cleanup_keeps_recent_pending_op_dedupe_for_full_stale_window() {
    let ctx = setup_sqlite_storage("maintenance-op-dedupe-stale-window").await;
    let now = 1_700_000_000_000_i64;
    let recent_key = "maintenance-op-dedupe-recent";
    let stale_key = "maintenance-op-dedupe-stale";

    ctx.storage
        .reserve_op_dedupe_pending(recent_key, "delivery-recent-pending", now - 119_000)
        .await
        .expect("recent pending op dedupe should be reserved");
    ctx.storage
        .reserve_op_dedupe_pending(stale_key, "delivery-stale-pending", now - 121_000)
        .await
        .expect("stale pending op dedupe should be reserved");

    ctx.storage
        .run_maintenance_cleanup(now, MaintenanceCleanupConfig::default())
        .await
        .expect("maintenance cleanup should succeed");

    let mut conn = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("sqlite dispatch sidecar connection should succeed");
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC")
            .fetch_all(&mut conn)
            .await
            .expect("op dedupe rows should be queryable");

    assert_eq!(
        rows,
        vec![(
            recent_key.to_string(),
            DedupeState::Pending.as_str().to_string()
        )]
    );
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
                payload: vec![3, 2, 1].into(),
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
        payload: vec![7, 8, 9].into(),
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
                    claimed_by: None,
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
                payload: vec![1].into(),
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
                payload: vec![2].into(),
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

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
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
async fn maintenance_cleanup_keeps_subscription_after_recent_device_activity() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-recent-device-activity").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let device_key = "maintenance-recent-activity-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-recent-activity-0001",
        "maintenance-recent-activity",
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
    drop(conn);

    ctx.storage
        .touch_device_activity(device_id, now)
        .await
        .expect("device activity touch should succeed");

    let cleanup = ctx
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
    assert_eq!(cleanup.stale_subscriptions_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, "active");
}

#[tokio::test]
async fn maintenance_cleanup_freezes_inactive_subscriptions_before_hard_delete() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-subscription-lifecycle").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 240_000;
    let device_key = "maintenance-subscription-lifecycle-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-subscription-lifecycle-0001",
        "maintenance-subscription-lifecycle",
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
        "UPDATE channel_subscriptions SET status = 'inactive', updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription should be marked inactive");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, now)
        .await
        .expect("dispatch targets should be queryable");
    assert!(
        targets.is_empty(),
        "inactive subscriptions must not receive dispatch targets"
    );

    let frozen = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: false,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should freeze inactive subscription");
    assert_eq!(frozen.stale_subscriptions_pruned, 0);
    assert_eq!(frozen.frozen_subscriptions_pruned, 1);
    assert_eq!(frozen.soft_deleted_devices_pruned, 0);

    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, crate::storage::SUBSCRIPTION_STATUS_FROZEN);

    let hard_deleted = ctx
        .storage
        .run_maintenance_cleanup(
            now + 120_000,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should delete removable frozen route");
    assert_eq!(hard_deleted.soft_deleted_devices_pruned, 1);

    let device_exists: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_id = ?")
        .bind(&device_id[..])
        .fetch_one(&mut conn)
        .await
        .expect("device count should be queryable");
    assert_eq!(device_exists, 0);
}

#[tokio::test]
async fn maintenance_cleanup_blocks_freeze_and_delete_with_pending_private_outbox() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-private-outbox-gate").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 240_000;
    let device_key = "maintenance-private-outbox-gate-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-private-outbox-gate-0001",
        "maintenance-private-outbox-gate",
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
        "UPDATE channel_subscriptions SET status = 'inactive', updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription should be marked inactive");
    drop(conn);

    let delivery_id = "maintenance-private-outbox-gate-delivery";
    ctx.storage
        .insert_private_message(
            delivery_id,
            &PrivateMessage {
                payload: vec![4, 5, 6].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
        )
        .await
        .expect("pending private payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: old,
                created_at: old,
                claimed_at: None,
                claimed_by: None,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now + 300_000,
                last_error_code: None,
                last_error_detail: None,
                updated_at: old,
            },
        )
        .await
        .expect("pending private outbox should be inserted");

    let blocked = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should run with pending outbox");
    assert_eq!(blocked.frozen_subscriptions_pruned, 0);
    assert_eq!(blocked.soft_deleted_devices_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, crate::storage::SUBSCRIPTION_STATUS_INACTIVE);
    drop(conn);

    ctx.storage
        .ack_private_delivery(device_id, delivery_id)
        .await
        .expect("pending private outbox should be cleared");

    let advanced = ctx
        .storage
        .run_maintenance_cleanup(
            now + 120_000,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should advance after outbox clears");
    assert_eq!(advanced.frozen_subscriptions_pruned, 1);
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
        payload: envelope.clone().into(),
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
        claimed_by: None,
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
async fn provider_invalid_token_cleanup_unsubscribes_and_clears_private_outbox() {
    let ctx = setup_sqlite_storage("provider-invalid-token-cleanup").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "provider-invalid-token-cleanup-device";
    let provider_token = "android-provider-token-invalid-cleanup-0000000001";
    let private_device_id = derive_private_device_id(device_key);
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        provider_token,
        "invalid-token-cleanup",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    ctx.storage
        .bind_private_token(private_device_id, Platform::ANDROID, provider_token)
        .await
        .expect("private token binding should succeed");

    let delivery_id = "provider-invalid-token-cleanup-delivery";
    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", delivery_id);
    let envelope = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("private envelope should encode");
    let message = PrivateMessage {
        payload: envelope.clone().into(),
        size: envelope.len(),
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("private message should insert");
    ctx.storage
        .enqueue_private_outbox(
            private_device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
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
        .expect("private outbox should enqueue");

    let runtime_counters = crate::runtime_counters::RuntimeCounterCollector::spawn_with_mode(
        ctx.storage.clone(),
        false,
        crate::runtime_config::GatewayRuntimeProfile::Small,
    );
    crate::delivery_core::execution::provider::cleanup_invalid_provider_token(
        crate::delivery_core::execution::provider::ProviderInvalidTokenCleanup {
            store: &ctx.storage,
            private: None,
            runtime_counters: runtime_counters.as_ref(),
            channel_id: subscribe.channel_id,
            channel_id_text: &crate::value::ChannelId::from(subscribe.channel_id).to_string(),
            device_key,
            platform: Platform::ANDROID,
            device_token: provider_token,
            provider: "FCM",
            correlation_id: "provider-invalid-token-cleanup-test",
        },
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, now + 1)
        .await
        .expect("dispatch targets should load");
    assert!(
        targets.is_empty(),
        "invalid provider token cleanup must unsubscribe the provider route from the channel"
    );
    let outbox = ctx
        .storage
        .list_private_outbox(private_device_id, 16)
        .await
        .expect("private outbox should load");
    assert!(
        outbox.is_empty(),
        "invalid provider token cleanup must clear linked private outbox rows"
    );
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

#[tokio::test]
async fn upsert_device_route_coalesces_duplicate_provider_identities() {
    let ctx = setup_sqlite_storage("route-coalesces-duplicate-provider-identities").await;
    let token = "android-token-provider-identity-coalesce-0000001";
    let old_device_key = "provider-identity-old-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        old_device_key,
        token,
        "provider-identity-old",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let old_device_id = derive_private_device_id(old_device_key);
    let now = chrono::Utc::now().timestamp_millis();
    let delivery_id = "delivery-provider-identity-coalesce-001";
    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            old_device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            token,
        )
        .await
        .expect("old device provider queue enqueue should succeed");

    let new_device_key = "provider-identity-new-device-key";
    let new_route = DeviceRouteRecordRow {
        device_key: new_device_key.to_string(),
        platform: Platform::ANDROID.name().to_string(),
        channel_type: Platform::ANDROID.channel_type().to_string(),
        provider_token: Some(token.to_string()),
        updated_at: now + 1,
    };
    ctx.storage
        .upsert_device_route(&new_route)
        .await
        .expect("new route upsert should coalesce duplicates");

    let routes = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes should succeed");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].device_key, new_device_key);

    let old_channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(old_device_key)
        .await
        .expect("list old device subscriptions should succeed");
    assert!(old_channels.is_empty());
    let new_channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(new_device_key)
        .await
        .expect("list new device subscriptions should succeed");
    assert_eq!(new_channels, vec![channel_id]);

    let new_device_id = derive_private_device_id(new_device_key);
    let migrated = ctx
        .storage
        .pull_provider_items(new_device_id, now + 10, 10)
        .await
        .expect("provider queue pull should succeed");
    assert_eq!(migrated.len(), 1);
    assert_eq!(migrated[0].delivery_id, delivery_id);

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 10)
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider { device_key, .. } => {
            assert_eq!(device_key, new_device_key);
        }
        other => panic!("expected provider target after coalescing identities, got {other:?}"),
    }
}
