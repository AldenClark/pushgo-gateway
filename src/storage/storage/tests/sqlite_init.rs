use super::*;

#[tokio::test]
async fn sqlite_cold_start_initializes_schema() {
    let ctx = setup_sqlite_storage_without_bootstrap("sqlite-cold-start").await;
    let token = "android-cold-start-000000000000000000000000000001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("cold-start"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed after cold-start schema init");
    let info = ctx
        .storage
        .channel_info(subscribe.channel_id)
        .await
        .expect("channel info should load");
    assert!(info.is_some());
}

#[tokio::test]
async fn sqlite_new_creates_parent_directories() {
    let dir = tempdir().expect("tempdir should be created");
    let nested_dir = dir.path().join("nested").join("gateway").join("db");
    let db_path = nested_dir.join("pushgo.sqlite");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    assert!(
        !nested_dir.exists(),
        "nested parent directory should not exist before init"
    );

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("sqlite storage should initialize and create parent directories");
    assert!(
        nested_dir.exists(),
        "sqlite parent directory should be created"
    );
    assert!(db_path.exists(), "sqlite db file should be created");

    let token = "android-parent-dir-create-0000000000000000000000000001";
    let subscribe = storage
        .subscribe_channel(
            None,
            Some("auto-parent"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed on auto-created sqlite path");
    let info = storage
        .channel_info(subscribe.channel_id)
        .await
        .expect("channel info should load");
    assert!(info.is_some());
}

#[tokio::test]
async fn sqlite_init_heals_missing_delivery_audit_audit_id_column() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-delivery-audit",
        &[ "CREATE TABLE IF NOT EXISTS delivery_audit (delivery_id TEXT NOT NULL, channel_id BLOB NOT NULL, device_key TEXT NOT NULL, entity_type TEXT, entity_id TEXT, op_id TEXT, path TEXT NOT NULL, status TEXT NOT NULL, error_code TEXT, created_at INTEGER NOT NULL)" ],
    )
    .await;

    let write = DeliveryAuditWrite {
        delivery_id: "delivery-heal-audit-id-1".to_string(),
        channel_id: [7; 16],
        device_key: "device-heal-audit-id-1".to_string(),
        entity_type: Some("message".to_string()),
        entity_id: Some("msg-heal-audit-id-1".to_string()),
        op_id: Some("op-heal-audit-id-1".to_string()),
        path: DeliveryAuditPath::Provider,
        status: DeliveryAuditStatus::Enqueued,
        error_code: None,
        created_at: chrono::Utc::now().timestamp(),
    };
    ctx.storage
        .append_delivery_audit(&write)
        .await
        .expect("append delivery audit should succeed after init healing");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let audit_id_is_set: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM delivery_audit WHERE audit_id IS NOT NULL")
            .fetch_one(&mut conn)
            .await
            .expect("delivery audit count should be queryable");
    assert_eq!(audit_id_is_set, 1);
}

#[tokio::test]
async fn sqlite_init_accepts_previous_schema_version_and_upgrades_meta() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-schema-version-upgrade",
        &[
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
            "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4')",
        ],
    )
    .await;

    let token = "android-schema-upgrade-000000000000000000000000000001";
    ctx.storage
        .subscribe_channel(
            None,
            Some("schema-upgrade"),
            "pw123456",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed after schema version upgrade");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let meta: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("schema meta query should succeed");
    assert_eq!(meta.as_deref(), Some(STORAGE_SCHEMA_VERSION));
}

#[tokio::test]
async fn sqlite_init_keeps_current_schema_version_and_backfills_new_tables() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-schema-version-current-backfill",
        &[
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
            "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-26-gateway-v5')",
        ],
    )
    .await;

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let has_mcp_state: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='mcp_state'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("sqlite master query should succeed");
    assert_eq!(has_mcp_state, 1);

    let meta: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("schema meta query should succeed");
    assert_eq!(meta.as_deref(), Some(STORAGE_SCHEMA_VERSION));
}

#[tokio::test]
async fn sqlite_init_heals_missing_devices_route_columns() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-devices-columns",
        &["CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY)"],
    )
    .await;

    let route = DeviceRouteRecordRow {
        device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
        platform: "android".to_string(),
        channel_type: "fcm".to_string(),
        provider_token: Some("android-heal-route-token-1".to_string()),
        updated_at: chrono::Utc::now().timestamp(),
    };
    ctx.storage
        .upsert_device_route(&route)
        .await
        .expect("upsert route should succeed after devices-column healing");

    let routes = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes should succeed");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].device_key, route.device_key);
    assert_eq!(routes[0].platform, route.platform);
    assert_eq!(routes[0].channel_type, route.channel_type);
    assert_eq!(routes[0].provider_token, route.provider_token);
}

#[tokio::test]
async fn sqlite_init_creates_missing_provider_pull_tables() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-provider-pull-tables",
        &["CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"],
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    let delivery_id = "delivery-heal-provider-table-1";
    let message = PrivateMessage {
        payload: vec![11, 22, 33],
        size: 3,
        sent_at: now,
        expires_at: now + 300,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-heal-provider-table-token-1",
            now,
        )
        .await
        .expect("enqueue provider pull item should succeed after table auto-create");

    let due = ctx
        .storage
        .list_provider_pull_retry_due(now + 1, 8)
        .await
        .expect("list provider due should succeed");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].delivery_id, delivery_id);
}

#[tokio::test]
async fn sqlite_init_heals_missing_private_outbox_columns() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-private-outbox-columns",
        &[ "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))" ],
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    let device_id: DeviceId = [8; 16];
    let entry = PrivateOutboxEntry {
        delivery_id: "delivery-heal-outbox-1".to_string(),
        status: OUTBOX_STATUS_PENDING.to_string(),
        attempts: 0,
        occurred_at: now - 1,
        created_at: now - 1,
        claimed_at: None,
        first_sent_at: None,
        last_attempt_at: None,
        acked_at: None,
        fallback_sent_at: None,
        next_attempt_at: now,
        last_error_code: None,
        last_error_detail: Some("none".to_string()),
        updated_at: now,
    };
    ctx.storage
        .enqueue_private_outbox(device_id, &entry)
        .await
        .expect("enqueue private outbox should succeed after init healing");

    let loaded = ctx
        .storage
        .load_private_outbox_entry(device_id, entry.delivery_id.as_str())
        .await
        .expect("load outbox entry should succeed");
    assert!(loaded.is_some());
    assert_eq!(
        loaded.expect("entry should exist").occurred_at,
        entry.occurred_at
    );
}

#[tokio::test]
async fn sqlite_init_heals_missing_channel_subscription_columns() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-channel-sub-columns",
        &[ "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))" ],
    )
    .await;

    let token = "android-heal-channel-sub-token-0001";
    let subscribe = ctx
        .storage
        .subscribe_channel(
            None,
            Some("heal-channel-sub"),
            "password-1234",
            token,
            Platform::ANDROID,
        )
        .await
        .expect("subscribe should succeed after channel_subscriptions column healing");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp())
        .await
        .expect("dispatch target listing should succeed");
    assert_eq!(targets.len(), 1);
}

#[tokio::test]
async fn sqlite_init_heals_missing_private_bindings_columns_and_indexes() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-private-bindings",
        &["CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash))"],
    )
    .await;

    let device_id: DeviceId = [5; 16];
    let token_1 = "android-heal-private-bindings-token-0001";
    let token_2 = "android-heal-private-bindings-token-0002";

    ctx.storage
        .bind_private_token(device_id, Platform::ANDROID, token_1)
        .await
        .expect("bind first token should succeed after schema healing");
    ctx.storage
        .bind_private_token(device_id, Platform::ANDROID, token_2)
        .await
        .expect("bind second token should succeed after schema healing");

    let found_1 = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token_1)
        .await
        .expect("lookup first token should succeed");
    let found_2 = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token_2)
        .await
        .expect("lookup second token should succeed");
    assert_eq!(found_1, Some(device_id));
    assert_eq!(found_2, Some(device_id));

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let required_columns = [
        "platform",
        "token_hash",
        "provider_token",
        "created_at",
        "updated_at",
    ];
    for column in required_columns {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM pragma_table_info('private_bindings') WHERE name = ? LIMIT 1",
        )
        .bind(column)
        .fetch_optional(&mut conn)
        .await
        .expect("pragma table_info query should succeed");
        assert_eq!(exists, Some(1), "column {column} should be present");
    }

    let unique_idx_exists: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM pragma_index_list('private_bindings') WHERE name = 'private_bindings_platform_token_uidx' AND \"unique\" = 1 LIMIT 1",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("pragma index_list query should succeed");
    assert_eq!(
        unique_idx_exists,
        Some(1),
        "platform/token_hash unique index should be present"
    );
}

#[tokio::test]
async fn sqlite_cleanup_pending_op_dedupe_uses_created_at_oldest_first_and_limit() {
    let ctx = setup_sqlite_storage("sqlite-dedupe-cleanup-created-at").await;

    let created_at = 1_700_000_000_i64;
    let k1 = "dedupe-created-at-1";
    let k2 = "dedupe-created-at-2";
    let k3 = "dedupe-created-at-3";
    let k4 = "dedupe-created-at-4";
    ctx.storage
        .reserve_op_dedupe_pending(k1, "delivery-created-at-1", created_at - 30)
        .await
        .expect("reserve k1 should succeed");
    ctx.storage
        .reserve_op_dedupe_pending(k2, "delivery-created-at-2", created_at - 20)
        .await
        .expect("reserve k2 should succeed");
    ctx.storage
        .reserve_op_dedupe_pending(k3, "delivery-created-at-3", created_at - 10)
        .await
        .expect("reserve k3 should succeed");
    ctx.storage
        .reserve_op_dedupe_pending(k4, "delivery-created-at-4", created_at + 10_000)
        .await
        .expect("reserve k4 should succeed");

    let sent = ctx
        .storage
        .mark_op_dedupe_sent(k2, "delivery-created-at-2")
        .await
        .expect("mark k2 sent should succeed");
    assert!(sent, "k2 should transition to sent");

    let removed_first = ctx
        .storage
        .cleanup_pending_op_dedupe(created_at, 1)
        .await
        .expect("first cleanup should succeed");
    assert_eq!(removed_first, 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let remain_after_first: Vec<(String, String)> =
        sqlx::query_as("SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC")
            .fetch_all(&mut conn)
            .await
            .expect("dedupe rows should be queryable");
    assert_eq!(
        remain_after_first,
        vec![
            (k2.to_string(), DedupeState::Sent.as_str().to_string()),
            (k3.to_string(), DedupeState::Pending.as_str().to_string()),
            (k4.to_string(), DedupeState::Pending.as_str().to_string()),
        ]
    );

    let removed_second = ctx
        .storage
        .cleanup_pending_op_dedupe(created_at, 8)
        .await
        .expect("second cleanup should succeed");
    assert_eq!(removed_second, 1);

    let remain_after_second: Vec<(String, String)> =
        sqlx::query_as("SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC")
            .fetch_all(&mut conn)
            .await
            .expect("dedupe rows should remain queryable");
    assert_eq!(
        remain_after_second,
        vec![
            (k2.to_string(), DedupeState::Sent.as_str().to_string()),
            (k4.to_string(), DedupeState::Pending.as_str().to_string()),
        ]
    );
}
