use super::*;

#[tokio::test]
async fn sqlite_cold_start_initializes_schema() {
    let ctx = setup_sqlite_storage_without_bootstrap("sqlite-cold-start").await;
    let token = "android-cold-start-000000000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "sqlite-cold-start-device-key",
        token,
        "cold-start",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
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
    let subscribe = subscribe_provider_channel_for_test(
        &storage,
        "sqlite-auto-parent-device-key",
        token,
        "auto-parent",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let info = storage
        .channel_info(subscribe.channel_id)
        .await
        .expect("channel info should load");
    assert!(info.is_some());
}

#[tokio::test]
async fn sqlite_sidecars_are_not_created_when_features_are_disabled() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("pushgo.sqlite");
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let _storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(db_url),
        stats_enabled: false,
        mcp_enabled: false,
        ..StorageInitConfig::default()
    })
    .await
    .expect("sqlite storage should initialize without sidecars");

    assert!(!dir.path().join("pushgo.telemetry.sqlite").exists());
    assert!(!dir.path().join("pushgo.runtime.sqlite").exists());
    assert!(
        dir.path().join("pushgo.dispatch.sqlite").exists(),
        "dispatch sidecar is always initialized because dispatch dedupe is on the message send path"
    );
}

#[tokio::test]
async fn sqlite_sidecars_migrate_legacy_stats_and_mcp_state() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("pushgo.sqlite");
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let mut conn = SqliteConnection::connect(&db_url)
        .await
        .expect("sqlite setup connection should succeed");
    sqlx::query("CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour TEXT PRIMARY KEY, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_outbox_depth_max INTEGER NOT NULL DEFAULT 0, dedupe_pending_max INTEGER NOT NULL DEFAULT 0, active_private_sessions_max INTEGER NOT NULL DEFAULT 0)")
        .execute(&mut conn)
        .await
        .expect("legacy gateway stats table should be created");
    sqlx::query("INSERT INTO gateway_stats_hourly (bucket_hour, messages_routed, deliveries_attempted, deliveries_acked, private_outbox_depth_max, dedupe_pending_max, active_private_sessions_max) VALUES ('2026-05-25T10', 7, 0, 0, 0, 0, 0)")
        .execute(&mut conn)
        .await
        .expect("legacy gateway stats row should be inserted");
    sqlx::query("CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)")
        .execute(&mut conn)
        .await
        .expect("legacy mcp state table should be created");
    sqlx::query("INSERT INTO mcp_state (state_key, state_json, updated_at) VALUES ('default', '{\"legacy\":true}', 1)")
        .execute(&mut conn)
        .await
        .expect("legacy mcp state row should be inserted");
    drop(conn);

    let storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(db_url),
        stats_enabled: true,
        mcp_enabled: true,
        ..StorageInitConfig::default()
    })
    .await
    .expect("sqlite storage should initialize with sidecars");

    let telemetry_url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("pushgo.telemetry.sqlite").to_string_lossy()
    );
    let runtime_url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("pushgo.runtime.sqlite").to_string_lossy()
    );

    let mut telemetry_conn = SqliteConnection::connect(&telemetry_url)
        .await
        .expect("telemetry sidecar should open");
    let migrated_count: i64 = sqlx::query_scalar(
        "SELECT messages_routed FROM gateway_stats_hourly WHERE bucket_hour = '2026-05-25T10'",
    )
    .fetch_one(&mut telemetry_conn)
    .await
    .expect("migrated telemetry row should exist");
    assert_eq!(migrated_count, 7);

    storage
        .save_mcp_state_json("{\"current\":true}")
        .await
        .expect("mcp state should save to runtime sidecar");
    let mut runtime_conn = SqliteConnection::connect(&runtime_url)
        .await
        .expect("runtime sidecar should open");
    let state_json: String =
        sqlx::query_scalar("SELECT state_json FROM mcp_state WHERE state_key = 'default'")
            .fetch_one(&mut runtime_conn)
            .await
            .expect("runtime mcp state should exist");
    assert_eq!(state_json, "{\"current\":true}");
}

#[tokio::test]
async fn sqlite_dispatch_sidecar_migrates_legacy_dedupe_and_handles_new_writes() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("pushgo.sqlite");
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let mut conn = SqliteConnection::connect(&db_url)
        .await
        .expect("sqlite setup connection should succeed");
    sqlx::query("CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)")
        .execute(&mut conn)
        .await
        .expect("legacy delivery dedupe table should be created");
    sqlx::query("INSERT INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at, expires_at) VALUES ('legacy-dispatch-key', 'legacy-delivery', 'sent', 1, 1, NULL)")
        .execute(&mut conn)
        .await
        .expect("legacy delivery dedupe row should be inserted");
    drop(conn);

    let storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(db_url.clone()),
        stats_enabled: false,
        mcp_enabled: false,
        ..StorageInitConfig::default()
    })
    .await
    .expect("sqlite storage should initialize with dispatch sidecar");

    let dispatch_url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("pushgo.dispatch.sqlite").to_string_lossy()
    );
    let mut dispatch_conn = SqliteConnection::connect(&dispatch_url)
        .await
        .expect("dispatch sidecar should open");
    let legacy_delivery_id: String = sqlx::query_scalar(
        "SELECT delivery_id FROM dispatch_delivery_dedupe WHERE dedupe_key = 'legacy-dispatch-key'",
    )
    .fetch_one(&mut dispatch_conn)
    .await
    .expect("legacy dispatch dedupe row should be migrated");
    assert_eq!(legacy_delivery_id, "legacy-delivery");

    assert!(
        !storage
            .reserve_delivery_dedupe("legacy-dispatch-key", "ignored-delivery", 2)
            .await
            .expect("legacy dispatch dedupe should be served from sidecar"),
        "legacy sidecar row should block duplicate reservation"
    );
    assert!(
        storage
            .reserve_delivery_dedupe("new-dispatch-key", "new-delivery", 3)
            .await
            .expect("new dispatch dedupe should write to sidecar")
    );

    let sidecar_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM dispatch_delivery_dedupe WHERE dedupe_key = 'new-dispatch-key'",
    )
    .fetch_one(&mut dispatch_conn)
    .await
    .expect("new dispatch sidecar row should exist");
    assert_eq!(sidecar_count, 1);

    let mut core_conn = SqliteConnection::connect(&db_url)
        .await
        .expect("core db should open");
    let core_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM dispatch_delivery_dedupe WHERE dedupe_key = 'new-dispatch-key'",
    )
    .fetch_one(&mut core_conn)
    .await
    .expect("core dispatch table should remain readable for rollback compatibility");
    assert_eq!(core_count, 0);
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
    subscribe_provider_channel_for_test(
        &ctx.storage,
        "sqlite-schema-upgrade-device-key",
        token,
        "schema-upgrade",
        "pw123456",
        Platform::ANDROID,
    )
    .await;

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
            "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-22-gateway-v9')",
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
async fn sqlite_init_upgrades_v8_schema_and_drops_legacy_delivery_audit_table() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-schema-version-v8-upgrade-drop-delivery-audit",
        &[
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
            "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-17-gateway-v8')",
            "CREATE TABLE IF NOT EXISTS delivery_audit (audit_id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, created_at INTEGER NOT NULL)",
        ],
    )
    .await;

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let has_delivery_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='delivery_audit'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("sqlite master query should succeed");
    assert_eq!(has_delivery_audit, 0);

    let meta: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("schema meta query should succeed");
    assert_eq!(meta.as_deref(), Some(STORAGE_SCHEMA_VERSION));
}

#[tokio::test]
async fn sqlite_init_records_current_schema_migration() {
    let ctx = setup_sqlite_storage_without_bootstrap("sqlite-schema-migration-ledger").await;
    let latest = crate::storage::database::migration::latest_schema_migration();
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    let row: (String, String, i64) = sqlx::query_as(
        "SELECT migration_id, target_schema_version, success \
         FROM pushgo_schema_migrations \
         WHERE migration_id = ?",
    )
    .bind(latest.id)
    .fetch_one(&mut conn)
    .await
    .expect("current migration ledger row should exist");
    assert_eq!(row.0, latest.id);
    assert_eq!(row.1, STORAGE_SCHEMA_VERSION);
    assert_eq!(row.2, 1);
}

#[tokio::test]
async fn sqlite_init_rejects_current_migration_checksum_drift() {
    let latest = crate::storage::database::migration::latest_schema_migration();
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("sqlite-schema-migration-checksum.sqlite");
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let mut conn = SqliteConnection::connect(&db_url)
        .await
        .expect("sqlite bootstrap connection should succeed");
    let setup_statements = vec![
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
        "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-22-gateway-v9')",
        "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (migration_id TEXT PRIMARY KEY, description TEXT NOT NULL, checksum TEXT NOT NULL, target_schema_version TEXT NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL, execution_ms INTEGER NOT NULL, success INTEGER NOT NULL, error TEXT)",
    ];
    for stmt in setup_statements {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("custom schema statement should succeed");
    }
    sqlx::query(
        "INSERT INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) VALUES (?, 'tampered', 'sha256:tampered', ?, 1, 1, 0, 1, NULL)",
    )
    .bind(latest.id)
    .bind(STORAGE_SCHEMA_VERSION)
    .execute(&mut conn)
    .await
    .expect("tampered migration row should be inserted");
    drop(conn);

    let err = Storage::new(Some(db_url.as_str()))
        .await
        .expect_err("checksum drift should reject startup");
    assert!(
        matches!(err, StoreError::SchemaVersionMismatch { .. }),
        "unexpected error: {err:?}"
    );
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
        updated_at: chrono::Utc::now().timestamp_millis(),
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

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [9; 16];
    let delivery_id = "delivery-heal-provider-table-1";
    let message = PrivateMessage {
        payload: vec![11, 22, 33].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-heal-provider-table-token-1",
        )
        .await
        .expect("enqueue provider pull item should succeed after table auto-create");

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("pull provider item should succeed");
    assert!(pulled.is_some());
    assert_eq!(
        pulled.expect("item should exist").delivery_id,
        delivery_id.to_string()
    );
}

#[tokio::test]
async fn sqlite_init_hard_resets_provider_pull_queue_without_schema_meta() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-provider-pull-legacy-pk",
        &[
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (delivery_id TEXT PRIMARY KEY, device_id BLOB, payload_blob BLOB, payload_size INTEGER, sent_at INTEGER, expires_at INTEGER, platform TEXT, provider_token TEXT, created_at INTEGER, updated_at INTEGER)",
            "INSERT INTO provider_pull_queue (delivery_id, device_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) VALUES ('legacy-provider-pull-existing-1', X'01010101010101010101010101010101', X'ABCD', 2, 100, 253402300799, 'android', 'legacy-token-1', 100, 100)",
        ],
    )
    .await;

    let now = chrono::Utc::now().timestamp_millis();
    let delivery_id = "legacy-provider-pull-shared-delivery-1";
    let payload = PrivateMessage {
        payload: vec![1, 3, 5, 7].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 600_000,
    };
    let device_a: DeviceId = [3; 16];
    let device_b: DeviceId = [4; 16];

    ctx.storage
        .enqueue_provider_pull_item(
            device_a,
            delivery_id,
            &payload,
            Platform::ANDROID,
            "legacy-provider-token-a",
        )
        .await
        .expect("enqueue provider item for device A should succeed");
    ctx.storage
        .enqueue_provider_pull_item(
            device_b,
            delivery_id,
            &payload,
            Platform::ANDROID,
            "legacy-provider-token-b",
        )
        .await
        .expect("enqueue provider item for device B should succeed");

    let pulled_a = ctx
        .storage
        .pull_provider_item(device_a, delivery_id, now + 1)
        .await
        .expect("pull device A should succeed");
    let pulled_b = ctx
        .storage
        .pull_provider_item(device_b, delivery_id, now + 1)
        .await
        .expect("pull device B should succeed");
    assert!(pulled_a.is_some(), "device A should receive queued payload");
    assert!(pulled_b.is_some(), "device B should receive queued payload");

    let legacy_existing = ctx
        .storage
        .pull_provider_item([1; 16], "legacy-provider-pull-existing-1", now + 1)
        .await
        .expect("pull legacy row should succeed after hard reset");
    assert!(
        legacy_existing.is_none(),
        "legacy row without schema meta should be dropped during hard-cut migration"
    );

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let pk_columns: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM pragma_table_info('provider_pull_queue') WHERE pk > 0 ORDER BY pk",
    )
    .fetch_all(&mut conn)
    .await
    .expect("provider_pull_queue primary key query should succeed");
    assert_eq!(
        pk_columns,
        vec!["device_id".to_string(), "delivery_id".to_string()]
    );
}

#[tokio::test]
async fn sqlite_init_hard_reset_legacy_runtime_preserves_base_data_and_recovers_writes() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-hard-reset-preserve-base-and-recover-runtime",
        &[
            "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) VALUES (X'0102030405060708090A0B0C0D0E0F10', 'legacy-hash-boundary', 'legacy-boundary-channel', -1, 9223372036854775807)",
            "CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash))",
            "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
            "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) VALUES (X'11111111111111111111111111111111', 'legacy-delivery-boundary-sqlite', 'pending', 7, -1, 'legacy-error', -1)",
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
        ],
    )
    .await;

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite verification connection should succeed");
    let schema_version: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("sqlite schema version query should succeed");
    assert_eq!(schema_version.as_deref(), Some(STORAGE_SCHEMA_VERSION));

    let preserved_channel_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE alias = 'legacy-boundary-channel'")
            .fetch_one(&mut conn)
            .await
            .expect("sqlite preserved channel query should succeed");
    assert_eq!(preserved_channel_count, 1);

    let legacy_outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE delivery_id = 'legacy-delivery-boundary-sqlite'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("sqlite legacy outbox query should succeed");
    assert_eq!(legacy_outbox_count, 0);

    let now = chrono::Utc::now().timestamp_millis();
    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: "sqlite-upgrade-boundary-device-key".to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some("android-token-sqlite-upgrade-boundary-000000000001".to_string()),
            updated_at: now,
        })
        .await
        .expect("sqlite route upsert should succeed after migration");
    let routes = ctx
        .storage
        .load_device_routes()
        .await
        .expect("sqlite route load should succeed after migration");
    assert!(
        routes
            .iter()
            .any(|row| row.device_key == "sqlite-upgrade-boundary-device-key"),
        "sqlite migrated schema should accept new route writes"
    );
}

#[tokio::test]
async fn sqlite_init_heals_missing_private_outbox_columns() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-private-outbox-columns",
        &[ "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))" ],
    )
    .await;

    let now = chrono::Utc::now().timestamp_millis();
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
async fn sqlite_init_upgrades_v7_channel_subscription_shape() {
    let ctx = setup_sqlite_storage_with_custom_schema(
        "sqlite-heal-channel-sub-columns",
        &[
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
            "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-16-gateway-v7')",
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
        ],
    )
    .await;

    let token = "android-heal-channel-sub-token-0001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "sqlite-heal-channel-sub-route-key",
        token,
        "heal-channel-sub",
        "password-1234",
        Platform::ANDROID,
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp_millis())
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

    let mut conn = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("sqlite dispatch sidecar connection should succeed");
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
