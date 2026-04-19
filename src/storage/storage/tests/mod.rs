use super::*;
use serde::Serialize;
use sqlx::{Connection, SqliteConnection};
use tempfile::{TempDir, tempdir};
use tokio::time::{Duration, sleep};

mod backend_init;
mod bindings;
mod invariants;
mod runtime;
mod sqlite_init;

struct SqliteTestContext {
    _dir: TempDir,
    db_url: String,
    storage: Storage,
}

#[derive(Serialize)]
struct TestPrivatePayloadEnvelope<'a> {
    payload_version: u8,
    data: hashbrown::HashMap<&'a str, &'a str>,
}

async fn setup_sqlite_storage(name: &str) -> SqliteTestContext {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join(format!("{name}.sqlite"));
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    bootstrap_sqlite_schema(&db_url)
        .await
        .expect("sqlite schema bootstrap should succeed");

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("sqlite storage should initialize");

    SqliteTestContext {
        _dir: dir,
        db_url,
        storage,
    }
}

async fn setup_sqlite_storage_without_bootstrap(name: &str) -> SqliteTestContext {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join(format!("{name}.sqlite"));
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("sqlite storage should initialize with auto schema bootstrap");
    SqliteTestContext {
        _dir: dir,
        db_url,
        storage,
    }
}

async fn setup_sqlite_storage_with_custom_schema(
    name: &str,
    statements: &[&str],
) -> SqliteTestContext {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join(format!("{name}.sqlite"));
    std::fs::File::create(&db_path).expect("sqlite db file should be created");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let mut conn = SqliteConnection::connect(&db_url)
        .await
        .expect("sqlite bootstrap connection should succeed");
    for stmt in statements {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("custom schema statement should succeed");
    }
    drop(conn);

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("sqlite storage should initialize with custom schema");

    SqliteTestContext {
        _dir: dir,
        db_url,
        storage,
    }
}

async fn bootstrap_sqlite_schema(db_url: &str) -> StoreResult<()> {
    let mut conn = SqliteConnection::connect(db_url).await?;

    let statements = [
        "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, token_raw BLOB NOT NULL, platform_code INTEGER NOT NULL, device_key TEXT, platform TEXT, channel_type TEXT, provider_token TEXT, route_updated_at INTEGER)",
        "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx ON devices (device_key)",
        "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
        "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx ON channel_subscriptions (device_id)",
        "CREATE INDEX IF NOT EXISTS channel_subscriptions_dispatch_idx ON channel_subscriptions (channel_id, status, created_at)",
        "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL, created_at INTEGER NOT NULL, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
        "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx ON private_outbox (delivery_id)",
        "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
        "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_created_idx ON provider_pull_queue (device_id, created_at)",
    ];

    for stmt in statements {
        sqlx::query(stmt).execute(&mut conn).await?;
    }
    Ok(())
}

async fn seed_provider_route(
    storage: &Storage,
    device_key: &str,
    platform: Platform,
    token: &str,
    updated_at: i64,
) {
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: platform.name().to_string(),
            channel_type: platform.channel_type().to_string(),
            provider_token: Some(token.to_string()),
            updated_at,
        })
        .await
        .expect("provider route should be persisted");
}

async fn subscribe_provider_channel_for_test(
    storage: &Storage,
    device_key: &str,
    token: &str,
    alias: &str,
    password: &str,
    platform: Platform,
) -> SubscribeOutcome {
    seed_provider_route(
        storage,
        device_key,
        platform,
        token,
        chrono::Utc::now().timestamp(),
    )
    .await;
    storage
        .subscribe_channel_for_device_key(None, Some(alias), password, device_key, token, platform)
        .await
        .expect("provider subscribe should succeed")
}
