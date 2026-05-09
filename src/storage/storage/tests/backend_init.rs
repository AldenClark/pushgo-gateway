use super::*;
use crate::routing::derive_private_device_id;
use sqlx::{Connection, MySqlConnection, PgConnection};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::storage::database::migration::latest_schema_migration;

struct DockerContainer {
    name: String,
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", self.name.as_str()])
            .status();
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free local port should be allocatable")
        .local_addr()
        .expect("local addr should be available")
        .port()
}

fn unique_container_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn run_docker(args: &[&str]) {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("docker command should execute");
    assert!(
        output.status.success(),
        "docker {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_postgres_container() -> Option<(DockerContainer, String)> {
    if !docker_available() {
        eprintln!("docker unavailable; skipping postgres backend migration test");
        return None;
    }
    let name = unique_container_name("pushgo-gateway-pg-test");
    let port = free_port();
    run_docker(&[
        "run",
        "-d",
        "--name",
        name.as_str(),
        "-e",
        "POSTGRES_PASSWORD=pushgo",
        "-e",
        "POSTGRES_DB=pushgo",
        "-p",
        &format!("{port}:5432"),
        "postgres:16-alpine",
    ]);
    Some((
        DockerContainer { name },
        format!("postgres://postgres:pushgo@127.0.0.1:{port}/pushgo"),
    ))
}

fn start_mysql_container() -> Option<(DockerContainer, String)> {
    if !docker_available() {
        eprintln!("docker unavailable; skipping mysql backend migration test");
        return None;
    }
    let name = unique_container_name("pushgo-gateway-mysql-test");
    let port = free_port();
    run_docker(&[
        "run",
        "-d",
        "--name",
        name.as_str(),
        "-e",
        "MYSQL_ROOT_PASSWORD=pushgo",
        "-e",
        "MYSQL_DATABASE=pushgo",
        "-p",
        &format!("{port}:3306"),
        "mysql:8.4",
    ]);
    Some((
        DockerContainer { name },
        format!("mysql://root:pushgo@127.0.0.1:{port}/pushgo"),
    ))
}

async fn wait_for_postgres(db_url: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        match PgConnection::connect(db_url).await {
            Ok(conn) => {
                let _ = conn.close().await;
                return;
            }
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for postgres: {err}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => panic!("postgres did not become ready: {err}"),
        }
    }
}

async fn wait_for_mysql(db_url: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match MySqlConnection::connect(db_url).await {
            Ok(conn) => {
                let _ = conn.close().await;
                return;
            }
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for mysql: {err}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => panic!("mysql did not become ready: {err}"),
        }
    }
}

#[tokio::test]
async fn postgres_init_records_current_schema_migration() {
    let Some((_container, db_url)) = start_postgres_container() else {
        return;
    };
    wait_for_postgres(&db_url).await;

    let latest = latest_schema_migration();
    let _storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("postgres storage should initialize");
    let mut conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres verification connection should succeed");
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT migration_id, checksum, success \
         FROM pushgo_schema_migrations \
         WHERE migration_id = $1",
    )
    .bind(latest.id)
    .fetch_one(&mut conn)
    .await
    .expect("postgres migration ledger row should exist");
    assert_eq!(row.0, latest.id);
    assert_eq!(row.1, latest.checksum);
    assert!(row.2);
}

#[tokio::test]
async fn postgres_init_rejects_current_migration_checksum_drift() {
    let Some((_container, db_url)) = start_postgres_container() else {
        return;
    };
    wait_for_postgres(&db_url).await;

    let latest = latest_schema_migration();
    let mut conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres setup connection should succeed");
    for stmt in [
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL)",
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-22-gateway-v9') \
         ON CONFLICT (meta_key) DO UPDATE SET meta_value = EXCLUDED.meta_value",
        "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (migration_id VARCHAR(128) PRIMARY KEY, description TEXT NOT NULL, checksum VARCHAR(255) NOT NULL, target_schema_version VARCHAR(255) NOT NULL, started_at BIGINT NOT NULL, finished_at BIGINT NOT NULL, execution_ms BIGINT NOT NULL, success BOOLEAN NOT NULL, error TEXT)",
    ] {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("postgres setup statement should succeed");
    }
    sqlx::query(
        "INSERT INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) VALUES ($1, 'tampered', 'sha256:tampered', $2, 1, 1, 0, TRUE, NULL)",
    )
    .bind(latest.id)
    .bind(crate::storage::STORAGE_SCHEMA_VERSION)
    .execute(&mut conn)
    .await
    .expect("postgres tampered migration row should be inserted");
    conn.close().await.expect("postgres close should succeed");

    let err = Storage::new(Some(db_url.as_str()))
        .await
        .expect_err("checksum drift should reject postgres startup");
    assert!(matches!(err, StoreError::SchemaVersionMismatch { .. }));
}

#[tokio::test]
async fn mysql_init_records_current_schema_migration() {
    let Some((_container, db_url)) = start_mysql_container() else {
        return;
    };
    wait_for_mysql(&db_url).await;

    let latest = latest_schema_migration();
    let _storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("mysql storage should initialize");
    let mut conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql verification connection should succeed");
    let row: (String, String, i8) = sqlx::query_as(
        "SELECT migration_id, checksum, success \
         FROM pushgo_schema_migrations \
         WHERE migration_id = ?",
    )
    .bind(latest.id)
    .fetch_one(&mut conn)
    .await
    .expect("mysql migration ledger row should exist");
    assert_eq!(row.0, latest.id);
    assert_eq!(row.1, latest.checksum);
    assert_eq!(row.2, 1);
}

#[tokio::test]
async fn mysql_init_rejects_current_migration_checksum_drift() {
    let Some((_container, db_url)) = start_mysql_container() else {
        return;
    };
    wait_for_mysql(&db_url).await;

    let latest = latest_schema_migration();
    let mut conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql setup connection should succeed");
    for stmt in [
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-04-22-gateway-v9') ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (migration_id VARCHAR(128) PRIMARY KEY, description TEXT NOT NULL, checksum VARCHAR(255) NOT NULL, target_schema_version VARCHAR(255) NOT NULL, started_at BIGINT NOT NULL, finished_at BIGINT NOT NULL, execution_ms BIGINT NOT NULL, success TINYINT NOT NULL, error TEXT NULL) ENGINE=InnoDB",
    ] {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("mysql setup statement should succeed");
    }
    sqlx::query(
        "INSERT INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) VALUES (?, 'tampered', 'sha256:tampered', ?, 1, 1, 0, 1, NULL)",
    )
    .bind(latest.id)
    .bind(crate::storage::STORAGE_SCHEMA_VERSION)
    .execute(&mut conn)
    .await
    .expect("mysql tampered migration row should be inserted");
    conn.close().await.expect("mysql close should succeed");

    let err = Storage::new(Some(db_url.as_str()))
        .await
        .expect_err("checksum drift should reject mysql startup");
    assert!(matches!(err, StoreError::SchemaVersionMismatch { .. }));
}

#[tokio::test]
async fn postgres_maintenance_cleanup_preserves_live_references_and_shared_deliveries() {
    let Some((_container, db_url)) = start_postgres_container() else {
        return;
    };
    wait_for_postgres(&db_url).await;

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("postgres storage should initialize");
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let session_device_key = "pg-maintenance-live-session-device";
    let queue_device_key = "pg-maintenance-live-queue-device";
    let session_device_id = derive_private_device_id(session_device_key);
    let queue_device_id = derive_private_device_id(queue_device_key);
    seed_old_private_routes(&storage, session_device_key, queue_device_key, old).await;

    let mut conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres verification connection should succeed");
    sqlx::query(
        "INSERT INTO private_sessions (session_id, device_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind("pg-maintenance-live-session")
    .bind(&session_device_id[..])
    .bind(now + 300_000)
    .execute(&mut conn)
    .await
    .expect("postgres live private session should be inserted");

    seed_cleanup_shared_delivery_scenario(&storage, now, old, queue_device_id).await;
    let stats = storage
        .run_maintenance_cleanup(now, strict_runtime_cleanup_config())
        .await
        .expect("postgres maintenance cleanup should succeed");

    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);
    assert_eq!(stats.orphan_devices_pruned, 0);
    assert_cleanup_shared_delivery_invariants(&storage).await;

    let route_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key IN ($1, $2)")
            .bind(session_device_key)
            .bind(queue_device_key)
            .fetch_one(&mut conn)
            .await
            .expect("postgres route count should be queryable");
    let live_provider_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
    )
    .bind(&PG_MYSQL_LIVE_DEVICE[..])
    .bind(SHARED_PROVIDER_DELIVERY_ID)
    .fetch_one(&mut conn)
    .await
    .expect("postgres provider count should be queryable");
    assert_eq!(route_count, 2);
    assert_eq!(live_provider_count, 1);
}

#[tokio::test]
async fn mysql_maintenance_cleanup_preserves_live_references_and_shared_deliveries() {
    let Some((_container, db_url)) = start_mysql_container() else {
        return;
    };
    wait_for_mysql(&db_url).await;

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("mysql storage should initialize");
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let session_device_key = "mysql-maintenance-live-session-device";
    let queue_device_key = "mysql-maintenance-live-queue-device";
    let session_device_id = derive_private_device_id(session_device_key);
    let queue_device_id = derive_private_device_id(queue_device_key);
    seed_old_private_routes(&storage, session_device_key, queue_device_key, old).await;

    let mut conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql verification connection should succeed");
    sqlx::query(
        "INSERT INTO private_sessions (session_id, device_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind("mysql-maintenance-live-session")
    .bind(&session_device_id[..])
    .bind(now + 300_000)
    .execute(&mut conn)
    .await
    .expect("mysql live private session should be inserted");

    seed_cleanup_shared_delivery_scenario(&storage, now, old, queue_device_id).await;
    let stats = storage
        .run_maintenance_cleanup(now, strict_runtime_cleanup_config())
        .await
        .expect("mysql maintenance cleanup should succeed");

    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);
    assert_eq!(stats.orphan_devices_pruned, 0);
    assert_cleanup_shared_delivery_invariants(&storage).await;

    let route_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key IN (?, ?)")
            .bind(session_device_key)
            .bind(queue_device_key)
            .fetch_one(&mut conn)
            .await
            .expect("mysql route count should be queryable");
    let live_provider_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(&PG_MYSQL_LIVE_DEVICE[..])
    .bind(SHARED_PROVIDER_DELIVERY_ID)
    .fetch_one(&mut conn)
    .await
    .expect("mysql provider count should be queryable");
    assert_eq!(route_count, 2);
    assert_eq!(live_provider_count, 1);
}

const PG_MYSQL_STALE_DEVICE: DeviceId = [31; 16];
const PG_MYSQL_LIVE_DEVICE: DeviceId = [32; 16];
const SHARED_PRIVATE_DELIVERY_ID: &str = "docker-maintenance-shared-private";
const SHARED_PROVIDER_DELIVERY_ID: &str = "docker-maintenance-shared-provider";

async fn seed_old_private_routes(
    storage: &Storage,
    session_device_key: &str,
    queue_device_key: &str,
    updated_at: i64,
) {
    for device_key in [session_device_key, queue_device_key] {
        storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at,
            })
            .await
            .expect("old private route should be persisted");
    }
}

async fn seed_cleanup_shared_delivery_scenario(
    storage: &Storage,
    now: i64,
    old: i64,
    referenced_queue_device_id: DeviceId,
) {
    storage
        .enqueue_provider_pull_item(
            referenced_queue_device_id,
            "docker-maintenance-live-reference-provider-pull",
            &PrivateMessage {
                payload: vec![9, 9, 9].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "docker-maintenance-live-reference-token",
        )
        .await
        .expect("live provider pull reference should be inserted");

    storage
        .insert_private_message(
            SHARED_PRIVATE_DELIVERY_ID,
            &PrivateMessage {
                payload: vec![1, 2, 3].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
        )
        .await
        .expect("shared private payload should be inserted");
    for (device_id, updated_at) in [(PG_MYSQL_STALE_DEVICE, old), (PG_MYSQL_LIVE_DEVICE, now)] {
        storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: SHARED_PRIVATE_DELIVERY_ID.to_string(),
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

    storage
        .enqueue_provider_pull_item(
            PG_MYSQL_STALE_DEVICE,
            SHARED_PROVIDER_DELIVERY_ID,
            &PrivateMessage {
                payload: vec![4].into(),
                size: 1,
                sent_at: old,
                expires_at: old,
            },
            Platform::ANDROID,
            "docker-maintenance-stale-provider-token",
        )
        .await
        .expect("stale provider pull row should be inserted");
    storage
        .enqueue_provider_pull_item(
            PG_MYSQL_LIVE_DEVICE,
            SHARED_PROVIDER_DELIVERY_ID,
            &PrivateMessage {
                payload: vec![5].into(),
                size: 1,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "docker-maintenance-live-provider-token",
        )
        .await
        .expect("live provider pull row should be inserted");
}

async fn assert_cleanup_shared_delivery_invariants(storage: &Storage) {
    assert!(
        storage
            .load_private_outbox_entry(PG_MYSQL_STALE_DEVICE, SHARED_PRIVATE_DELIVERY_ID)
            .await
            .expect("stale private outbox lookup should succeed")
            .is_none()
    );
    assert!(
        storage
            .load_private_outbox_entry(PG_MYSQL_LIVE_DEVICE, SHARED_PRIVATE_DELIVERY_ID)
            .await
            .expect("live private outbox lookup should succeed")
            .is_some()
    );
    assert!(
        storage
            .load_private_message(SHARED_PRIVATE_DELIVERY_ID)
            .await
            .expect("shared private payload lookup should succeed")
            .is_some()
    );
}

fn strict_runtime_cleanup_config() -> MaintenanceCleanupConfig {
    MaintenanceCleanupConfig {
        private_stale_outbox_ttl_secs: 60,
        orphan_device_ttl_secs: 60,
        ..MaintenanceCleanupConfig::default()
    }
}
