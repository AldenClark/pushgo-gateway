use super::*;
use crate::routing::derive_private_device_id;
use sqlx::{Connection, MySqlConnection, PgConnection};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::storage::database::migration::latest_schema_migration;

struct DockerContainer {
    name: String,
}

static CONTAINER_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);
const BETA1_TAG: &str = "v1.3.0-beta.1";
const BETA1_COMMIT: &str = "a84a937ccc7cbcce99c5a0e37f35ed2d0fe55906";

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", self.name.as_str()])
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

fn external_db_tests_required() -> bool {
    std::env::var("PUSHGO_REQUIRE_EXTERNAL_DB_TESTS")
        .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
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
    let sequence = CONTAINER_NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{nanos}-{sequence}", std::process::id())
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

fn beta1_bootstrap_source(backend: &str) -> String {
    let revision = format!("{BETA1_TAG}^{{commit}}");
    let resolved = Command::new("git")
        .args(["rev-parse", revision.as_str()])
        .output()
        .expect("git rev-parse for beta1 tag should execute");
    assert!(
        resolved.status.success(),
        "the exact beta1 tag is required for database upgrade fixtures"
    );
    assert_eq!(
        String::from_utf8_lossy(&resolved.stdout).trim(),
        BETA1_COMMIT,
        "beta1 fixture tag must resolve to the audited commit"
    );
    let object = format!("{BETA1_TAG}:src/storage/database/{backend}/bootstrap.rs");
    let output = Command::new("git")
        .args(["show", object.as_str()])
        .output()
        .expect("git show for beta1 bootstrap should execute");
    assert!(output.status.success(), "beta1 bootstrap source must exist");
    String::from_utf8(output.stdout).expect("beta1 bootstrap source must be utf8")
}

fn rust_string_array(source: &str, name: &str) -> Vec<String> {
    let marker = format!("const {name}: &[&str] = &[");
    let (_, tail) = source
        .split_once(marker.as_str())
        .unwrap_or_else(|| panic!("missing beta1 SQL array {name}"));
    let (body, _) = tail
        .split_once("\n];")
        .unwrap_or_else(|| panic!("unterminated beta1 SQL array {name}"));
    body.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('"'))
        .map(|line| {
            let literal = line.strip_suffix(',').unwrap_or(line);
            serde_json::from_str::<String>(literal)
                .unwrap_or_else(|err| panic!("invalid Rust SQL literal in {name}: {err}"))
        })
        .collect()
}

async fn seed_exact_beta1_postgres(conn: &mut PgConnection) {
    let source = beta1_bootstrap_source("pg");
    for array in [
        "PG_BASE_TABLE_STATEMENTS",
        "PG_RUNTIME_TABLE_STATEMENTS",
        "PG_BASE_INDEX_STATEMENTS",
        "PG_RUNTIME_INDEX_STATEMENTS",
    ] {
        for statement in rust_string_array(&source, array) {
            sqlx::query(&statement)
                .execute(&mut *conn)
                .await
                .unwrap_or_else(|err| panic!("beta1 PostgreSQL statement failed: {err}"));
        }
    }
    sqlx::query(
        "CREATE TABLE pushgo_schema_migrations (migration_id VARCHAR(128) PRIMARY KEY, description TEXT NOT NULL, checksum VARCHAR(255) NOT NULL, target_schema_version VARCHAR(255) NOT NULL, started_at BIGINT NOT NULL, finished_at BIGINT NOT NULL, execution_ms BIGINT NOT NULL, success BOOLEAN NOT NULL, error TEXT)",
    )
    .execute(&mut *conn)
    .await
    .expect("beta1 PostgreSQL migration ledger should be created");
    sqlx::query(
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', $1)",
    )
    .bind(STORAGE_SCHEMA_VERSION_BETA1)
    .execute(&mut *conn)
    .await
    .expect("beta1 PostgreSQL schema marker should be inserted");
    for migration in &crate::storage::database::migration::SCHEMA_MIGRATIONS[..2] {
        sqlx::query(
            "INSERT INTO pushgo_schema_migrations \
             (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) \
             VALUES ($1, $2, $3, $4, 1, 1, 0, TRUE, NULL)",
        )
        .bind(migration.id)
        .bind(migration.description)
        .bind(migration.checksum)
        .bind(migration.target_schema_version)
        .execute(&mut *conn)
        .await
        .expect("beta1 PostgreSQL migration row should be inserted");
    }
}

async fn seed_exact_beta1_mysql(conn: &mut MySqlConnection) {
    let source = beta1_bootstrap_source("mysql");
    for array in [
        "MYSQL_BASE_TABLE_STATEMENTS",
        "MYSQL_RUNTIME_TABLE_STATEMENTS",
        "MYSQL_BASE_INDEX_STATEMENTS",
        "MYSQL_RUNTIME_INDEX_STATEMENTS",
    ] {
        for statement in rust_string_array(&source, array) {
            sqlx::query(&statement)
                .execute(&mut *conn)
                .await
                .unwrap_or_else(|err| panic!("beta1 MySQL statement failed: {err}"));
        }
    }
    sqlx::query(
        "CREATE TABLE pushgo_schema_migrations (migration_id VARCHAR(128) PRIMARY KEY, description TEXT NOT NULL, checksum VARCHAR(255) NOT NULL, target_schema_version VARCHAR(255) NOT NULL, started_at BIGINT NOT NULL, finished_at BIGINT NOT NULL, execution_ms BIGINT NOT NULL, success BOOLEAN NOT NULL, error TEXT NULL) ENGINE=InnoDB",
    )
    .execute(&mut *conn)
    .await
    .expect("beta1 MySQL migration ledger should be created");
    sqlx::query(
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?)",
    )
    .bind(STORAGE_SCHEMA_VERSION_BETA1)
    .execute(&mut *conn)
    .await
    .expect("beta1 MySQL schema marker should be inserted");
    for migration in &crate::storage::database::migration::SCHEMA_MIGRATIONS[..2] {
        sqlx::query(
            "INSERT INTO pushgo_schema_migrations \
             (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) \
             VALUES (?, ?, ?, ?, 1, 1, 0, TRUE, NULL)",
        )
        .bind(migration.id)
        .bind(migration.description)
        .bind(migration.checksum)
        .bind(migration.target_schema_version)
        .execute(&mut *conn)
        .await
        .expect("beta1 MySQL migration row should be inserted");
    }
}

fn start_postgres_container() -> Option<(DockerContainer, String)> {
    if !docker_available() {
        assert!(
            !external_db_tests_required(),
            "PostgreSQL release tests are required but Docker is unavailable"
        );
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
        assert!(
            !external_db_tests_required(),
            "MySQL release tests are required but Docker is unavailable"
        );
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

async fn assert_postgres_provider_token_case_migration(db_url: &str) {
    let lower = "cd".repeat(32);
    let upper = lower.to_ascii_uppercase();
    let old_key = "postgres-apns-case-old";
    let winner_key = "postgres-apns-case-winner";
    let old_id = PrivateDeviceId::derive(old_key).to_vec();
    let winner_id = PrivateDeviceId::derive(winner_key).to_vec();
    let token_raw = DeviceInfo::from_token(Platform::IOS, lower.as_str())
        .expect("valid APNs fixture")
        .token_raw
        .to_vec();
    let old_hash = ProviderTokenSnapshot::from_token(upper.as_str())
        .hash()
        .expect("uppercase APNs hash")
        .to_vec();
    let winner_hash = ProviderTokenSnapshot::from_token(lower.as_str())
        .hash()
        .expect("lowercase APNs hash")
        .to_vec();
    let now = chrono::Utc::now().timestamp_millis();
    let mut conn = PgConnection::connect(db_url)
        .await
        .expect("postgres token fixture connection should succeed");
    for (id, key, token, updated_at) in [
        (old_id.as_slice(), old_key, upper.as_str(), now),
        (winner_id.as_slice(), winner_key, lower.as_str(), now + 10),
    ] {
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
             VALUES ($1, $2, $3, $4, 'ios', 'apns', $5, $6)",
        )
        .bind(id)
        .bind(token_raw.as_slice())
        .bind(Platform::IOS.to_byte() as i16)
        .bind(key)
        .bind(token)
        .bind(updated_at)
        .execute(&mut conn)
        .await
        .expect("postgres duplicate APNs route should be inserted");
    }
    for (hash, id, token, updated_at) in [
        (old_hash.as_slice(), old_id.as_slice(), upper.as_str(), now),
        (
            winner_hash.as_slice(),
            winner_id.as_slice(),
            lower.as_str(),
            now + 10,
        ),
    ] {
        sqlx::query(
            "INSERT INTO private_bindings (platform, token_hash, device_id, provider_token, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $5)",
        )
        .bind(Platform::IOS.to_byte() as i16)
        .bind(hash)
        .bind(id)
        .bind(token)
        .bind(updated_at)
        .execute(&mut conn)
        .await
        .expect("postgres duplicate APNs binding should be inserted");
    }
    for (channel_byte, id, delivery, token) in [
        (3_u8, old_id.as_slice(), "pg-apns-old", upper.as_str()),
        (4_u8, winner_id.as_slice(), "pg-apns-winner", lower.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             VALUES ($1, $2, 'active', $3, $3)",
        )
        .bind(vec![channel_byte; 16])
        .bind(id)
        .bind(now)
        .execute(&mut conn)
        .await
        .expect("postgres APNs subscription should be inserted");
        sqlx::query(
            "INSERT INTO provider_pull_queue (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             VALUES ($1, $2, $3, 1, $4, $5, 'ios', $6, $4, $4)",
        )
        .bind(id)
        .bind(delivery)
        .bind(vec![1_u8])
        .bind(now)
        .bind(now + 60_000)
        .bind(token)
        .execute(&mut conn)
        .await
        .expect("postgres APNs pending pull should be inserted");
    }
    for (id, key, token) in [
        (
            PrivateDeviceId::derive("pg-fcm-upper").to_vec(),
            "pg-fcm-upper",
            "FcmCaseSensitiveToken0002",
        ),
        (
            PrivateDeviceId::derive("pg-fcm-lower").to_vec(),
            "pg-fcm-lower",
            "fcmcasesensitivetoken0002",
        ),
    ] {
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
             VALUES ($1, $2, $3, $4, 'android', 'fcm', $5, $6)",
        )
        .bind(id)
        .bind(token.as_bytes())
        .bind(Platform::ANDROID.to_byte() as i16)
        .bind(key)
        .bind(token)
        .bind(now)
        .execute(&mut conn)
        .await
        .expect("postgres FCM case variant should be inserted");
    }
    sqlx::query("DELETE FROM pushgo_schema_meta WHERE meta_key = 'provider_token_semantics_v1'")
        .execute(&mut conn)
        .await
        .expect("postgres normalization marker should be reset");
    conn.close().await.expect("postgres fixture close");

    let _reopened = Storage::new(Some(db_url))
        .await
        .expect("postgres token migration should succeed");
    let mut verify = PgConnection::connect(db_url)
        .await
        .expect("postgres token verification connection should succeed");
    let apns_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM devices WHERE platform = 'ios' AND provider_token = $1",
    )
    .bind(lower.as_str())
    .fetch_one(&mut verify)
    .await
    .expect("postgres canonical APNs count");
    assert_eq!(apns_devices, 1);
    let subscriptions: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions WHERE device_id = $1")
            .bind(winner_id.as_slice())
            .fetch_one(&mut verify)
            .await
            .expect("postgres merged subscription count");
    assert_eq!(subscriptions, 2);
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = $1 AND provider_token = $2",
    )
    .bind(winner_id.as_slice())
    .bind(lower.as_str())
    .fetch_one(&mut verify)
    .await
    .expect("postgres merged pending count");
    assert_eq!(pending, 2);
    let fcm: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM devices WHERE platform = 'android' AND provider_token IN ($1, $2)",
    )
    .bind("FcmCaseSensitiveToken0002")
    .bind("fcmcasesensitivetoken0002")
    .fetch_one(&mut verify)
    .await
    .expect("postgres FCM case count");
    assert_eq!(fcm, 2);
}

async fn assert_mysql_provider_token_case_migration(db_url: &str) {
    let lower = "ef".repeat(32);
    let upper = lower.to_ascii_uppercase();
    let old_key = "mysql-apns-case-old";
    let winner_key = "mysql-apns-case-winner";
    let old_id = PrivateDeviceId::derive(old_key).to_vec();
    let winner_id = PrivateDeviceId::derive(winner_key).to_vec();
    let mut winner_public_id = winner_id.clone();
    winner_public_id.resize(32, 0);
    let token_raw = DeviceInfo::from_token(Platform::IOS, lower.as_str())
        .expect("valid APNs fixture")
        .token_raw
        .to_vec();
    let old_hash = ProviderTokenSnapshot::from_token(upper.as_str())
        .hash()
        .expect("uppercase APNs hash")
        .to_vec();
    let winner_hash = ProviderTokenSnapshot::from_token(lower.as_str())
        .hash()
        .expect("lowercase APNs hash")
        .to_vec();
    let now = chrono::Utc::now().timestamp_millis();
    let mut conn = MySqlConnection::connect(db_url)
        .await
        .expect("mysql token fixture connection should succeed");
    for (id, key, token, updated_at) in [
        (old_id.as_slice(), old_key, upper.as_str(), now),
        (winner_id.as_slice(), winner_key, lower.as_str(), now + 10),
    ] {
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
             VALUES (?, ?, ?, ?, 'ios', 'apns', ?, ?)",
        )
        .bind(id)
        .bind(token_raw.as_slice())
        .bind(Platform::IOS.to_byte() as i16)
        .bind(key)
        .bind(token)
        .bind(updated_at)
        .execute(&mut conn)
        .await
        .expect("mysql duplicate APNs route should be inserted");
    }
    for (hash, id, token, updated_at) in [
        (old_hash.as_slice(), old_id.as_slice(), upper.as_str(), now),
        (
            winner_hash.as_slice(),
            winner_id.as_slice(),
            lower.as_str(),
            now + 10,
        ),
    ] {
        sqlx::query(
            "INSERT INTO private_bindings (platform, token_hash, device_id, provider_token, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(Platform::IOS.to_byte() as i16)
        .bind(hash)
        .bind(id)
        .bind(token)
        .bind(updated_at)
        .bind(updated_at)
        .execute(&mut conn)
        .await
        .expect("mysql duplicate APNs binding should be inserted");
    }
    for (channel_byte, id, delivery, token) in [
        (5_u8, old_id.as_slice(), "mysql-apns-old", upper.as_str()),
        (
            6_u8,
            winner_id.as_slice(),
            "mysql-apns-winner",
            lower.as_str(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             VALUES (?, ?, 'active', ?, ?)",
        )
        .bind(vec![channel_byte; 16])
        .bind(id)
        .bind(now)
        .bind(now)
        .execute(&mut conn)
        .await
        .expect("mysql APNs subscription should be inserted");
        sqlx::query(
            "INSERT INTO provider_pull_queue (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             VALUES (?, ?, ?, 1, ?, ?, 'ios', ?, ?, ?)",
        )
        .bind(id)
        .bind(delivery)
        .bind(vec![1_u8])
        .bind(now)
        .bind(now + 60_000)
        .bind(token)
        .bind(now)
        .bind(now)
        .execute(&mut conn)
        .await
        .expect("mysql APNs pending pull should be inserted");
    }
    for (id, key, token) in [
        (
            PrivateDeviceId::derive("mysql-fcm-upper").to_vec(),
            "mysql-fcm-upper",
            "FcmCaseSensitiveToken0003",
        ),
        (
            PrivateDeviceId::derive("mysql-fcm-lower").to_vec(),
            "mysql-fcm-lower",
            "fcmcasesensitivetoken0003",
        ),
    ] {
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
             VALUES (?, ?, ?, ?, 'android', 'fcm', ?, ?)",
        )
        .bind(id)
        .bind(token.as_bytes())
        .bind(Platform::ANDROID.to_byte() as i16)
        .bind(key)
        .bind(token)
        .bind(now)
        .execute(&mut conn)
        .await
        .expect("mysql FCM case variant should be inserted");
    }
    sqlx::query("DELETE FROM pushgo_schema_meta WHERE meta_key = 'provider_token_semantics_v1'")
        .execute(&mut conn)
        .await
        .expect("mysql normalization marker should be reset");
    conn.close().await.expect("mysql fixture close");

    let _reopened = Storage::new(Some(db_url))
        .await
        .expect("mysql token migration should succeed");
    let mut verify = MySqlConnection::connect(db_url)
        .await
        .expect("mysql token verification connection should succeed");
    let apns_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM devices WHERE platform = 'ios' AND provider_token = ?",
    )
    .bind(lower.as_str())
    .fetch_one(&mut verify)
    .await
    .expect("mysql canonical APNs count");
    assert_eq!(apns_devices, 1);
    let subscriptions: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions WHERE device_id = ?")
            .bind(winner_public_id.as_slice())
            .fetch_one(&mut verify)
            .await
            .expect("mysql merged subscription count");
    assert_eq!(subscriptions, 2);
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND provider_token = ?",
    )
    .bind(winner_id.as_slice())
    .bind(lower.as_str())
    .fetch_one(&mut verify)
    .await
    .expect("mysql merged pending count");
    assert_eq!(pending, 2);
    let fcm: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM devices WHERE platform = 'android' AND provider_token IN (?, ?)",
    )
    .bind("FcmCaseSensitiveToken0003")
    .bind("fcmcasesensitivetoken0003")
    .fetch_one(&mut verify)
    .await
    .expect("mysql FCM case count");
    assert_eq!(fcm, 2);
}

async fn seed_provider_finalize_transaction_fixture(
    storage: &Storage,
    op_id: &str,
    delivery_id: &str,
) {
    let now = chrono::Utc::now().timestamp_millis();
    assert!(matches!(
        storage
            .reserve_op_dedupe_pending(op_id, delivery_id, now)
            .await
            .expect("reserve external provider finalization dedupe"),
        OpDedupeReservation::Reserved
    ));
    assert!(
        storage
            .mark_op_dedupe_finalized(op_id, delivery_id, DedupeState::ProviderQueued)
            .await
            .expect("mark external provider queued")
    );
    storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [34; 16],
            model: "message".to_string(),
            entity_id: format!("{op_id}-entity"),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert external provider queued sender status");
}

async fn seed_provider_raw_discard_fixture(
    storage: &Storage,
    device_id: DeviceId,
    outer_delivery_id: &str,
    innocent_delivery_id: &str,
) -> i64 {
    let now = chrono::Utc::now().timestamp_millis();
    let innocent_message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    storage
        .insert_private_message(innocent_delivery_id, &innocent_message)
        .await
        .expect("innocent private payload should insert");
    storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: innocent_delivery_id.to_string(),
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
        .expect("innocent private outbox should insert");
    storage
        .enqueue_provider_pull_item(
            device_id,
            outer_delivery_id,
            &PrivateMessage {
                payload: vec![0xff, 0x00, 0x7f].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "raw-discard-provider-token",
        )
        .await
        .expect("invalid provider candidate should insert");
    now
}

async fn assert_provider_raw_discard_invariants(
    storage: &Storage,
    device_id: DeviceId,
    outer_delivery_id: &str,
    innocent_delivery_id: &str,
    now: i64,
) {
    let candidate = storage
        .peek_provider_candidate(device_id, outer_delivery_id, now)
        .await
        .expect("raw candidate lookup must ignore unrelated metadata")
        .expect("raw candidate should remain visible");
    assert_eq!(candidate.delivery_id, outer_delivery_id);
    assert_eq!(candidate.payload.as_ref(), [0xff, 0x00, 0x7f]);
    assert_eq!(
        storage
            .discard_invalid_provider_items(device_id, &[outer_delivery_id.to_string()], now,)
            .await
            .expect("invalid provider row should delete by outer ID only"),
        1
    );
    assert!(
        storage
            .peek_provider_candidate(device_id, outer_delivery_id, now)
            .await
            .expect("discarded raw candidate lookup should succeed")
            .is_none()
    );
    assert!(
        storage
            .load_private_outbox_entry(device_id, innocent_delivery_id)
            .await
            .expect("innocent private outbox lookup should succeed")
            .is_some(),
        "discarding a corrupt provider envelope must not ACK its inner delivery ID"
    );
    assert!(
        storage
            .load_private_message(innocent_delivery_id)
            .await
            .expect("innocent private payload lookup should succeed")
            .is_some(),
        "discarding a corrupt provider envelope must not delete its inner payload"
    );
}

async fn assert_postgres_provider_finalize_transaction_rollback(storage: &Storage, db_url: &str) {
    let op_id = "postgres-provider-finalize-rollback-op";
    let delivery_id = "postgres-provider-finalize-rollback-delivery";
    seed_provider_finalize_transaction_fixture(storage, op_id, delivery_id).await;
    let mut conn = PgConnection::connect(db_url)
        .await
        .expect("postgres finalization trigger connection should succeed");
    sqlx::query(
        "CREATE FUNCTION fail_provider_sender_finalize() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.dispatch_status IN ('provider_success', 'provider_failed') THEN \
             RAISE EXCEPTION 'injected sender finalization failure'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&mut conn)
    .await
    .expect("postgres finalization failure function should install");
    sqlx::raw_sql(
        "CREATE TRIGGER fail_provider_sender_finalize_trigger \
         BEFORE UPDATE ON sender_submit_status FOR EACH ROW \
         EXECUTE FUNCTION fail_provider_sender_finalize()",
    )
    .execute(&mut conn)
    .await
    .expect("postgres finalization failure trigger should install");
    assert!(
        storage
            .finalize_provider_dispatch_outcome(op_id, delivery_id, true)
            .await
            .is_err()
    );
    let states: (String, String) = sqlx::query_as(
        "SELECT d.state, s.status FROM dispatch_op_dedupe d \
         JOIN sender_submit_status s ON s.op_id = $1 WHERE d.delivery_id = $2",
    )
    .bind(op_id)
    .bind(delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("postgres rolled back states should be queryable");
    assert_eq!(states.0, DedupeState::ProviderQueued.as_str());
    assert_eq!(states.1, SenderSubmitStatusKind::ProviderQueued.as_str());
    sqlx::query("DROP TRIGGER fail_provider_sender_finalize_trigger ON sender_submit_status")
        .execute(&mut conn)
        .await
        .expect("postgres finalization trigger should drop");
    sqlx::query("DROP FUNCTION fail_provider_sender_finalize()")
        .execute(&mut conn)
        .await
        .expect("postgres finalization function should drop");
    storage
        .finalize_provider_dispatch_outcome(op_id, delivery_id, true)
        .await
        .expect("postgres finalization should recover after trigger removal");
}

async fn assert_mysql_provider_finalize_transaction_rollback(storage: &Storage, db_url: &str) {
    let op_id = "mysql-provider-finalize-rollback-op";
    let delivery_id = "mysql-provider-finalize-rollback-delivery";
    seed_provider_finalize_transaction_fixture(storage, op_id, delivery_id).await;
    let mut conn = MySqlConnection::connect(db_url)
        .await
        .expect("mysql finalization trigger connection should succeed");
    sqlx::raw_sql(
        "CREATE TRIGGER fail_provider_sender_finalize_trigger \
         BEFORE UPDATE ON sender_submit_status FOR EACH ROW \
         BEGIN \
           IF NEW.dispatch_status IN ('provider_success', 'provider_failed') THEN \
             SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected sender finalization failure'; \
           END IF; \
         END",
    )
    .execute(&mut conn)
    .await
    .expect("mysql finalization failure trigger should install");
    assert!(
        storage
            .finalize_provider_dispatch_outcome(op_id, delivery_id, true)
            .await
            .is_err()
    );
    let states: (String, String) = sqlx::query_as(
        "SELECT d.state, s.status FROM dispatch_op_dedupe d \
         JOIN sender_submit_status s ON s.op_id = ? WHERE d.delivery_id = ?",
    )
    .bind(op_id)
    .bind(delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("mysql rolled back states should be queryable");
    assert_eq!(states.0, DedupeState::ProviderQueued.as_str());
    assert_eq!(states.1, SenderSubmitStatusKind::ProviderQueued.as_str());
    sqlx::raw_sql("DROP TRIGGER fail_provider_sender_finalize_trigger")
        .execute(&mut conn)
        .await
        .expect("mysql finalization trigger should drop");
    storage
        .finalize_provider_dispatch_outcome(op_id, delivery_id, true)
        .await
        .expect("mysql finalization should recover after trigger removal");
}

#[tokio::test]
async fn postgres_exact_beta1_schema_migrates_to_formal_release() {
    let Some((_container, db_url)) = start_postgres_container() else {
        return;
    };
    wait_for_postgres(&db_url).await;

    let latest = latest_schema_migration();
    let mut conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres beta1 fixture connection should succeed");
    seed_exact_beta1_postgres(&mut conn).await;
    let sentinel = SenderSubmitStatusRecord {
        op_id: "postgres-v9-v10-sentinel-op".to_string(),
        channel_id: [4; 16],
        model: "message".to_string(),
        entity_id: "postgres-v9-v10-sentinel".to_string(),
        status: SenderSubmitStatusKind::Accepted,
        dispatch_status: None,
        accepted_at: 1,
        updated_at: 1,
        expires_at: i64::MAX,
    };
    sqlx::query(
        "INSERT INTO sender_submit_status \
         (op_id, channel_id, model, entity_id, status, dispatch_status, accepted_at, updated_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8)",
    )
    .bind(&sentinel.op_id)
    .bind(&sentinel.channel_id[..])
    .bind(&sentinel.model)
    .bind(&sentinel.entity_id)
    .bind(sentinel.status.as_str())
    .bind(sentinel.accepted_at)
    .bind(sentinel.updated_at)
    .bind(sentinel.expires_at)
    .execute(&mut conn)
    .await
    .expect("postgres beta1 sentinel should insert");
    conn.close().await.expect("postgres close should succeed");
    let migrated = Storage::new(Some(db_url.as_str()))
        .await
        .expect("exact postgres beta1 schema should migrate to formal v10");
    assert_eq!(
        migrated
            .load_sender_submit_status(&sentinel.op_id)
            .await
            .expect("postgres migrated sentinel lookup")
            .expect("postgres migrated sentinel should remain"),
        sentinel
    );
    assert_postgres_provider_finalize_transaction_rollback(&migrated, &db_url).await;
    let raw_device_id = [44; 16];
    let raw_outer_id = "postgres-raw-discard-outer";
    let raw_innocent_id = "postgres-raw-discard-innocent";
    let raw_now =
        seed_provider_raw_discard_fixture(&migrated, raw_device_id, raw_outer_id, raw_innocent_id)
            .await;
    let mut raw_conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres raw discard mutation connection should succeed");
    sqlx::query(
        "UPDATE provider_pull_queue SET platform = 'future-unsupported-platform' \
         WHERE device_id = $1 AND delivery_id = $2",
    )
    .bind(raw_device_id.as_slice())
    .bind(raw_outer_id)
    .execute(&mut raw_conn)
    .await
    .expect("postgres unsupported historical platform should seed");
    raw_conn
        .close()
        .await
        .expect("postgres raw discard mutation connection should close");
    assert_provider_raw_discard_invariants(
        &migrated,
        raw_device_id,
        raw_outer_id,
        raw_innocent_id,
        raw_now,
    )
    .await;
    let mut verify = PgConnection::connect(&db_url)
        .await
        .expect("postgres migrated verification connection should succeed");
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT migration_id, checksum, success FROM pushgo_schema_migrations WHERE migration_id = $1",
    )
    .bind(latest.id)
    .fetch_one(&mut verify)
    .await
    .expect("postgres formal migration ledger row should exist");
    assert_eq!(
        row,
        (latest.id.to_string(), latest.checksum.to_string(), true)
    );
    verify.close().await.expect("postgres verify close");
    drop(migrated);
    assert_postgres_provider_token_case_migration(&db_url).await;
}

#[tokio::test]
async fn postgres_init_hard_reset_legacy_runtime_preserves_base_data_and_recovers_writes() {
    let Some((_container, db_url)) = start_postgres_container() else {
        return;
    };
    wait_for_postgres(&db_url).await;

    let mut conn = PgConnection::connect(&db_url)
        .await
        .expect("postgres setup connection should succeed");
    for stmt in [
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL)",
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4') \
         ON CONFLICT (meta_key) DO UPDATE SET meta_value = EXCLUDED.meta_value",
        "CREATE TABLE IF NOT EXISTS channels (channel_id BYTEA PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BYTEA NOT NULL, device_id BYTEA NOT NULL, PRIMARY KEY (platform, token_hash))",
        "CREATE TABLE IF NOT EXISTS private_outbox (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, last_error_code TEXT, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id))",
        "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BYTEA NOT NULL, device_id BYTEA NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id))",
    ] {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("postgres legacy schema statement should succeed");
    }
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (decode('0102030405060708090a0b0c0d0e0f10', 'hex'), 'legacy-hash-boundary', 'legacy-boundary-channel', -1, 9223372036854775807)",
    )
    .execute(&mut conn)
    .await
    .expect("postgres legacy channel row should be inserted");
    sqlx::query(
        "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) \
         VALUES (decode('11111111111111111111111111111111', 'hex'), 'legacy-delivery-boundary-postgres', 'pending', 7, -1, 'legacy-error', -1)",
    )
    .execute(&mut conn)
    .await
    .expect("postgres legacy runtime row should be inserted");
    conn.close().await.expect("postgres close should succeed");

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("postgres storage should initialize from legacy schema");

    let mut verify = PgConnection::connect(&db_url)
        .await
        .expect("postgres verification connection should succeed");
    let schema_version: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut verify)
    .await
    .expect("postgres schema version query should succeed");
    assert_eq!(schema_version.as_deref(), Some(STORAGE_SCHEMA_VERSION));
    let backup_uri: Option<String> = sqlx::query_scalar(
        "SELECT backup_uri FROM pushgo_upgrade_runs WHERE backup_uri IS NOT NULL ORDER BY started_at DESC LIMIT 1",
    )
    .fetch_optional(&mut verify)
    .await
    .expect("postgres backup uri should be queryable");
    assert!(
        backup_uri
            .as_deref()
            .is_some_and(|value| value.starts_with("test://postgres/external-backup/")),
        "postgres managed upgrade should record external snapshot"
    );

    let preserved_channel_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE alias = 'legacy-boundary-channel'")
            .fetch_one(&mut verify)
            .await
            .expect("postgres preserved channel query should succeed");
    assert_eq!(preserved_channel_count, 1);

    let legacy_outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE delivery_id = 'legacy-delivery-boundary-postgres'",
    )
    .fetch_one(&mut verify)
    .await
    .expect("postgres legacy outbox query should succeed");
    assert_eq!(legacy_outbox_count, 0);

    let now = chrono::Utc::now().timestamp_millis();
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: "postgres-upgrade-boundary-device-key".to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(
                "android-token-postgres-upgrade-boundary-000000000001".to_string(),
            ),
            updated_at: now,
        })
        .await
        .expect("postgres route upsert should succeed after migration");
    let routes = storage
        .load_device_routes()
        .await
        .expect("postgres route load should succeed after migration");
    assert!(
        routes
            .iter()
            .any(|row| row.device_key == "postgres-upgrade-boundary-device-key"),
        "postgres migrated schema should accept new route writes"
    );
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
    assert!(
        matches!(&err, StoreError::Upgrade(message) if message.contains("Schema version mismatch")),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn mysql_exact_beta1_schema_repairs_identity_and_migrates_to_formal_release() {
    let Some((_container, db_url)) = start_mysql_container() else {
        return;
    };
    wait_for_mysql(&db_url).await;

    let latest = latest_schema_migration();
    let mut conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql beta1 fixture connection should succeed");
    seed_exact_beta1_mysql(&mut conn).await;
    let sentinel = SenderSubmitStatusRecord {
        op_id: "mysql-v9-v10-sentinel-op".to_string(),
        channel_id: [5; 16],
        model: "message".to_string(),
        entity_id: "mysql-v9-v10-sentinel".to_string(),
        status: SenderSubmitStatusKind::Accepted,
        dispatch_status: None,
        accepted_at: 1,
        updated_at: 1,
        expires_at: i64::MAX,
    };
    sqlx::query(
        "INSERT INTO sender_submit_status \
         (op_id, channel_id, model, entity_id, status, dispatch_status, accepted_at, updated_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(&sentinel.op_id)
    .bind(&sentinel.channel_id[..])
    .bind(&sentinel.model)
    .bind(&sentinel.entity_id)
    .bind(sentinel.status.as_str())
    .bind(sentinel.accepted_at)
    .bind(sentinel.updated_at)
    .bind(sentinel.expires_at)
    .execute(&mut conn)
    .await
    .expect("mysql beta1 sentinel should insert");

    let old_key = "CaseKey";
    let repaired_key = "casekey";
    let old_device_id = PrivateDeviceId::derive(old_key).into_inner();
    let repaired_device_id = PrivateDeviceId::derive(repaired_key).into_inner();
    let identity_delivery_id = "mysql-beta1-identity-pending";
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES (?, ?, ?, ?, 'android', 'fcm', ?, 1)",
    )
    .bind(old_device_id.as_slice())
    .bind(b"mysql-case-token-lower-000001".as_slice())
    .bind(Platform::ANDROID.to_byte() as i16)
    .bind(repaired_key)
    .bind("mysql-case-token-lower-000001")
    .execute(&mut conn)
    .await
    .expect("mysql beta1 inconsistent device identity should seed");
    sqlx::query(
        "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
         VALUES (?, ?, 'active', 1, 1)",
    )
    .bind([9_u8; 16].as_slice())
    .bind(old_device_id.as_slice())
    .execute(&mut conn)
    .await
    .expect("mysql beta1 old identity subscription should seed");
    sqlx::query(
        "INSERT INTO private_payloads \
         (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
         VALUES (?, ?, 1, 1, 9999999999999, 1, 1)",
    )
    .bind(identity_delivery_id)
    .bind([1_u8].as_slice())
    .execute(&mut conn)
    .await
    .expect("mysql beta1 identity payload should seed");
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
         VALUES (?, ?, 'pending', 0, 1, 1, 1, 1)",
    )
    .bind(old_device_id.as_slice())
    .bind(identity_delivery_id)
    .execute(&mut conn)
    .await
    .expect("mysql beta1 old identity outbox should seed");
    conn.close().await.expect("mysql close should succeed");
    let migrated = Storage::new(Some(db_url.as_str()))
        .await
        .expect("exact mysql beta1 schema should migrate to formal v10");
    assert_eq!(
        migrated
            .load_sender_submit_status(&sentinel.op_id)
            .await
            .expect("mysql migrated sentinel lookup")
            .expect("mysql migrated sentinel should remain"),
        sentinel
    );
    assert_mysql_provider_finalize_transaction_rollback(&migrated, &db_url).await;
    let raw_device_id = [45; 16];
    let raw_outer_id = "mysql-raw-discard-outer";
    let raw_innocent_id = "mysql-raw-discard-innocent";
    let raw_now =
        seed_provider_raw_discard_fixture(&migrated, raw_device_id, raw_outer_id, raw_innocent_id)
            .await;
    let mut raw_conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql raw discard mutation connection should succeed");
    sqlx::query(
        "UPDATE provider_pull_queue SET platform = 'future-unsupported-platform' \
         WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(raw_device_id.as_slice())
    .bind(raw_outer_id)
    .execute(&mut raw_conn)
    .await
    .expect("mysql unsupported historical platform should seed");
    raw_conn
        .close()
        .await
        .expect("mysql raw discard mutation connection should close");
    assert_provider_raw_discard_invariants(
        &migrated,
        raw_device_id,
        raw_outer_id,
        raw_innocent_id,
        raw_now,
    )
    .await;
    migrated
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: old_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some("mysql-case-token-upper-000001".to_string()),
            updated_at: 2,
        })
        .await
        .expect("case-distinct MySQL device key should insert after migration");
    let mut verify = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql migrated verification connection should succeed");
    let repaired_route_id: Vec<u8> =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE BINARY device_key = BINARY ?")
            .bind(repaired_key)
            .fetch_one(&mut verify)
            .await
            .expect("repaired MySQL device route should exist");
    assert_eq!(&repaired_route_id[..16], repaired_device_id.as_slice());
    let preserved_outbox: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(repaired_device_id.as_slice())
    .bind(identity_delivery_id)
    .fetch_one(&mut verify)
    .await
    .expect("repaired MySQL outbox should be queryable");
    assert_eq!(preserved_outbox, 1);
    let case_distinct_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM devices WHERE device_key IN ('CaseKey', 'casekey')",
    )
    .fetch_one(&mut verify)
    .await
    .expect("case-distinct MySQL devices should be countable");
    assert_eq!(case_distinct_devices, 2);
    sqlx::query(
        "INSERT INTO private_payloads \
         (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
         VALUES ('DeliveryCase', X'01', 1, 1, 2, 1, 1), ('deliverycase', X'02', 1, 1, 2, 1, 1)",
    )
    .execute(&mut verify)
    .await
    .expect("case-distinct MySQL delivery IDs must coexist");
    let row: (String, String, i8) = sqlx::query_as(
        "SELECT migration_id, checksum, success FROM pushgo_schema_migrations WHERE migration_id = ?",
    )
    .bind(latest.id)
    .fetch_one(&mut verify)
    .await
    .expect("mysql formal migration ledger row should exist");
    assert_eq!(row, (latest.id.to_string(), latest.checksum.to_string(), 1));
    verify.close().await.expect("mysql verify close");
    drop(migrated);
    assert_mysql_provider_token_case_migration(&db_url).await;
}

#[tokio::test]
async fn mysql_init_hard_reset_legacy_runtime_preserves_base_data_and_recovers_writes() {
    let Some((_container, db_url)) = start_mysql_container() else {
        return;
    };
    wait_for_mysql(&db_url).await;

    let mut conn = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql setup connection should succeed");
    for stmt in [
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
        "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4') \
         ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        "CREATE TABLE IF NOT EXISTS channels (channel_id BINARY(16) PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
        "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BINARY(32) NOT NULL, device_id BINARY(16) NOT NULL, PRIMARY KEY (platform, token_hash)) ENGINE=InnoDB",
        "CREATE TABLE IF NOT EXISTS private_outbox (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, last_error_code VARCHAR(64) NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
        "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BINARY(16) NOT NULL, device_id BINARY(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)) ENGINE=InnoDB",
    ] {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("mysql legacy schema statement should succeed");
    }
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (UNHEX('0102030405060708090A0B0C0D0E0F10'), 'legacy-hash-boundary', 'legacy-boundary-channel', -1, 9223372036854775807)",
    )
    .execute(&mut conn)
    .await
    .expect("mysql legacy channel row should be inserted");
    sqlx::query(
        "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) \
         VALUES (UNHEX('11111111111111111111111111111111'), 'legacy-delivery-boundary-mysql', 'pending', 7, -1, 'legacy-error', -1)",
    )
    .execute(&mut conn)
    .await
    .expect("mysql legacy runtime row should be inserted");
    conn.close().await.expect("mysql close should succeed");

    let storage = Storage::new(Some(db_url.as_str()))
        .await
        .expect("mysql storage should initialize from legacy schema");

    let mut verify = MySqlConnection::connect(&db_url)
        .await
        .expect("mysql verification connection should succeed");
    let schema_version: Option<String> = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
    )
    .fetch_optional(&mut verify)
    .await
    .expect("mysql schema version query should succeed");
    assert_eq!(schema_version.as_deref(), Some(STORAGE_SCHEMA_VERSION));
    let backup_uri: Option<String> = sqlx::query_scalar(
        "SELECT backup_uri FROM pushgo_upgrade_runs WHERE backup_uri IS NOT NULL ORDER BY started_at DESC LIMIT 1",
    )
    .fetch_optional(&mut verify)
    .await
    .expect("mysql backup uri should be queryable");
    assert!(
        backup_uri
            .as_deref()
            .is_some_and(|value| value.starts_with("test://mysql/external-backup/")),
        "mysql managed upgrade should record external snapshot"
    );

    let preserved_channel_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE alias = 'legacy-boundary-channel'")
            .fetch_one(&mut verify)
            .await
            .expect("mysql preserved channel query should succeed");
    assert_eq!(preserved_channel_count, 1);

    let legacy_outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE delivery_id = 'legacy-delivery-boundary-mysql'",
    )
    .fetch_one(&mut verify)
    .await
    .expect("mysql legacy outbox query should succeed");
    assert_eq!(legacy_outbox_count, 0);

    let now = chrono::Utc::now().timestamp_millis();
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: "mysql-upgrade-boundary-device-key".to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some("android-token-mysql-upgrade-boundary-000000000001".to_string()),
            updated_at: now,
        })
        .await
        .expect("mysql route upsert should succeed after migration");
    let routes = storage
        .load_device_routes()
        .await
        .expect("mysql route load should succeed after migration");
    assert!(
        routes
            .iter()
            .any(|row| row.device_key == "mysql-upgrade-boundary-device-key"),
        "mysql migrated schema should accept new route writes"
    );
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
    assert!(
        matches!(&err, StoreError::Upgrade(message) if message.contains("Schema version mismatch")),
        "unexpected error: {err:?}"
    );
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
