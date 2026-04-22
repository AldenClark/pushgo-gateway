use super::*;
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
