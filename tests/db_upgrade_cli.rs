use std::process::Command;

use tempfile::tempdir;

const STORAGE_SCHEMA_VERSION: &str = "2026-08-20-gateway-v12";
const STORAGE_SCHEMA_VERSION_BETA1: &str = "2026-04-22-gateway-v9";
const STORAGE_SCHEMA_VERSION_MIGRATABLE: &str = "2026-04-17-gateway-v8";
const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-04-16-gateway-v7";
const STORAGE_SCHEMA_VERSION_LEGACY: &str = "2026-04-13-gateway-v6";
const STORAGE_SCHEMA_VERSION_OLDER_LEGACY: &str = "2026-03-26-gateway-v5";
const STORAGE_SCHEMA_VERSION_OLDEST_LEGACY: &str = "2026-03-18-gateway-v4";
const DEVICE_IDENTITY_V8_MIGRATION_ID: &str = "20260417_001_device_identity_v8";
const DEVICE_IDENTITY_V8_CHECKSUM: &str =
    "sha256:426de3f380802b8706ddd10151d30d4ba8286fddb234eeefc7800c42d7860a29";
const OBSERVABILITY_V9_MIGRATION_ID: &str = "20260422_001_observability_v9";
const OBSERVABILITY_V9_CHECKSUM: &str =
    "sha256:8f4cb15c7dc5a328a88f596f59eaec157045a78287cf27a52f88f0a5518f5e47";
const FORMAL_RELEASE_V10_MIGRATION_ID: &str = "20260805_001_release_v10";
const FORMAL_RELEASE_V10_CHECKSUM: &str =
    "sha256:f526ca103e36ed4ca6a0e0bddb6ebe2aff757a4c11417ff7d26500e2513b0bb1";
const CONCURRENCY_FENCING_V11_MIGRATION_ID: &str = "20260808_001_concurrency_fencing_v11";
const CONCURRENCY_FENCING_V11_CHECKSUM: &str =
    "sha256:5ac8609854a01918f99f837fb1240aa74c8543f17fa777cf786520884271296e";
const BETA1_TAG: &str = "v1.3.0-beta.1";
const BETA1_COMMIT: &str = "a84a937ccc7cbcce99c5a0e37f35ed2d0fe55906";

#[test]
fn db_upgrade_plan_and_run_are_explicit_cli_paths() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("cli-upgrade.sqlite");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    seed_legacy_sqlite(db_path.to_string_lossy().as_ref());

    let bin = env!("CARGO_BIN_EXE_pushgo-gateway");
    let plan = Command::new(bin)
        .args(["--db-url", db_url.as_str(), "--db-upgrade", "plan"])
        .output()
        .expect("db-upgrade plan should execute");
    assert!(
        plan.status.success(),
        "db-upgrade plan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&plan.stdout),
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(plan_stdout.contains("[upgrade] check started driver=sqlite"));
    assert!(plan_stdout.contains("action=hard_reset_runtime"));
    assert!(
        !table_exists(db_path.to_string_lossy().as_ref(), "pushgo_upgrade_runs"),
        "plan must not create upgrade state tables"
    );

    let run = Command::new(bin)
        .args(["--db-url", db_url.as_str(), "--db-upgrade", "run"])
        .output()
        .expect("db-upgrade run should execute");
    assert!(
        run.status.success(),
        "db-upgrade run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let run_stdout = String::from_utf8_lossy(&run.stdout);
    assert!(run_stdout.contains("[upgrade] backup completed"));
    assert!(run_stdout.contains("[upgrade] verify completed"));
    assert!(run_stdout.contains("[upgrade] completed"));
    assert_eq!(
        schema_version(db_path.to_string_lossy().as_ref()),
        STORAGE_SCHEMA_VERSION
    );
    assert_eq!(
        completed_upgrade_runs(db_path.to_string_lossy().as_ref()),
        1,
        "run should record a completed upgrade run"
    );
}

#[test]
fn db_upgrade_run_accepts_multiple_legacy_sqlite_versions_with_data() {
    for version in [
        STORAGE_SCHEMA_VERSION_OLDEST_LEGACY,
        STORAGE_SCHEMA_VERSION_OLDER_LEGACY,
        STORAGE_SCHEMA_VERSION_LEGACY,
        STORAGE_SCHEMA_VERSION_PREVIOUS,
    ] {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join(format!("cli-upgrade-{version}.sqlite"));
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        seed_legacy_runtime_sqlite(db_path.to_string_lossy().as_ref(), Some(version));

        let run = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "run"]);
        assert!(
            run.status.success(),
            "db-upgrade run failed for {version}: stdout={} stderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            stdout.contains("action=hard_reset_runtime"),
            "legacy {version} should hard-reset runtime tables: {stdout}"
        );
        assert!(
            stdout.contains("[upgrade] backup completed"),
            "legacy {version} should create a backup: {stdout}"
        );
        assert_upgraded_sqlite(db_path.to_string_lossy().as_ref());
        assert_eq!(
            table_row_count(db_path.to_string_lossy().as_ref(), "private_bindings"),
            0,
            "legacy runtime bindings should be reset for {version}"
        );

        let backup_uri = latest_backup_uri(db_path.to_string_lossy().as_ref())
            .expect("legacy hard reset should record a backup uri");
        assert!(
            std::path::Path::new(backup_uri.as_str()).exists(),
            "backup should exist for {version}: {backup_uri}"
        );
        assert_eq!(
            table_row_count(backup_uri.as_str(), "private_bindings"),
            1,
            "backup should retain pre-upgrade runtime data for {version}"
        );

        let rerun = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "run"]);
        assert!(
            rerun.status.success(),
            "second db-upgrade run should be idempotent for {version}: stdout={} stderr={}",
            String::from_utf8_lossy(&rerun.stdout),
            String::from_utf8_lossy(&rerun.stderr)
        );
        assert_eq!(
            completed_upgrade_runs(db_path.to_string_lossy().as_ref()),
            1,
            "explicit no-op rerun must not create another upgrade-run record for {version}"
        );
    }
}

#[test]
fn db_upgrade_run_accepts_legacy_sqlite_runtime_without_schema_meta() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("cli-upgrade-no-schema-meta.sqlite");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    seed_legacy_runtime_sqlite(db_path.to_string_lossy().as_ref(), None);

    let run = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "run"]);
    assert!(
        run.status.success(),
        "db-upgrade run failed for no-schema legacy db: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("current schema=none action=hard_reset_runtime"));
    assert_upgraded_sqlite(db_path.to_string_lossy().as_ref());
    assert_eq!(
        table_row_count(db_path.to_string_lossy().as_ref(), "private_bindings"),
        0,
        "legacy runtime data should be reset after no-meta hard reset"
    );
}

#[test]
fn db_upgrade_run_accepts_v8_sqlite_with_observability_data() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("cli-upgrade-v8.sqlite");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    seed_v8_sqlite(db_path.to_string_lossy().as_ref());

    let run = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "run"]);
    assert!(
        run.status.success(),
        "db-upgrade run failed for v8 db: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("current schema=2026-04-17-gateway-v8 action=backfill_current"),
        "v8 should use in-place backfill: {stdout}"
    );
    assert!(
        stdout.contains("[upgrade] backup completed"),
        "v8 to formal v10 includes a required backup migration: {stdout}"
    );
    assert_upgraded_sqlite(db_path.to_string_lossy().as_ref());
    assert!(
        !table_exists(db_path.to_string_lossy().as_ref(), "delivery_audit"),
        "v8 upgrade should drop deprecated delivery_audit"
    );
    assert_eq!(
        table_row_count(db_path.to_string_lossy().as_ref(), "private_bindings"),
        1,
        "v8 in-place backfill should keep current runtime bindings"
    );
    assert_eq!(
        migration_count(
            db_path.to_string_lossy().as_ref(),
            OBSERVABILITY_V9_MIGRATION_ID
        ),
        1,
        "v8 upgrade should record the v9 migration"
    );
    assert_eq!(
        migration_count(
            db_path.to_string_lossy().as_ref(),
            FORMAL_RELEASE_V10_MIGRATION_ID
        ),
        1,
        "v8 upgrade should record the formal v10 migration"
    );
}

#[test]
fn db_upgrade_run_migrates_beta1_v9_to_current_schema() {
    let dir = tempdir().expect("tempdir should be created");
    let db_path = dir.path().join("cli-upgrade-v9-to-current.sqlite");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    seed_v9_sqlite(db_path.to_string_lossy().as_ref());

    let plan = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "plan"]);
    assert!(plan.status.success());
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(
        plan_stdout
            .contains("current schema=2026-04-22-gateway-v9 action=backfill_current pending=3"),
        "beta1 must expose the formal, fencing, and durable-dispatch migrations: {plan_stdout}"
    );

    let run = run_gateway(&["--db-url", db_url.as_str(), "--db-upgrade", "run"]);
    assert!(
        run.status.success(),
        "v9 to current schema upgrade failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("migration=20260805_001_release_v10"));
    assert!(stdout.contains("migration=20260808_001_concurrency_fencing_v11"));
    assert!(stdout.contains("[upgrade] backup completed"));
    assert_upgraded_sqlite(db_path.to_string_lossy().as_ref());
    assert_eq!(
        table_row_count(db_path.to_string_lossy().as_ref(), "private_bindings"),
        1,
        "v9 to current schema must preserve runtime bindings"
    );
}

fn seed_legacy_sqlite(path: &str) {
    seed_legacy_runtime_sqlite(path, Some(STORAGE_SCHEMA_VERSION_OLDEST_LEGACY));
}

fn seed_legacy_runtime_sqlite(path: &str, schema_version: Option<&str>) {
    let meta = schema_version.map_or_else(String::new, |version| {
        format!(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL);
             INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '{version}');"
        )
    });
    run_sqlite3(
        path,
        format!(
            "{meta}
             CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash));
             CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id));
             CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id));
             CREATE TABLE IF NOT EXISTS delivery_audit (audit_id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, created_at INTEGER NOT NULL);
             INSERT OR REPLACE INTO channels (channel_id, password_hash, alias, created_at, updated_at) VALUES (X'01010101010101010101010101010101', 'legacy-hash', 'legacy', 1700000000, 1700000001);
             INSERT OR REPLACE INTO private_bindings (platform, token_hash, device_id) VALUES (1, X'0202020202020202020202020202020202020202020202020202020202020202', X'03030303030303030303030303030303');
             INSERT OR REPLACE INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) VALUES (X'03030303030303030303030303030303', 'legacy-delivery', 'pending', 1, 1700000002, NULL, 1700000003);
             INSERT OR REPLACE INTO channel_subscriptions (channel_id, device_id, platform, channel_type, created_at, updated_at) VALUES (X'01010101010101010101010101010101', X'03030303030303030303030303030303', 'android', 'fcm', 1700000004, 1700000005);
             INSERT OR REPLACE INTO delivery_audit (audit_id, delivery_id, created_at) VALUES ('legacy-audit', 'legacy-delivery', 1700000006);"
        )
        .as_str(),
    );
}

fn seed_v8_sqlite(path: &str) {
    run_sqlite3(
        path,
        format!(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL);
             INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '{STORAGE_SCHEMA_VERSION_MIGRATABLE}');
             CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (migration_id TEXT PRIMARY KEY, description TEXT NOT NULL, checksum TEXT NOT NULL, target_schema_version TEXT NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL, execution_ms INTEGER NOT NULL, success INTEGER NOT NULL, error TEXT);
             INSERT OR REPLACE INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error)
             VALUES ('{DEVICE_IDENTITY_V8_MIGRATION_ID}', 'v8 fixture', '{DEVICE_IDENTITY_V8_CHECKSUM}', '{STORAGE_SCHEMA_VERSION_MIGRATABLE}', 1, 1, 0, 1, NULL);
             CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (platform, token_hash));
             CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id));
             CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id));
             CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id));
             CREATE TABLE IF NOT EXISTS delivery_audit (audit_id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, created_at INTEGER NOT NULL);
             INSERT OR REPLACE INTO private_bindings (platform, token_hash, device_id, provider_token, created_at, updated_at) VALUES (1, X'0202020202020202020202020202020202020202020202020202020202020202', X'03030303030303030303030303030303', 'fixture-provider-token', 1700000000000, 1700000000001);
             INSERT OR REPLACE INTO delivery_audit (audit_id, delivery_id, created_at) VALUES ('v8-audit', 'v8-delivery', 1700000000002);"
        )
        .as_str(),
    );
}

fn seed_v9_sqlite(path: &str) {
    let source = beta1_bootstrap_source("sqlite");
    for array in [
        "SQLITE_BASE_TABLE_STATEMENTS",
        "SQLITE_RUNTIME_TABLE_STATEMENTS",
        "SQLITE_BASE_INDEX_STATEMENTS",
        "SQLITE_RUNTIME_INDEX_STATEMENTS",
    ] {
        for statement in rust_string_array(&source, array) {
            run_sqlite3(path, format!("{statement};").as_str());
        }
    }
    run_sqlite3(
        path,
        format!(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (migration_id TEXT PRIMARY KEY, description TEXT NOT NULL, checksum TEXT NOT NULL, target_schema_version TEXT NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL, execution_ms INTEGER NOT NULL, success INTEGER NOT NULL, error TEXT);
             INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '{STORAGE_SCHEMA_VERSION_BETA1}');
             INSERT OR REPLACE INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error)
             VALUES ('{DEVICE_IDENTITY_V8_MIGRATION_ID}', 'beta1 exact v8 ledger', '{DEVICE_IDENTITY_V8_CHECKSUM}', '{STORAGE_SCHEMA_VERSION_MIGRATABLE}', 1, 1, 0, 1, NULL);
             INSERT OR REPLACE INTO pushgo_schema_migrations (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error)
             VALUES ('{OBSERVABILITY_V9_MIGRATION_ID}', 'beta1 exact v9 ledger', '{OBSERVABILITY_V9_CHECKSUM}', '{STORAGE_SCHEMA_VERSION_BETA1}', 2, 2, 0, 1, NULL);
             INSERT INTO private_bindings (platform, token_hash, device_id, provider_token, created_at, updated_at)
             VALUES (1, X'0202020202020202020202020202020202020202020202020202020202020202', X'03030303030303030303030303030303', 'fixture-provider-token', 1700000000000, 1700000000001);"
        )
        .as_str(),
    );
}

fn beta1_bootstrap_source(backend: &str) -> String {
    let resolved = Command::new("git")
        .args(["rev-parse", &format!("{BETA1_TAG}^{{commit}}")])
        .output()
        .expect("git rev-parse for beta1 tag should execute");
    assert!(
        resolved.status.success(),
        "the exact beta1 tag is required for upgrade fixtures"
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

fn run_gateway(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
        .args(args)
        .output()
        .expect("pushgo-gateway should execute")
}

fn assert_upgraded_sqlite(path: &str) {
    assert_eq!(schema_version(path), STORAGE_SCHEMA_VERSION);
    assert_eq!(migration_count(path, OBSERVABILITY_V9_MIGRATION_ID), 1);
    assert_eq!(
        sqlite3_scalar(
            path,
            format!(
                "SELECT checksum FROM pushgo_schema_migrations WHERE migration_id='{OBSERVABILITY_V9_MIGRATION_ID}';"
            )
            .as_str(),
        ),
        OBSERVABILITY_V9_CHECKSUM
    );
    assert_eq!(migration_count(path, FORMAL_RELEASE_V10_MIGRATION_ID), 1);
    assert_eq!(
        sqlite3_scalar(
            path,
            format!(
                "SELECT checksum FROM pushgo_schema_migrations WHERE migration_id='{FORMAL_RELEASE_V10_MIGRATION_ID}';"
            )
            .as_str(),
        ),
        FORMAL_RELEASE_V10_CHECKSUM
    );
    assert_eq!(
        migration_count(path, CONCURRENCY_FENCING_V11_MIGRATION_ID),
        1
    );
    assert_eq!(
        sqlite3_scalar(
            path,
            format!(
                "SELECT checksum FROM pushgo_schema_migrations WHERE migration_id='{CONCURRENCY_FENCING_V11_MIGRATION_ID}';"
            )
            .as_str(),
        ),
        CONCURRENCY_FENCING_V11_CHECKSUM
    );
    assert_eq!(
        completed_upgrade_runs(path),
        1,
        "first explicit upgrade should record one completed run"
    );
}

fn table_exists(path: &str, table: &str) -> bool {
    sqlite3_scalar(
        path,
        format!("SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='{table}';")
            .as_str(),
    ) != "0"
}

fn schema_version(path: &str) -> String {
    sqlite3_scalar(
        path,
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version';",
    )
}

fn completed_upgrade_runs(path: &str) -> i64 {
    sqlite3_scalar(
        path,
        "SELECT COUNT(1) FROM pushgo_upgrade_runs WHERE status='completed';",
    )
    .parse()
    .expect("completed upgrade count should parse")
}

fn latest_backup_uri(path: &str) -> Option<String> {
    let value = sqlite3_scalar(
        path,
        "SELECT COALESCE(backup_uri, '') FROM pushgo_upgrade_runs WHERE backup_uri IS NOT NULL ORDER BY started_at DESC LIMIT 1;",
    );
    (!value.is_empty()).then_some(value)
}

fn table_row_count(path: &str, table: &str) -> i64 {
    sqlite3_scalar(path, format!("SELECT COUNT(1) FROM {table};").as_str())
        .parse()
        .expect("table row count should parse")
}

fn migration_count(path: &str, migration_id: &str) -> i64 {
    sqlite3_scalar(
        path,
        format!("SELECT COUNT(1) FROM pushgo_schema_migrations WHERE migration_id='{migration_id}' AND success=1;").as_str(),
    )
    .parse()
    .expect("migration count should parse")
}

fn sqlite3_scalar(path: &str, sql: &str) -> String {
    let output = Command::new("sqlite3")
        .args([path, sql])
        .output()
        .expect("sqlite3 should execute");
    assert!(
        output.status.success(),
        "sqlite3 scalar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn run_sqlite3(path: &str, sql: &str) {
    let output = Command::new("sqlite3")
        .args([path, sql])
        .output()
        .expect("sqlite3 should execute");
    assert!(
        output.status.success(),
        "sqlite3 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
