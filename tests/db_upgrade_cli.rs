use std::process::Command;

use tempfile::tempdir;

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
        "2026-04-22-gateway-v9"
    );
    assert_eq!(
        completed_upgrade_runs(db_path.to_string_lossy().as_ref()),
        1,
        "run should record a completed upgrade run"
    );
}

fn seed_legacy_sqlite(path: &str) {
    run_sqlite3(
        path,
        "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL);
         INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4');
         CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash));",
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
