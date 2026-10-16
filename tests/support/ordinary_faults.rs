//! Process and SQL fault controls for fresh normal-product blackbox databases.
//! Only Provider IO is synthetic; the executable, HTTP router and SQL are real.
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Connection, MySqlConnection, PgConnection, SqliteConnection};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use super::product_ordinary_ledger::{ProductLedger, guard_disk};

pub const AUTH: &str = "qa-gateway-local-synthetic";
pub const PASSWORD: &str = "qa-ordinary-fault-password";

pub struct ProductProcess {
    pub child: Child,
    pub directory: PathBuf,
    pub ledger: ProductLedger,
    pub base: String,
    pub client: Client,
    args: Vec<String>,
    log: PathBuf,
    scenario: PathBuf,
}

impl ProductProcess {
    pub async fn spawn(external: Option<ProductLedger>) -> Self {
        guard_disk(Path::new(env!("CARGO_MANIFEST_DIR")));
        let directory = if let Some(root) = std::env::var_os("C10_PRODUCT_EVIDENCE_DIR") {
            std::fs::create_dir_all(&root).unwrap();
            tempfile::Builder::new()
                .prefix("c10-synthetic-fault-")
                .tempdir_in(root)
                .unwrap()
        } else {
            tempfile::Builder::new()
                .prefix("c10-synthetic-fault-")
                .tempdir()
                .unwrap()
        }
        .keep();
        let scenario = directory.join("providers");
        std::fs::create_dir(&scenario).unwrap();
        // Time to acquire the real SQL lock after the observed network handoff.
        std::fs::write(
            scenario.join("scenario.json"),
            br#"{"synthetic_only":true,"status":202,"delay_ms":1000}"#,
        )
        .unwrap();
        let ledger =
            external.unwrap_or_else(|| ProductLedger::sqlite(&directory.join("gateway.sqlite")));
        let address = fresh_address();
        let base = format!("http://{address}");
        let args = vec![
            "--http-addr".into(),
            address,
            "--db-url".into(),
            ledger.url().into(),
            "--token".into(),
            AUTH.into(),
            "--token-service-url".into(),
            "http://127.0.0.1:1".into(),
            "--private-transports".into(),
            "false".into(),
            "--qa-provider-fixture-dir".into(),
            scenario.to_string_lossy().into_owned(),
        ];
        let log = directory.join("normal-gateway.log");
        let child = launch(&args, &log);
        let mut process = Self {
            child,
            directory,
            ledger,
            base,
            args,
            log,
            scenario,
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        };
        process.ready().await;
        process
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    pub async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "normal product exited before ready: {}",
                self.logs()
            );
            if self
                .client
                .get(&self.base)
                .bearer_auth(AUTH)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "normal product ready timeout: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Restart an already failed process, or kill only this owned test process.
    pub async fn restart(&mut self) {
        guard_disk(&self.directory);
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        self.child = launch(&self.args, &self.log);
        self.ready().await;
    }

    pub async fn post(&self, path: &str, input: &Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(AUTH)
            .json(input)
            .send()
            .await
            .unwrap()
    }

    pub async fn post_ok(&self, path: &str, input: &Value) -> Value {
        let response = self.post(path, input).await;
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, 200, "{path}: {body}; {}", self.logs());
        body
    }

    pub async fn register_channel(&self) -> (String, String) {
        let result = self
            .post_ok("/device/register", &json!({"platform":"android"}))
            .await;
        let key = result["data"]["device_key"].as_str().unwrap().to_owned();
        self.post_ok(
            "/channel/device",
            &json!({
                "platform":"android","device_key":key,"channel_type":"fcm",
                "provider_token":"qa-fcm-fault-synthetic-0123456789",
            }),
        )
        .await;
        let result = self
            .post_ok(
                "/channel/subscribe",
                &json!({
                    "device_key":key,"channel_name":"qa-normal-fault","password":PASSWORD,
                }),
            )
            .await;
        (
            key,
            result["data"]["channel_id"].as_str().unwrap().to_owned(),
        )
    }

    pub fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.scenario.join("records.jsonl"))
            .unwrap_or_default()
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    pub async fn network_started(&self, message: &str, minimum: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let records: Vec<_> = self
                .records()
                .into_iter()
                .filter(|record| record["data"]["message_id"] == message)
                .collect();
            if records.len() >= minimum {
                return records[0]["data"]["delivery_id"]
                    .as_str()
                    .unwrap()
                    .to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "network handoff not observed: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn settled(&self, op: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let response = self
                .client
                .get(format!("{}/send_status/{op}", self.base))
                .bearer_auth(AUTH)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let result: Value = response.json().await.unwrap();
            if result["data"]["status"] == "sent" {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "receipt COMMIT not observed: {result}; {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn failed_exit(&mut self) -> ExitStatus {
        // Three-second SQL lock timeout plus the existing 20-second bounded
        // product shutdown. This is a fault oracle, not a capacity time window.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    !status.success(),
                    "failed SQL receipt exited successfully: {}",
                    self.logs()
                );
                assert!(
                    self.logs().contains("product runtime failed"),
                    "missing product failure propagation: {}",
                    self.logs()
                );
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "SQL failure left normal process alive: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn assert_second_owner_rejected(&mut self, first_responds: bool) {
        let mut args = self.args.clone();
        args[1] = fresh_address();
        if let ProductLedger::Sqlite { core, .. } = &self.ledger {
            let parsed = reqwest::Url::parse(core).unwrap();
            let source = PathBuf::from(parsed.path());
            let alias = self.directory.join("same-dataset-alias.sqlite");
            #[cfg(unix)]
            std::os::unix::fs::symlink(source, &alias).unwrap();
            #[cfg(not(unix))]
            std::fs::hard_link(source, &alias).unwrap();
            args[3] = format!("sqlite://{}?mode=rwc&cache=private", alias.display());
        } else {
            let mut alias = reqwest::Url::parse(self.ledger.url()).unwrap();
            // Explicit default/connection options cannot manufacture a second
            // product identity for the same selected database.
            alias
                .query_pairs_mut()
                .append_pair("statement-cache-capacity", "1");
            args[3] = alias.into();
        }
        let log = self.directory.join("second-owner.log");
        let mut second = launch(&args, &log);
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = second.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = second.kill();
                let _ = second.wait();
                panic!("second owner did not reject within bounded startup");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(!status.success(), "second owner unexpectedly succeeded");
        let logs = std::fs::read_to_string(log).unwrap();
        assert!(
            logs.contains("another owner")
                || logs.contains("OwnerContention")
                || logs.contains("WouldBlock")
                || logs.contains("os error 35")
                || logs.contains("os error 11"),
            "second process failed for a reason other than ownership: {logs}"
        );
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "second-owner rejection stopped the first process"
        );
        if first_responds {
            assert!(
                self.client
                    .get(&self.base)
                    .bearer_auth(AUTH)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
        }
    }

    pub fn evidence(&self, value: &Value) {
        std::fs::write(
            self.directory.join("normal-fault-result.json"),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
        eprintln!(
            "normal product SQL fault evidence: {}",
            self.directory.display()
        );
    }
}

impl Drop for ProductProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fresh_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn launch(args: &[String], log: &Path) -> Child {
    let output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
        .args(args)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output))
        .spawn()
        .unwrap()
}

/// A real database write lock, not a synthetic error or failed authentication.
pub enum WriteBlock {
    Sqlite(SqliteConnection),
    Postgres(PgConnection),
    Mysql(MySqlConnection),
}
impl WriteBlock {
    pub async fn acquire(ledger: &ProductLedger) -> Self {
        match ledger {
            ProductLedger::Sqlite { core, .. } => {
                let mut connection = SqliteConnection::connect(core).await.unwrap();
                sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                Self::Sqlite(connection)
            }
            ProductLedger::Postgres(url) => {
                let mut connection = PgConnection::connect(url).await.unwrap();
                sqlx::query("BEGIN").execute(&mut connection).await.unwrap();
                sqlx::query(
                    "SELECT singleton FROM ordinary_ledger_usage WHERE singleton=1 FOR UPDATE",
                )
                .fetch_one(&mut connection)
                .await
                .unwrap();
                Self::Postgres(connection)
            }
            ProductLedger::Mysql(url) => {
                let mut connection = MySqlConnection::connect(url).await.unwrap();
                // Administrative transaction control uses MySQL's text
                // protocol; BEGIN is not supported by COM_STMT_PREPARE.
                sqlx::raw_sql("BEGIN")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                sqlx::query(
                    "SELECT singleton FROM ordinary_ledger_usage WHERE singleton=1 FOR UPDATE",
                )
                .fetch_one(&mut connection)
                .await
                .unwrap();
                Self::Mysql(connection)
            }
        }
    }

    pub async fn release(self) {
        match self {
            Self::Sqlite(mut connection) => {
                sqlx::query("ROLLBACK")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                connection.close().await.unwrap();
            }
            Self::Postgres(mut connection) => {
                sqlx::query("ROLLBACK")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                connection.close().await.unwrap();
            }
            Self::Mysql(mut connection) => {
                sqlx::raw_sql("ROLLBACK")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                connection.close().await.unwrap();
            }
        }
    }
}

/// Pause only the child owned by this test. RAII resumes it on an assertion
/// failure so cleanup never leaves a suspended test process behind.
#[cfg(unix)]
pub struct SuspendedProcess(u32);
#[cfg(unix)]
impl SuspendedProcess {
    pub async fn new(process: &ProductProcess) -> Self {
        assert!(
            signal(process.child.id(), "-STOP"),
            "could not suspend owned Gateway child"
        );
        let suspended = Self(process.child.id());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let state = Command::new("ps")
                .args(["-o", "stat=", "-p", &process.child.id().to_string()])
                .output()
                .unwrap();
            assert!(
                state.status.success(),
                "owned Gateway child disappeared before suspension"
            );
            if String::from_utf8(state.stdout).unwrap().contains('T') {
                return suspended;
            }
            assert!(
                Instant::now() < deadline,
                "owned Gateway child did not enter stopped OS state"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
#[cfg(unix)]
impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        // Cleanup cannot turn an earlier test panic into a double-panic abort.
        let _ = signal(self.0, "-CONT");
    }
}
#[cfg(unix)]
fn signal(pid: u32, name: &str) -> bool {
    Command::new("kill")
        .args([name, &pid.to_string()])
        .status()
        .is_ok_and(|result| result.success())
}

/// Terminate only the fixed owner session selected by the current synthetic
/// database's actual native lock identity. Never enumerate or kill other DBs.
pub async fn terminate_fixed_owner_session(ledger: &ProductLedger) {
    match ledger {
        ProductLedger::Postgres(url) => {
            let mut connection = PgConnection::connect(url).await.unwrap();
            let owners: Vec<i32> = sqlx::query_scalar("SELECT pid FROM pg_catalog.pg_locks WHERE locktype='advisory' AND classid=1346852687::bigint::oid AND objid=1330791756::bigint::oid AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())")
                .fetch_all(&mut connection).await.unwrap();
            assert_eq!(
                owners.len(),
                1,
                "fresh synthetic DB must have exactly one fixed product owner"
            );
            let terminated: bool = sqlx::query_scalar("SELECT pg_catalog.pg_terminate_backend($1)")
                .bind(owners[0])
                .fetch_one(&mut connection)
                .await
                .unwrap();
            assert!(
                terminated,
                "failed to terminate the test-owned PG lock session"
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=$1 AND classid=1346852687::bigint::oid AND objid=1330791756::bigint::oid AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()))")
                    .bind(owners[0]).fetch_one(&mut connection).await.unwrap();
                if !exists {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "terminated PG owner still holds its native lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            connection.close().await.unwrap();
        }
        ProductLedger::Mysql(url) => {
            let mut connection = MySqlConnection::connect(url).await.unwrap();
            let uuid: String = sqlx::query_scalar("SELECT CAST(dataset_uuid AS CHAR CHARACTER SET utf8mb4) FROM pushgo_product_owner WHERE singleton=1")
                .fetch_one(&mut connection).await.unwrap();
            assert_eq!(uuid.len(), 32);
            assert!(uuid.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let owner: Option<u64> = sqlx::query_scalar("SELECT IS_USED_LOCK(?)")
                .bind(format!("pushgo-product-{uuid}"))
                .fetch_one(&mut connection)
                .await
                .unwrap();
            let owner = owner.expect("fresh synthetic DB must have a fixed MySQL owner");
            assert!(owner > 0);
            sqlx::raw_sql(&format!("KILL CONNECTION {owner}"))
                .execute(&mut connection)
                .await
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let current: Option<u64> = sqlx::query_scalar("SELECT IS_USED_LOCK(?)")
                    .bind(format!("pushgo-product-{uuid}"))
                    .fetch_one(&mut connection)
                    .await
                    .unwrap();
                if current.is_none() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "terminated MySQL owner still holds its native lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            connection.close().await.unwrap();
        }
        ProductLedger::Sqlite { .. } => {
            panic!("SQLite file owner has no remote session to terminate")
        }
    }
}

/// Read while the transaction is blocked, proving no successful receipt/ACK
/// became visible and no body was released before durable mutation succeeded.
pub async fn target_state(
    ledger: &ProductLedger,
    delivery: &str,
) -> (String, Option<i64>, Option<i64>) {
    match ledger {
        ProductLedger::Sqlite { core, .. } => {
            let mut connection = SqliteConnection::connect(core).await.unwrap();
            sqlx::query_as(
                "SELECT state,receipt_at,acked_at FROM ordinary_targets WHERE delivery_id=?",
            )
            .bind(delivery)
            .fetch_one(&mut connection)
            .await
            .unwrap()
        }
        ProductLedger::Postgres(url) => {
            let mut connection = PgConnection::connect(url).await.unwrap();
            sqlx::query_as(
                "SELECT state,receipt_at,acked_at FROM ordinary_targets WHERE delivery_id=$1",
            )
            .bind(delivery)
            .fetch_one(&mut connection)
            .await
            .unwrap()
        }
        ProductLedger::Mysql(url) => {
            let mut connection = MySqlConnection::connect(url).await.unwrap();
            sqlx::query_as("SELECT CAST(state AS CHAR CHARACTER SET utf8mb4),receipt_at,acked_at FROM ordinary_targets WHERE delivery_id=?")
                .bind(delivery).fetch_one(&mut connection).await.unwrap()
        }
    }
}
