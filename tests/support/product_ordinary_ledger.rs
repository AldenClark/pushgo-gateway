//! Read-only oracles for fresh, isolated normal-product blackbox databases.
//! This is test support, not a product database abstraction or fixture server.
use std::path::{Path, PathBuf};

use sqlx::{Connection, MySqlConnection, PgConnection, SqliteConnection};

#[derive(Clone)]
pub enum ProductLedger {
    Sqlite {
        core: String,
        sidecars: Vec<String>,
    },
    #[allow(
        dead_code,
        reason = "Shared test oracle; external backends are exercised by provider, fallback and fault test crates"
    )]
    Postgres(String),
    #[allow(
        dead_code,
        reason = "Shared test oracle; external backends are exercised by provider, fallback and fault test crates"
    )]
    Mysql(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub message_id: String,
    pub accepted_at: i64,
    pub expires_at: i64,
    pub dedupe_until: i64,
    pub payload_bytes: i64,
    pub body_length: i64,
    pub targets: i64,
}

type SnapshotRow = (String, i64, i64, i64, i64, i64, i64);

impl From<SnapshotRow> for Snapshot {
    fn from(row: SnapshotRow) -> Self {
        Self {
            message_id: row.0,
            accepted_at: row.1,
            expires_at: row.2,
            dedupe_until: row.3,
            payload_bytes: row.4,
            body_length: row.5,
            targets: row.6,
        }
    }
}

impl ProductLedger {
    pub fn sqlite(path: &Path) -> Self {
        let stem = path.with_extension("");
        let sidecars = ["delivery", "dispatch"]
            .into_iter()
            .map(|kind| {
                format!(
                    "sqlite://{}.{}.sqlite?mode=rw",
                    stem.to_string_lossy(),
                    kind
                )
            })
            .collect();
        Self::Sqlite {
            core: format!("sqlite://{}?mode=rwc", path.to_string_lossy()),
            sidecars,
        }
    }

    /// Credentials remain inside the explicitly supplied isolated URL file.
    /// No existing database is reset, reused, dropped, or migrated by this helper.
    #[allow(
        dead_code,
        reason = "Shared test oracle; external backends are exercised by provider, fallback and fault test crates"
    )]
    pub async fn external_from_file(backend: &str, variable: &str) -> Self {
        let file =
            PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
                panic!("{variable} must name a freshly provisioned C10 URL file")
            }));
        let raw = std::fs::read_to_string(file).expect("isolated URL file should read");
        let raw = raw.trim().to_owned();
        let parsed = reqwest::Url::parse(&raw).expect("isolated URL should parse");
        assert!(
            matches!(parsed.host_str(), Some("127.0.0.1") | Some("localhost")),
            "product blackbox may only access the approved loopback test engine"
        );
        assert!(
            parsed
                .path()
                .trim_start_matches('/')
                .starts_with("c10_synthetic_"),
            "product blackbox requires a new C10 synthetic database"
        );
        match backend {
            "postgres" => {
                assert!(matches!(parsed.scheme(), "postgres" | "postgresql"));
                assert_eq!(parsed.port_or_known_default().unwrap_or(5432), 32772);
                let mut connection = PgConnection::connect(&raw)
                    .await
                    .expect("isolated PG should connect");
                let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')")
                    .fetch_one(&mut connection).await.expect("fresh PG inventory should read");
                assert_eq!(tables, 0, "refuse nonempty PG test database");
                connection
                    .close()
                    .await
                    .expect("close PG inventory connection");
                Self::Postgres(raw)
            }
            "mysql" => {
                assert_eq!(parsed.scheme(), "mysql");
                assert_eq!(parsed.port_or_known_default().unwrap_or(3306), 32773);
                let mut connection = MySqlConnection::connect(&raw)
                    .await
                    .expect("isolated MySQL should connect");
                let tables: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.tables WHERE table_schema=DATABASE()")
                    .fetch_one(&mut connection).await.expect("fresh MySQL inventory should read");
                assert_eq!(tables, 0, "refuse nonempty MySQL test database");
                connection
                    .close()
                    .await
                    .expect("close MySQL inventory connection");
                Self::Mysql(raw)
            }
            _ => panic!("unknown isolated product test backend"),
        }
    }

    pub fn url(&self) -> &str {
        match self {
            Self::Sqlite { core, .. } => core,
            Self::Postgres(url) | Self::Mysql(url) => url,
        }
    }

    pub async fn snapshot(&self, op_id: &str) -> Snapshot {
        // A real row is required: an empty legacy outbox is never evidence of ACK.
        const QUESTION: &str = "SELECT message_id,accepted_at,expires_at,dedupe_until,payload_bytes,length(payload_blob),(SELECT COUNT(*) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id) FROM ordinary_messages m WHERE op_id=?";
        let row: SnapshotRow = match self {
            Self::Sqlite { core, .. } => {
                let mut c = SqliteConnection::connect(core)
                    .await
                    .expect("open ordinary core");
                sqlx::query_as(QUESTION)
                    .bind(op_id)
                    .fetch_one(&mut c)
                    .await
                    .expect("ordinary identity must exist")
            }
            Self::Postgres(url) => {
                let mut c = PgConnection::connect(url).await.expect("open ordinary PG");
                sqlx::query_as("SELECT message_id,accepted_at,expires_at,dedupe_until,payload_bytes,CAST(octet_length(payload_blob) AS BIGINT),(SELECT COUNT(*) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id) FROM ordinary_messages m WHERE op_id=$1")
                    .bind(op_id).fetch_one(&mut c).await.expect("ordinary PG identity must exist")
            }
            Self::Mysql(url) => {
                let mut c = MySqlConnection::connect(url)
                    .await
                    .expect("open ordinary MySQL");
                // Normalize only the observer's text metadata. The native
                // binary identity comparison and storage stay unchanged.
                sqlx::query_as("SELECT CAST(message_id AS CHAR CHARACTER SET utf8mb4),accepted_at,expires_at,dedupe_until,payload_bytes,CAST(OCTET_LENGTH(payload_blob) AS SIGNED),(SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id) FROM ordinary_messages m WHERE op_id=?")
                    .bind(op_id).fetch_one(&mut c).await.expect("ordinary MySQL identity must exist")
            }
        };
        row.into()
    }

    pub async fn assert_capacity_released(&self) {
        const SQL: &str = "SELECT messages,targets,bytes,private_pending FROM ordinary_ledger_usage WHERE singleton=1";
        let usage: (i64, i64, i64, i64) = match self {
            Self::Sqlite { core, .. } => {
                let mut c = SqliteConnection::connect(core)
                    .await
                    .expect("open SQLite capacity oracle");
                sqlx::query_as(SQL)
                    .fetch_one(&mut c)
                    .await
                    .expect("SQLite capacity oracle should read")
            }
            Self::Postgres(url) => {
                let mut c = PgConnection::connect(url)
                    .await
                    .expect("open PG capacity oracle");
                sqlx::query_as(SQL)
                    .fetch_one(&mut c)
                    .await
                    .expect("PG capacity oracle should read")
            }
            Self::Mysql(url) => {
                let mut c = MySqlConnection::connect(url)
                    .await
                    .expect("open MySQL capacity oracle");
                sqlx::query_as(SQL)
                    .fetch_one(&mut c)
                    .await
                    .expect("MySQL capacity oracle should read")
            }
        };
        assert_eq!(
            usage,
            (0, 0, 0, 0),
            "ACK must release body, target and Private capacity exactly once"
        );
    }

    pub async fn assert_no_legacy_ordinary_writes(&self) {
        // These tests exercise only ordinary messages, so every legacy payload,
        // identity/status producer and dispatch consumer must remain empty.
        const TABLES: &[&str] = &[
            "private_payloads",
            "private_outbox",
            "provider_pull_queue",
            "dispatch_op_dedupe",
            "dispatch_submission",
            "provider_dispatch_outbox",
            "sender_submit_status",
            "semantic_id_registry",
        ];
        match self {
            Self::Sqlite { core, sidecars } => {
                for url in std::iter::once(core).chain(sidecars) {
                    let mut c = SqliteConnection::connect(url)
                        .await
                        .expect("open existing product database");
                    for table in TABLES {
                        let exists: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                        )
                        .bind(table)
                        .fetch_one(&mut c)
                        .await
                        .expect("inspect existing table");
                        if exists == 0 {
                            continue;
                        }
                        let count: i64 =
                            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                                .fetch_one(&mut c)
                                .await
                                .expect("legacy writer oracle should read");
                        assert_eq!(count, 0, "ordinary path wrote legacy {table}");
                    }
                }
            }
            Self::Postgres(url) => {
                let mut c = PgConnection::connect(url)
                    .await
                    .expect("open PG legacy oracle");
                for table in TABLES {
                    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                        .fetch_one(&mut c)
                        .await
                        .expect("PG legacy writer oracle should read");
                    assert_eq!(count, 0, "ordinary path wrote legacy {table}");
                }
            }
            Self::Mysql(url) => {
                let mut c = MySqlConnection::connect(url)
                    .await
                    .expect("open MySQL legacy oracle");
                for table in TABLES {
                    let count: i64 = sqlx::query_scalar(&format!(
                        "SELECT CAST(COUNT(*) AS SIGNED) FROM {table}"
                    ))
                    .fetch_one(&mut c)
                    .await
                    .expect("MySQL legacy writer oracle should read");
                    assert_eq!(count, 0, "ordinary path wrote legacy {table}");
                }
            }
        }
    }
}

pub fn guard_disk(path: &Path) {
    let output = std::process::Command::new("df")
        .args(["-Pk"])
        .arg(path)
        .output()
        .expect("disk guard should execute");
    assert!(output.status.success(), "disk guard failed");
    let output = String::from_utf8(output.stdout).expect("disk guard output should decode");
    let available = output
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .expect("disk available bytes should parse")
        * 1024;
    const REQUIRED: u64 = 4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
    assert!(
        available >= REQUIRED,
        "resource STOP: below 4GiB floor + 512MiB product-test growth reserve (available={available})"
    );
}
