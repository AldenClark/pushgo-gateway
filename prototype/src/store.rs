use crate::profiling::{Path, Phase, Statement};
pub use crate::sender::AcceptRequest;
use crate::types::{Platform, generate_hex_id_128, normalize_provider_token};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
    fs::File,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

pub fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
#[derive(Clone, Debug)]
pub struct Config {
    pub max_messages: i64,
    pub max_targets: i64,
    pub max_payload_bytes: i64,
    pub max_body_bytes: usize,
    pub max_handlers: usize,
    pub provider_budget: usize,
    pub claim_quantum: usize,
    pub default_ttl_secs: i64,
    pub dedupe_retention_ms: i64,
    pub public_base_url: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_messages: 10_000,
            max_targets: 1_000_000,
            max_payload_bytes: i64::MAX,
            max_body_bytes: 32 * 1024,
            max_handlers: 128,
            provider_budget: 32,
            claim_quantum: 32,
            default_ttl_secs: 7 * 86_400,
            dedupe_retention_ms: 30 * 86_400_000,
            public_base_url: "http://127.0.0.1:65535".into(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("{message}")]
    Control {
        status: u16,
        code: &'static str,
        message: String,
    },
    #[error("operation fingerprint conflict")]
    Conflict,
    #[error("op_id is already used by a different operation")]
    ScopeConflict,
    #[error("send status not found")]
    NotFound,
    #[error("authority capacity exceeded")]
    Capacity,
    #[error("channel authorization failed")]
    Unauthorized,
    #[error("another owner holds this authority")]
    OwnerContention,
    #[error("owner lock: {0}")]
    Lock(#[from] std::io::Error),
    #[error("payload serialization: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, KernelError>;
#[derive(Default)]
pub struct Counters {
    pub profile: crate::profiling::Profile,
    pub timings: crate::metrics::Timings,
    pub peak_claim_reservations: [AtomicU64; 2],
    pub network_samples: AtomicU64,
    pub network_total_us: AtomicU64,
    pub network_max_us: AtomicU64,
    pub receipt_samples: AtomicU64,
    pub receipt_total_us: AtomicU64,
    pub receipt_max_us: AtomicU64,
    pub peak_network_inflight: AtomicU64,
    pub peak_receipts_owned: AtomicU64,
    pub admission_commit_samples: AtomicU64,
    pub admission_commit_total_us: AtomicU64,
    pub admission_commit_max_us: AtomicU64,
    pub receipt_commit_samples: AtomicU64,
    pub receipt_commit_total_us: AtomicU64,
    pub receipt_commit_max_us: AtomicU64,
    pub gate_wait_samples: AtomicU64,
    pub gate_wait_total_us: AtomicU64,
    pub gate_wait_max_us: AtomicU64,
    pub sql_operations: AtomicU64,
    pub claim_queries: AtomicU64,
    pub admission_commits: AtomicU64,
    pub receipt_commits: AtomicU64,
    pub ack_commits: AtomicU64,
    pub owned_attempts: AtomicU64,
    pub peak_owned_attempts: AtomicU64,
    pub network_attempts: AtomicU64,
    pub num_alive: AtomicU64,
    pub db_errors: AtomicU64,
    pub provider_targets: [AtomicU64; 2],
    pub claim_reservations: [AtomicU64; 2],
    pub network_inflight: AtomicU64,
    pub receipts_owned: AtomicU64,
    pub provider_owned: [AtomicU64; 2],
    pub provider_claim_queries: [AtomicU64; 2],
    pub http_connections: AtomicU64,
    pub peak_http_connections: AtomicU64,
}
impl Counters {
    pub fn snapshot(&self) -> Value {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({"profile":self.profile.snapshot(),"network_samples":get(&self.network_samples),"network_total_us":get(&self.network_total_us),"network_max_us":get(&self.network_max_us),"receipt_samples":get(&self.receipt_samples),"receipt_total_us":get(&self.receipt_total_us),"receipt_max_us":get(&self.receipt_max_us),"peak_network_inflight":get(&self.peak_network_inflight),"peak_receipts_owned":get(&self.peak_receipts_owned),"admission_commit_samples":get(&self.admission_commit_samples),"admission_commit_total_us":get(&self.admission_commit_total_us),"admission_commit_max_us":get(&self.admission_commit_max_us),"receipt_commit_samples":get(&self.receipt_commit_samples),"receipt_commit_total_us":get(&self.receipt_commit_total_us),"receipt_commit_max_us":get(&self.receipt_commit_max_us),"gate_wait_samples":get(&self.gate_wait_samples),"gate_wait_total_us":get(&self.gate_wait_total_us),"gate_wait_max_us":get(&self.gate_wait_max_us),"peak_claim_reservations":[get(&self.peak_claim_reservations[0]),get(&self.peak_claim_reservations[1])],"sql_operations":get(&self.sql_operations),"claim_queries":get(&self.claim_queries),"admission_commits":get(&self.admission_commits),"receipt_commits":get(&self.receipt_commits),"ack_commits":get(&self.ack_commits),"owned_attempts":get(&self.owned_attempts),"peak_owned_attempts":get(&self.peak_owned_attempts),"network_attempts":get(&self.network_attempts),"num_alive":get(&self.num_alive),"db_errors":get(&self.db_errors),"provider_targets":[get(&self.provider_targets[0]),get(&self.provider_targets[1])],"claim_reservations":[get(&self.claim_reservations[0]),get(&self.claim_reservations[1])],"network_inflight":get(&self.network_inflight),"receipts_owned":get(&self.receipts_owned),"provider_owned":[get(&self.provider_owned[0]),get(&self.provider_owned[1])],"provider_claim_queries":[get(&self.provider_claim_queries[0]),get(&self.provider_claim_queries[1])],"http_connections":get(&self.http_connections),"peak_http_connections":get(&self.peak_http_connections)})
    }
    pub(super) fn sql(&self, n: u64) {
        self.sql_operations.fetch_add(n, Ordering::Relaxed);
    }
}
// Keep the lock until process exit on abnormal Drop: SQLx work can outlive a
// cancelled caller. Only explicit pool close followed by release unlocks.
pub(super) struct OwnerLock(Option<File>);
impl OwnerLock {
    fn acquire(path: PathBuf) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        file.try_lock().map_err(|_| KernelError::OwnerContention)?;
        Ok(Self(Some(file)))
    }
    pub(super) fn release(mut self) {
        drop(self.0.take());
    }
}
impl Drop for OwnerLock {
    fn drop(&mut self) {
        if let Some(file) = self.0.take() {
            std::mem::forget(file);
        }
    }
}
// Even if an HTTP caller disappears during accept COMMIT, wake after dropping
// its future. The one-connection pool orders any in-flight SQL before claiming.
struct AdmissionWake(DeliveryStore);
impl Drop for AdmissionWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
#[derive(Clone)]
pub struct DeliveryStore {
    pub(super) pool: SqlitePool,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 2],
    #[cfg(test)]
    pub(super) hooks: Arc<TestHooks>,
}
// Test-only barriers expose the real committed DB state before adoption/wake.
// None of these fields or waits exists in the executable's dependency graph.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TestHooks {
    pub claim_after_commit: std::sync::Mutex<Option<Arc<CommitBarrier>>>,
    pub accept_after_commit: std::sync::Mutex<Option<Arc<CommitBarrier>>>,
    pub receipt_with_gate: std::sync::Mutex<Option<Arc<CommitBarrier>>>,
    pub claim_before_gate: std::sync::Mutex<Option<Arc<Notify>>>,
}
#[cfg(test)]
#[derive(Default)]
pub(super) struct CommitBarrier {
    pub reached: Notify,
    pub resume: Notify,
}
#[cfg(test)]
impl CommitBarrier {
    async fn pause(&self) {
        self.reached.notify_one();
        self.resume.notified().await;
    }
}
#[derive(Debug, Serialize, Clone)]
pub struct Accepted {
    pub delivery_id: String,
    pub message_id: String,
    pub op_id: String,
    pub acceptance: &'static str,
    pub dispatch_status: &'static str,
}
#[derive(Debug, Clone)]
pub(super) struct Ticket {
    pub delivery_id: String,
    pub device_key: String,
    pub platform: String,
    pub provider: String,
    pub token: String,
    pub route_generation: i64,
    pub attempt_id: i64,
    pub attempts: i64,
    pub payload: Value,
    pub accepted_at: i64,
    pub expires_at: i64,
}
pub(super) struct ClaimBatch {
    pub tickets: Vec<Ticket>,
    pub next_due: Option<i64>,
    pub has_more: bool,
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_id=? AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
pub(super) const RECOVER_RUNNING_SQL: &str =
    "UPDATE targets SET state='retry_wait',next_attempt_at=? WHERE provider=? AND state='running'";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM retired_provider_tokens r CROSS JOIN targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";
const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS messages(delivery_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,op_id TEXT NOT NULL UNIQUE,channel_id TEXT NOT NULL,fingerprint TEXT NOT NULL,payload_blob BLOB NOT NULL,payload_bytes INTEGER NOT NULL,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,dedupe_until INTEGER NOT NULL,status TEXT NOT NULL,updated_at INTEGER NOT NULL,pending_targets INTEGER NOT NULL DEFAULT 0,provider_accepted_count INTEGER NOT NULL DEFAULT 0,provider_failed_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS targets(delivery_id TEXT NOT NULL REFERENCES messages(delivery_id) ON DELETE CASCADE,device_key TEXT NOT NULL,pull_owner TEXT NOT NULL DEFAULT '',owner_generation INTEGER NOT NULL DEFAULT 0,control_epoch INTEGER NOT NULL DEFAULT 0,platform TEXT NOT NULL,provider TEXT NOT NULL,provider_token TEXT NOT NULL,route_generation INTEGER NOT NULL DEFAULT 0,accepted_at INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,next_attempt_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,attempt_id INTEGER NOT NULL DEFAULT 0,provider_status INTEGER,provider_error TEXT,receipt_at INTEGER,acked_at INTEGER,PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS targets_due ON targets(provider,state,next_attempt_at,delivery_id);
CREATE INDEX IF NOT EXISTS targets_device ON targets(pull_owner,accepted_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_retention ON messages(dedupe_until);
CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at,delivery_id) WHERE payload_bytes>0;
CREATE TABLE IF NOT EXISTS ledger_usage(singleton INTEGER PRIMARY KEY CHECK(singleton=1),messages INTEGER NOT NULL,targets INTEGER NOT NULL,bytes INTEGER NOT NULL,control_epoch INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO ledger_usage(singleton,messages,targets,bytes) VALUES(1,0,0,0);
CREATE TRIGGER IF NOT EXISTS messages_usage_insert AFTER INSERT ON messages BEGIN UPDATE ledger_usage SET messages=messages+(NEW.pending_targets>0),bytes=bytes+NEW.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS messages_usage_update AFTER UPDATE OF payload_bytes,pending_targets ON messages BEGIN UPDATE ledger_usage SET messages=messages+(NEW.pending_targets>0)-(OLD.pending_targets>0),bytes=bytes+NEW.payload_bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS messages_usage_delete AFTER DELETE ON messages BEGIN UPDATE ledger_usage SET messages=messages-(OLD.pending_targets>0),bytes=bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_insert AFTER INSERT ON targets WHEN NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait') BEGIN UPDATE ledger_usage SET targets=targets+1 WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets+1 WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_update AFTER UPDATE OF acked_at,state ON targets BEGIN UPDATE ledger_usage SET targets=targets+(NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait'))-(OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait')) WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets+(NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait'))-(OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait')) WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_delete AFTER DELETE ON targets WHEN OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait') BEGIN UPDATE ledger_usage SET targets=targets-1 WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets-1 WHERE delivery_id=OLD.delivery_id; END;
CREATE TABLE IF NOT EXISTS devices(device_key TEXT PRIMARY KEY,platform TEXT NOT NULL,provider TEXT,provider_token TEXT,route_generation INTEGER NOT NULL DEFAULT 0,route_revision INTEGER NOT NULL DEFAULT 1,retired_at INTEGER,coalesced_to TEXT);
CREATE INDEX IF NOT EXISTS devices_retired ON devices(retired_at,device_key) WHERE retired_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS registration_aliases(old_key TEXT PRIMARY KEY,new_key TEXT NOT NULL,platform TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS registration_alias_expiry ON registration_aliases(expires_at);
CREATE TABLE IF NOT EXISTS channels(channel_id TEXT PRIMARY KEY,channel_name TEXT NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS channel_subscriptions(channel_id TEXT NOT NULL REFERENCES channels(channel_id),device_key TEXT NOT NULL REFERENCES devices(device_key),PRIMARY KEY(channel_id,device_key));
CREATE INDEX IF NOT EXISTS subscriptions_device ON channel_subscriptions(device_key,channel_id);
CREATE TABLE IF NOT EXISTS retired_provider_tokens(platform TEXT NOT NULL,provider_token TEXT NOT NULL,control_epoch INTEGER NOT NULL,PRIMARY KEY(platform,provider_token));
CREATE INDEX IF NOT EXISTS targets_owner_delivery ON targets(pull_owner,delivery_id,device_key) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_token_retirement ON targets(platform,provider_token,control_epoch);
CREATE TRIGGER IF NOT EXISTS targets_owner_insert AFTER INSERT ON targets WHEN NEW.pull_owner='' BEGIN UPDATE targets SET pull_owner=NEW.device_key,owner_generation=NEW.route_generation,control_epoch=(SELECT control_epoch FROM ledger_usage WHERE singleton=1) WHERE delivery_id=NEW.delivery_id AND device_key=NEW.device_key; END;
CREATE TABLE IF NOT EXISTS provider_cooldowns(provider TEXT PRIMARY KEY,next_attempt_at INTEGER NOT NULL);
";
impl DeliveryStore {
    pub(super) async fn open(db_url: &str, mut config: Config) -> Result<(Self, OwnerLock)> {
        // This candidate follows the explicitly selected full 30-day identity
        // contract even when its payload TTL uses the low-resource profile.
        if config.dedupe_retention_ms < 30 * 86_400_000 {
            return Err(KernelError::Invalid(
                "at least 30 days of identity retention required".into(),
            ));
        }
        if config.provider_budget == 0
            || config.claim_quantum == 0
            || config.claim_quantum > config.provider_budget
            || config.max_handlers == 0
            || config.max_messages <= 0
            || config.max_targets <= 0
            || config.max_payload_bytes <= 0
            || config.default_ttl_secs <= 0
            || config.default_ttl_secs > 30 * 86_400
        {
            return Err(KernelError::Invalid("positive budgets required".into()));
        }
        {
            let url = reqwest::Url::parse(config.public_base_url.trim())
                .map_err(|_| KernelError::Invalid("public base URL".into()))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || (url.scheme() == "http"
                    && !url.host_str().is_some_and(|host| {
                        host == "localhost"
                            || host
                                .trim_matches(['[', ']'])
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    }))
            {
                return Err(KernelError::Invalid("public base URL".into()));
            }
            config.public_base_url = url.as_str().trim_end_matches('/').to_owned();
        }
        let options = SqliteConnectOptions::from_str(db_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(3));
        let filename = options.get_filename();
        if filename.to_string_lossy().contains(":memory:") {
            return Err(KernelError::Invalid("local on-disk SQLite required".into()));
        }
        let filename = if filename.is_absolute() {
            filename.to_owned()
        } else {
            std::env::current_dir()?.join(filename)
        };
        let parent = filename
            .parent()
            .ok_or_else(|| KernelError::Invalid("database path".into()))?;
        std::fs::create_dir_all(parent)?;
        let filename = if filename.exists() {
            std::fs::canonicalize(&filename)?
        } else {
            std::fs::canonicalize(parent)?.join(filename.file_name().unwrap())
        };
        // A DB hardlink would give the same inode different WAL/lock names.
        #[cfg(unix)]
        if filename.exists() {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&filename)?.nlink() > 1 {
                return Err(KernelError::Invalid(
                    "hardlinked database is unsupported".into(),
                ));
            }
        }
        let lock_path = filename.with_file_name(format!(
            "{}.owner",
            filename.file_name().unwrap().to_string_lossy()
        ));
        let owner = OwnerLock::acquire(lock_path)?;
        let pool = match SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect_with(options.filename(&filename))
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                drop(owner);
                return Err(error.into());
            }
        };
        let store = Self {
            pool,
            gate: Arc::new(Mutex::new(())),
            config,
            counters: Arc::new(Counters::default()),
            wake: [Arc::new(Notify::new()), Arc::new(Notify::new())],
            #[cfg(test)]
            hooks: Arc::new(TestHooks::default()),
        };
        if let Err(error) = store.initialize().await {
            store.pool.close().await;
            owner.release();
            return Err(error);
        }
        Ok((store, owner))
    }
    async fn initialize(&self) -> Result<()> {
        self.counters.sql(3);
        let columns = sqlx::query("PRAGMA table_info(channels)")
            .fetch_all(&self.pool)
            .await?;
        if columns
            .iter()
            .any(|r| r.get::<String, _>("name") == "password")
        {
            return Err(KernelError::Invalid(
                "C1 fixture database schema is not C2; use a separate synthetic database".into(),
            ));
        }
        let target_columns = sqlx::query("PRAGMA table_info(targets)")
            .fetch_all(&self.pool)
            .await?;
        if !target_columns.is_empty()
            && !target_columns
                .iter()
                .any(|row| row.get::<String, _>("name") == "pull_owner")
        {
            return Err(KernelError::Invalid("earlier prototype database schema is incompatible; use a separate synthetic database".into()));
        }
        let device_columns = sqlx::query("PRAGMA table_info(devices)")
            .fetch_all(&self.pool)
            .await?;
        if !device_columns.is_empty()
            && !device_columns
                .iter()
                .any(|row| row.get::<String, _>("name") == "route_revision")
        {
            return Err(KernelError::Invalid(
                "earlier prototype route schema is incompatible; use a separate synthetic database"
                    .into(),
            ));
        }
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        // Recovery is only permitted after acquiring the exclusive OS lock.
        // ACKed owned attempts lost with the former process have no callback.
        // Client confirmation is sufficient to close them without a network retry.
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE status='provider_queued' AND pending_targets=0 AND delivery_id IN (SELECT delivery_id FROM targets WHERE provider IN ('FCM','APNS') AND state='running' AND acked_at IS NOT NULL)").bind(now()).execute(&mut *tx).await?;
        for provider in ["FCM", "APNS"] {
            sqlx::query(
                "DELETE FROM targets WHERE provider=? AND state='running' AND acked_at IS NOT NULL",
            )
            .bind(provider)
            .execute(&mut *tx)
            .await?;
            sqlx::query(RECOVER_RUNNING_SQL)
                .bind(now())
                .bind(provider)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        self.maintenance().await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
    }
    pub async fn register(&self, platform: &str) -> Result<String> {
        Ok(self.register_device(platform, None).await?["device_key"]
            .as_str()
            .expect("registration key")
            .into())
    }
    pub async fn register_device(&self, platform: &str, requested: Option<&str>) -> Result<Value> {
        let platform = supported_platform(platform)?;
        let requested = requested.map(str::trim).filter(|key| !key.is_empty());
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM registration_aliases WHERE old_key IN (SELECT old_key FROM registration_aliases WHERE expires_at<? ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut *tx)).await?;
        let mut old_key = None;
        if let Some(key) = requested {
            if let Some(row)=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=? AND retired_at IS NULL").bind(key).fetch_optional(&mut *tx)).await?{
                if row.get::<String,_>("platform")==platform.name(){let result=registration_response(&row,false,None)?;self.counters.profile.phase(Path::Control, Phase::Commit, tx.commit()).await?; drop(profile_connection);return Ok(result)}
                old_key=Some(key);
            } else if let Some(row)=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,d.route_revision FROM registration_aliases a JOIN devices d ON d.device_key=a.new_key WHERE a.old_key=? AND a.platform=? AND a.expires_at>=? AND d.platform=? AND d.retired_at IS NULL").bind(key).bind(platform.name()).bind(at).bind(platform.name()).fetch_optional(&mut *tx)).await? {
                let result=registration_response(&row,true,Some("platform_mismatch"))?;self.counters.profile.phase(Path::Control, Phase::Commit, tx.commit()).await?; drop(profile_connection);return Ok(result)
            }
        }
        let key = generate_hex_id_128();
        self.counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query("INSERT INTO devices(device_key,platform) VALUES(?,?)")
                    .bind(&key)
                    .bind(platform.name())
                    .execute(&mut *tx),
            )
            .await?;
        let reason = if let Some(old) = old_key {
            // Retire instead of migrating subscriptions or accepted targets.
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query("UPDATE devices SET retired_at=? WHERE device_key=?")
                        .bind(at)
                        .bind(old)
                        .execute(&mut *tx),
                )
                .await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id IN (SELECT channel_id FROM channel_subscriptions WHERE device_key=? ORDER BY channel_id LIMIT 256)").bind(old).bind(old).execute(&mut *tx)).await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT INTO registration_aliases(old_key,new_key,platform,expires_at) VALUES(?,?,?,?) ON CONFLICT(old_key) DO UPDATE SET new_key=excluded.new_key,platform=excluded.platform,expires_at=excluded.expires_at").bind(old).bind(&key).bind(platform.name()).bind(at.saturating_add(600_000)).execute(&mut *tx)).await?;
            self.retire_targets_tx(&mut tx, old, at, 256).await?;
            "platform_mismatch"
        } else if requested.is_some() {
            "device_key_not_found"
        } else {
            "device_key_missing"
        };
        let row=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=? AND retired_at IS NULL").bind(&key).fetch_one(&mut *tx)).await?;
        let result = registration_response(&row, true, Some(reason))?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        Ok(result)
    }
    async fn retire_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        key: &str,
        at: i64,
        limit: usize,
    ) -> Result<usize> {
        let ids=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM targets WHERE pull_owner=? AND acked_at IS NULL ORDER BY accepted_at,delivery_id LIMIT ?").bind(key).bind(limit as i64).fetch_all(&mut **tx)).await?;
        for row in &ids {
            let id: String = row.get("delivery_id");
            let original: String = row.get("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE device_key=? AND delivery_id=? AND acked_at IS NULL").bind(at).bind(&original).bind(&id).execute(&mut **tx)).await?;
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued' AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(at).bind(&id).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &original, &id, Path::Maintenance)
                .await?;
        }
        Ok(ids.len())
    }
    pub async fn route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: &str,
    ) -> Result<()> {
        self.update_route(device, platform, provider, Some(raw))
            .await
            .map(|_| ())
    }
    pub async fn update_route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: Option<&str>,
    ) -> Result<Value> {
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Control, Phase::PoolAcquire, self.pool.acquire()).await?; self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=? AND retired_at IS NULL").bind(device).fetch_optional(&mut *profile_read_connection)).await }?.ok_or_else(||control_error(400,"device_key_not_found","device_key not found"))?;
        let prior_platform: String = row.get("platform");
        let platform = supported_platform(
            platform
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(&prior_platform),
        )?;
        if platform.name() != prior_platform {
            return Err(control_error(
                400,
                "platform_mismatch",
                "platform does not match device identity",
            ));
        }
        let provider = provider.trim().to_ascii_uppercase();
        let token = if provider == "PRIVATE" {
            if raw.is_some_and(|v| !v.trim().is_empty()) {
                return Err(control_error(
                    400,
                    "provider_token_forbidden_for_private_channel",
                    "provider_token is not allowed for private channel",
                ));
            }
            None
        } else {
            if provider != platform.provider_name() {
                return Err(control_error(
                    400,
                    "invalid_channel_type",
                    "platform/provider mismatch",
                ));
            }
            let raw = raw.filter(|v| !v.trim().is_empty()).ok_or_else(|| {
                control_error(
                    400,
                    "provider_token_required",
                    "provider_token required for provider channel",
                )
            })?;
            Some(
                normalize_provider_token(raw, platform)
                    .map_err(|e| control_error(400, "invalid_provider_token", &e.to_string()))?,
            )
        };
        let stored_provider = if provider == "PRIVATE" {
            None
        } else {
            Some(provider.as_str())
        };
        let changed = row.get::<Option<String>, _>("provider").as_deref() != stored_provider
            || row.get::<Option<String>, _>("provider_token") != token;
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        if row.get::<i64, _>("route_revision") == i64::MAX
            || (changed && row.get::<i64, _>("route_generation") == i64::MAX)
        {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET provider=?,provider_token=?,route_generation=route_generation+?,route_revision=route_revision+1 WHERE device_key=?").bind(stored_provider).bind(&token).bind(i64::from(changed)).bind(device).execute(&mut *tx)).await?;
        if let Some(token) = token.as_deref() {
            self.coalesce_owners_tx(&mut tx, device, platform.name(), token)
                .await?;
        }
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        self.route_response(device).await
    }
    async fn coalesce_owners_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        winner: &str,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        // SQL owns the set; no allocation proportional to historical owners or
        // deliveries. Frozen attempt rows survive under their original key.
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT OR IGNORE INTO channel_subscriptions(channel_id,device_key) SELECT s.channel_id,? FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL").bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        // Coalescing transfers retained Pull ownership only. Already-materialized
        // provider jobs retain their original wire ACK capability and must never
        // start/retry under the winner. An already-owned network future may
        // still return its receipt to the frozen original target key.
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE targets SET pull_owner=?,owner_generation=-1 WHERE pull_owner IN (SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL)").bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key IN (SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL)").bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET retired_at=?,coalesced_to=? WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL").bind(now()).bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        Ok(())
    }
    async fn route_response(&self, device: &str) -> Result<Value> {
        let row = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=? AND retired_at IS NULL").bind(device).fetch_one(&mut *profile_read_connection)).await
        }?;
        let revision = row.get::<i64, _>("route_revision");
        let mut result = json!({"device_key":device,"channel_type":row.get::<Option<String>,_>("provider").unwrap_or_else(||"private".into()).to_ascii_lowercase(),"issued_new_key":false,"route_revision":revision});
        if let Some(token) = row.get::<Option<String>, _>("provider_token") {
            result["provider_token"] = token.into();
        }
        Ok(result)
    }
    pub async fn delete_route(&self, device: &str, channel_type: &str) -> Result<Value> {
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let route = self.active_route(device).await?;
        if route["channel_type"] != channel_type.trim().to_ascii_lowercase() {
            return Err(control_error(
                400,
                "channel_type_mismatch",
                "channel_type does not match current device route",
            ));
        }
        let changed={
            let mut profile_read_connection = self.counters.profile.phase(Path::Control, Phase::PoolAcquire, self.pool.acquire()).await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET route_generation=route_generation+(provider_token IS NOT NULL),provider_token=NULL,route_revision=route_revision+1 WHERE device_key=? AND route_revision<? AND (provider_token IS NULL OR route_generation<?)").bind(device).bind(i64::MAX).bind(i64::MAX).execute(&mut *profile_read_connection)).await?
        }.rows_affected();
        if changed == 0 {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        // Provider delete retains accepted Pull and subscriptions; generation
        // invalidation prevents stale tickets from starting new network work.
        self.notify();
        self.route_response(device).await
    }
    pub async fn retire_provider_token(&self, platform: &str, raw: &str) -> Result<()> {
        let platform = supported_platform(platform)?;
        let token = normalize_provider_token(raw, platform)
            .map_err(|error| control_error(400, "invalid_provider_token", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let exhausted:bool=self.counters.profile.sql(Path::Control,Statement::Control,sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE platform=? AND provider_token=? AND retired_at IS NULL AND (route_generation=? OR route_revision=?))").bind(platform.name()).bind(&token).bind(i64::MAX).bind(i64::MAX).fetch_one(&mut *tx)).await?;
        if exhausted {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        let changed=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1 AND control_epoch<?").bind(i64::MAX).execute(&mut *tx)).await?.rows_affected();
        if changed == 0 {
            return Err(KernelError::Invalid("control epoch exhausted".into()));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT INTO retired_provider_tokens(platform,provider_token,control_epoch) SELECT ?,?,control_epoch FROM ledger_usage WHERE singleton=1 ON CONFLICT(platform,provider_token) DO UPDATE SET control_epoch=excluded.control_epoch").bind(platform.name()).bind(&token).execute(&mut *tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET provider=NULL,provider_token=NULL,route_generation=route_generation+1,route_revision=route_revision+1 WHERE platform=? AND provider_token=? AND retired_at IS NULL").bind(platform.name()).bind(&token).execute(&mut *tx)).await?;
        self.retire_token_targets_tx(&mut tx).await?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        Ok(())
    }
    async fn retire_token_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<()> {
        let rows = self
            .counters
            .profile
            .sql(
                Path::Maintenance,
                Statement::MaintenanceTargets,
                sqlx::query(RETIRE_TOKEN_TARGETS_SQL).fetch_all(&mut **tx),
            )
            .await?;
        for row in rows {
            let id: String = row.get("delivery_id");
            let key: String = row.get("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=? AND device_key=? AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("DELETE FROM retired_provider_tokens WHERE rowid IN (SELECT r.rowid FROM retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM targets t WHERE t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256)").execute(&mut **tx)).await?;
        Ok(())
    }
    pub async fn subscribe(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.subscribe_under_gate(device, channel_id, channel_name, auth)
            .await
    }
    async fn subscribe_under_gate(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        let channel_id = channel_id.map(str::trim).filter(|v| !v.is_empty());
        let channel_name = channel_name.map(str::trim).filter(|v| !v.is_empty());
        if channel_id.is_some() == channel_name.is_some() {
            return Err(control_error(
                400,
                "channel_binding_invalid",
                "must provide either channel_id or channel_name",
            ));
        }
        let auth = crate::sender::password(auth)
            .map_err(|error| control_error(400, "invalid_password", &error.to_string()))?;
        if device.is_empty() {
            return Err(KernelError::Invalid("device/channel authorization".into()));
        }
        self.counters.sql(5);
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let exists: Option<String> = self
            .counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query_scalar(
                    "SELECT provider_token FROM devices WHERE device_key=? AND retired_at IS NULL",
                )
                .bind(device)
                .fetch_optional(&mut *tx),
            )
            .await?
            .ok_or_else(|| control_error(400, "device_key_not_found", "device_key not found"))?;
        if exists.is_none() {
            return Err(control_error(
                400,
                "provider_token_required",
                "provider_token required for provider channel",
            ));
        }
        let channel_id = channel_id
            .map(crate::sender::channel_id)
            .transpose()
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let (id, name, created) = if let Some(id) = channel_id.as_deref() {
            let row = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "SELECT channel_name,password_hash FROM channels WHERE channel_id=?",
                    )
                    .bind(id)
                    .fetch_optional(&mut *tx),
                )
                .await?
                .ok_or_else(|| {
                    control_error(404, "channel_not_found", "channel not found on gateway")
                })?;
            if !self
                .counters
                .profile
                .phase(
                    Path::Control,
                    Phase::Auth,
                    verify_password_async(row.get::<String, _>("password_hash"), auth.to_owned()),
                )
                .await?
            {
                return Err(control_error(
                    403,
                    "password_mismatch",
                    "channel exists but password mismatch",
                ));
            }
            (id.to_owned(), row.get::<String, _>("channel_name"), false)
        } else {
            let name = channel_name
                .map(str::trim)
                .filter(|v| {
                    !v.is_empty() && v.chars().count() <= 128 && !v.chars().any(char::is_control)
                })
                .ok_or_else(|| {
                    control_error(400, "invalid_channel_name", "invalid channel name")
                })?;
            let id = crate::sender::generate_channel_id();
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "INSERT INTO channels(channel_id,channel_name,password_hash) VALUES(?,?,?)",
                    )
                    .bind(&id)
                    .bind(name)
                    .bind(hash_password(auth))
                    .execute(&mut *tx),
                )
                .await?;
            (id, name.to_owned(), true)
        };
        let count: i64 = self
            .counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=?")
                    .bind(&id)
                    .fetch_one(&mut *tx),
            )
            .await?;
        let subscribed: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
        )
        .bind(&id)
        .bind(device)
        .fetch_one(&mut *tx)
        ).await?;
        if count >= 32 && subscribed == 0 {
            return Err(control_error(
                400,
                "channel_subscriber_limit_exceeded",
                "channel subscriber limit exceeded",
            ));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query(
            "INSERT OR IGNORE INTO channel_subscriptions(channel_id,device_key) VALUES(?,?)",
        )
        .bind(&id)
        .bind(device)
        .execute(&mut *tx)
        ).await?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        Ok(json!({"channel_id":id,"channel_name":name,"created":created,"subscribed":true}))
    }
    async fn active_route(&self, device: &str) -> Result<Value> {
        let row = { let mut profile_read_connection = self.counters.profile.phase(Path::Control, Phase::PoolAcquire, self.pool.acquire()).await?; self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=? AND retired_at IS NULL").bind(device).fetch_optional(&mut *profile_read_connection)).await }?
            .ok_or_else(|| control_error(400, "device_key_not_found", "device_key not found"))?;
        Ok(registration_response(&row, false, None)?["route"].clone())
    }
    pub async fn unsubscribe(&self, device: &str, channel: &str) -> Result<Value> {
        let device = device.trim();
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.active_route(device).await?;
        let removed = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id=?",
                    )
                    .bind(device)
                    .bind(&channel)
                    .execute(&mut *profile_read_connection),
                )
                .await
        }?
        .rows_affected()
            > 0;
        // Subscription changes affect future fanout only. Accepted delivery,
        // retained Pull, operation identity and in-flight receipt remain owned.
        Ok(json!({"channel_id":channel,"removed":removed}))
    }
    pub async fn channel_info(&self, channel: &str) -> Result<Value> {
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let name: Option<String> = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query_scalar("SELECT channel_name FROM channels WHERE channel_id=?")
                        .bind(&channel)
                        .fetch_optional(&mut *profile_read_connection),
                )
                .await
        }?;
        let mut result = json!({"channel_id":channel,"exists":name.is_some()});
        if let Some(name) = name {
            result["channel_name"] = name.into();
        }
        Ok(result)
    }
    pub async fn rename_channel(&self, channel: &str, name: &str, password: &str) -> Result<Value> {
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
            return Err(control_error(
                400,
                "invalid_channel_name",
                "invalid channel name",
            ));
        }
        let password = crate::sender::password(password)
            .map_err(|error| control_error(400, "invalid_password", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let hash: String = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=?")
                        .bind(&channel)
                        .fetch_optional(&mut *profile_read_connection),
                )
                .await
        }?
        .ok_or_else(|| control_error(404, "channel_not_found", "channel not found on gateway"))?;
        if !self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Auth,
                verify_password_async(hash, password.into()),
            )
            .await?
        {
            return Err(control_error(
                403,
                "password_mismatch",
                "channel exists but password mismatch",
            ));
        }
        {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query("UPDATE channels SET channel_name=? WHERE channel_id=?")
                        .bind(name)
                        .bind(&channel)
                        .execute(&mut *profile_read_connection),
                )
                .await
        }?;
        Ok(json!({"channel_id":channel,"channel_name":name}))
    }
    pub async fn sync_channels(&self, device: &str, items: Vec<(String, String)>) -> Result<Value> {
        if items.len() > 2000 {
            return Err(control_error(
                400,
                "channels_limit_exceeded",
                "channels exceeds max limit 2000",
            ));
        }
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        let route = self.active_route(device).await?;
        let mut results = Vec::with_capacity(items.len());
        let mut desired = Vec::with_capacity(items.len());
        for (raw, password) in items {
            let channel = match crate::sender::channel_id(&raw) {
                Ok(channel) => channel,
                Err(error) => {
                    results.push(sync_failure(
                        raw.trim(),
                        400,
                        "invalid_channel_id",
                        &error.to_string(),
                    ));
                    continue;
                }
            };
            if let Err(error) = crate::sender::password(&password) {
                results.push(sync_failure(
                    &channel,
                    400,
                    "invalid_password",
                    &error.to_string(),
                ));
                continue;
            }
            match self
                .subscribe_under_gate(device, Some(&channel), None, &password)
                .await
            {
                Ok(value) => {
                    desired.push(channel);
                    results.push(value);
                }
                Err(KernelError::Control {
                    status,
                    code,
                    message,
                }) => {
                    let code = if code == "provider_token_required" {
                        "provider_token_missing"
                    } else {
                        code
                    };
                    results.push(sync_failure(&channel, status, code, &message));
                }
                Err(error) => return Err(error),
            }
        }
        let success = desired.len();
        let total = results.len();
        if success == total {
            let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
                "DELETE FROM channel_subscriptions WHERE device_key=",
            );
            query.push_bind(device);
            if !desired.is_empty() {
                query.push(" AND channel_id NOT IN (");
                let mut separated = query.separated(",");
                for id in desired {
                    separated.push_bind(id);
                }
                separated.push_unseparated(")");
            }
            {
                let mut profile_read_connection = self
                    .counters
                    .profile
                    .phase(Path::Control, Phase::PoolAcquire, self.pool.acquire())
                    .await?;
                self.counters
                    .profile
                    .sql(
                        Path::Control,
                        Statement::Control,
                        query.build().execute(&mut *profile_read_connection),
                    )
                    .await
            }?;
        }
        Ok(
            json!({"device_key":device,"route":route,"total":total,"success":success,"failed":total-success,"channels":results}),
        )
    }
    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        let admission_started = std::time::Instant::now();
        let request = {
            let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
            request.normalize()?
        };
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Accept, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Accept, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let _wake = AdmissionWake(self.clone());
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Accept, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Accept,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let auth: Option<String> = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Auth,
                sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=?")
                    .bind(&request.channel_id)
                    .fetch_optional(&mut *tx),
            )
            .await?;
        let hash = auth.ok_or(KernelError::Unauthorized)?;
        if !self
            .counters
            .profile
            .phase(
                Path::Accept,
                Phase::Auth,
                verify_password_async(hash, request.password.clone()),
            )
            .await?
        {
            return Err(KernelError::Unauthorized);
        }
        let at = now();
        // Reclaim expired delivery bodies independently of their identity history.
        self.maintain_tx(&mut tx, at).await?;
        if let Some(row)=self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("SELECT delivery_id,message_id,channel_id,fingerprint FROM messages WHERE op_id=? AND dedupe_until>?").bind(&request.op_id).bind(at).fetch_optional(&mut *tx)).await? {
            if row.get::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get("delivery_id"),message_id:row.get("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:"provider_queued"})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("DELETE FROM messages WHERE op_id=? AND dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(&request.op_id).bind(at).execute(&mut *tx)).await?;
        let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
        let delivery_id = generate_hex_id_128();
        let message_id = generate_hex_id_128();
        let expires = request
            .ttl
            .map(|ttl| ttl.min(at.saturating_add(crate::sender::MAX_TTL_MS)))
            .unwrap_or(at.saturating_add(self.config.default_ttl_secs * 1000));
        let mut fields = request.fields;
        for (key, value) in [
            ("op_id", request.op_id.clone()),
            ("message_id", message_id.clone()),
            ("delivery_id", delivery_id.clone()),
            ("channel_id", request.channel_id.clone()),
            ("base_url", self.config.public_base_url.clone()),
            ("sent_at", at.to_string()),
            ("ingested_at", at.to_string()),
            ("occurred_at", request.occurred_at.unwrap_or(at).to_string()),
            ("entity_type", "message".into()),
            ("entity_id", message_id.clone()),
            ("payload_version", "1".into()),
            ("schema_version", "1".into()),
        ] {
            fields.insert(key.into(), value);
        }
        if request.ttl.is_some() {
            fields.insert("ttl".into(), expires.to_string());
        }
        let payload = serde_json::to_vec(&fields)?;
        drop(_compute);
        let usage = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Usage,
                sqlx::query("SELECT messages,targets,bytes FROM ledger_usage WHERE singleton=1")
                    .fetch_one(&mut *tx),
            )
            .await?;
        let fanout:i64=self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&request.channel_id).fetch_one(&mut *tx)).await?;
        let live = fanout > 0 && expires > at;
        if live
            && (usage.get::<i64, _>("messages") >= self.config.max_messages
                || usage
                    .get::<i64, _>("bytes")
                    .saturating_add(payload.len() as i64)
                    > self.config.max_payload_bytes
                || usage.get::<i64, _>("targets").saturating_add(fanout) > self.config.max_targets)
        {
            return Err(KernelError::Capacity);
        }
        let status = if live { "provider_queued" } else { "failed" };
        self.counters.profile.sql(Path::Accept, Statement::MessageInsert, sqlx::query("INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).execute(&mut *tx)).await?;
        if live {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at) SELECT ?,d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,?,'pending',? FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&delivery_id).bind(at).bind(at).bind(&request.channel_id).execute(&mut *tx)).await?;
        }
        let commit_at = std::time::Instant::now();
        self.counters
            .profile
            .phase(Path::Accept, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        record_duration(
            &self.counters.admission_commit_samples,
            &self.counters.admission_commit_total_us,
            &self.counters.admission_commit_max_us,
            commit_at.elapsed(),
        );
        #[cfg(test)]
        {
            let barrier = self.hooks.accept_after_commit.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.pause().await;
            }
        }
        self.counters
            .admission_commits
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .timings
            .admission
            .record(admission_started.elapsed());
        self.notify();
        Ok(Accepted {
            delivery_id,
            message_id,
            op_id: request.op_id,
            acceptance: "new",
            dispatch_status: "provider_queued",
        })
    }
    async fn release_acked_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        device: &str,
        id: &str,
        profile_path: Path,
    ) -> Result<()> {
        // A completed client ACK is positive delivery evidence, independent of
        // whether a provider was attempted. Do not count it as provider acceptance.
        self.counters.profile.sql(profile_path, Statement::ReleaseStatus, sqlx::query("UPDATE messages SET status='sent',updated_at=? WHERE delivery_id=? AND status='provider_queued' AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND (acked_at IS NULL OR state='running'))").bind(now()).bind(id).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget, sqlx::query("DELETE FROM targets WHERE delivery_id=? AND (device_key=? OR acked_at IS NOT NULL) AND acked_at IS NOT NULL AND state!='running'").bind(id).bind(device).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload, sqlx::query("UPDATE messages SET payload_blob=X'',payload_bytes=0 WHERE delivery_id=? AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL)").bind(id).execute(&mut **tx)).await?;
        Ok(())
    }
    /// One bounded retention batch; caller schedules subsequent batches.
    pub async fn maintenance(&self) -> Result<usize> {
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Maintenance, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self
            .counters
            .profile
            .timer(Path::Maintenance, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Maintenance, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Maintenance,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let removed = self.maintain_tx(&mut tx, now()).await?;
        self.counters
            .profile
            .phase(Path::Maintenance, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        Ok(removed)
    }
    async fn maintain_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        at: i64,
    ) -> Result<usize> {
        self.retire_token_targets_tx(tx).await?;
        let retired:Vec<String>=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetired, sqlx::query_scalar("SELECT device_key FROM devices WHERE retired_at IS NOT NULL AND coalesced_to IS NULL ORDER BY retired_at LIMIT 256").fetch_all(&mut **tx)).await?;
        let mut remaining = 256;
        let mut subscriptions_remaining = 256;
        for key in retired {
            if subscriptions_remaining > 0 {
                let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceSubscriptions, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id IN (SELECT channel_id FROM channel_subscriptions WHERE device_key=? ORDER BY channel_id LIMIT ?)").bind(&key).bind(&key).bind(subscriptions_remaining as i64).execute(&mut **tx)).await?.rows_affected() as usize;
                subscriptions_remaining -= removed;
            }
            if remaining > 0 {
                remaining -= self.retire_targets_tx(tx, &key, at, remaining).await?;
            }
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceSubscriptions, sqlx::query("DELETE FROM devices WHERE device_key=? AND retired_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.device_key=devices.device_key AND acked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM targets WHERE provider IN ('FCM','APNS') AND state='running' AND targets.device_key=devices.device_key) AND NOT EXISTS(SELECT 1 FROM channel_subscriptions WHERE channel_subscriptions.device_key=devices.device_key)").bind(key).execute(&mut **tx)).await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceDevice, sqlx::query("DELETE FROM devices WHERE device_key IN (SELECT d.device_key FROM devices d WHERE d.coalesced_to IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets t WHERE t.device_key=d.device_key OR t.pull_owner=d.device_key) LIMIT 256)").execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceAliases, sqlx::query("DELETE FROM registration_aliases WHERE old_key IN (SELECT old_key FROM registration_aliases WHERE expires_at<? ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        // Expiry is a terminal failure only for targets not yet accepted by a
        // provider. Running attempts retain their unknown outcome until receipt.
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryCount, sqlx::query("UPDATE messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryAck, sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryStatus, sqlx::query("UPDATE messages SET status=CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=? WHERE status='provider_queued' AND provider_failed_count>0 AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryDelete, sqlx::query("DELETE FROM targets WHERE acked_at IS NOT NULL AND state!='running' AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryPayload, sqlx::query("UPDATE messages SET payload_blob=X'',payload_bytes=0 WHERE payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL) AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetention, sqlx::query("DELETE FROM messages WHERE delivery_id IN (SELECT delivery_id FROM messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') ORDER BY dedupe_until LIMIT 256)").bind(at).execute(&mut **tx)).await?.rows_affected();
        Ok(removed as usize)
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.counters.sql(1);
        let rows = if let Some(id) = delivery {
            {
                let mut profile_read_connection = self
                    .counters
                    .profile
                    .phase(Path::Read, Phase::PoolAcquire, self.pool.acquire())
                    .await?;
                self.counters
                    .profile
                    .sql(
                        Path::Read,
                        Statement::Read,
                        sqlx::query(PULL_EXACT_SQL)
                            .bind(device)
                            .bind(id)
                            .bind(now())
                            .fetch_all(&mut *profile_read_connection),
                    )
                    .await
            }?
        } else {
            {
                let mut profile_read_connection = self
                    .counters
                    .profile
                    .phase(Path::Read, Phase::PoolAcquire, self.pool.acquire())
                    .await?;
                self.counters
                    .profile
                    .sql(
                        Path::Read,
                        Statement::Read,
                        sqlx::query(PULL_BATCH_SQL)
                            .bind(device)
                            .bind(now())
                            .bind(201_i64)
                            .fetch_all(&mut *profile_read_connection),
                    )
                    .await
            }?
        };
        let more = rows.len() > 200;
        let mut items = Vec::new();
        for row in rows.into_iter().take(200) {
            let mut payload: Value =
                serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            if let Some(object) = payload.as_object_mut() {
                object.remove("delivery_id");
            }
            items.push(json!({"delivery_id":row.get::<String,_>("delivery_id"),"payload":payload}));
        }
        Ok(json!({"items":items,"has_more":more}))
    }
    pub async fn pull_legacy(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Ack, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Ack, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Ack, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let at = now();
        self.counters.sql(1);
        let rows = if let Some(id) = delivery {
            self.counters
                .profile
                .sql(
                    Path::Ack,
                    Statement::Control,
                    sqlx::query(PULL_EXACT_SQL)
                        .bind(device)
                        .bind(id)
                        .bind(at)
                        .fetch_all(&mut *tx),
                )
                .await?
        } else {
            self.counters
                .profile
                .sql(
                    Path::Ack,
                    Statement::Control,
                    sqlx::query(PULL_BATCH_SQL)
                        .bind(device)
                        .bind(at)
                        .bind(512_i64)
                        .fetch_all(&mut *tx),
                )
                .await?
        };
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("delivery_id");
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            self.counters.sql(1);
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL")
                .bind(at).bind(device).bind(&id).execute(&mut *tx)).await?;
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
            items.push(json!({"delivery_id":id,"payload":payload}));
        }
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.counters.ack_commits.fetch_add(1, Ordering::Relaxed);
        self.notify();
        Ok(json!({"items":items}))
    }
    pub async fn ack(&self, device: &str, ids: Vec<String>) -> Result<usize> {
        let mut ids = ids
            .into_iter()
            .map(|v| v.trim().to_owned())
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        if ids.is_empty() || ids.len() > 200 || ids.iter().any(|v| v.is_empty() || v.len() > 128) {
            return Err(KernelError::Invalid("ACK ids".into()));
        }
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Ack, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Ack, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(ids.len() as u64 + 2);
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Ack, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL AND EXISTS(SELECT 1 FROM devices WHERE devices.device_key=targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM messages WHERE messages.delivery_id=targets.delivery_id AND expires_at>?) AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=targets.platform AND r.provider_token=targets.provider_token AND targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
        }
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.counters.ack_commits.fetch_add(1, Ordering::Relaxed);
        self.notify();
        Ok(removed)
    }
    #[cfg(test)]
    pub(super) async fn claim(
        &self,
        provider: &str,
        limit: usize,
        retry_first: bool,
    ) -> Result<ClaimBatch> {
        self.claim_reserved(provider, limit, retry_first).await
    }
    pub(super) async fn claim_reserved(
        &self,
        provider: &str,
        limit: usize,
        retry_first: bool,
    ) -> Result<ClaimBatch> {
        #[cfg(test)]
        if provider == "FCM" {
            let probe = self.hooks.claim_before_gate.lock().unwrap().take();
            if let Some(probe) = probe {
                probe.notify_one();
            }
        }
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Claim, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Claim, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.claim_queries.fetch_add(1, Ordering::Relaxed);
        self.counters.provider_claim_queries[usize::from(provider == "APNS")]
            .fetch_add(1, Ordering::Relaxed);
        self.counters.sql(5);
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Claim,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        self.maintain_tx(&mut tx, at).await?;
        let cooldown: Option<i64> = self
            .counters
            .profile
            .sql(
                Path::Claim,
                Statement::ClaimCooldown,
                sqlx::query_scalar(
                    "SELECT next_attempt_at FROM provider_cooldowns WHERE provider=?",
                )
                .bind(provider)
                .fetch_optional(&mut *tx),
            )
            .await?;
        let mut tickets = Vec::new();
        if cooldown.is_none_or(|due| due <= at) {
            let classes = if retry_first {
                ["retry_wait", "pending"]
            } else {
                ["pending", "retry_wait"]
            };
            for n in 0..limit {
                let mut selected = None;
                for class in [classes[n % 2], classes[(n + 1) % 2]] {
                    self.counters.sql(1);
                    let row=self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.*,m.payload_blob,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE d.retired_at IS NULL AND t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx)).await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get("delivery_id");
                let device: String = row.get("device_key");
                self.counters.sql(1);
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=? AND device_key=?").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
                let _compute = self.counters.profile.timer(Path::Claim, Phase::Compute);
                tickets.push(Ticket {
                    delivery_id: delivery,
                    device_key: device,
                    platform: row.get("platform"),
                    provider: row.get("provider"),
                    token: row.get("provider_token"),
                    route_generation: row.get("route_generation"),
                    attempt_id: row.get::<i64, _>("attempt_id") + 1,
                    attempts: row.get::<i64, _>("attempts") + 1,
                    payload: serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?,
                    accepted_at: row.get("accepted_at"),
                    expires_at: row.get("expires_at"),
                });
                drop(_compute);
            }
        }
        let due:Option<i64>=self.counters.profile.sql(Path::Claim, Statement::ClaimNextDue, sqlx::query_scalar("SELECT MIN(next_attempt_at) FROM targets WHERE provider=? AND state IN ('pending','retry_wait') AND acked_at IS NULL").bind(provider).fetch_one(&mut *tx)).await?;
        let retiring:bool=self.counters.profile.sql(Path::Claim, Statement::ClaimRetiring, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices d WHERE d.retired_at IS NOT NULL AND d.coalesced_to IS NULL AND (EXISTS(SELECT 1 FROM targets t WHERE t.pull_owner=d.device_key AND t.acked_at IS NULL) OR EXISTS(SELECT 1 FROM channel_subscriptions s WHERE s.device_key=d.device_key)))").fetch_one(&mut *tx)).await?;
        let next_due = if retiring {
            Some(at)
        } else {
            due.map(|due| due.max(cooldown.unwrap_or(0)))
        };
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        drop(_gate);
        drop(_gate_hold);
        #[cfg(test)]
        if !tickets.is_empty() {
            let barrier = self.hooks.claim_after_commit.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.pause().await;
            }
        }
        let has_more = next_due.is_some_and(|due| due <= at);
        Ok(ClaimBatch {
            tickets,
            next_due,
            has_more,
        })
    }
    pub(super) async fn authorize_ticket(&self, ticket: &Ticket) -> Result<bool> {
        self.counters.sql(1);
        let current: i64 = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters.profile.sql(Path::Claim, Statement::Read, sqlx::query_scalar("SELECT COUNT(*) FROM targets t JOIN devices d ON d.device_key=t.pull_owner JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.state='running' AND t.attempt_id=? AND t.acked_at IS NULL AND m.expires_at>? AND d.retired_at IS NULL AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.owner_generation AND t.route_generation=? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&mut *profile_read_connection)).await
        }?;
        Ok(current != 0)
    }
    pub(super) async fn settle(
        &self,
        ticket: &Ticket,
        state: &str,
        status: u16,
        error: &str,
        next_due: i64,
        cooldown: Option<i64>,
    ) -> Result<()> {
        let gate_at = std::time::Instant::now();
        let _gate = self
            .counters
            .profile
            .phase(Path::Receipt, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Receipt, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(3 + u64::from(cooldown.is_some()));
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Receipt, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Receipt,
                Phase::Begin,
                sqlx::Acquire::begin(&mut *profile_connection),
            )
            .await?;
        #[cfg(test)]
        {
            let barrier = self.hooks.receipt_with_gate.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.pause().await;
            }
        }
        let state = if state == "retry_wait" && ticket.expires_at <= now() {
            "permanent_failed"
        } else {
            state
        };
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE targets SET state=?,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=MAX(next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id=(SELECT channel_id FROM messages WHERE delivery_id=?) AND EXISTS(SELECT 1 FROM devices WHERE device_key=? AND retired_at IS NULL AND platform=? AND provider=? AND provider_token=? AND route_generation=?)")
                    .bind(&ticket.device_key).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(&ticket.platform).bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE messages SET provider_accepted_count=provider_accepted_count+?,provider_failed_count=provider_failed_count+? WHERE delivery_id=?").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptStatus, sqlx::query("UPDATE messages SET status=CASE WHEN pending_targets>0 OR EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=?").bind(now()).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
            self.release_acked_tx(
                &mut tx,
                &ticket.device_key,
                &ticket.delivery_id,
                Path::Receipt,
            )
            .await?;
        }
        let commit_at = std::time::Instant::now();
        self.counters
            .profile
            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        record_duration(
            &self.counters.receipt_commit_samples,
            &self.counters.receipt_commit_total_us,
            &self.counters.receipt_commit_max_us,
            commit_at.elapsed(),
        );
        self.counters
            .timings
            .receipt_commit
            .record(commit_at.elapsed());
        self.counters
            .receipt_commits
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub async fn status(&self, op: &str) -> Result<Value> {
        let op = crate::sender::op_id(op)?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.pool.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM messages WHERE op_id=? AND dedupe_until>?").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
        Ok(
            json!({"op_id":row.get::<String,_>("op_id"),"status":row.get::<String,_>("status"),"model":"message","entity_id":row.get::<String,_>("message_id"),"accepted_at":row.get::<i64,_>("accepted_at"),"updated_at":row.get::<i64,_>("updated_at"),"expires_at":row.get::<i64,_>("dedupe_until")}),
        )
    }
    pub async fn target_status(&self, op: &str) -> Result<Value> {
        let rows = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Read, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&mut *profile_read_connection)).await
        }?;
        Ok(
            json!({"targets":rows.iter().map(|r|json!({"delivery_id":r.get::<String,_>("delivery_id"),"state":r.get::<Option<String>,_>("state"),"provider_status":r.get::<Option<i64>,_>("provider_status"),"acked_at":r.get::<Option<i64>,_>("acked_at")})).collect::<Vec<_>>()}),
        )
    }
}
pub(super) fn supported_platform(raw: &str) -> Result<Platform> {
    let platform = Platform::from_str(raw).map_err(|_| KernelError::Invalid("platform".into()))?;
    if !matches!(
        platform,
        Platform::Android | Platform::Ios | Platform::Macos
    ) {
        return Err(KernelError::Invalid(
            "ordinary Android/iOS/macOS only".into(),
        ));
    }
    Ok(platform)
}

fn record_duration(samples: &AtomicU64, total: &AtomicU64, max: &AtomicU64, duration: Duration) {
    let us = duration.as_micros().min(u64::MAX as u128) as u64;
    samples.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(us, Ordering::Relaxed);
    max.fetch_max(us, Ordering::Relaxed);
}

const BLAKE3_PASSWORD_SCHEME: &str = "pushgo-blake3";
const BLAKE3_PASSWORD_VERSION: &str = "v=1";
const BLAKE3_PASSWORD_SALT_BYTES: usize = 16;
const BLAKE3_PASSWORD_DIGEST_BYTES: usize = blake3::OUT_LEN;
const BLAKE3_PASSWORD_DOMAIN: &[u8] = b"pushgo.gateway.channel.password.v1";

fn password_digest(salt: &[u8], value: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(BLAKE3_PASSWORD_DOMAIN);
    h.update(&(salt.len() as u64).to_le_bytes());
    h.update(salt);
    h.update(value.as_bytes());
    *h.finalize().as_bytes()
}
fn hash_password(value: &str) -> String {
    let salt: [u8; BLAKE3_PASSWORD_SALT_BYTES] = rand::random();
    let digest = password_digest(&salt, value);
    format!(
        "${}${}${}${}",
        BLAKE3_PASSWORD_SCHEME,
        BLAKE3_PASSWORD_VERSION,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(digest)
    )
}
fn verify_password(hash: &str, value: &str) -> bool {
    if hash.starts_with(&format!("${}$", BLAKE3_PASSWORD_SCHEME)) {
        let parts: Vec<_> = hash.split('$').collect();
        if parts.len() != 5 || parts[2] != BLAKE3_PASSWORD_VERSION {
            return false;
        }
        let Ok(salt) = URL_SAFE_NO_PAD.decode(parts[3]) else {
            return false;
        };
        let Ok(expected) = URL_SAFE_NO_PAD.decode(parts[4]) else {
            return false;
        };
        if salt.len() != BLAKE3_PASSWORD_SALT_BYTES
            || expected.len() != BLAKE3_PASSWORD_DIGEST_BYTES
        {
            return false;
        }
        let actual = password_digest(&salt, value);
        let mut diff = 0_u8;
        for (a, b) in actual.iter().zip(expected) {
            diff |= a ^ b;
        }
        diff == 0
    } else {
        PasswordHash::new(hash).ok().is_some_and(|parsed| {
            Argon2::default()
                .verify_password(value.as_bytes(), &parsed)
                .is_ok()
        })
    }
}

async fn verify_password_async(hash: String, value: String) -> Result<bool> {
    if hash.starts_with(&format!("${}$", BLAKE3_PASSWORD_SCHEME)) {
        return Ok(verify_password(&hash, &value));
    }
    static LEGACY_PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(4)));
    let permit = LEGACY_PERMITS
        .clone()
        .try_acquire_owned()
        .map_err(|_| KernelError::Capacity)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(&hash, &value)
    })
    .await
    .map_err(|_| KernelError::Invalid("credential verification failed".into()))
}

fn registration_response(
    row: &sqlx::sqlite::SqliteRow,
    issued: bool,
    reason: Option<&str>,
) -> Result<Value> {
    let revision = row.get::<i64, _>("route_revision");
    let channel = row
        .get::<Option<String>, _>("provider")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "private".into());
    let mut result = json!({"device_key":row.get::<String,_>("device_key"),"issued_new_key":issued,"route_revision":revision,"route":{"channel_type":channel,"route_revision":revision,"provider_token_present":row.get::<Option<String>,_>("provider_token").is_some()}});
    if let Some(reason) = reason {
        result["issue_reason"] = reason.into();
    }
    Ok(result)
}

fn control_error(status: u16, code: &'static str, message: &str) -> KernelError {
    KernelError::Control {
        status,
        code,
        message: message.into(),
    }
}
fn sync_failure(channel: &str, status: u16, code: &str, message: &str) -> Value {
    json!({"channel_id":channel,"subscribed":false,"created":false,"error":message,"error_code":code,"problem":{"code":code,"category":if status==403 {"conflict"} else if status==404 {"not_found"} else {"validation"},"status":status,"detail":message,"retryable":false}})
}
