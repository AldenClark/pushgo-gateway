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
        json!({"network_samples":get(&self.network_samples),"network_total_us":get(&self.network_total_us),"network_max_us":get(&self.network_max_us),"receipt_samples":get(&self.receipt_samples),"receipt_total_us":get(&self.receipt_total_us),"receipt_max_us":get(&self.receipt_max_us),"peak_network_inflight":get(&self.peak_network_inflight),"peak_receipts_owned":get(&self.peak_receipts_owned),"admission_commit_samples":get(&self.admission_commit_samples),"admission_commit_total_us":get(&self.admission_commit_total_us),"admission_commit_max_us":get(&self.admission_commit_max_us),"receipt_commit_samples":get(&self.receipt_commit_samples),"receipt_commit_total_us":get(&self.receipt_commit_total_us),"receipt_commit_max_us":get(&self.receipt_commit_max_us),"gate_wait_samples":get(&self.gate_wait_samples),"gate_wait_total_us":get(&self.gate_wait_total_us),"gate_wait_max_us":get(&self.gate_wait_max_us),"peak_claim_reservations":[get(&self.peak_claim_reservations[0]),get(&self.peak_claim_reservations[1])],"sql_operations":get(&self.sql_operations),"claim_queries":get(&self.claim_queries),"admission_commits":get(&self.admission_commits),"receipt_commits":get(&self.receipt_commits),"ack_commits":get(&self.ack_commits),"owned_attempts":get(&self.owned_attempts),"peak_owned_attempts":get(&self.peak_owned_attempts),"network_attempts":get(&self.network_attempts),"num_alive":get(&self.num_alive),"db_errors":get(&self.db_errors),"provider_targets":[get(&self.provider_targets[0]),get(&self.provider_targets[1])],"claim_reservations":[get(&self.claim_reservations[0]),get(&self.claim_reservations[1])],"network_inflight":get(&self.network_inflight),"receipts_owned":get(&self.receipts_owned),"provider_owned":[get(&self.provider_owned[0]),get(&self.provider_owned[1])],"provider_claim_queries":[get(&self.provider_claim_queries[0]),get(&self.provider_claim_queries[1])],"http_connections":get(&self.http_connections),"peak_http_connections":get(&self.peak_http_connections)})
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
const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS messages(delivery_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,op_id TEXT NOT NULL UNIQUE,channel_id TEXT NOT NULL,fingerprint TEXT NOT NULL,payload_blob BLOB NOT NULL,payload_bytes INTEGER NOT NULL,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,dedupe_until INTEGER NOT NULL,status TEXT NOT NULL,updated_at INTEGER NOT NULL,pending_targets INTEGER NOT NULL DEFAULT 0,provider_accepted_count INTEGER NOT NULL DEFAULT 0,provider_failed_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS targets(delivery_id TEXT NOT NULL REFERENCES messages(delivery_id) ON DELETE CASCADE,device_key TEXT NOT NULL,platform TEXT NOT NULL,provider TEXT NOT NULL,provider_token TEXT NOT NULL,route_generation INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,next_attempt_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,attempt_id INTEGER NOT NULL DEFAULT 0,provider_status INTEGER,provider_error TEXT,receipt_at INTEGER,acked_at INTEGER,PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS targets_due ON targets(provider,state,next_attempt_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_device ON targets(device_key,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_retention ON messages(dedupe_until);
CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at,delivery_id) WHERE payload_bytes>0;
CREATE TABLE IF NOT EXISTS ledger_usage(singleton INTEGER PRIMARY KEY CHECK(singleton=1),messages INTEGER NOT NULL,targets INTEGER NOT NULL,bytes INTEGER NOT NULL);
INSERT OR IGNORE INTO ledger_usage VALUES(1,0,0,0);
CREATE TRIGGER IF NOT EXISTS messages_usage_insert AFTER INSERT ON messages BEGIN UPDATE ledger_usage SET messages=messages+(NEW.pending_targets>0),bytes=bytes+NEW.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS messages_usage_update AFTER UPDATE OF payload_bytes,pending_targets ON messages BEGIN UPDATE ledger_usage SET messages=messages+(NEW.pending_targets>0)-(OLD.pending_targets>0),bytes=bytes+NEW.payload_bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS messages_usage_delete AFTER DELETE ON messages BEGIN UPDATE ledger_usage SET messages=messages-(OLD.pending_targets>0),bytes=bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_insert AFTER INSERT ON targets WHEN NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait') BEGIN UPDATE ledger_usage SET targets=targets+1 WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets+1 WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_update AFTER UPDATE OF acked_at,state ON targets BEGIN UPDATE ledger_usage SET targets=targets+(NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait'))-(OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait')) WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets+(NEW.acked_at IS NULL AND NEW.state IN ('pending','running','retry_wait'))-(OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait')) WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS targets_usage_delete AFTER DELETE ON targets WHEN OLD.acked_at IS NULL AND OLD.state IN ('pending','running','retry_wait') BEGIN UPDATE ledger_usage SET targets=targets-1 WHERE singleton=1; UPDATE messages SET pending_targets=pending_targets-1 WHERE delivery_id=OLD.delivery_id; END;
CREATE TABLE IF NOT EXISTS devices(device_key TEXT PRIMARY KEY,platform TEXT NOT NULL,provider TEXT,provider_token TEXT,route_generation INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS channels(channel_id TEXT PRIMARY KEY,channel_name TEXT NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS channel_subscriptions(channel_id TEXT NOT NULL REFERENCES channels(channel_id),device_key TEXT NOT NULL REFERENCES devices(device_key),PRIMARY KEY(channel_id,device_key));
CREATE TABLE IF NOT EXISTS provider_cooldowns(provider TEXT PRIMARY KEY,next_attempt_at INTEGER NOT NULL);
";
impl DeliveryStore {
    pub(super) async fn open(db_url: &str, mut config: Config) -> Result<(Self, OwnerLock)> {
        if config.provider_budget == 0
            || config.claim_quantum == 0
            || config.claim_quantum > config.provider_budget
            || config.max_handlers == 0
            || config.max_messages <= 0
            || config.max_targets <= 0
            || config.max_payload_bytes <= 0
            || config.default_ttl_secs <= 0
            || config.default_ttl_secs > 30 * 86_400
            || config.dedupe_retention_ms <= 0
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
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        // Recovery is only permitted after acquiring the exclusive OS lock.
        sqlx::query(
            "UPDATE targets SET state='retry_wait',next_attempt_at=? WHERE state='running'",
        )
        .bind(now())
        .execute(&self.pool)
        .await?;
        self.maintenance().await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
    }
    pub async fn register(&self, platform: &str) -> Result<String> {
        let platform = supported_platform(platform)?;
        let key = generate_hex_id_128();
        let gate_at = std::time::Instant::now();
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(1);
        sqlx::query("INSERT INTO devices(device_key,platform) VALUES(?,?)")
            .bind(&key)
            .bind(platform.name())
            .execute(&self.pool)
            .await?;
        Ok(key)
    }
    pub async fn route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: &str,
    ) -> Result<()> {
        let gate_at = std::time::Instant::now();
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(2);
        let existing =
            sqlx::query("SELECT platform,provider,provider_token,route_generation FROM devices WHERE device_key=?")
                .bind(device)
                .fetch_optional(&self.pool)
                .await?;
        let existing = existing.ok_or_else(|| KernelError::Invalid("unknown device".into()))?;
        let prior_platform: String = existing.get("platform");
        let platform = supported_platform(platform.unwrap_or(&prior_platform))?;
        let provider = provider.to_ascii_uppercase();
        if provider != platform.provider_name() {
            return Err(KernelError::Invalid("platform/provider mismatch".into()));
        }
        let canonical = normalize_provider_token(raw, platform)
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        let changed = prior_platform != platform.name()
            || existing.get::<Option<String>, _>("provider").as_deref() != Some(provider.as_str())
            || existing
                .get::<Option<String>, _>("provider_token")
                .as_deref()
                != Some(canonical.as_str());
        if changed {
            if existing.get::<i64, _>("route_generation") == i64::MAX {
                return Err(KernelError::Invalid("route generation exhausted".into()));
            }
            sqlx::query("UPDATE devices SET platform=?,provider=?,provider_token=?,route_generation=route_generation+1 WHERE device_key=?")
                .bind(platform.name()).bind(provider).bind(canonical).bind(device).execute(&self.pool).await?;
        }
        self.notify();
        Ok(())
    }
    pub async fn subscribe(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        let auth = crate::sender::password(auth)?;
        if device.is_empty() {
            return Err(KernelError::Invalid("device/channel authorization".into()));
        }
        let gate_at = std::time::Instant::now();
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(5);
        let mut tx = self.pool.begin().await?;
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE device_key=?")
            .bind(device)
            .fetch_one(&mut *tx)
            .await?;
        if exists == 0 {
            return Err(KernelError::Invalid("unknown device".into()));
        }
        let channel_id = channel_id.map(crate::sender::channel_id).transpose()?;
        let (id, name, created) = if let Some(id) = channel_id.as_deref() {
            let row =
                sqlx::query("SELECT channel_name,password_hash FROM channels WHERE channel_id=?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(KernelError::Unauthorized)?;
            if !verify_password_async(row.get::<String, _>("password_hash"), auth.to_owned())
                .await?
            {
                return Err(KernelError::Unauthorized);
            }
            (id.to_owned(), row.get::<String, _>("channel_name"), false)
        } else {
            let name = channel_name
                .map(str::trim)
                .filter(|v| {
                    !v.is_empty() && v.chars().count() <= 128 && !v.chars().any(char::is_control)
                })
                .ok_or_else(|| KernelError::Invalid("channel_name".into()))?;
            let id = crate::sender::generate_channel_id();
            sqlx::query(
                "INSERT INTO channels(channel_id,channel_name,password_hash) VALUES(?,?,?)",
            )
            .bind(&id)
            .bind(name)
            .bind(hash_password(auth))
            .execute(&mut *tx)
            .await?;
            (id, name.to_owned(), true)
        };
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=?")
                .bind(&id)
                .fetch_one(&mut *tx)
                .await?;
        let subscribed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
        )
        .bind(&id)
        .bind(device)
        .fetch_one(&mut *tx)
        .await?;
        if count >= 32 && subscribed == 0 {
            return Err(KernelError::Capacity);
        }
        sqlx::query(
            "INSERT OR IGNORE INTO channel_subscriptions(channel_id,device_key) VALUES(?,?)",
        )
        .bind(&id)
        .bind(device)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(json!({"channel_id":id,"channel_name":name,"created":created,"subscribed":true}))
    }
    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        let admission_started = std::time::Instant::now();
        let request = request.normalize()?;
        let gate_at = std::time::Instant::now();
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let _wake = AdmissionWake(self.clone());
        let mut tx = self.pool.begin().await?;
        let auth: Option<String> =
            sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=?")
                .bind(&request.channel_id)
                .fetch_optional(&mut *tx)
                .await?;
        let hash = auth.ok_or(KernelError::Unauthorized)?;
        if !verify_password_async(hash, request.password.clone()).await? {
            return Err(KernelError::Unauthorized);
        }
        let at = now();
        // Reclaim expired delivery bodies independently of their identity history.
        self.maintain_tx(&mut tx, at).await?;
        if let Some(row)=sqlx::query("SELECT delivery_id,message_id,channel_id,fingerprint FROM messages WHERE op_id=? AND dedupe_until>?").bind(&request.op_id).bind(at).fetch_optional(&mut *tx).await? {
            if row.get::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get("delivery_id"),message_id:row.get("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:"provider_queued"})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        sqlx::query("DELETE FROM messages WHERE op_id=? AND dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(&request.op_id).bind(at).execute(&mut *tx).await?;
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
        let usage =
            sqlx::query("SELECT messages,targets,bytes FROM ledger_usage WHERE singleton=1")
                .fetch_one(&mut *tx)
                .await?;
        let fanout:i64=sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&request.channel_id).fetch_one(&mut *tx).await?;
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
        sqlx::query("INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).execute(&mut *tx).await?;
        if live {
            sqlx::query("INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,route_generation,state,next_attempt_at) SELECT ?,d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,'pending',? FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&delivery_id).bind(at).bind(&request.channel_id).execute(&mut *tx).await?;
        }
        let commit_at = std::time::Instant::now();
        tx.commit().await?;
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
    ) -> Result<()> {
        // A completed client ACK is positive delivery evidence, independent of
        // whether a provider was attempted. Do not count it as provider acceptance.
        sqlx::query("UPDATE messages SET status='sent',updated_at=? WHERE delivery_id=? AND status='provider_queued' AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND (acked_at IS NULL OR state='running'))").bind(now()).bind(id).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM targets WHERE delivery_id=? AND device_key=? AND acked_at IS NOT NULL AND state!='running'").bind(id).bind(device).execute(&mut **tx).await?;
        sqlx::query("UPDATE messages SET payload_blob=X'',payload_bytes=0 WHERE delivery_id=? AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL)").bind(id).execute(&mut **tx).await?;
        Ok(())
    }
    /// One bounded retention batch; caller schedules subsequent batches.
    pub async fn maintenance(&self) -> Result<usize> {
        let gate_at = std::time::Instant::now();
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let mut tx = self.pool.begin().await?;
        let removed = self.maintain_tx(&mut tx, now()).await?;
        tx.commit().await?;
        Ok(removed)
    }
    async fn maintain_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        at: i64,
    ) -> Result<usize> {
        // Expiry is a terminal failure only for targets not yet accepted by a
        // provider. Running attempts retain their unknown outcome until receipt.
        sqlx::query("UPDATE messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx).await?;
        sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx).await?;
        sqlx::query("UPDATE messages SET status=CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=? WHERE status='provider_queued' AND provider_failed_count>0 AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM targets WHERE acked_at IS NOT NULL AND state!='running' AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx).await?;
        sqlx::query("UPDATE messages SET payload_blob=X'',payload_bytes=0 WHERE payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL) AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx).await?;
        let removed=sqlx::query("DELETE FROM messages WHERE delivery_id IN (SELECT delivery_id FROM messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') ORDER BY dedupe_until LIMIT 256)").bind(at).execute(&mut **tx).await?.rows_affected();
        Ok(removed as usize)
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.counters.sql(1);
        let rows=sqlx::query("SELECT m.delivery_id,m.payload_blob FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE t.device_key=? AND t.acked_at IS NULL AND m.expires_at>? AND (? IS NULL OR m.delivery_id=?) ORDER BY m.accepted_at,m.delivery_id LIMIT 201").bind(device).bind(now()).bind(delivery).bind(delivery).fetch_all(&self.pool).await?;
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
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let mut tx = self.pool.begin().await?;
        let at = now();
        self.counters.sql(1);
        let rows = sqlx::query("SELECT m.delivery_id,m.payload_blob FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE t.device_key=? AND t.acked_at IS NULL AND m.expires_at>? AND (? IS NULL OR m.delivery_id=?) ORDER BY m.accepted_at,m.delivery_id LIMIT 512")
            .bind(device).bind(at).bind(delivery).bind(delivery).fetch_all(&mut *tx).await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("delivery_id");
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            self.counters.sql(1);
            sqlx::query("UPDATE targets SET acked_at=? WHERE device_key=? AND delivery_id=? AND acked_at IS NULL")
                .bind(at).bind(device).bind(&id).execute(&mut *tx).await?;
            self.release_acked_tx(&mut tx, device, &id).await?;
            items.push(json!({"delivery_id":id,"payload":payload}));
        }
        tx.commit().await?;
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
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(ids.len() as u64 + 2);
        let mut tx = self.pool.begin().await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=sqlx::query("UPDATE targets SET acked_at=? WHERE device_key=? AND delivery_id=? AND acked_at IS NULL AND EXISTS(SELECT 1 FROM messages WHERE messages.delivery_id=targets.delivery_id AND expires_at>?)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx).await?.rows_affected() as usize;
            self.release_acked_tx(&mut tx, device, &id).await?;
        }
        tx.commit().await?;
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
        let _gate = self.gate.lock().await;
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
        let mut tx = self.pool.begin().await?;
        self.maintain_tx(&mut tx, at).await?;
        let cooldown: Option<i64> =
            sqlx::query_scalar("SELECT next_attempt_at FROM provider_cooldowns WHERE provider=?")
                .bind(provider)
                .fetch_optional(&mut *tx)
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
                    let row=sqlx::query("SELECT t.*,m.payload_blob,m.accepted_at,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx).await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get("delivery_id");
                let device: String = row.get("device_key");
                self.counters.sql(1);
                sqlx::query("UPDATE targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=? AND device_key=?").bind(&delivery).bind(&device).execute(&mut *tx).await?;
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
            }
        }
        let due:Option<i64>=sqlx::query_scalar("SELECT MIN(next_attempt_at) FROM targets WHERE provider=? AND state IN ('pending','retry_wait') AND acked_at IS NULL").bind(provider).fetch_one(&mut *tx).await?;
        let next_due = due.map(|due| due.max(cooldown.unwrap_or(0)));
        tx.commit().await?;
        drop(_gate);
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
        let current:i64=sqlx::query_scalar("SELECT COUNT(*) FROM targets t JOIN devices d ON d.device_key=t.device_key JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.state='running' AND t.attempt_id=? AND t.acked_at IS NULL AND m.expires_at>? AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.route_generation AND t.route_generation=?").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&self.pool).await?;
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
        let _gate = self.gate.lock().await;
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.sql(3 + u64::from(cooldown.is_some()));
        let mut tx = self.pool.begin().await?;
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
        let changed=sqlx::query("UPDATE targets SET state=?,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx).await?.rows_affected();
        if let Some(due) = cooldown {
            sqlx::query("INSERT INTO provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=MAX(next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id=(SELECT channel_id FROM messages WHERE delivery_id=?) AND EXISTS(SELECT 1 FROM devices WHERE device_key=? AND platform=? AND provider=? AND provider_token=? AND route_generation=?)")
                    .bind(&ticket.device_key).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(&ticket.platform).bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE messages SET provider_accepted_count=provider_accepted_count+?,provider_failed_count=provider_failed_count+? WHERE delivery_id=?").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE messages SET status=CASE WHEN pending_targets>0 OR EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=?").bind(now()).bind(&ticket.delivery_id).execute(&mut *tx).await?;
            self.release_acked_tx(&mut tx, &ticket.device_key, &ticket.delivery_id)
                .await?;
        }
        let commit_at = std::time::Instant::now();
        tx.commit().await?;
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
        let row=sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM messages WHERE op_id=? AND dedupe_until>?").bind(op).bind(now()).fetch_optional(&self.pool).await?.ok_or(KernelError::NotFound)?;
        Ok(
            json!({"op_id":row.get::<String,_>("op_id"),"status":row.get::<String,_>("status"),"model":"message","entity_id":row.get::<String,_>("message_id"),"accepted_at":row.get::<i64,_>("accepted_at"),"updated_at":row.get::<i64,_>("updated_at"),"expires_at":row.get::<i64,_>("dedupe_until")}),
        )
    }
    pub async fn target_status(&self, op: &str) -> Result<Value> {
        let rows=sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&self.pool).await?;
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
