use crate::types::{Platform, generate_hex_id_128, normalize_provider_token};
use serde::{Deserialize, Serialize};
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
    pub demand_scaling: bool,
    pub public_base_url: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_messages: 10_000,
            max_targets: 1_000_000,
            max_payload_bytes: 64 * 1024 * 1024,
            max_body_bytes: 32 * 1024,
            max_handlers: 128,
            provider_budget: 8,
            claim_quantum: 8,
            demand_scaling: true,
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
        json!({"sql_operations":get(&self.sql_operations),"claim_queries":get(&self.claim_queries),"admission_commits":get(&self.admission_commits),"receipt_commits":get(&self.receipt_commits),"ack_commits":get(&self.ack_commits),"owned_attempts":get(&self.owned_attempts),"peak_owned_attempts":get(&self.peak_owned_attempts),"network_attempts":get(&self.network_attempts),"num_alive":get(&self.num_alive),"db_errors":get(&self.db_errors),"provider_targets":[get(&self.provider_targets[0]),get(&self.provider_targets[1])],"claim_reservations":[get(&self.claim_reservations[0]),get(&self.claim_reservations[1])],"network_inflight":get(&self.network_inflight),"receipts_owned":get(&self.receipts_owned),"provider_owned":[get(&self.provider_owned[0]),get(&self.provider_owned[1])],"provider_claim_queries":[get(&self.provider_claim_queries[0]),get(&self.provider_claim_queries[1])],"http_connections":get(&self.http_connections),"peak_http_connections":get(&self.peak_http_connections)})
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
#[derive(Debug, Deserialize, Clone)]
pub struct AcceptRequest {
    pub channel_id: String,
    pub password: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    pub op_id: String,
    #[serde(default)]
    pub ttl: Option<u32>,
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
    pub attempt_id: i64,
    pub attempts: i64,
    pub payload: Value,
    pub accepted_at: i64,
    pub expires_at: i64,
}
pub(super) struct ClaimBatch {
    pub tickets: Vec<Ticket>,
    pub next_due: Option<i64>,
    pub ready: usize,
    pub has_more: bool,
}
const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS messages(delivery_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,op_id TEXT NOT NULL UNIQUE,channel_id TEXT NOT NULL,fingerprint TEXT NOT NULL,payload_blob BLOB NOT NULL,payload_bytes INTEGER NOT NULL,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,dedupe_until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS targets(delivery_id TEXT NOT NULL REFERENCES messages(delivery_id) ON DELETE CASCADE,device_key TEXT NOT NULL,platform TEXT NOT NULL,provider TEXT NOT NULL,provider_token TEXT NOT NULL,state TEXT NOT NULL,next_attempt_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,attempt_id INTEGER NOT NULL DEFAULT 0,provider_status INTEGER,provider_error TEXT,receipt_at INTEGER,acked_at INTEGER,PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS targets_due ON targets(provider,state,next_attempt_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_device ON targets(device_key,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_retention ON messages(dedupe_until);
CREATE TABLE IF NOT EXISTS devices(device_key TEXT PRIMARY KEY,platform TEXT NOT NULL,provider TEXT,provider_token TEXT);
CREATE TABLE IF NOT EXISTS channels(channel_id TEXT PRIMARY KEY,channel_name TEXT NOT NULL,password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS channel_subscriptions(channel_id TEXT NOT NULL REFERENCES channels(channel_id),device_key TEXT NOT NULL REFERENCES devices(device_key),PRIMARY KEY(channel_id,device_key));
CREATE TABLE IF NOT EXISTS provider_cooldowns(provider TEXT PRIMARY KEY,next_attempt_at INTEGER NOT NULL);
";
impl DeliveryStore {
    pub(super) async fn open(db_url: &str, mut config: Config) -> Result<(Self, OwnerLock)> {
        if config.provider_budget == 0
            || config.provider_budget > 32
            || config.claim_quantum == 0
            || config.claim_quantum > 32
            || config.max_handlers == 0
            || config.max_messages <= 0
            || config.max_targets <= 0
            || config.max_payload_bytes <= 0
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
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        // Recovery is only permitted after acquiring the exclusive OS lock.
        sqlx::query(
            "UPDATE targets SET state='retry_wait',next_attempt_at=? WHERE state='running'",
        )
        .bind(now())
        .execute(&self.pool)
        .await?;
        sqlx::query("UPDATE targets SET state='expired' WHERE state IN ('pending','retry_wait') AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=?)").bind(now()).execute(&self.pool).await?;
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
        let _gate = self.gate.lock().await;
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
        let _gate = self.gate.lock().await;
        self.counters.sql(2);
        let existing: Option<String> =
            sqlx::query_scalar("SELECT platform FROM devices WHERE device_key=?")
                .bind(device)
                .fetch_optional(&self.pool)
                .await?;
        let existing = existing.ok_or_else(|| KernelError::Invalid("unknown device".into()))?;
        let platform = supported_platform(platform.unwrap_or(&existing))?;
        let provider = provider.to_ascii_uppercase();
        if provider != platform.provider_name() {
            return Err(KernelError::Invalid("platform/provider mismatch".into()));
        }
        let canonical = normalize_provider_token(raw, platform)
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        sqlx::query("UPDATE devices SET platform=?,provider=?,provider_token=? WHERE device_key=?")
            .bind(platform.name())
            .bind(provider)
            .bind(canonical)
            .bind(device)
            .execute(&self.pool)
            .await?;
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
        if device.is_empty() || auth.is_empty() || auth.len() > 256 {
            return Err(KernelError::Invalid("device/channel authorization".into()));
        }
        let _gate = self.gate.lock().await;
        self.counters.sql(5);
        let mut tx = self.pool.begin().await?;
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE device_key=?")
            .bind(device)
            .fetch_one(&mut *tx)
            .await?;
        if exists == 0 {
            return Err(KernelError::Invalid("unknown device".into()));
        }
        let (id, name, created) = if let Some(id) = channel_id.filter(|v| !v.is_empty()) {
            let row = sqlx::query("SELECT channel_name,password FROM channels WHERE channel_id=?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(KernelError::Unauthorized)?;
            if row.get::<String, _>("password") != auth {
                return Err(KernelError::Unauthorized);
            }
            (id.to_owned(), row.get::<String, _>("channel_name"), false)
        } else {
            let name = channel_name
                .filter(|v| !v.is_empty() && v.len() <= 256)
                .ok_or_else(|| KernelError::Invalid("channel_name".into()))?;
            let id = generate_hex_id_128();
            sqlx::query("INSERT INTO channels(channel_id,channel_name,password) VALUES(?,?,?)")
                .bind(&id)
                .bind(name)
                .bind(auth)
                .execute(&mut *tx)
                .await?;
            (id, name.to_owned(), true)
        };
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
        if request.op_id.trim().is_empty()
            || request.op_id.len() > 128
            || request.title.len() + request.body.len() > self.config.max_body_bytes
        {
            return Err(KernelError::Invalid("op_id or payload size".into()));
        }
        let ttl = request.ttl.unwrap_or(86_400).min(35 * 86_400);
        if ttl == 0 {
            return Err(KernelError::Invalid("positive ttl required".into()));
        }
        let fingerprint = blake3::hash(&serde_json::to_vec(&json!([
            request.channel_id,
            request.title,
            request.body,
            ttl
        ]))?)
        .to_hex()
        .to_string();
        let _gate = self.gate.lock().await;
        let _wake = AdmissionWake(self.clone());
        self.counters.sql(4);
        let mut tx = self.pool.begin().await?;
        let channel_auth: Option<String> =
            sqlx::query_scalar("SELECT password FROM channels WHERE channel_id=?")
                .bind(&request.channel_id)
                .fetch_optional(&mut *tx)
                .await?;
        if channel_auth.as_deref() != Some(request.password.as_str()) {
            return Err(KernelError::Unauthorized);
        }
        if let Some(row) =
            sqlx::query("SELECT delivery_id,message_id,fingerprint FROM messages WHERE op_id=?")
                .bind(&request.op_id)
                .fetch_optional(&mut *tx)
                .await?
        {
            if row.get::<String, _>("fingerprint") != fingerprint {
                return Err(KernelError::Conflict);
            }
            return Ok(Accepted {
                delivery_id: row.get("delivery_id"),
                message_id: row.get("message_id"),
                op_id: request.op_id,
                acceptance: "duplicate_completed",
                dispatch_status: "provider_queued",
            });
        }
        let at = now();
        // ACK identities remain until no frozen/retry/recovery source can live.
        sqlx::query("DELETE FROM messages WHERE dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(at).execute(&mut *tx).await?;
        let delivery_id = generate_hex_id_128();
        let message_id = generate_hex_id_128();
        let expires = at + i64::from(ttl) * 1000;
        // One immutable canonical client payload is shared by direct delivery,
        // Pull and recovery. Authority comes solely from validated configuration.
        let payload = serde_json::to_vec(
            &json!({"op_id":request.op_id,"title":request.title,"body":request.body,
                "message_id":message_id,"delivery_id":delivery_id,
                "channel_id":request.channel_id,"base_url":self.config.public_base_url,
                "sent_at":at.to_string(),"ingested_at":at.to_string(),"occurred_at":at.to_string(),
                "ttl":expires.div_euclid(1000).to_string(),"entity_type":"message",
                "entity_id":message_id,"payload_version":"1","schema_version":"1"}),
        )?;
        let counts = sqlx::query(
            "SELECT COUNT(*) AS messages,COALESCE(SUM(payload_bytes),0) AS bytes FROM messages",
        )
        .fetch_one(&mut *tx)
        .await?;
        if counts.get::<i64, _>("messages") >= self.config.max_messages
            || counts.get::<i64, _>("bytes") + payload.len() as i64 > self.config.max_payload_bytes
        {
            return Err(KernelError::Capacity);
        }
        self.counters.sql(3);
        let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
            .fetch_one(&mut *tx)
            .await?;
        let fanout:i64=sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&request.channel_id).fetch_one(&mut *tx).await?;
        if retained + fanout > self.config.max_targets {
            return Err(KernelError::Capacity);
        }
        let dedupe = at + 35_i64 * 86_400_000;
        sqlx::query("INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(fingerprint).bind(&payload).bind(payload.len() as i64).bind(at).bind(expires).bind(dedupe).execute(&mut *tx).await?;
        self.counters.sql(2);
        sqlx::query("INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,state,next_attempt_at) SELECT ?,d.device_key,d.platform,d.provider,d.provider_token,'pending',? FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&delivery_id).bind(at).bind(&request.channel_id).execute(&mut *tx).await?;
        tx.commit().await?;
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
        self.notify();
        Ok(Accepted {
            delivery_id,
            message_id,
            op_id: request.op_id,
            acceptance: "new",
            dispatch_status: "provider_queued",
        })
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.counters.sql(1);
        let rows=sqlx::query("SELECT m.delivery_id,m.payload_blob FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE t.device_key=? AND t.acked_at IS NULL AND m.expires_at>? AND (? IS NULL OR m.delivery_id=?) ORDER BY m.accepted_at,m.delivery_id LIMIT 201").bind(device).bind(now()).bind(delivery).bind(delivery).fetch_all(&self.pool).await?;
        let more = rows.len() > 200;
        let mut items = Vec::new();
        for row in rows.into_iter().take(200) {
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            items.push(json!({"delivery_id":row.get::<String,_>("delivery_id"),"payload":payload}));
        }
        Ok(json!({"items":items,"has_more":more}))
    }
    pub async fn pull_legacy(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        let _gate = self.gate.lock().await;
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
        let _gate = self.gate.lock().await;
        self.counters.sql(ids.len() as u64 + 2);
        let mut tx = self.pool.begin().await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=sqlx::query("UPDATE targets SET acked_at=? WHERE device_key=? AND delivery_id=? AND acked_at IS NULL AND EXISTS(SELECT 1 FROM messages WHERE messages.delivery_id=targets.delivery_id AND expires_at>?)").bind(at).bind(device).bind(id).bind(at).execute(&mut *tx).await?.rows_affected() as usize;
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
        self.claim_reserved(provider, limit, retry_first, limit, 0, 0)
            .await
    }
    pub(super) async fn claim_reserved(
        &self,
        provider: &str,
        limit: usize,
        retry_first: bool,
        demand_cap: usize,
        owned: usize,
        warm_target: usize,
    ) -> Result<ClaimBatch> {
        #[cfg(test)]
        if provider == "FCM" {
            let probe = self.hooks.claim_before_gate.lock().unwrap().take();
            if let Some(probe) = probe {
                probe.notify_one();
            }
        }
        let _gate = self.gate.lock().await;
        self.counters.claim_queries.fetch_add(1, Ordering::Relaxed);
        self.counters.provider_claim_queries[usize::from(provider == "APNS")]
            .fetch_add(1, Ordering::Relaxed);
        self.counters.sql(5);
        let at = now();
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE targets SET state='expired' WHERE provider=? AND state IN ('pending','retry_wait') AND delivery_id IN (SELECT delivery_id FROM messages WHERE expires_at<=?)").bind(provider).bind(at).execute(&mut *tx).await?;
        let cooldown: Option<i64> =
            sqlx::query_scalar("SELECT next_attempt_at FROM provider_cooldowns WHERE provider=?")
                .bind(provider)
                .fetch_optional(&mut *tx)
                .await?;
        let mut tickets = Vec::new();
        let mut ready = 0;
        if cooldown.is_none_or(|due| due <= at) {
            // Probe identifiers only; payloads are loaded solely for reserved
            // grants. The extra row distinguishes a full batch from backlog.
            if self.config.demand_scaling {
                self.counters.sql(1);
                let due_rows = sqlx::query("SELECT t.delivery_id,t.device_key FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.provider=? AND t.state IN ('pending','retry_wait') AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? ORDER BY t.next_attempt_at,m.accepted_at,t.delivery_id,t.device_key LIMIT ?")
                    .bind(provider).bind(at).bind(at).bind(demand_cap.saturating_add(1) as i64)
                    .fetch_all(&mut *tx).await?;
                ready = due_rows.len();
            } else {
                // Fixed mode grants lazily up to the reservation without an
                // additional demand probe; actual empty selection still stops.
                ready = limit;
            }
            let classes = if retry_first {
                ["retry_wait", "pending"]
            } else {
                ["pending", "retry_wait"]
            };
            let desired = owned.saturating_add(ready).min(self.config.provider_budget);
            let target = if !self.config.demand_scaling {
                self.config.provider_budget
            } else if desired == 0 {
                0
            } else {
                desired.max(warm_target).min(self.config.provider_budget)
            };
            let index = usize::from(provider == "APNS");
            self.counters.provider_targets[index].store(target as u64, Ordering::Relaxed);
            for n in 0..limit.min(ready).min(target.saturating_sub(owned)) {
                let mut selected = None;
                for class in [classes[n % 2], classes[(n + 1) % 2]] {
                    self.counters.sql(1);
                    let row=sqlx::query("SELECT t.*,m.payload_blob,m.accepted_at,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? ORDER BY t.next_attempt_at,m.accepted_at,t.delivery_id LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx).await?;
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
        let has_more = if self.config.demand_scaling {
            ready > tickets.len()
        } else {
            next_due.is_some_and(|due| due <= at)
        };
        Ok(ClaimBatch {
            tickets,
            next_due,
            ready,
            has_more,
        })
    }
    pub(super) async fn authorize_ticket(&self, ticket: &Ticket) -> Result<bool> {
        self.counters.sql(1);
        let current:i64=sqlx::query_scalar("SELECT COUNT(*) FROM targets t JOIN devices d ON d.device_key=t.device_key JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.state='running' AND t.attempt_id=? AND t.acked_at IS NULL AND m.expires_at>? AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).fetch_one(&self.pool).await?;
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
        let _gate = self.gate.lock().await;
        self.counters.sql(3 + u64::from(cooldown.is_some()));
        let mut tx = self.pool.begin().await?;
        #[cfg(test)]
        {
            let barrier = self.hooks.receipt_with_gate.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.pause().await;
            }
        }
        sqlx::query("UPDATE targets SET state=?,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx).await?;
        if let Some(due) = cooldown {
            sqlx::query("INSERT INTO provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=MAX(next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.counters
            .receipt_commits
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub async fn status(&self, op: &str) -> Result<Value> {
        self.counters.sql(1);
        let rows=sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM messages m LEFT JOIN targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&self.pool).await?;
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
