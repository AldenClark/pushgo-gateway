use crate::ordinary::expiry::is_expired;
use crate::ordinary::profiling::{Path, Phase, Statement};
pub use crate::ordinary::sender::AcceptRequest;
use crate::ordinary::types::generate_hex_id_128;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Connection, Row, SqlitePool};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

pub fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
/// Complete JSON request limit for ordinary message submission only.
pub const MESSAGE_SUBMISSION_BODY_BYTES: usize = 48 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub max_messages: i64,
    pub max_targets: i64,
    /// Shared with retained nonordinary Provider dispatch obligations.
    pub max_provider_targets: i64,
    pub max_payload_bytes: i64,
    /// Body limit for control requests; message submission has its own fixed limit.
    pub max_body_bytes: usize,
    pub max_handlers: usize,
    pub provider_budget: usize,
    pub claim_quantum: usize,
    pub default_ttl_secs: i64,
    pub dedupe_retention_ms: i64,
    pub public_base_url: String,
    pub private: crate::ordinary::private_model::PrivateLedgerConfig,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_messages: 10_000,
            max_targets: 1_000_000,
            max_provider_targets: 1_000_000,
            max_payload_bytes: i64::MAX,
            max_body_bytes: 32 * 1024,
            max_handlers: 128,
            provider_budget: 32,
            claim_quantum: 32,
            default_ttl_secs: 7 * 86_400,
            dedupe_retention_ms: 30 * 86_400_000,
            public_base_url: "http://127.0.0.1:65535".into(),
            private: crate::ordinary::private_model::PrivateLedgerConfig::default(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("authority is unavailable until exclusive-owner restart")]
    Unavailable,
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

// Ordinary runtime SQL keeps its established short fail-stop boundary without
// changing the normal product/control pool's busy_timeout. A changed setting is
// returned only after an explicit successful restore; errors/cancellation close
// that physical connection instead of contaminating the shared pool.
pub(super) struct SqliteWriteConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    previous_busy_timeout: i64,
    restored: bool,
}
impl SqliteWriteConnection {
    pub(super) async fn acquire(pool: &SqlitePool) -> Result<Self> {
        let mut owner = Self {
            connection: pool.acquire().await?,
            previous_busy_timeout: 0,
            restored: false,
        };
        owner.previous_busy_timeout = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&mut *owner.connection)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 3000")
            .execute(&mut *owner.connection)
            .await?;
        Ok(owner)
    }

    pub(super) async fn restore(mut self) -> Result<()> {
        sqlx::query(&format!(
            "PRAGMA busy_timeout = {}",
            self.previous_busy_timeout
        ))
        .execute(&mut *self.connection)
        .await?;
        self.restored = true;
        Ok(())
    }
}
impl std::ops::Deref for SqliteWriteConnection {
    type Target = sqlx::SqliteConnection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}
impl std::ops::DerefMut for SqliteWriteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
impl Drop for SqliteWriteConnection {
    fn drop(&mut self) {
        if !self.restored {
            self.connection.close_on_drop();
        }
    }
}
/// One-way process-local admission fence, shared by every store/router clone.
pub(crate) struct Health {
    failed: AtomicBool,
    failure: tokio::sync::watch::Sender<Option<String>>,
}
impl Default for Health {
    fn default() -> Self {
        let (failure, _) = tokio::sync::watch::channel(None);
        Self {
            failed: AtomicBool::new(false),
            failure,
        }
    }
}
impl Health {
    pub(crate) fn ensure(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            Err(KernelError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) fn fail(&self, reason: &str) {
        self.failure.send_if_modified(|cause| {
            if cause.is_some() {
                return false;
            }
            self.failed.store(true, Ordering::Release);
            *cause = Some(reason.chars().take(4096).collect());
            true
        });
    }
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.failure.subscribe()
    }
}

#[derive(Default)]
pub struct Counters {
    pub profile: crate::ordinary::profiling::Profile,
    pub timings: crate::ordinary::metrics::Timings,
    pub peak_claim_reservations: [AtomicU64; 3],
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
    pub provider_targets: [AtomicU64; 3],
    pub claim_reservations: [AtomicU64; 3],
    pub network_inflight: AtomicU64,
    pub receipts_owned: AtomicU64,
    pub provider_owned: [AtomicU64; 3],
    pub provider_claim_queries: [AtomicU64; 3],
    pub http_connections: AtomicU64,
    pub peak_http_connections: AtomicU64,
}
impl Counters {
    pub fn snapshot(&self) -> Value {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({"profile":self.profile.snapshot(),"network_samples":get(&self.network_samples),"network_total_us":get(&self.network_total_us),"network_max_us":get(&self.network_max_us),"receipt_samples":get(&self.receipt_samples),"receipt_total_us":get(&self.receipt_total_us),"receipt_max_us":get(&self.receipt_max_us),"peak_network_inflight":get(&self.peak_network_inflight),"peak_receipts_owned":get(&self.peak_receipts_owned),"admission_commit_samples":get(&self.admission_commit_samples),"admission_commit_total_us":get(&self.admission_commit_total_us),"admission_commit_max_us":get(&self.admission_commit_max_us),"receipt_commit_samples":get(&self.receipt_commit_samples),"receipt_commit_total_us":get(&self.receipt_commit_total_us),"receipt_commit_max_us":get(&self.receipt_commit_max_us),"gate_wait_samples":get(&self.gate_wait_samples),"gate_wait_total_us":get(&self.gate_wait_total_us),"gate_wait_max_us":get(&self.gate_wait_max_us),"peak_claim_reservations":[get(&self.peak_claim_reservations[0]),get(&self.peak_claim_reservations[1]),get(&self.peak_claim_reservations[2])],"sql_operations":get(&self.sql_operations),"claim_queries":get(&self.claim_queries),"admission_commits":get(&self.admission_commits),"receipt_commits":get(&self.receipt_commits),"ack_commits":get(&self.ack_commits),"owned_attempts":get(&self.owned_attempts),"peak_owned_attempts":get(&self.peak_owned_attempts),"network_attempts":get(&self.network_attempts),"num_alive":get(&self.num_alive),"db_errors":get(&self.db_errors),"provider_targets":[get(&self.provider_targets[0]),get(&self.provider_targets[1]),get(&self.provider_targets[2])],"claim_reservations":[get(&self.claim_reservations[0]),get(&self.claim_reservations[1]),get(&self.claim_reservations[2])],"network_inflight":get(&self.network_inflight),"receipts_owned":get(&self.receipts_owned),"provider_owned":[get(&self.provider_owned[0]),get(&self.provider_owned[1]),get(&self.provider_owned[2])],"provider_claim_queries":[get(&self.provider_claim_queries[0]),get(&self.provider_claim_queries[1]),get(&self.provider_claim_queries[2])],"http_connections":get(&self.http_connections),"peak_http_connections":get(&self.peak_http_connections)})
    }
    pub(super) fn sql(&self, n: u64) {
        self.sql_operations.fetch_add(n, Ordering::Relaxed);
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
    pub(super) health: Arc<Health>,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 3],
    legacy_dispatch_pool: Arc<std::sync::OnceLock<SqlitePool>>,
    pub(super) legacy_delivery_pool: Arc<std::sync::OnceLock<SqlitePool>>,
    #[cfg(test)]
    pub(super) hooks: Arc<TestHooks>,
}
// Test-only barriers expose the real committed DB state before adoption/wake.
// None of these fields or waits exists in the executable's dependency graph.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TestHooks {
    pub delivery_candidates: std::sync::Mutex<std::collections::VecDeque<String>>,
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
pub(crate) struct Ticket {
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
    pub watch_alert_deadline: Option<i64>,
}
pub(crate) struct ClaimBatch {
    pub tickets: Vec<Ticket>,
    pub next_due: Option<i64>,
    pub has_more: bool,
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='provider' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_id=? AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
pub(super) const RECOVER_RUNNING_SQL: &str = "UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='private' THEN 'superseded_route' ELSE 'retry_wait' END,next_attempt_at=? WHERE provider=? AND state='running'";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM ordinary_retired_provider_tokens r CROSS JOIN ordinary_targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.delivery_mode='provider' AND t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";
// Historical identities share the ordinary authority but have no invented wire
// identity, fingerprint or delivery TTL. A nullable UNIQUE delivery key remains
// the parent key of live targets; no target can reference a historical NULL.
pub(crate) const MESSAGE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ordinary_messages(delivery_id TEXT UNIQUE,message_id TEXT NOT NULL UNIQUE,op_id TEXT NOT NULL UNIQUE,channel_id TEXT NOT NULL,thing_id TEXT,fingerprint TEXT,payload_blob BLOB NOT NULL,payload_bytes INTEGER NOT NULL,accepted_at INTEGER NOT NULL,expires_at INTEGER,dedupe_until INTEGER NOT NULL,status TEXT NOT NULL,updated_at INTEGER NOT NULL,pending_targets INTEGER NOT NULL DEFAULT 0,provider_accepted_count INTEGER NOT NULL DEFAULT 0,provider_failed_count INTEGER NOT NULL DEFAULT 0,provider_target_count INTEGER NOT NULL DEFAULT 0,private_enqueued_count INTEGER NOT NULL DEFAULT 0,private_rejected_count INTEGER NOT NULL DEFAULT 0,identity_state TEXT NOT NULL DEFAULT 'live',CHECK((identity_state='live' AND delivery_id IS NOT NULL AND fingerprint IS NOT NULL AND expires_at IS NOT NULL) OR (identity_state='legacy_unverifiable' AND delivery_id IS NULL AND fingerprint IS NULL AND expires_at IS NULL AND payload_bytes=0 AND length(payload_blob)=0 AND status='historical_unverifiable' AND pending_targets=0 AND provider_target_count=0 AND private_enqueued_count=0 AND provider_accepted_count=0 AND provider_failed_count=0 AND private_rejected_count=0)));
";
const SCHEMA:&str="
CREATE UNIQUE INDEX IF NOT EXISTS ordinary_historical_op ON ordinary_messages(lower(op_id)) WHERE identity_state='legacy_unverifiable';
CREATE TABLE IF NOT EXISTS ordinary_widget_refresh(delivery_id TEXT PRIMARY KEY,channel_id BLOB NOT NULL UNIQUE CHECK(length(channel_id)=16),coalesce_order INTEGER NOT NULL UNIQUE,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ordinary_widget_refresh_expiry ON ordinary_widget_refresh(expires_at,delivery_id);
CREATE TABLE IF NOT EXISTS ordinary_targets(delivery_id TEXT NOT NULL REFERENCES ordinary_messages(delivery_id) ON DELETE CASCADE,device_key TEXT NOT NULL,pull_owner TEXT NOT NULL DEFAULT '',owner_generation INTEGER NOT NULL DEFAULT 0,control_epoch INTEGER NOT NULL DEFAULT 0,platform TEXT NOT NULL,provider TEXT NOT NULL,provider_token TEXT NOT NULL,route_generation INTEGER NOT NULL DEFAULT 0,accepted_at INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,next_attempt_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,attempt_id INTEGER NOT NULL DEFAULT 0,provider_status INTEGER,provider_error TEXT,receipt_at INTEGER,acked_at INTEGER,delivery_mode TEXT NOT NULL DEFAULT 'provider',delivery_epoch INTEGER NOT NULL DEFAULT 0,private_claim TEXT,private_group TEXT,watch_alert_deadline_at INTEGER,PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS ordinary_targets_due ON ordinary_targets(provider,state,next_attempt_at,delivery_id);
CREATE INDEX IF NOT EXISTS ordinary_targets_device ON ordinary_targets(pull_owner,accepted_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_messages_retention ON ordinary_messages(dedupe_until);
CREATE INDEX IF NOT EXISTS ordinary_messages_expiry ON ordinary_messages(expires_at,delivery_id) WHERE payload_bytes>0;
CREATE TABLE IF NOT EXISTS ordinary_ledger_usage(singleton INTEGER PRIMARY KEY CHECK(singleton=1),messages INTEGER NOT NULL,targets INTEGER NOT NULL,bytes INTEGER NOT NULL,control_epoch INTEGER NOT NULL DEFAULT 0,private_pending INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO ordinary_ledger_usage(singleton,messages,targets,bytes) VALUES(1,0,0,0);
CREATE TRIGGER IF NOT EXISTS ordinary_messages_usage_insert AFTER INSERT ON ordinary_messages BEGIN UPDATE ordinary_ledger_usage SET messages=messages+(NEW.pending_targets>0),bytes=bytes+NEW.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS ordinary_messages_usage_update AFTER UPDATE OF payload_bytes,pending_targets ON ordinary_messages BEGIN UPDATE ordinary_ledger_usage SET messages=messages+(NEW.pending_targets>0)-(OLD.pending_targets>0),bytes=bytes+NEW.payload_bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS ordinary_messages_usage_delete AFTER DELETE ON ordinary_messages BEGIN UPDATE ordinary_ledger_usage SET messages=messages-(OLD.pending_targets>0),bytes=bytes-OLD.payload_bytes WHERE singleton=1; END;
CREATE TRIGGER IF NOT EXISTS ordinary_targets_usage_insert AFTER INSERT ON ordinary_targets WHEN NEW.acked_at IS NULL AND (NEW.delivery_mode='private' OR NEW.state IN ('pending','running','retry_wait')) BEGIN UPDATE ordinary_ledger_usage SET targets=targets+1 WHERE singleton=1; UPDATE ordinary_messages SET pending_targets=pending_targets+1 WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS ordinary_targets_usage_update AFTER UPDATE OF acked_at,state,delivery_mode ON ordinary_targets BEGIN UPDATE ordinary_ledger_usage SET targets=targets+(NEW.acked_at IS NULL AND (NEW.delivery_mode='private' OR NEW.state IN ('pending','running','retry_wait')))-(OLD.acked_at IS NULL AND (OLD.delivery_mode='private' OR OLD.state IN ('pending','running','retry_wait'))) WHERE singleton=1; UPDATE ordinary_messages SET pending_targets=pending_targets+(NEW.acked_at IS NULL AND (NEW.delivery_mode='private' OR NEW.state IN ('pending','running','retry_wait')))-(OLD.acked_at IS NULL AND (OLD.delivery_mode='private' OR OLD.state IN ('pending','running','retry_wait'))) WHERE delivery_id=NEW.delivery_id; END;
CREATE TRIGGER IF NOT EXISTS ordinary_targets_usage_delete AFTER DELETE ON ordinary_targets WHEN OLD.acked_at IS NULL AND (OLD.delivery_mode='private' OR OLD.state IN ('pending','running','retry_wait')) BEGIN UPDATE ordinary_ledger_usage SET targets=targets-1 WHERE singleton=1; UPDATE ordinary_messages SET pending_targets=pending_targets-1 WHERE delivery_id=OLD.delivery_id; END;
CREATE TABLE IF NOT EXISTS ordinary_retired_provider_tokens(platform TEXT NOT NULL,provider_token TEXT NOT NULL,control_epoch INTEGER NOT NULL,PRIMARY KEY(platform,provider_token));
CREATE INDEX IF NOT EXISTS ordinary_targets_owner_delivery ON ordinary_targets(pull_owner,delivery_id,device_key) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_token_retirement ON ordinary_targets(platform,provider_token,control_epoch);
CREATE TRIGGER IF NOT EXISTS ordinary_targets_owner_insert AFTER INSERT ON ordinary_targets WHEN NEW.pull_owner='' BEGIN UPDATE ordinary_targets SET pull_owner=NEW.device_key,owner_generation=NEW.route_generation,control_epoch=(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1) WHERE delivery_id=NEW.delivery_id AND device_key=NEW.device_key; END;
CREATE TABLE IF NOT EXISTS ordinary_provider_cooldowns(provider TEXT PRIMARY KEY,next_attempt_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ordinary_limits(singleton INTEGER PRIMARY KEY CHECK(singleton=1),max_messages INTEGER NOT NULL,max_targets INTEGER NOT NULL,max_payload_bytes INTEGER NOT NULL,max_private_per_device INTEGER NOT NULL,max_private INTEGER NOT NULL);
";
// These are projections, not control records. Every read, freeze and pre-send
// authorization sees the same normal-product rows as control transactions.
const CANONICAL_VIEWS: &str = r#"
CREATE VIEW IF NOT EXISTS ordinary_channel_routes AS
 SELECT lower(hex(channel_id)) AS channel_id,password_hash,alias AS channel_name FROM channels;
CREATE VIEW IF NOT EXISTS ordinary_device_routes AS
 SELECT COALESCE(device_key,lower(hex(device_id))) AS device_key,
 platform,channel_type,route_updated_at,device_id,
 CASE WHEN lower(channel_type)='private' OR channel_type IS NULL THEN NULL ELSE CASE lower(platform) WHEN 'android' THEN 'FCM' WHEN 'windows' THEN 'WNS' WHEN 'ios' THEN 'APNS' WHEN 'macos' THEN 'APNS' WHEN 'watchos' THEN 'APNS' ELSE NULL END END AS provider,
 provider_token,ordinary_route_generation AS route_generation,route_revision,
 CASE WHEN channel_type IS NULL THEN 1 ELSE NULL END AS retired_at,
 NULL AS coalesced_to,watch_alert_window_minutes
 FROM devices WHERE platform IS NOT NULL;
CREATE VIEW IF NOT EXISTS ordinary_subscriptions AS
 SELECT lower(hex(s.channel_id)) AS channel_id,COALESCE(d.device_key,lower(hex(d.device_id))) AS device_key,s.created_at,s.updated_at,s.device_id
 FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id WHERE s.status='active';
CREATE TRIGGER IF NOT EXISTS ordinary_device_insert_epoch AFTER INSERT ON devices
BEGIN
 SELECT CASE WHEN (SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1)=9223372036854775807 THEN RAISE(ABORT,'ordinary route epoch exhausted') END;
 UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1;
 UPDATE devices SET ordinary_route_generation=(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1) WHERE device_id=NEW.device_id;
END;
CREATE TRIGGER IF NOT EXISTS ordinary_device_route_epoch AFTER UPDATE OF platform,channel_type,provider_token,device_key ON devices
WHEN OLD.platform IS NOT NEW.platform OR OLD.channel_type IS NOT NEW.channel_type OR OLD.provider_token IS NOT NEW.provider_token OR OLD.device_key IS NOT NEW.device_key
BEGIN
 SELECT CASE WHEN (SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1)=9223372036854775807 THEN RAISE(ABORT,'ordinary route epoch exhausted') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM ordinary_targets WHERE pull_owner=OLD.device_key AND acked_at IS NULL AND delivery_epoch=9223372036854775807) THEN RAISE(ABORT,'ordinary private epoch exhausted') END;
 UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1;
 UPDATE devices SET ordinary_route_generation=(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1) WHERE device_id=NEW.device_id;
 SELECT CASE WHEN lower(NEW.channel_type)='private' AND lower(COALESCE(OLD.channel_type,''))<>'private' AND EXISTS(SELECT 1 FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=OLD.device_key AND t.delivery_mode<>'private' AND t.acked_at IS NULL AND m.expires_at>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)) AND EXISTS(SELECT 1 FROM ordinary_limits l WHERE COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=OLD.device_key),0)+(SELECT COUNT(DISTINCT t.delivery_id) FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=OLD.device_key AND t.delivery_mode<>'private' AND t.acked_at IS NULL AND m.expires_at>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=t.pull_owner AND s.delivery_id=t.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch))>l.max_private_per_device) THEN RAISE(ABORT,'ordinary route transition capacity exceeded') END;
 UPDATE ordinary_targets SET delivery_mode=CASE WHEN lower(NEW.channel_type)='private' THEN 'private' ELSE 'provider' END,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,owner_generation=-1,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=OLD.device_key AND acked_at IS NULL AND (lower(NEW.channel_type)<>'private' OR EXISTS(SELECT 1 FROM ordinary_messages m WHERE m.delivery_id=ordinary_targets.delivery_id AND m.expires_at>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER))) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=ordinary_targets.platform AND r.provider_token=ordinary_targets.provider_token AND ordinary_targets.control_epoch<r.control_epoch);
 UPDATE ordinary_messages SET status=CASE WHEN EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_id=ordinary_messages.delivery_id AND t.provider IN ('FCM','APNS','WNS') AND (t.state='running' OR (t.delivery_mode='provider' AND t.acked_at IS NULL AND t.state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE status='provider_queued' AND delivery_id IN (SELECT delivery_id FROM ordinary_targets WHERE pull_owner=COALESCE(OLD.device_key,lower(hex(OLD.device_id))));
 SELECT CASE WHEN EXISTS(SELECT 1 FROM ordinary_limits l JOIN ordinary_ledger_usage u ON u.singleton=l.singleton WHERE u.messages>l.max_messages OR u.targets>l.max_targets OR u.bytes>l.max_payload_bytes) THEN RAISE(ABORT,'ordinary route transition capacity exceeded') END;
END;
CREATE TRIGGER IF NOT EXISTS ordinary_device_delete_fence BEFORE DELETE ON devices
BEGIN
 UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER),state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE pull_owner=COALESCE(OLD.device_key,lower(hex(OLD.device_id))) AND acked_at IS NULL;
 UPDATE ordinary_messages SET status=CASE WHEN EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_id=ordinary_messages.delivery_id AND t.provider IN ('FCM','APNS','WNS') AND (t.state='running' OR (t.delivery_mode='provider' AND t.acked_at IS NULL AND t.state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE status='provider_queued' AND delivery_id IN (SELECT delivery_id FROM ordinary_targets WHERE pull_owner=COALESCE(OLD.device_key,lower(hex(OLD.device_id))));
 UPDATE ordinary_messages SET payload_blob=X'',payload_bytes=0 WHERE payload_bytes>0 AND delivery_id IN (SELECT delivery_id FROM ordinary_targets WHERE pull_owner=COALESCE(OLD.device_key,lower(hex(OLD.device_id)))) AND NOT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_id=ordinary_messages.delivery_id AND t.acked_at IS NULL);
 DELETE FROM ordinary_targets WHERE pull_owner=COALESCE(OLD.device_key,lower(hex(OLD.device_id))) AND acked_at IS NOT NULL AND state<>'running';
END;
"#;
impl DeliveryStore {
    pub(crate) fn set_legacy_pools(
        &self,
        dispatch: SqlitePool,
        delivery: SqlitePool,
    ) -> Result<()> {
        self.legacy_dispatch_pool.set(dispatch).map_err(|_| {
            KernelError::Invalid("ordinary legacy dispatch pool already assigned".into())
        })?;
        self.legacy_delivery_pool.set(delivery).map_err(|_| {
            KernelError::Invalid("ordinary legacy delivery pool already assigned".into())
        })?;
        Ok(())
    }
    /// Read only. The caller that combines this with another producer's
    /// capacity check must already hold Storage's shared durable mutation gate.
    pub(crate) async fn active_provider_count(&self) -> Result<i64> {
        self.health.ensure()?;
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND (state='running' OR (delivery_mode='provider' AND state IN ('pending','retry_wait')))").fetch_one(&self.pool).await?)
    }
    pub(crate) async fn private_pending_count(&self, device: Option<&str>) -> Result<i64> {
        self.health.ensure()?;
        if let Some(device) = device {
            Ok(sqlx::query_scalar("SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=?),0)").bind(device).fetch_one(&self.pool).await?)
        } else {
            Ok(sqlx::query_scalar(
                "SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1",
            )
            .fetch_one(&self.pool)
            .await?)
        }
    }
    async fn legacy_active_provider_count(&self) -> Result<i64> {
        let Some(pool) = self.legacy_dispatch_pool.get() else {
            return Ok(0);
        };
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased')").fetch_one(pool).await?)
    }
    async fn reserve_widget_refresh_order(&self) -> Result<i64> {
        let pool = self.legacy_dispatch_pool.get().ok_or_else(|| {
            KernelError::Invalid(
                "ordinary Widget refresh requires the product dispatch pool".into(),
            )
        })?;
        let mut connection = SqliteWriteConnection::acquire(pool).await?;
        let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT OR IGNORE INTO dispatch_acceptance_sequence(singleton,current_value) VALUES(1,0)")
            .execute(&mut *tx).await?;
        let changed = sqlx::query("UPDATE dispatch_acceptance_sequence SET current_value=current_value+1 WHERE singleton=1 AND current_value<9223372036854775807")
            .execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(KernelError::Invalid(
                "dispatch acceptance order exhausted".into(),
            ));
        }
        let order = sqlx::query_scalar(
            "SELECT current_value FROM dispatch_acceptance_sequence WHERE singleton=1",
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        connection.restore().await?;
        Ok(order)
    }

    // The retained lane already owns its execution queue budget. Accepted C
    // targets wait durably under the system target budget, and reserve these
    // per-device/global execution slots only at private_claim.
    pub(super) async fn legacy_private_pending(&self) -> Result<i64> {
        if !self.config.private.enabled {
            return Ok(0);
        }
        let Some(pool) = self.legacy_delivery_pool.get() else {
            return Ok(0);
        };
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')",
        )
        .fetch_one(pool)
        .await?)
    }

    pub(super) async fn legacy_private_pending_for_device(&self, device: &str) -> Result<i64> {
        let Some(pool) = self.legacy_delivery_pool.get() else {
            return Ok(0);
        };
        let id: crate::storage::DeviceId = crate::storage::PrivateDeviceId::derive(device).into();
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM private_outbox WHERE device_id=? AND status IN ('pending','claimed','sent')")
            .bind(id.as_slice()).fetch_one(pool).await?)
    }

    /// Read only; Storage owns the shared mutation gate when combining this
    /// count with the retained nonordinary lane's per-device capacity check.
    pub(crate) async fn private_executing_count(&self, device: Option<&str>) -> Result<i64> {
        self.health.ensure()?;
        if let Some(device) = device {
            Ok(sqlx::query_scalar("SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE pull_owner=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL")
                .bind(device).fetch_one(&self.pool).await?)
        } else {
            Ok(sqlx::query_scalar("SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL")
                .fetch_one(&self.pool).await?)
        }
    }

    /// The caller owns Storage's shared gate. Return the existing product's
    /// route-migration pending/capacity units without claiming work or writing.
    pub(crate) async fn private_route_capacity(&self, device: &str) -> Result<(i64, i64)> {
        self.health.ensure()?;
        let current = self.private_pending_count(Some(device)).await?;
        let global = self.private_pending_count(None).await?;
        let additional:i64=sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT DISTINCT t.delivery_id FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_mode='provider' AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_targets p WHERE p.pull_owner=t.pull_owner AND p.delivery_id=t.delivery_id AND p.delivery_mode='private' AND p.acked_at IS NULL))")
            .bind(device).bind(now()).fetch_one(&self.pool).await?;
        let (legacy, legacy_owner) = if let Some(pool) = self.legacy_delivery_pool.get() {
            let id: crate::storage::DeviceId =
                crate::storage::PrivateDeviceId::derive(device).into();
            let row=sqlx::query("SELECT COUNT(*) AS pending,COALESCE(SUM(device_id=?),0) AS owner_pending FROM private_outbox WHERE status IN ('pending','claimed','sent')").bind(id.as_slice()).fetch_one(pool).await?;
            (
                row.get::<i64, _>("pending"),
                row.get::<i64, _>("owner_pending"),
            )
        } else {
            (0, 0)
        };
        let pending = current
            .saturating_add(legacy_owner)
            .saturating_add(additional);
        let capacity = (self.config.private.max_pending_per_device as i64)
            .min(
                (self.config.private.max_pending as i64)
                    .saturating_sub(global)
                    .saturating_sub(legacy)
                    .saturating_add(current)
                    .saturating_add(legacy_owner),
            )
            .max(0);
        Ok((pending, capacity))
    }
    /// Uses the normal product core pool and lifecycle. Exclusive ownership must
    /// already have been acquired before this initialization can recover work.
    pub(crate) async fn from_product(
        pool: SqlitePool,
        gate: Arc<Mutex<()>>,
        config: Config,
        health: Arc<Health>,
        counters: Arc<Counters>,
    ) -> Result<Self> {
        if config.dedupe_retention_ms < 30 * 86_400_000
            || config.provider_budget == 0
            || config.claim_quantum == 0
            || config.claim_quantum > config.provider_budget
            || config.max_handlers == 0
            || config.max_messages <= 0
            || config.max_targets <= 0
            || config.max_payload_bytes <= 0
            || config.default_ttl_secs <= 0
            || config.default_ttl_secs > 30 * 86_400
        {
            return Err(KernelError::Invalid(
                "ordinary budgets and full 30-day identity retention required".into(),
            ));
        }
        // Only the explicit offline cutover may transfer supported drained
        // histories. Never silently retain a second ordinary identity owner.
        let old: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE model='message' AND expires_at>?) OR EXISTS(SELECT 1 FROM semantic_id_registry WHERE dedupe_key LIKE 'semantic:%:message:%' AND (expires_at IS NULL OR expires_at>?))")
            .bind(now()).bind(now()).fetch_one(&pool).await?;
        if old {
            return Err(KernelError::Invalid("retained legacy ordinary identities require an explicit migration before ordinary cutover".into()));
        }
        let store = Self {
            pool,
            health,
            gate,
            config,
            counters,
            wake: std::array::from_fn(|_| Arc::new(Notify::new())),
            legacy_dispatch_pool: Arc::new(std::sync::OnceLock::new()),
            legacy_delivery_pool: Arc::new(std::sync::OnceLock::new()),
            #[cfg(test)]
            hooks: Arc::new(TestHooks::default()),
        };
        store.initialize().await?;
        Ok(store)
    }
    async fn initialize(&self) -> Result<()> {
        let mut connection = SqliteWriteConnection::acquire(&self.pool).await?;
        sqlx::raw_sql(MESSAGE_SCHEMA)
            .execute(&mut *connection)
            .await?;
        let has_identity_state: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('ordinary_messages') WHERE name='identity_state')")
            .fetch_one(&mut *connection).await?;
        if !has_identity_state {
            return Err(KernelError::Invalid("ordinary identity schema requires an explicit offline upgrade; prior C candidate databases are not a fixed-main migration source".into()));
        }
        sqlx::raw_sql(SCHEMA).execute(&mut *connection).await?;
        let channel_unique: bool = sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM pragma_index_list('ordinary_widget_refresh') idx WHERE idx."unique"=1 AND idx.partial=0 AND (SELECT COUNT(*) FROM pragma_index_info(idx.name))=1 AND EXISTS(SELECT 1 FROM pragma_index_info(idx.name) col WHERE col.name='channel_id'))"#)
            .fetch_one(&mut *connection).await?;
        if !channel_unique {
            return Err(KernelError::Invalid("ordinary Widget channel coalescing constraint missing; use a fresh C10 database or explicitly migrate the prior candidate before startup".into()));
        }
        let columns = sqlx::query("PRAGMA table_info(devices)")
            .fetch_all(&mut *connection)
            .await?;
        if !columns
            .iter()
            .any(|r| r.get::<String, _>("name") == "ordinary_route_generation")
        {
            sqlx::query("ALTER TABLE devices ADD COLUMN ordinary_route_generation INTEGER NOT NULL DEFAULT 0").execute(&mut *connection).await?;
        }
        sqlx::raw_sql(CANONICAL_VIEWS)
            .execute(&mut *connection)
            .await?;
        sqlx::raw_sql(crate::ordinary::sqlite_private::PRIVATE_USAGE_SCHEMA)
            .execute(&mut *connection)
            .await?;
        sqlx::query("INSERT INTO ordinary_limits(singleton,max_messages,max_targets,max_payload_bytes,max_private_per_device,max_private) VALUES(1,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET max_messages=excluded.max_messages,max_targets=excluded.max_targets,max_payload_bytes=excluded.max_payload_bytes,max_private_per_device=excluded.max_private_per_device,max_private=excluded.max_private")
            .bind(self.config.max_messages).bind(self.config.max_targets).bind(self.config.max_payload_bytes).bind(self.config.private.max_pending_per_device as i64).bind(self.config.private.max_pending as i64).execute(&mut *connection).await?;
        let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
        while self.recover_private_claims_tx(&mut tx).await? == 256 {}
        for provider in ["FCM", "APNS", "WNS"] {
            sqlx::query("DELETE FROM ordinary_targets WHERE provider=? AND state='running' AND acked_at IS NOT NULL").bind(provider).execute(&mut *tx).await?;
            sqlx::query(RECOVER_RUNNING_SQL)
                .bind(now())
                .bind(provider)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE status='provider_queued' AND NOT EXISTS(SELECT 1 FROM ordinary_targets outstanding WHERE outstanding.delivery_id=ordinary_messages.delivery_id AND outstanding.provider IN ('FCM','APNS','WNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait'))))").bind(now()).execute(&mut *tx).await?;
        self.health.ensure()?;
        tx.commit().await?;
        connection.restore().await?;
        self.maintenance().await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
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
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=? AND device_key=? AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("DELETE FROM ordinary_retired_provider_tokens WHERE rowid IN (SELECT r.rowid FROM ordinary_retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_mode='provider' AND t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256)").execute(&mut **tx)).await?;
        Ok(())
    }
    async fn allocate_delivery_id(&self) -> Result<String> {
        for _ in 0..4 {
            #[cfg(test)]
            let candidate = self
                .hooks
                .delivery_candidates
                .lock()
                .expect("test candidates")
                .pop_front()
                .unwrap_or_else(generate_hex_id_128);
            #[cfg(not(test))]
            let candidate = generate_hex_id_128();
            let collision: bool = if let Some(pool) = self.legacy_dispatch_pool.get() {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM dispatch_delivery_dedupe WHERE dedupe_key=?)",
                )
                .bind(format!("delivery:{candidate}"))
                .fetch_one(pool)
                .await?
            } else {
                false
            };
            if !collision {
                return Ok(candidate);
            }
        }
        Err(KernelError::Unavailable)
    }

    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        let authorized_channel = request.authorized_channel;
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
        self.health.ensure()?;
        let _gate_hold = self.counters.profile.timer(Path::Accept, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        let _wake = AdmissionWake(self.clone());
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(
                Path::Accept,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Accept,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        let storage_channel = channel_storage_key(&request.channel_id)?;
        let auth: Option<String> = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Auth,
                sqlx::query_scalar(
                    "SELECT password_hash FROM ordinary_channel_routes WHERE channel_id=?",
                )
                .bind(&storage_channel)
                .fetch_optional(&mut *tx),
            )
            .await?;
        let hash = auth.ok_or(KernelError::Unauthorized)?;
        if authorized_channel.is_none()
            && !self
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
        // The ordinary ledger is its only identity owner. Retained Event/Thing
        // status still owns the shared public op_id scope for those models.
        let other_scope: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE op_id=? AND expires_at>?)",
        )
        .bind(&request.op_id)
        .bind(at)
        .fetch_one(&mut *tx)
        .await?;
        if other_scope {
            return Err(KernelError::ScopeConflict);
        }
        if let Some(row)=self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("SELECT delivery_id,message_id,channel_id,thing_id,fingerprint,status,provider_target_count,private_enqueued_count,identity_state FROM ordinary_messages WHERE (op_id=? OR (identity_state='legacy_unverifiable' AND lower(op_id)=lower(?))) AND dedupe_until>?").bind(&request.op_id).bind(&request.op_id).bind(at).fetch_optional(&mut *tx)).await? {
            if row.get::<String,_>("identity_state")=="legacy_unverifiable" {
                return Err(KernelError::Control { status:409, code:"historical_identity_unverifiable", message:"historical message identity is retained, but its original request cannot be verified; use a new op_id".into() });
            }
            if row.get::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get::<Option<String>,_>("thing_id")!=request.thing_id {return Err(KernelError::ScopeConflict)}
            if row.get::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            let accepted = Accepted{delivery_id:row.get("delivery_id"),message_id:row.get("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:crate::ordinary::application::accepted_dispatch_status(&row.get::<String,_>("status"),row.get("provider_target_count"),row.get("private_enqueued_count"))?};
            tx.rollback().await?;
            profile_connection.restore().await?;
            return Ok(accepted)
        }
        // Only maintenance is committed here. No new identity, payload,
        // recipient or capacity reservation exists until the final transaction.
        // This prevents a core write lease from waiting on a second connection
        // to an attached delivery database during normal control coalescing.
        self.maintain_tx(&mut tx, at).await?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Maintenance, Phase::Commit, tx.commit())
            .await?;
        let at = now();
        let legacy_provider = self.legacy_active_provider_count().await?;
        // Do not hold the core write transaction while reading the dispatch
        // sidecar. Existing independent collision reservations remain effective
        // even when the original operation-to-delivery relation was lost.
        let delivery_id = self.allocate_delivery_id().await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Accept,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        self.health.ensure()?;
        // An exact expired identity can be replaced even if bounded GC has backlog.
        self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("DELETE FROM ordinary_messages WHERE op_id=? AND dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running')").bind(&request.op_id).bind(at).execute(&mut *tx)).await?;
        let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
        let message_id = generate_hex_id_128();
        let expires = request
            .ttl
            .map(|ttl| ttl.min(at.saturating_add(crate::ordinary::sender::MAX_TTL_MS)))
            .unwrap_or(at.saturating_add(self.config.default_ttl_secs * 1000));
        let mut fields = request.fields;
        // This routing hint is Gateway configuration, never sender authority.
        // An unconfigured product omits it rather than advertising an empty URL.
        fields.remove("base_url");
        let public_base_url = self.config.public_base_url.trim();
        if !public_base_url.is_empty() {
            fields.insert("base_url".into(), public_base_url.to_owned());
        }
        for (key, value) in [
            ("op_id", request.op_id.clone()),
            ("message_id", message_id.clone()),
            ("delivery_id", delivery_id.clone()),
            ("channel_id", request.channel_id.clone()),
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
                sqlx::query(
                    "SELECT messages,targets,bytes FROM ordinary_ledger_usage WHERE singleton=1",
                )
                .fetch_one(&mut *tx),
            )
            .await?;
        let provider_fanout:i64=self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT d.platform,d.provider_token FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL AND trim(d.provider_token)<>'' AND d.route_updated_at IS NOT NULL GROUP BY d.platform,d.provider_token)").bind(&storage_channel).bind(at).fetch_one(&mut *tx)).await?;
        let active_provider:i64=sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND (state='running' OR (delivery_mode='provider' AND state IN ('pending','retry_wait')))").fetch_one(&mut *tx).await?;
        if !is_expired(expires, at)
            && active_provider
                .saturating_add(legacy_provider)
                .saturating_add(provider_fanout)
                > self.config.max_provider_targets
        {
            return Err(KernelError::Capacity);
        }
        let private_fanout = if !is_expired(expires, at) {
            self.count_private_fanout_tx(&mut tx, &request.channel_id, at)
                .await?
        } else {
            0
        };
        let fanout = provider_fanout.saturating_add(private_fanout);
        let live = fanout > 0 && !is_expired(expires, at);
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
        let status = if !live {
            "failed"
        } else if provider_fanout > 0 {
            "provider_queued"
        } else {
            "sent"
        };
        let dispatch_status = crate::ordinary::application::accepted_dispatch_status(
            status,
            if live { provider_fanout } else { 0 },
            if live { private_fanout } else { 0 },
        )?;
        self.counters.profile.sql(Path::Accept, Statement::MessageInsert, sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,thing_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,provider_target_count,private_enqueued_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.thing_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).bind(if live {provider_fanout}else{0}).bind(if live {private_fanout}else{0}).execute(&mut *tx)).await?;
        if live {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,platform,provider,provider_token,route_generation,watch_alert_deadline_at,accepted_at,state,next_attempt_at) SELECT ?,d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,CASE WHEN d.platform='watchos' THEN ?+d.watch_alert_window_minutes*60000 ELSE NULL END,?,'pending',? FROM (SELECT d.*,ROW_NUMBER() OVER(PARTITION BY d.platform,d.provider_token ORDER BY d.channel_type ASC,d.route_updated_at DESC,s.updated_at DESC,s.created_at DESC,s.device_id DESC) AS recipient_rank FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL AND trim(d.provider_token)<>'' AND d.route_updated_at IS NOT NULL) d WHERE d.recipient_rank=1").bind(&delivery_id).bind(at).bind(at).bind(at).bind(&storage_channel).bind(at).execute(&mut *tx)).await?;
        }
        if live && private_fanout > 0 {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at,delivery_mode) SELECT ?,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1),d.platform,'PRIVATE','',d.route_generation,?,'superseded_route',?,'private' FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.channel_type='private' AND length(d.device_id)=16 AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(&delivery_id).bind(at).bind(at).bind(&storage_channel).bind(at).execute(&mut *tx)).await?;
        }
        // Widget notifications carry no ordinary body or identity authority.
        // Preserve the existing matching subscription side effect even when no
        // ordinary transport target was frozen, but never for an expired send.
        if !is_expired(expires, at) {
            let canonical_channel = crate::value::ChannelId::parse(&request.channel_id)
                .map_err(|_| KernelError::Invalid("channel_id".into()))?
                .into_inner();
            let matching_widget: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM widget_push_subscriptions w JOIN devices d ON d.device_key=w.device_key JOIN channel_subscriptions s ON s.device_id=d.device_id WHERE s.channel_id=? AND s.status='active' AND lower(trim(w.platform)) IN ('ios','ipados','macos','watchos') AND w.widget_kind IN (?,?))",
            )
            .bind(canonical_channel.as_slice())
            .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
            .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
            .fetch_one(&mut *tx).await?;
            if matching_widget {
                // This is the normal sidecar clock, shared with existing Widget,
                // Event and Thing ordering. A failed outer TX may leave a gap.
                let order = self.reserve_widget_refresh_order().await?;
                sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,coalesce_order,accepted_at,expires_at) SELECT delivery_id,?, ?,accepted_at,expires_at FROM ordinary_messages WHERE delivery_id=? ON CONFLICT(channel_id) DO UPDATE SET delivery_id=excluded.delivery_id,coalesce_order=excluded.coalesce_order,accepted_at=excluded.accepted_at,expires_at=excluded.expires_at WHERE ordinary_widget_refresh.coalesce_order<excluded.coalesce_order")
                    .bind(canonical_channel.as_slice())
                    .bind(order).bind(&delivery_id).execute(&mut *tx).await?;
            }
        }
        let commit_at = std::time::Instant::now();
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Accept, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
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
            dispatch_status,
        })
    }
    pub(super) async fn release_acked_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        device: &str,
        id: &str,
        profile_path: Path,
    ) -> Result<()> {
        // A completed client ACK is positive delivery evidence, independent of
        // whether a provider was attempted. Do not count it as provider acceptance.
        self.refresh_provider_status_tx(tx, id, profile_path)
            .await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget, sqlx::query("DELETE FROM ordinary_targets WHERE delivery_id=? AND (device_key=? OR acked_at IS NOT NULL) AND acked_at IS NOT NULL AND state!='running'").bind(id).bind(device).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload, sqlx::query("UPDATE ordinary_messages SET payload_blob=X'',payload_bytes=0 WHERE delivery_id=? AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND acked_at IS NULL)").bind(id).execute(&mut **tx)).await?;
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
        self.health.ensure()?;
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
            .phase(
                Path::Maintenance,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Maintenance,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        let removed = self.maintain_tx(&mut tx, now()).await?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Maintenance, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
        Ok(removed)
    }
    async fn maintain_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        at: i64,
    ) -> Result<usize> {
        self.retire_token_targets_tx(tx).await?;
        sqlx::query("DELETE FROM ordinary_widget_refresh WHERE delivery_id IN (SELECT delivery_id FROM ordinary_widget_refresh WHERE expires_at<=? ORDER BY expires_at,delivery_id LIMIT 256)")
            .bind(at).execute(&mut **tx).await?;
        // Expiry is a terminal failure only for ordinary_targets not yet accepted by a
        // provider. Running attempts retain their unknown outcome until receipt.
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryCount, sqlx::query("UPDATE ordinary_messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND delivery_mode='provider' AND provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id IN (SELECT delivery_id FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryAck, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=?,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id IN (SELECT delivery_id FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryStatus, sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=? WHERE status='provider_queued' AND provider_failed_count>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets outstanding WHERE outstanding.delivery_id=ordinary_messages.delivery_id AND outstanding.provider IN ('FCM','APNS','WNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait')))) AND delivery_id IN (SELECT delivery_id FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryDelete, sqlx::query("DELETE FROM ordinary_targets WHERE acked_at IS NOT NULL AND state!='running' AND delivery_id IN (SELECT delivery_id FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryPayload, sqlx::query("UPDATE ordinary_messages SET payload_blob=X'',payload_bytes=0 WHERE payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND acked_at IS NULL) AND delivery_id IN (SELECT delivery_id FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetention, sqlx::query("DELETE FROM ordinary_messages WHERE op_id IN (SELECT op_id FROM ordinary_messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running') ORDER BY dedupe_until,op_id LIMIT 256)").bind(at).execute(&mut **tx)).await?.rows_affected();
        Ok(removed as usize)
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.health.ensure()?;
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
        self.health.ensure()?;
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
            .phase(
                Path::Ack,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
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
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=? WHERE delivery_mode='provider' AND pull_owner=? AND delivery_id=? AND acked_at IS NULL")
                .bind(at).bind(device).bind(&id).execute(&mut *tx)).await?;
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
            items.push(json!({"delivery_id":id,"payload":payload}));
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
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
        self.health.ensure()?;
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
            .phase(
                Path::Ack,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=? WHERE delivery_mode='provider' AND pull_owner=? AND delivery_id=? AND acked_at IS NULL AND EXISTS(SELECT 1 FROM ordinary_device_routes WHERE ordinary_device_routes.device_key=ordinary_targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM ordinary_messages WHERE ordinary_messages.delivery_id=ordinary_targets.delivery_id AND expires_at>?) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=ordinary_targets.platform AND r.provider_token=ordinary_targets.provider_token AND ordinary_targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
        self.counters.ack_commits.fetch_add(1, Ordering::Relaxed);
        self.notify();
        Ok(removed)
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
        self.health.ensure()?;
        let _gate_hold = self.counters.profile.timer(Path::Claim, Phase::GateHold);
        record_duration(
            &self.counters.gate_wait_samples,
            &self.counters.gate_wait_total_us,
            &self.counters.gate_wait_max_us,
            gate_at.elapsed(),
        );
        self.counters.claim_queries.fetch_add(1, Ordering::Relaxed);
        self.counters.provider_claim_queries[match provider {
            "FCM" => 0,
            "APNS" => 1,
            "WNS" => 2,
            _ => return Err(KernelError::Invalid("provider".into())),
        }]
        .fetch_add(1, Ordering::Relaxed);
        self.counters.sql(5);
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(
                Path::Claim,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Claim,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
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
                    "SELECT next_attempt_at FROM ordinary_provider_cooldowns WHERE provider=?",
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
                    let row=self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.*,m.payload_blob,m.expires_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.delivery_mode='provider' AND d.retired_at IS NULL AND t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx)).await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get("delivery_id");
                let device: String = row.get("device_key");
                self.counters.sql(1);
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=? AND device_key=?").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
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
                    watch_alert_deadline: row.get("watch_alert_deadline_at"),
                });
                drop(_compute);
            }
        }
        let due:Option<i64>=self.counters.profile.sql(Path::Claim, Statement::ClaimNextDue, sqlx::query_scalar("SELECT MIN(next_attempt_at) FROM ordinary_targets WHERE delivery_mode='provider' AND provider=? AND state IN ('pending','retry_wait') AND acked_at IS NULL").bind(provider).fetch_one(&mut *tx)).await?;
        let retiring = false;
        let next_due = if retiring {
            Some(at)
        } else {
            due.map(|due| due.max(cooldown.unwrap_or(0)))
        };
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
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
        self.health.ensure()?;
        self.counters.sql(1);
        let current: i64 = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters.profile.sql(Path::Claim, Statement::Read, sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_mode='provider' AND t.delivery_id=? AND t.device_key=? AND t.state='running' AND t.attempt_id=? AND t.acked_at IS NULL AND m.expires_at>? AND d.retired_at IS NULL AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.owner_generation AND t.route_generation=? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&mut *profile_read_connection)).await
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
        self.health.ensure()?;
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
            .phase(
                Path::Receipt,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Receipt,
                Phase::Begin,
                profile_connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        #[cfg(test)]
        {
            let barrier = self.hooks.receipt_with_gate.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.pause().await;
            }
        }
        let state = if state == "retry_wait" && is_expired(ticket.expires_at, now()) {
            "permanent_failed"
        } else {
            state
        };
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='private' AND ? IN ('pending','retry_wait') THEN 'superseded_route' ELSE ? END,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO ordinary_provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=MAX(next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                let channel: String = sqlx::query_scalar(
                    "SELECT channel_id FROM ordinary_messages WHERE delivery_id=?",
                )
                .bind(&ticket.delivery_id)
                .fetch_one(&mut *tx)
                .await?;
                let channel = channel_storage_key(&channel)?;
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription, sqlx::query("UPDATE channel_subscriptions SET status='inactive',updated_at=CAST(strftime('%s','now') AS INTEGER)*1000 WHERE device_id=(SELECT device_id FROM devices WHERE device_key=?) AND channel_id=(SELECT channel_id FROM channels WHERE lower(hex(channel_id))=?) AND EXISTS(SELECT 1 FROM ordinary_device_routes WHERE device_key=? AND retired_at IS NULL AND platform=? AND provider=? AND provider_token=? AND route_generation=?)")
                    .bind(&ticket.device_key).bind(&channel).bind(&ticket.device_key).bind(&ticket.platform).bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE ordinary_messages SET provider_accepted_count=provider_accepted_count+?,provider_failed_count=provider_failed_count+? WHERE delivery_id=?").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
            self.refresh_provider_status_tx(&mut tx, &ticket.delivery_id, Path::Receipt)
                .await?;
            self.release_acked_tx(
                &mut tx,
                &ticket.device_key,
                &ticket.delivery_id,
                Path::Receipt,
            )
            .await?;
        }
        let commit_at = std::time::Instant::now();
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        profile_connection.restore().await?;
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

    pub(crate) async fn widget_refresh_ceiling(&self) -> Result<Option<i64>> {
        self.health.ensure()?;
        Ok(
            sqlx::query_scalar("SELECT MAX(coalesce_order) FROM ordinary_widget_refresh")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub(crate) async fn widget_refresh_after(
        &self,
        after: i64,
        ceiling: i64,
    ) -> Result<Option<crate::ordinary::widget_refresh::WidgetRefresh>> {
        self.health.ensure()?;
        let row = sqlx::query("SELECT delivery_id,channel_id,coalesce_order,accepted_at,expires_at FROM ordinary_widget_refresh WHERE coalesce_order>? AND coalesce_order<=? ORDER BY coalesce_order LIMIT 1")
            .bind(after).bind(ceiling)
            .fetch_optional(&self.pool).await?;
        row.map(|row| {
            let channel: Vec<u8> = row.try_get("channel_id")?;
            Ok(crate::ordinary::widget_refresh::WidgetRefresh {
                delivery_id: row.try_get("delivery_id")?,
                channel_id: channel
                    .try_into()
                    .map_err(|_| KernelError::Invalid("invalid Widget refresh channel".into()))?,
                coalesce_order: row.try_get("coalesce_order")?,
                accepted_at: row.try_get("accepted_at")?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .transpose()
    }

    pub(crate) async fn complete_widget_refresh(
        &self,
        delivery_id: &str,
        coalesce_order: i64,
    ) -> Result<bool> {
        let _gate = self.gate.lock().await;
        self.health.ensure()?;
        let mut connection = SqliteWriteConnection::acquire(&self.pool).await?;
        let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
        let changed = sqlx::query(
            "DELETE FROM ordinary_widget_refresh WHERE delivery_id=? AND coalesce_order=?",
        )
        .bind(delivery_id)
        .bind(coalesce_order)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 0;
        self.health.ensure()?;
        tx.commit().await?;
        connection.restore().await?;
        Ok(changed)
    }

    pub(crate) async fn widget_refresh_targets(
        &self,
        channel_id: [u8; 16],
        after: Option<&crate::ordinary::widget_refresh::WidgetRefreshCursor>,
        limit: usize,
    ) -> Result<Vec<crate::ordinary::widget_refresh::WidgetRefreshTarget>> {
        self.health.ensure()?;
        if !(1..=128).contains(&limit) {
            return Err(KernelError::Invalid(
                "Widget refresh page must contain 1..=128 targets".into(),
            ));
        }
        let rows = sqlx::query(
            "SELECT device_key,platform,token FROM (SELECT w.device_key,CASE lower(trim(w.platform)) WHEN 'ipados' THEN 'ios' ELSE lower(trim(w.platform)) END AS platform,w.token,ROW_NUMBER() OVER(PARTITION BY CASE lower(trim(w.platform)) WHEN 'ipados' THEN 'ios' ELSE lower(trim(w.platform)) END,w.token ORDER BY w.updated_at DESC,w.widget_kind ASC,w.family ASC,w.device_key ASC) AS rank FROM widget_push_subscriptions w JOIN devices d ON d.device_key=w.device_key JOIN channel_subscriptions s ON s.device_id=d.device_id WHERE s.channel_id=? AND s.status='active' AND lower(trim(w.platform)) IN ('ios','ipados','macos','watchos') AND w.widget_kind IN (?,?) AND (? IS NULL OR CASE lower(trim(w.platform)) WHEN 'ipados' THEN 'ios' ELSE lower(trim(w.platform)) END>? OR (CASE lower(trim(w.platform)) WHEN 'ipados' THEN 'ios' ELSE lower(trim(w.platform)) END=? AND w.token>?))) WHERE rank=1 ORDER BY platform,token LIMIT ?",
        )
        .bind(channel_id.as_slice())
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
        .bind(after.map(|a| a.platform.as_str()))
        .bind(after.map(|a| a.platform.as_str()))
        .bind(after.map(|a| a.platform.as_str()))
        .bind(after.map(|a| a.token.as_str()))
        .bind(limit as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                let platform: String = row.try_get("platform")?;
                Ok(crate::ordinary::widget_refresh::WidgetRefreshTarget {
                    device_key: row.try_get("device_key")?,
                    platform: platform
                        .parse()
                        .map_err(|_| KernelError::Invalid("invalid Widget platform".into()))?,
                    token: row.try_get("token")?,
                })
            })
            .collect()
    }

    // Called while Storage owns the shared gate: never acquire that gate here.
    pub(crate) async fn widget_refresh_job_order(&self, job_id: &str) -> Result<Option<i64>> {
        self.health.ensure()?;
        let pool = self.legacy_dispatch_pool.get().ok_or_else(|| {
            KernelError::Invalid(
                "ordinary Widget refresh requires the product dispatch pool".into(),
            )
        })?;
        Ok(
            sqlx::query_scalar(
                "SELECT coalesce_order FROM provider_dispatch_outbox WHERE job_id=?",
            )
            .bind(job_id)
            .fetch_optional(pool)
            .await?,
        )
    }

    pub async fn status(&self, op: &str) -> Result<Value> {
        self.health.ensure()?;
        let op = crate::ordinary::sender::op_id(op)?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.pool.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until,identity_state,channel_id,thing_id FROM ordinary_messages WHERE op_id=? AND dedupe_until>?").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
        if row.get::<String, _>("identity_state") == "legacy_unverifiable" {
            return Ok(
                json!({"op_id":row.get::<String,_>("op_id"),"status":"historical_unverifiable","identity_state":"legacy_unverifiable","model":"message","entity_id":row.get::<String,_>("message_id"),"channel_id":row.get::<String,_>("channel_id"),"thing_id":row.get::<Option<String>,_>("thing_id"),"accepted_at":row.get::<i64,_>("accepted_at"),"updated_at":row.get::<i64,_>("updated_at"),"expires_at":row.get::<i64,_>("dedupe_until"),"delivery_id":null,"delivery_expires_at":null,"dispatch_status":"not_attempted"}),
            );
        }
        Ok(
            json!({"op_id":row.get::<String,_>("op_id"),"status":row.get::<String,_>("status"),"model":"message","entity_id":row.get::<String,_>("message_id"),"accepted_at":row.get::<i64,_>("accepted_at"),"updated_at":row.get::<i64,_>("updated_at"),"expires_at":row.get::<i64,_>("dedupe_until")}),
        )
    }
    pub async fn target_status(&self, op: &str) -> Result<Value> {
        self.health.ensure()?;
        let rows = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Read, Phase::PoolAcquire, self.pool.acquire())
                .await?;
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM ordinary_messages m JOIN ordinary_targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&mut *profile_read_connection)).await
        }?;
        Ok(
            json!({"targets":rows.iter().map(|r|json!({"delivery_id":r.get::<String,_>("delivery_id"),"state":r.get::<Option<String>,_>("state"),"provider_status":r.get::<Option<i64>,_>("provider_status"),"acked_at":r.get::<Option<i64>,_>("acked_at")})).collect::<Vec<_>>()}),
        )
    }
}
pub(super) fn record_duration(
    samples: &AtomicU64,
    total: &AtomicU64,
    max: &AtomicU64,
    duration: Duration,
) {
    let us = duration.as_micros().min(u64::MAX as u128) as u64;
    samples.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(us, Ordering::Relaxed);
    max.fetch_max(us, Ordering::Relaxed);
}

pub(super) fn control_error(status: u16, code: &'static str, message: &str) -> KernelError {
    KernelError::Control {
        status,
        code,
        message: message.into(),
    }
}
pub(super) async fn verify_password_async(hash: String, value: String) -> Result<bool> {
    if crate::storage::types::channel_password_uses_current_scheme(&hash) {
        return Ok(crate::storage::types::verify_channel_password(&hash, &value).is_ok());
    }
    static PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(4)));
    let permit = PERMITS
        .clone()
        .try_acquire_owned()
        .map_err(|_| KernelError::Capacity)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::storage::types::verify_channel_password(&hash, &value).is_ok()
    })
    .await
    .map_err(|_| KernelError::Unavailable)
}
pub(super) fn channel_storage_key(raw: &str) -> Result<String> {
    let id = crate::value::ChannelId::parse(raw)
        .map_err(|_| KernelError::Invalid("channel id".into()))?
        .into_inner();
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn supported_platform(raw: &str) -> Result<crate::ordinary::types::Platform> {
    raw.parse()
        .map_err(|_| KernelError::Invalid("platform".into()))
}

/// The existing SQLite route-transition path sometimes writes through an
/// attached core database. This fixed choice addresses that same authority;
/// it does not create another control store or another transaction owner.
fn core_schema(schema: &'static str) -> &'static str {
    match schema {
        "main" => "main",
        "pushgo_core" => "pushgo_core",
        _ => unreachable!("internal SQLite core schema"),
    }
}
async fn product_ledger_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &'static str,
) -> std::result::Result<bool, sqlx::Error> {
    sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM {}.sqlite_master WHERE type='table' AND name='ordinary_targets')",core_schema(schema)))
        .fetch_one(&mut **tx).await
}

/// Transfer only the retained consumer. Every external receipt remains bound
/// to its original (delivery_id,device_key,attempt_id); no job is reissued under
/// the identity winner. Called before normal control deletes the losing row.
pub(crate) async fn sqlite_coalesce_ordinary(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &[u8],
    winner_id: &[u8],
    schema: &'static str,
) -> std::result::Result<(), sqlx::Error> {
    let schema = core_schema(schema);
    if !product_ledger_exists(tx, schema).await? {
        return Ok(());
    }
    let source: Option<String> = sqlx::query_scalar(&format!(
        "SELECT COALESCE(device_key,lower(hex(device_id))) FROM {schema}.devices WHERE device_id=?"
    ))
    .bind(source_id)
    .fetch_optional(&mut **tx)
    .await?;
    let winner: Option<String> = sqlx::query_scalar(&format!(
        "SELECT COALESCE(device_key,lower(hex(device_id))) FROM {schema}.devices WHERE device_id=?"
    ))
    .bind(winner_id)
    .fetch_optional(&mut **tx)
    .await?;
    let (Some(source), Some(winner)) = (source, winner) else {
        return Ok(());
    };
    let exhausted:bool=sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.ordinary_targets WHERE acked_at IS NULL AND delivery_epoch=9223372036854775807 AND (pull_owner=? OR (pull_owner=? AND delivery_id IN (SELECT delivery_id FROM {schema}.ordinary_targets WHERE pull_owner=? AND acked_at IS NULL))))"))
        .bind(&source).bind(&winner).bind(&source).fetch_one(&mut **tx).await?;
    if exhausted {
        return Err(sqlx::Error::Protocol(
            "ordinary private epoch exhausted".into(),
        ));
    }
    sqlx::query(&format!("UPDATE {schema}.ordinary_targets SET delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL WHERE pull_owner=? AND acked_at IS NULL AND delivery_id IN (SELECT delivery_id FROM {schema}.ordinary_targets WHERE pull_owner=? AND acked_at IS NULL)"))
        .bind(&winner).bind(&source).execute(&mut **tx).await?;
    sqlx::query(&format!("UPDATE {schema}.ordinary_targets SET pull_owner=?,owner_generation=-1,delivery_mode='provider',delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND acked_at IS NULL"))
        .bind(&winner).bind(&source).execute(&mut **tx).await?;
    sqlx::query(&format!("UPDATE {schema}.ordinary_messages SET status=CASE WHEN EXISTS(SELECT 1 FROM {schema}.ordinary_targets t WHERE t.delivery_id=ordinary_messages.delivery_id AND t.provider IN ('FCM','APNS','WNS') AND (t.state='running' OR (t.delivery_mode='provider' AND t.acked_at IS NULL AND t.state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE status='provider_queued' AND delivery_id IN (SELECT delivery_id FROM {schema}.ordinary_targets WHERE pull_owner=?)"))
        .bind(now()).bind(&winner).execute(&mut **tx).await?;
    Ok(())
}

/// A token tombstone belongs to this ledger's authorization history. The normal
/// devices row is still the only current route record. Bounded maintenance may
/// reclaim old obligations later; Pull and pre-send checks fence them at COMMIT.
pub(crate) async fn sqlite_retire_ordinary_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    platform: &str,
    token: &str,
) -> std::result::Result<(), sqlx::Error> {
    if !product_ledger_exists(tx, "main").await? {
        return Ok(());
    }
    let advanced=sqlx::query("UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1 AND control_epoch<9223372036854775807").execute(&mut **tx).await?.rows_affected();
    if advanced == 0 {
        return Err(sqlx::Error::Protocol(
            "ordinary control epoch exhausted".into(),
        ));
    }
    sqlx::query("INSERT INTO ordinary_retired_provider_tokens(platform,provider_token,control_epoch) SELECT ?,?,control_epoch FROM ordinary_ledger_usage WHERE singleton=1 ON CONFLICT(platform,provider_token) DO UPDATE SET control_epoch=excluded.control_epoch")
        .bind(platform).bind(token).execute(&mut **tx).await?;
    Ok(())
}

/// SQLite ABORT rolls back this statement (including its triggers), while the
/// surrounding control transaction remains usable. Preserve the product's
/// existing typed 409 route-capacity result instead of exposing a generic 500.
pub(crate) async fn sqlite_route_control_error(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device_key: &str,
    schema: &'static str,
    error: sqlx::Error,
) -> crate::storage::StoreError {
    if !error.as_database_error().is_some_and(|e| {
        e.message()
            .contains("ordinary route transition capacity exceeded")
    }) {
        return error.into();
    }
    let schema = core_schema(schema);
    let measured: std::result::Result<(i64,i64),sqlx::Error>=async {
        let pending:i64=sqlx::query_scalar(&format!("SELECT COUNT(DISTINCT t.delivery_id) FROM {schema}.ordinary_targets t JOIN {schema}.ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND m.expires_at>?"))
            .bind(device_key).bind(now()).fetch_one(&mut **tx).await?;
        let limits=sqlx::query(&format!("SELECT l.max_private_per_device,l.max_private-u.private_pending+COALESCE((SELECT pending FROM {schema}.ordinary_private_usage WHERE device_key=?),0) AS available FROM {schema}.ordinary_limits l JOIN {schema}.ordinary_ledger_usage u ON u.singleton=l.singleton"))
            .bind(device_key).fetch_one(&mut **tx).await?;
        Ok((pending,limits.get::<i64,_>("max_private_per_device").min(limits.get("available")).max(0)))
    }.await;
    match measured {
        Ok((pending, capacity)) => crate::storage::StoreError::RouteMigrationCapacityExceeded {
            pending: usize::try_from(pending).unwrap_or(usize::MAX),
            capacity: usize::try_from(capacity).unwrap_or(usize::MAX),
        },
        Err(_) => error.into(),
    }
}

#[cfg(test)]
mod sqlite_write_connection_tests {
    use super::SqliteWriteConnection;
    use sqlx::{Connection, SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions};
    use std::time::Duration;

    async fn normal_timeout(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sqlite_ordinary_write_timeout_is_scoped_to_borrowed_connection() {
        let directory = tempfile::tempdir().unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(directory.path().join("scoped-timeout.sqlite"))
                    .create_if_missing(true)
                    .busy_timeout(Duration::from_secs(30)),
            )
            .await
            .unwrap();
        assert_eq!(normal_timeout(&pool).await, 30_000);
        let mut connection = SqliteWriteConnection::acquire(&pool).await.unwrap();
        let scoped: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert_eq!(scoped, 3_000);
        let tx = connection.begin_with("BEGIN IMMEDIATE").await.unwrap();
        tx.commit().await.unwrap();
        connection.restore().await.unwrap();
        assert_eq!(normal_timeout(&pool).await, 30_000);

        // An early error follows the same Drop boundary as any failing C write.
        let mut connection = SqliteWriteConnection::acquire(&pool).await.unwrap();
        assert!(
            sqlx::query("SELECT * FROM absent_synthetic_table")
                .execute(&mut *connection)
                .await
                .is_err()
        );
        drop(connection);
        assert_eq!(normal_timeout(&pool).await, 30_000);

        // Cancel with an open transaction: neither the transaction nor its
        // connection-local setting may be returned to the normal control pool.
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let borrowed_pool = pool.clone();
        let task = tokio::spawn(async move {
            let mut connection = SqliteWriteConnection::acquire(&borrowed_pool)
                .await
                .unwrap();
            let tx = connection.begin_with("BEGIN IMMEDIATE").await.unwrap();
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
            tx.rollback().await.unwrap();
            connection.restore().await.unwrap();
        });
        waiting.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(normal_timeout(&pool).await, 30_000);
        pool.close().await;
    }
}
