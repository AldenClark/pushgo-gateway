//! MySQL ordinary-message ledger. One pinned physical session owns both
//! the advisory lock and all SQL; it is never replaced or reconnected.
//! MySQL marks text with a binary collation using BINARY_FLAG. SQLx's checked
//! String compatibility rejects that flag even for valid UTF8 VARCHAR/TEXT.
//! Text row reads use get_unchecked to retain String's UTF8 Decode validation;
//! scalar text projections CAST only their result metadata, never predicates,
//! storage collation or identity equality.
use crate::profiling::{Path, Phase, Statement};
use crate::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, Health, KernelError, OwnerLock, Result,
    Ticket, now, record_duration, verify_password_async,
};
use crate::types::generate_hex_id_128;
use serde_json::{Value, json};
use sqlx::{Connection, MySql, MySqlConnection, Row, Transaction};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::{Mutex, MutexGuard, Notify};
#[derive(Clone)]
pub struct MySqlDeliveryStore {
    pub(super) connection: Arc<Mutex<Option<MySqlConnection>>>,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 2],
    pub(super) health: Arc<Health>,
}
pub(super) struct MySqlGuard<'a>(MutexGuard<'a, Option<MySqlConnection>>);
impl Deref for MySqlGuard<'_> {
    type Target = MySqlConnection;
    fn deref(&self) -> &MySqlConnection {
        self.0.as_ref().expect("checked pinned connection")
    }
}
impl DerefMut for MySqlGuard<'_> {
    fn deref_mut(&mut self) -> &mut MySqlConnection {
        self.0.as_mut().expect("checked pinned connection")
    }
}
struct AdmissionWake(MySqlDeliveryStore);
impl Drop for AdmissionWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_id=? AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM retired_provider_tokens r JOIN targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";

pub(super) const EXPIRY_BATCH_SQL: &str = "SELECT delivery_id FROM messages WHERE has_payload=1 AND expires_at<=? ORDER BY expires_at,delivery_id LIMIT 256 FOR UPDATE";
pub(super) const RECOVERY_BATCH_SQL: &str = "SELECT DISTINCT delivery_id FROM targets WHERE state='running' AND delivery_id>? ORDER BY delivery_id LIMIT 256";
pub(super) const CLAIM_ONE_SQL: &str = "SELECT t.*,m.payload_blob,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE d.retired_at IS NULL AND t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1";

impl MySqlDeliveryStore {
    pub(super) async fn acquire(&self) -> Result<MySqlGuard<'_>> {
        let mut guard = self.connection.lock().await;
        self.health.ensure()?;
        let Some(connection) = guard.as_mut() else {
            return Err(KernelError::Unavailable);
        };
        let owned = sqlx::query_scalar::<_,Option<i64>>("SELECT IS_USED_LOCK(CONCAT('pushgo-c-dataset-',dataset_uuid))=CONNECTION_ID() FROM authority_metadata WHERE singleton=1")
            .fetch_one(&mut *connection).await;
        match owned {
            Ok(Some(1)) => Ok(MySqlGuard(guard)),
            Ok(_) => {
                self.health.fail("MySQL pinned dataset lock lost");
                Err(KernelError::Unavailable)
            }
            Err(error) => {
                self.health.fail("MySQL pinned owner connection lost");
                Err(error.into())
            }
        }
    }
    pub(super) async fn lock_usage(tx: &mut Transaction<'_, MySql>) -> Result<()> {
        sqlx::query("SELECT singleton FROM ledger_usage WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
        Ok(())
    }
    /// All callers hold ledger_usage FOR UPDATE. This reads exactly one
    /// immutable accepted fanout (at most 32), never the retained ledger.
    /// Profiling callers record this four-SQL bundle as one Usage sample;
    /// sample count is a helper invocation count, not a SQL statement count.
    pub(super) async fn reconcile_message_tx(
        tx: &mut Transaction<'_, MySql>,
        id: &str,
    ) -> Result<()> {
        let row = sqlx::query("SELECT pending_targets,usage_payload_bytes,payload_bytes FROM messages WHERE delivery_id=?")
            .bind(id).fetch_optional(&mut **tx).await?;
        let Some(row) = row else { return Ok(()) };
        let old: i64 = row.get("pending_targets");
        let old_bytes: i64 = row.get("usage_payload_bytes");
        let bytes: i64 = row.get("payload_bytes");
        let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=? AND acked_at IS NULL AND state IN ('pending','running','retry_wait')")
            .bind(id).fetch_one(&mut **tx).await?;
        sqlx::query("UPDATE ledger_usage SET messages=messages+?,targets=targets+?,bytes=bytes+? WHERE singleton=1")
            .bind(i64::from(pending>0)-i64::from(old>0)).bind(pending-old).bind(bytes-old_bytes).execute(&mut **tx).await?;
        sqlx::query(
            "UPDATE messages SET pending_targets=?,usage_payload_bytes=? WHERE delivery_id=?",
        )
        .bind(pending)
        .bind(bytes)
        .bind(id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
    async fn delete_message_tx(tx: &mut Transaction<'_, MySql>, id: &str) -> Result<()> {
        sqlx::query("UPDATE ledger_usage u JOIN messages m ON m.delivery_id=? SET u.messages=u.messages-(m.pending_targets>0),u.targets=u.targets-m.pending_targets,u.bytes=u.bytes-m.usage_payload_bytes WHERE u.singleton=1")
            .bind(id).execute(&mut **tx).await?;
        // FK cascade removes targets; application owns the counter delta above.
        sqlx::query("DELETE FROM messages WHERE delivery_id=?")
            .bind(id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    async fn refresh_status_tx(tx: &mut Transaction<'_, MySql>, id: &str, at: i64) -> Result<()> {
        sqlx::query("UPDATE messages SET status=CASE WHEN pending_targets>0 OR EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued'")
            .bind(at).bind(id).execute(&mut **tx).await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
    }
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

        let mut connection = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            MySqlConnection::connect(db_url),
        )
        .await
        .map_err(|_| {
            KernelError::Database(sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "MySQL owner connection timed out",
            )))
        })??;
        // DATABASE() is server canonical, independent of URL/user/parameter aliases.
        // The short bootstrap lock serializes metadata creation; the retained UUID
        // lock owns this dataset for the entire pinned session lifetime.
        let database: Option<String> = sqlx::query_scalar("SELECT DATABASE()")
            .fetch_one(&mut connection)
            .await?;
        let database = database
            .filter(|v| !v.is_empty())
            .ok_or_else(|| KernelError::Invalid("a dedicated MySQL database is required".into()))?;
        let bootstrap: String = sqlx::query_scalar(
            "SELECT CAST(CONCAT('pushgo-c-bootstrap-',SHA2(?,256)) AS CHAR CHARACTER SET utf8mb4)",
        )
        .bind(database.to_lowercase())
        .fetch_one(&mut connection)
        .await?;
        let bootstrap = &bootstrap[..64];
        let owned: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
            .bind(bootstrap)
            .fetch_one(&mut connection)
            .await?;
        if owned != Some(1) {
            return Err(KernelError::OwnerContention);
        }
        sqlx::raw_sql("SET SESSION innodb_lock_wait_timeout=3; SET SESSION lock_wait_timeout=3; SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED; SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'; CREATE TABLE IF NOT EXISTS authority_metadata(singleton BIGINT PRIMARY KEY CHECK(singleton=1),dataset_uuid VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,schema_version BIGINT NOT NULL) ENGINE=InnoDB")
            .execute(&mut connection).await?;
        let hex = generate_hex_id_128();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        sqlx::query("INSERT INTO authority_metadata(singleton,dataset_uuid,schema_version) VALUES(1,?,1) ON DUPLICATE KEY UPDATE singleton=singleton")
            .bind(uuid).execute(&mut connection).await?;
        let (uuid, version): (String, i64) = sqlx::query_as(
            "SELECT CAST(dataset_uuid AS CHAR CHARACTER SET utf8mb4),schema_version FROM authority_metadata WHERE singleton=1",
        )
        .fetch_one(&mut connection)
        .await?;
        if version != 1
            || uuid.len() != 36
            || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(KernelError::Invalid(
                "unsupported MySQL authority metadata".into(),
            ));
        }
        let owned: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
            .bind(format!("pushgo-c-dataset-{uuid}"))
            .fetch_one(&mut connection)
            .await?;
        if owned != Some(1) {
            return Err(KernelError::OwnerContention);
        }
        let _: Option<i64> = sqlx::query_scalar("SELECT RELEASE_LOCK(?)")
            .bind(bootstrap)
            .fetch_one(&mut connection)
            .await?;
        // A successful server commit must represent the durable InnoDB commit.
        let durability: (i64, i64) =
            sqlx::query_as("SELECT CAST(@@GLOBAL.innodb_flush_log_at_trx_commit AS SIGNED),CAST(@@GLOBAL.sync_binlog AS SIGNED)")
                .fetch_one(&mut connection)
                .await?;
        if durability.0 != 1 || durability.1 != 1 {
            return Err(KernelError::Invalid(
                "MySQL requires innodb_flush_log_at_trx_commit=1 and sync_binlog=1".into(),
            ));
        }
        let owner_path = mysql_owner_path(&uuid)?;
        let owner = OwnerLock::acquire(owner_path)?;
        let store = Self {
            connection: Arc::new(Mutex::new(Some(connection))),
            gate: Arc::new(Mutex::new(())),
            config,
            counters: Arc::new(Counters::default()),
            wake: [Arc::new(Notify::new()), Arc::new(Notify::new())],
            health: Arc::new(Health::default()),
        };
        if let Err(error) = store.initialize().await {
            store.close().await;
            owner.release();
            return Err(error);
        }
        Ok((store, owner))
    }
    pub(super) async fn close(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            let _ = connection.close().await;
        }
    }
    /// A same-version access-path repair, after both owner locks and before
    /// any recovery/business transaction. CREATE TABLE IF NOT EXISTS cannot
    /// update an accepted C5 dataset's existing four-column index.
    async fn ensure_due_index(connection: &mut MySqlConnection) -> Result<()> {
        let rows = sqlx::query("SELECT CAST(SEQ_IN_INDEX AS SIGNED) AS seq,COLUMN_NAME,CAST(SUB_PART AS SIGNED) AS sub_part,COLLATION,CAST(NON_UNIQUE AS SIGNED) AS non_unique,INDEX_TYPE,IS_VISIBLE,EXPRESSION FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='targets' AND INDEX_NAME='targets_due' ORDER BY SEQ_IN_INDEX LIMIT 6")
            .fetch_all(&mut *connection).await?;
        let expected = [
            "provider",
            "state",
            "next_attempt_at",
            "delivery_id",
            "device_key",
        ];
        let mut known = matches!(rows.len(), 4 | 5);
        for (index, row) in rows.iter().enumerate() {
            // Native metadata text can carry BINARY_FLAG. The unchecked text
            // getter still performs UTF8 Decode, as for the ordinary rows.
            known &= row.try_get::<i64, _>("seq")? == index as i64 + 1
                && row
                    .try_get_unchecked::<Option<String>, _>("COLUMN_NAME")?
                    .as_deref()
                    == expected.get(index).copied()
                && row.try_get::<Option<i64>, _>("sub_part")?.is_none()
                && row
                    .try_get_unchecked::<Option<String>, _>("COLLATION")?
                    .as_deref()
                    == Some("A")
                && row.try_get::<i64, _>("non_unique")? == 1
                && row.try_get_unchecked::<String, _>("INDEX_TYPE")? == "BTREE"
                && row.try_get_unchecked::<String, _>("IS_VISIBLE")? == "YES"
                && row
                    .try_get_unchecked::<Option<String>, _>("EXPRESSION")?
                    .is_none();
        }
        if !known {
            return Err(KernelError::Invalid(
                "unsupported MySQL targets_due definition".into(),
            ));
        }
        if rows.len() == 4 {
            // One atomic native DDL, outside any application transaction. On
            // timeout/error open() closes the pinned session and never returns
            // a READY store; accepted identity and running work remain intact.
            sqlx::query("ALTER TABLE targets DROP INDEX targets_due, ADD INDEX targets_due(provider,state,next_attempt_at,delivery_id,device_key)")
                .execute(&mut *connection).await?;
        }
        Ok(())
    }
    async fn initialize(&self) -> Result<()> {
        let mut connection = self.acquire().await?;
        sqlx::raw_sql(include_str!("mysql_schema.sql"))
            .execute(&mut *connection)
            .await?;
        Self::ensure_due_index(&mut connection).await?;
        let mut tx = connection.begin().await?;
        Self::lock_usage(&mut tx).await?;
        // Recover in one startup transaction, but hold only one bounded batch
        // of identities even if the previous owner used a larger safety cap.
        let mut cursor = String::new();
        loop {
            let ids: Vec<String> = sqlx::query(RECOVERY_BATCH_SQL)
                .bind(&cursor)
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|row| row.try_get_unchecked::<String, _>(0))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if ids.is_empty() {
                break;
            }
            for id in &ids {
                sqlx::query("DELETE FROM targets WHERE delivery_id=? AND state='running' AND acked_at IS NOT NULL")
                    .bind(id).execute(&mut *tx).await?;
                sqlx::query("UPDATE targets SET state='retry_wait',next_attempt_at=? WHERE delivery_id=? AND state='running'")
                    .bind(now()).bind(id).execute(&mut *tx).await?;
                self.counters
                    .profile
                    .sql(
                        Path::Maintenance,
                        Statement::Usage,
                        Self::reconcile_message_tx(&mut tx, id),
                    )
                    .await?;
                Self::refresh_status_tx(&mut tx, id, now()).await?;
            }
            cursor = ids.last().unwrap().clone();
        }
        self.health.ensure()?;
        tx.commit().await?;
        drop(connection);
        self.maintenance().await?;
        Ok(())
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
        self.health.ensure()?;
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
            .phase(Path::Accept, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Accept, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let auth: Option<String> = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Auth,
                sqlx::query_scalar("SELECT CAST(password_hash AS CHAR CHARACTER SET utf8mb4) FROM channels WHERE channel_id=?")
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
            if row.get_unchecked::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get_unchecked::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get_unchecked("delivery_id"),message_id:row.get_unchecked("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:"provider_queued"})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        if let Some(id) = sqlx::query_scalar::<_,String>("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM messages WHERE op_id=? AND dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')")
            .bind(&request.op_id).bind(at).fetch_optional(&mut *tx).await? {
            Self::delete_message_tx(&mut tx,&id).await?;
        }
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
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at) SELECT ?,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ledger_usage WHERE singleton=1),d.platform,d.provider,d.provider_token,d.route_generation,?,'pending',? FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&delivery_id).bind(at).bind(at).bind(&request.channel_id).execute(&mut *tx)).await?;
        }
        self.counters
            .profile
            .sql(
                Path::Accept,
                Statement::Usage,
                Self::reconcile_message_tx(&mut tx, &delivery_id),
            )
            .await?;
        let commit_at = std::time::Instant::now();
        self.health.ensure()?;
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
    pub(super) async fn release_acked_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        device: &str,
        id: &str,
        profile_path: Path,
    ) -> Result<()> {
        let _ = device;
        self.counters
            .profile
            .sql(
                profile_path,
                Statement::Usage,
                Self::reconcile_message_tx(tx, id),
            )
            .await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseStatus,
            sqlx::query("UPDATE messages SET status='sent',updated_at=? WHERE delivery_id=? AND status='provider_queued' AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND (acked_at IS NULL OR state='running'))")
                .bind(now()).bind(id).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget,
            sqlx::query("DELETE FROM targets WHERE delivery_id=? AND acked_at IS NOT NULL AND state!='running'")
                .bind(id).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload,
            sqlx::query("UPDATE messages SET payload_blob=X'',payload_bytes=0 WHERE delivery_id=? AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL)")
                .bind(id).execute(&mut **tx)).await?;
        self.counters
            .profile
            .sql(
                profile_path,
                Statement::Usage,
                Self::reconcile_message_tx(tx, id),
            )
            .await?;
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
            .phase(Path::Maintenance, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Maintenance, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let removed = self.maintain_tx(&mut tx, now()).await?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Maintenance, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        Ok(removed)
    }
    pub(super) async fn maintain_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        at: i64,
    ) -> Result<usize> {
        self.retire_token_targets_tx(tx).await?;
        let retired: Vec<String> = sqlx::query_scalar("SELECT CAST(device_key AS CHAR CHARACTER SET utf8mb4) FROM devices WHERE retired_at IS NOT NULL AND coalesced_to IS NULL ORDER BY retired_at,device_key LIMIT 256").fetch_all(&mut **tx).await?;
        let mut remaining = 256;
        let mut subscriptions_remaining = 256;
        for key in retired {
            let removed = sqlx::query(
                "DELETE FROM channel_subscriptions WHERE device_key=? ORDER BY channel_id LIMIT ?",
            )
            .bind(&key)
            .bind(subscriptions_remaining as i64)
            .execute(&mut **tx)
            .await?
            .rows_affected() as usize;
            subscriptions_remaining -= removed;
            if remaining > 0 {
                remaining -= self.retire_targets_tx(tx, &key, at, remaining).await?;
            }
            sqlx::query("DELETE FROM devices WHERE device_key=? AND retired_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.device_key=devices.device_key AND (acked_at IS NULL OR state='running')) AND NOT EXISTS(SELECT 1 FROM channel_subscriptions WHERE channel_subscriptions.device_key=devices.device_key)")
                .bind(&key).execute(&mut **tx).await?;
        }
        let coalesced: Vec<String> = sqlx::query_scalar("SELECT CAST(d.device_key AS CHAR CHARACTER SET utf8mb4) FROM devices d WHERE d.coalesced_to IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets t WHERE t.device_key=d.device_key OR t.pull_owner=d.device_key) LIMIT 256")
            .fetch_all(&mut **tx).await?;
        for key in coalesced {
            sqlx::query("DELETE FROM devices WHERE device_key=?")
                .bind(key)
                .execute(&mut **tx)
                .await?;
        }
        sqlx::query(
            "DELETE FROM registration_aliases WHERE expires_at<? ORDER BY expires_at LIMIT 256",
        )
        .bind(at)
        .execute(&mut **tx)
        .await?;
        // One captured keyset owns all expiry mutations, including equal-TTL rows.
        let expiring: Vec<String> = sqlx::query(EXPIRY_BATCH_SQL)
            .bind(at)
            .fetch_all(&mut **tx)
            .await?
            .iter()
            .map(|row| row.try_get_unchecked::<String, _>(0))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in expiring {
            sqlx::query("UPDATE messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id=?")
                .bind(&id).execute(&mut **tx).await?;
            sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id=?")
                .bind(at).bind(&id).execute(&mut **tx).await?;
            self.counters
                .profile
                .sql(
                    Path::Maintenance,
                    Statement::Usage,
                    Self::reconcile_message_tx(tx, &id),
                )
                .await?;
            sqlx::query("UPDATE messages SET status=CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=? WHERE delivery_id=? AND status='provider_queued' AND provider_failed_count>0 AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')")
                .bind(at).bind(&id).execute(&mut **tx).await?;
            self.release_acked_tx(tx, "", &id, Path::Maintenance)
                .await?;
        }
        let retained: Vec<String> = sqlx::query_scalar("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') ORDER BY dedupe_until,delivery_id LIMIT 256")
            .bind(at).fetch_all(&mut **tx).await?;
        for id in &retained {
            Self::delete_message_tx(tx, id).await?;
        }
        Ok(retained.len())
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.counters.sql(1);
        let rows = if let Some(id) = delivery {
            {
                let mut profile_read_connection = self
                    .counters
                    .profile
                    .phase(Path::Read, Phase::PoolAcquire, self.acquire())
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
                    .phase(Path::Read, Phase::PoolAcquire, self.acquire())
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
            items.push(json!({"delivery_id":row.get_unchecked::<String,_>("delivery_id"),"payload":payload}));
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
            .phase(Path::Ack, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Ack, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
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
            let id: String = row.get_unchecked("delivery_id");
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            self.counters.sql(1);
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL")
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
            .phase(Path::Ack, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Ack, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL AND EXISTS(SELECT 1 FROM devices WHERE devices.device_key=targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM messages WHERE messages.delivery_id=targets.delivery_id AND expires_at>?) AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=targets.platform AND r.provider_token=targets.provider_token AND targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
        }
        self.health.ensure()?;
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
        self.counters.provider_claim_queries[usize::from(provider == "APNS")]
            .fetch_add(1, Ordering::Relaxed);
        self.counters.sql(5);
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Claim, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Claim, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
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
                    let row = self
                        .counters
                        .profile
                        .sql(
                            Path::Claim,
                            Statement::ClaimSelect,
                            sqlx::query(CLAIM_ONE_SQL)
                                .bind(provider)
                                .bind(class)
                                .bind(at)
                                .bind(at)
                                .fetch_optional(&mut *tx),
                        )
                        .await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get_unchecked("delivery_id");
                let device: String = row.get_unchecked("device_key");
                self.counters.sql(1);
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=? AND device_key=?").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
                let _compute = self.counters.profile.timer(Path::Claim, Phase::Compute);
                tickets.push(Ticket {
                    delivery_id: delivery,
                    device_key: device,
                    platform: row.get_unchecked("platform"),
                    provider: row.get_unchecked("provider"),
                    token: row.get_unchecked("provider_token"),
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
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        drop(_gate);
        drop(_gate_hold);
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
                .phase(Path::Claim, Phase::PoolAcquire, self.acquire())
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
            .phase(Path::Receipt, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Receipt, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let state = if state == "retry_wait" && ticket.expires_at <= now() {
            "permanent_failed"
        } else {
            state
        };
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE targets SET state=?,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON DUPLICATE KEY UPDATE next_attempt_at=GREATEST(provider_cooldowns.next_attempt_at,VALUES(next_attempt_at))").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=? AND channel_id=(SELECT channel_id FROM messages WHERE delivery_id=?) AND EXISTS(SELECT 1 FROM devices WHERE device_key=? AND retired_at IS NULL AND platform=? AND provider=? AND provider_token=? AND route_generation=?)")
                    .bind(&ticket.device_key).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(&ticket.platform).bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE messages SET provider_accepted_count=provider_accepted_count+?,provider_failed_count=provider_failed_count+? WHERE delivery_id=?").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
            self.counters
                .profile
                .sql(
                    Path::Receipt,
                    Statement::Usage,
                    Self::reconcile_message_tx(&mut tx, &ticket.delivery_id),
                )
                .await?;
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
        self.health.ensure()?;
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
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM messages WHERE op_id=? AND dedupe_until>?").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
        Ok(
            json!({"op_id":row.get_unchecked::<String,_>("op_id"),"status":row.get_unchecked::<String,_>("status"),"model":"message","entity_id":row.get_unchecked::<String,_>("message_id"),"accepted_at":row.get::<i64,_>("accepted_at"),"updated_at":row.get::<i64,_>("updated_at"),"expires_at":row.get::<i64,_>("dedupe_until")}),
        )
    }
    pub async fn target_status(&self, op: &str) -> Result<Value> {
        let rows = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Read, Phase::PoolAcquire, self.acquire())
                .await?;
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&mut *profile_read_connection)).await
        }?;
        Ok(
            json!({"targets":rows.iter().map(|r|json!({"delivery_id":r.get_unchecked::<String,_>("delivery_id"),"state":r.get_unchecked::<Option<String>,_>("state"),"provider_status":r.get::<Option<i64>,_>("provider_status"),"acked_at":r.get::<Option<i64>,_>("acked_at")})).collect::<Vec<_>>()}),
        )
    }
    pub(super) async fn retire_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        key: &str,
        at: i64,
        limit: usize,
    ) -> Result<usize> {
        let ids=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM targets WHERE pull_owner=? AND acked_at IS NULL ORDER BY accepted_at,delivery_id LIMIT ?").bind(key).bind(limit as i64).fetch_all(&mut **tx)).await?;
        for row in &ids {
            let id: String = row.get_unchecked("delivery_id");
            let original: String = row.get_unchecked("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE device_key=? AND delivery_id=? AND acked_at IS NULL").bind(at).bind(&original).bind(&id).execute(&mut **tx)).await?;
            self.counters
                .profile
                .sql(
                    Path::Maintenance,
                    Statement::Usage,
                    Self::reconcile_message_tx(tx, &id),
                )
                .await?;
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued' AND pending_targets=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(at).bind(&id).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &original, &id, Path::Maintenance)
                .await?;
        }
        Ok(ids.len())
    }
    pub(super) async fn retire_token_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
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
            let id: String = row.get_unchecked("delivery_id");
            let key: String = row.get_unchecked("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=? AND device_key=? AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        let markers: Vec<i64> = sqlx::query_scalar("SELECT r.marker_id FROM retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM targets t WHERE t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256").fetch_all(&mut **tx).await?;
        for marker in markers {
            sqlx::query("DELETE FROM retired_provider_tokens WHERE marker_id=?")
                .bind(marker)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

// The fixture already uses Unix process/signal lifecycle. Never substitute a
// per-user temporary directory for this machine-wide owner identity.
#[cfg(unix)]
fn mysql_owner_path(uuid: &str) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from("/tmp").join(format!("pushgo-c-mysql-{uuid}.owner")))
}
#[cfg(not(unix))]
fn mysql_owner_path(_: &str) -> Result<std::path::PathBuf> {
    Err(KernelError::Invalid(
        "MySQL candidate requires a Unix machine-wide owner lock".into(),
    ))
}
