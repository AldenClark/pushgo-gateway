//! MySQL ordinary-message ledger in the normal Storage database lifecycle.
//! The product owns and fences the separate fixed advisory-lock session;
//! transactions use the existing bounded pool and canonical control rows.
//! MySQL marks text with a binary collation using BINARY_FLAG. SQLx's checked
//! String compatibility rejects that flag even for valid UTF8 VARCHAR/TEXT.
//! Text row reads use get_unchecked to retain String's UTF8 Decode validation;
//! scalar text projections CAST only their result metadata, never predicates,
//! storage collation or identity equality.
use crate::ordinary::profiling::{Path, Phase, Statement};
use crate::ordinary::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, Health, KernelError, Result, Ticket,
    now, record_duration, verify_password_async,
};
use crate::ordinary::types::generate_hex_id_128;
use serde_json::{Value, json};
use sqlx::{Connection, MySql, MySqlConnection, MySqlPool, Row, Transaction};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::{Mutex, MutexGuard, Notify};
#[derive(Clone)]
pub struct MySqlDeliveryStore {
    pub(super) connection: Arc<Mutex<Option<sqlx::pool::PoolConnection<MySql>>>>,
    #[cfg(test)]
    pub(super) pool: MySqlPool,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 3],
    pub(super) health: Arc<Health>,
}
pub(super) struct MySqlDataGuard<'a>(MutexGuard<'a, Option<sqlx::pool::PoolConnection<MySql>>>);
impl Deref for MySqlDataGuard<'_> {
    type Target = MySqlConnection;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("checked ordinary data session")
    }
}
impl DerefMut for MySqlDataGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("checked ordinary data session")
    }
}

struct AdmissionWake(MySqlDeliveryStore);
impl Drop for AdmissionWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='provider' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_id=? AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM ordinary_retired_provider_tokens r JOIN ordinary_targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.delivery_mode='provider' AND t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";

pub(super) const EXPIRY_BATCH_SQL: &str = "SELECT delivery_id FROM ordinary_messages WHERE has_payload=1 AND expires_at<=? ORDER BY expires_at,delivery_id LIMIT 256 FOR UPDATE";
pub(super) const RECOVERY_BATCH_SQL: &str = "SELECT DISTINCT delivery_id FROM ordinary_targets WHERE state='running' AND delivery_id>? ORDER BY delivery_id LIMIT 256";
// Preserve the due-index order and stop after the first eligible target. Without
// both native directives MySQL can scan historical targets through another join
// order and materialize/sort the entire pending class despite LIMIT 1.
pub(super) const CLAIM_ONE_SQL: &str = "SELECT STRAIGHT_JOIN t.*,m.payload_blob,m.expires_at FROM ordinary_targets t FORCE INDEX(targets_due) JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE d.retired_at IS NULL AND t.delivery_mode='provider' AND t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1";

// MIN over both state ranges scans the pending backlog on MySQL. Each ordered
// range needs only its first matching row; residual mode/ACK filters still apply.
pub(super) const NEXT_DUE_SQL: &str = "SELECT MIN(next_attempt_at) FROM ((SELECT next_attempt_at FROM ordinary_targets FORCE INDEX(targets_due) WHERE provider=? AND delivery_mode='provider' AND state='pending' AND acked_at IS NULL ORDER BY next_attempt_at,delivery_id,device_key LIMIT 1) UNION ALL (SELECT next_attempt_at FROM ordinary_targets FORCE INDEX(targets_due) WHERE provider=? AND delivery_mode='provider' AND state='retry_wait' AND acked_at IS NULL ORDER BY next_attempt_at,delivery_id,device_key LIMIT 1)) AS first_due";

impl MySqlDeliveryStore {
    pub(super) async fn acquire(&self) -> Result<MySqlDataGuard<'_>> {
        self.health.ensure()?;
        let connection = self.connection.lock().await;
        self.health.ensure()?;
        if connection.is_none() {
            return Err(KernelError::Unavailable);
        }
        // No pool acquisition or reconnect occurs after startup. The product's
        // separate fixed owner session still owns the dataset lock.
        Ok(MySqlDataGuard(connection))
    }
    pub(super) async fn commit(&self, tx: Transaction<'_, MySql>) -> Result<()> {
        self.health.ensure()?;
        match tx.commit().await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.health
                    .fail("MySQL ordinary COMMIT failed or result unknown");
                Err(error.into())
            }
        }
    }
    pub(super) async fn lock_usage(tx: &mut Transaction<'_, MySql>) -> Result<()> {
        sqlx::query("SELECT singleton FROM ordinary_ledger_usage WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
        Ok(())
    }
    /// All callers hold ledger_usage FOR UPDATE. This reads one delivery's
    /// accepted targets, bounded by the admission target budget, not history.
    /// Profiling callers record this four-SQL bundle as one Usage sample;
    /// sample count is a helper invocation count, not a SQL statement count.
    pub(super) async fn reconcile_message_tx(
        tx: &mut Transaction<'_, MySql>,
        id: &str,
    ) -> Result<()> {
        let row = sqlx::query("SELECT pending_targets,usage_payload_bytes,payload_bytes FROM ordinary_messages WHERE delivery_id=?")
            .bind(id).fetch_optional(&mut **tx).await?;
        let Some(row) = row else { return Ok(()) };
        let old: i64 = row.get("pending_targets");
        let old_bytes: i64 = row.get("usage_payload_bytes");
        let bytes: i64 = row.get("payload_bytes");
        let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE delivery_id=? AND acked_at IS NULL AND (delivery_mode='private' OR state IN ('pending','running','retry_wait'))")
            .bind(id).fetch_one(&mut **tx).await?;
        sqlx::query("UPDATE ordinary_ledger_usage SET messages=messages+?,targets=targets+?,bytes=bytes+? WHERE singleton=1")
            .bind(i64::from(pending>0)-i64::from(old>0)).bind(pending-old).bind(bytes-old_bytes).execute(&mut **tx).await?;
        sqlx::query(
            "UPDATE ordinary_messages SET pending_targets=?,usage_payload_bytes=? WHERE delivery_id=?",
        )
        .bind(pending)
        .bind(bytes)
        .bind(id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
    async fn delete_message_tx(tx: &mut Transaction<'_, MySql>, id: &str) -> Result<()> {
        let before = Self::private_owners_for_message_tx(tx, id).await?;
        sqlx::query("UPDATE ordinary_ledger_usage u JOIN ordinary_messages m ON m.delivery_id=? SET u.messages=u.messages-(m.pending_targets>0),u.targets=u.targets-m.pending_targets,u.bytes=u.bytes-m.usage_payload_bytes WHERE u.singleton=1")
            .bind(id).execute(&mut **tx).await?;
        // FK cascade removes targets; application owns the counter delta above.
        sqlx::query("DELETE FROM ordinary_messages WHERE delivery_id=?")
            .bind(id)
            .execute(&mut **tx)
            .await?;
        Self::reconcile_private_message_tx(tx, id, &before).await?;
        Ok(())
    }
    pub(super) async fn refresh_status_tx(
        tx: &mut Transaction<'_, MySql>,
        id: &str,
        at: i64,
    ) -> Result<()> {
        sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND provider IN ('FCM','APNS','WNS') AND (state='running' OR (delivery_mode='provider' AND acked_at IS NULL AND state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued'")
            .bind(at).bind(id).execute(&mut **tx).await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
    }
    /// Shares the normal product database and mutation gate. The product
    /// lifecycle owns and fences the independent dataset-lock session.
    pub(crate) async fn from_product(
        pool: MySqlPool,
        gate: Arc<Mutex<()>>,
        config: Config,
        health: Arc<Health>,
        counters: Arc<Counters>,
    ) -> Result<Self> {
        if pool.options().get_max_connections() < 2 {
            return Err(KernelError::Invalid("normal MySQL pool requires a control slot in addition to the ordinary data session".into()));
        }
        let mut connection = pool.acquire().await?;
        // A scoped C data session must never return its settings to another
        // product user, including cancellation or partial initialization.
        connection.close_on_drop();
        sqlx::query("SET SESSION innodb_lock_wait_timeout=3, lock_wait_timeout=3, sql_mode='STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'")
            .execute(&mut *connection).await?;
        let store = Self {
            connection: Arc::new(Mutex::new(Some(connection))),
            #[cfg(test)]
            pool,
            gate,
            config,
            health,
            counters,
            wake: std::array::from_fn(|_| Arc::new(Notify::new())),
        };
        store.ensure_no_legacy_ordinary().await?;
        store.initialize().await?;
        Ok(store)
    }

    async fn ensure_no_legacy_ordinary(&self) -> Result<()> {
        let mut connection = self.acquire().await?;
        let at = now();
        let legacy: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE model='message' AND expires_at>?) OR EXISTS(SELECT 1 FROM semantic_id_registry WHERE REGEXP_LIKE(dedupe_key,'^semantic:[^:]+:message:','c') AND (expires_at IS NULL OR expires_at>?)) OR EXISTS(SELECT 1 FROM dispatch_op_dedupe WHERE REGEXP_LIKE(dedupe_key,'^op:[^:]+:message:','c') AND (expires_at IS NULL OR expires_at>?))")
            .bind(at).bind(at).bind(at).fetch_one(&mut *connection).await?;
        if legacy != 0 {
            return Err(legacy_cutover_error());
        }
        // These are fixed backend-native keysets, not a SQL dialect layer or a
        // loaded history window. The classifier inspects known envelope fields.
        for query in [
            "SELECT dedupe_key AS cursor_key,payload_blob FROM dispatch_submission WHERE dedupe_key>? AND expires_at>? ORDER BY dedupe_key LIMIT 64",
            "SELECT job_id AS cursor_key,payload_blob FROM provider_dispatch_outbox WHERE job_id>? AND expires_at>? AND state IN ('preparing','pending','retry_wait','leased') ORDER BY job_id LIMIT 64",
            "SELECT p.delivery_id AS cursor_key,p.payload_blob FROM private_payloads p WHERE p.delivery_id>? AND p.expires_at>? AND EXISTS(SELECT 1 FROM private_outbox o WHERE o.delivery_id=p.delivery_id AND o.status<>'acked') ORDER BY p.delivery_id LIMIT 64",
        ] {
            let mut cursor = String::new();
            loop {
                let rows = sqlx::query(query)
                    .bind(&cursor)
                    .bind(at)
                    .fetch_all(&mut *connection)
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in &rows {
                    let payload: Vec<u8> = row.try_get("payload_blob")?;
                    if crate::ordinary::legacy::payload_is_ordinary(&payload)? {
                        return Err(legacy_cutover_error());
                    }
                    cursor = row.try_get_unchecked("cursor_key")?;
                }
            }
        }
        let mut device_cursor = Vec::<u8>::new();
        let mut delivery_cursor = String::new();
        let mut first = true;
        loop {
            let rows = sqlx::query("SELECT q.device_id,q.delivery_id,CASE WHEN OCTET_LENGTH(q.payload_blob)>0 THEN q.payload_blob ELSE p.payload_blob END AS payload_blob FROM provider_pull_queue q LEFT JOIN private_payloads p ON p.delivery_id=q.delivery_id WHERE q.expires_at>? AND (?=1 OR q.device_id>? OR (q.device_id=? AND q.delivery_id>?)) ORDER BY q.device_id,q.delivery_id LIMIT 64")
                .bind(at).bind(i64::from(first)).bind(&device_cursor).bind(&device_cursor).bind(&delivery_cursor)
                .fetch_all(&mut *connection).await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let payload: Option<Vec<u8>> = row.try_get("payload_blob")?;
                let payload = payload.ok_or_else(|| {
                    KernelError::Invalid(
                        "legacy Pull body missing; explicit cutover repair required".into(),
                    )
                })?;
                if crate::ordinary::legacy::payload_is_ordinary(&payload)? {
                    return Err(legacy_cutover_error());
                }
                device_cursor = row.try_get("device_id")?;
                delivery_cursor = row.try_get_unchecked("delivery_id")?;
            }
            first = false;
        }
        Ok(())
    }

    pub(super) async fn close(&self) -> Result<()> {
        // One deadline includes waiting for a leaked/unfinished user as well as
        // closing the physical scoped session. Storage owns shared-pool close.
        let closing = async {
            let Some(connection) = self.connection.lock().await.take() else {
                return Ok(());
            };
            connection.close().await
        };
        match tokio::time::timeout(std::time::Duration::from_secs(3), closing).await {
            Ok(Ok(())) => self.health.ensure(),
            Ok(Err(error)) => {
                self.health.fail("MySQL ordinary data session close failed");
                Err(error.into())
            }
            Err(_) => {
                self.health
                    .fail("MySQL ordinary data session close timed out");
                Err(sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "MySQL ordinary data session close timed out",
                ))
                .into())
            }
        }
    }

    async fn initialize(&self) -> Result<()> {
        let mut connection = self.acquire().await?;
        sqlx::raw_sql(include_str!("mysql_schema.sql"))
            .execute(&mut *connection)
            .await?;
        let channel_unique: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM (SELECT INDEX_NAME FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ordinary_widget_refresh' AND NON_UNIQUE=0 GROUP BY INDEX_NAME HAVING COUNT(*)=1 AND MAX(COLUMN_NAME)='channel_id') channel_keys")
            .fetch_one(&mut *connection).await?;
        if channel_unique == 0 {
            return Err(KernelError::Invalid("ordinary Widget channel coalescing constraint missing; use a fresh C10 database or explicitly migrate the prior candidate before startup".into()));
        }
        let mut tx = connection.begin().await?;
        Self::lock_usage(&mut tx).await?;
        while self.recover_private_claims_tx(&mut tx).await? > 0 {}
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
                sqlx::query("DELETE FROM ordinary_targets WHERE delivery_id=? AND state='running' AND acked_at IS NOT NULL")
                    .bind(id).execute(&mut *tx).await?;
                sqlx::query("UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='provider' THEN 'retry_wait' ELSE 'superseded_route' END,next_attempt_at=? WHERE delivery_id=? AND state='running'")
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
        self.commit(tx).await?;
        drop(connection);
        self.maintenance().await?;
        Ok(())
    }
    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        let authorized_channel = request.authorized_channel;
        let admission_started = std::time::Instant::now();
        let request = {
            let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
            request.normalize()?
        };
        let channel_bytes = crate::value::ChannelId::parse(&request.channel_id)
            .map_err(|error| KernelError::Invalid(error.to_string()))?
            .into_inner();
        if authorized_channel.is_some_and(|channel| channel != channel_bytes) {
            return Err(KernelError::Unauthorized);
        }
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
                sqlx::query_scalar("SELECT CAST(password_hash AS CHAR CHARACTER SET utf8mb4) FROM ordinary_channel_routes WHERE channel_id=?")
                    .bind(channel_bytes.as_slice())
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
        let at = now();
        let existing_scope: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE op_id=? AND expires_at>?)",
        )
        .bind(&request.op_id)
        .bind(at)
        .fetch_one(&mut *tx)
        .await?;
        if existing_scope != 0 {
            return Err(KernelError::ScopeConflict);
        }
        // Reclaim expired delivery bodies independently of their identity history.
        self.maintain_tx(&mut tx, at).await?;
        if let Some(row)=self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("SELECT delivery_id,message_id,channel_id,thing_id,fingerprint,status,provider_target_count,private_enqueued_count FROM ordinary_messages WHERE op_id=? AND dedupe_until>?").bind(&request.op_id).bind(at).fetch_optional(&mut *tx)).await? {
            if row.get_unchecked::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get_unchecked::<Option<String>,_>("thing_id")!=request.thing_id {return Err(KernelError::ScopeConflict)}
            if row.get_unchecked::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get_unchecked("delivery_id"),message_id:row.get_unchecked("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:crate::ordinary::application::accepted_dispatch_status(&row.get_unchecked::<String,_>("status"),row.get("provider_target_count"),row.get("private_enqueued_count"))?})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        if let Some(id) = sqlx::query_scalar::<_,String>("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_messages WHERE op_id=? AND dedupe_until<=? AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running')")
            .bind(&request.op_id).bind(at).fetch_optional(&mut *tx).await? {
            Self::delete_message_tx(&mut tx,&id).await?;
        }
        let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
        let delivery_id = generate_hex_id_128();
        let message_id = generate_hex_id_128();
        let expires = request
            .ttl
            .map(|ttl| ttl.min(at.saturating_add(crate::ordinary::sender::MAX_TTL_MS)))
            .unwrap_or(at.saturating_add(self.config.default_ttl_secs * 1000));
        let mut fields = request.fields;
        // Sender metadata cannot assert a Gateway endpoint. Omission of the
        // trusted product URL stays omission on the wire.
        fields.remove("base_url");
        if !self.config.public_base_url.trim().is_empty() {
            fields.insert("base_url".into(), self.config.public_base_url.clone());
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
        let fanout:i64=self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT d.*,ROW_NUMBER() OVER(PARTITION BY d.platform,d.provider_token ORDER BY d.channel_type ASC,d.route_updated_at DESC,s.updated_at DESC,s.created_at DESC,s.device_id DESC) AS recipient_rank FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL AND TRIM(d.provider_token)<>'' AND d.route_updated_at IS NOT NULL) recipients WHERE recipient_rank=1").bind(channel_bytes.as_slice()).bind(at).fetch_one(&mut *tx)).await?;
        let provider_fanout = fanout;
        if !crate::ordinary::expiry::is_expired(expires, at) && provider_fanout > 0 {
            let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE provider IN ('FCM','APNS','WNS') AND delivery_mode='provider' AND state IN ('pending','running','retry_wait') AND acked_at IS NULL")
                .fetch_one(&mut *tx).await?;
            let legacy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased')")
                .fetch_one(&mut *tx).await?;
            if active
                .saturating_add(legacy)
                .saturating_add(provider_fanout)
                > self.config.max_provider_targets
            {
                return Err(KernelError::Capacity);
            }
        }
        let private_fanout = if !crate::ordinary::expiry::is_expired(expires, at) {
            self.check_private_admission_tx(&mut tx, &channel_bytes, at)
                .await?
        } else {
            0
        };
        let fanout = provider_fanout.saturating_add(private_fanout);
        let live = fanout > 0 && !crate::ordinary::expiry::is_expired(expires, at);
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
        self.counters.profile.sql(Path::Accept, Statement::MessageInsert, sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,provider_target_count,private_enqueued_count,thing_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).bind(if live {provider_fanout} else {0}).bind(if live {private_fanout} else {0}).bind(request.thing_id.as_deref()).execute(&mut *tx)).await?;
        if live {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,watch_alert_deadline_at,state,next_attempt_at) SELECT ?,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1),d.platform,d.provider,d.provider_token,d.route_generation,?,CASE WHEN d.platform='watchos' THEN ? + COALESCE(d.watch_alert_window_minutes,30)*60000 ELSE NULL END,'pending',? FROM (SELECT d.*,ROW_NUMBER() OVER(PARTITION BY d.platform,d.provider_token ORDER BY d.channel_type ASC,d.route_updated_at DESC,s.updated_at DESC,s.created_at DESC,s.device_id DESC) AS recipient_rank FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL AND TRIM(d.provider_token)<>'' AND d.route_updated_at IS NOT NULL) d WHERE d.recipient_rank=1").bind(&delivery_id).bind(at).bind(at).bind(at).bind(channel_bytes.as_slice()).bind(at).execute(&mut *tx)).await?;
        }
        if live && private_fanout > 0 {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at,delivery_mode) SELECT ?,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1),d.platform,'PRIVATE','',d.route_generation,?,'superseded_route',?,'private' FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(&delivery_id).bind(at).bind(at).bind(channel_bytes.as_slice()).bind(at).execute(&mut *tx)).await?;
            Self::reconcile_private_message_tx(&mut tx, &delivery_id, &[]).await?;
        }
        self.counters
            .profile
            .sql(
                Path::Accept,
                Statement::Usage,
                Self::reconcile_message_tx(&mut tx, &delivery_id),
            )
            .await?;
        if !crate::ordinary::expiry::is_expired(expires, at) {
            let widget: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM widget_push_subscriptions w JOIN devices d ON d.device_key=w.device_key JOIN channel_subscriptions s ON s.device_id=d.device_id WHERE s.channel_id=? AND s.status='active' AND LOWER(TRIM(w.platform)) IN ('ios','ipados','macos','watchos') AND w.widget_kind IN (?,?))")
                .bind(channel_bytes.as_slice())
                .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
                .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
                .fetch_one(&mut *tx).await?;
            if widget != 0 {
                // Reuse the normal product ordering row inside this admission
                // transaction. The marker has no ordinary payload or FK.
                let advanced = sqlx::query("UPDATE dispatch_acceptance_sequence SET current_value=current_value+1 WHERE singleton=1 AND current_value<9223372036854775807")
                    .execute(&mut *tx).await?.rows_affected();
                if advanced != 1 {
                    return Err(KernelError::Invalid(
                        "dispatch acceptance order exhausted or missing".into(),
                    ));
                }
                let order: i64 = sqlx::query_scalar(
                    "SELECT current_value FROM dispatch_acceptance_sequence WHERE singleton=1",
                )
                .fetch_one(&mut *tx)
                .await?;
                sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,coalesce_order,accepted_at,expires_at) VALUES(?,?,?,?,?) AS latest ON DUPLICATE KEY UPDATE delivery_id=latest.delivery_id,coalesce_order=latest.coalesce_order,accepted_at=latest.accepted_at,expires_at=latest.expires_at")
                    .bind(&delivery_id).bind(channel_bytes.as_slice()).bind(order).bind(at).bind(expires)
                    .execute(&mut *tx).await?;
            }
        }
        let commit_at = std::time::Instant::now();
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Accept, Phase::Commit, self.commit(tx))
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
            dispatch_status: crate::ordinary::application::accepted_dispatch_status(
                status,
                if live { provider_fanout } else { 0 },
                if live { private_fanout } else { 0 },
            )?,
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
        // Status reads Provider facts, not pending/usage counters.
        // Reconcile once after release mutations, inside this same transaction.
        self.counters
            .profile
            .sql(
                profile_path,
                Statement::ReleaseStatus,
                Self::refresh_status_tx(tx, id, now()),
            )
            .await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget,
            sqlx::query("DELETE FROM ordinary_targets WHERE delivery_id=? AND acked_at IS NOT NULL AND state!='running'")
                .bind(id).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload,
            sqlx::query("UPDATE ordinary_messages SET payload_blob=X'',payload_bytes=0 WHERE delivery_id=? AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND acked_at IS NULL)")
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
            .phase(Path::Maintenance, Phase::Commit, self.commit(tx))
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
        // One captured keyset owns all expiry mutations, including equal-TTL rows.
        let expiring: Vec<String> = sqlx::query(EXPIRY_BATCH_SQL)
            .bind(at)
            .fetch_all(&mut **tx)
            .await?
            .iter()
            .map(|row| row.try_get_unchecked::<String, _>(0))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in expiring {
            let before = Self::private_owners_for_message_tx(tx, &id).await?;
            sqlx::query("UPDATE ordinary_messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND delivery_mode='provider' AND provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id=?")
                .bind(&id).execute(&mut **tx).await?;
            sqlx::query("UPDATE ordinary_targets SET acked_at=?,private_claim=NULL,private_group=NULL,state=CASE WHEN delivery_mode='provider' AND state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id=?")
                .bind(at).bind(&id).execute(&mut **tx).await?;
            Self::reconcile_private_message_tx(tx, &id, &before).await?;
            self.counters
                .profile
                .sql(
                    Path::Maintenance,
                    Statement::Usage,
                    Self::reconcile_message_tx(tx, &id),
                )
                .await?;
            Self::refresh_status_tx(tx, &id, at).await?;
            self.release_acked_tx(tx, "", &id, Path::Maintenance)
                .await?;
        }
        let retained: Vec<String> = sqlx::query_scalar("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running') ORDER BY dedupe_until,delivery_id LIMIT 256")
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
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND delivery_mode='provider' AND acked_at IS NULL")
                .bind(at).bind(device).bind(&id).execute(&mut *tx)).await?;
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
            items.push(json!({"delivery_id":id,"payload":payload}));
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, self.commit(tx))
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
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET acked_at=? WHERE pull_owner=? AND delivery_id=? AND delivery_mode='provider' AND acked_at IS NULL AND EXISTS(SELECT 1 FROM ordinary_device_routes WHERE ordinary_device_routes.device_key=ordinary_targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM ordinary_messages WHERE ordinary_messages.delivery_id=ordinary_targets.delivery_id AND expires_at>?) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=ordinary_targets.platform AND r.provider_token=ordinary_targets.provider_token AND ordinary_targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
            self.release_acked_tx(&mut tx, device, &id, Path::Ack)
                .await?;
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, self.commit(tx))
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
        self.counters.provider_claim_queries[match provider {
            "APNS" => 1,
            "WNS" => 2,
            _ => 0,
        }]
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
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=? AND device_key=?").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
                let _compute = self.counters.profile.timer(Path::Claim, Phase::Compute);
                tickets.push(Ticket {
                    delivery_id: delivery,
                    device_key: device,
                    platform: row.get_unchecked("platform"),
                    provider: row.get_unchecked("provider"),
                    token: row.get_unchecked("provider_token"),
                    route_generation: row.get("route_generation"),
                    watch_alert_deadline: row.get("watch_alert_deadline_at"),
                    attempt_id: row.get::<i64, _>("attempt_id") + 1,
                    attempts: row.get::<i64, _>("attempts") + 1,
                    payload: serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?,
                    accepted_at: row.get("accepted_at"),
                    expires_at: row.get("expires_at"),
                });
                drop(_compute);
            }
        }
        let due: Option<i64> = self
            .counters
            .profile
            .sql(
                Path::Claim,
                Statement::ClaimNextDue,
                sqlx::query_scalar(NEXT_DUE_SQL)
                    .bind(provider)
                    .bind(provider)
                    .fetch_one(&mut *tx),
            )
            .await?;
        let retiring:bool=self.counters.profile.sql(Path::Claim, Statement::ClaimRetiring, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_device_routes d WHERE d.retired_at IS NOT NULL AND d.coalesced_to IS NULL AND (EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.pull_owner=d.device_key AND t.acked_at IS NULL) OR EXISTS(SELECT 1 FROM ordinary_subscriptions s WHERE s.device_key=d.device_key)))").fetch_one(&mut *tx)).await?;
        let next_due = if retiring {
            Some(at)
        } else {
            due.map(|due| due.max(cooldown.unwrap_or(0)))
        };
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, self.commit(tx))
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
            self.counters.profile.sql(Path::Claim, Statement::Read, sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.state='running' AND t.delivery_mode='provider' AND t.attempt_id=? AND t.acked_at IS NULL AND m.expires_at>? AND d.retired_at IS NULL AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.owner_generation AND t.route_generation=? AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&mut *profile_read_connection)).await
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
        let state = if state == "retry_wait"
            && crate::ordinary::expiry::is_expired(ticket.expires_at, now())
        {
            "permanent_failed"
        } else {
            state
        };
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='private' AND ? IN ('pending','retry_wait') THEN 'superseded_route' ELSE ? END,provider_status=?,provider_error=?,receipt_at=?,next_attempt_at=? WHERE delivery_id=? AND device_key=? AND state='running' AND attempt_id=?").bind(state).bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO ordinary_provider_cooldowns(provider,next_attempt_at) VALUES(?,?) ON DUPLICATE KEY UPDATE next_attempt_at=GREATEST(ordinary_provider_cooldowns.next_attempt_at,VALUES(next_attempt_at))").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                let channel: String = sqlx::query_scalar("SELECT CAST(channel_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_messages WHERE delivery_id=?")
                    .bind(&ticket.delivery_id).fetch_one(&mut *tx).await?;
                let channel = crate::value::ChannelId::parse(&channel)
                    .map_err(|error| KernelError::Invalid(error.to_string()))?
                    .into_inner();
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription,
                    sqlx::query("DELETE s FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id WHERE d.device_key=? AND s.channel_id=? AND d.platform=? AND CASE WHEN d.platform='android' THEN 'FCM' WHEN d.platform IN ('ios','macos','watchos') THEN 'APNS' WHEN d.platform='windows' THEN 'WNS' END=? AND d.provider_token=? AND d.ordinary_route_generation=?")
                        .bind(&ticket.device_key).bind(channel.as_slice()).bind(&ticket.platform)
                        .bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation)
                        .execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE ordinary_messages SET provider_accepted_count=provider_accepted_count+?,provider_failed_count=provider_failed_count+? WHERE delivery_id=?").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
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
            .phase(Path::Receipt, Phase::Commit, self.commit(tx))
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
    pub(crate) async fn next_widget_refresh(
        &self,
    ) -> Result<Option<crate::ordinary::widget_refresh::WidgetRefresh>> {
        let mut connection = self.acquire().await?;
        let row = sqlx::query("SELECT delivery_id,channel_id,coalesce_order,accepted_at,expires_at FROM ordinary_widget_refresh ORDER BY coalesce_order,delivery_id LIMIT 1")
            .fetch_optional(&mut *connection).await?;
        row.map(|row| {
            let channel: Vec<u8> = row.try_get("channel_id")?;
            Ok(crate::ordinary::widget_refresh::WidgetRefresh {
                delivery_id: row.try_get_unchecked("delivery_id")?,
                channel_id: channel.try_into().map_err(|_| KernelError::Unavailable)?,
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
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await?;
        let removed = sqlx::query(
            "DELETE FROM ordinary_widget_refresh WHERE delivery_id=? AND coalesce_order=?",
        )
        .bind(delivery_id)
        .bind(coalesce_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        self.commit(tx).await?;
        Ok(removed != 0)
    }

    pub(crate) async fn widget_refresh_targets(
        &self,
        channel_id: [u8; 16],
        after: Option<&crate::ordinary::widget_refresh::WidgetRefreshCursor>,
        limit: usize,
    ) -> Result<Vec<crate::ordinary::widget_refresh::WidgetRefreshTarget>> {
        if !(1..=128).contains(&limit) {
            return Err(KernelError::Invalid(
                "Widget refresh page limit must be between 1 and 128".into(),
            ));
        }
        let mut connection = self.acquire().await?;
        let cursor_platform = after.map_or("", |cursor| cursor.platform.as_str());
        let cursor_token = after.map_or("", |cursor| cursor.token.as_str());
        let rows = sqlx::query("SELECT device_key,platform,token FROM (SELECT w.device_key,CASE LOWER(TRIM(w.platform)) WHEN 'ipados' THEN 'ios' ELSE LOWER(TRIM(w.platform)) END COLLATE utf8mb4_bin AS platform,w.token COLLATE utf8mb4_bin AS token,ROW_NUMBER() OVER(PARTITION BY CASE LOWER(TRIM(w.platform)) WHEN 'ipados' THEN 'ios' ELSE LOWER(TRIM(w.platform)) END,w.token COLLATE utf8mb4_bin ORDER BY w.updated_at DESC,w.widget_kind ASC,w.family ASC,w.device_key ASC) AS recipient_rank FROM widget_push_subscriptions w JOIN devices d ON d.device_key=w.device_key JOIN channel_subscriptions s ON s.device_id=d.device_id WHERE s.channel_id=? AND s.status='active' AND LOWER(TRIM(w.platform)) IN ('ios','ipados','macos','watchos') AND w.widget_kind IN (?,?) AND (?=1 OR (CASE LOWER(TRIM(w.platform)) WHEN 'ipados' THEN 'ios' ELSE LOWER(TRIM(w.platform)) END COLLATE utf8mb4_bin)>? OR ((CASE LOWER(TRIM(w.platform)) WHEN 'ipados' THEN 'ios' ELSE LOWER(TRIM(w.platform)) END COLLATE utf8mb4_bin)=? AND w.token COLLATE utf8mb4_bin>?))) ranked WHERE recipient_rank=1 ORDER BY platform,token LIMIT ?")
            .bind(channel_id.as_slice())
            .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
            .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
            .bind(i64::from(after.is_none())).bind(cursor_platform).bind(cursor_platform).bind(cursor_token)
            .bind(limit as i64).fetch_all(&mut *connection).await?;
        rows.into_iter()
            .map(|row| {
                let platform: String = row.try_get_unchecked("platform")?;
                Ok(crate::ordinary::widget_refresh::WidgetRefreshTarget {
                    device_key: row.try_get_unchecked("device_key")?,
                    platform: platform.parse().map_err(|_| KernelError::Unavailable)?,
                    token: row.try_get_unchecked("token")?,
                })
            })
            .collect()
    }

    /// Read all states so a replayed derived intent cannot reopen a terminal
    /// Widget job whose same-or-later acceptance order is already durable.
    pub(crate) async fn widget_refresh_job_order(&self, job_id: &str) -> Result<Option<i64>> {
        let mut connection = self.acquire().await?;
        Ok(
            sqlx::query_scalar(
                "SELECT coalesce_order FROM provider_dispatch_outbox WHERE job_id=?",
            )
            .bind(job_id)
            .fetch_optional(&mut *connection)
            .await?,
        )
    }

    pub(crate) async fn private_route_capacity(&self, device: &str) -> Result<(i64, i64)> {
        let mut connection = self.acquire().await?;
        let retained: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT t.delivery_id) FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND (t.delivery_mode='private' OR (t.delivery_mode='provider' AND m.expires_at>?))")
            .bind(device).bind(now()).fetch_one(&mut *connection).await?;
        let existing: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=?),0)",
        )
        .bind(device)
        .fetch_one(&mut *connection)
        .await?;
        let global: i64 = sqlx::query_scalar(
            "SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1",
        )
        .fetch_one(&mut *connection)
        .await?;
        let private_id = crate::storage::types::PrivateDeviceId::derive(device).into_inner();
        let legacy_device: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM private_outbox WHERE device_id=? AND status IN ('pending','claimed','sent')")
            .bind(private_id.as_slice()).fetch_one(&mut *connection).await?;
        let legacy_global: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')",
        )
        .fetch_one(&mut *connection)
        .await?;
        let per_device =
            i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
        let global_limit = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
        let capacity = per_device.min(
            global_limit
                .saturating_sub(global)
                .saturating_sub(legacy_global)
                .saturating_add(existing)
                .saturating_add(legacy_device)
                .max(0),
        );
        Ok((retained.saturating_add(legacy_device), capacity))
    }

    pub(crate) async fn active_provider_count(&self) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE provider IN ('FCM','APNS','WNS') AND delivery_mode='provider' AND state IN ('pending','running','retry_wait') AND acked_at IS NULL")
            .fetch_one(&mut *connection).await?;
        Ok(count.max(0))
    }

    pub(crate) async fn private_executing_count(&self, device: Option<&str>) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let executing: i64 = if let Some(device) = device {
            sqlx::query_scalar("SELECT COUNT(DISTINCT delivery_id) FROM ordinary_targets WHERE pull_owner=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL")
                .bind(device).fetch_one(&mut *connection).await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT pull_owner,delivery_id FROM ordinary_targets WHERE delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL GROUP BY pull_owner,delivery_id) executing")
                .fetch_one(&mut *connection).await?
        };
        Ok(executing.max(0))
    }

    pub(crate) async fn private_pending_count(&self, device: Option<&str>) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let count: i64 = if let Some(key) = device {
            sqlx::query_scalar("SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=?),0)")
                .bind(key).fetch_one(&mut *connection).await?
        } else {
            sqlx::query_scalar(
                "SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1",
            )
            .fetch_one(&mut *connection)
            .await?
        };
        Ok(count.max(0))
    }

    pub async fn status(&self, op: &str) -> Result<Value> {
        let op = crate::ordinary::sender::op_id(op)?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM ordinary_messages WHERE op_id=? AND dedupe_until>?").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
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
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM ordinary_messages m JOIN ordinary_targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=?").bind(op).fetch_all(&mut *profile_read_connection)).await
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
        let ids=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM ordinary_targets WHERE pull_owner=? AND acked_at IS NULL ORDER BY accepted_at,delivery_id LIMIT ?").bind(key).bind(limit as i64).fetch_all(&mut **tx)).await?;
        for row in &ids {
            let id: String = row.get_unchecked("delivery_id");
            let original: String = row.get_unchecked("device_key");
            let before = Self::private_owners_for_message_tx(tx, &id).await?;
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET acked_at=?,private_claim=NULL,private_group=NULL,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE device_key=? AND delivery_id=? AND acked_at IS NULL").bind(at).bind(&original).bind(&id).execute(&mut **tx)).await?;
            Self::reconcile_private_message_tx(tx, &id, &before).await?;
            self.counters
                .profile
                .sql(
                    Path::Maintenance,
                    Statement::Usage,
                    Self::reconcile_message_tx(tx, &id),
                )
                .await?;
            Self::refresh_status_tx(tx, &id, at).await?;
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
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET acked_at=?,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=? AND device_key=? AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        let markers: Vec<i64> = sqlx::query_scalar("SELECT r.marker_id FROM ordinary_retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_mode='provider' AND t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256").fetch_all(&mut **tx).await?;
        for marker in markers {
            sqlx::query("DELETE FROM ordinary_retired_provider_tokens WHERE marker_id=?")
                .bind(marker)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

impl MySqlDeliveryStore {
    /// Called by the canonical route transaction, after its device upsert.
    pub(crate) async fn canonical_route_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        device: &str,
        to_private: bool,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        self.transition_private_mode_tx(tx, device, to_private)
            .await?;
        self.notify();
        Ok(())
    }

    /// Coalescing executes before canonical duplicate rows disappear. Receipt
    /// owner keys remain immutable; only the retained consumer is migrated.
    pub(crate) async fn canonical_coalesce_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        winner: &str,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        self.coalesce_private_owners_tx(tx, winner, platform, token)
            .await?;
        self.notify();
        Ok(())
    }

    pub(crate) async fn canonical_merge_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        old: &str,
        winner: &str,
        to_private: bool,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        let mut cursor = String::new();
        loop {
            let ids: Vec<String> = sqlx::query_scalar("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_targets WHERE pull_owner=? AND delivery_id>? GROUP BY delivery_id ORDER BY delivery_id LIMIT 256")
                .bind(old).bind(&cursor).fetch_all(&mut **tx).await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                let before = Self::private_owners_for_message_tx(tx, &id).await?;
                let exhausted: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets WHERE delivery_id=? AND pull_owner IN (?,?) AND acked_at IS NULL AND delivery_epoch=?)")
                    .bind(&id).bind(old).bind(winner).bind(i64::MAX).fetch_one(&mut **tx).await?;
                if exhausted != 0 {
                    return Err(KernelError::Invalid(
                        "private delivery epoch exhausted".into(),
                    ));
                }
                sqlx::query("UPDATE ordinary_targets SET owner_generation=CASE WHEN pull_owner=? THEN -1 ELSE owner_generation END,pull_owner=?,delivery_epoch=delivery_epoch+CASE WHEN acked_at IS NULL THEN 1 ELSE 0 END,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE delivery_id=? AND pull_owner IN (?,?)")
                    .bind(old).bind(winner).bind(&id).bind(old).bind(winner).execute(&mut **tx).await?;
                Self::reconcile_private_message_tx(tx, &id, &before).await?;
                Self::reconcile_message_tx(tx, &id).await?;
                Self::refresh_status_tx(tx, &id, now()).await?;
                cursor = id;
            }
        }
        self.transition_private_mode_tx(tx, winner, to_private)
            .await?;
        self.notify();
        Ok(())
    }

    /// Explicit exit revokes existing capabilities in the same transaction as
    /// deleting canonical credentials. Running attempts remain until receipt.
    /// Clear only the current Private consumption obligations. This is not
    /// logout: Provider Pull, canonical subscriptions and identity history stay.
    pub(crate) async fn canonical_clear_private_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        device: &str,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        // Clearing is a per-delivery revocation, not a route or session exit.
        // The existing Private connection remains authorized for future sends.
        loop {
            let ids: Vec<String> = sqlx::query_scalar("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_targets WHERE pull_owner=? AND delivery_mode='private' AND acked_at IS NULL GROUP BY delivery_id,accepted_at ORDER BY accepted_at,delivery_id LIMIT 256")
                .bind(device).fetch_all(&mut **tx).await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                let before = Self::private_owners_for_message_tx(tx, &id).await?;
                let exhausted: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND acked_at IS NULL AND delivery_epoch=?)")
                    .bind(device).bind(&id).bind(i64::MAX).fetch_one(&mut **tx).await?;
                if exhausted != 0 {
                    return Err(KernelError::Invalid(
                        "private delivery epoch exhausted".into(),
                    ));
                }
                sqlx::query("UPDATE ordinary_targets SET acked_at=?,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND acked_at IS NULL")
                    .bind(now()).bind(device).bind(&id).execute(&mut **tx).await?;
                Self::reconcile_private_message_tx(tx, &id, &before).await?;
                self.release_acked_tx(tx, device, &id, Path::Control)
                    .await?;
            }
        }
        self.notify();
        Ok(())
    }

    pub(crate) async fn canonical_revoke_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        device: &str,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        while self.retire_targets_tx(tx, device, now(), 256).await? > 0 {}
        self.notify();
        Ok(())
    }

    pub(crate) async fn canonical_retire_token_tx(
        &self,
        tx: &mut Transaction<'_, MySql>,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        self.health.ensure()?;
        Self::lock_usage(tx).await?;
        let changed = sqlx::query("UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1 AND control_epoch<?")
            .bind(i64::MAX).execute(&mut **tx).await?.rows_affected();
        if changed != 1 {
            return Err(KernelError::Invalid("control epoch exhausted".into()));
        }
        sqlx::query("UPDATE ordinary_retired_provider_tokens r JOIN ordinary_ledger_usage u ON u.singleton=1 SET r.control_epoch=u.control_epoch WHERE r.platform=? AND r.provider_token=?")
            .bind(platform).bind(token).execute(&mut **tx).await?;
        let exists: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens WHERE platform=? AND provider_token=?)")
            .bind(platform).bind(token).fetch_one(&mut **tx).await?;
        if exists == 0 {
            sqlx::query("INSERT INTO ordinary_retired_provider_tokens(platform,provider_token,control_epoch) SELECT ?,?,control_epoch FROM ordinary_ledger_usage WHERE singleton=1")
                .bind(platform).bind(token).execute(&mut **tx).await?;
        }
        self.retire_token_targets_tx(tx).await?;
        self.notify();
        Ok(())
    }

    pub(crate) async fn canonical_commit(&self, tx: Transaction<'_, MySql>) -> Result<()> {
        self.commit(tx).await
    }
}

fn legacy_cutover_error() -> KernelError {
    KernelError::Invalid("legacy ordinary records require explicit migration before product cutover; no dual authority or fallback is enabled".into())
}

#[cfg(test)]
mod product_contract_tests {
    use super::*;
    use crate::runtime_config::GatewayRuntimeProfile;
    use crate::storage::database::mysql::MySqlDb;
    use crate::storage::database::{
        DeviceRouteDatabaseAccess, PrivateChannelDatabaseAccess, SystemStateDatabaseAccess,
    };
    use crate::storage::types::{DeviceRouteRecordRow, PrivateDeviceId, RouteChannelType};

    async fn session_settings(connection: &mut MySqlConnection) -> (String, i64, i64, String) {
        let row = sqlx::query("SELECT @@SESSION.transaction_isolation AS isolation_level,CAST(@@SESSION.innodb_lock_wait_timeout AS SIGNED) AS row_wait,CAST(@@SESSION.lock_wait_timeout AS SIGNED) AS metadata_wait,@@SESSION.sql_mode AS sql_mode")
            .fetch_one(connection).await.expect("session settings");
        (
            row.try_get_unchecked("isolation_level")
                .expect("isolation text"),
            row.try_get("row_wait").expect("row wait"),
            row.try_get("metadata_wait").expect("metadata wait"),
            row.try_get_unchecked("sql_mode").expect("sql mode text"),
        )
    }

    /// This is deliberately opt-in and refuses every nonempty/non-C10 database.
    /// Provision a new isolated c10_* database, never an existing user dataset.
    #[tokio::test]
    #[ignore = "requires a newly provisioned isolated c10_* MySQL database"]
    async fn native_mysql_product_control_receipt_and_private_contract() {
        let url = std::env::var("PUSHGO_C10_MYSQL_TEST_URL").expect("isolated test URL");
        let probe = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("test database connection");
        let name: String = sqlx::query_scalar("SELECT DATABASE()")
            .fetch_one(&probe)
            .await
            .expect("test database identity");
        assert!(
            name.starts_with("c10_"),
            "only newly provisioned C10 test databases are permitted"
        );
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()",
        )
        .fetch_one(&probe)
        .await
        .expect("freshness probe");
        assert_eq!(
            tables, 0,
            "refuse an existing database, including a prior test run"
        );
        probe.close().await;

        let db = MySqlDb::new(&url, GatewayRuntimeProfile::Small)
            .await
            .expect("normal database initialization");
        let mut normal_before = db
            .ordinary_pool()
            .acquire()
            .await
            .expect("normal baseline session");
        let baseline = session_settings(&mut normal_before).await;
        drop(normal_before);
        let mut config = Config::default();
        config.private.enabled = true;
        config.private.max_pending_per_device = 1;
        config.private.max_pending = 1;
        config.max_targets = 4;
        config.public_base_url.clear();
        let store = MySqlDeliveryStore::from_product(
            db.ordinary_pool(),
            Arc::new(Mutex::new(())),
            config,
            Arc::new(Health::default()),
            Arc::new(Counters::default()),
        )
        .await
        .expect("product ledger attachment");
        db.set_ordinary_store(store.clone());
        let mut normal_after = store.pool.acquire().await.expect("normal sibling session");
        let sibling = session_settings(&mut normal_after).await;
        drop(normal_after);
        assert_eq!(
            sibling, baseline,
            "ordinary setup must not alter other product sessions"
        );
        let scoped = {
            let mut ordinary_connection =
                store.acquire().await.expect("fixed ordinary data session");
            session_settings(&mut ordinary_connection).await
        };
        println!(
            "c10 native MySQL normal settings: {sibling:?}; ordinary data settings: {scoped:?}"
        );
        assert_eq!(
            scoped.0, "REPEATABLE-READ",
            "this isolated native lane verifies C under the normal server RR default"
        );
        assert_eq!(scoped.0, baseline.0);
        assert_eq!((scoped.1, scoped.2), (3, 3));
        assert!(scoped.3.split(',').any(|mode| mode == "STRICT_ALL_TABLES"));
        let created = db
            .upsert_private_channel(None, Some("c10-native"), "unused-authorized-context")
            .await
            .expect("canonical channel creation");
        let empty_request = AcceptRequest {
            authorized_channel: Some(created.channel_id),
            channel_id: crate::util::encode_crockford_base32_128(&created.channel_id),
            title: "empty recipient contract".into(),
            op_id: Some("c10-empty-recipients".into()),
            ..Default::default()
        };
        let empty = store
            .accept(empty_request.clone())
            .await
            .expect("empty target acceptance");
        assert_eq!(empty.dispatch_status, "not_attempted");
        let empty_replay = store
            .accept(empty_request)
            .await
            .expect("empty target replay");
        assert_eq!(empty_replay.dispatch_status, "not_attempted");
        assert_eq!(empty_replay.delivery_id, empty.delivery_id);
        let key = "c10-native-device";
        let mut route = DeviceRouteRecordRow {
            device_key: key.into(),
            platform: "android".into(),
            channel_type: "fcm".into(),
            provider_token: Some("c10-synthetic-provider-token".into()),
            updated_at: now(),
        };
        db.upsert_device_route(&route)
            .await
            .expect("canonical provider route");
        db.private_subscribe_channel(
            created.channel_id,
            PrivateDeviceId::derive(key).into_inner(),
        )
        .await
        .expect("canonical subscription");
        let mut request = AcceptRequest {
            authorized_channel: Some(created.channel_id),
            channel_id: crate::util::encode_crockford_base32_128(&created.channel_id),
            title: "完整正文".into(),
            body: Some("payload survives route changes".into()),
            op_id: Some("C10-Case-Sensitive".into()),
            ..Default::default()
        };
        request
            .metadata
            .insert("base_url".into(), json!("https://sender.invalid/untrusted"));
        let accepted = store
            .accept(request.clone())
            .await
            .expect("durable acceptance");
        let batch = store
            .claim_reserved("FCM", 1, false)
            .await
            .expect("bounded claim");
        let ticket = batch.tickets.into_iter().next().expect("frozen target");
        route.updated_at += 1;
        db.upsert_device_route(&route)
            .await
            .expect("repeat route sync");
        assert!(
            store
                .authorize_ticket(&ticket)
                .await
                .expect("same-route generation")
        );
        route.channel_type = "private".into();
        route.provider_token = None;
        route.updated_at += 1;
        db.transition_device_route(&route, RouteChannelType::Fcm, 30, 1024)
            .await
            .expect("canonical provider to private transition");
        assert!(
            !store
                .authorize_ticket(&ticket)
                .await
                .expect("stale provider authorization")
        );
        store
            .settle(&ticket, "provider_accepted", 200, "", now(), None)
            .await
            .expect("late frozen receipt commit");
        let current = store
            .private_route(key)
            .await
            .expect("current private owner");
        let grant = store
            .private_claim(&current, "c10-session-a", 1)
            .await
            .expect("Private claim")
            .into_iter()
            .next()
            .expect("retained Private body");
        assert_eq!(grant.delivery_id, accepted.delivery_id);
        let body: Value = serde_json::from_slice(&grant.payload).expect("preserved payload");
        assert_eq!(body["body"], "payload survives route changes");
        assert!(
            body.get("base_url").is_none(),
            "an absent trusted product URL must not inherit sender metadata"
        );
        assert!(
            store
                .private_ack(&current, &grant)
                .await
                .expect("durable Private ACK")
        );
        assert!(
            !store
                .private_ack(&current, &grant)
                .await
                .expect("duplicate ACK")
        );
        let replay = store
            .accept(request.clone())
            .await
            .expect("identity replay after body release");
        assert_eq!(replay.message_id, accepted.message_id);
        assert_eq!(replay.delivery_id, accepted.delivery_id);
        assert_eq!(replay.dispatch_status, "attempted_accepted");
        let mut changed = request.clone();
        changed.title = "changed legal content".into();
        assert!(matches!(
            store.accept(changed).await,
            Err(KernelError::Conflict)
        ));
        let mut scoped = request.clone();
        scoped.thing_id = Some("c10-associated-thing".into());
        scoped.occurred_at = Some(now());
        assert!(matches!(
            store.accept(scoped).await,
            Err(KernelError::ScopeConflict)
        ));
        let remaining: i64 =
            sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?")
                .bind(&accepted.delivery_id)
                .fetch_one(&store.pool)
                .await
                .expect("body release evidence");
        assert_eq!(remaining, 0);

        let mut clearing = request.clone();
        clearing.op_id = Some("c10-private-clear".into());
        let clear_accepted = store
            .accept(clearing.clone())
            .await
            .expect("clear acceptance");
        let clear_grant = store
            .private_claim(&current, "c10-session-clear", 1)
            .await
            .expect("claim before clear")
            .into_iter()
            .next()
            .expect("Private clear capability");
        db.clear_ordinary_private_channel(&route)
            .await
            .expect("atomic Private channel clear");
        assert!(
            !store
                .private_authorize(&clear_grant)
                .await
                .expect("clear fences old capability")
        );
        assert!(
            !store
                .private_ack(&current, &clear_grant)
                .await
                .expect("cleared capability cannot ACK")
        );
        let after_clear = store
            .private_route(key)
            .await
            .expect("clear retains active Private route");
        assert_eq!(after_clear.route_generation, current.route_generation);
        assert_eq!(current.route_generation, clear_grant.route_generation);
        let clear_replay = store
            .accept(clearing)
            .await
            .expect("clear retains identity history");
        assert_eq!(clear_replay.message_id, clear_accepted.message_id);
        // The next accept exercises the same preserved canonical subscription.
        let mut next = request;
        next.op_id = Some("c10-merge-pending".into());
        let pending = store.accept(next).await.expect("second acceptance");
        let stale = store
            .private_claim(&current, "c10-session-b", 1)
            .await
            .expect("pre-merge claim")
            .into_iter()
            .next()
            .expect("pending capability");
        let winner = "c10-native-merged-device";
        route.device_key = winner.into();
        route.updated_at += 1;
        db.replace_device_identity(&route, Some(key))
            .await
            .expect("canonical identity replacement");
        assert!(
            !store
                .private_authorize(&stale)
                .await
                .expect("old capability retired")
        );
        let merged_route = store
            .private_route(winner)
            .await
            .expect("merged current owner");
        let merged = store
            .private_claim(&merged_route, "c10-session-c", 1)
            .await
            .expect("post-merge claim")
            .into_iter()
            .next()
            .expect("recovered capability");
        assert_eq!(merged.delivery_id, pending.delivery_id);
        assert_eq!(merged.receipt_owner, key);
        assert_eq!(merged.pull_owner, winner);
        assert!(
            store
                .private_ack(&merged_route, &merged)
                .await
                .expect("post-merge ACK")
        );
        db.revoke_device_identity(winner)
            .await
            .expect("canonical logout");
        assert!(store.private_route(winner).await.is_err());
        let usage: (i64, i64, i64) = sqlx::query_as(
            "SELECT messages,targets,bytes FROM ordinary_ledger_usage WHERE singleton=1",
        )
        .fetch_one(&store.pool)
        .await
        .expect("released capacity");
        assert_eq!(usage, (0, 0, 0));

        // A full Private execution allowance leaves accepted rows waiting on
        // disk while healthy Provider targets of the same message can finish.
        let waiting_key = "c10-native-waiting-private";
        let healthy_key = "c10-native-healthy-provider";
        let mut waiting_route = DeviceRouteRecordRow {
            device_key: waiting_key.into(),
            platform: "android".into(),
            channel_type: "private".into(),
            provider_token: None,
            updated_at: now(),
        };
        let healthy_route = DeviceRouteRecordRow {
            device_key: healthy_key.into(),
            platform: "android".into(),
            channel_type: "fcm".into(),
            provider_token: Some("c10-healthy-provider-token".into()),
            updated_at: now(),
        };
        for route in [&waiting_route, &healthy_route] {
            db.upsert_device_route(route)
                .await
                .expect("mixed canonical route");
            db.private_subscribe_channel(
                created.channel_id,
                PrivateDeviceId::derive(&route.device_key).into_inner(),
            )
            .await
            .expect("mixed canonical subscription");
        }
        let mixed = AcceptRequest {
            authorized_channel: Some(created.channel_id),
            channel_id: crate::util::encode_crockford_base32_128(&created.channel_id),
            title: "mixed waiting and healthy Provider".into(),
            op_id: Some("c10-mixed-first".into()),
            ..Default::default()
        };
        let first = store
            .accept(mixed.clone())
            .await
            .expect("first mixed acceptance");
        let mut second_request = mixed.clone();
        second_request.op_id = Some("c10-mixed-second".into());
        let second = store
            .accept(second_request)
            .await
            .expect("Private per-device fullness retains accepted waiting");
        let replay = store
            .accept(mixed.clone())
            .await
            .expect("duplicate remains accepted at full active-target budget");
        assert_eq!(replay.delivery_id, first.delivery_id);
        assert_eq!(
            store
                .private_pending_count(Some(waiting_key))
                .await
                .unwrap(),
            2
        );
        let mut rejected = mixed;
        rejected.op_id = Some("c10-mixed-global-full".into());
        assert!(matches!(
            store.accept(rejected).await,
            Err(KernelError::Capacity)
        ));
        assert!(matches!(
            store.status("c10-mixed-global-full").await,
            Err(KernelError::NotFound)
        ));
        let provider = store
            .claim_reserved("FCM", 8, false)
            .await
            .expect("healthy Provider proceeds");
        assert_eq!(provider.tickets.len(), 2);
        for ticket in provider.tickets {
            store
                .settle(&ticket, "provider_accepted", 200, "", now(), None)
                .await
                .expect("healthy Provider receipt");
        }
        assert_eq!(
            store
                .ack(
                    healthy_key,
                    vec![first.delivery_id.clone(), second.delivery_id.clone()]
                )
                .await
                .expect("healthy Provider content ACK"),
            2
        );
        let private_route = store
            .private_route(waiting_key)
            .await
            .expect("waiting Private route");
        let first_grant = store
            .private_claim(&private_route, "c10-waiting-session", 8)
            .await
            .expect("bounded Private execution")
            .into_iter()
            .next()
            .expect("one execution slot");
        assert_eq!(
            store
                .private_executing_count(Some(waiting_key))
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.private_executing_count(None).await.unwrap(), 1);
        let other_key = "c10-native-other-private";
        let other_channel = db
            .upsert_private_channel(None, Some("c10-other"), "unused-authorized-context")
            .await
            .expect("second Private canonical channel");
        db.upsert_device_route(&DeviceRouteRecordRow {
            device_key: other_key.into(),
            platform: "android".into(),
            channel_type: "private".into(),
            provider_token: None,
            updated_at: now(),
        })
        .await
        .expect("second Private canonical route");
        db.private_subscribe_channel(
            other_channel.channel_id,
            PrivateDeviceId::derive(other_key).into_inner(),
        )
        .await
        .expect("second Private canonical subscription");
        let other = store
            .accept(AcceptRequest {
                authorized_channel: Some(other_channel.channel_id),
                channel_id: crate::util::encode_crockford_base32_128(&other_channel.channel_id),
                title: "global Private execution waiting".into(),
                op_id: Some("c10-mixed-other-private".into()),
                ..Default::default()
            })
            .await
            .expect("global Private fullness retains accepted waiting");
        let other_route = store
            .private_route(other_key)
            .await
            .expect("second Private current route");
        assert_eq!(
            store
                .private_executing_count(Some(other_key))
                .await
                .unwrap(),
            0
        );
        assert!(
            store
                .private_claim(&other_route, "c10-other-device-session", 8)
                .await
                .expect("global execution allowance shared across devices")
                .is_empty()
        );
        assert!(
            store
                .private_claim(&private_route, "c10-other-session", 8)
                .await
                .expect("full execution allowance")
                .is_empty()
        );
        waiting_route.updated_at += 1;
        db.upsert_device_route(&waiting_route)
            .await
            .expect("same Private sync with a waiting backlog");
        assert!(
            store
                .private_authorize(&first_grant)
                .await
                .expect("same Private sync preserves issued grant")
        );
        assert!(
            store
                .private_ack(&private_route, &first_grant)
                .await
                .expect("release one execution slot")
        );
        let second_grant = store
            .private_claim(&private_route, "c10-waiting-session", 8)
            .await
            .expect("waiting target advances")
            .into_iter()
            .next()
            .expect("next accepted obligation");
        assert_ne!(first_grant.delivery_id, second_grant.delivery_id);
        assert!(
            store
                .private_ack(&private_route, &second_grant)
                .await
                .expect("waiting target durable ACK")
        );
        assert_eq!(
            store
                .private_executing_count(Some(waiting_key))
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.private_executing_count(None).await.unwrap(), 0);
        let other_grant = store
            .private_claim(&other_route, "c10-other-device-session", 8)
            .await
            .expect("global waiting advances after durable ACK")
            .into_iter()
            .next()
            .expect("global execution slot released");
        assert_eq!(other_grant.delivery_id, other.delivery_id);
        assert!(
            store
                .private_ack(&other_route, &other_grant)
                .await
                .expect("second Private owner durable ACK")
        );
        assert_eq!(
            store
                .private_pending_count(Some(waiting_key))
                .await
                .unwrap(),
            0
        );
        db.revoke_device_identity(waiting_key)
            .await
            .expect("exit mixed Private device");
        db.revoke_device_identity(healthy_key)
            .await
            .expect("exit mixed Provider device");
        db.revoke_device_identity(other_key)
            .await
            .expect("exit second Private device");

        // Native derived-Widget boundary: normal canonical registration and
        // production job projection, not a second ordinary payload/identity.
        let widget_key = "c10-native-widget-device";
        let widget_route = DeviceRouteRecordRow {
            device_key: widget_key.into(),
            platform: "ios".into(),
            channel_type: "apns".into(),
            provider_token: Some("ab".repeat(32)),
            updated_at: now(),
        };
        db.upsert_device_route(&widget_route)
            .await
            .expect("canonical Widget device");
        db.private_subscribe_channel(
            created.channel_id,
            PrivateDeviceId::derive(widget_key).into_inner(),
        )
        .await
        .expect("canonical Widget channel subscription");
        let widget_token = "cd".repeat(32);
        let registered: Vec<_> = [
            crate::api::handlers::widget_push::WIDGET_KIND_UNREAD,
            crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY,
        ]
        .into_iter()
        .map(|kind| crate::storage::WidgetPushSubscriptionRecord {
            device_key: widget_key.into(),
            platform: "ios".into(),
            token: widget_token.clone(),
            widget_kind: kind.into(),
            family: "systemSmall".into(),
            schema_version: 1,
            created_at: now(),
            updated_at: now(),
        })
        .collect();
        db.upsert_widget_push_subscriptions(
            widget_key,
            crate::storage::Platform::IOS,
            &widget_token,
            &registered,
            1,
            now(),
        )
        .await
        .expect("normal Widget registration");
        let widget_request = AcceptRequest {
            authorized_channel: Some(created.channel_id),
            channel_id: crate::util::encode_crockford_base32_128(&created.channel_id),
            title: "ordinary Widget invalidation".into(),
            op_id: Some("c10-widget-derived".into()),
            ..Default::default()
        };
        let accepted_widget = store
            .accept(widget_request.clone())
            .await
            .expect("accept with derived marker");
        let refresh = store
            .next_widget_refresh()
            .await
            .expect("read derived marker")
            .expect("durable marker");
        assert_eq!(refresh.delivery_id, accepted_widget.delivery_id);
        assert_eq!(refresh.channel_id, created.channel_id);
        let target = store
            .widget_refresh_targets(created.channel_id, None, 1)
            .await
            .expect("bounded Widget selector");
        assert_eq!(
            target.len(),
            1,
            "Unread and WatchSummary share one platform/token target"
        );
        let cursor = crate::ordinary::widget_refresh::WidgetRefreshCursor {
            platform: target[0].platform.name().into(),
            token: target[0].token.clone(),
        };
        assert!(
            store
                .widget_refresh_targets(created.channel_id, Some(&cursor), 1)
                .await
                .expect("Widget keyset advances")
                .is_empty()
        );
        let apns = store
            .claim_reserved("APNS", 1, false)
            .await
            .expect("ordinary APNS claim")
            .tickets
            .into_iter()
            .next()
            .expect("ordinary target");
        store
            .settle(&apns, "provider_accepted", 200, "", now(), None)
            .await
            .expect("ordinary APNS receipt");
        assert_eq!(
            store
                .ack(widget_key, vec![accepted_widget.delivery_id.clone()])
                .await
                .expect("ordinary body ACK"),
            1
        );
        assert_eq!(
            store
                .next_widget_refresh()
                .await
                .expect("marker after ordinary body release")
                .unwrap()
                .coalesce_order,
            refresh.coalesce_order
        );
        assert_eq!(
            store
                .accept(widget_request.clone())
                .await
                .expect("Widget identity replay")
                .delivery_id,
            refresh.delivery_id
        );
        let target = target.into_iter().next().unwrap();
        let mut projected = crate::api::handlers::message::widget_push_job(
            refresh.channel_id,
            "message",
            Arc::from(refresh.delivery_id.as_str()),
            Arc::from(refresh.delivery_id.as_str()),
            target.platform,
            target.device_key,
            target.token,
        );
        projected.ordinary_target_scoped = true;
        let mut derived = crate::dispatch::DurableProviderJob::from_widget(&projected)
            .to_record("pending", refresh.accepted_at, refresh.expires_at)
            .expect("production Widget job projection");
        derived.coalesce_order = refresh.coalesce_order;
        assert!(derived.op_id.is_none() && derived.dedupe_key.is_none());
        assert!(
            store
                .widget_refresh_job_order(&derived.job_id)
                .await
                .expect("prior derived order")
                .is_none()
        );
        assert!(
            db.enqueue_provider_dispatch_job(&derived, 1_000_000)
                .await
                .expect("derived job COMMIT")
        );
        assert_eq!(
            store
                .widget_refresh_job_order(&derived.job_id)
                .await
                .expect("committed derived order"),
            Some(refresh.coalesce_order)
        );
        let mut blocked = derived.clone();
        blocked.job_id.push_str("-capacity-probe");
        assert!(
            matches!(
                db.enqueue_provider_dispatch_job(&blocked, 0).await,
                Err(crate::storage::StoreError::ProviderDispatchCapacityExceeded { .. })
            ),
            "a known full native derived budget leaves the durable marker pending"
        );
        let mut latest = refresh.clone();
        for index in 0..3 {
            let mut request = widget_request.clone();
            request.op_id = Some(format!("c10-widget-coalesced-{index}"));
            let accepted = store
                .accept(request)
                .await
                .expect("coalesced Widget accept");
            latest = store.next_widget_refresh().await.unwrap().unwrap();
            assert_eq!(latest.delivery_id, accepted.delivery_id);
            let mut read = store.acquire().await.unwrap();
            let count: i64 = sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_widget_refresh WHERE channel_id=?",
            )
            .bind(created.channel_id.as_slice())
            .fetch_one(&mut *read)
            .await
            .unwrap();
            assert_eq!(
                count, 1,
                "derived backpressure must not accumulate per-request markers"
            );
        }
        assert!(latest.coalesce_order > refresh.coalesce_order);
        assert!(
            !store
                .complete_widget_refresh(&refresh.delivery_id, refresh.coalesce_order + 1)
                .await
                .expect("stale marker completion")
        );
        assert!(
            !store
                .complete_widget_refresh(&refresh.delivery_id, refresh.coalesce_order)
                .await
                .expect("old snapshot cannot delete latest channel marker")
        );
        assert!(
            store
                .complete_widget_refresh(&latest.delivery_id, latest.coalesce_order)
                .await
                .expect("complete latest marker after derived COMMIT")
        );
        assert!(
            store
                .next_widget_refresh()
                .await
                .expect("derived queue drained")
                .is_none()
        );
        let expired_widget = store
            .accept(AcceptRequest {
                authorized_channel: Some(created.channel_id),
                channel_id: crate::util::encode_crockford_base32_128(&created.channel_id),
                title: "already expired Widget invalidation".into(),
                op_id: Some("c10-widget-expired".into()),
                ttl: Some(0),
                ..Default::default()
            })
            .await
            .expect("expired identity is still accepted");
        assert_eq!(expired_widget.dispatch_status, "not_attempted");
        assert!(
            store
                .next_widget_refresh()
                .await
                .expect("expired acceptance has no Widget side effect")
                .is_none()
        );
        store
            .close()
            .await
            .expect("scoped ordinary data session closes cleanly");
        store.pool.close().await;
    }
}
