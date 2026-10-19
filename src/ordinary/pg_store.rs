//! Native PostgreSQL ordinary ledger attached to normal product Storage.
//! Control views project canonical records; no duplicate control authority exists.
use crate::ordinary::expiry::is_expired;
use crate::ordinary::profiling::{Path, Phase, Statement};
use crate::ordinary::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, Health, KernelError, Result, Ticket,
    channel_storage_key, now, record_duration, verify_password_async,
};
use crate::ordinary::types::generate_hex_id_128;
use crate::ordinary::widget_refresh::{WidgetRefresh, WidgetRefreshCursor, WidgetRefreshTarget};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool, Postgres, Row, Transaction, pool::PoolConnection};
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{Mutex, Notify};
#[derive(Clone)]
pub struct PgDeliveryStore {
    pub(super) pool: PgPool,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 3],
    pub(super) health: Arc<Health>,
    #[cfg(test)]
    pub(super) delivery_candidates: Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}
struct AdmissionWake(PgDeliveryStore);
impl Drop for AdmissionWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=$1 AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>$2 AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='provider' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT $3";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=$1 AND t.delivery_id=$2 AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>$3 AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
pub(super) const RECOVER_RUNNING_SQL: &str = "UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='private' THEN 'superseded_route' ELSE 'retry_wait' END,next_attempt_at=$1 WHERE provider=$2 AND state='running'";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM ordinary_retired_provider_tokens r JOIN ordinary_targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.delivery_mode='provider' AND t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";

pub(crate) const MESSAGE_SCHEMA: &str = include_str!("pg_message_schema.sql");

impl PgDeliveryStore {
    pub(crate) fn fail_closed(&self, reason: &str) {
        self.health.fail(reason);
        self.notify();
    }

    pub(super) async fn acquire(&self) -> Result<PoolConnection<Postgres>> {
        self.health.ensure()?;
        let connection = self.pool.acquire().await?;
        self.health.ensure()?;
        Ok(connection)
    }
    /// Settings are transaction-local: returning this connection to normal
    /// Storage cannot change retained Event/Thing/Live Activity sessions.
    pub(super) async fn begin_ordinary(
        connection: &mut PgConnection,
    ) -> Result<Transaction<'_, Postgres>> {
        let mut tx = connection
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await?;
        Self::set_tx_limits(&mut tx).await?;
        Ok(tx)
    }
    async fn set_tx_limits(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query("SELECT set_config('lock_timeout','3s',true),set_config('synchronous_commit','on',true)")
            .execute(&mut **tx).await?;
        Ok(())
    }
    pub(crate) async fn configure_control_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> crate::storage::StoreResult<()> {
        self.health.ensure().map_err(native_control_error)?;
        Self::set_tx_limits(tx).await.map_err(native_control_error)
    }
    pub(super) async fn lock_usage(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query("SELECT singleton FROM ordinary_ledger_usage WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
        Ok(())
    }
    pub(super) fn notify(&self) {
        for wake in &self.wake {
            wake.notify_one();
        }
    }
    /// Attach to the normal product's database lifecycle and mutation gate.
    /// The product owns the pool and its single-instance guard.
    pub(crate) async fn from_product(
        pool: PgPool,
        gate: Arc<Mutex<()>>,
        config: Config,
        health: Arc<Health>,
        counters: Arc<Counters>,
    ) -> Result<Self> {
        // Forward migration of old ordinary identities and pending work has a
        // separate acceptance gate. Refuse a silent half-switch or fallback.
        let legacy = legacy_ordinary_present(&pool).await?;
        if legacy {
            return Err(KernelError::Invalid("legacy ordinary records require the explicit ledger migration before product cutover".into()));
        }
        let store = Self {
            pool,
            gate,
            config,
            health,
            counters,
            wake: std::array::from_fn(|_| Arc::new(Notify::new())),
            #[cfg(test)]
            delivery_candidates: Arc::new(std::sync::Mutex::new(Default::default())),
        };
        store.initialize().await?;
        Ok(store)
    }
    /// Storage closes its shared pool after every consumer has drained.
    async fn initialize(&self) -> Result<()> {
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let prior_identity_schema: bool = sqlx::query_scalar("SELECT to_regclass('ordinary_messages') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('ordinary_messages') AND attname='identity_state' AND NOT attisdropped)")
            .fetch_one(&mut *tx).await?;
        if prior_identity_schema {
            return Err(KernelError::Invalid("ordinary identity schema requires an explicit offline upgrade; prior C candidate databases are not a fixed-main migration source".into()));
        }
        sqlx::raw_sql(MESSAGE_SCHEMA).execute(&mut *tx).await?;
        sqlx::raw_sql(include_str!("pg_schema.sql"))
            .execute(&mut *tx)
            .await?;
        let channel_unique: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_index idx JOIN pg_attribute col ON col.attrelid=idx.indrelid AND col.attname='channel_id' AND col.attnum=idx.indkey[0] WHERE idx.indrelid='ordinary_widget_refresh'::regclass AND idx.indisunique AND idx.indisvalid AND idx.indpred IS NULL AND idx.indexprs IS NULL AND idx.indnkeyatts=1)")
            .fetch_one(&mut *tx).await?;
        if !channel_unique {
            return Err(KernelError::Invalid("ordinary Widget channel coalescing constraint missing; use a fresh C10 database or explicitly migrate the prior candidate before startup".into()));
        }
        sqlx::raw_sql(crate::ordinary::pg_private::PRIVATE_USAGE_SCHEMA)
            .execute(&mut *tx)
            .await?;
        Self::lock_usage(&mut tx).await?;
        while self.recover_private_claims_tx(&mut tx).await? == 256 {}
        for provider in ["FCM", "APNS", "WNS"] {
            sqlx::query("DELETE FROM ordinary_targets WHERE provider=$1 AND state='running' AND acked_at IS NOT NULL").bind(provider).execute(&mut *tx).await?;
            sqlx::query(RECOVER_RUNNING_SQL)
                .bind(now())
                .bind(provider)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=$1 WHERE status='provider_queued' AND NOT EXISTS(SELECT 1 FROM ordinary_targets outstanding WHERE outstanding.delivery_id=ordinary_messages.delivery_id AND outstanding.provider IN ('FCM','APNS','WNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait'))))").bind(now()).execute(&mut *tx).await?;
        self.health.ensure()?;
        tx.commit().await?;
        drop(connection);
        self.maintenance().await?;
        Ok(())
    }
    // The fixed-main independent collision reservations have no trustworthy
    // operation relationship. Preserve them and probe their primary key even
    // after all ordinary legacy operations have been converted offline.
    async fn allocate_delivery_id_tx(&self, tx: &mut Transaction<'_, Postgres>) -> Result<String> {
        for _ in 0..4 {
            #[cfg(test)]
            let candidate = self
                .delivery_candidates
                .lock()
                .expect("test candidates")
                .pop_front()
                .unwrap_or_else(generate_hex_id_128);
            #[cfg(not(test))]
            let candidate = generate_hex_id_128();
            let collision: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dispatch_delivery_dedupe WHERE dedupe_key=$1) OR EXISTS(SELECT 1 FROM ordinary_messages WHERE delivery_id=$2)")
                .bind(format!("delivery:{candidate}"))
                .bind(&candidate)
                .fetch_one(&mut **tx).await?;
            if !collision {
                return Ok(candidate);
            }
        }
        Err(KernelError::Unavailable)
    }

    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        let admission_started = std::time::Instant::now();
        let authorized_channel = request.authorized_channel;
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
            .phase(
                Path::Accept,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
            .await?;
        Self::lock_usage(&mut tx).await?;
        let storage_channel = channel_storage_key(&request.channel_id)?;
        let auth: Option<String> = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Auth,
                sqlx::query_scalar(
                    "SELECT password_hash FROM ordinary_channel_routes WHERE channel_id=$1",
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
        let at = now();
        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE op_id=$1 AND expires_at>$2)",
        )
        .bind(&request.op_id)
        .bind(at)
        .fetch_one(&mut *tx)
        .await?;
        if occupied {
            return Err(KernelError::ScopeConflict);
        }
        // The historical alias probe has its own partial expression index.
        // It precedes scope/fingerprint decoding and leaves new live op IDs
        // case-sensitive, including when the caller changes channel or Thing.
        let historical: bool = self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_messages WHERE identity_state='legacy_unverifiable' AND lower(op_id)=lower($1) AND dedupe_until>$2)").bind(&request.op_id).bind(at).fetch_one(&mut *tx)).await?;
        if historical {
            return Err(KernelError::Control { status:409, code:"historical_identity_unverifiable", message:"historical message identity is retained, but its original request cannot be verified; use a new op_id".into() });
        }
        // Reclaim expired delivery bodies independently of their identity history.
        self.maintain_tx(&mut tx, at).await?;
        if let Some(row)=self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("SELECT delivery_id,message_id,channel_id,thing_id,fingerprint,status,provider_target_count,private_enqueued_count FROM ordinary_messages WHERE op_id=$1 AND dedupe_until>$2").bind(&request.op_id).bind(at).fetch_optional(&mut *tx)).await? {
            if row.get::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get::<Option<String>,_>("thing_id") != request.thing_id { return Err(KernelError::ScopeConflict); }
            if row.get::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get("delivery_id"),message_id:row.get("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:crate::ordinary::application::accepted_dispatch_status(&row.get::<String,_>("status"),row.get("provider_target_count"),row.get("private_enqueued_count"))?})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("DELETE FROM ordinary_messages WHERE op_id=$1 AND dedupe_until<=$2 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running')").bind(&request.op_id).bind(at).execute(&mut *tx)).await?;
        let _compute = self.counters.profile.timer(Path::Accept, Phase::Compute);
        let delivery_id = self.allocate_delivery_id_tx(&mut tx).await?;
        let message_id = generate_hex_id_128();
        let expires = request
            .ttl
            .map(|ttl| ttl.min(at.saturating_add(crate::ordinary::sender::MAX_TTL_MS)))
            .unwrap_or(at.saturating_add(self.config.default_ttl_secs * 1000));
        let mut fields = request.fields;
        // Gateway configuration is the only base URL authority. In particular,
        // an omitted product URL must not expose an empty or sender-supplied one.
        fields.remove("base_url");
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
        if !self.config.public_base_url.trim().is_empty() {
            fields.insert(
                "base_url".into(),
                self.config.public_base_url.trim().to_owned(),
            );
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
        let provider_fanout:i64=self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT DISTINCT d.platform,d.provider_token FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=$1 AND s.created_at<=$2 AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL) frozen").bind(&storage_channel).bind(at).fetch_one(&mut *tx)).await?;
        let private_fanout = if !is_expired(expires, at) {
            self.check_private_admission_tx(&mut tx, &storage_channel, at)
                .await?
        } else {
            0
        };
        let active_provider: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE delivery_mode='provider' AND provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND state IN ('pending','running','retry_wait')")
            .fetch_one(&mut *tx).await?;
        let legacy_provider: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased')")
            .fetch_one(&mut *tx).await?;
        if !is_expired(expires, at)
            && active_provider
                .saturating_add(legacy_provider)
                .saturating_add(provider_fanout)
                > self.config.max_provider_targets
        {
            return Err(KernelError::Capacity);
        }
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
        self.counters.profile.sql(Path::Accept, Statement::MessageInsert, sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,provider_target_count,private_enqueued_count,thing_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).bind(if live {provider_fanout}else{0}).bind(if live {private_fanout}else{0}).bind(&request.thing_id).execute(&mut *tx)).await?;
        if live {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at,watch_alert_deadline_at) SELECT DISTINCT ON(d.platform,d.provider_token) $1,d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,$2,'pending',$3,CASE WHEN d.platform='watchos' THEN $2+CASE WHEN d.watch_alert_window_minutes IN (5,15,30,60) THEN d.watch_alert_window_minutes ELSE 30 END*60000 ELSE NULL END FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=$4 AND s.created_at<=$2 AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS','WNS') AND d.provider_token IS NOT NULL ORDER BY d.platform,d.provider_token,d.channel_type ASC,d.route_updated_at DESC,s.updated_at DESC,s.created_at DESC,s.device_id DESC").bind(&delivery_id).bind(at).bind(at).bind(&storage_channel).execute(&mut *tx)).await?;
        }
        if live && private_fanout > 0 {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO ordinary_targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at,delivery_mode) SELECT $1,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1),d.platform,'PRIVATE','',d.route_generation,$2,'superseded_route',$3,'private' FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=$4 AND s.created_at<=$2 AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(&delivery_id).bind(at).bind(at).bind(&storage_channel).execute(&mut *tx)).await?;
        }
        // Widget refresh is an existing derived side effect, including channels
        // with no ordinary delivery target. Its marker carries no ordinary body
        // and does not count as a successful ordinary delivery or retain Pull.
        if !is_expired(expires, at) {
            Self::insert_widget_refresh_tx(&mut tx, &storage_channel, &delivery_id, at, expires)
                .await?;
        }
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
            dispatch_status,
        })
    }

    async fn insert_widget_refresh_tx(
        tx: &mut Transaction<'_, Postgres>,
        storage_channel: &str,
        delivery_id: &str,
        accepted_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        let matched: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM widget_push_subscriptions w \
             JOIN devices d ON d.device_key=w.device_key \
             JOIN channel_subscriptions s ON s.device_id=d.device_id \
             WHERE encode(s.channel_id,'hex')=$1 AND s.status='active' \
              AND lower(btrim(w.platform)) IN ('ios','ipados','macos','watchos') \
              AND w.widget_kind IN ($2,$3))",
        )
        .bind(storage_channel)
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
        .fetch_one(&mut **tx)
        .await?;
        if !matched {
            return Ok(());
        }
        // Reuse the normal shared coalescing clock. Allocating the order and
        // marker in this transaction makes acceptance/recovery indivisible.
        let order: Option<i64> = sqlx::query_scalar(
            "UPDATE dispatch_acceptance_sequence SET current_value=current_value+1 \
             WHERE singleton=1 AND current_value<9223372036854775807 RETURNING current_value",
        )
        .fetch_optional(&mut **tx)
        .await?;
        let order = order.ok_or_else(|| {
            KernelError::Invalid("dispatch acceptance order unavailable or exhausted".into())
        })?;
        sqlx::query(
            "INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,acceptance_order,accepted_at,expires_at) \
             VALUES($1,decode($2,'hex'),$3,$4,$5) \
             ON CONFLICT(channel_id) DO UPDATE SET delivery_id=EXCLUDED.delivery_id, \
             acceptance_order=EXCLUDED.acceptance_order,accepted_at=EXCLUDED.accepted_at, \
             expires_at=EXCLUDED.expires_at \
             WHERE ordinary_widget_refresh.acceptance_order<EXCLUDED.acceptance_order",
        )
        .bind(delivery_id)
        .bind(storage_channel)
        .bind(order)
        .bind(accepted_at)
        .bind(expires_at)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub(crate) async fn widget_refresh_ceiling(&self) -> Result<Option<i64>> {
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let ceiling =
            sqlx::query_scalar("SELECT MAX(acceptance_order) FROM ordinary_widget_refresh")
                .fetch_one(&mut *tx)
                .await?;
        self.health.ensure()?;
        tx.commit().await?;
        Ok(ceiling)
    }

    pub(crate) async fn widget_refresh_after(
        &self,
        after: i64,
        ceiling: i64,
    ) -> Result<Option<WidgetRefresh>> {
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let row = sqlx::query(
            "SELECT delivery_id,channel_id,acceptance_order,accepted_at,expires_at \
             FROM ordinary_widget_refresh WHERE acceptance_order>$1 AND acceptance_order<=$2 ORDER BY acceptance_order LIMIT 1",
        )
        .bind(after)
        .bind(ceiling)
        .fetch_optional(&mut *tx)
        .await?;
        let refresh = row
            .map(|row| -> Result<WidgetRefresh> {
                let channel_id: Vec<u8> = row.try_get("channel_id")?;
                let channel_id = channel_id.try_into().map_err(|_| {
                    KernelError::Invalid("invalid Widget refresh channel identity".into())
                })?;
                Ok(WidgetRefresh {
                    delivery_id: row.try_get("delivery_id")?,
                    channel_id,
                    coalesce_order: row.try_get("acceptance_order")?,
                    accepted_at: row.try_get("accepted_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .transpose()?;
        self.health.ensure()?;
        tx.commit().await?;
        Ok(refresh)
    }

    pub(crate) async fn complete_widget_refresh(
        &self,
        delivery_id: &str,
        coalesce_order: i64,
    ) -> Result<bool> {
        let _gate = self.gate.lock().await;
        self.health.ensure()?;
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let changed = sqlx::query(
            "DELETE FROM ordinary_widget_refresh WHERE delivery_id=$1 AND acceptance_order=$2",
        )
        .bind(delivery_id)
        .bind(coalesce_order)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;
        self.health.ensure()?;
        if let Err(error) = tx.commit().await {
            self.fail_closed("PostgreSQL Widget refresh completion COMMIT failed or unknown");
            return Err(error.into());
        }
        Ok(changed)
    }

    /// Bounded canonical projection, not a new frozen ordinary recipient set.
    /// Keyset filtering precedes DISTINCT so every returned platform/token is
    /// unique while only one page is loaded into the process.
    pub(crate) async fn widget_refresh_targets(
        &self,
        channel_id: [u8; 16],
        after: Option<&WidgetRefreshCursor>,
        limit: usize,
    ) -> Result<Vec<WidgetRefreshTarget>> {
        if !(1..=128).contains(&limit) {
            return Err(KernelError::Invalid("Widget refresh page limit".into()));
        }
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let rows = sqlx::query(
            "WITH candidates AS (SELECT w.device_key, \
               CASE lower(btrim(w.platform)) WHEN 'ipados' THEN 'ios' ELSE lower(btrim(w.platform)) END AS platform, \
               w.token,w.updated_at,w.widget_kind,w.family \
             FROM widget_push_subscriptions w \
             WHERE lower(btrim(w.platform)) IN ('ios','ipados','macos','watchos') \
              AND w.widget_kind IN ($5,$6) \
              AND EXISTS(SELECT 1 FROM devices d JOIN channel_subscriptions s ON s.device_id=d.device_id \
               WHERE d.device_key=w.device_key AND s.channel_id=$1 AND s.status='active')) \
             SELECT DISTINCT ON(platform COLLATE \"C\",token COLLATE \"C\") device_key,platform,token \
             FROM candidates WHERE ($2::text IS NULL OR (platform COLLATE \"C\",token COLLATE \"C\")>($2::text COLLATE \"C\",$3::text COLLATE \"C\")) \
             ORDER BY platform COLLATE \"C\",token COLLATE \"C\",updated_at DESC,widget_kind COLLATE \"C\",family COLLATE \"C\",device_key COLLATE \"C\" LIMIT $4",
        )
        .bind(channel_id.as_slice())
        .bind(after.map(|cursor| cursor.platform.as_str()))
        .bind(after.map(|cursor| cursor.token.as_str()))
        .bind(limit as i64)
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_UNREAD)
        .bind(crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY)
        .fetch_all(&mut *tx)
        .await?;
        let targets = rows
            .into_iter()
            .map(|row| {
                let platform: String = row.try_get("platform")?;
                let platform = platform.parse().map_err(|_| {
                    KernelError::Invalid("invalid canonical Widget platform".into())
                })?;
                Ok(WidgetRefreshTarget {
                    device_key: row.try_get("device_key")?,
                    platform,
                    token: row.try_get("token")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.health.ensure()?;
        tx.commit().await?;
        Ok(targets)
    }

    /// Called by the normal Storage enqueue operation while it owns the shared
    /// write gate. Do not acquire that gate recursively for this read.
    pub(crate) async fn widget_refresh_job_order(&self, job_id: &str) -> Result<Option<i64>> {
        let mut connection = self.acquire().await?;
        let mut tx = Self::begin_ordinary(&mut connection).await?;
        let order = sqlx::query_scalar(
            "SELECT coalesce_order FROM provider_dispatch_outbox WHERE job_id=$1",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?;
        self.health.ensure()?;
        tx.commit().await?;
        Ok(order)
    }

    pub(super) async fn release_acked_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        device: &str,
        id: &str,
        profile_path: Path,
    ) -> Result<()> {
        // A completed client ACK is positive delivery evidence, independent of
        // whether a provider was attempted. Do not count it as provider acceptance.
        self.refresh_provider_status_tx(tx, id, profile_path)
            .await?;
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget, sqlx::query("DELETE FROM ordinary_targets WHERE delivery_id=$1 AND (device_key=$2 OR acked_at IS NOT NULL) AND acked_at IS NOT NULL AND state!='running'").bind(id).bind(device).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload, sqlx::query("UPDATE ordinary_messages SET payload_blob=''::bytea,payload_bytes=0 WHERE delivery_id=$1 AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND acked_at IS NULL)").bind(id).execute(&mut **tx)).await?;
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
            .phase(
                Path::Maintenance,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
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
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        at: i64,
    ) -> Result<usize> {
        self.retire_token_targets_tx(tx).await?;
        sqlx::query("DELETE FROM ordinary_widget_refresh WHERE delivery_id IN (SELECT delivery_id FROM ordinary_widget_refresh WHERE expires_at<=$1 ORDER BY expires_at,delivery_id LIMIT 256)")
            .bind(at).execute(&mut **tx).await?;
        // Canonical controls are owned and cleaned by normal Storage. A
        // deleted route is not a second device history in the ordinary ledger.
        // Retire at most one bounded orphan target batch per maintenance turn.
        let orphans: Vec<String> = sqlx::query_scalar("SELECT DISTINCT t.pull_owner FROM ordinary_targets t WHERE t.acked_at IS NULL AND NOT EXISTS(SELECT 1 FROM ordinary_device_routes d WHERE d.device_key=t.pull_owner) ORDER BY t.pull_owner LIMIT 256")
            .fetch_all(&mut **tx).await?;
        let mut remaining = 256;
        for key in orphans {
            if remaining == 0 {
                break;
            }
            remaining -= self.retire_targets_tx(tx, &key, at, remaining).await?;
        }
        // Expiry is a terminal failure only for targets not yet accepted by a
        // provider. Running attempts retain their unknown outcome until receipt.
        // Capture one bounded keyset once. Repeating LIMIT selections across
        // writes can choose different equal-expiry rows after MVCC updates.
        let expiring: Vec<String> = self.counters.profile.sql(
            Path::Maintenance, Statement::MaintenanceExpiryCount,
            sqlx::query_scalar("SELECT delivery_id FROM ordinary_messages WHERE expires_at<=$1 AND payload_bytes>0 ORDER BY expires_at,delivery_id LIMIT 256 FOR UPDATE")
                .bind(at).fetch_all(&mut **tx),
        ).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryCount, sqlx::query("UPDATE ordinary_messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND delivery_mode='provider' AND provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryAck, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id=ANY($2)").bind(at).bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryStatus, sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=$1 WHERE status='provider_queued' AND provider_failed_count>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets outstanding WHERE outstanding.delivery_id=ordinary_messages.delivery_id AND outstanding.provider IN ('FCM','APNS','WNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait')))) AND delivery_id=ANY($2)").bind(at).bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryDelete, sqlx::query("DELETE FROM ordinary_targets WHERE acked_at IS NOT NULL AND state!='running' AND delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryPayload, sqlx::query("UPDATE ordinary_messages SET payload_blob=''::bytea,payload_bytes=0 WHERE payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND acked_at IS NULL) AND delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetention, sqlx::query("DELETE FROM ordinary_messages WHERE op_id IN (SELECT op_id FROM ordinary_messages WHERE dedupe_until<=$1 AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets WHERE ordinary_targets.delivery_id=ordinary_messages.delivery_id AND state='running') ORDER BY dedupe_until,op_id LIMIT 256)").bind(at).execute(&mut **tx)).await?.rows_affected();
        Ok(removed as usize)
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
            .phase(Path::Ack, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
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
            let id: String = row.get("delivery_id");
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            self.counters.sql(1);
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=$1 WHERE delivery_mode='provider' AND pull_owner=$2 AND delivery_id=$3 AND acked_at IS NULL")
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
            .phase(
                Path::Ack,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
            .await?;
        Self::lock_usage(&mut tx).await?;
        let mut removed = 0;
        let at = now();
        for id in ids {
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=$1 WHERE delivery_mode='provider' AND pull_owner=$2 AND delivery_id=$3 AND acked_at IS NULL AND EXISTS(SELECT 1 FROM ordinary_device_routes WHERE ordinary_device_routes.device_key=ordinary_targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM ordinary_messages WHERE ordinary_messages.delivery_id=ordinary_targets.delivery_id AND expires_at>$4) AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=ordinary_targets.platform AND r.provider_token=ordinary_targets.provider_token AND ordinary_targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
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
            .phase(
                Path::Claim,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
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
                    "SELECT next_attempt_at FROM ordinary_provider_cooldowns WHERE provider=$1",
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
                    let row=self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.*,m.payload_blob,m.expires_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.delivery_mode='provider' AND d.retired_at IS NULL AND t.provider=$1 AND t.state=$2 AND t.acked_at IS NULL AND t.next_attempt_at<=$3 AND m.expires_at>$4 AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx)).await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get("delivery_id");
                let device: String = row.get("device_key");
                self.counters.sql(1);
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=$1 AND device_key=$2").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
                let _compute = self.counters.profile.timer(Path::Claim, Phase::Compute);
                tickets.push(Ticket {
                    delivery_id: delivery,
                    device_key: device,
                    platform: row.get("platform"),
                    provider: row.get("provider"),
                    token: row.get("provider_token"),
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
        let due:Option<i64>=self.counters.profile.sql(Path::Claim, Statement::ClaimNextDue, sqlx::query_scalar("SELECT MIN(next_attempt_at) FROM ordinary_targets WHERE delivery_mode='provider' AND provider=$1 AND state IN ('pending','retry_wait') AND acked_at IS NULL").bind(provider).fetch_one(&mut *tx)).await?;
        let retiring: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.acked_at IS NULL AND NOT EXISTS(SELECT 1 FROM ordinary_device_routes d WHERE d.device_key=t.pull_owner))")
            .fetch_one(&mut *tx).await?;
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
            self.counters.profile.sql(Path::Claim, Statement::Read, sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_mode='provider' AND t.delivery_id=$1 AND t.device_key=$2 AND t.state='running' AND t.attempt_id=$3 AND t.acked_at IS NULL AND m.expires_at>$4 AND d.retired_at IS NULL AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.owner_generation AND t.route_generation=$5 AND NOT EXISTS(SELECT 1 FROM ordinary_retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&mut *profile_read_connection)).await
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
            .phase(
                Path::Receipt,
                Phase::Begin,
                Self::begin_ordinary(&mut profile_connection),
            )
            .await?;
        Self::lock_usage(&mut tx).await?;
        let state = if state == "retry_wait" && is_expired(ticket.expires_at, now()) {
            "permanent_failed"
        } else {
            state
        };
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE ordinary_targets SET state=CASE WHEN delivery_mode='private' AND $1 IN ('pending','retry_wait') THEN 'superseded_route' ELSE $1 END,provider_status=$2,provider_error=$3,receipt_at=$4,next_attempt_at=$5 WHERE delivery_id=$6 AND device_key=$7 AND state='running' AND attempt_id=$8").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO ordinary_provider_cooldowns(provider,next_attempt_at) VALUES($1,$2) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=GREATEST(ordinary_provider_cooldowns.next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                let storage_channel = channel_storage_key(
                    ticket
                        .payload
                        .get("channel_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            KernelError::Invalid("stored ordinary channel id is missing".into())
                        })?,
                )?;
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription,
                    sqlx::query("UPDATE channel_subscriptions s SET status='inactive',updated_at=$1 FROM devices d WHERE s.device_id=d.device_id AND d.device_key=$2 AND encode(s.channel_id,'hex')=$3 AND d.platform=$4 AND d.provider_token=$5 AND d.ordinary_route_generation=$6")
                        .bind(now()).bind(&ticket.device_key).bind(&storage_channel).bind(&ticket.platform).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE ordinary_messages SET provider_accepted_count=provider_accepted_count+$1,provider_failed_count=provider_failed_count+$2 WHERE delivery_id=$3").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
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
    pub async fn channel_info(&self, channel: &str) -> Result<Value> {
        let channel = crate::ordinary::sender::channel_id(channel)?;
        let key = channel_storage_key(&channel)?;
        let mut connection = self.acquire().await?;
        let name: Option<String> = sqlx::query_scalar(
            "SELECT channel_name FROM ordinary_channel_routes WHERE channel_id=$1",
        )
        .bind(key)
        .fetch_optional(&mut *connection)
        .await?;
        let mut result = json!({"channel_id":channel,"exists":name.is_some()});
        if let Some(name) = name {
            result["channel_name"] = name.into();
        }
        Ok(result)
    }
    pub async fn status(&self, op: &str) -> Result<Value> {
        let op = crate::ordinary::sender::op_id(op)?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until,identity_state,channel_id,thing_id FROM ordinary_messages WHERE op_id=$1 AND dedupe_until>$2").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
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
        let rows = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Read, Phase::PoolAcquire, self.acquire())
                .await?;
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM ordinary_messages m JOIN ordinary_targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=$1").bind(op).fetch_all(&mut *profile_read_connection)).await
        }?;
        Ok(
            json!({"targets":rows.iter().map(|r|json!({"delivery_id":r.get::<String,_>("delivery_id"),"state":r.get::<Option<String>,_>("state"),"provider_status":r.get::<Option<i64>,_>("provider_status"),"acked_at":r.get::<Option<i64>,_>("acked_at")})).collect::<Vec<_>>()}),
        )
    }
    pub(super) async fn retire_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        key: &str,
        at: i64,
        limit: usize,
    ) -> Result<usize> {
        let ids=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM ordinary_targets WHERE pull_owner=$1 AND acked_at IS NULL ORDER BY accepted_at,delivery_id LIMIT $2").bind(key).bind(limit as i64).fetch_all(&mut **tx)).await?;
        for row in &ids {
            let id: String = row.get("delivery_id");
            let original: String = row.get("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE device_key=$2 AND delivery_id=$3 AND acked_at IS NULL").bind(at).bind(&original).bind(&id).execute(&mut **tx)).await?;
            self.refresh_provider_status_tx(tx, &id, Path::Maintenance)
                .await?;
            self.release_acked_tx(tx, &original, &id, Path::Maintenance)
                .await?;
        }
        Ok(ids.len())
    }
    pub(super) async fn retire_token_targets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
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
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=$2 AND device_key=$3 AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("DELETE FROM ordinary_retired_provider_tokens WHERE (platform,provider_token) IN (SELECT r.platform,r.provider_token FROM ordinary_retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_mode='provider' AND t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256)").execute(&mut **tx)).await?;
        Ok(())
    }
}

/// Identity guards are evaluated before ordinary DDL and before public
/// ingress. JSON probes cover old pending work that outlived sender status.
const LEGACY_ORDINARY_GUARD_SQL: &str = r#"
 SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE model='message' AND expires_at>$1)
 OR EXISTS(SELECT 1 FROM semantic_id_registry WHERE dedupe_key ~ '^semantic:[^:]+:message:' AND (expires_at IS NULL OR expires_at>$1))
 OR EXISTS(SELECT 1 FROM dispatch_op_dedupe WHERE dedupe_key ~ '^op:[^:]+:message:' AND (expires_at IS NULL OR expires_at>$1))
 OR EXISTS(SELECT 1 FROM dispatch_submission WHERE (convert_from(payload_blob,'UTF8')::jsonb ->> 'entity_type')='message')
 OR EXISTS(SELECT 1 FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased') AND (convert_from(payload_blob,'UTF8')::jsonb #>> '{direct_payload,data,entity_type}'='message' OR convert_from(payload_blob,'UTF8')::jsonb #>> '{wakeup_payload,data,entity_type}'='message'))

"#;

impl PgDeliveryStore {
    /// Called only while normal Storage owns the shared mutation gate and its
    /// canonical control transaction. No nested connection or transaction exists.
    pub(crate) async fn canonical_route_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        device: &str,
        to_private: bool,
    ) -> crate::storage::StoreResult<()> {
        Self::lock_usage(tx).await.map_err(native_control_error)?;
        let result = self
            .transition_private_mode_tx(tx, device, to_private)
            .await;
        if let Err(error) = result {
            if matches!(
                &error,
                KernelError::Capacity | KernelError::Control { status: 409, .. }
            ) {
                let pending: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT t.delivery_id) FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=$1 AND t.acked_at IS NULL AND t.delivery_mode='provider' AND m.expires_at>$2")
                    .bind(device).bind(now()).fetch_one(&mut **tx).await?;
                let existing: i64 = sqlx::query_scalar("SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=$1),0)+(SELECT COUNT(*) FROM private_outbox o JOIN devices d ON d.device_id=o.device_id WHERE d.device_key=$1 AND o.status IN ('pending','claimed','sent'))")
                    .bind(device).fetch_one(&mut **tx).await?;
                let global: i64 = sqlx::query_scalar("SELECT private_pending+(SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')) FROM ordinary_ledger_usage WHERE singleton=1")
                    .fetch_one(&mut **tx).await?;
                let capacity = self
                    .config
                    .private
                    .max_pending_per_device
                    .saturating_sub(existing.max(0) as usize)
                    .min(
                        self.config
                            .private
                            .max_pending
                            .saturating_sub(global.max(0) as usize),
                    );
                return Err(crate::storage::StoreError::RouteMigrationCapacityExceeded {
                    pending: pending.max(0) as usize,
                    capacity,
                });
            }
            return Err(native_control_error(error));
        }
        Ok(())
    }

    /// Identity merging transfers retained consumers, never frozen wire attempts.
    pub(crate) async fn canonical_coalesce_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        loser: &str,
        winner: &str,
        to_private: bool,
    ) -> crate::storage::StoreResult<()> {
        if loser == winner {
            return Ok(());
        }
        Self::lock_usage(tx).await.map_err(native_control_error)?;
        // Fence overlapping winner capabilities before canonical receipt ownership
        // changes; old sessions must not complete a now-different logical item.
        sqlx::query("UPDATE ordinary_targets SET delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL WHERE pull_owner=$1 AND acked_at IS NULL AND delivery_id IN (SELECT delivery_id FROM ordinary_targets WHERE pull_owner=$2 AND acked_at IS NULL)")
            .bind(winner).bind(loser).execute(&mut **tx).await?;
        sqlx::query("UPDATE ordinary_targets SET pull_owner=$1,owner_generation=-1,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN delivery_mode='private' AND state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=$2")
            .bind(winner).bind(loser).execute(&mut **tx).await?;
        self.canonical_route_tx(tx, winner, to_private).await
    }

    pub(crate) async fn canonical_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        key: &str,
    ) -> crate::storage::StoreResult<()> {
        Self::lock_usage(tx).await.map_err(native_control_error)?;
        while self
            .retire_targets_tx(tx, key, now(), 256)
            .await
            .map_err(native_control_error)?
            == 256
        {}
        Ok(())
    }

    pub(crate) async fn canonical_clear_private_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        key: &str,
    ) -> crate::storage::StoreResult<()> {
        Self::lock_usage(tx).await.map_err(native_control_error)?;
        loop {
            let rows = sqlx::query("SELECT delivery_id,device_key FROM ordinary_targets WHERE pull_owner=$1 AND delivery_mode='private' AND acked_at IS NULL ORDER BY accepted_at,delivery_id,device_key LIMIT 256 FOR UPDATE")
                .bind(key).fetch_all(&mut **tx).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let delivery: String = row.get("delivery_id");
                let frozen_owner: String = row.get("device_key");
                sqlx::query("UPDATE ordinary_targets SET acked_at=$1,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=$2 AND device_key=$3 AND delivery_mode='private' AND acked_at IS NULL")
                    .bind(now()).bind(&delivery).bind(&frozen_owner).execute(&mut **tx).await?;
                self.release_acked_tx(tx, &frozen_owner, &delivery, Path::Control)
                    .await
                    .map_err(native_control_error)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn canonical_retire_token_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        platform: &str,
        token: &str,
    ) -> crate::storage::StoreResult<()> {
        Self::lock_usage(tx).await.map_err(native_control_error)?;
        sqlx::query(
            "UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1",
        )
        .execute(&mut **tx)
        .await?;
        sqlx::query("INSERT INTO ordinary_retired_provider_tokens(platform,provider_token,control_epoch) SELECT $1,$2,control_epoch FROM ordinary_ledger_usage WHERE singleton=1 ON CONFLICT(platform,provider_token) DO UPDATE SET control_epoch=excluded.control_epoch")
            .bind(platform).bind(token).execute(&mut **tx).await?;
        Ok(())
    }
}

fn native_control_error(error: KernelError) -> crate::storage::StoreError {
    match error {
        KernelError::Database(error) => crate::storage::StoreError::Sqlx(error),
        other => crate::storage::StoreError::Ordinary(other),
    }
}

async fn legacy_ordinary_present(pool: &PgPool) -> Result<bool> {
    let at = now();
    let identity_or_provider: bool = sqlx::query_scalar(LEGACY_ORDINARY_GUARD_SQL)
        .bind(at)
        .fetch_one(pool)
        .await?;
    if identity_or_provider {
        return Ok(true);
    }
    let mut cursor = String::new();
    loop {
        let rows = sqlx::query("SELECT p.delivery_id,p.payload_blob FROM private_payloads p WHERE p.delivery_id>$1 AND p.expires_at>$2 AND (EXISTS(SELECT 1 FROM private_outbox o WHERE o.delivery_id=p.delivery_id AND o.status IN ('pending','claimed','sent')) OR EXISTS(SELECT 1 FROM provider_pull_queue q WHERE q.delivery_id=p.delivery_id AND q.expires_at>$2 AND octet_length(q.payload_blob)=0)) ORDER BY p.delivery_id LIMIT 64")
            .bind(&cursor).bind(at).fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.get("delivery_id");
            let bytes: Vec<u8> = row.get("payload_blob");
            if crate::ordinary::legacy::payload_is_ordinary(&bytes)? {
                return Ok(true);
            }
        }
    }
    let mut owner: Vec<u8> = Vec::new();
    cursor.clear();
    loop {
        let rows = sqlx::query("SELECT device_id,delivery_id,payload_blob FROM provider_pull_queue WHERE (device_id,delivery_id)>($1,$2) AND expires_at>$3 AND octet_length(payload_blob)>0 ORDER BY device_id,delivery_id LIMIT 64")
            .bind(&owner).bind(&cursor).bind(at).fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            owner = row.get("device_id");
            cursor = row.get("delivery_id");
            let bytes: Vec<u8> = row.get("payload_blob");
            if crate::ordinary::legacy::payload_is_ordinary(&bytes)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

impl PgDeliveryStore {
    pub(crate) async fn private_route_capacity(&self, device: &str) -> Result<(i64, i64)> {
        if !self.config.private.enabled {
            return Ok((0, i64::MAX));
        }
        let mut connection = self.acquire().await?;
        let existing: i64 = sqlx::query_scalar("SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=$1),0)+(SELECT COUNT(*) FROM private_outbox o JOIN devices d ON d.device_id=o.device_id WHERE d.device_key=$1 AND o.status IN ('pending','claimed','sent'))")
            .bind(device).fetch_one(&mut *connection).await?;
        let additional: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT t.delivery_id) FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=$1 AND t.delivery_mode='provider' AND t.acked_at IS NULL AND m.expires_at>$2 AND NOT EXISTS(SELECT 1 FROM ordinary_targets p WHERE p.pull_owner=t.pull_owner AND p.delivery_id=t.delivery_id AND p.delivery_mode='private' AND p.acked_at IS NULL)")
            .bind(device).bind(now()).fetch_one(&mut *connection).await?;
        let global: i64 = sqlx::query_scalar("SELECT private_pending+(SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')) FROM ordinary_ledger_usage WHERE singleton=1")
            .fetch_one(&mut *connection).await?;
        let device_limit =
            i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
        let global_limit = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
        Ok((
            existing.saturating_add(additional),
            device_limit
                .min(global_limit.saturating_sub(global.saturating_sub(existing)))
                .max(0),
        ))
    }

    pub(crate) async fn active_provider_count(&self) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE delivery_mode='provider' AND provider IN ('FCM','APNS','WNS') AND acked_at IS NULL AND state IN ('pending','running','retry_wait')")
            .fetch_one(&mut *connection).await?;
        Ok(count.max(0))
    }
    #[cfg(test)]
    pub(crate) async fn private_pending_count(&self, device: Option<&str>) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let count: i64 = match device {
            Some(key) => sqlx::query_scalar("SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=$1),0)").bind(key).fetch_one(&mut *connection).await?,
            None => sqlx::query_scalar("SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1").fetch_one(&mut *connection).await?,
        };
        Ok(count.max(0))
    }

    /// Read-only C share of the device/global execution window. Waiting targets
    /// remain system target responsibility, not this issued-grant count.
    pub(crate) async fn private_executing_count(&self, device: Option<&str>) -> Result<i64> {
        let mut connection = self.acquire().await?;
        let count: i64 = match device {
            Some(device) => sqlx::query_scalar(
                "SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE pull_owner=$1 \
                 AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL",
            )
            .bind(device)
            .fetch_one(&mut *connection)
            .await?,
            None => {
                sqlx::query_scalar(
                    "SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE \
                 delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL",
                )
                .fetch_one(&mut *connection)
                .await?
            }
        };
        Ok(count.max(0))
    }
}
