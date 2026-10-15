//! PostgreSQL ordinary-message ledger. One pinned physical session owns both
//! the advisory lock and all SQL; it is never replaced or reconnected.
use crate::profiling::{Path, Phase, Statement};
use crate::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, Health, KernelError, OwnerLock, Result,
    Ticket, now, record_duration, verify_password_async,
};
use crate::types::generate_hex_id_128;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, Postgres, Row, Transaction};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::{Mutex, MutexGuard, Notify};
#[derive(Clone)]
pub struct PgDeliveryStore {
    pub(super) connection: Arc<Mutex<Option<PgConnection>>>,
    pub(super) gate: Arc<Mutex<()>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 2],
    pub(super) health: Arc<Health>,
}
pub(super) struct PgGuard<'a>(MutexGuard<'a, Option<PgConnection>>);
impl Deref for PgGuard<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &PgConnection {
        self.0.as_ref().expect("checked pinned connection")
    }
}
impl DerefMut for PgGuard<'_> {
    fn deref_mut(&mut self) -> &mut PgConnection {
        self.0.as_mut().expect("checked pinned connection")
    }
}
struct AdmissionWake(PgDeliveryStore);
impl Drop for AdmissionWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
pub(super) const PULL_BATCH_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=$1 AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>$2 AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) AND NOT EXISTS(SELECT 1 FROM targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='provider' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=sibling.platform AND r.provider_token=sibling.provider_token AND sibling.control_epoch<r.control_epoch)) ORDER BY t.accepted_at,t.delivery_id LIMIT $3";
pub(super) const PULL_EXACT_SQL: &str = "SELECT t.delivery_id,m.payload_blob FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=$1 AND t.delivery_id=$2 AND t.delivery_mode='provider' AND t.acked_at IS NULL AND d.retired_at IS NULL AND m.expires_at>$3 AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) LIMIT 1";
pub(super) const RECOVER_RUNNING_SQL: &str = "UPDATE targets SET state=CASE WHEN delivery_mode='private' THEN 'superseded_route' ELSE 'retry_wait' END,next_attempt_at=$1 WHERE provider=$2 AND state='running'";
// Markers are normally empty. Keep them outside the join so idle maintenance
// never scans every retained target; the existing index bounds each token probe.
// Matching retirement work and its ORDER BY remain data dependent.
pub(super) const RETIRE_TOKEN_TARGETS_SQL: &str = "SELECT t.delivery_id,t.device_key FROM retired_provider_tokens r JOIN targets t ON r.platform=t.platform AND r.provider_token=t.provider_token WHERE t.delivery_mode='provider' AND t.control_epoch<r.control_epoch AND t.acked_at IS NULL ORDER BY t.accepted_at,t.delivery_id,t.device_key LIMIT 256";

impl PgDeliveryStore {
    pub(super) async fn acquire(&self) -> Result<PgGuard<'_>> {
        let guard = self.connection.lock().await;
        self.health.ensure()?;
        if guard.is_none() {
            return Err(KernelError::Invalid(
                "PostgreSQL owner connection closed".into(),
            ));
        }
        Ok(PgGuard(guard))
    }
    pub(super) async fn lock_usage(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query("SELECT singleton FROM ledger_usage WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
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
            || (config.private.enabled
                && (config.private.max_pending_per_device == 0
                    || config.private.max_pending == 0
                    || i64::try_from(config.private.max_pending_per_device).is_err()
                    || i64::try_from(config.private.max_pending).is_err()))
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
            PgConnection::connect(db_url),
        )
        .await
        .map_err(|_| {
            KernelError::Database(sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "PostgreSQL owner connection timed out",
            )))
        })??;
        // Fixed namespace, fixed private schema: URL/user aliases cannot obtain
        // a second session owner for this database's ordinary ledger.
        let owned: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(1346852687,1129271876)")
            .fetch_one(&mut connection)
            .await?;
        if !owned {
            return Err(KernelError::OwnerContention);
        }
        sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS pushgo_c; SET search_path TO pushgo_c,pg_catalog; SET lock_timeout='3s'; SET synchronous_commit=on; SET default_transaction_isolation TO 'read committed'; CREATE TABLE IF NOT EXISTS authority_metadata(singleton BIGINT PRIMARY KEY CHECK(singleton=1),dataset_uuid TEXT NOT NULL UNIQUE,schema_version BIGINT NOT NULL)").execute(&mut connection).await?;
        let hex = generate_hex_id_128();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        sqlx::query("INSERT INTO authority_metadata(singleton,dataset_uuid,schema_version) VALUES(1,$1,2) ON CONFLICT(singleton) DO NOTHING").bind(uuid).execute(&mut connection).await?;
        let (uuid, version): (String, i64) = sqlx::query_as(
            "SELECT dataset_uuid,schema_version FROM authority_metadata WHERE singleton=1",
        )
        .fetch_one(&mut connection)
        .await?;
        if version != 2
            || uuid.len() != 36
            || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(KernelError::Invalid(
                "unsupported PG authority metadata".into(),
            ));
        }
        let owner_path = pg_owner_path(&uuid)?;
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
    async fn initialize(&self) -> Result<()> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await?;
        sqlx::raw_sql(include_str!("pg_schema.sql"))
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(crate::pg_private::PRIVATE_USAGE_SCHEMA)
            .execute(&mut *tx)
            .await?;
        Self::lock_usage(&mut tx).await?;
        while self.recover_private_claims_tx(&mut tx).await? == 256 {}
        for provider in ["FCM", "APNS"] {
            sqlx::query("DELETE FROM targets WHERE provider=$1 AND state='running' AND acked_at IS NOT NULL").bind(provider).execute(&mut *tx).await?;
            sqlx::query(RECOVER_RUNNING_SQL)
                .bind(now())
                .bind(provider)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE messages SET status=CASE WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=$1 WHERE status='provider_queued' AND NOT EXISTS(SELECT 1 FROM targets outstanding WHERE outstanding.delivery_id=messages.delivery_id AND outstanding.provider IN ('FCM','APNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait'))))").bind(now()).execute(&mut *tx).await?;
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
                sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=$1")
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
        if let Some(row)=self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("SELECT delivery_id,message_id,channel_id,fingerprint,provider_target_count,private_enqueued_count FROM messages WHERE op_id=$1 AND dedupe_until>$2").bind(&request.op_id).bind(at).fetch_optional(&mut *tx)).await? {
            if row.get::<String,_>("channel_id")!=request.channel_id {return Err(KernelError::ScopeConflict)}
            if row.get::<String,_>("fingerprint")!=request.fingerprint {return Err(KernelError::Conflict)}
            return Ok(Accepted{delivery_id:row.get("delivery_id"),message_id:row.get("message_id"),op_id:request.op_id,acceptance:"duplicate_completed",dispatch_status:if row.get::<i64,_>("private_enqueued_count")>0 && row.get::<i64,_>("provider_target_count")==0 {"attempted_accepted"}else{"provider_queued"}})
        }
        // An exact expired identity can be replaced even if bounded GC has backlog.
        self.counters.profile.sql(Path::Accept, Statement::Dedupe, sqlx::query("DELETE FROM messages WHERE op_id=$1 AND dedupe_until<=$2 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running')").bind(&request.op_id).bind(at).execute(&mut *tx)).await?;
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
        let provider_fanout:i64=self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=$1 AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&request.channel_id).fetch_one(&mut *tx)).await?;
        let private_fanout = if expires > at {
            self.check_private_admission_tx(&mut tx, &request.channel_id)
                .await?
        } else {
            0
        };
        let fanout = provider_fanout.saturating_add(private_fanout);
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
        let status = if !live {
            "failed"
        } else if provider_fanout > 0 {
            "provider_queued"
        } else {
            "sent"
        };
        let dispatch_status = if live && private_fanout > 0 && provider_fanout == 0 {
            "attempted_accepted"
        } else {
            "provider_queued"
        };
        self.counters.profile.sql(Path::Accept, Statement::MessageInsert, sqlx::query("INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,provider_target_count,private_enqueued_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)").bind(&delivery_id).bind(&message_id).bind(&request.op_id).bind(&request.channel_id).bind(&request.fingerprint).bind(if live{payload.as_slice()}else{&[]}).bind(if live{payload.len() as i64}else{0}).bind(at).bind(expires).bind(at.saturating_add(self.config.dedupe_retention_ms)).bind(status).bind(at).bind(if live {provider_fanout}else{0}).bind(if live {private_fanout}else{0}).execute(&mut *tx)).await?;
        if live {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at) SELECT $1,d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,$2,'pending',$3 FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=$4 AND d.retired_at IS NULL AND d.provider IN ('FCM','APNS') AND d.provider_token IS NOT NULL").bind(&delivery_id).bind(at).bind(at).bind(&request.channel_id).execute(&mut *tx)).await?;
        }
        if live && private_fanout > 0 {
            self.counters.profile.sql(Path::Fanout, Statement::FanoutInsert, sqlx::query("INSERT INTO targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at,delivery_mode) SELECT $1,d.device_key,d.device_key,d.route_generation,(SELECT control_epoch FROM ledger_usage WHERE singleton=1),d.platform,'PRIVATE','',d.route_generation,$2,'superseded_route',$3,'private' FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=$4 AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(&delivery_id).bind(at).bind(at).bind(&request.channel_id).execute(&mut *tx)).await?;
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
        self.counters.profile.sql(profile_path, Statement::ReleaseTarget, sqlx::query("DELETE FROM targets WHERE delivery_id=$1 AND (device_key=$2 OR acked_at IS NOT NULL) AND acked_at IS NOT NULL AND state!='running'").bind(id).bind(device).execute(&mut **tx)).await?;
        self.counters.profile.sql(profile_path, Statement::ReleasePayload, sqlx::query("UPDATE messages SET payload_blob=''::bytea,payload_bytes=0 WHERE delivery_id=$1 AND payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL)").bind(id).execute(&mut **tx)).await?;
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
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        at: i64,
    ) -> Result<usize> {
        self.retire_token_targets_tx(tx).await?;
        let retired:Vec<String>=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetired, sqlx::query_scalar("SELECT device_key FROM devices WHERE retired_at IS NOT NULL AND coalesced_to IS NULL ORDER BY retired_at LIMIT 256").fetch_all(&mut **tx)).await?;
        let mut remaining = 256;
        let mut subscriptions_remaining = 256;
        for key in retired {
            if subscriptions_remaining > 0 {
                let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceSubscriptions, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=$1 AND channel_id IN (SELECT channel_id FROM channel_subscriptions WHERE device_key=$2 ORDER BY channel_id LIMIT $3)").bind(&key).bind(&key).bind(subscriptions_remaining as i64).execute(&mut **tx)).await?.rows_affected() as usize;
                subscriptions_remaining -= removed;
            }
            if remaining > 0 {
                remaining -= self.retire_targets_tx(tx, &key, at, remaining).await?;
            }
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceSubscriptions, sqlx::query("DELETE FROM devices WHERE device_key=$1 AND retired_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.device_key=devices.device_key AND acked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM targets WHERE provider IN ('FCM','APNS') AND state='running' AND targets.device_key=devices.device_key) AND NOT EXISTS(SELECT 1 FROM channel_subscriptions WHERE channel_subscriptions.device_key=devices.device_key)").bind(key).execute(&mut **tx)).await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceDevice, sqlx::query("DELETE FROM devices WHERE device_key IN (SELECT d.device_key FROM devices d WHERE d.coalesced_to IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets t WHERE t.device_key=d.device_key OR t.pull_owner=d.device_key) LIMIT 256)").execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceAliases, sqlx::query("DELETE FROM registration_aliases WHERE old_key IN (SELECT old_key FROM registration_aliases WHERE expires_at<$1 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut **tx)).await?;
        // Expiry is a terminal failure only for targets not yet accepted by a
        // provider. Running attempts retain their unknown outcome until receipt.
        // Capture one bounded keyset once. Repeating LIMIT selections across
        // writes can choose different equal-expiry rows after MVCC updates.
        let expiring: Vec<String> = self.counters.profile.sql(
            Path::Maintenance, Statement::MaintenanceExpiryCount,
            sqlx::query_scalar("SELECT delivery_id FROM messages WHERE expires_at<=$1 AND payload_bytes>0 ORDER BY expires_at,delivery_id LIMIT 256 FOR UPDATE")
                .bind(at).fetch_all(&mut **tx),
        ).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryCount, sqlx::query("UPDATE messages SET provider_failed_count=provider_failed_count+(SELECT COUNT(*) FROM targets WHERE targets.delivery_id=messages.delivery_id AND delivery_mode='provider' AND provider IN ('FCM','APNS') AND acked_at IS NULL AND state IN ('pending','retry_wait')) WHERE delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryAck, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state IN ('pending','retry_wait') THEN 'expired' ELSE state END WHERE acked_at IS NULL AND delivery_id=ANY($2)").bind(at).bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryStatus, sqlx::query("UPDATE messages SET status=CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END,updated_at=$1 WHERE status='provider_queued' AND provider_failed_count>0 AND NOT EXISTS(SELECT 1 FROM targets outstanding WHERE outstanding.delivery_id=messages.delivery_id AND outstanding.provider IN ('FCM','APNS') AND (outstanding.state='running' OR (outstanding.delivery_mode='provider' AND outstanding.acked_at IS NULL AND outstanding.state IN ('pending','retry_wait')))) AND delivery_id=ANY($2)").bind(at).bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryDelete, sqlx::query("DELETE FROM targets WHERE acked_at IS NOT NULL AND state!='running' AND delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceExpiryPayload, sqlx::query("UPDATE messages SET payload_blob=''::bytea,payload_bytes=0 WHERE payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND acked_at IS NULL) AND delivery_id=ANY($1)").bind(&expiring).execute(&mut **tx)).await?;
        let removed=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceRetention, sqlx::query("DELETE FROM messages WHERE delivery_id IN (SELECT delivery_id FROM messages WHERE dedupe_until<=$1 AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') ORDER BY dedupe_until LIMIT 256)").bind(at).execute(&mut **tx)).await?.rows_affected();
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
            let id: String = row.get("delivery_id");
            let payload: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob"))?;
            self.counters.sql(1);
            self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL,acked_at=$1 WHERE delivery_mode='provider' AND pull_owner=$2 AND delivery_id=$3 AND acked_at IS NULL")
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
            removed+=usize::from(self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL,acked_at=$1 WHERE delivery_mode='provider' AND pull_owner=$2 AND delivery_id=$3 AND acked_at IS NULL AND EXISTS(SELECT 1 FROM devices WHERE devices.device_key=targets.pull_owner AND retired_at IS NULL) AND EXISTS(SELECT 1 FROM messages WHERE messages.delivery_id=targets.delivery_id AND expires_at>$4) AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=targets.platform AND r.provider_token=targets.provider_token AND targets.control_epoch<r.control_epoch)").bind(at).bind(device).bind(&id).bind(at).execute(&mut *tx)).await?.rows_affected()>0);
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
                    "SELECT next_attempt_at FROM provider_cooldowns WHERE provider=$1",
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
                    let row=self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.*,m.payload_blob,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.delivery_mode='provider' AND d.retired_at IS NULL AND t.provider=$1 AND t.state=$2 AND t.acked_at IS NULL AND t.next_attempt_at<=$3 AND m.expires_at>$4 AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1").bind(provider).bind(class).bind(at).bind(at).fetch_optional(&mut *tx)).await?;
                    if row.is_some() {
                        selected = row;
                        break;
                    }
                }
                let Some(row) = selected else { break };
                let delivery: String = row.get("delivery_id");
                let device: String = row.get("device_key");
                self.counters.sql(1);
                self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE targets SET state='running',attempts=attempts+1,attempt_id=attempt_id+1 WHERE delivery_id=$1 AND device_key=$2").bind(&delivery).bind(&device).execute(&mut *tx)).await?;
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
        let due:Option<i64>=self.counters.profile.sql(Path::Claim, Statement::ClaimNextDue, sqlx::query_scalar("SELECT MIN(next_attempt_at) FROM targets WHERE delivery_mode='provider' AND provider=$1 AND state IN ('pending','retry_wait') AND acked_at IS NULL").bind(provider).fetch_one(&mut *tx)).await?;
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
            self.counters.profile.sql(Path::Claim, Statement::Read, sqlx::query_scalar("SELECT COUNT(*) FROM targets t JOIN devices d ON d.device_key=t.pull_owner JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_mode='provider' AND t.delivery_id=$1 AND t.device_key=$2 AND t.state='running' AND t.attempt_id=$3 AND t.acked_at IS NULL AND m.expires_at>$4 AND d.retired_at IS NULL AND d.platform=t.platform AND d.provider=t.provider AND d.provider_token=t.provider_token AND d.route_generation=t.owner_generation AND t.route_generation=$5 AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch)").bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).bind(now()).bind(ticket.route_generation).fetch_one(&mut *profile_read_connection)).await
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
        let changed=self.counters.profile.sql(Path::Receipt, Statement::ReceiptTarget, sqlx::query("UPDATE targets SET state=CASE WHEN delivery_mode='private' AND $1 IN ('pending','retry_wait') THEN 'superseded_route' ELSE $1 END,provider_status=$2,provider_error=$3,receipt_at=$4,next_attempt_at=$5 WHERE delivery_id=$6 AND device_key=$7 AND state='running' AND attempt_id=$8").bind(state).bind(i64::from(status)).bind(error).bind(now()).bind(next_due).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(ticket.attempt_id).execute(&mut *tx)).await?.rows_affected();
        if let Some(due) = cooldown {
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCooldown, sqlx::query("INSERT INTO provider_cooldowns(provider,next_attempt_at) VALUES($1,$2) ON CONFLICT(provider) DO UPDATE SET next_attempt_at=GREATEST(provider_cooldowns.next_attempt_at,excluded.next_attempt_at)").bind(&ticket.provider).bind(due).execute(&mut *tx)).await?;
        }
        if changed > 0 {
            // Invalidate only this channel's subscription for the exact frozen
            // route. A token that changes A -> B -> A is a different generation.
            if error == "invalid_token" {
                self.counters.profile.sql(Path::Receipt, Statement::ReceiptSubscription, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=$1 AND channel_id=(SELECT channel_id FROM messages WHERE delivery_id=$2) AND EXISTS(SELECT 1 FROM devices WHERE device_key=$3 AND retired_at IS NULL AND platform=$4 AND provider=$5 AND provider_token=$6 AND route_generation=$7)")
                    .bind(&ticket.device_key).bind(&ticket.delivery_id).bind(&ticket.device_key).bind(&ticket.platform).bind(&ticket.provider).bind(&ticket.token).bind(ticket.route_generation).execute(&mut *tx)).await?;
            }
            self.counters.profile.sql(Path::Receipt, Statement::ReceiptCounts, sqlx::query("UPDATE messages SET provider_accepted_count=provider_accepted_count+$1,provider_failed_count=provider_failed_count+$2 WHERE delivery_id=$3").bind(i64::from(state=="provider_accepted")).bind(i64::from(matches!(state,"permanent_failed"|"expired"|"cancelled"))).bind(&ticket.delivery_id).execute(&mut *tx)).await?;
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
    pub async fn status(&self, op: &str) -> Result<Value> {
        let op = crate::sender::op_id(op)?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Read, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM messages WHERE op_id=$1 AND dedupe_until>$2").bind(op).bind(now()).fetch_optional(&mut *profile_read_connection)).await }?.ok_or(KernelError::NotFound)?;
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
            self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT t.state,t.provider_status,t.acked_at,m.delivery_id FROM messages m JOIN targets t ON t.delivery_id=m.delivery_id WHERE m.op_id=$1").bind(op).fetch_all(&mut *profile_read_connection)).await
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
        let ids=self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM targets WHERE pull_owner=$1 AND acked_at IS NULL ORDER BY accepted_at,delivery_id LIMIT $2").bind(key).bind(limit as i64).fetch_all(&mut **tx)).await?;
        for row in &ids {
            let id: String = row.get("delivery_id");
            let original: String = row.get("device_key");
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE device_key=$2 AND delivery_id=$3 AND acked_at IS NULL").bind(at).bind(&original).bind(&id).execute(&mut **tx)).await?;
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
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL,acked_at=$1,state=CASE WHEN state='running' THEN state ELSE 'superseded_route' END WHERE delivery_id=$2 AND device_key=$3 AND acked_at IS NULL").bind(now()).bind(&id).bind(&key).execute(&mut **tx)).await?;
            self.release_acked_tx(tx, &key, &id, Path::Maintenance)
                .await?;
        }
        self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("DELETE FROM retired_provider_tokens WHERE (platform,provider_token) IN (SELECT r.platform,r.provider_token FROM retired_provider_tokens r WHERE NOT EXISTS(SELECT 1 FROM targets t WHERE t.delivery_mode='provider' AND t.platform=r.platform AND t.provider_token=r.provider_token AND t.control_epoch<r.control_epoch) LIMIT 256)").execute(&mut **tx)).await?;
        Ok(())
    }
}

// The fixture already uses Unix process/signal lifecycle. Never substitute a
// per-user temporary directory for this machine-wide owner identity.
#[cfg(unix)]
fn pg_owner_path(uuid: &str) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from("/tmp").join(format!("pushgo-c-pg-{uuid}.owner")))
}
#[cfg(not(unix))]
fn pg_owner_path(_: &str) -> Result<std::path::PathBuf> {
    Err(KernelError::Invalid(
        "PostgreSQL candidate requires a Unix machine-wide owner lock".into(),
    ))
}
