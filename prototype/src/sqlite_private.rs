//! SQLite durable Private delivery capabilities. The transport owns its bounded
//! reservation before calling claim; only a successful COMMIT returns a grant.
use crate::private_model::{PrivateRoute, PrivateTicket};
use crate::profiling::{Path, Phase, Statement};
use crate::store::{DeliveryStore, KernelError, Result, control_error, now};
use crate::types::generate_hex_id_128;
use sqlx::{Connection, Row};

impl DeliveryStore {
    pub(crate) async fn private_route(&self, device: &str) -> Result<PrivateRoute> {
        self.health.ensure()?;
        if !self.config.private.enabled {
            return Err(control_error(
                409,
                "private_channel_disabled",
                "private channel is disabled",
            ));
        }
        let mut connection = self
            .counters
            .profile
            .phase(Path::Read, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        self.health.ensure()?;
        let row = self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT device_key,route_generation,route_revision FROM devices WHERE device_key=? AND provider IS NULL AND retired_at IS NULL AND coalesced_to IS NULL").bind(device).fetch_optional(&mut *connection)).await?
            .ok_or_else(|| control_error(400, "private_route_required", "current private device route required"))?;
        Ok(PrivateRoute {
            device_key: row.try_get("device_key")?,
            route_generation: row.try_get("route_generation")?,
            route_revision: row.try_get("route_revision")?,
        })
    }

    pub(crate) async fn private_claim(
        &self,
        route: &PrivateRoute,
        group: &str,
        limit: usize,
    ) -> Result<Vec<PrivateTicket>> {
        self.health.ensure()?;
        if !self.config.private.enabled || limit == 0 {
            return Ok(Vec::new());
        }
        if group.is_empty() {
            return Err(KernelError::Invalid("private claim group required".into()));
        }
        let limit = limit
            .min(self.config.private.max_pending_per_device)
            .min(96);
        let _gate = self
            .counters
            .profile
            .phase(Path::Claim, Phase::GateWait, self.gate.lock())
            .await;
        self.health.ensure()?;
        let _hold = self.counters.profile.timer(Path::Claim, Phase::GateHold);
        let mut connection = self
            .counters
            .profile
            .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Claim,
                Phase::Begin,
                connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        self.health.ensure()?;
        let at = now();
        // One canonical frozen key represents every coalesced unacknowledged
        // private row for this (consumer, delivery). A logical item is not claimed
        // twice by separate sessions, and only this bounded batch loads payloads.
        let rows = self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.delivery_id,t.device_key,t.delivery_epoch,m.payload_blob,m.accepted_at,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_mode='private' AND t.acked_at IS NULL AND t.private_claim IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets s WHERE s.pull_owner=t.pull_owner AND s.delivery_id=t.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND (s.device_key<t.device_key OR s.private_claim IS NOT NULL)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?").bind(&route.device_key).bind(route.route_generation).bind(at).bind(limit as i64).fetch_all(&mut *tx)).await?;
        let mut tickets = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery_id: String = row.try_get("delivery_id")?;
            let claim_token = generate_hex_id_128();
            // Claim token and group are shared across all physical siblings;
            // canonical receipt_owner + epoch fences the issued logical grant.
            self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE targets SET private_claim=?,private_group=? WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NULL").bind(&claim_token).bind(group).bind(&route.device_key).bind(&delivery_id).execute(&mut *tx)).await?;
            tickets.push(PrivateTicket {
                delivery_id,
                receipt_owner: row.try_get("device_key")?,
                pull_owner: route.device_key.clone(),
                route_generation: route.route_generation,
                delivery_epoch: row.try_get("delivery_epoch")?,
                claim_token,
                group_id: group.to_owned(),
                payload: row.try_get("payload_blob")?,
                accepted_at: row.try_get("accepted_at")?,
                expires_at: row.try_get("expires_at")?,
            });
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        Ok(tickets)
    }

    pub(crate) async fn private_authorize(&self, ticket: &PrivateTicket) -> Result<bool> {
        self.health.ensure()?;
        if !self.config.private.enabled {
            return Ok(false);
        }
        let mut connection = self
            .counters
            .profile
            .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        self.health.ensure()?;
        let exists: i64 = self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM targets t JOIN devices d ON d.device_key=t.pull_owner JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.pull_owner=? AND t.delivery_mode='private' AND t.delivery_epoch=? AND t.private_claim=? AND t.private_group=? AND t.acked_at IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='private' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key))").bind(&ticket.delivery_id).bind(&ticket.receipt_owner).bind(&ticket.pull_owner).bind(ticket.delivery_epoch).bind(&ticket.claim_token).bind(&ticket.group_id).bind(ticket.route_generation).bind(now()).fetch_one(&mut *connection)).await?;
        Ok(exists != 0)
    }

    pub(crate) async fn private_ack(
        &self,
        route: &PrivateRoute,
        ticket: &PrivateTicket,
    ) -> Result<bool> {
        self.health.ensure()?;
        if !self.config.private.enabled
            || route.device_key != ticket.pull_owner
            || route.route_generation != ticket.route_generation
        {
            return Ok(false);
        }
        let _gate = self
            .counters
            .profile
            .phase(Path::Ack, Phase::GateWait, self.gate.lock())
            .await;
        self.health.ensure()?;
        let _hold = self.counters.profile.timer(Path::Ack, Phase::GateHold);
        let mut connection = self
            .counters
            .profile
            .phase(Path::Ack, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Ack,
                Phase::Begin,
                connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        self.health.ensure()?;
        let at = now();
        let granted: i64 = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM targets t JOIN devices d ON d.device_key=t.pull_owner JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.pull_owner=? AND t.delivery_mode='private' AND t.delivery_epoch=? AND t.private_claim=? AND t.private_group=? AND t.acked_at IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='private' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key))").bind(&ticket.delivery_id).bind(&ticket.receipt_owner).bind(&ticket.pull_owner).bind(ticket.delivery_epoch).bind(&ticket.claim_token).bind(&ticket.group_id).bind(ticket.route_generation).bind(at).fetch_one(&mut *tx)).await?;
        let removed = if granted != 0 {
            let changed = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE targets SET acked_at=?,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND private_claim=? AND private_group=? AND acked_at IS NULL").bind(at).bind(&ticket.pull_owner).bind(&ticket.delivery_id).bind(&ticket.claim_token).bind(&ticket.group_id).execute(&mut *tx)).await?.rows_affected() > 0;
            // Keep any frozen running Provider attempt until its own receipt.
            // Private ACK is delivery evidence, never Provider acceptance.
            self.release_acked_tx(
                &mut tx,
                &ticket.receipt_owner,
                &ticket.delivery_id,
                Path::Ack,
            )
            .await?;
            changed
        } else {
            false
        };
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Ack, Phase::Commit, tx.commit())
            .await?;
        drop(connection);
        if removed {
            self.notify();
        }
        Ok(removed)
    }

    pub(crate) async fn private_release(
        &self,
        group: &str,
        claim_tokens: &[String],
    ) -> Result<usize> {
        self.health.ensure()?;
        if claim_tokens.len() > 4096 {
            return Err(KernelError::Invalid(
                "private release exceeds runtime reservation budget".into(),
            ));
        }
        if claim_tokens.is_empty() {
            return Ok(0);
        }
        let _gate = self
            .counters
            .profile
            .phase(Path::Claim, Phase::GateWait, self.gate.lock())
            .await;
        self.health.ensure()?;
        let _hold = self.counters.profile.timer(Path::Claim, Phase::GateHold);
        let mut connection = self
            .counters
            .profile
            .phase(Path::Claim, Phase::PoolAcquire, self.pool.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(
                Path::Claim,
                Phase::Begin,
                connection.begin_with("BEGIN IMMEDIATE"),
            )
            .await?;
        self.health.ensure()?;
        let mut released = 0;
        for token in claim_tokens {
            let changed = self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL WHERE delivery_mode='private' AND private_group=? AND private_claim=?").bind(group).bind(token).execute(&mut *tx)).await?.rows_affected();
            released += usize::from(changed > 0);
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        Ok(released)
    }

    /// Sender outcome follows the original Provider attempts plus the frozen
    /// successful Private enqueue fact; retained Private ACK is not Provider work.
    pub(super) async fn refresh_provider_status_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        id: &str,
        profile_path: Path,
    ) -> Result<()> {
        self.counters.profile.sql(profile_path, Statement::ReleaseStatus, sqlx::query("UPDATE messages SET status=CASE WHEN EXISTS(SELECT 1 FROM targets t WHERE t.delivery_id=messages.delivery_id AND t.provider IN ('FCM','APNS') AND (t.state='running' OR (t.delivery_mode='provider' AND t.acked_at IS NULL AND t.state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued'").bind(now()).bind(id).execute(&mut **tx)).await?;
        Ok(())
    }

    /// Admission uses derived counters and at most one channel's frozen fanout.
    /// The caller already owns the writer transaction and global usage lock.
    pub(super) async fn check_private_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        channel: &str,
    ) -> Result<i64> {
        if !self.config.private.enabled {
            return Ok(0);
        }
        let fanout: i64 = self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE s.channel_id=? AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(channel).fetch_one(&mut **tx)).await?;
        let per_device =
            i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
        let global = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
        let pending: i64 = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Usage,
                sqlx::query_scalar("SELECT private_pending FROM ledger_usage WHERE singleton=1")
                    .fetch_one(&mut **tx),
            )
            .await?;
        let full: i64 = self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key LEFT JOIN private_usage u ON u.device_key=d.device_key WHERE s.channel_id=? AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND COALESCE(u.pending,0)>=?)").bind(channel).bind(per_device).fetch_one(&mut **tx)).await?;
        if full != 0 || pending.saturating_add(fanout) > global {
            return Err(KernelError::Capacity);
        }
        Ok(fanout)
    }

    /// Move the retained consumer mode, never the frozen Provider wire attempt.
    pub(super) async fn transition_private_mode_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        device: &str,
        to_private: bool,
    ) -> Result<()> {
        if !self.config.private.enabled && to_private {
            return Ok(());
        }
        let at = now();
        if to_private {
            let existing: i64 = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Usage,
                    sqlx::query_scalar(
                        "SELECT COALESCE((SELECT pending FROM private_usage WHERE device_key=?),0)",
                    )
                    .bind(device)
                    .fetch_one(&mut **tx),
                )
                .await?;
            let global: i64 = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Usage,
                    sqlx::query_scalar(
                        "SELECT private_pending FROM ledger_usage WHERE singleton=1",
                    )
                    .fetch_one(&mut **tx),
                )
                .await?;
            let per_device =
                i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
            let global_limit = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
            let available = per_device
                .saturating_sub(existing)
                .min(global_limit.saturating_sub(global))
                .max(0);
            // COUNT is over a bounded SQL keyset of this owner's candidate
            // logical deliveries, not a global history scan or payload load.
            let additional: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT DISTINCT t.delivery_id FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_mode='provider' AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM targets p WHERE p.pull_owner=t.pull_owner AND p.delivery_id=t.delivery_id AND p.delivery_mode='private' AND p.acked_at IS NULL) LIMIT ?) additions").bind(device).bind(at).bind(available.saturating_add(1)).fetch_one(&mut **tx)).await?;
            if additional > available {
                return Err(control_error(
                    409,
                    "route_transition_pending_capacity_exceeded",
                    "pending deliveries exceed private route capacity",
                ));
            }
        }
        let mode = if to_private { "private" } else { "provider" };
        loop {
            let ids: Vec<String> = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT DISTINCT t.delivery_id FROM targets t WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_mode<>? AND (?=0 OR EXISTS(SELECT 1 FROM messages m WHERE m.delivery_id=t.delivery_id AND m.expires_at>?)) ORDER BY t.delivery_id LIMIT 256").bind(device).bind(mode).bind(i64::from(to_private)).bind(at).fetch_all(&mut **tx)).await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                // Clear the whole logical grant, including already-destination
                // siblings. Otherwise an overlapping coalesced row could retain
                // part of a capability after canonical receipt ownership changes.
                let exhausted: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM targets WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL AND delivery_epoch=?)").bind(device).bind(&id).bind(i64::MAX).fetch_one(&mut **tx)).await?;
                if exhausted != 0 {
                    return Err(KernelError::Invalid(
                        "private delivery epoch exhausted".into(),
                    ));
                }
                self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE targets SET delivery_mode=?,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL").bind(mode).bind(device).bind(&id).execute(&mut **tx)).await?;
                // A retained terminal Provider target can become live again
                // when its consumer mode changes to Private. The row triggers
                // have applied that delta; check the same shared admission
                // budgets before committing any part of this route transition.
                let usage = self
                    .counters
                    .profile
                    .sql(
                        Path::Control,
                        Statement::Usage,
                        sqlx::query(
                            "SELECT messages,targets,bytes FROM ledger_usage WHERE singleton=1",
                        )
                        .fetch_one(&mut **tx),
                    )
                    .await?;
                if usage.try_get::<i64, _>("messages")? > self.config.max_messages
                    || usage.try_get::<i64, _>("targets")? > self.config.max_targets
                    || usage.try_get::<i64, _>("bytes")? > self.config.max_payload_bytes
                {
                    return Err(KernelError::Capacity);
                }
                self.refresh_provider_status_tx(tx, &id, Path::Control)
                    .await?;
            }
        }
        Ok(())
    }

    /// Fence every logical capability before the caller transfers Pull owners.
    pub(super) async fn fence_private_coalesce_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        winner: &str,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        if !self.config.private.enabled {
            let retained: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM targets t WHERE t.delivery_mode='private' AND t.acked_at IS NULL AND (t.pull_owner IN (SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL) OR (t.pull_owner=? AND t.delivery_id IN (SELECT x.delivery_id FROM targets x JOIN devices d ON d.device_key=x.pull_owner WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL AND x.acked_at IS NULL))))").bind(platform).bind(token).bind(winner).bind(winner).bind(platform).bind(token).bind(winner).fetch_one(&mut **tx)).await?;
            if retained == 0 {
                return Ok(());
            }
        }
        let exhausted: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM targets t WHERE t.acked_at IS NULL AND t.delivery_epoch=? AND (t.pull_owner IN (SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL) OR (t.pull_owner=? AND t.delivery_id IN (SELECT x.delivery_id FROM targets x JOIN devices d ON d.device_key=x.pull_owner WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL AND x.acked_at IS NULL))))").bind(i64::MAX).bind(platform).bind(token).bind(winner).bind(winner).bind(platform).bind(token).bind(winner).fetch_one(&mut **tx)).await?;
        if exhausted != 0 {
            return Err(KernelError::Invalid(
                "private delivery epoch exhausted".into(),
            ));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE targets SET delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL WHERE pull_owner=? AND acked_at IS NULL AND delivery_id IN (SELECT x.delivery_id FROM targets x JOIN devices d ON d.device_key=x.pull_owner WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL AND x.acked_at IS NULL)").bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE targets SET state=CASE WHEN delivery_mode='private' AND state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END,delivery_mode='provider',delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL WHERE acked_at IS NULL AND pull_owner IN (SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL)").bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        Ok(())
    }

    /// Startup only: no live runtime owner exists until all bounded batches finish.
    pub(super) async fn recover_private_claims_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<usize> {
        let rows = self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM targets WHERE private_claim IS NOT NULL ORDER BY delivery_id,device_key LIMIT 256").fetch_all(&mut **tx)).await?;
        for row in &rows {
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE targets SET private_claim=NULL,private_group=NULL WHERE delivery_id=? AND device_key=?").bind(row.try_get::<String,_>("delivery_id")?).bind(row.try_get::<String,_>("device_key")?).execute(&mut **tx)).await?;
        }
        Ok(rows.len())
    }
}

// Counts are derived from the ordinary targets, not a second private queue.
// First/last-sibling probes are bounded by one frozen fanout through the partial
// owner/delivery index. Claim-field updates do not create another obligation.
pub(super) const PRIVATE_USAGE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS private_usage(device_key TEXT PRIMARY KEY,pending INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS targets_private_logical ON targets(pull_owner,delivery_id,device_key) WHERE delivery_mode='private' AND acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_private_pending ON targets(pull_owner,accepted_at,delivery_id,device_key) WHERE delivery_mode='private' AND acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_private_group ON targets(private_group,private_claim,pull_owner,delivery_id) WHERE private_claim IS NOT NULL;
CREATE INDEX IF NOT EXISTS targets_private_recovery ON targets(delivery_id,device_key) WHERE private_claim IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS private_usage_insert AFTER INSERT ON targets
WHEN NEW.delivery_mode='private' AND NEW.acked_at IS NULL AND NEW.pull_owner<>''
AND NOT EXISTS(SELECT 1 FROM targets s WHERE s.pull_owner=NEW.pull_owner AND s.delivery_id=NEW.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND s.device_key<>NEW.device_key)
BEGIN
 UPDATE ledger_usage SET private_pending=private_pending+1 WHERE singleton=1;
 INSERT INTO private_usage(device_key,pending) VALUES(NEW.pull_owner,1) ON CONFLICT(device_key) DO UPDATE SET pending=pending+1;
END;
CREATE TRIGGER IF NOT EXISTS private_usage_delete AFTER DELETE ON targets
WHEN OLD.delivery_mode='private' AND OLD.acked_at IS NULL AND OLD.pull_owner<>''
AND NOT EXISTS(SELECT 1 FROM targets s WHERE s.pull_owner=OLD.pull_owner AND s.delivery_id=OLD.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL)
BEGIN
 UPDATE ledger_usage SET private_pending=private_pending-1 WHERE singleton=1;
 UPDATE private_usage SET pending=pending-1 WHERE device_key=OLD.pull_owner;
 DELETE FROM private_usage WHERE device_key=OLD.pull_owner AND pending=0;
END;
CREATE TRIGGER IF NOT EXISTS private_usage_update_remove AFTER UPDATE OF delivery_mode,acked_at,pull_owner ON targets
WHEN OLD.delivery_mode='private' AND OLD.acked_at IS NULL AND OLD.pull_owner<>''
AND (NEW.delivery_mode<>'private' OR NEW.acked_at IS NOT NULL OR NEW.pull_owner<>OLD.pull_owner)
AND NOT EXISTS(SELECT 1 FROM targets s WHERE s.pull_owner=OLD.pull_owner AND s.delivery_id=OLD.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL)
BEGIN
 UPDATE ledger_usage SET private_pending=private_pending-1 WHERE singleton=1;
 UPDATE private_usage SET pending=pending-1 WHERE device_key=OLD.pull_owner;
 DELETE FROM private_usage WHERE device_key=OLD.pull_owner AND pending=0;
END;
CREATE TRIGGER IF NOT EXISTS private_usage_update_add AFTER UPDATE OF delivery_mode,acked_at,pull_owner ON targets
WHEN NEW.delivery_mode='private' AND NEW.acked_at IS NULL AND NEW.pull_owner<>''
AND (OLD.delivery_mode<>'private' OR OLD.acked_at IS NOT NULL OR OLD.pull_owner<>NEW.pull_owner)
AND NOT EXISTS(SELECT 1 FROM targets s WHERE s.pull_owner=NEW.pull_owner AND s.delivery_id=NEW.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND s.device_key<>NEW.device_key)
BEGIN
 UPDATE ledger_usage SET private_pending=private_pending+1 WHERE singleton=1;
 INSERT INTO private_usage(device_key,pending) VALUES(NEW.pull_owner,1) ON CONFLICT(device_key) DO UPDATE SET pending=pending+1;
END;
"#;
