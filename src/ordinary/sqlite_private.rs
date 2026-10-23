//! SQLite durable Private delivery capabilities. The transport owns its bounded
//! reservation before calling claim; only a successful COMMIT returns a grant.
use crate::ordinary::private_model::{PrivateRoute, PrivateTicket};
use crate::ordinary::profiling::{Path, Phase, Statement};
use crate::ordinary::store::{
    DeliveryStore, KernelError, Result, SqliteWriteConnection, control_error, now,
};
use crate::ordinary::types::generate_hex_id_128;
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
        let row = self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT device_key,route_generation,route_revision FROM ordinary_device_routes WHERE device_key=? AND provider IS NULL AND retired_at IS NULL AND coalesced_to IS NULL").bind(device).fetch_optional(&mut *connection)).await?
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
            .phase(
                Path::Claim,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
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
        let legacy_executing = self
            .legacy_private_pending_for_device(&route.device_key)
            .await?;
        let executing: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE pull_owner=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL")
            .bind(&route.device_key).fetch_one(&mut *tx).await?;
        let legacy_global = self.legacy_private_pending().await?;
        let executing_global: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT private_claim) FROM ordinary_targets WHERE delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL")
            .fetch_one(&mut *tx).await?;
        let per_device_available = i64::try_from(self.config.private.max_pending_per_device)
            .unwrap_or(i64::MAX)
            .saturating_sub(legacy_executing)
            .saturating_sub(executing);
        let global_available = i64::try_from(self.config.private.max_pending)
            .unwrap_or(i64::MAX)
            .saturating_sub(legacy_global)
            .saturating_sub(executing_global);
        let available = per_device_available.min(global_available).max(0);
        let limit = limit.min(usize::try_from(available).unwrap_or(usize::MAX));
        if limit == 0 {
            tx.commit().await?;
            connection.restore().await?;
            return Ok(Vec::new());
        }
        // One canonical frozen key represents every coalesced unacknowledged
        // private row for this (consumer, delivery). A logical item is not claimed
        // twice by separate sessions, and only this bounded batch loads payloads.
        let rows = self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.delivery_id,t.device_key,t.delivery_epoch,m.payload_blob,m.accepted_at,m.expires_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_mode='private' AND t.acked_at IS NULL AND t.private_claim IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=t.pull_owner AND s.delivery_id=t.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND (s.device_key<t.device_key OR s.private_claim IS NOT NULL)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?").bind(&route.device_key).bind(route.route_generation).bind(at).bind(limit as i64).fetch_all(&mut *tx)).await?;
        let mut tickets = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery_id: String = row.try_get("delivery_id")?;
            let claim_token = generate_hex_id_128();
            // Claim token and group are shared across all physical siblings;
            // canonical receipt_owner + epoch fences the issued logical grant.
            self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=?,private_group=? WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NULL").bind(&claim_token).bind(group).bind(&route.device_key).bind(&delivery_id).execute(&mut *tx)).await?;
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
        connection.restore().await?;
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
        let exists: i64 = self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.pull_owner=? AND t.delivery_mode='private' AND t.delivery_epoch=? AND t.private_claim=? AND t.private_group=? AND t.acked_at IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='private' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key))").bind(&ticket.delivery_id).bind(&ticket.receipt_owner).bind(&ticket.pull_owner).bind(ticket.delivery_epoch).bind(&ticket.claim_token).bind(&ticket.group_id).bind(ticket.route_generation).bind(now()).fetch_one(&mut *connection)).await?;
        Ok(exists != 0)
    }

    pub(crate) async fn private_ack(
        &self,
        route: &PrivateRoute,
        ticket: &PrivateTicket,
    ) -> Result<bool> {
        self.private_terminal(route, ticket, false).await
    }

    pub(crate) async fn private_reject(
        &self,
        route: &PrivateRoute,
        ticket: &PrivateTicket,
        reason: &str,
    ) -> Result<bool> {
        if reason != "invalid_payload" {
            return Err(KernelError::Invalid("private rejection reason".into()));
        }
        self.private_terminal(route, ticket, true).await
    }

    async fn private_terminal(
        &self,
        route: &PrivateRoute,
        ticket: &PrivateTicket,
        rejected: bool,
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
            .phase(
                Path::Ack,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
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
        let granted: i64 = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.pull_owner=? AND t.delivery_mode='private' AND t.delivery_epoch=? AND t.private_claim=? AND t.private_group=? AND t.acked_at IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='private' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key))").bind(&ticket.delivery_id).bind(&ticket.receipt_owner).bind(&ticket.pull_owner).bind(ticket.delivery_epoch).bind(&ticket.claim_token).bind(&ticket.group_id).bind(ticket.route_generation).bind(at).fetch_one(&mut *tx)).await?;
        let removed = if granted != 0 {
            let changed = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET acked_at=?,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND private_claim=? AND private_group=? AND acked_at IS NULL").bind(at).bind(&ticket.pull_owner).bind(&ticket.delivery_id).bind(&ticket.claim_token).bind(&ticket.group_id).execute(&mut *tx)).await?.rows_affected() > 0;
            if changed && rejected {
                // This is a durable negative receipt, never a successful ACK or
                // provider acceptance. The terminal marker releases the same
                // body/queue capacity once; duplicate/stale grants cannot count.
                sqlx::query("UPDATE ordinary_messages SET private_rejected_count=private_rejected_count+1 WHERE delivery_id=?")
                    .bind(&ticket.delivery_id).execute(&mut *tx).await?;
                sqlx::query("UPDATE ordinary_targets SET state='private_rejected' WHERE delivery_id=? AND pull_owner=? AND acked_at IS NOT NULL AND state<>'running'")
                    .bind(&ticket.delivery_id).bind(&ticket.pull_owner).execute(&mut *tx).await?;
            }
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
        connection.restore().await?;
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
            .phase(
                Path::Claim,
                Phase::PoolAcquire,
                SqliteWriteConnection::acquire(&self.pool),
            )
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
            let changed = self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL WHERE delivery_mode='private' AND private_group=? AND private_claim=?").bind(group).bind(token).execute(&mut *tx)).await?.rows_affected();
            released += usize::from(changed > 0);
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, tx.commit())
            .await?;
        connection.restore().await?;
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
        self.counters.profile.sql(profile_path, Statement::ReleaseStatus, sqlx::query("UPDATE ordinary_messages SET status=CASE WHEN EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.delivery_id=ordinary_messages.delivery_id AND t.provider IN ('FCM','APNS','WNS') AND (t.state='running' OR (t.delivery_mode='provider' AND t.acked_at IS NULL AND t.state IN ('pending','retry_wait')))) THEN 'provider_queued' WHEN provider_failed_count>0 THEN CASE WHEN provider_accepted_count>0 OR private_enqueued_count>0 THEN 'partially_failed' ELSE 'failed' END ELSE 'sent' END,updated_at=? WHERE delivery_id=? AND status='provider_queued'").bind(now()).bind(id).execute(&mut **tx)).await?;
        Ok(())
    }

    /// Frozen target count participates in the one system target admission
    /// budget. Private execution slots are reserved separately during claim.
    pub(super) async fn count_private_fanout_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        channel: &str,
        at: i64,
    ) -> Result<i64> {
        if !self.config.private.enabled {
            return Ok(0);
        }
        let fanout: i64 = self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.channel_type='private' AND length(d.device_id)=16 AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(crate::ordinary::store::channel_storage_key(channel)?).bind(at).fetch_one(&mut **tx)).await?;
        Ok(fanout)
    }

    /// Startup only: no live runtime owner exists until all bounded batches finish.
    pub(super) async fn recover_private_claims_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<usize> {
        let rows = self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM ordinary_targets WHERE private_claim IS NOT NULL ORDER BY delivery_id,device_key LIMIT 256").fetch_all(&mut **tx)).await?;
        for row in &rows {
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL WHERE delivery_id=? AND device_key=?").bind(row.try_get::<String,_>("delivery_id")?).bind(row.try_get::<String,_>("device_key")?).execute(&mut **tx)).await?;
        }
        Ok(rows.len())
    }
}

// Counts are derived from the ordinary targets, not a second private queue.
// First/last-sibling probes are bounded by one frozen fanout through the partial
// owner/delivery index. Claim-field updates do not create another obligation.
pub(super) const PRIVATE_USAGE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS ordinary_private_usage(device_key TEXT PRIMARY KEY,pending INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ordinary_targets_private_logical ON ordinary_targets(pull_owner,delivery_id,device_key) WHERE delivery_mode='private' AND acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_private_pending ON ordinary_targets(pull_owner,accepted_at,delivery_id,device_key) WHERE delivery_mode='private' AND acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_private_group ON ordinary_targets(private_group,private_claim,pull_owner,delivery_id) WHERE private_claim IS NOT NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_private_recovery ON ordinary_targets(delivery_id,device_key) WHERE private_claim IS NOT NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_private_executing ON ordinary_targets(pull_owner,private_claim) WHERE delivery_mode='private' AND acked_at IS NULL AND private_claim IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS ordinary_private_usage_insert AFTER INSERT ON ordinary_targets
WHEN NEW.delivery_mode='private' AND NEW.acked_at IS NULL AND NEW.pull_owner<>''
AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=NEW.pull_owner AND s.delivery_id=NEW.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND s.device_key<>NEW.device_key)
BEGIN
 UPDATE ordinary_ledger_usage SET private_pending=private_pending+1 WHERE singleton=1;
 INSERT INTO ordinary_private_usage(device_key,pending) VALUES(NEW.pull_owner,1) ON CONFLICT(device_key) DO UPDATE SET pending=pending+1;
END;
CREATE TRIGGER IF NOT EXISTS ordinary_private_usage_delete AFTER DELETE ON ordinary_targets
WHEN OLD.delivery_mode='private' AND OLD.acked_at IS NULL AND OLD.pull_owner<>''
AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=OLD.pull_owner AND s.delivery_id=OLD.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL)
BEGIN
 UPDATE ordinary_ledger_usage SET private_pending=private_pending-1 WHERE singleton=1;
 UPDATE ordinary_private_usage SET pending=pending-1 WHERE device_key=OLD.pull_owner;
 DELETE FROM ordinary_private_usage WHERE device_key=OLD.pull_owner AND pending=0;
END;
CREATE TRIGGER IF NOT EXISTS ordinary_private_usage_update_remove AFTER UPDATE OF delivery_mode,acked_at,pull_owner ON ordinary_targets
WHEN OLD.delivery_mode='private' AND OLD.acked_at IS NULL AND OLD.pull_owner<>''
AND (NEW.delivery_mode<>'private' OR NEW.acked_at IS NOT NULL OR NEW.pull_owner<>OLD.pull_owner)
AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=OLD.pull_owner AND s.delivery_id=OLD.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL)
BEGIN
 UPDATE ordinary_ledger_usage SET private_pending=private_pending-1 WHERE singleton=1;
 UPDATE ordinary_private_usage SET pending=pending-1 WHERE device_key=OLD.pull_owner;
 DELETE FROM ordinary_private_usage WHERE device_key=OLD.pull_owner AND pending=0;
END;
CREATE TRIGGER IF NOT EXISTS ordinary_private_usage_update_add AFTER UPDATE OF delivery_mode,acked_at,pull_owner ON ordinary_targets
WHEN NEW.delivery_mode='private' AND NEW.acked_at IS NULL AND NEW.pull_owner<>''
AND (OLD.delivery_mode<>'private' OR OLD.acked_at IS NOT NULL OR OLD.pull_owner<>NEW.pull_owner)
AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=NEW.pull_owner AND s.delivery_id=NEW.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND s.device_key<>NEW.device_key)
BEGIN
 UPDATE ordinary_ledger_usage SET private_pending=private_pending+1 WHERE singleton=1;
 INSERT INTO ordinary_private_usage(device_key,pending) VALUES(NEW.pull_owner,1) ON CONFLICT(device_key) DO UPDATE SET pending=pending+1;
END;
"#;
