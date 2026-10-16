//! MySQL durable Private capabilities on the pinned owner session. The transport owns its bounded
//! reservation before calling claim; only a successful COMMIT returns a grant.
use crate::ordinary::mysql_store::MySqlDeliveryStore;
use crate::ordinary::private_model::{PrivateRoute, PrivateTicket};
use crate::ordinary::profiling::{Path, Phase, Statement};
use crate::ordinary::store::{KernelError, Result, control_error, now};
use crate::ordinary::types::generate_hex_id_128;
use sqlx::{Connection, Row};

impl MySqlDeliveryStore {
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
            .phase(Path::Read, Phase::PoolAcquire, self.acquire())
            .await?;
        self.health.ensure()?;
        let row = self.counters.profile.sql(Path::Read, Statement::Read, sqlx::query("SELECT device_key,route_generation,route_revision FROM ordinary_device_routes WHERE device_key=? AND provider IS NULL AND retired_at IS NULL AND coalesced_to IS NULL").bind(device).fetch_optional(&mut *connection)).await?
            .ok_or_else(|| control_error(400, "private_route_required", "current private device route required"))?;
        Ok(PrivateRoute {
            device_key: row.try_get_unchecked("device_key")?,
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
            .phase(Path::Claim, Phase::PoolAcquire, self.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Claim, Phase::Begin, connection.begin())
            .await?;
        self.health.ensure()?;
        Self::lock_usage(&mut tx).await?;
        let at = now();
        // One canonical frozen key represents every coalesced unacknowledged
        // private row for this (consumer, delivery). A logical item is not claimed
        // twice by separate sessions, and only this bounded batch loads payloads.
        let rows = self.counters.profile.sql(Path::Claim, Statement::ClaimSelect, sqlx::query("SELECT t.delivery_id,t.device_key,t.delivery_epoch,m.payload_blob,m.accepted_at,m.expires_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.pull_owner=? AND t.delivery_mode='private' AND t.acked_at IS NULL AND t.private_claim IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets s WHERE s.pull_owner=t.pull_owner AND s.delivery_id=t.delivery_id AND s.delivery_mode='private' AND s.acked_at IS NULL AND (s.device_key<t.device_key OR s.private_claim IS NOT NULL)) ORDER BY t.accepted_at,t.delivery_id LIMIT ?").bind(&route.device_key).bind(route.route_generation).bind(at).bind(limit as i64).fetch_all(&mut *tx)).await?;
        let mut tickets = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery_id: String = row.try_get_unchecked("delivery_id")?;
            let claim_token = generate_hex_id_128();
            // Claim token and group are shared across all physical siblings;
            // canonical receipt_owner + epoch fences the issued logical grant.
            self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=?,private_group=? WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND acked_at IS NULL AND private_claim IS NULL").bind(&claim_token).bind(group).bind(&route.device_key).bind(&delivery_id).execute(&mut *tx)).await?;
            tickets.push(PrivateTicket {
                delivery_id,
                receipt_owner: row.try_get_unchecked("device_key")?,
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
            .phase(Path::Claim, Phase::Commit, self.commit(tx))
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
            .phase(Path::Claim, Phase::PoolAcquire, self.acquire())
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
            return Err(KernelError::Invalid(
                "unsupported Private terminal reason".into(),
            ));
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
            .phase(Path::Ack, Phase::PoolAcquire, self.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Ack, Phase::Begin, connection.begin())
            .await?;
        self.health.ensure()?;
        Self::lock_usage(&mut tx).await?;
        let at = now();
        let granted: i64 = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.delivery_id=? AND t.device_key=? AND t.pull_owner=? AND t.delivery_mode='private' AND t.delivery_epoch=? AND t.private_claim=? AND t.private_group=? AND t.acked_at IS NULL AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND d.route_generation=? AND m.expires_at>? AND m.payload_bytes>0 AND NOT EXISTS(SELECT 1 FROM ordinary_targets sibling WHERE sibling.pull_owner=t.pull_owner AND sibling.delivery_id=t.delivery_id AND sibling.delivery_mode='private' AND sibling.acked_at IS NULL AND sibling.device_key<t.device_key))").bind(&ticket.delivery_id).bind(&ticket.receipt_owner).bind(&ticket.pull_owner).bind(ticket.delivery_epoch).bind(&ticket.claim_token).bind(&ticket.group_id).bind(ticket.route_generation).bind(at).fetch_one(&mut *tx)).await?;
        let removed = if granted != 0 {
            let before = Self::private_owners_for_message_tx(&mut tx, &ticket.delivery_id).await?;
            let changed = self.counters.profile.sql(Path::Ack, Statement::AckUpdate, sqlx::query("UPDATE ordinary_targets SET acked_at=?,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND delivery_id=? AND delivery_mode='private' AND private_claim=? AND private_group=? AND acked_at IS NULL").bind(at).bind(&ticket.pull_owner).bind(&ticket.delivery_id).bind(&ticket.claim_token).bind(&ticket.group_id).execute(&mut *tx)).await?.rows_affected() > 0;
            if changed && rejected {
                // A negative durable result is not an ACK success. The issued
                // capability predicate above makes this increment idempotent.
                sqlx::query("UPDATE ordinary_messages SET private_rejected_count=private_rejected_count+1 WHERE delivery_id=?")
                    .bind(&ticket.delivery_id).execute(&mut *tx).await?;
            }
            Self::reconcile_private_message_tx(&mut tx, &ticket.delivery_id, &before).await?;
            Self::reconcile_message_tx(&mut tx, &ticket.delivery_id).await?;
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
            .phase(Path::Ack, Phase::Commit, self.commit(tx))
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
            .phase(Path::Claim, Phase::PoolAcquire, self.acquire())
            .await?;
        self.health.ensure()?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Claim, Phase::Begin, connection.begin())
            .await?;
        self.health.ensure()?;
        Self::lock_usage(&mut tx).await?;
        let mut released = 0;
        for token in claim_tokens {
            let changed = self.counters.profile.sql(Path::Claim, Statement::ClaimUpdate, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL WHERE delivery_mode='private' AND private_group=? AND private_claim=?").bind(group).bind(token).execute(&mut *tx)).await?.rows_affected();
            released += usize::from(changed > 0);
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Claim, Phase::Commit, self.commit(tx))
            .await?;
        Ok(released)
    }

    /// Admission uses derived counters and at most one channel's frozen fanout.
    /// The caller already owns the writer transaction and global usage lock.
    pub(super) async fn check_private_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        channel: &[u8; 16],
        accepted_at: i64,
    ) -> Result<i64> {
        if !self.config.private.enabled {
            return Ok(0);
        }
        let fanout: i64 = self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL").bind(channel.as_slice()).bind(accepted_at).fetch_one(&mut **tx)).await?;
        let per_device =
            i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
        let global = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
        let pending: i64 = self
            .counters
            .profile
            .sql(
                Path::Accept,
                Statement::Usage,
                sqlx::query_scalar(
                    "SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1",
                )
                .fetch_one(&mut **tx),
            )
            .await?;
        let legacy_pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')",
        )
        .fetch_one(&mut **tx)
        .await?;
        let full: i64 = self.counters.profile.sql(Path::Fanout, Statement::FanoutCount, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key LEFT JOIN ordinary_private_usage u ON u.device_key=d.device_key WHERE s.channel_id=? AND s.created_at<=? AND d.provider IS NULL AND d.retired_at IS NULL AND d.coalesced_to IS NULL AND COALESCE(u.pending,0)+(SELECT COUNT(*) FROM private_outbox o WHERE o.device_id=LEFT(d.device_id,16) AND o.status IN ('pending','claimed','sent'))>=?)").bind(channel.as_slice()).bind(accepted_at).bind(per_device).fetch_one(&mut **tx)).await?;
        if full != 0
            || pending
                .saturating_add(legacy_pending)
                .saturating_add(fanout)
                > global
        {
            return Err(KernelError::Capacity);
        }
        Ok(fanout)
    }

    /// Move the retained consumer mode, never the frozen Provider wire attempt.
    pub(super) async fn transition_private_mode_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        device: &str,
        to_private: bool,
    ) -> Result<()> {
        // Disabling transports cannot strand a previously durable Private
        // obligation when its owner explicitly switches back to Provider.
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
                        "SELECT COALESCE((SELECT pending FROM ordinary_private_usage WHERE device_key=?),0)",
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
                        "SELECT private_pending FROM ordinary_ledger_usage WHERE singleton=1",
                    )
                    .fetch_one(&mut **tx),
                )
                .await?;
            let legacy_device: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM private_outbox o JOIN devices d ON o.device_id=LEFT(d.device_id,16) WHERE d.device_key=? AND o.status IN ('pending','claimed','sent')")
                .bind(device).fetch_one(&mut **tx).await?;
            let legacy_global: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM private_outbox WHERE status IN ('pending','claimed','sent')",
            )
            .fetch_one(&mut **tx)
            .await?;
            let per_device =
                i64::try_from(self.config.private.max_pending_per_device).unwrap_or(i64::MAX);
            let global_limit = i64::try_from(self.config.private.max_pending).unwrap_or(i64::MAX);
            let available = per_device
                .saturating_sub(existing.saturating_add(legacy_device))
                .min(global_limit.saturating_sub(global.saturating_add(legacy_global)))
                .max(0);
            // COUNT is over a bounded SQL keyset of this owner's candidate
            // logical deliveries, not a global history scan or payload load.
            let additional: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT DISTINCT t.delivery_id FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_mode='provider' AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM ordinary_targets p WHERE p.pull_owner=t.pull_owner AND p.delivery_id=t.delivery_id AND p.delivery_mode='private' AND p.acked_at IS NULL) LIMIT ?) additions").bind(device).bind(at).bind(available.saturating_add(1)).fetch_one(&mut **tx)).await?;
            if additional > available {
                return Err(control_error(
                    409,
                    "route_transition_pending_capacity_exceeded",
                    "pending deliveries exceed private route capacity",
                ));
            }
        }
        let mode = if to_private { "private" } else { "provider" };
        let exhausted: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_epoch=? AND (?=0 OR EXISTS(SELECT 1 FROM ordinary_messages m WHERE m.delivery_id=t.delivery_id AND m.expires_at>?)))").bind(device).bind(i64::MAX).bind(i64::from(to_private)).bind(at).fetch_one(&mut **tx)).await?;
        if exhausted != 0 {
            return Err(KernelError::Invalid(
                "private delivery epoch exhausted".into(),
            ));
        }
        // Capture at most one native keyset at a time. A mode change revokes
        // every sibling of each affected logical capability, including an
        // existing destination-mode sibling that overlaps the changed rows.
        let mut cursor = String::new();
        loop {
            let rows = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT t.delivery_id FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id WHERE t.pull_owner=? AND t.acked_at IS NULL AND t.delivery_mode<>? AND t.delivery_id>? AND (?=0 OR m.expires_at>?) GROUP BY t.delivery_id ORDER BY t.delivery_id LIMIT 256").bind(device).bind(mode).bind(&cursor).bind(i64::from(to_private)).bind(at).fetch_all(&mut **tx)).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let id: String = row.try_get_unchecked("delivery_id")?;
                let before = Self::private_owners_for_message_tx(tx, &id).await?;
                self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE ordinary_targets SET delivery_mode=?,delivery_epoch=delivery_epoch+1,private_claim=NULL,private_group=NULL,state=CASE WHEN state IN ('pending','retry_wait') THEN 'superseded_route' ELSE state END WHERE pull_owner=? AND delivery_id=? AND acked_at IS NULL").bind(mode).bind(device).bind(&id).execute(&mut **tx)).await?;
                Self::reconcile_private_message_tx(tx, &id, &before).await?;
                Self::reconcile_message_tx(tx, &id).await?;
                // A retained Provider body can become live again in Private
                // mode. Re-admission must obey the same shared budgets as a
                // new accept; failure rolls back the entire control mutation.
                let usage = self
                    .counters
                    .profile
                    .sql(
                        Path::Control,
                        Statement::Usage,
                        sqlx::query(
                            "SELECT messages,targets,bytes FROM ordinary_ledger_usage WHERE singleton=1",
                        )
                        .fetch_one(&mut **tx),
                    )
                    .await?;
                if usage.get::<i64, _>("messages") > self.config.max_messages
                    || usage.get::<i64, _>("targets") > self.config.max_targets
                    || usage.get::<i64, _>("bytes") > self.config.max_payload_bytes
                {
                    return Err(KernelError::Capacity);
                }
                Self::refresh_status_tx(tx, &id, at).await?;
                cursor = id;
            }
        }
        Ok(())
    }

    /// Provider-token coalescing migrates retained consumption only. Frozen
    /// Provider keys and owned attempts survive; every affected logical grant,
    /// including an overlapping winner sibling, is revoked as one unit.
    pub(super) async fn coalesce_private_owners_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        winner: &str,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        let retained_private: i64 = sqlx::query_scalar("SELECT (EXISTS(SELECT 1 FROM ordinary_private_usage WHERE device_key=? AND pending>0) OR EXISTS(SELECT 1 FROM ordinary_device_routes d JOIN ordinary_private_usage u ON u.device_key=d.device_key WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL AND u.pending>0))")
            .bind(winner).bind(platform).bind(token).bind(winner).fetch_one(&mut **tx).await?;
        if !self.config.private.enabled && retained_private == 0 {
            sqlx::query("UPDATE ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner SET t.pull_owner=?,t.owner_generation=-1 WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL")
                .bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx).await?;
            return Ok(());
        }
        let mut cursor = String::new();
        loop {
            let rows=sqlx::query("SELECT t.delivery_id FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL AND t.delivery_id>? GROUP BY t.delivery_id ORDER BY t.delivery_id LIMIT 256")
                .bind(platform).bind(token).bind(winner).bind(&cursor).fetch_all(&mut **tx).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let id: String = row.try_get_unchecked("delivery_id")?;
                let before = Self::private_owners_for_message_tx(tx, &id).await?;
                let exhausted:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner WHERE t.delivery_id=? AND t.acked_at IS NULL AND t.delivery_epoch=? AND (t.pull_owner=? OR (d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL)))")
                    .bind(&id).bind(i64::MAX).bind(winner).bind(platform).bind(token).bind(winner).fetch_one(&mut **tx).await?;
                if exhausted != 0 {
                    return Err(KernelError::Invalid(
                        "private delivery epoch exhausted".into(),
                    ));
                }
                // The WHERE admits the current winner plus old owners before
                // SET rewrites pull_owner, so every row advances at most once.
                sqlx::query("UPDATE ordinary_targets t JOIN ordinary_device_routes d ON d.device_key=t.pull_owner SET t.owner_generation=CASE WHEN d.device_key<>? THEN -1 ELSE t.owner_generation END,t.pull_owner=?,t.delivery_mode=CASE WHEN t.acked_at IS NULL THEN 'provider' ELSE t.delivery_mode END,t.delivery_epoch=t.delivery_epoch+CASE WHEN t.acked_at IS NULL THEN 1 ELSE 0 END,t.private_claim=NULL,t.private_group=NULL,t.state=CASE WHEN t.state IN ('pending','retry_wait') THEN 'superseded_route' ELSE t.state END WHERE t.delivery_id=? AND (t.pull_owner=? OR (d.platform=? AND d.provider_token=? AND d.device_key<>? AND d.retired_at IS NULL))")
                    .bind(winner).bind(winner).bind(&id).bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx).await?;
                Self::reconcile_private_message_tx(tx, &id, &before).await?;
                Self::reconcile_message_tx(tx, &id).await?;
                Self::refresh_status_tx(tx, &id, now()).await?;
                cursor = id;
            }
        }
        Ok(())
    }

    /// At most the accepted physical fanout (32) contributes owners for one
    /// identity. SQL GROUP BY uses the stored NO PAD binary key, never a CAST.
    pub(super) async fn private_owners_for_message_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        id: &str,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT pull_owner FROM ordinary_targets WHERE delivery_id=? AND delivery_mode='private' AND acked_at IS NULL GROUP BY pull_owner LIMIT 33")
            .bind(id).fetch_all(&mut **tx).await?;
        if rows.len() > 32 {
            return Err(KernelError::Invalid(
                "private logical fanout exceeds frozen limit".into(),
            ));
        }
        rows.iter()
            .map(|row| {
                row.try_get_unchecked("pull_owner")
                    .map_err(KernelError::from)
            })
            .collect()
    }

    /// Called around each mutation by the singleton-lock owner. These are
    /// derived logical counts, not a second delivery identity or global recount.
    pub(super) async fn reconcile_private_message_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        id: &str,
        before: &[String],
    ) -> Result<()> {
        let after = Self::private_owners_for_message_tx(tx, id).await?;
        for owner in before.iter().filter(|owner| !after.contains(owner)) {
            let changed = sqlx::query(
                "UPDATE ordinary_private_usage SET pending=pending-1 WHERE device_key=? AND pending>0",
            )
            .bind(owner)
            .execute(&mut **tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(KernelError::Invalid(
                    "private per-device usage underflow".into(),
                ));
            }
        }
        for owner in after.iter().filter(|owner| !before.contains(owner)) {
            sqlx::query("INSERT INTO ordinary_private_usage(device_key,pending) VALUES(?,1) ON DUPLICATE KEY UPDATE pending=ordinary_private_usage.pending+1")
                .bind(owner).execute(&mut **tx).await?;
        }
        let delta = after.len() as i64 - before.len() as i64;
        if delta != 0 {
            let changed=sqlx::query("UPDATE ordinary_ledger_usage SET private_pending=private_pending+? WHERE singleton=1 AND private_pending+?>=0")
                .bind(delta).bind(delta).execute(&mut **tx).await?.rows_affected();
            if changed != 1 {
                return Err(KernelError::Invalid(
                    "private global usage underflow".into(),
                ));
            }
        }
        Ok(())
    }

    /// Startup only: no live runtime owner exists until all bounded batches finish.
    pub(super) async fn recover_private_claims_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    ) -> Result<usize> {
        let rows = self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("SELECT delivery_id,device_key FROM ordinary_targets WHERE private_claim IS NOT NULL ORDER BY delivery_id,device_key LIMIT 256").fetch_all(&mut **tx)).await?;
        for row in &rows {
            self.counters.profile.sql(Path::Maintenance, Statement::MaintenanceTargets, sqlx::query("UPDATE ordinary_targets SET private_claim=NULL,private_group=NULL WHERE delivery_id=? AND device_key=?").bind(row.try_get_unchecked::<String,_>("delivery_id")?).bind(row.try_get_unchecked::<String,_>("device_key")?).execute(&mut **tx)).await?;
        }
        Ok(rows.len())
    }
}
