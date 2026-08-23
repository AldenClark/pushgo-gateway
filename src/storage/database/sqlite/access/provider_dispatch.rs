use super::*;

impl SqliteDb {
    pub async fn enqueue_provider_dispatch_job(
        &self,
        record: &ProviderDispatchOutboxRecord,
        hard_capacity: usize,
    ) -> StoreResult<bool> {
        let mut tx = self.dispatch_pool().begin().await?;
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM provider_dispatch_outbox WHERE job_id = ?")
                .bind(&record.job_id)
                .fetch_one(&mut *tx)
                .await?;
        if exists > 0 {
            if record.coalescible {
                let changed = sqlx::query(
                    "UPDATE provider_dispatch_outbox SET provider=?, delivery_id=?, op_id=?, dedupe_key=?, device_key=?, \
                            payload_blob=?, state='pending', attempt_count=0, next_attempt_at=?, \
                            lease_owner=NULL, lease_until=NULL, lease_generation=lease_generation+1, \
                            provider_status=NULL, provider_error_code=NULL, accepted_at=?, expires_at=?, coalesce_order=?, \
                            completed_at=NULL, updated_at=? WHERE job_id=? AND (coalesce_order<? OR (coalesce_order=? AND delivery_id=?))",
                )
                .bind(&record.provider)
                .bind(&record.delivery_id)
                .bind(&record.op_id)
                .bind(&record.dedupe_key)
                .bind(&record.device_key)
                .bind(&record.payload_blob)
                .bind(record.next_attempt_at)
                .bind(record.accepted_at)
                .bind(record.expires_at)
                .bind(record.coalesce_order)
                .bind(record.accepted_at)
                .bind(&record.job_id)
                .bind(record.coalesce_order)
                .bind(record.coalesce_order)
                .bind(&record.delivery_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                tx.commit().await?;
                return Ok(changed == 1);
            }
            tx.commit().await?;
            return Ok(false);
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased')",
        )
        .fetch_one(&mut *tx)
        .await?;
        if pending >= hard_capacity as i64 {
            tx.rollback().await?;
            return Err(StoreError::ProviderDispatchCapacityExceeded {
                pending: pending as usize,
                capacity: hard_capacity,
            });
        }
        let changed = sqlx::query(
            "INSERT OR IGNORE INTO provider_dispatch_outbox \
             (job_id, provider, delivery_id, op_id, dedupe_key, device_key, payload_blob, state, attempt_count, \
              next_attempt_at, lease_generation, accepted_at, expires_at, coalesce_order, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?, ?)",
        )
        .bind(&record.job_id)
        .bind(&record.provider)
        .bind(&record.delivery_id)
        .bind(&record.op_id)
        .bind(&record.dedupe_key)
        .bind(&record.device_key)
        .bind(&record.payload_blob)
        .bind(&record.state)
        .bind(record.next_attempt_at)
        .bind(record.accepted_at)
        .bind(record.expires_at)
        .bind(record.coalesce_order)
        .bind(record.accepted_at)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(changed == 1)
    }

    pub async fn activate_provider_dispatch_jobs(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<usize> {
        let changed = sqlx::query("UPDATE provider_dispatch_outbox SET state='pending', next_attempt_at=?, updated_at=? WHERE delivery_id=? AND state='preparing'")
            .bind(now).bind(now).bind(delivery_id).execute(self.dispatch_pool()).await?.rows_affected();
        Ok(changed as usize)
    }

    pub async fn cancel_preparing_provider_dispatch_jobs(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<usize> {
        let changed = sqlx::query("UPDATE provider_dispatch_outbox SET state='cancelled', completed_at=?, updated_at=? WHERE delivery_id=? AND state='preparing'")
            .bind(now).bind(now).bind(delivery_id).execute(self.dispatch_pool()).await?.rows_affected();
        Ok(changed as usize)
    }

    pub async fn reconcile_preparing_provider_dispatch_jobs(&self, now: i64) -> StoreResult<usize> {
        let activated = sqlx::query("UPDATE provider_dispatch_outbox SET state='pending', next_attempt_at=?, updated_at=? WHERE state='preparing' AND EXISTS (SELECT 1 FROM dispatch_op_dedupe d WHERE d.delivery_id=provider_dispatch_outbox.delivery_id AND d.state IN ('provider_queued','sent','partial_failure'))")
            .bind(now).bind(now).execute(self.dispatch_pool()).await?.rows_affected();
        let cancelled = sqlx::query("UPDATE provider_dispatch_outbox SET state='cancelled', completed_at=?, updated_at=? WHERE state='preparing' AND accepted_at<=? AND NOT EXISTS (SELECT 1 FROM dispatch_op_dedupe d WHERE d.delivery_id=provider_dispatch_outbox.delivery_id AND d.state IN ('pending','provider_queued','sent','partial_failure'))")
            .bind(now).bind(now).bind(now.saturating_sub(120_000)).execute(self.dispatch_pool()).await?.rows_affected();
        Ok((activated + cancelled) as usize)
    }

    pub async fn claim_provider_dispatch_job(
        &self,
        provider: &str,
        job_id: Option<&str>,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        self.claim_provider_dispatch_job_filtered(provider, job_id, owner, now, lease_until, false)
            .await
    }

    pub async fn claim_due_provider_dispatch_retry_job(
        &self,
        provider: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        self.claim_provider_dispatch_job_filtered(provider, None, owner, now, lease_until, true)
            .await
    }

    async fn claim_provider_dispatch_job_filtered(
        &self,
        provider: &str,
        job_id: Option<&str>,
        owner: &str,
        now: i64,
        lease_until: i64,
        retry_only: bool,
    ) -> StoreResult<Option<ProviderDispatchOutboxLease>> {
        let mut tx = self.dispatch_pool().begin().await?;
        let row = if let Some(job_id) = job_id {
            sqlx::query(
                "SELECT job_id, provider, delivery_id, op_id, dedupe_key, device_key, payload_blob, next_attempt_at, \
                        accepted_at, expires_at, coalesce_order, attempt_count, lease_generation \
                 FROM provider_dispatch_outbox WHERE provider = ? AND job_id = ? AND expires_at > ? \
                   AND ((state IN ('pending','retry_wait') AND next_attempt_at <= ?) \
                     OR (state = 'leased' AND lease_until <= ?)) LIMIT 1",
            )
            .bind(provider).bind(job_id).bind(now).bind(now).bind(now)
            .fetch_optional(&mut *tx).await?
        } else if retry_only {
            sqlx::query(
                "SELECT job_id, provider, delivery_id, op_id, dedupe_key, device_key, payload_blob, next_attempt_at, \
                        accepted_at, expires_at, coalesce_order, attempt_count, lease_generation \
                 FROM provider_dispatch_outbox WHERE provider = ? AND expires_at > ? \
                   AND state = 'retry_wait' AND next_attempt_at <= ? \
                 ORDER BY expires_at, next_attempt_at, accepted_at LIMIT 1",
            )
            .bind(provider)
            .bind(now)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query(
                "SELECT job_id, provider, delivery_id, op_id, dedupe_key, device_key, payload_blob, next_attempt_at, \
                        accepted_at, expires_at, coalesce_order, attempt_count, lease_generation \
                 FROM provider_dispatch_outbox WHERE provider = ? AND expires_at > ? \
                   AND ((state IN ('pending','retry_wait') AND next_attempt_at <= ?) \
                     OR (state = 'leased' AND lease_until <= ?)) \
                 ORDER BY next_attempt_at, accepted_at LIMIT 1",
            )
            .bind(provider)
            .bind(now)
            .bind(now)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?
        };
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let selected_id: String = row.try_get("job_id")?;
        let previous_generation: i64 = row.try_get("lease_generation")?;
        let changed = sqlx::query(
            "UPDATE provider_dispatch_outbox SET state='leased', lease_owner=?, lease_until=?, \
                    lease_generation=lease_generation+1, updated_at=? \
             WHERE job_id=? AND lease_generation=? AND ((state IN ('pending','retry_wait') \
               AND next_attempt_at <= ?) OR (state='leased' AND lease_until <= ?))",
        )
        .bind(owner)
        .bind(lease_until)
        .bind(now)
        .bind(&selected_id)
        .bind(previous_generation)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            tx.rollback().await?;
            return Ok(None);
        }
        let lease = ProviderDispatchOutboxLease {
            record: ProviderDispatchOutboxRecord {
                job_id: selected_id,
                provider: row.try_get("provider")?,
                delivery_id: row.try_get("delivery_id")?,
                op_id: row.try_get("op_id")?,
                dedupe_key: row.try_get("dedupe_key")?,
                device_key: row.try_get("device_key")?,
                payload_blob: row.try_get("payload_blob")?,
                state: "leased".to_string(),
                next_attempt_at: row.try_get("next_attempt_at")?,
                accepted_at: row.try_get("accepted_at")?,
                expires_at: row.try_get("expires_at")?,
                coalesce_order: row.try_get("coalesce_order")?,
                coalescible: false,
            },
            owner: owner.to_string(),
            lease_generation: previous_generation + 1,
            lease_until,
            attempt_count: row.try_get("attempt_count")?,
        };
        tx.commit().await?;
        Ok(Some(lease))
    }

    pub async fn renew_provider_dispatch_job_lease(
        &self,
        lease: &ProviderDispatchOutboxLease,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        let changed = sqlx::query(
            "UPDATE provider_dispatch_outbox SET lease_until=?, updated_at=? \
             WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_generation=? \
               AND expires_at>?",
        )
        .bind(lease_until)
        .bind(now)
        .bind(&lease.record.job_id)
        .bind(&lease.owner)
        .bind(lease.lease_generation)
        .bind(now)
        .execute(self.dispatch_pool())
        .await?
        .rows_affected();
        Ok(changed == 1)
    }

    pub async fn settle_provider_dispatch_job(
        &self,
        lease: &ProviderDispatchOutboxLease,
        settlement: ProviderDispatchSettlement,
        next_attempt_at: i64,
        status_code: u16,
        error_code: Option<&str>,
        now: i64,
    ) -> StoreResult<bool> {
        let state = match settlement {
            ProviderDispatchSettlement::Accepted => "provider_accepted",
            ProviderDispatchSettlement::Retry => "retry_wait",
            ProviderDispatchSettlement::PermanentFailure => "permanent_failed",
            ProviderDispatchSettlement::Superseded => "superseded_route",
            ProviderDispatchSettlement::Expired => "expired",
        };
        let changed = sqlx::query(
            "UPDATE provider_dispatch_outbox SET state=?, attempt_count=attempt_count+1, \
                    next_attempt_at=?, lease_owner=NULL, lease_until=NULL, provider_status=?, \
                    provider_error_code=?, completed_at=CASE WHEN ?='retry_wait' THEN NULL ELSE ? END, \
                    updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
        )
        .bind(state).bind(next_attempt_at).bind(i32::from(status_code)).bind(error_code)
        .bind(state).bind(now).bind(now).bind(&lease.record.job_id).bind(&lease.owner)
        .bind(lease.lease_generation).execute(self.dispatch_pool()).await?.rows_affected();
        Ok(changed == 1)
    }

    pub async fn count_pending_provider_dispatch_jobs(&self, provider: &str) -> StoreResult<usize> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM provider_dispatch_outbox WHERE provider=? AND state IN ('pending','retry_wait','leased')",
        ).bind(provider).fetch_one(self.dispatch_pool()).await?;
        Ok(count.max(0) as usize)
    }

    pub async fn provider_dispatch_terminal_success(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<bool>> {
        let (total, open, failed): (i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(1), COALESCE(SUM(CASE WHEN state IN ('preparing','pending','retry_wait','leased') THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN state IN ('permanent_failed','expired','cancelled') THEN 1 ELSE 0 END),0) FROM provider_dispatch_outbox WHERE delivery_id=? AND provider IN ('APNS','FCM','WNS')"
        ).bind(delivery_id).fetch_one(self.dispatch_pool()).await?;
        Ok((total > 0 && open == 0).then_some(failed == 0))
    }

    pub async fn has_durable_dispatch_side_effects(&self, delivery_id: &str) -> StoreResult<bool> {
        let provider: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM provider_dispatch_outbox WHERE delivery_id=?")
                .bind(delivery_id)
                .fetch_one(self.dispatch_pool())
                .await?;
        if provider > 0 {
            return Ok(true);
        }
        let private: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id=?")
                .bind(delivery_id)
                .fetch_one(self.delivery_pool())
                .await?;
        if private > 0 {
            return Ok(true);
        }
        let pull: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE delivery_id=?")
                .bind(delivery_id)
                .fetch_one(self.delivery_pool())
                .await?;
        Ok(pull > 0)
    }

    pub async fn recover_expired_provider_dispatch_leases(&self, now: i64) -> StoreResult<usize> {
        let expired = sqlx::query(
            "UPDATE provider_dispatch_outbox SET state='expired', lease_owner=NULL, lease_until=NULL, completed_at=?, updated_at=? WHERE state IN ('preparing','pending','retry_wait','leased') AND expires_at<=?",
        ).bind(now).bind(now).bind(now).execute(self.dispatch_pool()).await?.rows_affected();
        let changed = sqlx::query(
            "UPDATE provider_dispatch_outbox SET state='retry_wait', lease_owner=NULL, lease_until=NULL, \
                    next_attempt_at=?, updated_at=? WHERE state='leased' AND lease_until <= ?",
        ).bind(now).bind(now).bind(now).execute(self.dispatch_pool()).await?.rows_affected();
        Ok((expired + changed) as usize)
    }

    pub async fn cleanup_terminal_provider_dispatch_jobs(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let removed = sqlx::query(
            "DELETE FROM provider_dispatch_outbox WHERE job_id IN (\
                SELECT job_id FROM provider_dispatch_outbox \
                WHERE state IN ('provider_accepted','permanent_failed','superseded_route','expired','cancelled') \
                  AND completed_at IS NOT NULL AND completed_at<=? \
                ORDER BY completed_at,job_id LIMIT ?\
             )",
        )
        .bind(before_ts)
        .bind(limit.min(100_000) as i64)
        .execute(self.dispatch_pool())
        .await?
        .rows_affected();
        Ok(removed as usize)
    }
}
