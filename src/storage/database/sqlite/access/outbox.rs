use super::*;

impl SqliteDb {
    pub(super) async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, ?), fallback_sent_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(OUTBOX_STATUS_SENT)
        .bind(at_ts)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .execute(self.delivery_pool())
        .await?;
        Ok(())
    }

    pub(super) async fn mark_private_fallback_sent_if_claimed(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        worker_id: &str,
        claim_generation: u64,
        at_ts: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, ?), fallback_sent_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ? AND status = ? AND claimed_by = ? AND claim_generation = ?",
        )
        .bind(OUTBOX_STATUS_SENT)
        .bind(at_ts)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(worker_id)
        .bind(claim_generation.min(i64::MAX as u64) as i64)
        .execute(self.delivery_pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(super) async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .execute(self.delivery_pool())
        .await?;
        Ok(())
    }

    pub(super) async fn defer_private_fallback_if_claimed(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        worker_id: &str,
        claim_generation: u64,
        at_ts: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, next_attempt_at = ?, claimed_at = NULL, claimed_by = NULL, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ? AND status = ? AND claimed_by = ? AND claim_generation = ?",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(worker_id)
        .bind(claim_generation.min(i64::MAX as u64) as i64)
        .execute(self.delivery_pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(super) async fn drop_private_delivery_if_claimed(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        worker_id: &str,
        claim_generation: u64,
    ) -> StoreResult<bool> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "DELETE FROM private_outbox \
             WHERE device_id = ? AND delivery_id = ? AND status = ? AND claimed_by = ? AND claim_generation = ?",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(worker_id)
        .bind(claim_generation.min(i64::MAX as u64) as i64)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 1 {
            delete_unreferenced_private_payload(&mut tx, delivery_id).await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub(super) async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let now = Utc::now().timestamp_millis();
        let acknowledged = sqlx::query(
            "UPDATE private_outbox SET status = ?, acked_at = ?, claimed_at = NULL, claimed_by = NULL, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
        )
        .bind(OUTBOX_STATUS_ACKED)
        .bind(now)
        .bind(now)
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = ? \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id AND private_outbox.status <> 'acked') \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(acknowledged.rows_affected() == 1)
    }

    pub(super) async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT delivery_id FROM private_outbox WHERE device_id = ? AND status <> 'acked'",
        )
        .bind(&device_id[..])
        .fetch_all(&mut *tx)
        .await?;
        let ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &ids {
            sqlx::query(
                "DELETE FROM private_payloads \
                 WHERE delivery_id = ? \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id AND private_outbox.status <> 'acked') \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(ids)
    }

    pub(super) async fn evict_oldest_pending_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Option<String>> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = ? AND status = ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT 1",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let delivery_id: String = row.get("delivery_id");
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
            .bind(&device_id[..])
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;
        delete_unreferenced_private_payload(&mut tx, &delivery_id).await?;
        tx.commit().await?;
        Ok(Some(delivery_id))
    }

    pub(super) async fn evict_oldest_pending_private_outbox_global(
        &self,
    ) -> StoreResult<Option<(DeviceId, String)>> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE status = ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT 1",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let raw_device_id: Vec<u8> = row.get("device_id");
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&raw_device_id);
        let delivery_id: String = row.get("delivery_id");
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
            .bind(&device_id[..])
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;
        delete_unreferenced_private_payload(&mut tx, &delivery_id).await?;
        tx.commit().await?;
        Ok(Some((device_id, delivery_id)))
    }

    pub(super) async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let rows = sqlx::query(
            "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, claimed_by, claim_generation, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE next_attempt_at <= ? AND status IN (?, ?, ?) LIMIT ?",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(self.delivery_pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let mut device_id = [0u8; 16];
            let raw: Vec<u8> = r.get("device_id");
            device_id.copy_from_slice(&raw);
            out.push((
                device_id,
                PrivateOutboxEntry {
                    delivery_id: r.get("delivery_id"),
                    status: r.get("status"),
                    attempts: r.get::<i64, _>("attempts") as u32,
                    occurred_at: r.get("occurred_at"),
                    created_at: r.get("created_at"),
                    claimed_at: r.get("claimed_at"),
                    claimed_by: r.get("claimed_by"),
                    claim_generation: r.get::<i64, _>("claim_generation").max(0) as u64,
                    first_sent_at: r.get("first_sent_at"),
                    last_attempt_at: r.get("last_attempt_at"),
                    acked_at: r.get("acked_at"),
                    fallback_sent_at: r.get("fallback_sent_at"),
                    next_attempt_at: r.get("next_attempt_at"),
                    last_error_code: r.get("last_error_code"),
                    last_error_detail: r.get("last_error_detail"),
                    updated_at: r.get("updated_at"),
                },
            ));
        }
        Ok(out)
    }

    pub(super) async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
        worker_id: &str,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE next_attempt_at <= ? \
               AND (status = ? OR (status IN (?, ?) AND (claimed_at IS NULL OR claimed_at <= ?))) \
             ORDER BY next_attempt_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let device_id_raw: Vec<u8> = r.get("device_id");
            let delivery_id: String = r.get("delivery_id");

            sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, claimed_by = ?, claim_generation = claim_generation + 1, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
            .bind(worker_id)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(&device_id_raw)
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;

            let r =
                sqlx::query("SELECT * FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id_raw)
                    .bind(&delivery_id)
                    .fetch_one(&mut *tx)
                    .await?;

            let mut device_id = [0u8; 16];
            device_id.copy_from_slice(&device_id_raw);
            out.push((
                device_id,
                PrivateOutboxEntry {
                    delivery_id: r.get("delivery_id"),
                    status: r.get("status"),
                    attempts: r.get::<i64, _>("attempts") as u32,
                    occurred_at: r.get("occurred_at"),
                    created_at: r.get("created_at"),
                    claimed_at: r.get("claimed_at"),
                    claimed_by: r.get("claimed_by"),
                    claim_generation: r.get::<i64, _>("claim_generation").max(0) as u64,
                    first_sent_at: r.get("first_sent_at"),
                    last_attempt_at: r.get("last_attempt_at"),
                    acked_at: r.get("acked_at"),
                    fallback_sent_at: r.get("fallback_sent_at"),
                    next_attempt_at: r.get("next_attempt_at"),
                    last_error_code: r.get("last_error_code"),
                    last_error_detail: r.get("last_error_detail"),
                    updated_at: r.get("updated_at"),
                },
            ));
        }
        tx.commit().await?;
        Ok(out)
    }

    pub(super) async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
        worker_id: &str,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = ? AND next_attempt_at <= ? \
               AND (status = ? OR (status IN (?, ?) AND (claimed_at IS NULL OR claimed_at <= ?))) \
             ORDER BY next_attempt_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
        )
        .bind(&device_id[..])
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let delivery_id: String = r.get("delivery_id");

            sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, claimed_by = ?, claim_generation = claim_generation + 1, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
            .bind(worker_id)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(&device_id[..])
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;

            let r =
                sqlx::query("SELECT * FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id[..])
                    .bind(&delivery_id)
                    .fetch_one(&mut *tx)
                    .await?;

            out.push(PrivateOutboxEntry {
                delivery_id: r.get("delivery_id"),
                status: r.get("status"),
                attempts: r.get::<i64, _>("attempts") as u32,
                occurred_at: r.get("occurred_at"),
                created_at: r.get("created_at"),
                claimed_at: r.get("claimed_at"),
                claimed_by: r.get("claimed_by"),
                claim_generation: r.get::<i64, _>("claim_generation").max(0) as u64,
                first_sent_at: r.get("first_sent_at"),
                last_attempt_at: r.get("last_attempt_at"),
                acked_at: r.get("acked_at"),
                fallback_sent_at: r.get("fallback_sent_at"),
                next_attempt_at: r.get("next_attempt_at"),
                last_error_code: r.get("last_error_code"),
                last_error_detail: r.get("last_error_detail"),
                updated_at: r.get("updated_at"),
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    pub(super) async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN (?, ?, ?)")
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(self.delivery_pool())
                .await?;
        Ok(count as usize)
    }
}

async fn delete_unreferenced_private_payload(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    delivery_id: &str,
) -> StoreResult<()> {
    sqlx::query(
        "DELETE FROM private_payloads \
         WHERE delivery_id = ? \
           AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id AND private_outbox.status <> 'acked') \
           AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
    )
    .bind(delivery_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn mark_provider_delivery_consumed_sqlite_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device_id: DeviceId,
    delivery_id: &str,
    now: i64,
) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, claimed_by, \
          claim_generation, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, \
          last_error_code, last_error_detail, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?, NULL, NULL, 0, NULL, NULL, ?, NULL, ?, NULL, NULL, ?) \
         ON CONFLICT(device_id, delivery_id) DO UPDATE SET \
           status = EXCLUDED.status, acked_at = COALESCE(private_outbox.acked_at, EXCLUDED.acked_at), \
           claimed_at = NULL, claimed_by = NULL, updated_at = EXCLUDED.updated_at",
    )
    .bind(device_id.as_slice())
    .bind(delivery_id)
    .bind(OUTBOX_STATUS_ACKED)
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(i64::MAX)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
