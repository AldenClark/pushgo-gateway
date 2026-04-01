use super::*;

impl PostgresDb {
    pub(super) async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = $3, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, $4), fallback_sent_at = $4, updated_at = $4 \
             WHERE device_id = $1 AND delivery_id = $2",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_SENT)
        .bind(at_ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = $3, attempts = attempts + 1, next_attempt_at = $4, updated_at = $4 \
             WHERE device_id = $1 AND delivery_id = $2",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(at_ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2")
            .bind(&device_id[..])
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = $1 \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let rows =
            sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 RETURNING delivery_id")
                .bind(&device_id[..])
                .fetch_all(&mut *tx)
                .await?;
        let ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();

        for delivery_id in &ids {
            sqlx::query(
                "DELETE FROM private_payloads \
                 WHERE delivery_id = $1 \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(ids)
    }

    pub(super) async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let rows = sqlx::query(
            "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE next_attempt_at <= $1 AND status IN ($2, $3, $4) LIMIT $5",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
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
                    attempts: r.get::<i32, _>("attempts") as u32,
                    occurred_at: r.get("occurred_at"),
                    created_at: r.get("created_at"),
                    claimed_at: r.get("claimed_at"),
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
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let rows = sqlx::query(
            "UPDATE private_outbox SET status = $1, claimed_at = $2, last_attempt_at = $2, updated_at = $2 \
             WHERE (device_id, delivery_id) IN ( \
                SELECT device_id, delivery_id FROM private_outbox \
                WHERE next_attempt_at <= $3 AND status IN ($4, $5, $6) \
                LIMIT $7 FOR UPDATE SKIP LOCKED \
             ) RETURNING *",
        )
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(claim_until_ts)
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
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
                    attempts: r.get::<i32, _>("attempts") as u32,
                    occurred_at: r.get("occurred_at"),
                    created_at: r.get("created_at"),
                    claimed_at: r.get("claimed_at"),
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

    pub(super) async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let rows = sqlx::query(
            "UPDATE private_outbox SET status = $1, claimed_at = $2, last_attempt_at = $2, updated_at = $2 \
             WHERE (device_id, delivery_id) IN ( \
                SELECT device_id, delivery_id FROM private_outbox \
                WHERE device_id = $3 AND next_attempt_at <= $4 AND status IN ($5, $6, $7) \
                LIMIT $8 FOR UPDATE SKIP LOCKED \
             ) RETURNING *",
        )
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(claim_until_ts)
        .bind(&device_id[..])
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| PrivateOutboxEntry {
                delivery_id: r.get("delivery_id"),
                status: r.get("status"),
                attempts: r.get::<i32, _>("attempts") as u32,
                occurred_at: r.get("occurred_at"),
                created_at: r.get("created_at"),
                claimed_at: r.get("claimed_at"),
                first_sent_at: r.get("first_sent_at"),
                last_attempt_at: r.get("last_attempt_at"),
                acked_at: r.get("acked_at"),
                fallback_sent_at: r.get("fallback_sent_at"),
                next_attempt_at: r.get("next_attempt_at"),
                last_error_code: r.get("last_error_code"),
                last_error_detail: r.get("last_error_detail"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    pub(super) async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN ($1, $2, $3)")
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(&self.pool)
                .await?;
        Ok(count as usize)
    }
}
