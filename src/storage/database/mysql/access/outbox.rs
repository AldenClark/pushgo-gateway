use super::*;

impl MySqlDb {
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
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
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
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
            .bind(&device_id[..])
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = ? \
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
        let rows = sqlx::query("SELECT delivery_id FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_all(&mut *tx)
            .await?;
        let ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &ids {
            sqlx::query(
                "DELETE FROM private_payloads \
                 WHERE delivery_id = ? \
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
             FROM private_outbox WHERE next_attempt_at <= ? AND status IN (?, ?, ?) LIMIT ?",
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
                    attempts: r.get::<u32, _>("attempts"),
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
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE next_attempt_at <= ? AND status IN (?, ?, ?) \
             LIMIT ? FOR UPDATE",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let device_id_raw: Vec<u8> = r.get("device_id");
            let delivery_id: String = r.get("delivery_id");

            let updated_row = sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(&device_id_raw)
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;

            if updated_row.rows_affected() > 0 {
                let r = sqlx::query(
                    "SELECT * FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
                )
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
                        attempts: r.get::<u32, _>("attempts"),
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
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = ? AND next_attempt_at <= ? AND status IN (?, ?, ?) \
             LIMIT ? FOR UPDATE",
        )
        .bind(&device_id[..])
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let delivery_id: String = r.get("delivery_id");

            sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
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
                attempts: r.get::<u32, _>("attempts"),
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
                .fetch_one(&self.pool)
                .await?;
        Ok(count as usize)
    }
}
