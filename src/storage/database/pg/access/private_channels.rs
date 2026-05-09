use super::*;

impl PostgresDb {
    pub(super) async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query("SELECT delivery_id FROM private_outbox WHERE device_id = $1")
            .bind(&device_id[..])
            .fetch_all(&mut *tx)
            .await?;
        let delivery_ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();

        sqlx::query("DELETE FROM private_bindings WHERE device_id = $1")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &delivery_ids {
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
        Ok(())
    }

    pub(super) async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        let size = message.size as i64;
        let now = Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO private_payloads (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (delivery_id) DO UPDATE SET \
             payload_blob = EXCLUDED.payload_blob, payload_size = EXCLUDED.payload_size, updated_at = EXCLUDED.updated_at",
        )
        .bind(delivery_id)
        .bind(message.payload.as_ref())
        .bind(size)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                 status = EXCLUDED.status, attempts = EXCLUDED.attempts, updated_at = EXCLUDED.updated_at, next_attempt_at = EXCLUDED.next_attempt_at",
        )
        .bind(&device_id[..])
        .bind(&entry.delivery_id)
        .bind(&entry.status)
        .bind(entry.attempts as i32)
        .bind(entry.occurred_at)
        .bind(entry.created_at)
        .bind(entry.claimed_at)
        .bind(entry.first_sent_at)
        .bind(entry.last_attempt_at)
        .bind(entry.acked_at)
        .bind(entry.fallback_sent_at)
        .bind(entry.next_attempt_at)
        .bind(entry.last_error_code.as_deref())
        .bind(entry.last_error_detail.as_deref())
        .bind(entry.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn enqueue_private_outbox_batch(
        &self,
        entries: &[PrivateOutboxBatchEntry],
        max_pending_per_device: usize,
        global_max_pending: usize,
        protected_delivery_id: Option<&str>,
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await?;
        for chunk in entries.chunks(50) {
            let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) ",
            );
            query.push_values(chunk, |mut row, item| {
                row.push_bind(&item.device_id[..])
                    .push_bind(&item.entry.delivery_id)
                    .push_bind(&item.entry.status)
                    .push_bind(item.entry.attempts as i32)
                    .push_bind(item.entry.occurred_at)
                    .push_bind(item.entry.created_at)
                    .push_bind(item.entry.claimed_at)
                    .push_bind(item.entry.first_sent_at)
                    .push_bind(item.entry.last_attempt_at)
                    .push_bind(item.entry.acked_at)
                    .push_bind(item.entry.fallback_sent_at)
                    .push_bind(item.entry.next_attempt_at)
                    .push_bind(item.entry.last_error_code.as_deref())
                    .push_bind(item.entry.last_error_detail.as_deref())
                    .push_bind(item.entry.updated_at);
            });
            query.push(
                " ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                 status = EXCLUDED.status, attempts = EXCLUDED.attempts, updated_at = EXCLUDED.updated_at, next_attempt_at = EXCLUDED.next_attempt_at",
            );
            query.build().execute(&mut *tx).await?;
        }
        let mut pruned_delivery_ids = Vec::new();
        for device_id in unique_batch_device_ids(entries) {
            pruned_delivery_ids.extend(
                prune_pg_device_outbox_overflow(
                    &mut tx,
                    device_id,
                    max_pending_per_device,
                    protected_delivery_id,
                )
                .await?,
            );
        }
        pruned_delivery_ids.extend(
            prune_pg_global_outbox_overflow(&mut tx, global_max_pending, protected_delivery_id)
                .await?,
        );
        cleanup_pg_pruned_payloads(&mut tx, &pruned_delivery_ids).await?;
        tx.commit().await?;
        Ok(pruned_delivery_ids.len())
    }

    pub(super) async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let rows = sqlx::query(
            "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4) \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT $5",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(PrivateOutboxEntry {
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
            });
        }
        Ok(out)
    }

    pub(super) async fn count_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4)",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    pub(super) async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        let mut removed = 0usize;
        let expired_rows = sqlx::query(
            "SELECT delivery_id FROM private_payloads \
             WHERE expires_at <= $1 \
             ORDER BY expires_at ASC \
             LIMIT $2",
        )
        .bind(before_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        for row in expired_rows {
            let delivery_id: String = row.get("delivery_id");
            sqlx::query("DELETE FROM private_payloads WHERE delivery_id = $1")
                .bind(&delivery_id)
                .execute(&self.pool)
                .await?;
            sqlx::query("DELETE FROM private_outbox WHERE delivery_id = $1")
                .bind(&delivery_id)
                .execute(&self.pool)
                .await?;
            removed = removed.saturating_add(1);
        }

        let dangling_rows = sqlx::query(
            "SELECT o.device_id, o.delivery_id \
             FROM private_outbox o \
             LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
             WHERE m.delivery_id IS NULL \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        for row in dangling_rows {
            let device_id: Vec<u8> = row.get("device_id");
            let delivery_id: String = row.get("delivery_id");
            sqlx::query(
                "DELETE FROM private_outbox \
                 WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(&device_id)
            .bind(&delivery_id)
            .execute(&self.pool)
            .await?;
            removed = removed.saturating_add(1);
        }
        Ok(removed)
    }

    pub(super) async fn cleanup_pending_op_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        let removed = sqlx::query(
            "WITH doomed AS (\
                SELECT dedupe_key \
                FROM dispatch_op_dedupe \
                WHERE created_at <= $1 AND state = $2 \
                ORDER BY created_at ASC \
                LIMIT $3\
             ) \
             DELETE FROM dispatch_op_dedupe d \
             USING doomed \
             WHERE d.dedupe_key = doomed.dedupe_key",
        )
        .bind(before_ts)
        .bind(DedupeState::Pending.as_str())
        .bind(limit)
        .execute(&self.pool)
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_semantic_id_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        let removed = sqlx::query(
            "WITH doomed AS (\
                SELECT dedupe_key \
                FROM semantic_id_registry \
                WHERE created_at <= $1 \
                ORDER BY created_at ASC \
                LIMIT $2\
             ) \
             DELETE FROM semantic_id_registry d \
             USING doomed \
             WHERE d.dedupe_key = doomed.dedupe_key",
        )
        .bind(before_ts)
        .bind(limit)
        .execute(&self.pool)
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_delivery_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        let removed = sqlx::query(
            "WITH doomed AS (\
                SELECT dedupe_key \
                FROM dispatch_delivery_dedupe \
                WHERE created_at <= $1 \
                ORDER BY created_at ASC \
                LIMIT $2\
             ) \
             DELETE FROM dispatch_delivery_dedupe d \
             USING doomed \
             WHERE d.dedupe_key = doomed.dedupe_key",
        )
        .bind(before_ts)
        .bind(limit)
        .execute(&self.pool)
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
        let removed = sqlx::query("DELETE FROM private_sessions WHERE expires_at <= $1")
            .bind(before_ts)
            .execute(&self.pool)
            .await?
            .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        let (token_hash, _) = ProviderTokenSnapshot::from_token(token).into_parts();
        sqlx::query(
            "INSERT INTO private_bindings (device_id, platform, provider_token, token_hash, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (platform, token_hash) DO UPDATE SET \
                device_id = EXCLUDED.device_id, \
                provider_token = EXCLUDED.provider_token, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind(&device_id[..])
        .bind(platform.to_byte() as i16)
        .bind(token)
        .bind(&token_hash)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn unique_batch_device_ids(entries: &[PrivateOutboxBatchEntry]) -> Vec<DeviceId> {
    let mut device_ids = Vec::new();
    for entry in entries {
        if !device_ids.contains(&entry.device_id) {
            device_ids.push(entry.device_id);
        }
    }
    device_ids
}

async fn prune_pg_device_outbox_overflow(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: DeviceId,
    max_pending_per_device: usize,
    protected_delivery_id: Option<&str>,
) -> StoreResult<Vec<String>> {
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4)",
    )
    .bind(&device_id[..])
    .bind(OUTBOX_STATUS_PENDING)
    .bind(OUTBOX_STATUS_CLAIMED)
    .bind(OUTBOX_STATUS_SENT)
    .fetch_one(&mut **tx)
    .await?;
    let excess = active_count.saturating_sub(max_pending_per_device as i64);
    if excess <= 0 {
        return Ok(Vec::new());
    }

    let rows = if let Some(protected_delivery_id) = protected_delivery_id {
        sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = $1 AND status = $2 AND delivery_id <> $3 \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT $4",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(protected_delivery_id)
        .bind(excess)
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = $1 AND status = $2 \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT $3",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(excess)
        .fetch_all(&mut **tx)
        .await?
    };
    let delivery_ids = rows
        .into_iter()
        .map(|row| row.get("delivery_id"))
        .collect::<Vec<String>>();
    for delivery_id in &delivery_ids {
        sqlx::query(
            "DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2 AND status = $3",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_PENDING)
        .execute(&mut **tx)
        .await?;
    }
    Ok(delivery_ids)
}

async fn prune_pg_global_outbox_overflow(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    global_max_pending: usize,
    protected_delivery_id: Option<&str>,
) -> StoreResult<Vec<String>> {
    let active_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN ($1, $2, $3)")
            .bind(OUTBOX_STATUS_PENDING)
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(OUTBOX_STATUS_SENT)
            .fetch_one(&mut **tx)
            .await?;
    let excess = active_count.saturating_sub(global_max_pending as i64);
    if excess <= 0 {
        return Ok(Vec::new());
    }

    let rows = if let Some(protected_delivery_id) = protected_delivery_id {
        sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE status = $1 AND delivery_id <> $2 \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT $3",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(protected_delivery_id)
        .bind(excess)
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE status = $1 \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT $2",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(excess)
        .fetch_all(&mut **tx)
        .await?
    };

    let mut delivery_ids = Vec::with_capacity(rows.len());
    for row in rows {
        let device_id: Vec<u8> = row.get("device_id");
        let delivery_id: String = row.get("delivery_id");
        sqlx::query(
            "DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2 AND status = $3",
        )
        .bind(&device_id)
        .bind(&delivery_id)
        .bind(OUTBOX_STATUS_PENDING)
        .execute(&mut **tx)
        .await?;
        delivery_ids.push(delivery_id);
    }
    Ok(delivery_ids)
}

async fn cleanup_pg_pruned_payloads(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_ids: &[String],
) -> StoreResult<()> {
    for delivery_id in delivery_ids {
        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = $1 \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
