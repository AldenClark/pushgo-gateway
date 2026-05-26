use super::*;

const SQLITE_PRIVATE_WRITE_BATCH_ROWS: usize = 64;
const SQLITE_PRIVATE_CLEANUP_BATCH_ROWS: usize = 256;

impl SqliteDb {
    pub(super) async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&self.pool)
            .await?;

        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query("SELECT delivery_id FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_all(&mut *tx)
            .await?;
        let delivery_ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();

        sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &delivery_ids {
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
             VALUES (?, ?, ?, ?, ?, ?, ?) \
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
        .execute(self.delivery_pool())
        .await?;
        Ok(())
    }

    pub(crate) async fn insert_private_messages_batch(
        &self,
        entries: &[PrivateMessageBatchEntry],
    ) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        insert_private_messages_sqlite_tx(&mut tx, entries).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                 status = EXCLUDED.status, attempts = EXCLUDED.attempts, updated_at = EXCLUDED.updated_at, next_attempt_at = EXCLUDED.next_attempt_at",
        )
        .bind(&device_id[..])
        .bind(&entry.delivery_id)
        .bind(&entry.status)
        .bind(entry.attempts as i64)
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
        .execute(self.delivery_pool())
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
        let mut pruned = 0usize;
        for chunk in entries.chunks(SQLITE_PRIVATE_WRITE_BATCH_ROWS) {
            let mut conn = self.delivery_pool().acquire().await?;
            let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
            insert_private_outbox_sqlite_tx(&mut tx, chunk).await?;
            let mut pruned_delivery_ids = Vec::new();
            for device_id in unique_batch_device_ids(chunk) {
                pruned_delivery_ids.extend(
                    prune_sqlite_device_outbox_overflow(
                        &mut tx,
                        device_id,
                        max_pending_per_device,
                        protected_delivery_id,
                    )
                    .await?,
                );
            }
            pruned_delivery_ids.extend(
                prune_sqlite_global_outbox_overflow(
                    &mut tx,
                    global_max_pending,
                    protected_delivery_id,
                )
                .await?,
            );
            cleanup_sqlite_pruned_payloads(&mut tx, &pruned_delivery_ids).await?;
            pruned = pruned.saturating_add(pruned_delivery_ids.len());
            tx.commit().await?;
        }
        Ok(pruned)
    }

    pub(crate) async fn enqueue_private_outbox_messages_batch(
        &self,
        entries: &[PrivateOutboxMessageBatchEntry],
        max_pending_per_device: usize,
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let payloads = entries
            .iter()
            .map(|item| PrivateMessageBatchEntry {
                delivery_id: item.entry.delivery_id.clone(),
                message: item.message.clone(),
            })
            .collect::<Vec<_>>();
        insert_private_messages_sqlite_tx(&mut tx, &payloads).await?;

        let outbox = entries
            .iter()
            .map(|item| PrivateOutboxBatchEntry {
                device_id: item.device_id,
                entry: item.entry.clone(),
            })
            .collect::<Vec<_>>();
        insert_private_outbox_sqlite_tx(&mut tx, &outbox).await?;

        let mut pruned_delivery_ids = Vec::new();
        for device_id in unique_batch_device_ids(&outbox) {
            pruned_delivery_ids.extend(
                prune_sqlite_device_outbox_overflow(
                    &mut tx,
                    device_id,
                    max_pending_per_device,
                    None,
                )
                .await?,
            );
        }
        cleanup_sqlite_pruned_payloads(&mut tx, &pruned_delivery_ids).await?;
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
             FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(self.delivery_pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(PrivateOutboxEntry {
                delivery_id: r.get("delivery_id"),
                status: r.get("status"),
                attempts: r.get::<i64, _>("attempts") as u32,
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

    pub(crate) async fn list_private_outbox_with_messages(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxMessageRow>> {
        let rows = sqlx::query(
            "SELECT o.device_id, o.delivery_id, o.status, o.attempts, o.occurred_at, o.created_at, \
                    o.claimed_at, o.first_sent_at, o.last_attempt_at, o.acked_at, o.fallback_sent_at, \
                    o.next_attempt_at, o.last_error_code, o.last_error_detail, o.updated_at, \
                    p.payload_blob, p.payload_size, p.sent_at, p.expires_at \
             FROM private_outbox o \
             LEFT JOIN private_payloads p ON p.delivery_id = o.delivery_id \
             WHERE o.device_id = ? AND o.status IN (?, ?, ?) \
             ORDER BY o.occurred_at ASC, o.created_at ASC, o.delivery_id ASC LIMIT ?",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(self.delivery_pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw_device_id: Vec<u8> = row.get("device_id");
            let mut row_device_id = [0u8; 16];
            row_device_id.copy_from_slice(&raw_device_id);
            let message = row
                .get::<Option<Vec<u8>>, _>("payload_blob")
                .map(|payload| PrivateMessage {
                    payload: std::sync::Arc::from(payload),
                    size: row
                        .get::<Option<i64>, _>("payload_size")
                        .unwrap_or_default() as usize,
                    sent_at: row.get::<Option<i64>, _>("sent_at").unwrap_or_default(),
                    expires_at: row.get::<Option<i64>, _>("expires_at").unwrap_or_default(),
                });
            out.push(PrivateOutboxMessageRow {
                device_id: row_device_id,
                entry: private_outbox_entry_from_sqlite_row(&row),
                message,
            });
        }
        Ok(out)
    }

    pub(super) async fn count_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?)",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .fetch_one(self.delivery_pool())
        .await?;
        Ok(count as usize)
    }

    pub(super) async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut removed = 0usize;
        let mut remaining = limit;
        while remaining > 0 {
            let batch_limit = remaining.min(SQLITE_PRIVATE_CLEANUP_BATCH_ROWS);
            let (selected, deleted) = self
                .cleanup_private_expired_payloads_chunk(before_ts, batch_limit)
                .await?;
            removed = removed.saturating_add(deleted);
            remaining = remaining.saturating_sub(selected);
            if selected < batch_limit {
                break;
            }
        }

        let mut remaining = limit;
        while remaining > 0 {
            let batch_limit = remaining.min(SQLITE_PRIVATE_CLEANUP_BATCH_ROWS);
            let (selected, deleted) = self
                .cleanup_private_dangling_outbox_chunk(batch_limit)
                .await?;
            removed = removed.saturating_add(deleted);
            remaining = remaining.saturating_sub(selected);
            if selected < batch_limit {
                break;
            }
        }
        Ok(removed)
    }

    async fn cleanup_private_expired_payloads_chunk(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<(usize, usize)> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let expired_rows = sqlx::query(
            "SELECT delivery_id FROM private_payloads \
             WHERE expires_at <= ? \
             ORDER BY expires_at ASC \
             LIMIT ?",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let selected = expired_rows.len();
        let mut removed = 0usize;
        for row in expired_rows {
            let delivery_id: String = row.get("delivery_id");
            sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?;
            removed = removed.saturating_add(
                sqlx::query("DELETE FROM private_outbox WHERE delivery_id = ?")
                    .bind(&delivery_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize,
            );
        }
        tx.commit().await?;
        Ok((selected, removed))
    }

    async fn cleanup_private_dangling_outbox_chunk(
        &self,
        limit: usize,
    ) -> StoreResult<(usize, usize)> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let dangling_rows = sqlx::query(
            "SELECT o.device_id, o.delivery_id \
             FROM private_outbox o \
             LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
             WHERE m.delivery_id IS NULL \
             LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let selected = dangling_rows.len();
        let mut removed = 0usize;
        for row in dangling_rows {
            let device_id: Vec<u8> = row.get("device_id");
            let delivery_id: String = row.get("delivery_id");
            removed = removed.saturating_add(
                sqlx::query(
                    "DELETE FROM private_outbox \
                     WHERE device_id = ? AND delivery_id = ?",
                )
                .bind(&device_id)
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize,
            );
        }
        tx.commit().await?;
        Ok((selected, removed))
    }

    pub(crate) async fn clear_private_outbox_entries(
        &self,
        entries: &[(DeviceId, String)],
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        let mut removed = 0usize;
        for chunk in entries.chunks(SQLITE_PRIVATE_WRITE_BATCH_ROWS) {
            let mut conn = self.delivery_pool().acquire().await?;
            let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
            let mut delivery_ids = Vec::with_capacity(chunk.len());
            for (device_id, delivery_id) in chunk {
                removed = removed.saturating_add(
                    sqlx::query(
                        "DELETE FROM private_outbox \
                         WHERE device_id = ? AND delivery_id = ?",
                    )
                    .bind(&device_id[..])
                    .bind(delivery_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize,
                );
                delivery_ids.push(delivery_id.clone());
            }
            cleanup_sqlite_pruned_payloads(&mut tx, &delivery_ids).await?;
            tx.commit().await?;
        }
        Ok(removed)
    }

    pub(super) async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
        let removed = sqlx::query("DELETE FROM private_sessions WHERE expires_at <= ?")
            .bind(before_ts)
            .execute(&self.pool)
            .await?
            .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_pending_op_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let removed = sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key IN (\
                SELECT dedupe_key FROM (\
                    SELECT dedupe_key \
                    FROM dispatch_op_dedupe \
                    WHERE created_at <= ? AND state = ? \
                    ORDER BY created_at ASC \
                    LIMIT ?\
                ) AS t\
             )",
        )
        .bind(before_ts)
        .bind(DedupeState::Pending.as_str())
        .bind(limit as i64)
        .execute(self.dispatch_pool())
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_semantic_id_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let removed = sqlx::query(
            "DELETE FROM semantic_id_registry \
             WHERE rowid IN (\
                SELECT rowid \
                FROM semantic_id_registry \
                WHERE created_at <= ? \
                ORDER BY created_at ASC, rowid ASC \
                LIMIT ?\
             )",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .execute(self.dispatch_pool())
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    pub(super) async fn cleanup_delivery_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let removed = sqlx::query(
            "DELETE FROM dispatch_delivery_dedupe \
             WHERE rowid IN (\
                SELECT rowid \
                FROM dispatch_delivery_dedupe \
                WHERE created_at <= ? \
                ORDER BY created_at ASC, rowid ASC \
                LIMIT ?\
             )",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .execute(self.dispatch_pool())
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
             VALUES (?, ?, ?, ?, ?, ?) \
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

async fn insert_private_messages_sqlite_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entries: &[PrivateMessageBatchEntry],
) -> StoreResult<()> {
    let now = Utc::now().timestamp_millis();
    for chunk in entries.chunks(SQLITE_PRIVATE_WRITE_BATCH_ROWS) {
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO private_payloads \
             (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) ",
        );
        query.push_values(chunk, |mut row, item| {
            row.push_bind(&item.delivery_id)
                .push_bind(item.message.payload.as_ref())
                .push_bind(item.message.size as i64)
                .push_bind(item.message.sent_at)
                .push_bind(item.message.expires_at)
                .push_bind(now)
                .push_bind(now);
        });
        query.push(
            " ON CONFLICT (delivery_id) DO UPDATE SET \
             payload_blob = EXCLUDED.payload_blob, payload_size = EXCLUDED.payload_size, updated_at = EXCLUDED.updated_at",
        );
        query.build().execute(&mut **tx).await?;
    }
    Ok(())
}

async fn insert_private_outbox_sqlite_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entries: &[PrivateOutboxBatchEntry],
) -> StoreResult<()> {
    for chunk in entries.chunks(SQLITE_PRIVATE_WRITE_BATCH_ROWS) {
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) ",
        );
        query.push_values(chunk, |mut row, item| {
            row.push_bind(&item.device_id[..])
                .push_bind(&item.entry.delivery_id)
                .push_bind(&item.entry.status)
                .push_bind(item.entry.attempts as i64)
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
        query.build().execute(&mut **tx).await?;
    }
    Ok(())
}

fn private_outbox_entry_from_sqlite_row(row: &sqlx::sqlite::SqliteRow) -> PrivateOutboxEntry {
    PrivateOutboxEntry {
        delivery_id: row.get("delivery_id"),
        status: row.get("status"),
        attempts: row.get::<i64, _>("attempts") as u32,
        occurred_at: row.get("occurred_at"),
        created_at: row.get("created_at"),
        claimed_at: row.get("claimed_at"),
        first_sent_at: row.get("first_sent_at"),
        last_attempt_at: row.get("last_attempt_at"),
        acked_at: row.get("acked_at"),
        fallback_sent_at: row.get("fallback_sent_at"),
        next_attempt_at: row.get("next_attempt_at"),
        last_error_code: row.get("last_error_code"),
        last_error_detail: row.get("last_error_detail"),
        updated_at: row.get("updated_at"),
    }
}

async fn prune_sqlite_device_outbox_overflow(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device_id: DeviceId,
    max_pending_per_device: usize,
    protected_delivery_id: Option<&str>,
) -> StoreResult<Vec<String>> {
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(OUTBOX_STATUS_PENDING)
    .bind(OUTBOX_STATUS_CLAIMED)
    .bind(OUTBOX_STATUS_SENT)
    .fetch_one(&mut **tx)
    .await?;
    let max_pending_per_device = max_pending_per_device.min(i64::MAX as usize) as i64;
    let excess = active_count.saturating_sub(max_pending_per_device);
    if excess <= 0 {
        return Ok(Vec::new());
    }

    let rows = if let Some(protected_delivery_id) = protected_delivery_id {
        sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = ? AND status = ? AND delivery_id <> ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
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
             WHERE device_id = ? AND status = ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
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
            "DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ? AND status = ?",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .bind(OUTBOX_STATUS_PENDING)
        .execute(&mut **tx)
        .await?;
    }
    Ok(delivery_ids)
}

async fn prune_sqlite_global_outbox_overflow(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    global_max_pending: usize,
    protected_delivery_id: Option<&str>,
) -> StoreResult<Vec<String>> {
    let active_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN (?, ?, ?)")
            .bind(OUTBOX_STATUS_PENDING)
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(OUTBOX_STATUS_SENT)
            .fetch_one(&mut **tx)
            .await?;
    let global_max_pending = global_max_pending.min(i64::MAX as usize) as i64;
    let excess = active_count.saturating_sub(global_max_pending);
    if excess <= 0 {
        return Ok(Vec::new());
    }

    let rows = if let Some(protected_delivery_id) = protected_delivery_id {
        sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE status = ? AND delivery_id <> ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(protected_delivery_id)
        .bind(excess)
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE status = ? \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
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
            "DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ? AND status = ?",
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

async fn cleanup_sqlite_pruned_payloads(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    delivery_ids: &[String],
) -> StoreResult<()> {
    for delivery_id in delivery_ids {
        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = ? \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
