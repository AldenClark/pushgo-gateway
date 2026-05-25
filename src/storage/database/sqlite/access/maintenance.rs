use super::*;
use std::collections::HashSet;

impl SqliteDb {
    pub(super) async fn cleanup_expired_provider_pull_queue(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let selected = select_delivery_keys(
            &mut tx,
            "SELECT device_id, delivery_id FROM provider_pull_queue \
             WHERE expires_at <= ? \
             ORDER BY expires_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
            before_ts,
            limit,
        )
        .await?;
        let mut deleted = 0usize;
        for (device_id, delivery_id) in &selected {
            deleted = deleted.saturating_add(
                sqlx::query(
                    "DELETE FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
                )
                .bind(device_id.as_slice())
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize,
            );
            delete_orphan_private_payload_in_sqlite_tx(&mut tx, delivery_id).await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub(super) async fn cleanup_stale_private_outbox(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let selected = select_delivery_keys(
            &mut tx,
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE updated_at <= ? \
             ORDER BY updated_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ?",
            before_ts,
            limit,
        )
        .await?;
        let mut deleted = 0usize;
        for (device_id, delivery_id) in &selected {
            deleted = deleted.saturating_add(
                sqlx::query(
                    "DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ? AND updated_at <= ?",
                )
                    .bind(device_id.as_slice())
                    .bind(delivery_id)
                    .bind(before_ts)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize,
            );
            delete_orphan_private_payload_in_sqlite_tx(&mut tx, delivery_id).await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub(super) async fn cleanup_orphan_devices(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.cleanup_devices_by_query(
            "SELECT device_id, device_key FROM devices d \
             WHERE d.route_updated_at IS NOT NULL AND d.route_updated_at <= ? \
               AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id) \
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = d.device_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = d.device_id) \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = d.device_id) \
             ORDER BY d.route_updated_at ASC, d.device_key ASC LIMIT ?",
            before_ts,
            limit,
        )
        .await
    }

    pub(super) async fn cleanup_stale_subscriptions(
        &self,
        before_ts: i64,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let result = sqlx::query(
            "UPDATE channel_subscriptions \
             SET status = 'inactive', updated_at = ? \
             WHERE rowid IN ( \
               SELECT s.rowid FROM channel_subscriptions s \
               JOIN devices d ON d.device_id = s.device_id \
               WHERE s.status = 'active' AND s.updated_at <= ? \
                 AND d.route_updated_at IS NOT NULL AND d.route_updated_at <= ? \
                 AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = s.device_id) \
                 AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = s.device_id) \
                 AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = s.device_id) \
               ORDER BY s.updated_at ASC LIMIT ? \
             )",
        )
        .bind(now)
        .bind(before_ts)
        .bind(before_ts)
        .bind(limit as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn cleanup_soft_deleted_devices(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.cleanup_devices_by_query(
            "SELECT device_id, device_key FROM devices d \
             WHERE NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status = 'active') \
               AND EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status <> 'active' AND s.updated_at <= ?) \
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = d.device_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = d.device_id) \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = d.device_id) \
             ORDER BY d.route_updated_at ASC, d.device_key ASC LIMIT ?",
            before_ts,
            limit,
        )
        .await
    }

    pub(super) async fn cleanup_orphan_channels(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        if self.telemetry_pool.is_some() {
            return self
                .cleanup_orphan_channels_with_telemetry(before_ts, limit)
                .await;
        }
        let result = sqlx::query(
            "DELETE FROM channels \
             WHERE rowid IN ( \
               SELECT c.rowid FROM channels c \
               WHERE c.updated_at <= ? \
                 AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.channel_id = c.channel_id) \
                 AND NOT EXISTS (SELECT 1 FROM channel_stats_daily st WHERE st.channel_id = c.channel_id AND st.messages_routed > 0) \
               ORDER BY c.updated_at ASC LIMIT ? \
             )",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn cleanup_audit_rows(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let route_rows = delete_limited_sqlite(
            &self.pool,
            "device_route_audit",
            "created_at <= ?",
            "created_at ASC",
            before_ts,
            limit,
        )
        .await?;
        let subscription_rows = delete_limited_sqlite(
            &self.pool,
            "subscription_audit",
            "created_at <= ?",
            "created_at ASC",
            before_ts,
            limit,
        )
        .await?;
        Ok(route_rows.saturating_add(subscription_rows))
    }

    pub(super) async fn cleanup_hourly_stats(
        &self,
        before_bucket: &str,
        limit: usize,
    ) -> StoreResult<usize> {
        let gateway_rows = delete_limited_by_bucket_sqlite(
            self.telemetry_pool(),
            "gateway_stats_hourly",
            "bucket_hour",
            before_bucket,
            limit,
        )
        .await?;
        let ops_rows = delete_limited_by_bucket_sqlite(
            self.telemetry_pool(),
            "ops_stats_hourly",
            "bucket_hour",
            before_bucket,
            limit,
        )
        .await?;
        Ok(gateway_rows.saturating_add(ops_rows))
    }

    pub(super) async fn cleanup_daily_stats(
        &self,
        before_bucket: &str,
        limit: usize,
    ) -> StoreResult<usize> {
        let channel_rows = delete_limited_by_bucket_sqlite(
            self.telemetry_pool(),
            "channel_stats_daily",
            "bucket_date",
            before_bucket,
            limit,
        )
        .await?;
        let device_rows = delete_limited_by_bucket_sqlite(
            self.telemetry_pool(),
            "device_stats_daily",
            "bucket_date",
            before_bucket,
            limit,
        )
        .await?;
        Ok(channel_rows.saturating_add(device_rows))
    }

    async fn cleanup_devices_by_query(
        &self,
        select_sql: &str,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(select_sql)
            .bind(before_ts)
            .bind(limit as i64)
            .fetch_all(&mut *tx)
            .await?;
        let mut deleted = 0usize;
        for row in rows {
            let device_id: Vec<u8> = row.get("device_id");
            let device_key: Option<String> = row.try_get("device_key").ok();
            let delivery_ids = sqlx::query(
                "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
                 UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
            )
            .bind(device_id.as_slice())
            .bind(device_id.as_slice())
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect::<Vec<String>>();
            for statement in [
                "DELETE FROM channel_subscriptions WHERE device_id = ?",
                "DELETE FROM provider_pull_queue WHERE device_id = ?",
                "DELETE FROM private_bindings WHERE device_id = ?",
                "DELETE FROM private_outbox WHERE device_id = ?",
                "DELETE FROM private_sessions WHERE device_id = ?",
                "DELETE FROM private_device_keys WHERE device_id = ?",
            ] {
                sqlx::query(statement)
                    .bind(device_id.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
            if let Some(device_key) = device_key.as_deref() {
                sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
                    .bind(device_key)
                    .execute(&mut *tx)
                    .await?;
            }
            deleted = deleted.saturating_add(
                sqlx::query("DELETE FROM devices WHERE device_id = ?")
                    .bind(device_id.as_slice())
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize,
            );
            for delivery_id in &delivery_ids {
                delete_orphan_private_payload_in_sqlite_tx(&mut tx, delivery_id).await?;
            }
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub(super) async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "INSERT INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Sent.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(self.dispatch_pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        let result = sqlx::query(
            "INSERT INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?) ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(semantic_id)
        .bind(created_at)
        .bind(created_at)
        .execute(self.dispatch_pool())
        .await?;

        if result.rows_affected() > 0 {
            Ok(SemanticIdReservation::Reserved)
        } else {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?",
            )
            .bind(dedupe_key)
            .fetch_optional(self.dispatch_pool())
            .await?;
            Ok(match existing {
                Some(s) => SemanticIdReservation::Existing { semantic_id: s },
                None => SemanticIdReservation::Collision,
            })
        }
    }

    pub(super) async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        let mut conn = self.dispatch_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let inserted = sqlx::query(
            "INSERT INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        let outcome = if inserted {
            OpDedupeReservation::Reserved
        } else {
            let existing = sqlx::query(
                "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = ?",
            )
            .bind(dedupe_key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                let existing_delivery_id: String = row.try_get("delivery_id")?;
                let state: String = row.try_get("state")?;
                match DedupeState::from_str(state.as_str())? {
                    DedupeState::Pending => OpDedupeReservation::Pending {
                        delivery_id: existing_delivery_id,
                    },
                    DedupeState::Sent => OpDedupeReservation::Sent {
                        delivery_id: existing_delivery_id,
                    },
                }
            } else {
                OpDedupeReservation::Pending {
                    delivery_id: delivery_id.to_string(),
                }
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    pub(super) async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        let now = Utc::now().timestamp_millis();
        let result = sqlx::query(
            "UPDATE dispatch_op_dedupe \
             SET state = ?, sent_at = ?, updated_at = ? \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(DedupeState::Sent.as_str())
        .bind(now)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(self.dispatch_pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(self.dispatch_pool())
        .await?;
        Ok(())
    }

    pub(super) async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query("UPDATE dispatch_delivery_dedupe SET state = ?, updated_at = ? WHERE dedupe_key = ? AND delivery_id = ?")
            .bind(DedupeState::Sent.as_str())
            .bind(Utc::now().timestamp_millis())
            .bind(dedupe_key)
            .bind(delivery_id)
            .execute(self.dispatch_pool())
            .await?;
        Ok(())
    }

    pub(super) async fn automation_reset(&self) -> StoreResult<()> {
        let tables = vec![
            "subscription_audit",
            "device_route_audit",
            "channel_stats_daily",
            "device_stats_daily",
            "gateway_stats_hourly",
            "ops_stats_hourly",
            "dispatch_op_dedupe",
            "dispatch_delivery_dedupe",
            "semantic_id_registry",
            "channel_subscriptions",
            "devices",
            "channels",
            "private_bindings",
            "private_outbox",
            "private_payloads",
            "private_sessions",
            "private_device_keys",
            "mcp_state",
        ];
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for table in tables {
            sqlx::query(&format!("DELETE FROM {}", table))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        if let Some(pool) = &self.telemetry_pool {
            let mut conn = pool.acquire().await?;
            let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
            for table in [
                "channel_stats_daily",
                "device_stats_daily",
                "gateway_stats_hourly",
                "ops_stats_hourly",
            ] {
                sqlx::query(&format!("DELETE FROM {}", table))
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
        if let Some(pool) = &self.runtime_pool {
            sqlx::query("DELETE FROM mcp_state").execute(pool).await?;
        }
        let mut conn = self.dispatch_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for table in [
            "dispatch_op_dedupe",
            "dispatch_delivery_dedupe",
            "semantic_id_registry",
        ] {
            sqlx::query(&format!("DELETE FROM {}", table))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
            .fetch_one(self.core_read_pool())
            .await?;
        let subscription_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                .fetch_one(self.core_read_pool())
                .await?;
        let delivery_dedupe_pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_delivery_dedupe")
                .fetch_one(self.dispatch_pool())
                .await?;

        Ok(AutomationCounts {
            channel_count: channel_count as usize,
            subscription_count: subscription_count as usize,
            delivery_dedupe_pending_count: delivery_dedupe_pending_count as usize,
        })
    }

    pub(super) async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state_json FROM mcp_state WHERE state_key = 'default'",
        )
        .fetch_optional(self.runtime_pool())
        .await?;
        Ok(state)
    }

    pub(super) async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO mcp_state (state_key, state_json, updated_at) VALUES ('default', ?, ?) \
             ON CONFLICT(state_key) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at",
        )
        .bind(state_json)
        .bind(now)
        .execute(self.runtime_pool())
        .await?;
        Ok(())
    }
}

impl SqliteDb {
    async fn cleanup_orphan_channels_with_telemetry(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let candidate_rows = sqlx::query(
            "SELECT c.rowid, c.channel_id \
             FROM channels c \
             WHERE c.updated_at <= ? \
               AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.channel_id = c.channel_id) \
             ORDER BY c.updated_at ASC \
             LIMIT ?",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(self.core_read_pool())
        .await?;
        if candidate_rows.is_empty() {
            return Ok(0);
        }
        let candidate_channels = candidate_rows
            .iter()
            .map(|row| row.get::<Vec<u8>, _>("channel_id"))
            .collect::<Vec<_>>();
        let channels_with_traffic =
            load_telemetry_channels_with_traffic(self.telemetry_pool(), &candidate_channels)
                .await?;

        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let mut removed = 0usize;
        for row in candidate_rows {
            let rowid: i64 = row.get("rowid");
            let channel_id: Vec<u8> = row.get("channel_id");
            if channels_with_traffic.contains(&channel_id) {
                continue;
            }
            removed = removed.saturating_add(
                sqlx::query(
                    "DELETE FROM channels \
                     WHERE rowid = ? \
                       AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.channel_id = channels.channel_id)",
                )
                .bind(rowid)
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize,
            );
        }
        tx.commit().await?;
        Ok(removed)
    }
}

async fn select_delivery_keys(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    sql: &str,
    before_ts: i64,
    limit: usize,
) -> StoreResult<Vec<(Vec<u8>, String)>> {
    let rows = sqlx::query(sql)
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut **tx)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get("device_id"), row.get("delivery_id")))
        .collect())
}

async fn delete_orphan_private_payload_in_sqlite_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    delivery_id: &str,
) -> StoreResult<()> {
    sqlx::query(
        "DELETE FROM private_payloads \
         WHERE delivery_id = ? \
           AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
           AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
    )
    .bind(delivery_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn delete_limited_sqlite(
    pool: &sqlx::SqlitePool,
    table: &str,
    predicate: &str,
    order_by: &str,
    before_ts: i64,
    limit: usize,
) -> StoreResult<usize> {
    let sql = format!(
        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {predicate} ORDER BY {order_by} LIMIT ?)"
    );
    let result = sqlx::query(sql.as_str())
        .bind(before_ts)
        .bind(limit as i64)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

async fn load_telemetry_channels_with_traffic(
    pool: &sqlx::SqlitePool,
    channel_ids: &[Vec<u8>],
) -> StoreResult<HashSet<Vec<u8>>> {
    if channel_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT DISTINCT channel_id FROM channel_stats_daily \
         WHERE messages_routed > 0 AND channel_id IN (",
    );
    let mut separated = query.separated(", ");
    for channel_id in channel_ids {
        separated.push_bind(channel_id);
    }
    separated.push_unseparated(")");
    let rows = query.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| row.get::<Vec<u8>, _>("channel_id"))
        .collect())
}

async fn delete_limited_by_bucket_sqlite(
    pool: &sqlx::SqlitePool,
    table: &str,
    column: &str,
    before_bucket: &str,
    limit: usize,
) -> StoreResult<usize> {
    let sql = format!(
        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column} < ? ORDER BY {column} ASC LIMIT ?)"
    );
    let result = sqlx::query(sql.as_str())
        .bind(before_bucket)
        .bind(limit as i64)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}
