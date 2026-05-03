use super::*;

impl MySqlDb {
    pub(super) async fn cleanup_expired_provider_pull_queue(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM provider_pull_queue \
             WHERE expires_at <= ? \
             ORDER BY expires_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ? FOR UPDATE",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let selected = rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<Vec<u8>, _>("device_id"),
                    row.get::<String, _>("delivery_id"),
                )
            })
            .collect::<Vec<(Vec<u8>, String)>>();
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
            delete_orphan_private_payload_in_mysql_tx(&mut tx, delivery_id).await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub(super) async fn cleanup_stale_private_outbox(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE updated_at <= ? \
             ORDER BY updated_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ? FOR UPDATE",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let selected = rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<Vec<u8>, _>("device_id"),
                    row.get::<String, _>("delivery_id"),
                )
            })
            .collect::<Vec<(Vec<u8>, String)>>();
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
            delete_orphan_private_payload_in_mysql_tx(&mut tx, delivery_id).await?;
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
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(d.device_id, 1, 16)) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = SUBSTRING(d.device_id, 1, 16)) \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = SUBSTRING(d.device_id, 1, 16)) \
             ORDER BY d.route_updated_at ASC, d.device_key ASC LIMIT ? FOR UPDATE",
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
            "UPDATE channel_subscriptions s \
             JOIN ( \
               SELECT channel_id, device_id FROM ( \
                 SELECT s.channel_id, s.device_id FROM channel_subscriptions s \
                 JOIN devices d ON d.device_id = s.device_id \
                 WHERE s.status = ? AND s.updated_at <= ? \
                   AND d.route_updated_at IS NOT NULL AND d.route_updated_at <= ? \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(s.device_id, 1, 16)) \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = SUBSTRING(s.device_id, 1, 16)) \
                   AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = SUBSTRING(s.device_id, 1, 16)) \
                 ORDER BY s.updated_at ASC LIMIT ? \
               ) selected_subscriptions \
             ) victim ON victim.channel_id = s.channel_id AND victim.device_id = s.device_id \
             SET s.status = ?, s.updated_at = ?",
        )
        .bind("active")
        .bind(before_ts)
        .bind(before_ts)
        .bind(limit as i64)
        .bind("inactive")
        .bind(now)
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
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(d.device_id, 1, 16)) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = SUBSTRING(d.device_id, 1, 16)) \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = SUBSTRING(d.device_id, 1, 16)) \
             ORDER BY d.route_updated_at ASC, d.device_key ASC LIMIT ? FOR UPDATE",
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
        let result = sqlx::query(
            "DELETE c FROM channels c \
             JOIN ( \
               SELECT channel_id FROM ( \
                 SELECT c.channel_id FROM channels c \
                 WHERE c.updated_at <= ? \
                   AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.channel_id = c.channel_id) \
                   AND NOT EXISTS (SELECT 1 FROM channel_stats_daily st WHERE st.channel_id = c.channel_id AND st.messages_routed > 0) \
                 ORDER BY c.updated_at ASC LIMIT ? \
               ) selected_channels \
             ) victim ON victim.channel_id = c.channel_id",
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
        let route_rows = delete_limited_mysql(
            &self.pool,
            "device_route_audit",
            "created_at",
            before_ts,
            limit,
        )
        .await?;
        let subscription_rows = delete_limited_mysql(
            &self.pool,
            "subscription_audit",
            "created_at",
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
        let gateway_rows = delete_limited_bucket_mysql(
            &self.pool,
            "gateway_stats_hourly",
            "bucket_hour",
            before_bucket,
            limit,
        )
        .await?;
        let ops_rows = delete_limited_bucket_mysql(
            &self.pool,
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
        let channel_rows = delete_limited_bucket_mysql(
            &self.pool,
            "channel_stats_daily",
            "bucket_date",
            before_bucket,
            limit,
        )
        .await?;
        let device_rows = delete_limited_bucket_mysql(
            &self.pool,
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
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(select_sql)
            .bind(before_ts)
            .bind(limit as i64)
            .fetch_all(&mut *tx)
            .await?;
        let mut deleted = 0usize;
        for row in rows {
            let route_device_id: Vec<u8> = row.get("device_id");
            let private_device_id = PrivateDeviceId::parse_compat(route_device_id.as_slice())
                .ok_or(StoreError::InvalidDeviceToken)?
                .to_vec();
            let device_key: Option<String> = row.try_get("device_key").ok();
            let delivery_ids = sqlx::query(
                "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
                 UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
            )
            .bind(private_device_id.as_slice())
            .bind(private_device_id.as_slice())
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect::<Vec<String>>();
            sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                .bind(route_device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            for statement in [
                "DELETE FROM provider_pull_queue WHERE device_id = ?",
                "DELETE FROM private_bindings WHERE device_id = ?",
                "DELETE FROM private_outbox WHERE device_id = ?",
                "DELETE FROM private_sessions WHERE device_id = ?",
                "DELETE FROM private_device_keys WHERE device_id = ?",
            ] {
                sqlx::query(statement)
                    .bind(private_device_id.as_slice())
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
                    .bind(route_device_id.as_slice())
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize,
            );
            for delivery_id in &delivery_ids {
                delete_orphan_private_payload_in_mysql_tx(&mut tx, delivery_id).await?;
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
            "INSERT IGNORE INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Sent.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(&self.pool)
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
            "INSERT IGNORE INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(semantic_id)
        .bind(created_at)
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            Ok(SemanticIdReservation::Reserved)
        } else {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?",
            )
            .bind(dedupe_key)
            .fetch_optional(&self.pool)
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
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
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
                "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = ? FOR UPDATE",
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
        .execute(&self.pool)
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
        .execute(&self.pool)
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
            .execute(&self.pool)
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
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&mut *tx)
            .await?;
        for table in tables {
            sqlx::query(&format!("TRUNCATE TABLE {}", table))
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
            .fetch_one(&self.pool)
            .await?;
        let subscription_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                .fetch_one(&self.pool)
                .await?;
        let delivery_dedupe_pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_delivery_dedupe")
                .fetch_one(&self.pool)
                .await?;

        Ok(AutomationCounts {
            channel_count: channel_count as usize,
            subscription_count: subscription_count as usize,
            delivery_dedupe_pending_count: delivery_dedupe_pending_count as usize,
        })
    }

    pub(super) async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        let state =
            sqlx::query_scalar::<_, String>("SELECT state_json FROM mcp_state WHERE state_key = ?")
                .bind("default")
                .fetch_optional(&self.pool)
                .await?;
        Ok(state)
    }

    pub(super) async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO mcp_state (state_key, state_json, updated_at) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE state_json = VALUES(state_json), updated_at = VALUES(updated_at)",
        )
        .bind("default")
        .bind(state_json)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn delete_orphan_private_payload_in_mysql_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
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

async fn delete_limited_mysql(
    pool: &sqlx::MySqlPool,
    table: &str,
    column: &str,
    before_ts: i64,
    limit: usize,
) -> StoreResult<usize> {
    let sql = format!("DELETE FROM {table} WHERE {column} <= ? ORDER BY {column} ASC LIMIT ?");
    let result = sqlx::query(sql.as_str())
        .bind(before_ts)
        .bind(limit as i64)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

async fn delete_limited_bucket_mysql(
    pool: &sqlx::MySqlPool,
    table: &str,
    column: &str,
    before_bucket: &str,
    limit: usize,
) -> StoreResult<usize> {
    let sql = format!("DELETE FROM {table} WHERE {column} < ? ORDER BY {column} ASC LIMIT ?");
    let result = sqlx::query(sql.as_str())
        .bind(before_bucket)
        .bind(limit as i64)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}
