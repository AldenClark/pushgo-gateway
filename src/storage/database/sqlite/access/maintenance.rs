use super::*;
use crate::storage::{
    SUBSCRIPTION_STATUS_ACTIVE, SUBSCRIPTION_STATUS_FROZEN, SUBSCRIPTION_STATUS_INACTIVE,
};

impl SqliteDb {
    pub(super) async fn upsert_live_activity_token(
        &self,
        record: &LiveActivityTokenRecord,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO live_activity_tokens \
             (activity_key, token, channel_id, platform, schema_version, created_at, updated_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(activity_key, token) DO UPDATE SET \
               channel_id = excluded.channel_id, \
               platform = excluded.platform, \
               schema_version = excluded.schema_version, \
               updated_at = excluded.updated_at, \
               expires_at = excluded.expires_at",
        )
        .bind(record.activity_key.as_str())
        .bind(record.token.as_str())
        .bind(record.channel_id.as_ref().map(|id| id.as_slice()))
        .bind(record.platform.as_str())
        .bind(record.schema_version)
        .bind(record.created_at)
        .bind(record.updated_at)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn delete_live_activity_token(
        &self,
        activity_key: &str,
        token: Option<&str>,
    ) -> StoreResult<usize> {
        let result = if let Some(token) = token {
            sqlx::query("DELETE FROM live_activity_tokens WHERE activity_key = ? AND token = ?")
                .bind(activity_key)
                .bind(token)
                .execute(&self.pool)
                .await?
        } else {
            sqlx::query("DELETE FROM live_activity_tokens WHERE activity_key = ?")
                .bind(activity_key)
                .execute(&self.pool)
                .await?
        };
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn list_live_activity_tokens(
        &self,
        activity_key: &str,
    ) -> StoreResult<Vec<LiveActivityTokenRecord>> {
        let rows = sqlx::query(
            "SELECT activity_key, token, channel_id, platform, schema_version, created_at, updated_at, expires_at \
             FROM live_activity_tokens WHERE activity_key = ? ORDER BY updated_at DESC, token ASC",
        )
        .bind(activity_key)
        .fetch_all(self.core_read_pool())
        .await?;
        rows.into_iter().map(decode_live_activity_token).collect()
    }

    pub(super) async fn upsert_widget_push_subscriptions(
        &self,
        device_key: &str,
        platform: Platform,
        token: &str,
        widgets: &[WidgetPushSubscriptionRecord],
        schema_version: i32,
        now: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "DELETE FROM widget_push_subscriptions \
             WHERE device_key = ? AND platform = ? AND token = ?",
        )
        .bind(device_key)
        .bind(platform.name())
        .bind(token)
        .execute(&self.pool)
        .await?;

        for widget in widgets {
            sqlx::query(
                "INSERT INTO widget_push_subscriptions \
                 (device_key, platform, token, widget_kind, family, schema_version, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(device_key)
            .bind(platform.name())
            .bind(token)
            .bind(widget.widget_kind.as_str())
            .bind(widget.family.as_str())
            .bind(schema_version)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(super) async fn delete_widget_push_token(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<usize> {
        let result =
            sqlx::query("DELETE FROM widget_push_subscriptions WHERE platform = ? AND token = ?")
                .bind(platform.name())
                .bind(token)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn list_widget_push_targets_for_channel(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<WidgetPushSubscriptionRecord>> {
        let rows = sqlx::query(
            "SELECT DISTINCT w.device_key, w.platform, w.token, w.widget_kind, w.family, \
                    w.schema_version, w.created_at, w.updated_at \
             FROM widget_push_subscriptions w \
             JOIN devices d ON d.device_key = w.device_key \
             JOIN channel_subscriptions s ON s.device_id = d.device_id \
             WHERE s.channel_id = ? AND s.status = 'active' \
             ORDER BY w.updated_at DESC, w.token ASC, w.widget_kind ASC, w.family ASC",
        )
        .bind(&channel_id[..])
        .fetch_all(self.core_read_pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(decode_widget_push_subscription)
            .collect())
    }

    pub(super) async fn upsert_sender_submit_status(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO sender_submit_status \
             (op_id, channel_id, model, entity_id, status, dispatch_status, accepted_at, updated_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(op_id) DO UPDATE SET \
               channel_id = excluded.channel_id, \
               model = excluded.model, \
               entity_id = excluded.entity_id, \
               status = excluded.status, \
               dispatch_status = excluded.dispatch_status, \
               accepted_at = excluded.accepted_at, \
               updated_at = excluded.updated_at, \
               expires_at = excluded.expires_at",
        )
        .bind(record.op_id.as_str())
        .bind(record.channel_id.as_slice())
        .bind(record.model.as_str())
        .bind(record.entity_id.as_str())
        .bind(record.status.as_str())
        .bind(record.dispatch_status.as_deref())
        .bind(record.accepted_at)
        .bind(record.updated_at)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE sender_submit_status \
             SET status = ?, dispatch_status = ?, updated_at = ? \
             WHERE op_id = ?",
        )
        .bind(status.as_str())
        .bind(dispatch_status)
        .bind(updated_at)
        .bind(op_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn load_sender_submit_status(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<SenderSubmitStatusRecord>> {
        let Some(row) = sqlx::query(
            "SELECT op_id, channel_id, model, entity_id, status, dispatch_status, accepted_at, updated_at, expires_at \
             FROM sender_submit_status WHERE op_id = ?",
        )
        .bind(op_id)
        .fetch_optional(self.core_read_pool())
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(decode_sender_submit_status(row)?))
    }

    pub(super) async fn cleanup_sender_submit_status(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let result = sqlx::query(
            "DELETE FROM sender_submit_status \
             WHERE op_id IN ( \
               SELECT op_id FROM sender_submit_status \
               WHERE expires_at <= ? \
               ORDER BY expires_at ASC, accepted_at ASC, op_id ASC \
               LIMIT ? \
             )",
        )
        .bind(now)
        .bind(limit as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn cleanup_expired_provider_pull_queue(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut conn = self.delivery_pool().acquire().await?;
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
        let mut conn = self.delivery_pool().acquire().await?;
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
        self.cleanup_subscription_status_with_delivery_gate(
            "SELECT s.rowid, s.device_id FROM channel_subscriptions s \
             JOIN devices d ON d.device_id = s.device_id \
             WHERE s.status = ? AND s.updated_at <= ? \
               AND d.route_updated_at IS NOT NULL AND d.route_updated_at <= ? \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = s.device_id) \
             ORDER BY s.updated_at ASC LIMIT ?",
            &[SUBSCRIPTION_STATUS_ACTIVE, SUBSCRIPTION_STATUS_INACTIVE],
            before_ts,
            now,
            limit,
        )
        .await
    }

    pub(super) async fn cleanup_inactive_subscriptions(
        &self,
        before_ts: i64,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.cleanup_subscription_status_with_delivery_gate(
            "SELECT s.rowid, s.device_id FROM channel_subscriptions s \
             JOIN devices d ON d.device_id = s.device_id \
             WHERE s.status = ? AND s.updated_at <= ? \
               AND d.route_updated_at IS NOT NULL \
               AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = s.device_id) \
             ORDER BY s.updated_at ASC LIMIT ?",
            &[SUBSCRIPTION_STATUS_INACTIVE, SUBSCRIPTION_STATUS_FROZEN],
            before_ts,
            now,
            limit,
        )
        .await
    }

    pub(super) async fn cleanup_soft_deleted_devices(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.cleanup_devices_by_query(
            "SELECT device_id, device_key FROM devices d \
             WHERE NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status <> 'frozen') \
               AND EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status = 'frozen' AND s.updated_at <= ?) \
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
        let result = sqlx::query(
            "DELETE FROM channels \
             WHERE rowid IN ( \
               SELECT c.rowid FROM channels c \
               WHERE c.updated_at <= ? \
                 AND NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.channel_id = c.channel_id) \
               ORDER BY c.updated_at ASC LIMIT ? \
             )",
        )
        .bind(before_ts)
        .bind(limit as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as usize)
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
            if self.delivery_device_has_rows(device_id.as_slice()).await? {
                continue;
            }
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

    async fn cleanup_subscription_status_with_delivery_gate(
        &self,
        select_sql: &str,
        statuses: &[&str; 2],
        before_ts: i64,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let mut query = sqlx::query(select_sql).bind(statuses[0]).bind(before_ts);
        if statuses[0] == SUBSCRIPTION_STATUS_ACTIVE {
            query = query.bind(before_ts);
        }
        let rows = query.bind(limit as i64).fetch_all(&mut *tx).await?;
        let mut updated = 0usize;
        for row in rows {
            let rowid: i64 = row.get("rowid");
            let device_id: Vec<u8> = row.get("device_id");
            if self.delivery_device_has_rows(device_id.as_slice()).await? {
                continue;
            }
            updated = updated.saturating_add(
                sqlx::query(
                    "UPDATE channel_subscriptions SET status = ?, updated_at = ? WHERE rowid = ?",
                )
                .bind(statuses[1])
                .bind(now)
                .bind(rowid)
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize,
            );
        }
        tx.commit().await?;
        Ok(updated)
    }

    async fn delivery_device_has_rows(&self, device_id: &[u8]) -> StoreResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT \
               (SELECT COUNT(1) FROM private_outbox WHERE device_id = ?) + \
               (SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ?)",
        )
        .bind(device_id)
        .bind(device_id)
        .fetch_one(self.delivery_pool())
        .await?;
        Ok(count > 0)
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
                    DedupeState::PartialFailure => OpDedupeReservation::PartialFailure {
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
        state: DedupeState,
    ) -> StoreResult<bool> {
        let now = Utc::now().timestamp_millis();
        let result = sqlx::query(
            "UPDATE dispatch_op_dedupe \
             SET state = ?, sent_at = ?, updated_at = ? \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(state.as_str())
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
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for table in ["provider_pull_queue", "private_outbox", "private_payloads"] {
            sqlx::query(&format!("DELETE FROM {}", table))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
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

fn decode_live_activity_token(
    row: sqlx::sqlite::SqliteRow,
) -> StoreResult<LiveActivityTokenRecord> {
    let channel_bytes: Option<Vec<u8>> = row.get("channel_id");
    let channel_id = channel_bytes
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| invalid_sender_status_data("invalid live activity channel_id length"))
        })
        .transpose()?;
    Ok(LiveActivityTokenRecord {
        activity_key: row.get("activity_key"),
        token: row.get("token"),
        channel_id,
        platform: row.get("platform"),
        schema_version: row.get("schema_version"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
    })
}

fn decode_widget_push_subscription(row: sqlx::sqlite::SqliteRow) -> WidgetPushSubscriptionRecord {
    WidgetPushSubscriptionRecord {
        device_key: row.get("device_key"),
        platform: row.get("platform"),
        token: row.get("token"),
        widget_kind: row.get("widget_kind"),
        family: row.get("family"),
        schema_version: row.get("schema_version"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn decode_sender_submit_status(
    row: sqlx::sqlite::SqliteRow,
) -> StoreResult<SenderSubmitStatusRecord> {
    let channel_bytes: Vec<u8> = row.get("channel_id");
    let channel_id: [u8; 16] = channel_bytes
        .try_into()
        .map_err(|_| invalid_sender_status_data("invalid sender status channel_id length"))?;
    let status_text: String = row.get("status");
    let status = SenderSubmitStatusKind::parse(status_text.as_str())
        .ok_or_else(|| invalid_sender_status_data("invalid sender status kind"))?;
    Ok(SenderSubmitStatusRecord {
        op_id: row.get("op_id"),
        channel_id,
        model: row.get("model"),
        entity_id: row.get("entity_id"),
        status,
        dispatch_status: row.get("dispatch_status"),
        accepted_at: row.get("accepted_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
    })
}

fn invalid_sender_status_data(message: &'static str) -> StoreError {
    StoreError::Serde(serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
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

pub(super) async fn delete_orphan_private_payload_in_sqlite_tx(
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
