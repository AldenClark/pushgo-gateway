use super::*;
use crate::storage::{
    SUBSCRIPTION_STATUS_ACTIVE, SUBSCRIPTION_STATUS_FROZEN, SUBSCRIPTION_STATUS_INACTIVE,
};

impl MySqlDb {
    pub(super) async fn upsert_live_activity_token(
        &self,
        record: &LiveActivityTokenRecord,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO live_activity_tokens \
             (activity_key, token, channel_id, platform, schema_version, created_at, updated_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
               channel_id = VALUES(channel_id), \
               platform = VALUES(platform), \
               schema_version = VALUES(schema_version), \
               updated_at = VALUES(updated_at), \
               expires_at = VALUES(expires_at)",
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
        .fetch_all(&self.pool)
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
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM widget_push_subscriptions \
             WHERE device_key = ? AND platform = ? AND token = ?",
        )
        .bind(device_key)
        .bind(platform.name())
        .bind(token)
        .execute(&mut *tx)
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
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
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
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(decode_widget_push_subscription)
            .collect()
    }

    pub(super) async fn insert_sender_submit_status_if_absent(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "INSERT INTO sender_submit_status \
             (op_id, channel_id, model, entity_id, status, dispatch_status, accepted_at, updated_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .await;
        match result {
            Ok(_) => Ok(true),
            Err(sqlx::Error::Database(error))
                if error
                    .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                    .is_some_and(|error| error.number() == 1062) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
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
             WHERE op_id = ? \
               AND updated_at <= ? \
               AND CASE ? \
                 WHEN 'accepted' THEN status IN ('accepted', 'failed') \
                 WHEN 'processing' THEN status IN ('accepted', 'processing') \
                 WHEN 'provider_queued' THEN status IN ('processing', 'provider_queued') \
                 WHEN 'sent' THEN status IN ('processing', 'provider_queued', 'sent') \
                 WHEN 'partially_failed' THEN status IN ('processing', 'provider_queued', 'partially_failed') \
                 WHEN 'failed' THEN status IN ('accepted', 'processing', 'failed') \
                 ELSE FALSE \
               END",
        )
        .bind(status.as_str())
        .bind(dispatch_status)
        .bind(updated_at)
        .bind(op_id)
        .bind(updated_at)
        .bind(status.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn finalize_provider_dispatch_outcome(
        &self,
        dedupe_key: &str,
        op_id: &str,
        delivery_id: &str,
        success: bool,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        let sender_status = if success { "sent" } else { "partially_failed" };
        let dispatch_status = if success {
            "provider_success"
        } else {
            "provider_failed"
        };
        let dedupe_state = if success {
            DedupeState::Sent
        } else {
            DedupeState::PartialFailure
        };
        let mut tx = self.pool.begin().await?;
        let dedupe_update = sqlx::query(
            "UPDATE dispatch_op_dedupe SET state = ?, sent_at = ?, updated_at = ? \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = 'provider_queued'",
        )
        .bind(dedupe_state.as_str())
        .bind(now)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?;
        if dedupe_update.rows_affected() != 1 {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query(
            "UPDATE sender_submit_status SET status = ?, dispatch_status = ?, updated_at = ? \
             WHERE op_id = ? AND status IN ('processing', 'provider_queued') AND updated_at <= ?",
        )
        .bind(sender_status)
        .bind(dispatch_status)
        .bind(now)
        .bind(op_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn recover_interrupted_provider_dispatches(
        &self,
        updated_at: i64,
    ) -> StoreResult<usize> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT d.dedupe_key, d.delivery_id FROM dispatch_op_dedupe d \
             WHERE d.state = 'provider_queued' AND ( \
                COALESCE(d.provider_lease_until, 0) <= ? OR ( \
                    EXISTS ( \
                        SELECT 1 FROM provider_dispatch_outbox terminal \
                        WHERE terminal.delivery_id = d.delivery_id \
                          AND terminal.provider IN ('APNS','FCM','WNS') \
                          AND terminal.state IN ('provider_accepted','permanent_failed','superseded_route','expired','cancelled') \
                    ) AND NOT EXISTS ( \
                        SELECT 1 FROM provider_dispatch_outbox open_job \
                        WHERE open_job.delivery_id = d.delivery_id \
                          AND open_job.provider IN ('APNS','FCM','WNS') \
                          AND open_job.state IN ('preparing','pending','retry_wait','leased') \
                    ) \
                ) \
             ) ORDER BY d.updated_at, d.dedupe_key LIMIT 1024 FOR UPDATE",
        )
        .bind(updated_at)
        .fetch_all(&mut *tx)
        .await?;
        for row in &rows {
            let dedupe_key = decode_mysql_text(row, "dedupe_key")?;
            let delivery_id = decode_mysql_text(row, "delivery_id")?;
            let summary = sqlx::query(
                "SELECT COUNT(1) AS total, \
                        CAST(COALESCE(SUM(CASE WHEN state IN ('preparing','pending','retry_wait','leased') THEN 1 ELSE 0 END), 0) AS SIGNED) AS open_count, \
                        CAST(COALESCE(SUM(CASE WHEN state IN ('permanent_failed','expired','cancelled') THEN 1 ELSE 0 END), 0) AS SIGNED) AS failed_count, \
                        CAST(COALESCE(SUM(CASE WHEN dedupe_key = ? AND op_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS SIGNED) AS matched_count, \
                        MIN(CASE WHEN dedupe_key = ? THEN op_id END) AS min_op_id, \
                        MAX(CASE WHEN dedupe_key = ? THEN op_id END) AS max_op_id \
                 FROM provider_dispatch_outbox \
                 WHERE delivery_id = ? AND provider IN ('APNS','FCM','WNS')",
            )
            .bind(&dedupe_key)
            .bind(&dedupe_key)
            .bind(&dedupe_key)
            .bind(&delivery_id)
            .fetch_one(&mut *tx)
            .await?;
            let total: i64 = summary.try_get("total")?;
            let open: i64 = summary.try_get("open_count")?;
            let failed: i64 = summary.try_get("failed_count")?;
            let matched: i64 = summary.try_get("matched_count")?;
            let min_op_id = decode_mysql_optional_text(&summary, "min_op_id")?;
            let max_op_id = decode_mysql_optional_text(&summary, "max_op_id")?;

            if total > 0 && open > 0 {
                sqlx::query(
                    "UPDATE dispatch_op_dedupe SET provider_owner = NULL, provider_lease_until = ? + 900000, updated_at = ? \
                     WHERE dedupe_key = ? AND state = 'provider_queued' AND COALESCE(provider_lease_until, 0) <= ?",
                )
                .bind(updated_at)
                .bind(updated_at)
                .bind(&dedupe_key)
                .bind(updated_at)
                .execute(&mut *tx)
                .await?;
                continue;
            }

            let exact_op_id =
                (total > 0 && matched == total && min_op_id.is_some() && min_op_id == max_op_id)
                    .then_some(min_op_id)
                    .flatten();
            let (dedupe_state, sender_status, dispatch_status) = if exact_op_id.is_some() {
                if failed == 0 {
                    ("sent", "sent", "provider_success")
                } else {
                    ("partial_failure", "partially_failed", "provider_failed")
                }
            } else {
                ("partial_failure", "failed", "provider_outcome_unknown")
            };
            sqlx::query(
                "UPDATE dispatch_op_dedupe \
                 SET state = ?, sent_at = ?, updated_at = ?, provider_owner = NULL, provider_lease_until = NULL \
                 WHERE dedupe_key = ? AND state = 'provider_queued'",
            )
            .bind(dedupe_state)
            .bind(updated_at)
            .bind(updated_at)
            .bind(&dedupe_key)
            .execute(&mut *tx)
            .await?;
            let sender_op_id = exact_op_id.as_deref().unwrap_or(&dedupe_key);
            sqlx::query(
                "UPDATE sender_submit_status \
                 SET status = ?, dispatch_status = ?, updated_at = ? \
                 WHERE op_id = ? AND status = 'provider_queued' AND updated_at <= ?",
            )
            .bind(sender_status)
            .bind(dispatch_status)
            .bind(updated_at)
            .bind(sender_op_id)
            .bind(updated_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(rows.len())
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
        .fetch_optional(&self.pool)
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
               SELECT op_id FROM ( \
                 SELECT op_id FROM sender_submit_status \
                 WHERE expires_at <= ? \
                 ORDER BY expires_at ASC, accepted_at ASC, op_id ASC \
                 LIMIT ? \
               ) selected_sender_status \
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
                Ok((
                    row.get::<Vec<u8>, _>("device_id"),
                    decode_mysql_text(&row, "delivery_id")?,
                ))
            })
            .collect::<StoreResult<Vec<(Vec<u8>, String)>>>()?;
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
        acked_before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE (status = 'acked' AND updated_at <= ?) \
                OR (status <> 'acked' AND updated_at <= ?) \
             ORDER BY updated_at ASC, created_at ASC, delivery_id ASC \
             LIMIT ? FOR UPDATE",
        )
        .bind(acked_before_ts)
        .bind(before_ts)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let selected = rows
            .into_iter()
            .map(|row| {
                Ok((
                    row.get::<Vec<u8>, _>("device_id"),
                    decode_mysql_text(&row, "delivery_id")?,
                ))
            })
            .collect::<StoreResult<Vec<(Vec<u8>, String)>>>()?;
        let mut deleted = 0usize;
        for (device_id, delivery_id) in &selected {
            deleted = deleted.saturating_add(
                sqlx::query(
                    "DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ? \
                     AND ((status = 'acked' AND updated_at <= ?) OR (status <> 'acked' AND updated_at <= ?))",
                )
                    .bind(device_id.as_slice())
                    .bind(delivery_id)
                    .bind(acked_before_ts)
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
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(d.device_id, 1, 16) AND o.status <> 'acked') \
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
                   AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(s.device_id, 1, 16) AND o.status <> 'acked') \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = SUBSTRING(s.device_id, 1, 16)) \
                   AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = SUBSTRING(s.device_id, 1, 16)) \
                 ORDER BY s.updated_at ASC LIMIT ? \
               ) selected_subscriptions \
             ) victim ON victim.channel_id = s.channel_id AND victim.device_id = s.device_id \
             SET s.status = ?, s.updated_at = ?",
        )
        .bind(SUBSCRIPTION_STATUS_ACTIVE)
        .bind(before_ts)
        .bind(before_ts)
        .bind(limit as i64)
        .bind(SUBSCRIPTION_STATUS_INACTIVE)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as usize)
    }

    pub(super) async fn cleanup_inactive_subscriptions(
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
                   AND d.route_updated_at IS NOT NULL \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(s.device_id, 1, 16) AND o.status <> 'acked') \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.device_id = SUBSTRING(s.device_id, 1, 16)) \
                   AND NOT EXISTS (SELECT 1 FROM private_sessions ps WHERE ps.device_id = SUBSTRING(s.device_id, 1, 16)) \
                 ORDER BY s.updated_at ASC LIMIT ? \
               ) selected_subscriptions \
             ) victim ON victim.channel_id = s.channel_id AND victim.device_id = s.device_id \
             SET s.status = ?, s.updated_at = ?",
        )
        .bind(SUBSCRIPTION_STATUS_INACTIVE)
        .bind(before_ts)
        .bind(limit as i64)
        .bind(SUBSCRIPTION_STATUS_FROZEN)
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
             WHERE NOT EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status <> 'frozen') \
               AND EXISTS (SELECT 1 FROM channel_subscriptions s WHERE s.device_id = d.device_id AND s.status = 'frozen' AND s.updated_at <= ?) \
               AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.device_id = SUBSTRING(d.device_id, 1, 16) AND o.status <> 'acked') \
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
            let delivery_ids = sqlx::query(
                "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
                 UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
            )
            .bind(private_device_id.as_slice())
            .bind(private_device_id.as_slice())
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| decode_mysql_text(&row, "delivery_id"))
            .collect::<StoreResult<Vec<_>>>()?;
            sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                .bind(route_device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            for statement in [
                "DELETE FROM provider_pull_queue WHERE device_id = ?",
                "DELETE FROM private_bindings WHERE device_id = ?",
                "DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'",
                "DELETE FROM private_sessions WHERE device_id = ?",
                "DELETE FROM private_device_keys WHERE device_id = ?",
            ] {
                sqlx::query(statement)
                    .bind(private_device_id.as_slice())
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
            let existing =
                sqlx::query("SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?")
                    .bind(dedupe_key)
                    .fetch_optional(&self.pool)
                    .await?;
            Ok(match existing {
                Some(row) => SemanticIdReservation::Existing {
                    semantic_id: decode_mysql_text(&row, "semantic_id")?,
                },
                None => SemanticIdReservation::Collision,
            })
        }
    }

    pub(super) async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        request_fingerprint: Option<&str>,
        created_at: i64,
        submission: Option<&DispatchSubmissionRecord>,
        submission_hard_capacity: usize,
    ) -> StoreResult<OpDedupeReservation> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO dispatch_op_dedupe (dedupe_key, delivery_id, request_fingerprint, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(request_fingerprint)
        .bind(DedupeState::Pending.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        let outcome = if inserted {
            let mut acceptance_order = 0;
            if let Some(submission) = submission {
                if submission.dedupe_key != dedupe_key
                    || submission.delivery_id != delivery_id
                    || submission.accepted_at != created_at
                {
                    return Err(StoreError::Upgrade(
                        "dispatch submission identity does not match dedupe reservation".into(),
                    ));
                }
                let pending: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) FROM dispatch_submission s \
                     JOIN dispatch_op_dedupe d ON d.dedupe_key=s.dedupe_key \
                     WHERE d.state='pending'",
                )
                .fetch_one(&mut *tx)
                .await?;
                if pending >= submission_hard_capacity as i64 {
                    return Err(StoreError::DispatchSubmissionCapacityExceeded {
                        pending: pending as usize,
                        capacity: submission_hard_capacity,
                    });
                }
                sqlx::query(
                    "INSERT IGNORE INTO dispatch_acceptance_sequence (singleton, current_value) VALUES (1, 0)",
                )
                .execute(&mut *tx)
                .await?;
                let advanced = sqlx::query(
                    "UPDATE dispatch_acceptance_sequence SET current_value=current_value+1 WHERE singleton=1 AND current_value<9223372036854775807",
                )
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if advanced != 1 {
                    return Err(StoreError::Upgrade(
                        "dispatch acceptance order exhausted".into(),
                    ));
                }
                acceptance_order = sqlx::query_scalar(
                    "SELECT current_value FROM dispatch_acceptance_sequence WHERE singleton=1",
                )
                .fetch_one(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO dispatch_submission \
                     (dedupe_key, delivery_id, op_id, payload_version, payload_blob, acceptance_order, accepted_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(submission.dedupe_key.as_str())
                .bind(submission.delivery_id.as_str())
                .bind(submission.op_id.as_str())
                .bind(submission.payload_version)
                .bind(submission.payload_blob.as_slice())
                .bind(acceptance_order)
                .bind(submission.accepted_at)
                .bind(submission.expires_at)
                .execute(&mut *tx)
                .await?;
            }
            if acceptance_order > 0 {
                OpDedupeReservation::ReservedSubmission { acceptance_order }
            } else {
                OpDedupeReservation::Reserved
            }
        } else {
            let existing = sqlx::query(
                "SELECT delivery_id, request_fingerprint, state FROM dispatch_op_dedupe WHERE dedupe_key = ? FOR UPDATE",
            )
            .bind(dedupe_key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                let existing_delivery_id = decode_mysql_text(&row, "delivery_id")?;
                let existing_fingerprint: Option<String> = row.try_get("request_fingerprint")?;
                let state: String = row.try_get("state")?;
                if matches!(
                    (request_fingerprint, existing_fingerprint.as_deref()),
                    (Some(requested), Some(existing)) if requested != existing
                ) {
                    OpDedupeReservation::FingerprintConflict {
                        delivery_id: existing_delivery_id,
                    }
                } else {
                    match DedupeState::from_str(state.as_str())? {
                        DedupeState::Pending => OpDedupeReservation::Pending {
                            delivery_id: existing_delivery_id,
                        },
                        DedupeState::ProviderQueued => OpDedupeReservation::ProviderQueued {
                            delivery_id: existing_delivery_id,
                        },
                        DedupeState::Sent => OpDedupeReservation::Sent {
                            delivery_id: existing_delivery_id,
                        },
                        DedupeState::PartialFailure => OpDedupeReservation::PartialFailure {
                            delivery_id: existing_delivery_id,
                        },
                    }
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

    pub(super) async fn list_pending_dispatch_submissions(
        &self,
        limit: usize,
        now: i64,
    ) -> StoreResult<Vec<DispatchSubmissionRecord>> {
        let rows = sqlx::query(
            "SELECT s.dedupe_key, s.delivery_id, s.op_id, s.payload_version, s.payload_blob, \
                    s.acceptance_order, s.accepted_at, s.expires_at \
             FROM dispatch_submission s \
             JOIN dispatch_op_dedupe d ON d.dedupe_key = s.dedupe_key \
             WHERE d.state = 'pending' AND COALESCE(d.provider_lease_until, 0) <= ? \
             ORDER BY s.accepted_at, s.delivery_id LIMIT ?",
        )
        .bind(now)
        .bind(limit.min(10_000) as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(DispatchSubmissionRecord {
                    dedupe_key: decode_mysql_text(&row, "dedupe_key")?,
                    delivery_id: decode_mysql_text(&row, "delivery_id")?,
                    op_id: decode_mysql_text(&row, "op_id")?,
                    payload_version: row.try_get("payload_version")?,
                    payload_blob: row.try_get("payload_blob")?,
                    acceptance_order: row.try_get("acceptance_order")?,
                    accepted_at: row.try_get("accepted_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .collect()
    }

    pub(super) async fn load_dispatch_submission_acceptance_order(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<Option<i64>> {
        sqlx::query_scalar(
            "SELECT acceptance_order FROM dispatch_submission WHERE dedupe_key=? AND delivery_id=?",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub(super) async fn claim_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        let changed = sqlx::query(
            "UPDATE dispatch_op_dedupe SET provider_owner=?, provider_lease_until=?, updated_at=? \
             WHERE dedupe_key=? AND delivery_id=? AND state='pending' \
               AND COALESCE(provider_lease_until, 0)<=?",
        )
        .bind(owner)
        .bind(lease_until)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(changed == 1)
    }

    pub(super) async fn renew_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
        lease_until: i64,
    ) -> StoreResult<bool> {
        let changed = sqlx::query(
            "UPDATE dispatch_op_dedupe SET provider_lease_until=?, updated_at=? \
             WHERE dedupe_key=? AND delivery_id=? AND state='pending' AND provider_owner=?",
        )
        .bind(lease_until)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(owner)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(changed == 1)
    }

    pub(super) async fn release_dispatch_submission_materialization(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        owner: &str,
        now: i64,
    ) -> StoreResult<bool> {
        let changed = sqlx::query(
            "UPDATE dispatch_op_dedupe SET provider_owner=NULL, provider_lease_until=NULL, updated_at=? \
             WHERE dedupe_key=? AND delivery_id=? AND state='pending' AND provider_owner=?",
        )
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(owner)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(changed == 1)
    }

    pub(super) async fn terminalize_unrecoverable_dispatch_submission(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        op_id: &str,
        reason: &str,
        now: i64,
    ) -> StoreResult<bool> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE dispatch_op_dedupe SET state='partial_failure', sent_at=?, updated_at=?, \
             provider_owner=NULL, provider_lease_until=NULL \
             WHERE dedupe_key=? AND delivery_id=? AND state='pending'",
        )
        .bind(now)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if changed {
            sqlx::query("DELETE FROM dispatch_submission WHERE dedupe_key=? AND delivery_id=?")
                .bind(dedupe_key)
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE sender_submit_status SET status='failed', dispatch_status=?, updated_at=? WHERE op_id=?",
            )
            .bind(reason)
            .bind(now)
            .bind(op_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub(super) async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        state: DedupeState,
    ) -> StoreResult<bool> {
        let now = Utc::now().timestamp_millis();
        let provider_queued = state == DedupeState::ProviderQueued;
        let provider_run_token = provider_queued.then(crate::util::generate_hex_id_128);
        let provider_owner = provider_queued.then(|| format!("gateway:{}", std::process::id()));
        let provider_lease_until = provider_queued.then(|| now.saturating_add(15 * 60 * 1000));
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE dispatch_op_dedupe \
             SET state = ?, sent_at = ?, updated_at = ?, provider_run_token = ?, provider_owner = ?, provider_lease_until = ? \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(state.as_str())
        .bind(now)
        .bind(now)
        .bind(provider_run_token.as_deref())
        .bind(provider_owner.as_deref())
        .bind(provider_lease_until)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&mut *tx)
        .await?;
        let finalized = result.rows_affected() > 0;
        if finalized {
            sqlx::query("DELETE FROM dispatch_submission WHERE dedupe_key=? AND delivery_id=?")
                .bind(dedupe_key)
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(finalized)
    }

    pub(super) async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM dispatch_submission WHERE dedupe_key = ? AND EXISTS (\
                SELECT 1 FROM dispatch_op_dedupe WHERE dedupe_key = ? AND delivery_id = ? AND state = ?\
             )",
        )
        .bind(dedupe_key)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
            "dispatch_submission",
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

fn decode_live_activity_token(row: sqlx::mysql::MySqlRow) -> StoreResult<LiveActivityTokenRecord> {
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

fn decode_widget_push_subscription(
    row: sqlx::mysql::MySqlRow,
) -> StoreResult<WidgetPushSubscriptionRecord> {
    Ok(WidgetPushSubscriptionRecord {
        device_key: decode_mysql_text(&row, "device_key")?,
        platform: row.get("platform"),
        token: row.get("token"),
        widget_kind: row.get("widget_kind"),
        family: row.get("family"),
        schema_version: row.get("schema_version"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn decode_sender_submit_status(
    row: sqlx::mysql::MySqlRow,
) -> StoreResult<SenderSubmitStatusRecord> {
    let channel_bytes: Vec<u8> = row.get("channel_id");
    let channel_id: [u8; 16] = channel_bytes
        .try_into()
        .map_err(|_| invalid_sender_status_data("invalid sender status channel_id length"))?;
    let status_text: String = row.get("status");
    let status = SenderSubmitStatusKind::parse(status_text.as_str())
        .ok_or_else(|| invalid_sender_status_data("invalid sender status kind"))?;
    Ok(SenderSubmitStatusRecord {
        op_id: decode_mysql_text(&row, "op_id")?,
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

pub(super) async fn delete_orphan_private_payload_in_mysql_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
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
