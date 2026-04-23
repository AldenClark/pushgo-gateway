use super::*;

async fn upsert_device_route_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    route: &DeviceRouteRecordRow,
) -> StoreResult<()> {
    let values = route.persistence_values()?;
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
           token_raw = VALUES(token_raw), \
           platform_code = VALUES(platform_code), \
           device_key = VALUES(device_key), \
           platform = VALUES(platform), \
           channel_type = VALUES(channel_type), \
           provider_token = VALUES(provider_token), \
           route_updated_at = VALUES(route_updated_at)",
    )
    .bind(values.device_id.as_slice())
    .bind(values.token_raw.as_slice())
    .bind(values.platform_code)
    .bind(&values.device_key)
    .bind(&values.platform)
    .bind(&values.channel_type)
    .bind(values.provider_token.as_deref())
    .bind(values.updated_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_device_route_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    audit: &DeviceRouteAuditWrite,
) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO device_route_audit (device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token, new_provider_token, issue_reason, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&audit.device_key)
    .bind(&audit.action)
    .bind(&audit.old_platform)
    .bind(&audit.new_platform)
    .bind(&audit.old_channel_type)
    .bind(&audit.new_channel_type)
    .bind(&audit.old_provider_token)
    .bind(&audit.new_provider_token)
    .bind(&audit.issue_reason)
    .bind(audit.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl MySqlDb {
    pub(super) async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        let rows = sqlx::query(
            "SELECT device_key, platform, channel_type, provider_token, route_updated_at \
             FROM devices \
             WHERE device_key IS NOT NULL \
               AND platform IS NOT NULL \
               AND channel_type IS NOT NULL \
               AND route_updated_at IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(DeviceRouteRecordRow {
                device_key: r.get("device_key"),
                platform: r.get("platform"),
                channel_type: r.get("channel_type"),
                provider_token: r.get("provider_token"),
                updated_at: r.get("route_updated_at"),
            });
        }
        Ok(out)
    }

    pub(super) async fn upsert_device_route(
        &self,
        route: &DeviceRouteRecordRow,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        upsert_device_route_in_tx(&mut tx, route).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        upsert_device_route_in_tx(&mut tx, route).await?;
        insert_device_route_audit_in_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let values = route.persistence_values()?;
        let old_key = old_device_key
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != values.device_key);
        let old_device_id = old_key.map(|key| PrivateDeviceId::derive(key).to_vec());

        let mut tx = self.pool.begin().await?;
        let delivery_ids = if let Some(device_id) = old_device_id.as_deref() {
            let rows = sqlx::query(
                "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
                 UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
            )
            .bind(device_id)
            .bind(device_id)
            .fetch_all(&mut *tx)
            .await?;
            rows.into_iter()
                .map(|row| row.get("delivery_id"))
                .collect::<Vec<String>>()
        } else {
            Vec::new()
        };

        upsert_device_route_in_tx(&mut tx, route).await?;
        insert_device_route_audit_in_tx(&mut tx, audit).await?;

        if let (Some(old_key), Some(device_id)) = (old_key, old_device_id.as_deref()) {
            for statement in [
                "DELETE FROM channel_subscriptions WHERE device_id = ?",
                "DELETE FROM provider_pull_queue WHERE device_id = ?",
                "DELETE FROM private_bindings WHERE device_id = ?",
                "DELETE FROM private_outbox WHERE device_id = ?",
                "DELETE FROM private_sessions WHERE device_id = ?",
                "DELETE FROM private_device_keys WHERE device_id = ?",
            ] {
                sqlx::query(statement)
                    .bind(device_id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("DELETE FROM devices WHERE device_key = ? OR device_id = ?")
                .bind(old_key)
                .bind(device_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
                .bind(old_key)
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
        }

        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        let normalized_key = device_key.trim();
        if normalized_key.is_empty() {
            return Ok(());
        }
        let device_id = PrivateDeviceId::derive(normalized_key).to_vec();
        let mut tx = self.pool.begin().await?;
        let delivery_rows = sqlx::query(
            "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
             UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
        )
        .bind(device_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

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
        sqlx::query("DELETE FROM devices WHERE device_key = ? OR device_id = ?")
            .bind(normalized_key)
            .bind(device_id.as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
            .bind(normalized_key)
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

    pub(super) async fn retire_provider_token(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        let normalized_token = provider_token.trim();
        if normalized_token.is_empty() {
            return Ok(());
        }
        let now = Utc::now().timestamp_millis();
        let platform_name = platform.name();
        let platform_code = platform.to_byte() as i16;
        let (token_hash, _) = ProviderTokenSnapshot::from_token(normalized_token).into_parts();
        let mut tx = self.pool.begin().await?;
        let delivery_rows = sqlx::query(
            "SELECT delivery_id FROM provider_pull_queue WHERE platform = ? AND provider_token = ?",
        )
        .bind(platform_name)
        .bind(normalized_token)
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

        sqlx::query("DELETE FROM provider_pull_queue WHERE platform = ? AND provider_token = ?")
            .bind(platform_name)
            .bind(normalized_token)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM private_bindings WHERE platform = ? AND token_hash = ?")
            .bind(platform_code)
            .bind(&token_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE devices \
             SET token_raw = CAST(device_key AS BINARY), channel_type = 'private', provider_token = NULL, route_updated_at = ? \
             WHERE platform = ? AND provider_token = ? AND device_key IS NOT NULL",
        )
        .bind(now)
        .bind(platform_name)
        .bind(normalized_token)
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

    pub(super) async fn append_device_route_audit(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        insert_device_route_audit_in_tx(&mut tx, entry).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn append_subscription_audit(
        &self,
        entry: &SubscriptionAuditWrite,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO subscription_audit (channel_id, device_key, action, platform, channel_type, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.channel_id[..])
        .bind(&entry.device_key)
        .bind(&entry.action)
        .bind(&entry.platform)
        .bind(&entry.channel_type)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        for row in &batch.channels {
            sqlx::query(
                "INSERT INTO channel_stats_daily \
                 (channel_id, bucket_date, messages_routed, deliveries_attempted, deliveries_acked, private_enqueued, provider_attempted, provider_failed, provider_success, private_realtime_delivered) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   messages_routed = messages_routed + VALUES(messages_routed), \
                   deliveries_attempted = deliveries_attempted + VALUES(deliveries_attempted), \
                   deliveries_acked = deliveries_acked + VALUES(deliveries_acked), \
                   private_enqueued = private_enqueued + VALUES(private_enqueued), \
                   provider_attempted = provider_attempted + VALUES(provider_attempted), \
                   provider_failed = provider_failed + VALUES(provider_failed), \
                   provider_success = provider_success + VALUES(provider_success), \
                   private_realtime_delivered = private_realtime_delivered + VALUES(private_realtime_delivered)",
            )
            .bind(&row.channel_id[..])
            .bind(row.bucket_date.as_str())
            .bind(row.messages_routed)
            .bind(row.deliveries_attempted)
            .bind(row.deliveries_acked)
            .bind(row.private_enqueued)
            .bind(row.provider_attempted)
            .bind(row.provider_failed)
            .bind(row.provider_success)
            .bind(row.private_realtime_delivered)
            .execute(&mut *tx)
            .await?;
        }
        for row in &batch.devices {
            sqlx::query(
                "INSERT INTO device_stats_daily \
                 (device_key, bucket_date, messages_received, messages_acked, private_connected_count, private_pull_count, provider_success_count, provider_failure_count, private_outbox_enqueued_count) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   messages_received = messages_received + VALUES(messages_received), \
                   messages_acked = messages_acked + VALUES(messages_acked), \
                   private_connected_count = private_connected_count + VALUES(private_connected_count), \
                   private_pull_count = private_pull_count + VALUES(private_pull_count), \
                   provider_success_count = provider_success_count + VALUES(provider_success_count), \
                   provider_failure_count = provider_failure_count + VALUES(provider_failure_count), \
                   private_outbox_enqueued_count = private_outbox_enqueued_count + VALUES(private_outbox_enqueued_count)",
            )
            .bind(row.device_key.trim())
            .bind(row.bucket_date.as_str())
            .bind(row.messages_received)
            .bind(row.messages_acked)
            .bind(row.private_connected_count)
            .bind(row.private_pull_count)
            .bind(row.provider_success_count)
            .bind(row.provider_failure_count)
            .bind(row.private_outbox_enqueued_count)
            .execute(&mut *tx)
            .await?;
        }
        for row in &batch.gateway {
            sqlx::query(
                "INSERT INTO gateway_stats_hourly \
                 (bucket_hour, messages_routed, deliveries_attempted, deliveries_acked, private_outbox_depth_max, dedupe_pending_max, active_private_sessions_max) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   messages_routed = messages_routed + VALUES(messages_routed), \
                   deliveries_attempted = deliveries_attempted + VALUES(deliveries_attempted), \
                   deliveries_acked = deliveries_acked + VALUES(deliveries_acked), \
                   private_outbox_depth_max = GREATEST(private_outbox_depth_max, VALUES(private_outbox_depth_max)), \
                   dedupe_pending_max = GREATEST(dedupe_pending_max, VALUES(dedupe_pending_max)), \
                   active_private_sessions_max = GREATEST(active_private_sessions_max, VALUES(active_private_sessions_max))",
            )
            .bind(row.bucket_hour.as_str())
            .bind(row.messages_routed)
            .bind(row.deliveries_attempted)
            .bind(row.deliveries_acked)
            .bind(row.private_outbox_depth_max)
            .bind(row.dedupe_pending_max)
            .bind(row.active_private_sessions_max)
            .execute(&mut *tx)
            .await?;
        }
        for row in &batch.ops {
            sqlx::query(
                "INSERT INTO ops_stats_hourly \
                 (bucket_hour, metric_key, metric_value) \
                 VALUES (?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   metric_value = metric_value + VALUES(metric_value)",
            )
            .bind(row.bucket_hour.as_str())
            .bind(row.metric_key.trim())
            .bind(row.metric_value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
