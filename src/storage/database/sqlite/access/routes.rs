use super::*;

async fn upsert_device_route_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &DeviceRouteRecordRow,
) -> StoreResult<()> {
    let values = route.persistence_values()?;
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (device_id) DO UPDATE SET \
           token_raw = EXCLUDED.token_raw, \
           platform_code = EXCLUDED.platform_code, \
           device_key = EXCLUDED.device_key, \
           platform = EXCLUDED.platform, \
           channel_type = EXCLUDED.channel_type, \
           provider_token = EXCLUDED.provider_token, \
           route_updated_at = EXCLUDED.route_updated_at",
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
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
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

impl SqliteDb {
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        upsert_device_route_in_tx(&mut tx, route).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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

        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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
        let now = Utc::now().timestamp();
        let platform_name = platform.name();
        let platform_code = platform.to_byte() as i16;
        let (token_hash, _) = ProviderTokenSnapshot::from_token(normalized_token).into_parts();
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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
             SET token_raw = CAST(device_key AS BLOB), channel_type = 'private', provider_token = NULL, route_updated_at = ? \
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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

    pub(super) async fn append_delivery_audit(
        &self,
        entry: &DeliveryAuditWrite,
    ) -> StoreResult<()> {
        let audit_id = crate::util::generate_hex_id_128();
        sqlx::query(
            "INSERT INTO delivery_audit \
             (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&audit_id)
        .bind(entry.delivery_id.trim())
        .bind(&entry.channel_id[..])
        .bind(entry.device_key.trim())
        .bind(entry.entity_type.as_deref())
        .bind(entry.entity_id.as_deref())
        .bind(entry.op_id.as_deref())
        .bind(entry.path.as_str())
        .bind(entry.status.as_str())
        .bind(entry.error_code.as_deref())
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn append_delivery_audit_batch(
        &self,
        entries: &[DeliveryAuditWrite],
    ) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for entry in entries {
            let audit_id = crate::util::generate_hex_id_128();
            sqlx::query(
                "INSERT INTO delivery_audit \
                 (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&audit_id)
            .bind(entry.delivery_id.trim())
            .bind(&entry.channel_id[..])
            .bind(entry.device_key.trim())
            .bind(entry.entity_type.as_deref())
            .bind(entry.entity_id.as_deref())
            .bind(entry.op_id.as_deref())
            .bind(entry.path.as_str())
            .bind(entry.status.as_str())
            .bind(entry.error_code.as_deref())
            .bind(entry.created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for row in &batch.channels {
            sqlx::query(
                "INSERT INTO channel_stats_daily \
                 (channel_id, bucket_date, messages_routed, deliveries_attempted, deliveries_acked, private_enqueued, provider_attempted, provider_failed, provider_success, private_realtime_delivered) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (channel_id, bucket_date) DO UPDATE SET \
                   messages_routed = channel_stats_daily.messages_routed + excluded.messages_routed, \
                   deliveries_attempted = channel_stats_daily.deliveries_attempted + excluded.deliveries_attempted, \
                   deliveries_acked = channel_stats_daily.deliveries_acked + excluded.deliveries_acked, \
                   private_enqueued = channel_stats_daily.private_enqueued + excluded.private_enqueued, \
                   provider_attempted = channel_stats_daily.provider_attempted + excluded.provider_attempted, \
                   provider_failed = channel_stats_daily.provider_failed + excluded.provider_failed, \
                   provider_success = channel_stats_daily.provider_success + excluded.provider_success, \
                   private_realtime_delivered = channel_stats_daily.private_realtime_delivered + excluded.private_realtime_delivered",
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
                 ON CONFLICT (device_key, bucket_date) DO UPDATE SET \
                   messages_received = device_stats_daily.messages_received + excluded.messages_received, \
                   messages_acked = device_stats_daily.messages_acked + excluded.messages_acked, \
                   private_connected_count = device_stats_daily.private_connected_count + excluded.private_connected_count, \
                   private_pull_count = device_stats_daily.private_pull_count + excluded.private_pull_count, \
                   provider_success_count = device_stats_daily.provider_success_count + excluded.provider_success_count, \
                   provider_failure_count = device_stats_daily.provider_failure_count + excluded.provider_failure_count, \
                   private_outbox_enqueued_count = device_stats_daily.private_outbox_enqueued_count + excluded.private_outbox_enqueued_count",
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
                 ON CONFLICT (bucket_hour) DO UPDATE SET \
                   messages_routed = gateway_stats_hourly.messages_routed + excluded.messages_routed, \
                   deliveries_attempted = gateway_stats_hourly.deliveries_attempted + excluded.deliveries_attempted, \
                   deliveries_acked = gateway_stats_hourly.deliveries_acked + excluded.deliveries_acked, \
                   private_outbox_depth_max = max(gateway_stats_hourly.private_outbox_depth_max, excluded.private_outbox_depth_max), \
                   dedupe_pending_max = max(gateway_stats_hourly.dedupe_pending_max, excluded.dedupe_pending_max), \
                   active_private_sessions_max = max(gateway_stats_hourly.active_private_sessions_max, excluded.active_private_sessions_max)",
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
        tx.commit().await?;
        Ok(())
    }
}
