use super::*;

async fn upsert_device_route_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    route: &DeviceRouteRecordRow,
) -> StoreResult<()> {
    let values = route.persistence_values()?;
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: &DeviceRouteAuditWrite,
) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO device_route_audit (device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token, new_provider_token, issue_reason, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
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

impl PostgresDb {
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
                "SELECT delivery_id FROM private_outbox WHERE device_id = $1 \
                 UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = $1",
            )
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
                "DELETE FROM channel_subscriptions WHERE device_id = $1",
                "DELETE FROM provider_pull_queue WHERE device_id = $1",
                "DELETE FROM private_bindings WHERE device_id = $1",
                "DELETE FROM private_outbox WHERE device_id = $1",
                "DELETE FROM private_sessions WHERE device_id = $1",
                "DELETE FROM private_device_keys WHERE device_id = $1",
            ] {
                sqlx::query(statement)
                    .bind(device_id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("DELETE FROM devices WHERE device_key = $1 OR device_id = $2")
                .bind(old_key)
                .bind(device_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM device_stats_daily WHERE device_key = $1")
                .bind(old_key)
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
            "SELECT delivery_id FROM private_outbox WHERE device_id = $1 \
             UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = $1",
        )
        .bind(device_id.as_slice())
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

        for statement in [
            "DELETE FROM channel_subscriptions WHERE device_id = $1",
            "DELETE FROM provider_pull_queue WHERE device_id = $1",
            "DELETE FROM private_bindings WHERE device_id = $1",
            "DELETE FROM private_outbox WHERE device_id = $1",
            "DELETE FROM private_sessions WHERE device_id = $1",
            "DELETE FROM private_device_keys WHERE device_id = $1",
        ] {
            sqlx::query(statement)
                .bind(device_id.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM devices WHERE device_key = $1 OR device_id = $2")
            .bind(normalized_key)
            .bind(device_id.as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_stats_daily WHERE device_key = $1")
            .bind(normalized_key)
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
        let mut tx = self.pool.begin().await?;
        let delivery_rows = sqlx::query(
            "SELECT delivery_id FROM provider_pull_queue WHERE platform = $1 AND provider_token = $2",
        )
        .bind(platform_name)
        .bind(normalized_token)
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

        sqlx::query("DELETE FROM provider_pull_queue WHERE platform = $1 AND provider_token = $2")
            .bind(platform_name)
            .bind(normalized_token)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM private_bindings WHERE platform = $1 AND token_hash = $2")
            .bind(platform_code)
            .bind(&token_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE devices \
             SET token_raw = convert_to(device_key, 'UTF8'), channel_type = 'private', provider_token = NULL, route_updated_at = $1 \
             WHERE platform = $2 AND provider_token = $3 AND device_key IS NOT NULL",
        )
        .bind(now)
        .bind(platform_name)
        .bind(normalized_token)
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
             VALUES ($1, $2, $3, $4, $5, $6)",
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
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (channel_id, bucket_date) DO UPDATE SET \
                   messages_routed = channel_stats_daily.messages_routed + EXCLUDED.messages_routed, \
                   deliveries_attempted = channel_stats_daily.deliveries_attempted + EXCLUDED.deliveries_attempted, \
                   deliveries_acked = channel_stats_daily.deliveries_acked + EXCLUDED.deliveries_acked, \
                   private_enqueued = channel_stats_daily.private_enqueued + EXCLUDED.private_enqueued, \
                   provider_attempted = channel_stats_daily.provider_attempted + EXCLUDED.provider_attempted, \
                   provider_failed = channel_stats_daily.provider_failed + EXCLUDED.provider_failed, \
                   provider_success = channel_stats_daily.provider_success + EXCLUDED.provider_success, \
                   private_realtime_delivered = channel_stats_daily.private_realtime_delivered + EXCLUDED.private_realtime_delivered",
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
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (device_key, bucket_date) DO UPDATE SET \
                   messages_received = device_stats_daily.messages_received + EXCLUDED.messages_received, \
                   messages_acked = device_stats_daily.messages_acked + EXCLUDED.messages_acked, \
                   private_connected_count = device_stats_daily.private_connected_count + EXCLUDED.private_connected_count, \
                   private_pull_count = device_stats_daily.private_pull_count + EXCLUDED.private_pull_count, \
                   provider_success_count = device_stats_daily.provider_success_count + EXCLUDED.provider_success_count, \
                   provider_failure_count = device_stats_daily.provider_failure_count + EXCLUDED.provider_failure_count, \
                   private_outbox_enqueued_count = device_stats_daily.private_outbox_enqueued_count + EXCLUDED.private_outbox_enqueued_count",
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
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (bucket_hour) DO UPDATE SET \
                   messages_routed = gateway_stats_hourly.messages_routed + EXCLUDED.messages_routed, \
                   deliveries_attempted = gateway_stats_hourly.deliveries_attempted + EXCLUDED.deliveries_attempted, \
                   deliveries_acked = gateway_stats_hourly.deliveries_acked + EXCLUDED.deliveries_acked, \
                   private_outbox_depth_max = GREATEST(gateway_stats_hourly.private_outbox_depth_max, EXCLUDED.private_outbox_depth_max), \
                   dedupe_pending_max = GREATEST(gateway_stats_hourly.dedupe_pending_max, EXCLUDED.dedupe_pending_max), \
                   active_private_sessions_max = GREATEST(gateway_stats_hourly.active_private_sessions_max, EXCLUDED.active_private_sessions_max)",
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
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (bucket_hour, metric_key) DO UPDATE SET \
                   metric_value = ops_stats_hourly.metric_value + EXCLUDED.metric_value",
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
