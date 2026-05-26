use super::*;
use crate::value::{DeviceKeyRef, ProviderTokenRef};

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

#[derive(Debug)]
struct DuplicateProviderRouteRow {
    device_id: Vec<u8>,
    device_key: Option<String>,
}

async fn collect_duplicate_provider_routes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<Vec<DuplicateProviderRouteRow>> {
    let Some(provider_token) = route.provider_token.as_deref() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        "SELECT device_id, device_key \
         FROM devices \
         WHERE platform = ? AND provider_token = ? AND device_id <> ?",
    )
    .bind(route.platform.as_str())
    .bind(provider_token)
    .bind(route.device_id.as_slice())
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| DuplicateProviderRouteRow {
            device_id: row.get("device_id"),
            device_key: row.get("device_key"),
        })
        .collect())
}

async fn load_device_delivery_ids_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device_id: &[u8],
) -> StoreResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
         UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
    )
    .bind(device_id)
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(|row| row.get("delivery_id")).collect())
}

async fn cleanup_orphan_private_payloads_in_tx(
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

async fn coalesce_duplicate_provider_routes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<Vec<Vec<u8>>> {
    let duplicates = collect_duplicate_provider_routes_in_tx(tx, route).await?;
    if duplicates.is_empty() {
        return Ok(Vec::new());
    }

    let mut duplicate_device_ids = Vec::with_capacity(duplicates.len());
    for duplicate in duplicates {
        duplicate_device_ids.push(duplicate.device_id.clone());
        let delivery_ids =
            load_device_delivery_ids_in_tx(tx, duplicate.device_id.as_slice()).await?;

        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             SELECT channel_id, ?, status, created_at, updated_at \
             FROM channel_subscriptions \
             WHERE device_id = ? AND status = 'active' \
             ON CONFLICT (channel_id, device_id) DO UPDATE SET \
               status = CASE \
                 WHEN channel_subscriptions.status = 'active' OR excluded.status = 'active' THEN 'active' \
                 ELSE excluded.status \
               END, \
               created_at = MIN(channel_subscriptions.created_at, excluded.created_at), \
               updated_at = MAX(channel_subscriptions.updated_at, excluded.updated_at)",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT ?, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at \
             FROM provider_pull_queue \
             WHERE device_id = ? \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
               payload_blob = excluded.payload_blob, \
               payload_size = excluded.payload_size, \
               sent_at = MIN(provider_pull_queue.sent_at, excluded.sent_at), \
               expires_at = MAX(provider_pull_queue.expires_at, excluded.expires_at), \
               platform = excluded.platform, \
               provider_token = excluded.provider_token, \
               created_at = MIN(provider_pull_queue.created_at, excluded.created_at), \
               updated_at = MAX(provider_pull_queue.updated_at, excluded.updated_at)",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        for statement in [
            "DELETE FROM channel_subscriptions WHERE device_id = ?",
            "DELETE FROM provider_pull_queue WHERE device_id = ?",
            "DELETE FROM private_bindings WHERE device_id = ?",
            "DELETE FROM private_outbox WHERE device_id = ?",
            "DELETE FROM private_sessions WHERE device_id = ?",
            "DELETE FROM private_device_keys WHERE device_id = ?",
        ] {
            sqlx::query(statement)
                .bind(duplicate.device_id.as_slice())
                .execute(&mut **tx)
                .await?;
        }

        sqlx::query("DELETE FROM devices WHERE device_id = ?")
            .bind(duplicate.device_id.as_slice())
            .execute(&mut **tx)
            .await?;
        if let Some(device_key) = duplicate.device_key.as_deref() {
            sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
                .bind(device_key)
                .execute(&mut **tx)
                .await?;
        }

        cleanup_orphan_private_payloads_in_tx(tx, &delivery_ids).await?;
    }

    Ok(duplicate_device_ids)
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
        .fetch_all(self.core_read_pool())
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
        let values = route.persistence_values()?;
        upsert_device_route_in_tx(&mut tx, route).await?;
        let duplicate_device_ids =
            coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        tx.commit().await?;
        self.coalesce_delivery_device_rows(&duplicate_device_ids, values.device_id.as_slice())
            .await?;
        Ok(())
    }

    pub(super) async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
        audit: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let values = route.persistence_values()?;
        upsert_device_route_in_tx(&mut tx, route).await?;
        let duplicate_device_ids =
            coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        insert_device_route_audit_in_tx(&mut tx, audit).await?;
        tx.commit().await?;
        self.coalesce_delivery_device_rows(&duplicate_device_ids, values.device_id.as_slice())
            .await?;
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
            .and_then(|value| DeviceKeyRef::optional(Some(value)))
            .filter(|value| value.as_str() != values.device_key);
        let old_device_id = old_key.map(|key| PrivateDeviceId::derive(key.as_str()).to_vec());

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
        let duplicate_device_ids =
            coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
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
                .bind(old_key.as_str())
                .bind(device_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
                .bind(old_key.as_str())
                .execute(&mut *tx)
                .await?;
            cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;
        }

        tx.commit().await?;
        self.coalesce_delivery_device_rows(&duplicate_device_ids, values.device_id.as_slice())
            .await?;
        if let Some(device_id) = old_device_id.as_deref() {
            self.delete_delivery_device_state(device_id).await?;
        }
        Ok(())
    }

    pub(super) async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        let Some(normalized_key) = DeviceKeyRef::optional(Some(device_key)) else {
            return Ok(());
        };
        let device_id = PrivateDeviceId::derive(normalized_key.as_str()).to_vec();
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
            .bind(normalized_key.as_str())
            .bind(device_id.as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_stats_daily WHERE device_key = ?")
            .bind(normalized_key.as_str())
            .execute(&mut *tx)
            .await?;

        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;

        tx.commit().await?;
        self.delete_delivery_device_state(device_id.as_slice())
            .await?;
        Ok(())
    }

    pub(super) async fn retire_provider_token(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        let Some(normalized_token) = ProviderTokenRef::optional(Some(provider_token)) else {
            return Ok(());
        };
        let now = Utc::now().timestamp_millis();
        let platform_name = platform.name();
        let platform_code = platform.to_byte() as i16;
        let (token_hash, _) =
            ProviderTokenSnapshot::from_token(normalized_token.as_str()).into_parts();
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let delivery_rows = sqlx::query(
            "SELECT delivery_id FROM provider_pull_queue WHERE platform = ? AND provider_token = ?",
        )
        .bind(platform_name)
        .bind(normalized_token.as_str())
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

        sqlx::query("DELETE FROM provider_pull_queue WHERE platform = ? AND provider_token = ?")
            .bind(platform_name)
            .bind(normalized_token.as_str())
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
        .bind(normalized_token.as_str())
        .execute(&mut *tx)
        .await?;

        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;

        tx.commit().await?;
        self.delete_delivery_provider_token(platform_name, normalized_token.as_str())
            .await?;
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

    async fn coalesce_delivery_device_rows(
        &self,
        duplicate_device_ids: &[Vec<u8>],
        target_device_id: &[u8],
    ) -> StoreResult<()> {
        if duplicate_device_ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        for duplicate_device_id in duplicate_device_ids {
            let delivery_ids = load_device_delivery_ids_in_tx(&mut tx, duplicate_device_id).await?;
            sqlx::query(
                "INSERT INTO provider_pull_queue \
                 (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
                 SELECT ?, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at \
                 FROM provider_pull_queue \
                 WHERE device_id = ? \
                 ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                   payload_blob = excluded.payload_blob, \
                   payload_size = excluded.payload_size, \
                   sent_at = MIN(provider_pull_queue.sent_at, excluded.sent_at), \
                   expires_at = MAX(provider_pull_queue.expires_at, excluded.expires_at), \
                   platform = excluded.platform, \
                   provider_token = excluded.provider_token, \
                   created_at = MIN(provider_pull_queue.created_at, excluded.created_at), \
                   updated_at = MAX(provider_pull_queue.updated_at, excluded.updated_at)",
            )
            .bind(target_device_id)
            .bind(duplicate_device_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ?")
                .bind(duplicate_device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                .bind(duplicate_device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn delete_delivery_device_state(&self, device_id: &[u8]) -> StoreResult<()> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let delivery_ids = load_device_delivery_ids_in_tx(&mut tx, device_id).await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete_delivery_provider_token(
        &self,
        platform_name: &str,
        provider_token: &str,
    ) -> StoreResult<()> {
        let mut conn = self.delivery_pool().acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT delivery_id FROM provider_pull_queue WHERE platform = ? AND provider_token = ?",
        )
        .bind(platform_name)
        .bind(provider_token)
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids = rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect::<Vec<String>>();
        sqlx::query("DELETE FROM provider_pull_queue WHERE platform = ? AND provider_token = ?")
            .bind(platform_name)
            .bind(provider_token)
            .execute(&mut *tx)
            .await?;
        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        let mut conn = self.telemetry_pool().acquire().await?;
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
            .bind(
                DeviceKeyRef::parse(row.device_key.as_str())
                    .map(DeviceKeyRef::as_str)
                    .unwrap_or(""),
            )
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
        for row in &batch.ops {
            sqlx::query(
                "INSERT INTO ops_stats_hourly \
                 (bucket_hour, metric_key, metric_value) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT (bucket_hour, metric_key) DO UPDATE SET \
                   metric_value = ops_stats_hourly.metric_value + excluded.metric_value",
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
