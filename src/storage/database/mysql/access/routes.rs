use super::*;

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
        let provider_token = route.provider_token.as_deref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let device_id = route.device_id_bytes()?;
        let platform: Platform = route.platform.parse()?;
        let (platform_code, token_raw) = if let Some(token) = provider_token.as_deref() {
            let info = DeviceInfo::from_token(platform, token)?;
            (platform.to_byte() as i16, info.token_raw.to_vec())
        } else {
            (
                platform.to_byte() as i16,
                route.device_key.trim().as_bytes().to_vec(),
            )
        };
        let platform = route.platform.trim().to_ascii_lowercase();
        let channel_type = route.channel_type.trim().to_ascii_lowercase();

        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM devices WHERE device_key = ? AND device_id <> ?")
            .bind(route.device_key.trim())
            .bind(&device_id)
            .execute(&mut *tx)
            .await?;
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
        .bind(&device_id)
        .bind(token_raw.as_slice())
        .bind(platform_code)
        .bind(route.device_key.trim())
        .bind(&platform)
        .bind(&channel_type)
        .bind(provider_token.as_deref())
        .bind(route.updated_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn apply_route_snapshot(
        &self,
        snapshot: &DeviceRouteSnapshot,
    ) -> StoreResult<()> {
        let (token_hash, token_preview) =
            RouteSnapshotFields::from_provider_token(snapshot.provider_token.as_deref())
                .into_parts();
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE channel_subscriptions \
             SET platform = ?, \
                 channel_type = ?, \
                 device_key = ?, \
                 provider_token = ?, \
                 provider_token_hash = ?, \
                 provider_token_preview = ?, \
                 route_version = route_version + 1, \
                 updated_at = ? \
             WHERE device_id = ?",
        )
        .bind(snapshot.platform.name())
        .bind(snapshot.channel_type.as_str())
        .bind(snapshot.device_key.as_str())
        .bind(snapshot.provider_token.as_deref())
        .bind(token_hash.as_deref())
        .bind(token_preview.as_deref())
        .bind(now)
        .bind(snapshot.device_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn append_device_route_audit(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO device_route_audit (device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token, new_provider_token, issue_reason, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.device_key)
        .bind(&entry.action)
        .bind(&entry.old_platform)
        .bind(&entry.new_platform)
        .bind(&entry.old_channel_type)
        .bind(&entry.new_channel_type)
        .bind(&entry.old_provider_token)
        .bind(&entry.new_provider_token)
        .bind(&entry.issue_reason)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
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
        tx.commit().await?;
        Ok(())
    }
}
