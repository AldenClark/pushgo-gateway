use super::*;
use crate::value::{DeviceKeyRef, ProviderTokenRef};

pub(in crate::storage::database::pg) async fn upsert_device_route_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    route: &DeviceRouteRecordRow,
) -> StoreResult<()> {
    let values = route.persistence_values()?;
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at, route_revision) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1) \
         ON CONFLICT (device_id) DO UPDATE SET \
           token_raw = EXCLUDED.token_raw, \
           platform_code = EXCLUDED.platform_code, \
           device_key = EXCLUDED.device_key, \
           platform = EXCLUDED.platform, \
           channel_type = EXCLUDED.channel_type, \
           provider_token = EXCLUDED.provider_token, \
           route_updated_at = EXCLUDED.route_updated_at, \
           route_revision = devices.route_revision + 1",
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

#[derive(Debug)]
struct DuplicateProviderRouteRow {
    device_id: Vec<u8>,
}

async fn collect_duplicate_provider_routes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<Vec<DuplicateProviderRouteRow>> {
    let Some(provider_token) = route.provider_token.as_deref() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        "SELECT device_id \
         FROM devices \
         WHERE platform = $1 AND provider_token = $2 AND device_id <> $3",
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
        })
        .collect())
}

async fn load_device_delivery_ids_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: &[u8],
) -> StoreResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT delivery_id FROM private_outbox WHERE device_id = $1 \
         UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(|row| row.get("delivery_id")).collect())
}

async fn cleanup_orphan_private_payloads_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_ids: &[String],
) -> StoreResult<()> {
    for delivery_id in delivery_ids {
        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = $1 \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub(in crate::storage::database::pg) async fn coalesce_duplicate_provider_routes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<()> {
    let duplicates = collect_duplicate_provider_routes_in_tx(tx, route).await?;
    if duplicates.is_empty() {
        return Ok(());
    }

    for duplicate in duplicates {
        let delivery_ids =
            load_device_delivery_ids_in_tx(tx, duplicate.device_id.as_slice()).await?;

        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             SELECT channel_id, $1, status, created_at, updated_at \
             FROM channel_subscriptions \
             WHERE device_id = $2 AND status = 'active' \
             ON CONFLICT (channel_id, device_id) DO UPDATE SET \
               status = CASE \
                 WHEN channel_subscriptions.status = 'active' OR EXCLUDED.status = 'active' THEN 'active' \
                 ELSE EXCLUDED.status \
               END, \
               created_at = LEAST(channel_subscriptions.created_at, EXCLUDED.created_at), \
               updated_at = GREATEST(channel_subscriptions.updated_at, EXCLUDED.updated_at)",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT $1, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at \
             FROM provider_pull_queue \
             WHERE device_id = $2 \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
               payload_blob = EXCLUDED.payload_blob, \
               payload_size = EXCLUDED.payload_size, \
               sent_at = LEAST(provider_pull_queue.sent_at, EXCLUDED.sent_at), \
               expires_at = GREATEST(provider_pull_queue.expires_at, EXCLUDED.expires_at), \
               platform = EXCLUDED.platform, \
               provider_token = EXCLUDED.provider_token, \
               created_at = LEAST(provider_pull_queue.created_at, EXCLUDED.created_at), \
               updated_at = GREATEST(provider_pull_queue.updated_at, EXCLUDED.updated_at)",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT $1, o.delivery_id, ''::bytea, 0, p.sent_at, p.expires_at, $2, $3, p.created_at, p.updated_at \
             FROM private_outbox o JOIN private_payloads p ON p.delivery_id = o.delivery_id \
             WHERE o.device_id = $4 \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
               sent_at = LEAST(provider_pull_queue.sent_at, EXCLUDED.sent_at), \
               expires_at = GREATEST(provider_pull_queue.expires_at, EXCLUDED.expires_at), \
               platform = EXCLUDED.platform, provider_token = EXCLUDED.provider_token, \
               updated_at = GREATEST(provider_pull_queue.updated_at, EXCLUDED.updated_at)",
        )
        .bind(route.device_id.as_slice())
        .bind(route.platform.as_str())
        .bind(route.provider_token.as_deref())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        for statement in [
            "DELETE FROM channel_subscriptions WHERE device_id = $1",
            "DELETE FROM provider_pull_queue WHERE device_id = $1",
            "DELETE FROM private_bindings WHERE device_id = $1",
            "DELETE FROM private_outbox WHERE device_id = $1",
            "DELETE FROM private_sessions WHERE device_id = $1",
            "DELETE FROM private_device_keys WHERE device_id = $1",
        ] {
            sqlx::query(statement)
                .bind(duplicate.device_id.as_slice())
                .execute(&mut **tx)
                .await?;
        }

        sqlx::query("DELETE FROM devices WHERE device_id = $1")
            .bind(duplicate.device_id.as_slice())
            .execute(&mut **tx)
            .await?;

        cleanup_orphan_private_payloads_in_tx(tx, &delivery_ids).await?;
    }

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
        let values = route.persistence_values()?;
        let now = values.updated_at;
        upsert_device_route_in_tx(&mut tx, route).await?;
        if let Some(provider_token) = values.provider_token.as_deref() {
            let (token_hash, _) = ProviderTokenSnapshot::from_token(provider_token).into_parts();
            sqlx::query(
                "INSERT INTO private_bindings \
                 (device_id, platform, provider_token, token_hash, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $5) \
                 ON CONFLICT (platform, token_hash) DO UPDATE SET \
                   device_id = EXCLUDED.device_id, provider_token = EXCLUDED.provider_token, \
                   updated_at = EXCLUDED.updated_at",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn touch_device_activity(
        &self,
        device_id: DeviceId,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE devices \
             SET route_updated_at = CASE \
               WHEN route_updated_at IS NULL OR route_updated_at < $1 THEN $1 \
               ELSE route_updated_at \
             END \
             WHERE device_id = $2",
        )
        .bind(at_ts)
        .bind(device_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn persist_device_route_change(
        &self,
        route: &DeviceRouteRecordRow,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        let values = route.persistence_values()?;
        let now = values.updated_at;
        upsert_device_route_in_tx(&mut tx, route).await?;
        if let Some(provider_token) = values.provider_token.as_deref() {
            let (token_hash, _) = ProviderTokenSnapshot::from_token(provider_token).into_parts();
            sqlx::query(
                "INSERT INTO private_bindings \
                 (device_id, platform, provider_token, token_hash, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $5) \
                 ON CONFLICT (platform, token_hash) DO UPDATE SET \
                   device_id = EXCLUDED.device_id, provider_token = EXCLUDED.provider_token, \
                   updated_at = EXCLUDED.updated_at",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn transition_device_route(
        &self,
        route: &DeviceRouteRecordRow,
        _previous_channel_type: RouteChannelType,
        ack_timeout_secs: u64,
        max_pending_per_device: usize,
    ) -> StoreResult<usize> {
        let values = route.persistence_values()?;
        let next_channel_type = route.channel_type_kind()?;
        let now = Utc::now().timestamp_millis();
        let mut tx = self.pool.begin().await?;
        let current_route = sqlx::query(
            "SELECT channel_type, route_updated_at FROM devices WHERE device_id = $1 FOR UPDATE",
        )
        .bind(values.device_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if current_route.as_ref().is_some_and(|row| {
            row.get::<Option<i64>, _>("route_updated_at")
                .is_some_and(|updated_at| updated_at >= values.updated_at)
        }) {
            tx.commit().await?;
            return Ok(0);
        }
        let previous_channel_type = current_route
            .and_then(|row| row.get::<Option<String>, _>("channel_type"))
            .map(|value| RouteChannelType::parse(value.as_str()))
            .transpose()?
            .unwrap_or(next_channel_type);
        let migrated = if previous_channel_type.is_private() && !next_channel_type.is_private() {
            let provider_token = values
                .provider_token
                .as_deref()
                .ok_or(StoreError::InvalidDeviceToken)?;
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(1) FROM private_outbox o \
                 JOIN private_payloads p ON p.delivery_id = o.delivery_id \
                 WHERE o.device_id = $1",
            )
            .bind(values.device_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO provider_pull_queue \
                 (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
                 SELECT o.device_id, o.delivery_id, ''::bytea, 0, p.sent_at, p.expires_at, $1, $2, $3, $3 \
                 FROM private_outbox o JOIN private_payloads p ON p.delivery_id = o.delivery_id \
                 WHERE o.device_id = $4 \
                 ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                   sent_at = EXCLUDED.sent_at, expires_at = EXCLUDED.expires_at, \
                   platform = EXCLUDED.platform, provider_token = EXCLUDED.provider_token, \
                   updated_at = EXCLUDED.updated_at",
            )
            .bind(values.platform.as_str())
            .bind(provider_token)
            .bind(now)
            .bind(values.device_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
                .bind(values.device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            pending.max(0) as usize
        } else if !previous_channel_type.is_private() && next_channel_type.is_private() {
            let existing: i64 =
                sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE device_id = $1")
                    .bind(values.device_id.as_slice())
                    .fetch_one(&mut *tx)
                    .await?;
            let capacity = max_pending_per_device.saturating_sub(existing.max(0) as usize);
            let provider_pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = $1 AND expires_at > $2",
            )
            .bind(values.device_id.as_slice())
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            let provider_pending = provider_pending.max(0) as usize;
            if provider_pending > capacity {
                return Err(StoreError::RouteMigrationCapacityExceeded {
                    pending: provider_pending,
                    capacity,
                });
            }
            let capacity = capacity.min(i64::MAX as usize) as i64;
            let rows = sqlx::query(
                "SELECT delivery_id, sent_at FROM provider_pull_queue \
                 WHERE device_id = $1 AND expires_at > $2 \
                 ORDER BY created_at ASC, delivery_id ASC LIMIT $3 FOR UPDATE",
            )
            .bind(values.device_id.as_slice())
            .bind(now)
            .bind(capacity)
            .fetch_all(&mut *tx)
            .await?;
            let next_attempt_at = now.saturating_add(ack_timeout_secs.max(1) as i64 * 1000);
            for row in &rows {
                let delivery_id: String = row.get("delivery_id");
                let sent_at: i64 = row.get("sent_at");
                sqlx::query(
                    "INSERT INTO private_payloads \
                     (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
                     SELECT delivery_id, payload_blob, payload_size, sent_at, expires_at, $1, $1 \
                     FROM provider_pull_queue WHERE device_id = $2 AND delivery_id = $3 \
                     ON CONFLICT (delivery_id) DO NOTHING",
                )
                .bind(now)
                .bind(values.device_id.as_slice())
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO private_outbox \
                     (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
                     VALUES ($1, $2, 'pending', 0, $3, $4, $5, $4) \
                     ON CONFLICT (device_id, delivery_id) DO NOTHING",
                )
                .bind(values.device_id.as_slice())
                .bind(&delivery_id)
                .bind(sent_at)
                .bind(now)
                .bind(next_attempt_at)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
                )
                .bind(values.device_id.as_slice())
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?;
            }
            rows.len()
        } else {
            0
        };
        upsert_device_route_in_tx(&mut tx, route).await?;
        if let Some(provider_token) = values.provider_token.as_deref() {
            let (token_hash, _) = ProviderTokenSnapshot::from_token(provider_token).into_parts();
            sqlx::query(
                "INSERT INTO private_bindings \
                 (device_id, platform, provider_token, token_hash, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $5) \
                 ON CONFLICT (platform, token_hash) DO UPDATE SET \
                   device_id = EXCLUDED.device_id, provider_token = EXCLUDED.provider_token, \
                   updated_at = EXCLUDED.updated_at",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("DELETE FROM private_bindings WHERE device_id = $1")
                .bind(values.device_id.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        tx.commit().await?;
        Ok(migrated)
    }

    pub(super) async fn replace_device_identity(
        &self,
        route: &DeviceRouteRecordRow,
        old_device_key: Option<&str>,
    ) -> StoreResult<()> {
        let values = route.persistence_values()?;
        let old_key = old_device_key
            .and_then(|value| DeviceKeyRef::optional(Some(value)))
            .filter(|value| value.as_str() != values.device_key);
        let old_device_id = old_key.map(|key| PrivateDeviceId::derive(key.as_str()).to_vec());

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
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;

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
                .bind(old_key.as_str())
                .bind(device_id)
                .execute(&mut *tx)
                .await?;
            cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn revoke_device_identity(&self, device_key: &str) -> StoreResult<()> {
        let Some(normalized_key) = DeviceKeyRef::optional(Some(device_key)) else {
            return Ok(());
        };
        let device_id = PrivateDeviceId::derive(normalized_key.as_str()).to_vec();
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
            .bind(normalized_key.as_str())
            .bind(device_id.as_slice())
            .execute(&mut *tx)
            .await?;

        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;

        tx.commit().await?;
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
        let mut tx = self.pool.begin().await?;
        let delivery_rows = sqlx::query(
            "SELECT delivery_id FROM provider_pull_queue WHERE platform = $1 AND provider_token = $2",
        )
        .bind(platform_name)
        .bind(normalized_token.as_str())
        .fetch_all(&mut *tx)
        .await?;
        let delivery_ids: Vec<String> = delivery_rows
            .into_iter()
            .map(|row| row.get("delivery_id"))
            .collect();

        sqlx::query("DELETE FROM provider_pull_queue WHERE platform = $1 AND provider_token = $2")
            .bind(platform_name)
            .bind(normalized_token.as_str())
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
        .bind(normalized_token.as_str())
        .execute(&mut *tx)
        .await?;

        cleanup_orphan_private_payloads_in_tx(&mut tx, &delivery_ids).await?;

        tx.commit().await?;
        Ok(())
    }
}
