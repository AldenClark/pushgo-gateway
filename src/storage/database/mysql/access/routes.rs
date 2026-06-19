use super::*;
use crate::value::{DeviceKeyRef, ProviderTokenRef};

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

#[derive(Debug)]
struct DuplicateProviderRouteRow {
    device_id: Vec<u8>,
    device_key: Option<String>,
}

fn resolve_private_device_id_for_duplicate(
    duplicate: &DuplicateProviderRouteRow,
) -> StoreResult<DeviceId> {
    if let Some(device_key) = duplicate.device_key.as_deref()
        && let Some(normalized) = DeviceKeyRef::optional(Some(device_key))
    {
        return Ok(PrivateDeviceId::derive(normalized.as_str()).into_inner());
    }
    PrivateDeviceId::parse_compat(duplicate.device_id.as_slice())
        .map(PrivateDeviceId::into_inner)
        .ok_or(StoreError::BinaryError)
}

async fn collect_duplicate_provider_routes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<Vec<DuplicateProviderRouteRow>> {
    let Some(provider_token) = route.provider_token.as_deref() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        "SELECT device_id, device_key \
         FROM devices \
         WHERE platform = ? AND provider_token = ? AND (device_key IS NULL OR device_key <> ?)",
    )
    .bind(route.platform.as_str())
    .bind(provider_token)
    .bind(route.device_key.as_str())
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
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    private_device_id: &[u8],
) -> StoreResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT delivery_id FROM private_outbox WHERE device_id = ? \
         UNION SELECT delivery_id FROM provider_pull_queue WHERE device_id = ?",
    )
    .bind(private_device_id)
    .bind(private_device_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(|row| row.get("delivery_id")).collect())
}

async fn cleanup_orphan_private_payloads_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
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
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    route: &DeviceRoutePersistenceValues,
) -> StoreResult<()> {
    let duplicates = collect_duplicate_provider_routes_in_tx(tx, route).await?;
    if duplicates.is_empty() {
        return Ok(());
    }

    for duplicate in duplicates {
        let duplicate_private_device_id = resolve_private_device_id_for_duplicate(&duplicate)?;
        let delivery_ids =
            load_device_delivery_ids_in_tx(tx, duplicate_private_device_id.as_slice()).await?;

        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             SELECT channel_id, ?, status, created_at, updated_at \
             FROM channel_subscriptions \
             WHERE device_id = ? AND status = 'active' \
             ON DUPLICATE KEY UPDATE \
               status = IF(status = 'active' OR VALUES(status) = 'active', 'active', VALUES(status)), \
               created_at = LEAST(created_at, VALUES(created_at)), \
               updated_at = GREATEST(updated_at, VALUES(updated_at))",
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
             ON DUPLICATE KEY UPDATE \
               payload_blob = VALUES(payload_blob), \
               payload_size = VALUES(payload_size), \
               sent_at = LEAST(sent_at, VALUES(sent_at)), \
               expires_at = GREATEST(expires_at, VALUES(expires_at)), \
               platform = VALUES(platform), \
               provider_token = VALUES(provider_token), \
               created_at = LEAST(created_at, VALUES(created_at)), \
               updated_at = GREATEST(updated_at, VALUES(updated_at))",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate_private_device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
            .bind(duplicate.device_id.as_slice())
            .execute(&mut **tx)
            .await?;
        for statement in [
            "DELETE FROM provider_pull_queue WHERE device_id = ?",
            "DELETE FROM private_bindings WHERE device_id = ?",
            "DELETE FROM private_outbox WHERE device_id = ?",
            "DELETE FROM private_sessions WHERE device_id = ?",
            "DELETE FROM private_device_keys WHERE device_id = ?",
        ] {
            sqlx::query(statement)
                .bind(duplicate_private_device_id.as_slice())
                .execute(&mut **tx)
                .await?;
        }

        sqlx::query("DELETE FROM devices WHERE device_id = ?")
            .bind(duplicate.device_id.as_slice())
            .execute(&mut **tx)
            .await?;

        cleanup_orphan_private_payloads_in_tx(tx, &delivery_ids).await?;
    }

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
        let values = route.persistence_values()?;
        upsert_device_route_in_tx(&mut tx, route).await?;
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
               WHEN route_updated_at IS NULL OR route_updated_at < ? THEN ? \
               ELSE route_updated_at \
             END \
             WHERE device_id = ?",
        )
        .bind(at_ts)
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
        upsert_device_route_in_tx(&mut tx, route).await?;
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        tx.commit().await?;
        Ok(())
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
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;

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
             SET token_raw = CAST(device_key AS BINARY), channel_type = 'private', provider_token = NULL, route_updated_at = ? \
             WHERE platform = ? AND provider_token = ? AND device_key IS NOT NULL",
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
