use super::*;
use crate::value::{DeviceKeyRef, ProviderTokenRef};

fn route_transition_from_mysql_row(
    row: &sqlx::mysql::MySqlRow,
) -> StoreResult<RouteTransitionRecord> {
    Ok(RouteTransitionRecord {
        transition_id: decode_mysql_text(row, "transition_id")?,
        operation_id: decode_mysql_text(row, "operation_id")?,
        device_key: decode_mysql_text(row, "device_key")?,
        platform: row.get("platform"),
        state: row.get("state"),
        base_revision: row.get("expected_route_revision"),
        candidate_channel_type: row.get("candidate_channel_type"),
        candidate_provider_token: decode_mysql_optional_text(row, "candidate_provider_token")?,
        candidate_fingerprint: row.get("candidate_fingerprint"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
        committed_revision: row.get("committed_revision"),
        migrated_pending_count: row
            .get::<Option<i64>, _>("migrated_pending_count")
            .map(|value| value.max(0) as usize),
    })
}

pub(in crate::storage::database::mysql) async fn upsert_device_route_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    route: &DeviceRouteRecordRow,
) -> StoreResult<()> {
    let values = route.persistence_values()?;
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at, route_revision) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1) \
         ON DUPLICATE KEY UPDATE \
           token_raw = VALUES(token_raw), \
           platform_code = VALUES(platform_code), \
           device_key = VALUES(device_key), \
           platform = VALUES(platform), \
           channel_type = VALUES(channel_type), \
           provider_token = VALUES(provider_token), \
           route_updated_at = VALUES(route_updated_at), \
           route_revision = route_revision + 1",
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
    rows.into_iter()
        .map(|row| {
            Ok(DuplicateProviderRouteRow {
                device_id: row.get("device_id"),
                device_key: decode_mysql_optional_text(&row, "device_key")?,
            })
        })
        .collect()
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
    rows.into_iter()
        .map(|row| decode_mysql_text(&row, "delivery_id"))
        .collect()
}

async fn cleanup_orphan_private_payloads_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    delivery_ids: &[String],
) -> StoreResult<()> {
    for delivery_id in delivery_ids {
        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = ? \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id AND private_outbox.status <> 'acked') \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub(in crate::storage::database::mysql) async fn coalesce_duplicate_provider_routes_in_tx(
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
             SELECT source_subscriptions.channel_id, ?, source_subscriptions.status, \
                    source_subscriptions.created_at, source_subscriptions.updated_at \
             FROM (SELECT channel_id, status, created_at, updated_at \
                   FROM channel_subscriptions \
                   WHERE device_id = ? AND status = 'active') AS source_subscriptions \
             ON DUPLICATE KEY UPDATE \
               status = IF(channel_subscriptions.status = 'active' OR VALUES(status) = 'active', 'active', VALUES(status)), \
               created_at = LEAST(channel_subscriptions.created_at, VALUES(created_at)), \
               updated_at = GREATEST(channel_subscriptions.updated_at, VALUES(updated_at))",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate.device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT ?, source_pull.delivery_id, source_pull.payload_blob, source_pull.payload_size, \
                    source_pull.sent_at, source_pull.expires_at, source_pull.platform, \
                    source_pull.provider_token, source_pull.created_at, source_pull.updated_at \
             FROM (SELECT delivery_id, payload_blob, payload_size, sent_at, expires_at, \
                          platform, provider_token, created_at, updated_at \
                   FROM provider_pull_queue WHERE device_id = ?) AS source_pull \
             ON DUPLICATE KEY UPDATE \
               payload_blob = VALUES(payload_blob), \
               payload_size = VALUES(payload_size), \
               sent_at = LEAST(provider_pull_queue.sent_at, VALUES(sent_at)), \
               expires_at = GREATEST(provider_pull_queue.expires_at, VALUES(expires_at)), \
               platform = VALUES(platform), \
               provider_token = VALUES(provider_token), \
               created_at = LEAST(provider_pull_queue.created_at, VALUES(created_at)), \
               updated_at = GREATEST(provider_pull_queue.updated_at, VALUES(updated_at))",
        )
        .bind(route.device_id.as_slice())
        .bind(duplicate_private_device_id.as_slice())
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT ?, o.delivery_id, X'', 0, p.sent_at, p.expires_at, ?, ?, p.created_at, p.updated_at \
             FROM private_outbox o JOIN private_payloads p ON p.delivery_id = o.delivery_id \
             WHERE o.device_id = ? AND o.status IN ('pending','claimed','sent') \
             ON DUPLICATE KEY UPDATE \
               sent_at = LEAST(provider_pull_queue.sent_at, VALUES(sent_at)), \
               expires_at = GREATEST(provider_pull_queue.expires_at, VALUES(expires_at)), \
               platform = VALUES(platform), provider_token = VALUES(provider_token), \
               updated_at = GREATEST(provider_pull_queue.updated_at, VALUES(updated_at))",
        )
        .bind(route.device_id.as_slice())
        .bind(route.platform.as_str())
        .bind(route.provider_token.as_deref())
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
            "DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'",
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
    pub(super) async fn provider_route_is_current(
        &self,
        device_key: &str,
        platform: Platform,
        channel_type: RouteChannelType,
        provider_token: &str,
        _route_updated_at: i64,
    ) -> StoreResult<bool> {
        let canonical = ProviderTokenRef::canonicalize_for_platform(provider_token, platform)
            .map_err(|_| StoreError::InvalidDeviceToken)?;
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_key = ? AND platform = ? \
             AND channel_type = ? AND provider_token = ?)",
        )
        .bind(device_key)
        .bind(platform.name())
        .bind(channel_type.as_str())
        .bind(canonical)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists != 0)
    }

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
                device_key: decode_mysql_text(&r, "device_key")?,
                platform: r.get("platform"),
                channel_type: r.get("channel_type"),
                provider_token: decode_mysql_optional_text(&r, "provider_token")?,
                updated_at: r.get("route_updated_at"),
            });
        }
        Ok(out)
    }

    pub(super) async fn active_device_route_snapshot(
        &self,
        device_key: &str,
    ) -> StoreResult<Option<DeviceRouteSnapshot>> {
        let row = sqlx::query(
            "SELECT route_revision, channel_type, provider_token FROM devices \
             WHERE device_key = ? AND channel_type IS NOT NULL",
        )
        .bind(device_key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(DeviceRouteSnapshot {
                route_revision: row.get("route_revision"),
                channel_type: row.get("channel_type"),
                provider_token: decode_mysql_optional_text(&row, "provider_token")?,
            })
        })
        .transpose()
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
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   device_id = VALUES(device_id), provider_token = VALUES(provider_token), \
                   updated_at = VALUES(updated_at)",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
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
        let now = values.updated_at;
        upsert_device_route_in_tx(&mut tx, route).await?;
        if let Some(provider_token) = values.provider_token.as_deref() {
            let (token_hash, _) = ProviderTokenSnapshot::from_token(provider_token).into_parts();
            sqlx::query(
                "INSERT INTO private_bindings \
                 (device_id, platform, provider_token, token_hash, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   device_id = VALUES(device_id), provider_token = VALUES(provider_token), \
                   updated_at = VALUES(updated_at)",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
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
        self.transition_device_route_inner(route, ack_timeout_secs, max_pending_per_device, None)
            .await
            .map(|(migrated, _)| migrated)
    }

    async fn transition_device_route_inner(
        &self,
        route: &DeviceRouteRecordRow,
        ack_timeout_secs: u64,
        max_pending_per_device: usize,
        prepared_operation: Option<(&str, &str, i64, i64)>,
    ) -> StoreResult<(usize, i64)> {
        let values = route.persistence_values()?;
        let next_channel_type = route.channel_type_kind()?;
        let now = Utc::now().timestamp_millis();
        let mut tx = self.pool.begin().await?;
        if let Some((transition_id, operation_id, expected_revision, requested_now)) =
            prepared_operation
        {
            let row = sqlx::query(
                "SELECT state, expected_route_revision, expires_at, committed_revision, migrated_pending_count FROM route_transition_operations \
                 WHERE transition_id = ? AND operation_id = ? FOR UPDATE",
            )
            .bind(transition_id)
            .bind(operation_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::RouteTransitionNotFound)?;
            let state: String = row.get("state");
            if state == ROUTE_TRANSITION_STATE_COMMITTED {
                let revision = row
                    .get::<Option<i64>, _>("committed_revision")
                    .ok_or(StoreError::RouteTransitionOperationConflict)?;
                let migrated = row
                    .get::<Option<i64>, _>("migrated_pending_count")
                    .ok_or(StoreError::RouteTransitionOperationConflict)?;
                tx.commit().await?;
                return Ok((migrated.max(0) as usize, revision));
            }
            if state == ROUTE_TRANSITION_STATE_ABORTED {
                return Err(StoreError::RouteTransitionAborted);
            }
            if state != ROUTE_TRANSITION_STATE_PREPARED {
                return Err(StoreError::RouteTransitionOperationConflict);
            }
            if row.get::<i64, _>("expires_at") <= now.max(requested_now) {
                return Err(StoreError::RouteTransitionExpired);
            }
            if row.get::<i64, _>("expected_route_revision") != expected_revision {
                return Err(StoreError::RouteTransitionOperationConflict);
            }
        }
        let current_route = sqlx::query(
            "SELECT channel_type, route_updated_at, route_revision FROM devices WHERE device_key = ? FOR UPDATE",
        )
        .bind(values.device_key.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let actual_revision = current_route
            .as_ref()
            .map(|row| row.get::<i64, _>("route_revision"));
        if let Some((_, _, expected_revision, _)) = prepared_operation {
            let actual = actual_revision.ok_or(StoreError::DeviceNotFound)?;
            if actual != expected_revision {
                return Err(StoreError::RouteTransitionRevisionConflict {
                    expected: expected_revision,
                    actual,
                });
            }
        }
        if prepared_operation.is_none()
            && current_route.as_ref().is_some_and(|row| {
                row.get::<Option<i64>, _>("route_updated_at")
                    .is_some_and(|updated_at| updated_at >= values.updated_at)
            })
        {
            tx.commit().await?;
            return Ok((0, actual_revision.unwrap_or_default()));
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
                 WHERE o.device_id = ?",
            )
            .bind(values.device_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO provider_pull_queue \
                 (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
                 SELECT o.device_id, o.delivery_id, X'', 0, p.sent_at, p.expires_at, ?, ?, ?, ? \
                 FROM private_outbox o JOIN private_payloads p ON p.delivery_id = o.delivery_id \
                 WHERE o.device_id = ? AND o.status IN ('pending','claimed','sent') \
                 ON DUPLICATE KEY UPDATE \
                   sent_at = VALUES(sent_at), expires_at = VALUES(expires_at), \
                   platform = VALUES(platform), provider_token = VALUES(provider_token), \
                   updated_at = VALUES(updated_at)",
            )
            .bind(values.platform.as_str())
            .bind(provider_token)
            .bind(now)
            .bind(now)
            .bind(values.device_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'")
                .bind(values.device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            pending.max(0) as usize
        } else if !previous_channel_type.is_private() && next_channel_type.is_private() {
            let existing: i64 =
                sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE device_id = ?")
                    .bind(values.device_id.as_slice())
                    .fetch_one(&mut *tx)
                    .await?;
            let capacity = max_pending_per_device.saturating_sub(existing.max(0) as usize);
            let provider_pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND expires_at > ?",
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
                 WHERE device_id = ? AND expires_at > ? \
                 ORDER BY created_at ASC, delivery_id ASC LIMIT ? FOR UPDATE",
            )
            .bind(values.device_id.as_slice())
            .bind(now)
            .bind(capacity)
            .fetch_all(&mut *tx)
            .await?;
            let next_attempt_at = now.saturating_add(ack_timeout_secs.max(1) as i64 * 1000);
            for row in &rows {
                let delivery_id = decode_mysql_text(row, "delivery_id")?;
                let sent_at: i64 = row.get("sent_at");
                sqlx::query(
                    "INSERT INTO private_payloads \
                     (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
                     SELECT delivery_id, payload_blob, payload_size, sent_at, expires_at, ?, ? \
                     FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ? \
                     ON DUPLICATE KEY UPDATE delivery_id = VALUES(delivery_id)",
                )
                .bind(now)
                .bind(now)
                .bind(values.device_id.as_slice())
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO private_outbox \
                     (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
                     VALUES (?, ?, 'pending', 0, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE delivery_id = VALUES(delivery_id)",
                )
                .bind(values.device_id.as_slice())
                .bind(&delivery_id)
                .bind(sent_at)
                .bind(now)
                .bind(next_attempt_at)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "DELETE FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
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
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   device_id = VALUES(device_id), provider_token = VALUES(provider_token), \
                   updated_at = VALUES(updated_at)",
            )
            .bind(values.device_id.as_slice())
            .bind(values.platform_code)
            .bind(provider_token)
            .bind(token_hash.as_deref())
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
                .bind(values.device_id.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        coalesce_duplicate_provider_routes_in_tx(&mut tx, &values).await?;
        let route_revision: i64 =
            sqlx::query_scalar("SELECT route_revision FROM devices WHERE device_key = ?")
                .bind(values.device_key.as_str())
                .fetch_one(&mut *tx)
                .await?;
        if let Some((transition_id, operation_id, _, _)) = prepared_operation {
            let updated = sqlx::query(
                "UPDATE route_transition_operations SET state = ?, updated_at = ?, \
                 committed_revision = ?, migrated_pending_count = ? \
                 WHERE transition_id = ? AND operation_id = ? AND state = ?",
            )
            .bind(ROUTE_TRANSITION_STATE_COMMITTED)
            .bind(now)
            .bind(route_revision)
            .bind(i64::try_from(migrated).unwrap_or(i64::MAX))
            .bind(transition_id)
            .bind(operation_id)
            .bind(ROUTE_TRANSITION_STATE_PREPARED)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(StoreError::RouteTransitionOperationConflict);
            }
        }
        tx.commit().await?;
        Ok((migrated, route_revision))
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
                .map(|row| decode_mysql_text(&row, "delivery_id"))
                .collect::<StoreResult<Vec<_>>>()?
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
                "DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'",
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
        let delivery_ids = delivery_rows
            .into_iter()
            .map(|row| decode_mysql_text(&row, "delivery_id"))
            .collect::<StoreResult<Vec<_>>>()?;

        for statement in [
            "DELETE FROM channel_subscriptions WHERE device_id = ?",
            "DELETE FROM provider_pull_queue WHERE device_id = ?",
            "DELETE FROM private_bindings WHERE device_id = ?",
            "DELETE FROM private_outbox WHERE device_id = ? AND status <> 'acked'",
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

    pub(super) async fn current_device_route_revision(
        &self,
        device_key: &str,
    ) -> StoreResult<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT route_revision FROM devices WHERE device_key = ?")
                .bind(device_key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub(super) async fn prepare_route_transition(
        &self,
        record: &RouteTransitionPrepareRecord,
    ) -> StoreResult<RouteTransitionRecord> {
        if let Some(existing) = self
            .query_route_transition(
                None,
                Some(record.device_key.as_str()),
                Some(record.operation_id.as_str()),
            )
            .await?
        {
            if existing.base_revision == record.expected_route_revision
                && existing.candidate_fingerprint == record.candidate_fingerprint
            {
                return Ok(existing);
            }
            return Err(StoreError::RouteTransitionOperationConflict);
        }
        let actual_revision = self
            .current_device_route_revision(record.device_key.as_str())
            .await?
            .ok_or(StoreError::DeviceNotFound)?;
        if actual_revision != record.expected_route_revision {
            return Err(StoreError::RouteTransitionRevisionConflict {
                expected: record.expected_route_revision,
                actual: actual_revision,
            });
        }
        let inserted = sqlx::query(
            "INSERT INTO route_transition_operations \
             (transition_id, operation_id, device_key, platform, expected_route_revision, \
              candidate_channel_type, candidate_provider_token, candidate_fingerprint, state, \
              created_at, updated_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.transition_id.as_str())
        .bind(record.operation_id.as_str())
        .bind(record.device_key.as_str())
        .bind(record.platform.as_str())
        .bind(record.expected_route_revision)
        .bind(record.candidate_channel_type.as_str())
        .bind(record.candidate_provider_token.as_deref())
        .bind(record.candidate_fingerprint.as_str())
        .bind(ROUTE_TRANSITION_STATE_PREPARED)
        .bind(record.created_at)
        .bind(record.created_at)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await;
        if let Err(err) = inserted {
            if !matches!(&err, sqlx::Error::Database(db) if db.is_unique_violation()) {
                return Err(StoreError::Sqlx(err));
            }
            let winner = self
                .query_route_transition(
                    None,
                    Some(record.device_key.as_str()),
                    Some(record.operation_id.as_str()),
                )
                .await?
                .ok_or(StoreError::RouteTransitionOperationConflict)?;
            if winner.base_revision == record.expected_route_revision
                && winner.candidate_fingerprint == record.candidate_fingerprint
            {
                return Ok(winner);
            }
            return Err(StoreError::RouteTransitionOperationConflict);
        }
        self.query_route_transition(Some(record.transition_id.as_str()), None, None)
            .await?
            .ok_or(StoreError::RouteTransitionNotFound)
    }

    pub(super) async fn query_route_transition(
        &self,
        transition_id: Option<&str>,
        device_key: Option<&str>,
        operation_id: Option<&str>,
    ) -> StoreResult<Option<RouteTransitionRecord>> {
        let row = if let Some(transition_id) = transition_id {
            sqlx::query("SELECT * FROM route_transition_operations WHERE transition_id = ?")
                .bind(transition_id)
                .fetch_optional(&self.pool)
                .await?
        } else if let (Some(device_key), Some(operation_id)) = (device_key, operation_id) {
            sqlx::query(
                "SELECT * FROM route_transition_operations WHERE device_key = ? AND operation_id = ?",
            )
            .bind(device_key)
            .bind(operation_id)
            .fetch_optional(&self.pool)
            .await?
        } else {
            return Err(StoreError::RouteTransitionOperationConflict);
        };
        row.as_ref()
            .map(route_transition_from_mysql_row)
            .transpose()
    }

    pub(super) async fn abort_route_transition(
        &self,
        transition_id: &str,
        operation_id: &str,
        now: i64,
    ) -> StoreResult<RouteTransitionRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT * FROM route_transition_operations WHERE transition_id = ? FOR UPDATE",
        )
        .bind(transition_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::RouteTransitionNotFound)?;
        let current = route_transition_from_mysql_row(&row)?;
        if current.operation_id != operation_id || current.state == ROUTE_TRANSITION_STATE_COMMITTED
        {
            return Err(StoreError::RouteTransitionOperationConflict);
        }
        if current.state == ROUTE_TRANSITION_STATE_PREPARED {
            sqlx::query(
                "UPDATE route_transition_operations SET state = ?, updated_at = ? \
                 WHERE transition_id = ? AND operation_id = ? AND state = ?",
            )
            .bind(ROUTE_TRANSITION_STATE_ABORTED)
            .bind(now)
            .bind(transition_id)
            .bind(operation_id)
            .bind(ROUTE_TRANSITION_STATE_PREPARED)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.query_route_transition(Some(transition_id), None, None)
            .await?
            .ok_or(StoreError::RouteTransitionNotFound)
    }

    pub(super) async fn commit_route_transition(
        &self,
        transition_id: &str,
        operation_id: &str,
        now: i64,
        ack_timeout_secs: u64,
        max_pending_per_device: usize,
    ) -> StoreResult<RouteTransitionCommitResult> {
        let current = self
            .query_route_transition(Some(transition_id), None, None)
            .await?
            .ok_or(StoreError::RouteTransitionNotFound)?;
        if current.operation_id != operation_id {
            return Err(StoreError::RouteTransitionOperationConflict);
        }
        if current.state == ROUTE_TRANSITION_STATE_ABORTED {
            return Err(StoreError::RouteTransitionAborted);
        }
        if current.state == ROUTE_TRANSITION_STATE_COMMITTED {
            return Ok(RouteTransitionCommitResult {
                previous_revision: current.base_revision,
                route_revision: current
                    .committed_revision
                    .ok_or(StoreError::RouteTransitionOperationConflict)?,
                migrated_pending_count: current.migrated_pending_count.unwrap_or_default(),
                record: current,
            });
        }
        let route = DeviceRouteRecordRow {
            device_key: current.device_key.clone(),
            platform: current.platform.clone(),
            channel_type: current.candidate_channel_type.clone(),
            provider_token: current.candidate_provider_token.clone(),
            updated_at: now,
        };
        let (migrated_pending_count, route_revision) = self
            .transition_device_route_inner(
                &route,
                ack_timeout_secs,
                max_pending_per_device,
                Some((transition_id, operation_id, current.base_revision, now)),
            )
            .await?;
        let record = self
            .query_route_transition(Some(transition_id), None, None)
            .await?
            .ok_or(StoreError::RouteTransitionNotFound)?;
        Ok(RouteTransitionCommitResult {
            record,
            previous_revision: current.base_revision,
            route_revision,
            migrated_pending_count,
        })
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
        let delivery_ids = delivery_rows
            .into_iter()
            .map(|row| decode_mysql_text(&row, "delivery_id"))
            .collect::<StoreResult<Vec<_>>>()?;

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
             SET token_raw = CAST(device_key AS BINARY), channel_type = 'private', provider_token = NULL, \
                 route_updated_at = ?, route_revision = route_revision + 1 \
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
