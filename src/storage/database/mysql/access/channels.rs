use super::*;

impl MySqlDb {
    pub(super) async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        let row = sqlx::query(
            "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PrivateOutboxEntry {
            delivery_id: r.get("delivery_id"),
            status: r.get("status"),
            attempts: r.get::<u32, _>("attempts"),
            occurred_at: r.get("occurred_at"),
            created_at: r.get("created_at"),
            claimed_at: r.get("claimed_at"),
            first_sent_at: r.get("first_sent_at"),
            last_attempt_at: r.get("last_attempt_at"),
            acked_at: r.get("acked_at"),
            fallback_sent_at: r.get("fallback_sent_at"),
            next_attempt_at: r.get("next_attempt_at"),
            last_error_code: r.get("last_error_code"),
            last_error_detail: r.get("last_error_detail"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub(super) async fn channel_info(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<ChannelInfo>> {
        let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| ChannelInfo {
            alias: r.get("alias"),
        }))
    }

    pub(super) async fn subscribe_channel_for_device_key(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_key: &str,
        _provider_token: &str,
        _platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let normalized_device_key = device_key.trim();
        if normalized_device_key.is_empty() {
            return Err(StoreError::DeviceNotFound);
        }
        let now = Utc::now().timestamp_millis();

        let mut tx = self.pool.begin().await?;

        let (channel_bytes, created, channel_alias) = if let Some(id) = channel_id {
            let id_vec = id.to_vec();
            let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
                .bind(&id_vec)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            (id_vec, false, row.get::<String, _>("alias"))
        } else {
            let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
            let new_id = crate::util::random_id_bytes_128().to_vec();
            sqlx::query("INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
                .bind(&new_id)
                .bind(password_hash)
                .bind(alias)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            (new_id, true, alias.to_string())
        };

        let device_id = sqlx::query(
            "SELECT device_id \
             FROM devices \
             WHERE device_key = ? \
             LIMIT 1",
        )
        .bind(normalized_device_key)
        .fetch_optional(&mut *tx)
        .await?
        .map(|row| row.get::<Vec<u8>, _>("device_id"))
        .ok_or(StoreError::DeviceNotFound)?;

        sqlx::query(
            "INSERT INTO channel_subscriptions \
             (channel_id, device_id, status, created_at, updated_at) \
             VALUES (?, ?, 'active', ?, ?) \
             ON DUPLICATE KEY UPDATE \
               status = VALUES(status), \
               updated_at = VALUES(updated_at)",
        )
        .bind(&channel_bytes)
        .bind(device_id.as_slice())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let mut actual_id = [0u8; 16];
        actual_id.copy_from_slice(&channel_bytes);
        Ok(SubscribeOutcome {
            channel_id: actual_id,
            alias: channel_alias,
            created,
        })
    }

    pub(super) async fn unsubscribe_channel_for_device_key(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
    ) -> StoreResult<bool> {
        let Some(device_id) = self.resolve_device_key_route_device(device_key).await? else {
            return Ok(false);
        };
        let result =
            sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?")
                .bind(&channel_id[..])
                .bind(device_id.as_slice())
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}
