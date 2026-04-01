use super::*;

impl PostgresDb {
    pub(super) async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        let row = sqlx::query(
            "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE device_id = $1 AND delivery_id = $2",
        )
        .bind(&device_id[..])
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PrivateOutboxEntry {
            delivery_id: r.get("delivery_id"),
            status: r.get("status"),
            attempts: r.get::<i32, _>("attempts") as u32,
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
        let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = $1")
            .bind(&channel_id[..])
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| ChannelInfo {
            alias: r.get("alias"),
        }))
    }

    pub(super) async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_info.device_id();
        let token_raw = device_info.token_raw.to_vec();
        let platform_code = platform.to_byte() as i16;
        let platform_text = platform.name();
        let channel_type = platform.channel_type();
        let (token_hash, token_preview) = device_info.token_snapshot().into_parts();
        let now = Utc::now().timestamp();

        let mut tx = self.pool.begin().await?;

        let (channel_bytes, created, channel_alias) = if let Some(id) = channel_id {
            let id_vec = id.to_vec();
            let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = $1")
                .bind(&id_vec)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            (id_vec, false, row.get::<String, _>("alias"))
        } else {
            let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
            let new_id = crate::util::random_id_bytes_128().to_vec();
            sqlx::query("INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
                .bind(&new_id)
                .bind(password_hash)
                .bind(alias)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            (new_id, true, alias.to_string())
        };

        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code) VALUES ($1, $2, $3) \
             ON CONFLICT (device_id) DO UPDATE SET \
             token_raw = EXCLUDED.token_raw, \
             platform_code = EXCLUDED.platform_code",
        )
        .bind(&device_id[..])
        .bind(&token_raw)
        .bind(platform_code)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO channel_subscriptions \
             (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, 1, 'active', 'channel_subscribe', $8, $8) \
             ON CONFLICT (channel_id, device_id) DO UPDATE SET \
               platform = EXCLUDED.platform, \
               channel_type = EXCLUDED.channel_type, \
               provider_token = EXCLUDED.provider_token, \
               provider_token_hash = EXCLUDED.provider_token_hash, \
               provider_token_preview = EXCLUDED.provider_token_preview, \
               status = EXCLUDED.status, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind(&channel_bytes)
        .bind(&device_id[..])
        .bind(platform_text)
        .bind(channel_type)
        .bind(device_info.token_str.as_ref())
        .bind(&token_hash)
        .bind(&token_preview)
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

    pub(super) async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_info.device_id();
        let result = sqlx::query(
            "DELETE FROM channel_subscriptions WHERE channel_id = $1 AND device_id = $2",
        )
        .bind(&channel_id[..])
        .bind(&device_id[..])
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn retire_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_info.device_id();
        let mut tx = self.pool.begin().await?;
        let removed = sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = $1")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?
            .rows_affected() as usize;
        sqlx::query("DELETE FROM devices WHERE device_id = $1")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(removed)
    }

    pub(super) async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let old_device_info = DeviceInfo::from_token(platform, old_device_token)?;
        let old_device_id = old_device_info.device_id();
        let new_device_info = DeviceInfo::from_token(platform, new_device_token)?;
        let new_device_id = new_device_info.device_id();
        let new_token_raw = new_device_info.token_raw.to_vec();
        let new_platform_code = new_device_info.platform.to_byte() as i16;

        if old_device_id == new_device_id {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code) VALUES ($1, $2, $3) \
             ON CONFLICT (device_id) DO UPDATE SET \
                token_raw = EXCLUDED.token_raw, \
                platform_code = EXCLUDED.platform_code",
        )
        .bind(&new_device_id[..])
        .bind(&new_token_raw)
        .bind(new_platform_code)
        .execute(&mut *tx)
        .await?;

        let moved = sqlx::query(
            "INSERT INTO channel_subscriptions \
             (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, updated_at) \
             SELECT channel_id, $1, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, $2 \
             FROM channel_subscriptions WHERE device_id = $3 \
             ON CONFLICT (channel_id, device_id) DO UPDATE SET \
               platform = EXCLUDED.platform, \
               channel_type = EXCLUDED.channel_type, \
               device_key = EXCLUDED.device_key, \
               provider_token = EXCLUDED.provider_token, \
               provider_token_hash = EXCLUDED.provider_token_hash, \
               provider_token_preview = EXCLUDED.provider_token_preview, \
               route_version = EXCLUDED.route_version, \
               status = EXCLUDED.status, \
               subscribed_via = EXCLUDED.subscribed_via, \
               last_dispatch_at = EXCLUDED.last_dispatch_at, \
               last_acked_at = EXCLUDED.last_acked_at, \
               last_error_code = EXCLUDED.last_error_code, \
               last_confirmed_at = EXCLUDED.last_confirmed_at, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind(&new_device_id[..])
        .bind(Utc::now().timestamp())
        .bind(&old_device_id[..])
        .execute(&mut *tx)
        .await?
        .rows_affected() as usize;

        sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = $1")
            .bind(&old_device_id[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM devices WHERE device_id = $1")
            .bind(&old_device_id[..])
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(moved)
    }
}
