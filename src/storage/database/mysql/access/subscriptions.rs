use super::*;

impl MySqlDb {
    pub(super) async fn resolve_device_key_route_device(
        &self,
        device_key: &str,
    ) -> StoreResult<Option<Vec<u8>>> {
        let normalized_key = device_key.trim();
        if normalized_key.is_empty() {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT device_id \
             FROM devices \
             WHERE device_key = ? \
             LIMIT 1",
        )
        .bind(normalized_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|value| value.get("device_id")))
    }

    pub(super) async fn list_channel_devices(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<DeviceInfo>> {
        let rows = sqlx::query(
            "SELECT d.token_raw, d.platform_code \
             FROM channel_subscriptions s \
             JOIN devices d ON s.device_id = d.device_id \
             WHERE s.channel_id = ? AND s.status = 'active'",
        )
        .bind(&channel_id[..])
        .fetch_all(&self.pool)
        .await?;

        let mut devices = Vec::with_capacity(rows.len());
        for row in rows {
            let token_raw: Vec<u8> = row.get("token_raw");
            let platform_code: i16 = row.get("platform_code");
            let platform =
                Platform::from_byte(platform_code as u8).ok_or(StoreError::InvalidPlatform)?;
            devices.push(DeviceInfo::from_raw(platform, token_raw)?);
        }
        Ok(devices)
    }

    pub(super) async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        let rows = sqlx::query(
            "SELECT s.device_id, d.platform, d.channel_type, d.device_key AS route_device_key, d.provider_token AS route_provider_token, d.route_updated_at \
             FROM channel_subscriptions s \
             JOIN devices d ON d.device_id = s.device_id \
             WHERE s.channel_id = ? AND s.status = 'active' AND s.created_at <= ? \
             ORDER BY d.channel_type ASC, s.created_at ASC, s.device_id ASC",
        )
        .bind(&channel_id[..])
        .bind(effective_at)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let channel_type: String = row.get("channel_type");
            let route_provider_token: Option<String> = row.get("route_provider_token");
            let route_updated_at: Option<i64> = row.get("route_updated_at");
            if !route_matches_dispatch_target(
                channel_type.as_str(),
                route_updated_at,
                route_provider_token.as_deref(),
            ) {
                continue;
            }
            let raw_device_id: Vec<u8> = row.get("device_id");
            let device_key: Option<String> = row
                .get::<Option<String>, _>("route_device_key")
                .and_then(|value| {
                    let trimmed = value.trim().to_string();
                    (!trimmed.is_empty()).then_some(trimmed)
                });

            if channel_type.eq_ignore_ascii_case("private") {
                if raw_device_id.len() == 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&raw_device_id);
                    out.push(DispatchTarget::Private {
                        device_id: id,
                        device_key,
                    });
                }
                continue;
            }

            let platform_raw: String = row.get("platform");
            let platform: Platform = platform_raw.parse()?;
            if let Some(token) = route_provider_token {
                let token = token.trim().to_string();
                if !token.is_empty()
                    && let Some(device_key) = device_key
                {
                    out.push(DispatchTarget::Provider {
                        platform,
                        provider_token: token,
                        device_key,
                    });
                }
            }
        }
        Ok(out)
    }

    pub(super) async fn list_subscribed_channels_for_device_key(
        &self,
        device_key: &str,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let Some(device_id) = self.resolve_device_key_route_device(device_key).await? else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query(
            "SELECT channel_id FROM channel_subscriptions \
             WHERE device_id = ? AND status = 'active'",
        )
        .bind(device_id.as_slice())
        .fetch_all(&self.pool)
        .await?;
        let mut channels = Vec::with_capacity(rows.len());
        for row in rows {
            let channel_bytes: Vec<u8> = row.get("channel_id");
            if channel_bytes.len() == 16 {
                let mut channel_id = [0u8; 16];
                channel_id.copy_from_slice(&channel_bytes);
                channels.push(channel_id);
            }
        }
        Ok(channels)
    }

    pub(super) async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let rows = sqlx::query(
            "SELECT channel_id FROM channel_subscriptions \
             WHERE device_id = ? AND status = 'active'",
        )
        .bind(&device_id[..])
        .fetch_all(&self.pool)
        .await?;
        let mut channels = Vec::with_capacity(rows.len());
        for row in rows {
            let channel_bytes: Vec<u8> = row.get("channel_id");
            if channel_bytes.len() == 16 {
                let mut channel_id = [0u8; 16];
                channel_id.copy_from_slice(&channel_bytes);
                channels.push(channel_id);
            }
        }
        Ok(channels)
    }

    pub(super) async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<(ChannelInfo, String)>> {
        let row = sqlx::query("SELECT alias, password_hash FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| {
            (
                ChannelInfo {
                    alias: r.get("alias"),
                },
                r.get("password_hash"),
            )
        }))
    }

    pub(super) async fn rename_channel(
        &self,
        channel_id: [u8; 16],
        alias: &str,
    ) -> StoreResult<()> {
        sqlx::query("UPDATE channels SET alias = ?, updated_at = ? WHERE channel_id = ?")
            .bind(alias)
            .bind(Utc::now().timestamp_millis())
            .bind(&channel_id[..])
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(super) async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
    ) -> StoreResult<SubscribeOutcome> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now().timestamp_millis();
        let (actual_id, created, actual_alias) = if let Some(id) = channel_id {
            let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
                .bind(&id[..])
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            (id, false, row.get::<String, _>("alias"))
        } else {
            let id = crate::util::random_id_bytes_128();
            let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
            sqlx::query("INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
                .bind(&id[..])
                .bind(password_hash)
                .bind(alias)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            (id, true, alias.to_string())
        };
        tx.commit().await?;
        Ok(SubscribeOutcome {
            channel_id: actual_id,
            alias: actual_alias,
            created,
        })
    }

    pub(super) async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE status = 'active', updated_at = VALUES(updated_at)",
        )
        .bind(&channel_id[..])
        .bind(&device_id[..])
        .bind("active")
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?")
            .bind(&channel_id[..])
            .bind(&device_id[..])
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(super) async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        let rows = sqlx::query(
            "SELECT s.device_id FROM channel_subscriptions s \
             JOIN devices d ON d.device_id = s.device_id \
             WHERE s.channel_id = ? AND s.status = 'active' AND d.channel_type = 'private' AND d.route_updated_at IS NOT NULL AND s.created_at <= ? \
             ORDER BY s.created_at ASC",
        )
        .bind(&channel_id[..])
        .bind(subscribed_at_or_before)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.get("device_id");
            if bytes.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                out.push(id);
            }
        }
        Ok(out)
    }

    pub(super) async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        let (token_hash, _) = ProviderTokenSnapshot::from_token(token).into_parts();
        let platform_id = platform.to_byte() as i16;
        let row = sqlx::query(
            "SELECT device_id FROM private_bindings WHERE platform = ? AND token_hash = ?",
        )
        .bind(platform_id)
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let bytes: Vec<u8> = r.get("device_id");
            if bytes.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}

fn route_matches_dispatch_target(
    channel_type: &str,
    route_updated_at: Option<i64>,
    route_provider_token: Option<&str>,
) -> bool {
    if route_updated_at.is_none() {
        return channel_type.eq_ignore_ascii_case("private");
    }
    if channel_type.eq_ignore_ascii_case("private") {
        return true;
    }
    let Some(route_provider_token) = normalize_optional_token(route_provider_token) else {
        return false;
    };
    !route_provider_token.is_empty()
}

fn normalize_optional_token(value: Option<&str>) -> Option<&str> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
}
