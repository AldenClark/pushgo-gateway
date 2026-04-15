use super::*;

impl SqliteDb {
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
            let platform_code: i64 = row.get("platform_code");
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
            "SELECT s.device_id, s.platform, s.channel_type, s.device_key AS subscription_device_key, d.device_key AS route_device_key, s.provider_token, \
                    d.channel_type AS route_channel_type, d.provider_token AS route_provider_token, d.route_updated_at \
             FROM channel_subscriptions s \
             JOIN devices d ON d.device_id = s.device_id \
             WHERE s.channel_id = ? AND s.status = 'active' AND s.created_at <= ? \
             ORDER BY s.channel_type ASC, s.created_at ASC, s.device_id ASC",
        )
        .bind(&channel_id[..])
        .bind(effective_at)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let channel_type: String = row.get("channel_type");
            let route_channel_type: Option<String> = row.get("route_channel_type");
            let route_provider_token: Option<String> = row.get("route_provider_token");
            let route_updated_at: Option<i64> = row.get("route_updated_at");
            let provider_token: Option<String> = row.get("provider_token");
            if !Self::route_matches_dispatch_target(
                channel_type.as_str(),
                provider_token.as_deref(),
                route_updated_at,
                route_channel_type.as_deref(),
                route_provider_token.as_deref(),
            ) {
                continue;
            }
            let raw_device_id: Vec<u8> = row.get("device_id");
            let device_key: Option<String> = row
                .get::<Option<String>, _>("subscription_device_key")
                .and_then(|value| {
                    let trimmed = value.trim().to_string();
                    (!trimmed.is_empty()).then_some(trimmed)
                })
                .or_else(|| {
                    row.get::<Option<String>, _>("route_device_key")
                        .and_then(|value| {
                            let trimmed = value.trim().to_string();
                            (!trimmed.is_empty()).then_some(trimmed)
                        })
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
            if let Some(token) = provider_token {
                let token = token.trim().to_string();
                if !token.is_empty() && device_key.is_some() {
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

    fn route_matches_dispatch_target(
        channel_type: &str,
        subscription_provider_token: Option<&str>,
        route_updated_at: Option<i64>,
        route_channel_type: Option<&str>,
        route_provider_token: Option<&str>,
    ) -> bool {
        if route_updated_at.is_none() {
            return channel_type.eq_ignore_ascii_case("private");
        }
        let Some(route_channel_type) = Self::normalize_optional_token(route_channel_type) else {
            return false;
        };
        if !route_channel_type.eq_ignore_ascii_case(channel_type) {
            return false;
        }
        if channel_type.eq_ignore_ascii_case("private") {
            return true;
        }
        let Some(route_provider_token) = Self::normalize_optional_token(route_provider_token)
        else {
            return false;
        };
        let Some(subscription_provider_token) =
            Self::normalize_optional_token(subscription_provider_token)
        else {
            return false;
        };
        route_provider_token == subscription_provider_token
    }

    fn normalize_optional_token(value: Option<&str>) -> Option<&str> {
        value
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
    }

    pub(super) async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_info.device_id();
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

    pub(super) async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let rows = sqlx::query(
            "SELECT channel_id FROM channel_subscriptions \
             WHERE device_id = ? AND channel_type = 'private'",
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
            .bind(Utc::now().timestamp())
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let now = Utc::now().timestamp();
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
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, platform, channel_type, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (channel_id, device_id) DO UPDATE SET status = 'active', updated_at = EXCLUDED.updated_at",
        )
        .bind(&channel_id[..])
        .bind(&device_id[..])
        .bind("private")
        .bind("private")
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
        sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ? AND channel_type = 'private'")
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
            "SELECT device_id FROM channel_subscriptions \
             WHERE channel_id = ? AND channel_type = 'private' AND created_at <= ? \
             ORDER BY created_at ASC",
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
        let platform_id = platform.to_byte() as i64;
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
