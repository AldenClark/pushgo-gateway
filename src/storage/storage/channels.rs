use super::*;
use crate::storage::database::{
    ChannelQueryDatabaseAccess, PrivateChannelDatabaseAccess, ProviderSubscriptionDatabaseAccess,
};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

const DISPATCH_TARGETS_CACHE_EFFECTIVE_AT_SKEW_MS: i64 = 5;
#[cfg(not(test))]
const PASSWORD_KDF_CONCURRENCY: usize = 4;
#[cfg(test)]
const PASSWORD_KDF_CONCURRENCY: usize = 64;
static PASSWORD_KDF_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(PASSWORD_KDF_CONCURRENCY)));

async fn hash_channel_password_async(password: &str) -> StoreResult<String> {
    let permit = Arc::clone(&PASSWORD_KDF_PERMITS)
        .try_acquire_owned()
        .map_err(|_| StoreError::PasswordKdfBusy)?;
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_channel_password(&password)
    })
    .await
    .map_err(|err| StoreError::PasswordHash(format!("password hashing task failed: {err}")))?
}

async fn verify_channel_password_async(
    password_hash: &str,
    password: &str,
) -> StoreResult<ChannelPasswordVerifyOutcome> {
    let permit = Arc::clone(&PASSWORD_KDF_PERMITS)
        .try_acquire_owned()
        .map_err(|_| StoreError::PasswordKdfBusy)?;
    let password_hash = password_hash.to_string();
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_channel_password(&password_hash, &password)
    })
    .await
    .map_err(|err| StoreError::PasswordHash(format!("password verification task failed: {err}")))?
}

impl Storage {
    pub async fn subscribe_channel_for_device_key(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_key: &str,
        provider_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, provider_token)?;
        let device_id = device_info.device_id();

        let password_hash = if let Some(id) = channel_id {
            let info = self
                .load_channel_info_for_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            self.verify_channel_password_and_maybe_upgrade(
                id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?
        } else {
            hash_channel_password_async(password).await?
        };

        let outcome = self
            .db
            .subscribe_channel_for_device_key(
                channel_id,
                alias,
                &password_hash,
                device_key,
                provider_token,
                platform,
            )
            .await?;

        self.cache.put_device(device_id, &device_info);
        self.cache.invalidate_channel_devices(outcome.channel_id);
        self.cache.put_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
                password_hash,
            },
        );

        Ok(outcome)
    }

    pub async fn unsubscribe_channel_for_device_key(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
    ) -> StoreResult<bool> {
        let removed = self
            .db
            .unsubscribe_channel_for_device_key(channel_id, device_key)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(removed)
    }

    pub async fn unsubscribe_channel_if_provider_route_current(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
        platform: Platform,
        provider_token: &str,
        route_updated_at: i64,
    ) -> StoreResult<bool> {
        let removed = self
            .db
            .unsubscribe_channel_if_provider_route_current(
                channel_id,
                device_key,
                platform,
                provider_token,
                route_updated_at,
            )
            .await?;
        if removed {
            self.cache.invalidate_channel_devices(channel_id);
        }
        Ok(removed)
    }

    pub async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            return Ok(Some(info));
        }
        let info = self.db.channel_info(channel_id).await?;
        if let Some(ref info_ref) = info {
            self.cache.put_channel_info(channel_id, info_ref);
        }
        Ok(info)
    }

    pub async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        if let Some(devices) = self.cache.get_channel_devices(channel_id) {
            return Ok(devices);
        }
        let devices = self.db.list_channel_devices(channel_id).await?;
        self.cache.put_channel_devices(channel_id, &devices);
        Ok(devices)
    }

    pub async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        let now = chrono::Utc::now().timestamp_millis();
        let use_cache = (effective_at - now).abs() <= DISPATCH_TARGETS_CACHE_EFFECTIVE_AT_SKEW_MS;

        if use_cache && let Some(entry) = self.cache.get_channel_dispatch_targets(channel_id) {
            let age_ms = chrono::Utc::now().timestamp_millis() - entry.cached_at_ms;
            if age_ms >= 0 && age_ms <= self.cache.dispatch_targets_cache_ttl_ms() {
                return Ok(entry.targets);
            }
        }

        let targets = self
            .db
            .list_channel_dispatch_targets(channel_id, effective_at)
            .await?;

        if use_cache {
            self.cache
                .put_channel_dispatch_targets(channel_id, &targets);
        }

        Ok(targets)
    }

    pub async fn list_subscribed_channels_for_device_key(
        &self,
        device_key: &str,
    ) -> StoreResult<Vec<[u8; 16]>> {
        self.db
            .list_subscribed_channels_for_device_key(device_key)
            .await
    }

    pub async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        self.db
            .list_private_subscribed_channels_for_device(device_id)
            .await
    }

    pub async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            self.verify_channel_password_and_maybe_upgrade(
                channel_id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?;
            return Ok(Some(info));
        }
        let Some(info) = self.load_channel_info_for_password(channel_id).await? else {
            return Ok(None);
        };
        let password_hash = self
            .verify_channel_password_and_maybe_upgrade(
                channel_id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?;
        let info = ChannelInfo {
            alias: info.alias,
            password_hash,
        };
        self.cache.put_channel_info(channel_id, &info);
        Ok(Some(info))
    }

    pub async fn rename_channel(
        &self,
        channel_id: [u8; 16],
        password: &str,
        alias: &str,
    ) -> StoreResult<()> {
        let loaded = self
            .load_channel_info_for_password(channel_id)
            .await?
            .ok_or(StoreError::ChannelNotFound)?;
        let password_hash = self
            .verify_channel_password_and_maybe_upgrade(
                channel_id,
                &loaded.password_hash,
                password,
                Some(&loaded.alias),
            )
            .await?;
        self.db.rename_channel(channel_id, alias).await?;
        self.cache.put_channel_info(
            channel_id,
            &ChannelInfo {
                alias: alias.to_string(),
                password_hash,
            },
        );
        Ok(())
    }

    pub async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
    ) -> StoreResult<SubscribeOutcome> {
        let password_hash = if let Some(id) = channel_id {
            let info = self
                .load_channel_info_for_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            self.verify_channel_password_and_maybe_upgrade(
                id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?
        } else {
            hash_channel_password_async(password).await?
        };
        let outcome = self
            .db
            .upsert_private_channel(channel_id, alias, &password_hash)
            .await?;
        self.cache.invalidate_channel_devices(outcome.channel_id);
        self.cache.put_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
                password_hash,
            },
        );
        Ok(outcome)
    }

    pub async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        self.db
            .private_subscribe_channel(channel_id, device_id)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(())
    }

    pub async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        self.db
            .private_unsubscribe_channel(channel_id, device_id)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(())
    }

    pub async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        self.db
            .list_private_subscribers(channel_id, subscribed_at_or_before)
            .await
    }

    async fn verify_channel_password_and_maybe_upgrade(
        &self,
        channel_id: [u8; 16],
        password_hash: &str,
        password: &str,
        alias: Option<&str>,
    ) -> StoreResult<String> {
        let verify_outcome = verify_channel_password_async(password_hash, password).await?;
        if verify_outcome.needs_upgrade() {
            let upgraded_hash = hash_channel_password_async(password).await?;
            self.db
                .update_channel_password_hash(channel_id, upgraded_hash.as_str())
                .await?;
            if let Some(alias) = alias {
                self.cache.put_channel_info(
                    channel_id,
                    &ChannelInfo {
                        alias: alias.to_string(),
                        password_hash: upgraded_hash.clone(),
                    },
                );
            } else {
                self.cache.invalidate_channel_info(channel_id);
            }
            return Ok(upgraded_hash);
        }
        Ok(password_hash.to_string())
    }

    async fn load_channel_info_for_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            return Ok(Some(info));
        }
        let loaded = self.db.channel_info_with_password(channel_id).await?;
        let Some((info, hash)) = loaded else {
            return Ok(None);
        };
        let info = ChannelInfo {
            alias: info.alias,
            password_hash: hash,
        };
        self.cache.put_channel_info(channel_id, &info);
        Ok(Some(info))
    }
}
