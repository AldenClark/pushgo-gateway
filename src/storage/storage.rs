use crate::storage::{
    cache::{CacheAccess, CacheStore},
    database::{DatabaseAccess, DatabaseDriver},
    types::*,
};
use std::sync::Arc;

const OP_DEDUPE_PENDING_STALE_SECS: i64 = 2 * 60;

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<DatabaseDriver>,
    cache: Arc<CacheStore>,
}

impl Storage {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        let db_url = db_url.and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Ok(Self {
            db: Arc::new(DatabaseDriver::new(db_url).await?),
            cache: Arc::new(CacheStore::new()),
        })
    }

    pub async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);

        let password_hash = if let Some(id) = channel_id {
            let (_, hash) = self
                .db
                .channel_info_with_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            verify_channel_password(&hash, password)?;
            hash
        } else {
            hash_channel_password(password)?
        };

        let outcome = self
            .db
            .subscribe_channel(channel_id, alias, &password_hash, device_token, platform)
            .await?;

        self.cache.put_device(device_id, &device_info);
        self.cache.invalidate_channel_devices(outcome.channel_id);
        self.cache.put_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
            },
        );

        Ok(outcome)
    }

    pub async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let removed = self
            .db
            .unsubscribe_channel(channel_id, device_token, platform)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(removed)
    }

    pub async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_private_expired_data(before_ts, limit).await
    }

    pub async fn cleanup_pending_op_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_pending_op_dedupe(before_ts, limit).await
    }

    pub async fn cleanup_semantic_id_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_semantic_id_dedupe(before_ts, limit).await
    }

    pub async fn cleanup_delivery_dedupe(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        self.db.cleanup_delivery_dedupe(before_ts, limit).await
    }

    pub async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            return Ok(Some(info));
        }
        let info = self.db.channel_info(channel_id).await?;
        if let Some(ref i) = info {
            self.cache.put_channel_info(channel_id, i);
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
        let now = chrono::Utc::now().timestamp();
        let use_cache = (effective_at - now).abs() <= 5;

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

    pub async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        self.db
            .load_private_outbox_entry(device_id, delivery_id)
            .await
    }

    pub async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        self.db.insert_private_message(delivery_id, message).await
    }

    pub async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        self.db.enqueue_private_outbox(device_id, entry).await
    }

    pub async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        self.db.list_private_outbox(device_id, limit).await
    }

    pub async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize> {
        self.db.count_private_outbox_for_device(device_id).await
    }

    pub async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db.ack_private_delivery(device_id, delivery_id).await
    }

    pub async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        self.db.apply_stats_batch(batch).await
    }

    pub async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        self.db.automation_counts().await
    }

    pub async fn automation_reset(&self) -> StoreResult<()> {
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        self.db.automation_reset().await
    }

    pub async fn retire_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let count = self.db.retire_device(device_token, platform).await?;
        self.cache.remove_device(&device_id);
        self.cache.invalidate_all_channel_devices();
        Ok(count)
    }

    pub async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let old_device_info = DeviceInfo::from_token(platform, old_device_token)?;
        let old_device_id = device_id_for(platform, &old_device_info.token_raw);
        let count = self
            .db
            .migrate_device_subscriptions(old_device_token, new_device_token, platform)
            .await?;
        self.cache.remove_device(&old_device_id);
        self.cache.invalidate_all_channel_devices();
        Ok(count)
    }

    pub async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        self.db.delete_private_device_state(device_id).await?;
        // Private-state deletion affects subscription fanout; invalidate related channel caches.
        self.cache.invalidate_all_channel_devices();
        Ok(())
    }

    pub async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        self.db.bind_private_token(device_id, platform, token).await
    }

    pub async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        self.db.load_device_routes().await
    }

    pub async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        let device_id = route_device_id_from_record(route)?;
        self.db.upsert_device_route(route).await?;
        self.db
            .apply_route_snapshot(
                &device_id,
                &route.device_key,
                &route.platform,
                &route.channel_type,
                route.provider_token.as_deref(),
            )
            .await?;
        Ok(())
    }

    pub async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
        let normalized = DeliveryAuditWrite {
            delivery_id: entry.delivery_id.clone(),
            channel_id: entry.channel_id,
            device_key: entry.device_key.clone(),
            entity_type: entry.entity_type.clone(),
            entity_id: entry.entity_id.clone(),
            op_id: entry.op_id.clone(),
            path: normalize_delivery_audit_path(&entry.path).to_string(),
            status: normalize_delivery_audit_status(&entry.status).to_string(),
            error_code: normalize_delivery_audit_error_code(entry.error_code.as_deref()),
            created_at: entry.created_at,
        };
        self.db.append_delivery_audit(&normalized).await
    }

    pub async fn append_subscription_audit(
        &self,
        entry: &SubscriptionAuditWrite,
    ) -> StoreResult<()> {
        self.db.append_subscription_audit(entry).await
    }

    pub async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>> {
        self.db.load_private_message(delivery_id).await
    }

    pub async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        if let Some(msg) = self.db.load_private_message(delivery_id).await? {
            return Ok(decode_private_payload_context(&msg.payload));
        }
        Ok(None)
    }

    pub async fn enqueue_provider_pull_item(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        self.db
            .enqueue_provider_pull_item(
                delivery_id,
                message,
                platform,
                provider_token,
                next_retry_at,
            )
            .await
    }

    pub async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        self.db.pull_provider_item(delivery_id, now).await
    }

    pub async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        self.db.list_provider_pull_retry_due(now, limit).await
    }

    pub async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        self.db
            .bump_provider_pull_retry(delivery_id, next_retry_at, now)
            .await
    }

    pub async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        self.db.clear_provider_pull_retry(delivery_id).await
    }

    pub async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        self.db
            .mark_private_fallback_sent(device_id, delivery_id, at_ts)
            .await
    }

    pub async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        self.db
            .defer_private_fallback(device_id, delivery_id, at_ts)
            .await
    }

    pub async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        self.db.clear_private_outbox_for_device(device_id).await
    }

    pub async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        self.db.list_private_outbox_due(before_ts, limit).await
    }

    pub async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        self.db
            .claim_private_outbox_due(before_ts, limit, claim_until_ts)
            .await
    }

    pub async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        self.db
            .claim_private_outbox_due_for_device(device_id, before_ts, limit, claim_until_ts)
            .await
    }

    pub async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        self.db.count_private_outbox_total().await
    }

    pub async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        self.db
            .reserve_delivery_dedupe(dedupe_key, delivery_id, created_at)
            .await
    }

    pub async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        self.db
            .reserve_semantic_id(dedupe_key, semantic_id, created_at)
            .await
    }

    pub async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db
            .confirm_delivery_dedupe(dedupe_key, delivery_id)
            .await
    }
}

impl Storage {
    pub async fn run_maintenance_cleanup(
        &self,
        now: i64,
        dedupe_before: i64,
    ) -> StoreResult<MaintenanceCleanupStats> {
        let _ = self.db.cleanup_private_sessions(now).await?;
        let private_outbox_pruned = self.cleanup_private_expired_data(now, 2048).await?;
        let _ = self
            .cleanup_pending_op_dedupe(now - OP_DEDUPE_PENDING_STALE_SECS, 2048)
            .await?;
        let _ = self.cleanup_semantic_id_dedupe(dedupe_before, 2048).await?;
        let _ = self.cleanup_delivery_dedupe(dedupe_before, 2048).await?;
        Ok(MaintenanceCleanupStats {
            private_outbox_pruned,
        })
    }

    pub async fn append_delivery_audit_batch(
        &self,
        entries: &[DeliveryAuditWrite],
    ) -> StoreResult<()> {
        self.db.append_delivery_audit_batch(entries).await
    }

    pub async fn append_device_route_audit(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        self.db.append_device_route_audit(entry).await
    }

    pub async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        self.db
            .list_subscribed_channels_for_device(device_token, platform)
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
        let loaded = self.db.channel_info_with_password(channel_id).await?;
        let Some((info, hash)) = loaded else {
            return Ok(None);
        };
        verify_channel_password(&hash, password)?;
        Ok(Some(info))
    }

    pub async fn rename_channel(
        &self,
        channel_id: [u8; 16],
        password: &str,
        alias: &str,
    ) -> StoreResult<()> {
        let loaded = self
            .db
            .channel_info_with_password(channel_id)
            .await?
            .ok_or(StoreError::ChannelNotFound)?;
        verify_channel_password(&loaded.1, password)?;
        self.db.rename_channel(channel_id, alias).await?;
        self.cache.put_channel_info(
            channel_id,
            &ChannelInfo {
                alias: alias.to_string(),
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
            let (_, hash) = self
                .db
                .channel_info_with_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            verify_channel_password(&hash, password)?;
            hash
        } else {
            hash_channel_password(password)?
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

    pub async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        self.db.lookup_private_device(platform, token).await
    }

    pub async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        self.db
            .reserve_op_dedupe_pending(dedupe_key, delivery_id, created_at)
            .await
    }

    pub async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        self.db.mark_op_dedupe_sent(dedupe_key, delivery_id).await
    }

    pub async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        self.db
            .clear_op_dedupe_pending(dedupe_key, delivery_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use sqlx::{Connection, SqliteConnection};
    use tempfile::{TempDir, tempdir};
    use tokio::time::{Duration, sleep};

    struct SqliteTestContext {
        _dir: TempDir,
        db_url: String,
        storage: Storage,
    }

    #[derive(Serialize)]
    struct TestPrivatePayloadEnvelope<'a> {
        payload_version: u8,
        data: hashbrown::HashMap<&'a str, &'a str>,
    }

    async fn setup_sqlite_storage(name: &str) -> SqliteTestContext {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join(format!("{name}.sqlite"));
        std::fs::File::create(&db_path).expect("sqlite db file should be created");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

        bootstrap_sqlite_schema(&db_url)
            .await
            .expect("sqlite schema bootstrap should succeed");

        let storage = Storage::new(Some(db_url.as_str()))
            .await
            .expect("sqlite storage should initialize");

        SqliteTestContext {
            _dir: dir,
            db_url,
            storage,
        }
    }

    async fn setup_sqlite_storage_without_bootstrap(name: &str) -> SqliteTestContext {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join(format!("{name}.sqlite"));
        std::fs::File::create(&db_path).expect("sqlite db file should be created");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let storage = Storage::new(Some(db_url.as_str()))
            .await
            .expect("sqlite storage should initialize with auto schema bootstrap");
        SqliteTestContext {
            _dir: dir,
            db_url,
            storage,
        }
    }

    async fn setup_sqlite_storage_with_custom_schema(
        name: &str,
        statements: &[&str],
    ) -> SqliteTestContext {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join(format!("{name}.sqlite"));
        std::fs::File::create(&db_path).expect("sqlite db file should be created");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

        let mut conn = SqliteConnection::connect(&db_url)
            .await
            .expect("sqlite bootstrap connection should succeed");
        for stmt in statements {
            sqlx::query(stmt)
                .execute(&mut conn)
                .await
                .expect("custom schema statement should succeed");
        }
        drop(conn);

        let storage = Storage::new(Some(db_url.as_str()))
            .await
            .expect("sqlite storage should initialize with custom schema");

        SqliteTestContext {
            _dir: dir,
            db_url,
            storage,
        }
    }

    async fn bootstrap_sqlite_schema(db_url: &str) -> StoreResult<()> {
        let mut conn = SqliteConnection::connect(db_url).await?;

        let statements = [
            "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, token_raw BLOB NOT NULL, platform_code INTEGER NOT NULL, device_key TEXT, platform TEXT, channel_type TEXT, provider_token TEXT, route_updated_at INTEGER)",
            "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx ON devices (device_key)",
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, device_key TEXT, provider_token TEXT, provider_token_hash BLOB, provider_token_preview TEXT, route_version INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active', subscribed_via TEXT, last_dispatch_at INTEGER, last_acked_at INTEGER, last_error_code TEXT, last_confirmed_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx ON channel_subscriptions (device_id)",
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_channel_type_idx ON channel_subscriptions (channel_id, channel_type)",
            "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL, created_at INTEGER NOT NULL, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
            "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx ON private_outbox (delivery_id)",
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (delivery_id TEXT PRIMARY KEY, status TEXT NOT NULL, pulled_at INTEGER, acked_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS provider_pull_retry (delivery_id TEXT PRIMARY KEY, platform TEXT NOT NULL, provider_token TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_retry_at INTEGER NOT NULL, last_attempt_at INTEGER, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS provider_pull_retry_next_idx ON provider_pull_retry (next_retry_at)",
        ];

        for stmt in statements {
            sqlx::query(stmt).execute(&mut conn).await?;
        }
        Ok(())
    }

    #[test]
    fn decode_private_payload_context_extracts_structured_fields() {
        let mut data = hashbrown::HashMap::new();
        data.insert("channel_id", "06J0FZG1Y8XGG14VTQ4Y3G10MR");
        data.insert("entity_type", "event");
        data.insert("entity_id", "evt-1");
        data.insert("op_id", "op-1");
        let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
            payload_version: 1,
            data,
        })
        .expect("payload encode should succeed");

        let context =
            decode_private_payload_context(&payload).expect("context decode should succeed");
        assert!(context.channel_id.is_some());
        assert_eq!(context.entity_type.as_deref(), Some("event"));
        assert_eq!(context.entity_id.as_deref(), Some("evt-1"));
        assert_eq!(context.op_id.as_deref(), Some("op-1"));
    }

    #[test]
    fn decode_private_payload_context_rejects_unknown_payload_version() {
        let mut data = hashbrown::HashMap::new();
        data.insert("channel_id", "06J0FZG1Y8XGG14VTQ4Y3G10MR");
        let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
            payload_version: 9,
            data,
        })
        .expect("payload encode should succeed");
        assert!(decode_private_payload_context(&payload).is_none());
    }

    #[test]
    fn normalize_delivery_audit_path_and_status_defaults() {
        assert_eq!(normalize_delivery_audit_path("provider"), "provider");
        assert_eq!(normalize_delivery_audit_path("DIRECT"), "direct");
        assert_eq!(normalize_delivery_audit_path("invalid-path"), "provider");

        assert_eq!(normalize_delivery_audit_status("enqueued"), "enqueued");
        assert_eq!(
            normalize_delivery_audit_status("SKIPPED_PRIVATE_REALTIME"),
            "skipped_private_realtime"
        );
        assert_eq!(
            normalize_delivery_audit_status("unknown-status"),
            "enqueue_failed"
        );
    }

    #[test]
    fn normalize_delivery_audit_error_code_truncates_and_trims() {
        assert_eq!(normalize_delivery_audit_error_code(Some("  ")), None);
        assert_eq!(
            normalize_delivery_audit_error_code(Some(" queue_full ")).as_deref(),
            Some("queue_full")
        );
        let long = "x".repeat(128);
        let normalized = normalize_delivery_audit_error_code(Some(long.as_str()))
            .expect("normalized error code should be present");
        assert_eq!(normalized.len(), 64);
    }

    #[test]
    fn route_snapshot_fields_trims_empty_provider_token() {
        let (hash, preview) = route_snapshot_fields(Some("   "));
        assert!(hash.is_none());
        assert!(preview.is_none());

        let (hash2, preview2) = route_snapshot_fields(Some("abcdef123456"));
        assert!(hash2.is_some());
        assert_eq!(preview2.as_deref(), Some("abcdef***3456"));
    }

    #[tokio::test]
    async fn dispatch_targets_cache_hits_within_ttl_and_expires() {
        let ctx = setup_sqlite_storage("dispatch-targets-cache").await;
        let token = "android-token-cache-hit-0000000000000000000000000001";
        let subscribe = ctx
            .storage
            .subscribe_channel(
                None,
                Some("cache-test"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed");
        let channel_id = subscribe.channel_id;
        let effective_at = chrono::Utc::now().timestamp();

        let first = ctx
            .storage
            .list_channel_dispatch_targets(channel_id, effective_at)
            .await
            .expect("first fetch should succeed");
        assert_eq!(first.len(), 1);

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ?")
            .bind(&channel_id[..])
            .execute(&mut conn)
            .await
            .expect("direct delete should succeed");

        let second = ctx
            .storage
            .list_channel_dispatch_targets(channel_id, effective_at)
            .await
            .expect("cached fetch should succeed");
        assert_eq!(second.len(), 1);

        sleep(Duration::from_millis(2300)).await;
        let third = ctx
            .storage
            .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp())
            .await
            .expect("post-ttl fetch should succeed");
        assert_eq!(third.len(), 0);
    }

    #[tokio::test]
    async fn dispatch_targets_cache_invalidates_on_unsubscribe() {
        let ctx = setup_sqlite_storage("dispatch-targets-invalidate").await;
        let token = "android-token-cache-invalidate-000000000000000000000001";
        let subscribe = ctx
            .storage
            .subscribe_channel(
                None,
                Some("cache-invalidate"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed");
        let channel_id = subscribe.channel_id;
        let effective_at = chrono::Utc::now().timestamp();

        let first = ctx
            .storage
            .list_channel_dispatch_targets(channel_id, effective_at)
            .await
            .expect("first fetch should succeed");
        assert_eq!(first.len(), 1);

        let removed = ctx
            .storage
            .unsubscribe_channel(channel_id, token, Platform::ANDROID)
            .await
            .expect("unsubscribe should succeed");
        assert!(removed);

        let second = ctx
            .storage
            .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp())
            .await
            .expect("post-invalidation fetch should succeed");
        assert_eq!(second.len(), 0);
    }

    #[tokio::test]
    async fn provider_pull_retry_lifecycle_works() {
        let ctx = setup_sqlite_storage("provider-pull-retry").await;

        let now = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-retry-001";
        let message = PrivateMessage {
            payload: vec![1, 2, 3, 4],
            size: 4,
            sent_at: now,
            expires_at: now + 300,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-001",
                now - 1,
            )
            .await
            .expect("enqueue should succeed");

        let due = ctx
            .storage
            .list_provider_pull_retry_due(now, 10)
            .await
            .expect("list due should succeed");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].delivery_id, delivery_id);
        assert_eq!(due[0].attempts, 0);

        ctx.storage
            .bump_provider_pull_retry(delivery_id, now + 60, now)
            .await
            .expect("bump should succeed");
        let due_after_bump = ctx
            .storage
            .list_provider_pull_retry_due(now, 10)
            .await
            .expect("second list due should succeed");
        assert!(due_after_bump.is_empty());

        let pulled = ctx
            .storage
            .pull_provider_item(delivery_id, now + 1)
            .await
            .expect("pull should succeed");
        assert!(pulled.is_some());
        let pulled_again = ctx
            .storage
            .pull_provider_item(delivery_id, now + 2)
            .await
            .expect("second pull should succeed");
        assert!(pulled_again.is_none());

        let payload_after_pull = ctx
            .storage
            .load_private_message(delivery_id)
            .await
            .expect("payload lookup after pull should succeed");
        assert!(payload_after_pull.is_none());

        let due_after_pull = ctx
            .storage
            .list_provider_pull_retry_due(now + 120, 10)
            .await
            .expect("list due after pull should succeed");
        assert!(due_after_pull.is_empty());
    }

    #[tokio::test]
    async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
        let ctx = setup_sqlite_storage("private-payload-cleanup").await;

        let now = chrono::Utc::now().timestamp();
        let device_a: DeviceId = [1; 16];
        let device_b: DeviceId = [2; 16];

        let message = PrivateMessage {
            payload: vec![9, 8, 7, 6],
            size: 4,
            sent_at: now,
            expires_at: now + 300,
        };

        let shared_delivery_id = "delivery-private-shared-001";
        ctx.storage
            .insert_private_message(shared_delivery_id, &message)
            .await
            .expect("insert shared payload should succeed");

        let entry = PrivateOutboxEntry {
            delivery_id: shared_delivery_id.to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        ctx.storage
            .enqueue_private_outbox(device_a, &entry)
            .await
            .expect("enqueue entry a should succeed");
        ctx.storage
            .enqueue_private_outbox(device_b, &entry)
            .await
            .expect("enqueue entry b should succeed");

        ctx.storage
            .ack_private_delivery(device_a, shared_delivery_id)
            .await
            .expect("ack entry a should succeed");
        let shared_still_exists = ctx
            .storage
            .load_private_message(shared_delivery_id)
            .await
            .expect("shared payload lookup should succeed");
        assert!(shared_still_exists.is_some());

        ctx.storage
            .ack_private_delivery(device_b, shared_delivery_id)
            .await
            .expect("ack entry b should succeed");
        let shared_after_all_acked = ctx
            .storage
            .load_private_message(shared_delivery_id)
            .await
            .expect("shared payload second lookup should succeed");
        assert!(shared_after_all_acked.is_none());

        let provider_delivery_id = "delivery-provider-ref-001";
        ctx.storage
            .insert_private_message(provider_delivery_id, &message)
            .await
            .expect("insert provider payload should succeed");
        let provider_entry = PrivateOutboxEntry {
            delivery_id: provider_delivery_id.to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        ctx.storage
            .enqueue_private_outbox(device_a, &provider_entry)
            .await
            .expect("enqueue provider entry should succeed");
        ctx.storage
            .enqueue_provider_pull_item(
                provider_delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-provider-ref-001",
                now,
            )
            .await
            .expect("enqueue provider queue should succeed");

        ctx.storage
            .ack_private_delivery(device_a, provider_delivery_id)
            .await
            .expect("ack provider entry should succeed");
        let provider_payload_after_private_ack = ctx
            .storage
            .load_private_message(provider_delivery_id)
            .await
            .expect("provider payload lookup should succeed");
        assert!(provider_payload_after_private_ack.is_some());

        let pulled = ctx
            .storage
            .pull_provider_item(provider_delivery_id, now + 1)
            .await
            .expect("provider pull should succeed");
        assert!(pulled.is_some());
        let provider_payload_after_pull = ctx
            .storage
            .load_private_message(provider_delivery_id)
            .await
            .expect("provider payload lookup after pull should succeed");
        assert!(provider_payload_after_pull.is_none());
    }

    #[tokio::test]
    async fn load_device_routes_uses_devices_snapshot_not_channel_subscriptions() {
        let ctx = setup_sqlite_storage("device-routes-semantics").await;
        let token = "android-route-semantics-000000000000000000000000000001";
        let subscribe = ctx
            .storage
            .subscribe_channel(
                None,
                Some("route-sem"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed");

        let routes_before = ctx
            .storage
            .load_device_routes()
            .await
            .expect("load routes before upsert should succeed");
        assert!(
            routes_before.is_empty(),
            "subscription rows must not be treated as route snapshots"
        );

        let route = DeviceRouteRecordRow {
            device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
            platform: "android".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: chrono::Utc::now().timestamp(),
        };
        ctx.storage
            .upsert_device_route(&route)
            .await
            .expect("upsert route should succeed");

        let routes_after = ctx
            .storage
            .load_device_routes()
            .await
            .expect("load routes after upsert should succeed");
        assert_eq!(routes_after.len(), 1);
        assert_eq!(routes_after[0].device_key, route.device_key);
        assert_eq!(routes_after[0].platform, route.platform);
        assert_eq!(routes_after[0].channel_type, route.channel_type);

        let targets = ctx
            .storage
            .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp())
            .await
            .expect("dispatch targets fetch should succeed");
        assert_eq!(targets.len(), 1);

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        let route_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE route_updated_at IS NOT NULL")
                .fetch_one(&mut conn)
                .await
                .expect("route row count should be queryable");
        let subscription_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM channel_subscriptions WHERE device_key IS NOT NULL",
        )
        .fetch_one(&mut conn)
        .await
        .expect("subscription row count should be queryable");
        assert_eq!(route_rows, 1);
        assert_eq!(subscription_rows, 0);
    }

    #[tokio::test]
    async fn sqlite_cold_start_initializes_schema() {
        let ctx = setup_sqlite_storage_without_bootstrap("sqlite-cold-start").await;
        let token = "android-cold-start-000000000000000000000000000001";
        let subscribe = ctx
            .storage
            .subscribe_channel(
                None,
                Some("cold-start"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed after cold-start schema init");
        let info = ctx
            .storage
            .channel_info(subscribe.channel_id)
            .await
            .expect("channel info should load");
        assert!(info.is_some());
    }

    #[tokio::test]
    async fn sqlite_new_creates_parent_directories() {
        let dir = tempdir().expect("tempdir should be created");
        let nested_dir = dir.path().join("nested").join("gateway").join("db");
        let db_path = nested_dir.join("pushgo.sqlite");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        assert!(
            !nested_dir.exists(),
            "nested parent directory should not exist before init"
        );

        let storage = Storage::new(Some(db_url.as_str()))
            .await
            .expect("sqlite storage should initialize and create parent directories");
        assert!(
            nested_dir.exists(),
            "sqlite parent directory should be created"
        );
        assert!(db_path.exists(), "sqlite db file should be created");

        let token = "android-parent-dir-create-0000000000000000000000000001";
        let subscribe = storage
            .subscribe_channel(
                None,
                Some("auto-parent"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed on auto-created sqlite path");
        let info = storage
            .channel_info(subscribe.channel_id)
            .await
            .expect("channel info should load");
        assert!(info.is_some());
    }

    #[tokio::test]
    async fn sqlite_init_heals_missing_delivery_audit_audit_id_column() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-delivery-audit",
            &[ "CREATE TABLE IF NOT EXISTS delivery_audit (delivery_id TEXT NOT NULL, channel_id BLOB NOT NULL, device_key TEXT NOT NULL, entity_type TEXT, entity_id TEXT, op_id TEXT, path TEXT NOT NULL, status TEXT NOT NULL, error_code TEXT, created_at INTEGER NOT NULL)" ],
        )
        .await;

        let write = DeliveryAuditWrite {
            delivery_id: "delivery-heal-audit-id-1".to_string(),
            channel_id: [7; 16],
            device_key: "device-heal-audit-id-1".to_string(),
            entity_type: Some("message".to_string()),
            entity_id: Some("msg-heal-audit-id-1".to_string()),
            op_id: Some("op-heal-audit-id-1".to_string()),
            path: "provider".to_string(),
            status: "enqueued".to_string(),
            error_code: None,
            created_at: chrono::Utc::now().timestamp(),
        };
        ctx.storage
            .append_delivery_audit(&write)
            .await
            .expect("append delivery audit should succeed after init healing");

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        let audit_id_is_set: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM delivery_audit WHERE audit_id IS NOT NULL")
                .fetch_one(&mut conn)
                .await
                .expect("delivery audit count should be queryable");
        assert_eq!(audit_id_is_set, 1);
    }

    #[tokio::test]
    async fn sqlite_init_accepts_previous_schema_version_and_upgrades_meta() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-schema-version-upgrade",
            &[ "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
               "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4')" ],
        )
        .await;

        let token = "android-schema-upgrade-000000000000000000000000000001";
        ctx.storage
            .subscribe_channel(
                None,
                Some("schema-upgrade"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed after schema version upgrade");

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        let meta: Option<String> = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(&mut conn)
        .await
        .expect("schema meta query should succeed");
        assert_eq!(meta.as_deref(), Some(STORAGE_SCHEMA_VERSION));
    }

    #[tokio::test]
    async fn sqlite_init_heals_missing_devices_route_columns() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-devices-columns",
            &["CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY)"],
        )
        .await;

        let route = DeviceRouteRecordRow {
            device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
            platform: "android".to_string(),
            channel_type: "fcm".to_string(),
            provider_token: Some("android-heal-route-token-1".to_string()),
            updated_at: chrono::Utc::now().timestamp(),
        };
        ctx.storage
            .upsert_device_route(&route)
            .await
            .expect("upsert route should succeed after devices-column healing");

        let routes = ctx
            .storage
            .load_device_routes()
            .await
            .expect("load routes should succeed");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].device_key, route.device_key);
        assert_eq!(routes[0].platform, route.platform);
        assert_eq!(routes[0].channel_type, route.channel_type);
        assert_eq!(routes[0].provider_token, route.provider_token);
    }

    #[tokio::test]
    async fn sqlite_init_creates_missing_provider_pull_tables() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-provider-pull-tables",
            &["CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"],
        )
        .await;

        let now = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-heal-provider-table-1";
        let message = PrivateMessage {
            payload: vec![11, 22, 33],
            size: 3,
            sent_at: now,
            expires_at: now + 300,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-heal-provider-table-token-1",
                now,
            )
            .await
            .expect("enqueue provider pull item should succeed after table auto-create");

        let due = ctx
            .storage
            .list_provider_pull_retry_due(now + 1, 8)
            .await
            .expect("list provider due should succeed");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].delivery_id, delivery_id);
    }

    #[tokio::test]
    async fn sqlite_init_heals_missing_private_outbox_columns() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-private-outbox-columns",
            &[ "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))" ],
        )
        .await;

        let now = chrono::Utc::now().timestamp();
        let device_id: DeviceId = [8; 16];
        let entry = PrivateOutboxEntry {
            delivery_id: "delivery-heal-outbox-1".to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now - 1,
            created_at: now - 1,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: Some("none".to_string()),
            updated_at: now,
        };
        ctx.storage
            .enqueue_private_outbox(device_id, &entry)
            .await
            .expect("enqueue private outbox should succeed after init healing");

        let loaded = ctx
            .storage
            .load_private_outbox_entry(device_id, entry.delivery_id.as_str())
            .await
            .expect("load outbox entry should succeed");
        assert!(loaded.is_some());
        assert_eq!(
            loaded.expect("entry should exist").occurred_at,
            entry.occurred_at
        );
    }

    #[tokio::test]
    async fn sqlite_init_heals_missing_channel_subscription_columns() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-channel-sub-columns",
            &[ "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))" ],
        )
        .await;

        let token = "android-heal-channel-sub-token-0001";
        let subscribe = ctx
            .storage
            .subscribe_channel(
                None,
                Some("heal-channel-sub"),
                "password-1234",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed after channel_subscriptions column healing");

        let targets = ctx
            .storage
            .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp())
            .await
            .expect("dispatch target listing should succeed");
        assert_eq!(targets.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_init_heals_missing_private_bindings_columns_and_indexes() {
        let ctx = setup_sqlite_storage_with_custom_schema(
            "sqlite-heal-private-bindings",
            &["CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash))"],
        )
        .await;

        let device_id: DeviceId = [5; 16];
        let token_1 = "android-heal-private-bindings-token-0001";
        let token_2 = "android-heal-private-bindings-token-0002";

        ctx.storage
            .bind_private_token(device_id, Platform::ANDROID, token_1)
            .await
            .expect("bind first token should succeed after schema healing");
        ctx.storage
            .bind_private_token(device_id, Platform::ANDROID, token_2)
            .await
            .expect("bind second token should succeed after schema healing");

        let found_1 = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token_1)
            .await
            .expect("lookup first token should succeed");
        let found_2 = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token_2)
            .await
            .expect("lookup second token should succeed");
        assert_eq!(found_1, Some(device_id));
        assert_eq!(found_2, Some(device_id));

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        let required_columns = [
            "platform",
            "token_hash",
            "provider_token",
            "created_at",
            "updated_at",
        ];
        for column in required_columns {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM pragma_table_info('private_bindings') WHERE name = ? LIMIT 1",
            )
            .bind(column)
            .fetch_optional(&mut conn)
            .await
            .expect("pragma table_info query should succeed");
            assert_eq!(exists, Some(1), "column {column} should be present");
        }

        let unique_idx_exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM pragma_index_list('private_bindings') WHERE name = 'private_bindings_platform_token_uidx' AND \"unique\" = 1 LIMIT 1",
        )
        .fetch_optional(&mut conn)
        .await
        .expect("pragma index_list query should succeed");
        assert_eq!(
            unique_idx_exists,
            Some(1),
            "platform/token_hash unique index should be present"
        );
    }

    #[tokio::test]
    async fn sqlite_cleanup_pending_op_dedupe_uses_created_at_oldest_first_and_limit() {
        let ctx = setup_sqlite_storage("sqlite-dedupe-cleanup-created-at").await;

        let created_at = 1_700_000_000_i64;
        let k1 = "dedupe-created-at-1";
        let k2 = "dedupe-created-at-2";
        let k3 = "dedupe-created-at-3";
        let k4 = "dedupe-created-at-4";
        ctx.storage
            .reserve_op_dedupe_pending(k1, "delivery-created-at-1", created_at - 30)
            .await
            .expect("reserve k1 should succeed");
        ctx.storage
            .reserve_op_dedupe_pending(k2, "delivery-created-at-2", created_at - 20)
            .await
            .expect("reserve k2 should succeed");
        ctx.storage
            .reserve_op_dedupe_pending(k3, "delivery-created-at-3", created_at - 10)
            .await
            .expect("reserve k3 should succeed");
        ctx.storage
            .reserve_op_dedupe_pending(k4, "delivery-created-at-4", created_at + 10_000)
            .await
            .expect("reserve k4 should succeed");

        let sent = ctx
            .storage
            .mark_op_dedupe_sent(k2, "delivery-created-at-2")
            .await
            .expect("mark k2 sent should succeed");
        assert!(sent, "k2 should transition to sent");

        let removed_first = ctx
            .storage
            .cleanup_pending_op_dedupe(created_at, 1)
            .await
            .expect("first cleanup should succeed");
        assert_eq!(
            removed_first, 1,
            "first cleanup should remove oldest pending only"
        );

        let mut conn = SqliteConnection::connect(&ctx.db_url)
            .await
            .expect("sqlite test connection should succeed");
        let remain_after_first: Vec<(String, String)> = sqlx::query_as(
            "SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC",
        )
        .fetch_all(&mut conn)
        .await
        .expect("dedupe rows should be queryable");
        assert_eq!(
            remain_after_first,
            vec![
                (k2.to_string(), DedupeState::Sent.as_str().to_string()),
                (k3.to_string(), DedupeState::Pending.as_str().to_string()),
                (k4.to_string(), DedupeState::Pending.as_str().to_string()),
            ]
        );

        let removed_second = ctx
            .storage
            .cleanup_pending_op_dedupe(created_at, 8)
            .await
            .expect("second cleanup should succeed");
        assert_eq!(
            removed_second, 1,
            "second cleanup should remove remaining old pending"
        );

        let remain_after_second: Vec<(String, String)> = sqlx::query_as(
            "SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC",
        )
        .fetch_all(&mut conn)
        .await
        .expect("dedupe rows should remain queryable");
        assert_eq!(
            remain_after_second,
            vec![
                (k2.to_string(), DedupeState::Sent.as_str().to_string()),
                (k4.to_string(), DedupeState::Pending.as_str().to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn private_bindings_keep_history_for_multiple_tokens_same_device() {
        let ctx = setup_sqlite_storage("private-bindings-history").await;
        let device_id: DeviceId = [9; 16];
        let token_1 = "android-history-token-0001";
        let token_2 = "android-history-token-0002";

        ctx.storage
            .bind_private_token(device_id, Platform::ANDROID, token_1)
            .await
            .expect("bind first token should succeed");
        ctx.storage
            .bind_private_token(device_id, Platform::ANDROID, token_2)
            .await
            .expect("bind second token should succeed");

        let found_1 = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token_1)
            .await
            .expect("lookup first token should succeed");
        let found_2 = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token_2)
            .await
            .expect("lookup second token should succeed");
        assert_eq!(found_1, Some(device_id));
        assert_eq!(found_2, Some(device_id));
    }

    #[tokio::test]
    async fn private_bindings_rebind_same_token_updates_target_device() {
        let ctx = setup_sqlite_storage("private-bindings-rebind").await;
        let old_device: DeviceId = [3; 16];
        let new_device: DeviceId = [4; 16];
        let token = "android-rebind-token-001";

        ctx.storage
            .bind_private_token(old_device, Platform::ANDROID, token)
            .await
            .expect("bind old device token should succeed");
        let old_found = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token)
            .await
            .expect("lookup token on old device should succeed");
        assert_eq!(old_found, Some(old_device));

        ctx.storage
            .bind_private_token(new_device, Platform::ANDROID, token)
            .await
            .expect("rebind token to new device should succeed");
        let new_found = ctx
            .storage
            .lookup_private_device(Platform::ANDROID, token)
            .await
            .expect("lookup token after rebind should succeed");
        assert_eq!(new_found, Some(new_device));
    }
}
