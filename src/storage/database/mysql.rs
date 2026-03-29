use super::DatabaseAccess;
use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{MySqlPool, Row};

#[derive(Debug, Clone)]
pub struct MySqlDb {
    pool: MySqlPool,
}

impl MySqlDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        let pool = MySqlPool::connect(db_url).await?;
        let this = Self { pool };
        this.init_schema().await?;
        Ok(this)
    }

    async fn init_schema(&self) -> StoreResult<()> {
        let statements = [
            "CREATE TABLE IF NOT EXISTS channels (channel_id BINARY(16) PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS devices (device_id BINARY(32) PRIMARY KEY, token_raw BLOB NOT NULL, platform_code SMALLINT NOT NULL, device_key VARCHAR(255) NULL, platform VARCHAR(32) NULL, channel_type VARCHAR(32) NULL, provider_token TEXT NULL, route_updated_at BIGINT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BINARY(16) NOT NULL, key_id INT NOT NULL, key_hash BLOB NOT NULL, issued_at BIGINT NOT NULL, valid_until BIGINT NULL, PRIMARY KEY (device_id, key_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS private_sessions (session_id VARCHAR(128) PRIMARY KEY, device_id BINARY(16) NOT NULL, expires_at BIGINT NOT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS private_outbox (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, occurred_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0, claimed_at BIGINT NULL, first_sent_at BIGINT NULL, last_attempt_at BIGINT NULL, acked_at BIGINT NULL, fallback_sent_at BIGINT NULL, next_attempt_at BIGINT NOT NULL, last_error_code VARCHAR(64) NULL, last_error_detail TEXT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BINARY(32) NOT NULL, device_id BINARY(16) NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (platform, token_hash)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BINARY(16) NOT NULL, device_id BINARY(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, device_key VARCHAR(255) NULL, provider_token TEXT NULL, provider_token_hash BINARY(32) NULL, provider_token_preview VARCHAR(128) NULL, route_version BIGINT NOT NULL DEFAULT 1, status VARCHAR(32) NOT NULL DEFAULT 'active', subscribed_via VARCHAR(32) NULL, last_dispatch_at BIGINT NULL, last_acked_at BIGINT NULL, last_error_code VARCHAR(64) NULL, last_confirmed_at BIGINT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id VARCHAR(128) NOT NULL, payload_blob BLOB NOT NULL, payload_size INT NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (delivery_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (delivery_id VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'pending', pulled_at BIGINT NULL, acked_at BIGINT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (delivery_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS provider_pull_retry (delivery_id VARCHAR(128) NOT NULL, platform VARCHAR(32) NOT NULL, provider_token VARCHAR(512) NOT NULL, attempts INT NOT NULL DEFAULT 0, next_retry_at BIGINT NOT NULL, last_attempt_at BIGINT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (delivery_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key VARCHAR(255) NOT NULL, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key VARCHAR(255) NOT NULL, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, sent_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key VARCHAR(255) NOT NULL, semantic_id VARCHAR(128) NOT NULL, source VARCHAR(64) NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, last_seen_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key), UNIQUE KEY semantic_id_registry_semantic_idx (semantic_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS device_route_audit (device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, old_platform VARCHAR(32) NULL, new_platform VARCHAR(32) NULL, old_channel_type VARCHAR(32) NULL, new_channel_type VARCHAR(32) NULL, old_provider_token TEXT NULL, new_provider_token TEXT NULL, issue_reason VARCHAR(64) NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS subscription_audit (channel_id BINARY(16) NOT NULL, device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS delivery_audit (audit_id VARCHAR(128) NOT NULL, delivery_id VARCHAR(128) NOT NULL, channel_id BINARY(16) NOT NULL, device_key VARCHAR(255) NOT NULL, entity_type VARCHAR(32) NULL, entity_id VARCHAR(255) NULL, op_id VARCHAR(128) NULL, path VARCHAR(32) NOT NULL, status VARCHAR(32) NOT NULL, error_code VARCHAR(64) NULL, created_at BIGINT NOT NULL, PRIMARY KEY (audit_id)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BINARY(16) NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_enqueued BIGINT NOT NULL DEFAULT 0, provider_attempted BIGINT NOT NULL DEFAULT 0, provider_failed BIGINT NOT NULL DEFAULT 0, provider_success BIGINT NOT NULL DEFAULT 0, private_realtime_delivered BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key VARCHAR(255) NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_received BIGINT NOT NULL DEFAULT 0, messages_acked BIGINT NOT NULL DEFAULT 0, private_connected_count BIGINT NOT NULL DEFAULT 0, private_pull_count BIGINT NOT NULL DEFAULT 0, provider_success_count BIGINT NOT NULL DEFAULT 0, provider_failure_count BIGINT NOT NULL DEFAULT 0, private_outbox_enqueued_count BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour VARCHAR(16) NOT NULL, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_outbox_depth_max BIGINT NOT NULL DEFAULT 0, dedupe_pending_max BIGINT NOT NULL DEFAULT 0, active_private_sessions_max BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (bucket_hour)) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
        ];
        for stmt in statements {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        self.ensure_mysql_column(
            "devices",
            "token_raw",
            "ALTER TABLE devices ADD COLUMN token_raw BLOB NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "platform_code",
            "ALTER TABLE devices ADD COLUMN platform_code SMALLINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "device_key",
            "ALTER TABLE devices ADD COLUMN device_key VARCHAR(255) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "platform",
            "ALTER TABLE devices ADD COLUMN platform VARCHAR(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "channel_type",
            "ALTER TABLE devices ADD COLUMN channel_type VARCHAR(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "provider_token",
            "ALTER TABLE devices ADD COLUMN provider_token TEXT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "devices",
            "route_updated_at",
            "ALTER TABLE devices ADD COLUMN route_updated_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_bindings",
            "platform",
            "ALTER TABLE private_bindings ADD COLUMN platform SMALLINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "private_bindings",
            "provider_token",
            "ALTER TABLE private_bindings ADD COLUMN provider_token TEXT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_bindings",
            "token_hash",
            "ALTER TABLE private_bindings ADD COLUMN token_hash BINARY(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_bindings",
            "created_at",
            "ALTER TABLE private_bindings ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "private_bindings",
            "updated_at",
            "ALTER TABLE private_bindings ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "occurred_at",
            "ALTER TABLE private_outbox ADD COLUMN occurred_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "created_at",
            "ALTER TABLE private_outbox ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "claimed_at",
            "ALTER TABLE private_outbox ADD COLUMN claimed_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "first_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN first_sent_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "last_attempt_at",
            "ALTER TABLE private_outbox ADD COLUMN last_attempt_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "acked_at",
            "ALTER TABLE private_outbox ADD COLUMN acked_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "fallback_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN fallback_sent_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "private_outbox",
            "last_error_detail",
            "ALTER TABLE private_outbox ADD COLUMN last_error_detail TEXT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "device_key",
            "ALTER TABLE channel_subscriptions ADD COLUMN device_key VARCHAR(255) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "provider_token",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token TEXT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "provider_token_hash",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token_hash BINARY(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "provider_token_preview",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token_preview VARCHAR(128) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "route_version",
            "ALTER TABLE channel_subscriptions ADD COLUMN route_version BIGINT NOT NULL DEFAULT 1",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "status",
            "ALTER TABLE channel_subscriptions ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active'",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "subscribed_via",
            "ALTER TABLE channel_subscriptions ADD COLUMN subscribed_via VARCHAR(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "last_dispatch_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_dispatch_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "last_acked_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_acked_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "last_error_code",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_error_code VARCHAR(64) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "channel_subscriptions",
            "last_confirmed_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_confirmed_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "delivery_audit",
            "audit_id",
            "ALTER TABLE delivery_audit ADD COLUMN audit_id VARCHAR(128) NULL",
        )
        .await?;
        for index_stmt in [
            "CREATE UNIQUE INDEX devices_device_key_uidx ON devices (device_key)",
            "CREATE INDEX devices_route_platform_type_updated_idx ON devices (platform, channel_type, route_updated_at)",
            "CREATE INDEX devices_route_provider_token_idx ON devices (provider_token(191))",
            "CREATE INDEX private_sessions_exp_idx ON private_sessions (expires_at)",
            "CREATE INDEX private_outbox_delivery_idx ON private_outbox (delivery_id)",
            "CREATE INDEX private_outbox_due_idx ON private_outbox (status, next_attempt_at, attempts)",
            "CREATE INDEX private_outbox_device_status_order_idx ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
            "CREATE INDEX private_bindings_device_idx ON private_bindings (device_id)",
            "CREATE INDEX private_bindings_token_idx ON private_bindings (platform, token_hash)",
            "CREATE UNIQUE INDEX private_bindings_platform_token_uidx ON private_bindings (platform, token_hash)",
            "CREATE INDEX channel_subscriptions_device_idx ON channel_subscriptions (device_id)",
            "CREATE INDEX channel_subscriptions_dispatch_idx ON channel_subscriptions (channel_id, status, channel_type, route_version)",
            "CREATE INDEX private_payloads_expires_idx ON private_payloads (expires_at)",
            "CREATE INDEX provider_pull_queue_status_updated_idx ON provider_pull_queue (status, updated_at)",
            "CREATE INDEX provider_pull_retry_due_idx ON provider_pull_retry (next_retry_at, attempts)",
            "CREATE INDEX dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
            "CREATE INDEX dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
            "CREATE INDEX dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
            "CREATE INDEX dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
            "CREATE INDEX semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
            "CREATE INDEX semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
            "CREATE INDEX device_route_audit_device_created_idx ON device_route_audit (device_key, created_at)",
            "CREATE INDEX subscription_audit_channel_created_idx ON subscription_audit (channel_id, created_at)",
            "CREATE INDEX subscription_audit_device_created_idx ON subscription_audit (device_key, created_at)",
            "CREATE INDEX delivery_audit_delivery_created_idx ON delivery_audit (delivery_id, created_at)",
            "CREATE INDEX delivery_audit_channel_created_idx ON delivery_audit (channel_id, created_at)",
            "CREATE INDEX delivery_audit_device_created_idx ON delivery_audit (device_key, created_at)",
        ] {
            self.ensure_mysql_index(index_stmt).await?;
        }

        let current: Option<String> = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(&self.pool)
        .await?;
        match current {
            None => {
                sqlx::query(
                    "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?)",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(&self.pool)
                .await?;
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION => {}
            Some(version) if version == STORAGE_SCHEMA_VERSION_PREVIOUS => {
                sqlx::query(
                    "UPDATE pushgo_schema_meta SET meta_value = ? WHERE meta_key = 'schema_version'",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(&self.pool)
                .await?;
            }
            Some(version) => {
                return Err(StoreError::SchemaVersionMismatch {
                    expected: STORAGE_SCHEMA_VERSION.to_string(),
                    actual: version,
                });
            }
        }
        Ok(())
    }

    async fn ensure_mysql_index(&self, create_sql: &str) -> StoreResult<()> {
        let index_name = create_sql
            .split("INDEX")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .ok_or(StoreError::BinaryError)?;
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND index_name = ? LIMIT 1",
        )
        .bind(index_name)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            sqlx::query(create_sql).execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn ensure_mysql_column(&self, table: &str, column: &str, ddl: &str) -> StoreResult<()> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            sqlx::query(ddl).execute(&self.pool).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl DatabaseAccess for MySqlDb {
    async fn load_private_outbox_entry(
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

    async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| ChannelInfo {
            alias: r.get("alias"),
        }))
    }

    async fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let token_raw = device_info.token_raw.to_vec();
        let platform_code = platform.to_byte() as i16;
        let platform_text = platform_name(platform);
        let channel_type = channel_type_for_platform(platform);
        let token_hash = provider_token_hash(device_info.token_str.as_ref());
        let token_preview = provider_token_preview(device_info.token_str.as_ref());
        let now = Utc::now().timestamp();

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

        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             token_raw = VALUES(token_raw), \
             platform_code = VALUES(platform_code)",
        )
        .bind(&device_id[..])
        .bind(&token_raw)
        .bind(platform_code)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO channel_subscriptions \
             (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
             VALUES (?, ?, ?, ?, NULL, ?, ?, ?, 1, 'active', 'channel_subscribe', ?, ?) \
             ON DUPLICATE KEY UPDATE \
               platform = VALUES(platform), \
               channel_type = VALUES(channel_type), \
               provider_token = VALUES(provider_token), \
               provider_token_hash = VALUES(provider_token_hash), \
               provider_token_preview = VALUES(provider_token_preview), \
               status = VALUES(status), \
               updated_at = VALUES(updated_at)",
        )
        .bind(&channel_bytes)
        .bind(&device_id[..])
        .bind(platform_text)
        .bind(channel_type)
        .bind(device_info.token_str.as_ref())
        .bind(&token_hash)
        .bind(&token_preview)
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

    async fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let result =
            sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?")
                .bind(&channel_id[..])
                .bind(&device_id[..])
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let mut tx = self.pool.begin().await?;
        let removed = sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?
            .rows_affected() as usize;
        sqlx::query("DELETE FROM devices WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(removed)
    }

    async fn migrate_device_subscriptions(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let old_device_info = DeviceInfo::from_token(platform, old_device_token)?;
        let old_device_id = device_id_for(platform, &old_device_info.token_raw);
        let new_device_info = DeviceInfo::from_token(platform, new_device_token)?;
        let new_device_id = device_id_for(platform, &new_device_info.token_raw);
        let new_token_raw = new_device_info.token_raw.to_vec();
        let new_platform_code = new_device_info.platform.to_byte() as i16;

        if old_device_id == new_device_id {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
                token_raw = VALUES(token_raw), \
                platform_code = VALUES(platform_code)",
        )
        .bind(&new_device_id[..])
        .bind(&new_token_raw)
        .bind(new_platform_code)
        .execute(&mut *tx)
        .await?;

        let moved = sqlx::query(
            "INSERT INTO channel_subscriptions \
             (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, updated_at) \
             SELECT channel_id, ?, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, ? \
             FROM channel_subscriptions WHERE device_id = ? \
             ON DUPLICATE KEY UPDATE \
               platform = VALUES(platform), \
               channel_type = VALUES(channel_type), \
               device_key = VALUES(device_key), \
               provider_token = VALUES(provider_token), \
               provider_token_hash = VALUES(provider_token_hash), \
               provider_token_preview = VALUES(provider_token_preview), \
               route_version = VALUES(route_version), \
               status = VALUES(status), \
               subscribed_via = VALUES(subscribed_via), \
               last_dispatch_at = VALUES(last_dispatch_at), \
               last_acked_at = VALUES(last_acked_at), \
               last_error_code = VALUES(last_error_code), \
               last_confirmed_at = VALUES(last_confirmed_at), \
               updated_at = VALUES(updated_at)",
        )
        .bind(&new_device_id[..])
        .bind(Utc::now().timestamp())
        .bind(&old_device_id[..])
        .execute(&mut *tx)
        .await?
        .rows_affected() as usize;

        sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
            .bind(&old_device_id[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM devices WHERE device_id = ?")
            .bind(&old_device_id[..])
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(moved)
    }

    async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query("SELECT delivery_id FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_all(&mut *tx)
            .await?;
        let delivery_ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();

        sqlx::query(
            "DELETE FROM channel_subscriptions WHERE device_id = ? AND channel_type = 'private'",
        )
        .bind(&device_id[..])
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &delivery_ids {
            sqlx::query(
                "DELETE FROM private_payloads \
                 WHERE delivery_id = ? \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        let size = message.size as i64;
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO private_payloads (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             payload_blob = VALUES(payload_blob), payload_size = VALUES(payload_size), updated_at = VALUES(updated_at)",
        )
        .bind(delivery_id)
        .bind(&message.payload)
        .bind(size)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
                 status = VALUES(status), attempts = VALUES(attempts), updated_at = VALUES(updated_at), next_attempt_at = VALUES(next_attempt_at)",
        )
        .bind(&device_id[..])
        .bind(&entry.delivery_id)
        .bind(&entry.status)
        .bind(entry.attempts as i32)
        .bind(entry.occurred_at)
        .bind(entry.created_at)
        .bind(entry.claimed_at)
        .bind(entry.first_sent_at)
        .bind(entry.last_attempt_at)
        .bind(entry.acked_at)
        .bind(entry.fallback_sent_at)
        .bind(entry.next_attempt_at)
        .bind(entry.last_error_code.as_deref())
        .bind(entry.last_error_detail.as_deref())
        .bind(entry.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let rows = sqlx::query(
            "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
             ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(PrivateOutboxEntry {
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
            });
        }
        Ok(out)
    }

    async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?)",
        )
        .bind(&device_id[..])
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        let mut removed = 0usize;
        let expired_rows = sqlx::query(
            "SELECT delivery_id FROM private_payloads \
             WHERE expires_at <= ? \
             ORDER BY expires_at ASC \
             LIMIT ?",
        )
        .bind(before_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        for row in expired_rows {
            let delivery_id: String = row.get("delivery_id");
            sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                .bind(&delivery_id)
                .execute(&self.pool)
                .await?;
            sqlx::query("DELETE FROM private_outbox WHERE delivery_id = ?")
                .bind(&delivery_id)
                .execute(&self.pool)
                .await?;
            removed = removed.saturating_add(1);
        }

        let dangling_rows = sqlx::query(
            "SELECT o.device_id, o.delivery_id \
             FROM private_outbox o \
             LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
             WHERE m.delivery_id IS NULL \
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        for row in dangling_rows {
            let device_id: Vec<u8> = row.get("device_id");
            let delivery_id: String = row.get("delivery_id");
            sqlx::query(
                "DELETE FROM private_outbox \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(&device_id)
            .bind(&delivery_id)
            .execute(&self.pool)
            .await?;
            removed = removed.saturating_add(1);
        }
        Ok(removed)
    }

    async fn cleanup_pending_op_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        let removed = sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key IN (\
                SELECT dedupe_key FROM (\
                    SELECT dedupe_key \
                    FROM dispatch_op_dedupe \
                    WHERE created_at <= ? AND state = ? \
                    ORDER BY created_at ASC \
                    LIMIT ?\
                ) AS t\
             )",
        )
        .bind(before_ts)
        .bind(DedupeState::Pending.as_str())
        .bind(limit as i64)
        .execute(&self.pool)
        .await?
        .rows_affected() as usize;
        Ok(removed)
    }

    async fn cleanup_semantic_id_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        let removed = sqlx::query("DELETE FROM semantic_id_registry WHERE created_at <= ? LIMIT ?")
            .bind(before_ts)
            .bind(limit as i64)
            .execute(&self.pool)
            .await?
            .rows_affected() as usize;
        Ok(removed)
    }

    async fn cleanup_delivery_dedupe(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        let removed =
            sqlx::query("DELETE FROM dispatch_delivery_dedupe WHERE created_at <= ? LIMIT ?")
                .bind(before_ts)
                .bind(limit as i64)
                .execute(&self.pool)
                .await?
                .rows_affected() as usize;
        Ok(removed)
    }

    async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
        let removed = sqlx::query("DELETE FROM private_sessions WHERE expires_at <= ?")
            .bind(before_ts)
            .execute(&self.pool)
            .await?
            .rows_affected() as usize;
        Ok(removed)
    }

    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        let token_hash = provider_token_hash(token);
        sqlx::query(
            "INSERT INTO private_bindings (device_id, platform, provider_token, token_hash, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
                device_id = VALUES(device_id), \
                provider_token = VALUES(provider_token), \
                updated_at = VALUES(updated_at)",
        )
        .bind(&device_id[..])
        .bind(platform.to_byte() as i16)
        .bind(token)
        .bind(&token_hash)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_device_routes(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
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

    async fn upsert_device_route(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        let provider_token = route.provider_token.as_deref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let device_id = route_device_id_from_record(route)?;
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

    async fn apply_route_snapshot(
        &self,
        device_id: &[u8],
        device_key: &str,
        platform: &str,
        channel_type: &str,
        provider_token: Option<&str>,
    ) -> StoreResult<()> {
        let (token_hash, token_preview) = route_snapshot_fields(provider_token);
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
        .bind(platform)
        .bind(channel_type)
        .bind(device_key)
        .bind(provider_token)
        .bind(token_hash.as_deref())
        .bind(token_preview.as_deref())
        .bind(now)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn append_device_route_audit(&self, entry: &DeviceRouteAuditWrite) -> StoreResult<()> {
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

    async fn append_subscription_audit(&self, entry: &SubscriptionAuditWrite) -> StoreResult<()> {
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

    async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
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
        .bind(&entry.path)
        .bind(&entry.status)
        .bind(entry.error_code.as_deref())
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
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

    async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
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

    async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        let rows = sqlx::query(
            "SELECT s.device_id, s.platform, s.channel_type, s.device_key, s.provider_token \
             FROM channel_subscriptions s \
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
            let raw_device_id: Vec<u8> = row.get("device_id");
            let device_key: Option<String> = row.get("device_key");

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
            let provider_token: Option<String> = row.get("provider_token");
            if let Some(token) = provider_token {
                let token = token.trim().to_string();
                if !token.is_empty() {
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

    async fn list_subscribed_channels_for_device(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
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

    async fn list_private_subscribed_channels_for_device(
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

    async fn channel_info_with_password(
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

    async fn rename_channel(&self, channel_id: [u8; 16], alias: &str) -> StoreResult<()> {
        sqlx::query("UPDATE channels SET alias = ?, updated_at = ? WHERE channel_id = ?")
            .bind(alias)
            .bind(Utc::now().timestamp())
            .bind(&channel_id[..])
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password_hash: &str,
    ) -> StoreResult<SubscribeOutcome> {
        let mut tx = self.pool.begin().await?;
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

    async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO channel_subscriptions (channel_id, device_id, platform, channel_type, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE status = 'active', updated_at = VALUES(updated_at)",
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

    async fn private_unsubscribe_channel(
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

    async fn list_private_subscribers(
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

    async fn lookup_private_device(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        let token_hash = provider_token_hash(token);
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

    async fn load_private_message(&self, delivery_id: &str) -> StoreResult<Option<PrivateMessage>> {
        let row = sqlx::query(
            "SELECT payload_blob, payload_size, sent_at, expires_at \
             FROM private_payloads WHERE delivery_id = ?",
        )
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PrivateMessage {
            payload: r.get("payload_blob"),
            size: r.get::<u32, _>("payload_size") as usize,
            sent_at: r.get("sent_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        if let Some(msg) = self.load_private_message(delivery_id).await? {
            return Ok(decode_private_payload_context(&msg.payload));
        }
        Ok(None)
    }

    async fn enqueue_provider_pull_item(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;

        let size = message.size as i64;
        sqlx::query(
            "INSERT INTO private_payloads (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             payload_blob = VALUES(payload_blob), payload_size = VALUES(payload_size), updated_at = VALUES(updated_at)",
        )
        .bind(delivery_id)
        .bind(&message.payload)
        .bind(size)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue (delivery_id, status, pulled_at, acked_at, created_at, updated_at) \
             VALUES (?, 'pending', NULL, NULL, ?, ?) \
             ON DUPLICATE KEY UPDATE status = 'pending', updated_at = VALUES(updated_at)",
        )
        .bind(delivery_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_retry \
             (delivery_id, platform, provider_token, attempts, next_retry_at, last_attempt_at, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, 0, ?, NULL, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
                attempts = 0, next_retry_at = VALUES(next_retry_at), updated_at = VALUES(updated_at)",
        )
        .bind(delivery_id)
        .bind(platform_name(platform))
        .bind(provider_token)
        .bind(next_retry_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT p.payload_blob, p.sent_at, p.expires_at \
             FROM provider_pull_queue q \
             INNER JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.delivery_id = ? AND q.status = 'pending' AND p.expires_at > ?",
        )
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let result = if let Some(r) = row {
            sqlx::query("UPDATE provider_pull_queue SET status = 'pulled', pulled_at = ?, updated_at = ? WHERE delivery_id = ? AND status = 'pending'")
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM provider_pull_queue WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            Some(ProviderPullItem {
                delivery_id: delivery_id.to_string(),
                payload: r.get("payload_blob"),
                sent_at: r.get("sent_at"),
                expires_at: r.get("expires_at"),
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(result)
    }

    async fn append_delivery_audit_batch(&self, entries: &[DeliveryAuditWrite]) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for entry in entries {
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
            .bind(&entry.path)
            .bind(&entry.status)
            .bind(entry.error_code.as_deref())
            .bind(entry.created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        let rows = sqlx::query(
            "SELECT r.delivery_id, r.platform, r.provider_token, r.attempts, r.next_retry_at, r.expires_at \
             FROM provider_pull_retry r \
             INNER JOIN provider_pull_queue q ON q.delivery_id = r.delivery_id \
             WHERE q.status = 'pending' AND r.next_retry_at <= ? AND r.expires_at > ? \
             ORDER BY r.next_retry_at ASC LIMIT ?",
        )
        .bind(now)
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let platform_text: String = r.get("platform");
            let platform = platform_text.parse()?;
            out.push(ProviderPullRetryEntry {
                delivery_id: r.get("delivery_id"),
                platform,
                provider_token: r.get("provider_token"),
                attempts: r.get("attempts"),
                next_retry_at: r.get("next_retry_at"),
                expires_at: r.get("expires_at"),
            });
        }
        Ok(out)
    }

    async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE provider_pull_retry SET attempts = attempts + 1, next_retry_at = ?, last_attempt_at = ?, updated_at = ? \
             WHERE delivery_id = ? AND expires_at > ?",
        )
        .bind(next_retry_at)
        .bind(now)
        .bind(now)
        .bind(delivery_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
            .bind(delivery_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, ?), fallback_sent_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(OUTBOX_STATUS_SENT)
        .bind(at_ts)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            "UPDATE private_outbox SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ? \
             WHERE device_id = ? AND delivery_id = ?",
        )
        .bind(OUTBOX_STATUS_PENDING)
        .bind(at_ts)
        .bind(at_ts)
        .bind(&device_id[..])
        .bind(delivery_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
            .bind(&device_id[..])
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "DELETE FROM private_payloads \
             WHERE delivery_id = ? \
               AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
               AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
        )
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query("SELECT delivery_id FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_all(&mut *tx)
            .await?;
        let ids: Vec<String> = rows.into_iter().map(|r| r.get("delivery_id")).collect();
        sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
            .bind(&device_id[..])
            .execute(&mut *tx)
            .await?;

        for delivery_id in &ids {
            sqlx::query(
                "DELETE FROM private_payloads \
                 WHERE delivery_id = ? \
                   AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
                   AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(ids)
    }

    async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let rows = sqlx::query(
            "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
             FROM private_outbox WHERE next_attempt_at <= ? AND status IN (?, ?, ?) LIMIT ?",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let mut device_id = [0u8; 16];
            let raw: Vec<u8> = r.get("device_id");
            device_id.copy_from_slice(&raw);
            out.push((
                device_id,
                PrivateOutboxEntry {
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
                },
            ));
        }
        Ok(out)
    }

    async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT device_id, delivery_id FROM private_outbox \
             WHERE next_attempt_at <= ? AND status IN (?, ?, ?) \
             LIMIT ? FOR UPDATE",
        )
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let device_id_raw: Vec<u8> = r.get("device_id");
            let delivery_id: String = r.get("delivery_id");

            let updated_row = sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(&device_id_raw)
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;

            if updated_row.rows_affected() > 0 {
                let r = sqlx::query(
                    "SELECT * FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
                )
                .bind(&device_id_raw)
                .bind(&delivery_id)
                .fetch_one(&mut *tx)
                .await?;

                let mut device_id = [0u8; 16];
                device_id.copy_from_slice(&device_id_raw);
                out.push((
                    device_id,
                    PrivateOutboxEntry {
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
                    },
                ));
            }
        }
        tx.commit().await?;
        Ok(out)
    }

    async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT delivery_id FROM private_outbox \
             WHERE device_id = ? AND next_attempt_at <= ? AND status IN (?, ?, ?) \
             LIMIT ? FOR UPDATE",
        )
        .bind(&device_id[..])
        .bind(before_ts)
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_CLAIMED)
        .bind(OUTBOX_STATUS_SENT)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let delivery_id: String = r.get("delivery_id");

            sqlx::query(
                "UPDATE private_outbox SET status = ?, claimed_at = ?, last_attempt_at = ?, updated_at = ? \
                 WHERE device_id = ? AND delivery_id = ?",
            )
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(claim_until_ts)
            .bind(&device_id[..])
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;

            let r =
                sqlx::query("SELECT * FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id[..])
                    .bind(&delivery_id)
                    .fetch_one(&mut *tx)
                    .await?;

            out.push(PrivateOutboxEntry {
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
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN (?, ?, ?)")
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(&self.pool)
                .await?;
        Ok(count as usize)
    }

    async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "INSERT IGNORE INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Sent.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        let result = sqlx::query(
            "INSERT IGNORE INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(semantic_id)
        .bind(created_at)
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            Ok(SemanticIdReservation::Reserved)
        } else {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?",
            )
            .bind(dedupe_key)
            .fetch_optional(&self.pool)
            .await?;
            Ok(match existing {
                Some(s) => SemanticIdReservation::Existing { semantic_id: s },
                None => SemanticIdReservation::Collision,
            })
        }
    }

    async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .bind(created_at)
        .bind(created_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        let outcome = if inserted {
            OpDedupeReservation::Reserved
        } else {
            let existing = sqlx::query(
                "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = ? FOR UPDATE",
            )
            .bind(dedupe_key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                let existing_delivery_id: String = row.try_get("delivery_id")?;
                let state: String = row.try_get("state")?;
                match DedupeState::from_str(state.as_str())? {
                    DedupeState::Pending => OpDedupeReservation::Pending {
                        delivery_id: existing_delivery_id,
                    },
                    DedupeState::Sent => OpDedupeReservation::Sent {
                        delivery_id: existing_delivery_id,
                    },
                }
            } else {
                OpDedupeReservation::Pending {
                    delivery_id: delivery_id.to_string(),
                }
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    async fn mark_op_dedupe_sent(&self, dedupe_key: &str, delivery_id: &str) -> StoreResult<bool> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE dispatch_op_dedupe \
             SET state = ?, sent_at = ?, updated_at = ? \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(DedupeState::Sent.as_str())
        .bind(now)
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query("UPDATE dispatch_delivery_dedupe SET state = ?, updated_at = ? WHERE dedupe_key = ? AND delivery_id = ?")
            .bind(DedupeState::Sent.as_str())
            .bind(Utc::now().timestamp())
            .bind(dedupe_key)
            .bind(delivery_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn automation_reset(&self) -> StoreResult<()> {
        let tables = vec![
            "delivery_audit",
            "subscription_audit",
            "device_route_audit",
            "channel_stats_daily",
            "device_stats_daily",
            "gateway_stats_hourly",
            "dispatch_op_dedupe",
            "dispatch_delivery_dedupe",
            "semantic_id_registry",
            "channel_subscriptions",
            "devices",
            "channels",
            "private_bindings",
            "private_outbox",
            "private_payloads",
            "private_sessions",
            "private_device_keys",
        ];
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&mut *tx)
            .await?;
        for table in tables {
            sqlx::query(&format!("TRUNCATE TABLE {}", table))
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
            .fetch_one(&self.pool)
            .await?;
        let subscription_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                .fetch_one(&self.pool)
                .await?;
        let delivery_dedupe_pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_delivery_dedupe")
                .fetch_one(&self.pool)
                .await?;

        Ok(AutomationCounts {
            channel_count: channel_count as usize,
            subscription_count: subscription_count as usize,
            delivery_dedupe_pending_count: delivery_dedupe_pending_count as usize,
        })
    }
}
