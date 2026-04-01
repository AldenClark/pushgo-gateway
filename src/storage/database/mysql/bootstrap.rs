use super::*;

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
            "CREATE TABLE IF NOT EXISTS mcp_state (state_key VARCHAR(64) PRIMARY KEY, state_json LONGTEXT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
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
