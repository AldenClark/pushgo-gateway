use super::*;
use crate::runtime_config::{GatewayRuntimeProfile, RuntimeTuning};
use crate::storage::database::migration::{
    AppliedSchemaMigration, SchemaMigrationDefinition, SchemaMigrationPlan,
    validate_applied_schema_migrations,
};

const MYSQL_BASE_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channels (channel_id BINARY(16) PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, payload_blob BLOB NOT NULL, payload_size INT NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (delivery_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, request_fingerprint VARCHAR(64) NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, sent_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, semantic_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, source VARCHAR(64) NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, last_seen_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key), UNIQUE KEY semantic_id_registry_semantic_idx (semantic_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS sender_submit_status (op_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, channel_id BINARY(16) NOT NULL, model VARCHAR(16) NOT NULL, entity_id VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL, dispatch_status VARCHAR(64) NULL, accepted_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (op_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS live_activity_tokens (activity_key VARCHAR(255) NOT NULL, token VARCHAR(512) NOT NULL, channel_id BINARY(16) NULL, platform VARCHAR(32) NOT NULL, schema_version INT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NULL, PRIMARY KEY (activity_key, token)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS widget_push_subscriptions (device_key VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, platform VARCHAR(32) NOT NULL, token VARCHAR(128) NOT NULL, widget_kind VARCHAR(128) NOT NULL, family VARCHAR(64) NOT NULL, schema_version INT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_key, platform, token, widget_kind, family)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key VARCHAR(64) PRIMARY KEY, state_json LONGTEXT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
];

const MYSQL_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BINARY(32) PRIMARY KEY, token_raw BLOB NOT NULL, platform_code SMALLINT NOT NULL, device_key VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL, platform VARCHAR(32) NULL, channel_type VARCHAR(32) NULL, provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL, route_updated_at BIGINT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BINARY(16) NOT NULL, key_id INT NOT NULL, key_hash BLOB NOT NULL, issued_at BIGINT NOT NULL, valid_until BIGINT NULL, PRIMARY KEY (device_id, key_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id VARCHAR(128) PRIMARY KEY, device_id BINARY(16) NOT NULL, expires_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, status VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, occurred_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0, claimed_at BIGINT NULL, claimed_by VARCHAR(128) NULL, first_sent_at BIGINT NULL, last_attempt_at BIGINT NULL, acked_at BIGINT NULL, fallback_sent_at BIGINT NULL, next_attempt_at BIGINT NOT NULL, last_error_code VARCHAR(64) NULL, last_error_detail TEXT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BINARY(32) NOT NULL, device_id BINARY(16) NOT NULL, provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (platform, token_hash)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BINARY(16) NOT NULL, device_id BINARY(32) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, payload_blob LONGBLOB NOT NULL, payload_size INT NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, platform VARCHAR(32) NOT NULL, provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
];

const MYSQL_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
    "CREATE INDEX sender_submit_status_expires_idx ON sender_submit_status (expires_at)",
    "CREATE INDEX live_activity_tokens_channel_idx ON live_activity_tokens (channel_id, updated_at)",
    "CREATE INDEX live_activity_tokens_expires_idx ON live_activity_tokens (expires_at)",
    "CREATE INDEX widget_push_subscriptions_channel_lookup_idx ON widget_push_subscriptions (device_key, widget_kind, updated_at)",
    "CREATE INDEX widget_push_subscriptions_token_idx ON widget_push_subscriptions (platform, token)",
];

const MYSQL_RUNTIME_INDEX_STATEMENTS: &[&str] = &[
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
    "CREATE INDEX channel_subscriptions_dispatch_idx ON channel_subscriptions (channel_id, status, created_at)",
    "CREATE UNIQUE INDEX provider_pull_queue_device_delivery_uidx ON provider_pull_queue (device_id, delivery_id)",
    "CREATE INDEX provider_pull_queue_device_created_idx ON provider_pull_queue (device_id, created_at)",
    "CREATE INDEX provider_pull_queue_device_expires_idx ON provider_pull_queue (device_id, expires_at)",
];

const MYSQL_RUNTIME_DROP_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS provider_pull_queue",
    "DROP TABLE IF EXISTS channel_subscriptions",
    "DROP TABLE IF EXISTS private_bindings",
    "DROP TABLE IF EXISTS private_outbox",
    "DROP TABLE IF EXISTS private_sessions",
    "DROP TABLE IF EXISTS private_device_keys",
    "DROP TABLE IF EXISTS devices",
    "DROP TABLE IF EXISTS subscription_audit",
    "DROP TABLE IF EXISTS device_route_audit",
    "DROP TABLE IF EXISTS device_stats_daily",
];
const MYSQL_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS delivery_audit",
    "DROP TABLE IF EXISTS subscription_audit",
    "DROP TABLE IF EXISTS device_route_audit",
    "DROP TABLE IF EXISTS channel_stats_daily",
    "DROP TABLE IF EXISTS device_stats_daily",
    "DROP TABLE IF EXISTS gateway_stats_hourly",
    "DROP TABLE IF EXISTS ops_stats_hourly",
];
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
const EPOCH_NORMALIZATION_META_KEY: &str = "epoch_millis_normalized_v1";
const PROVIDER_TOKEN_NORMALIZATION_META_KEY: &str = "provider_token_semantics_v1";

impl MySqlDb {
    pub async fn new(db_url: &str, runtime_profile: GatewayRuntimeProfile) -> StoreResult<Self> {
        let tuning = RuntimeTuning::for_profile(runtime_profile).external_db;
        let pool = MySqlPoolOptions::new()
            .max_connections(tuning.max_connections)
            .min_connections(tuning.min_connections)
            .acquire_timeout(tuning.acquire_timeout)
            .idle_timeout(tuning.idle_timeout)
            .max_lifetime(tuning.max_lifetime)
            .connect(db_url)
            .await?;
        let this = Self { pool };
        this.init_schema().await?;
        Ok(this)
    }

    pub(crate) async fn open_for_upgrade(
        db_url: &str,
        runtime_profile: GatewayRuntimeProfile,
    ) -> StoreResult<Self> {
        let tuning = RuntimeTuning::for_profile(runtime_profile).external_db;
        let pool = MySqlPoolOptions::new()
            .max_connections(1)
            .min_connections(0)
            .acquire_timeout(tuning.acquire_timeout)
            .idle_timeout(tuning.idle_timeout)
            .max_lifetime(tuning.max_lifetime)
            .connect(db_url)
            .await?;
        Ok(Self { pool })
    }

    async fn init_schema(&self) -> StoreResult<()> {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_started",
            driver = %("mysql")
        );
        self.ensure_mysql_schema_meta_table().await?;
        self.ensure_mysql_schema_migrations_table().await?;
        let applied_migrations = self.load_mysql_schema_migrations().await?;
        validate_applied_schema_migrations(&applied_migrations)?;
        let plan = SchemaMigrationPlan::for_state(
            self.load_mysql_schema_version().await?.as_deref(),
            self.mysql_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        if let Some(migration) = plan.hard_reset_migration() {
            let started_at = Utc::now().timestamp();
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "db.schema_hard_reset_started",
                driver = %("mysql"),
                migration_id = %(migration.id)
            );
            if let Err(err) = self.hard_reset_mysql_runtime_tables().await {
                let _ = self
                    .record_mysql_schema_migration(
                        migration,
                        started_at,
                        false,
                        Some(err.to_string()),
                    )
                    .await;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "db.schema_hard_reset_failed",
                    driver = %("mysql"),
                    migration_id = %(migration.id),
                    error = %(err.to_string())
                );
                return Err(err);
            }
        }

        for stmt in MYSQL_BASE_TABLE_STATEMENTS
            .iter()
            .chain(MYSQL_RUNTIME_TABLE_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        self.ensure_mysql_column(
            "dispatch_op_dedupe",
            "request_fingerprint",
            "ALTER TABLE dispatch_op_dedupe ADD COLUMN request_fingerprint VARCHAR(64) NULL",
        )
        .await?;

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
            "ALTER TABLE devices ADD COLUMN provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL",
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
            "ALTER TABLE private_bindings ADD COLUMN provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL",
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
            "claimed_by",
            "ALTER TABLE private_outbox ADD COLUMN claimed_by VARCHAR(128) NULL",
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
            "status",
            "ALTER TABLE channel_subscriptions ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active'",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "device_id",
            "ALTER TABLE provider_pull_queue ADD COLUMN device_id BINARY(16) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "payload_blob",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_blob LONGBLOB NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "payload_size",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_size INT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "sent_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN sent_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "expires_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN expires_at BIGINT NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "platform",
            "ALTER TABLE provider_pull_queue ADD COLUMN platform VARCHAR(32) NULL",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "provider_token",
            "ALTER TABLE provider_pull_queue ADD COLUMN provider_token VARCHAR(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL",
        )
        .await?;
        self.ensure_mysql_binary_text_column("devices", "provider_token")
            .await?;
        self.ensure_mysql_binary_text_column("private_bindings", "provider_token")
            .await?;
        self.ensure_mysql_binary_text_column("provider_pull_queue", "provider_token")
            .await?;
        self.repair_mysql_device_key_identities().await?;
        for (table, column, length) in [
            ("dispatch_delivery_dedupe", "dedupe_key", 255_u16),
            ("dispatch_delivery_dedupe", "delivery_id", 128_u16),
            ("dispatch_op_dedupe", "dedupe_key", 255_u16),
            ("dispatch_op_dedupe", "delivery_id", 128_u16),
            ("semantic_id_registry", "dedupe_key", 255_u16),
            ("semantic_id_registry", "semantic_id", 128_u16),
            ("sender_submit_status", "op_id", 128_u16),
            ("private_payloads", "delivery_id", 128_u16),
            ("private_outbox", "delivery_id", 128_u16),
            ("provider_pull_queue", "delivery_id", 128_u16),
            ("devices", "device_key", 255_u16),
            ("widget_push_subscriptions", "device_key", 128_u16),
        ] {
            self.ensure_mysql_binary_varchar_column(table, column, length)
                .await?;
        }
        self.ensure_mysql_column(
            "provider_pull_queue",
            "created_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_mysql_column(
            "provider_pull_queue",
            "updated_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        for index_stmt in MYSQL_BASE_INDEX_STATEMENTS
            .iter()
            .chain(MYSQL_RUNTIME_INDEX_STATEMENTS.iter())
        {
            self.ensure_mysql_index(index_stmt).await?;
        }
        for stmt in MYSQL_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        sqlx::query("DROP TABLE IF EXISTS provider_pull_retry")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM provider_pull_queue \
             WHERE device_id IS NULL OR payload_blob IS NULL OR platform IS NULL OR provider_token IS NULL",
        )
        .execute(&self.pool)
        .await?;
        self.ensure_mysql_provider_pull_queue_primary_key().await?;
        self.normalize_mysql_epoch_columns_to_millis_once().await?;
        self.normalize_mysql_provider_tokens_once().await?;

        self.store_mysql_schema_version(STORAGE_SCHEMA_VERSION)
            .await?;
        let migration_started_at = Utc::now().timestamp();
        for migration in &plan.pending_migrations {
            self.record_mysql_schema_migration(*migration, migration_started_at, true, None)
                .await?;
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_finished",
            driver = %("mysql"),
            target_schema_version = %(STORAGE_SCHEMA_VERSION),
            pending_migrations = (plan.pending_migrations.len() as u64)
        );
        Ok(())
    }

    async fn ensure_mysql_schema_meta_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_mysql_schema_version(&self) -> StoreResult<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn store_mysql_schema_version(&self, version: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?) \
             ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        )
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn normalize_mysql_epoch_columns_to_millis_once(&self) -> StoreResult<()> {
        const TARGET_COLUMNS: &[(&str, &[&str])] = &[
            ("channels", &["created_at", "updated_at"]),
            (
                "private_payloads",
                &["sent_at", "expires_at", "created_at", "updated_at"],
            ),
            (
                "dispatch_delivery_dedupe",
                &["created_at", "updated_at", "expires_at"],
            ),
            (
                "dispatch_op_dedupe",
                &["created_at", "updated_at", "sent_at", "expires_at"],
            ),
            (
                "semantic_id_registry",
                &["created_at", "updated_at", "last_seen_at", "expires_at"],
            ),
            ("mcp_state", &["updated_at"]),
            ("devices", &["route_updated_at"]),
            ("private_device_keys", &["issued_at", "valid_until"]),
            ("private_sessions", &["expires_at"]),
            (
                "private_outbox",
                &[
                    "occurred_at",
                    "created_at",
                    "claimed_at",
                    "first_sent_at",
                    "last_attempt_at",
                    "acked_at",
                    "fallback_sent_at",
                    "next_attempt_at",
                    "updated_at",
                ],
            ),
            ("private_bindings", &["created_at", "updated_at"]),
            ("channel_subscriptions", &["created_at", "updated_at"]),
            (
                "provider_pull_queue",
                &["sent_at", "expires_at", "created_at", "updated_at"],
            ),
        ];

        let mut tx = self.pool.begin().await?;
        let marker_exists: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = ?")
                .bind(EPOCH_NORMALIZATION_META_KEY)
                .fetch_optional(&mut *tx)
                .await?;
        if marker_exists.is_some() {
            tx.commit().await?;
            return Ok(());
        }

        for (table, columns) in TARGET_COLUMNS {
            for column in *columns {
                let sql = format!(
                    "UPDATE {table} \
                     SET {column} = {column} * 1000 \
                     WHERE {column} IS NOT NULL AND ABS({column}) < ?"
                );
                sqlx::query(&sql)
                    .bind(EPOCH_MILLIS_THRESHOLD)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        )
        .bind(EPOCH_NORMALIZATION_META_KEY)
        .bind("1")
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_mysql_provider_tokens_once(&self) -> StoreResult<()> {
        let normalized: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = ?")
                .bind(PROVIDER_TOKEN_NORMALIZATION_META_KEY)
                .fetch_optional(&self.pool)
                .await?;
        if normalized.as_deref() == Some("complete") {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        let bindings = sqlx::query(
            "SELECT platform, token_hash, device_id, provider_token, created_at, updated_at \
             FROM private_bindings WHERE platform IN (1, 2, 4) \
               AND provider_token IS NOT NULL AND token_hash IS NOT NULL \
             ORDER BY updated_at ASC, created_at ASC, token_hash ASC",
        )
        .fetch_all(&mut *tx)
        .await?;
        let routes = sqlx::query(
            "SELECT device_id, device_key, platform, channel_type, provider_token, route_updated_at \
             FROM devices \
             WHERE platform IN ('ios', 'macos', 'watchos') \
               AND provider_token IS NOT NULL AND device_key IS NOT NULL \
               AND channel_type IS NOT NULL AND route_updated_at IS NOT NULL \
             ORDER BY LOWER(TRIM(provider_token)), platform, route_updated_at DESC, device_key DESC",
        )
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE devices SET provider_token = LOWER(TRIM(provider_token)) \
             WHERE platform IN ('ios', 'macos', 'watchos') AND provider_token IS NOT NULL",
        )
        .execute(&mut *tx)
        .await?;
        for row in bindings {
            let platform: i16 = row.get("platform");
            let old_hash: Vec<u8> = row.get("token_hash");
            let device_id: Vec<u8> = row.get("device_id");
            let provider_token = super::access::decode_mysql_text(&row, "provider_token")?;
            let canonical = provider_token.trim().to_ascii_lowercase();
            let (new_hash, _) = ProviderTokenSnapshot::from_token(&canonical).into_parts();
            let new_hash = new_hash.ok_or(StoreError::InvalidDeviceToken)?;
            sqlx::query(
                "INSERT INTO private_bindings \
                 (platform, token_hash, device_id, provider_token, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE device_id = VALUES(device_id), \
                   provider_token = VALUES(provider_token), updated_at = GREATEST(updated_at, VALUES(updated_at))",
            )
            .bind(platform)
            .bind(new_hash.as_slice())
            .bind(device_id.as_slice())
            .bind(&canonical)
            .bind(row.get::<i64, _>("created_at"))
            .bind(row.get::<i64, _>("updated_at"))
            .execute(&mut *tx)
            .await?;
            if old_hash != new_hash {
                sqlx::query("DELETE FROM private_bindings WHERE platform = ? AND token_hash = ?")
                    .bind(platform)
                    .bind(old_hash.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
        }
        sqlx::query(
            "UPDATE provider_pull_queue SET provider_token = LOWER(TRIM(provider_token)) \
             WHERE platform IN ('ios', 'macos', 'watchos') AND provider_token IS NOT NULL",
        )
        .execute(&mut *tx)
        .await?;
        let mut merged_routes = std::collections::HashSet::new();
        for row in routes {
            let platform: String = row.get("platform");
            let provider_token = super::access::decode_mysql_text(&row, "provider_token")?;
            let canonical = provider_token.trim().to_ascii_lowercase();
            if !merged_routes.insert((platform.clone(), canonical.clone())) {
                continue;
            }
            let route = DeviceRouteRecordRow {
                device_key: super::access::decode_mysql_text(&row, "device_key")?,
                platform,
                channel_type: super::access::decode_mysql_text(&row, "channel_type")?,
                provider_token: Some(canonical.clone()),
                updated_at: row.get("route_updated_at"),
            };
            let values = route.persistence_values()?;
            let old_device_id: Vec<u8> = row.get("device_id");
            if PrivateDeviceId::parse_compat(old_device_id.as_slice())
                .is_none_or(|id| id.into_inner().as_slice() != values.device_id.as_slice())
            {
                sqlx::query("UPDATE devices SET device_key = NULL WHERE device_id = ?")
                    .bind(old_device_id.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
            super::access::routes::upsert_device_route_in_tx(&mut tx, &route).await?;
            let (token_hash, _) = ProviderTokenSnapshot::from_token(&canonical).into_parts();
            sqlx::query(
                "INSERT INTO private_bindings \
                 (platform, token_hash, device_id, provider_token, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE device_id = VALUES(device_id), \
                   provider_token = VALUES(provider_token), updated_at = GREATEST(updated_at, VALUES(updated_at))",
            )
            .bind(values.platform_code)
            .bind(token_hash.as_deref())
            .bind(values.device_id.as_slice())
            .bind(&canonical)
            .bind(values.updated_at)
            .bind(values.updated_at)
            .execute(&mut *tx)
            .await?;
            super::access::routes::coalesce_duplicate_provider_routes_in_tx(&mut tx, &values)
                .await?;
        }
        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES (?, 'complete') \
             ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        )
        .bind(PROVIDER_TOKEN_NORMALIZATION_META_KEY)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn ensure_mysql_schema_migrations_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (\
                migration_id VARCHAR(128) PRIMARY KEY,\
                description TEXT NOT NULL,\
                checksum VARCHAR(255) NOT NULL,\
                target_schema_version VARCHAR(255) NOT NULL,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT NOT NULL,\
                execution_ms BIGINT NOT NULL,\
                success TINYINT NOT NULL,\
                error TEXT NULL\
            ) ENGINE=InnoDB",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_mysql_schema_migrations(&self) -> StoreResult<Vec<AppliedSchemaMigration>> {
        let rows = sqlx::query(
            "SELECT migration_id, checksum, success \
             FROM pushgo_schema_migrations \
             ORDER BY started_at, migration_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| AppliedSchemaMigration {
                id: row.get("migration_id"),
                checksum: row.get("checksum"),
                success: row.get::<i8, _>("success") != 0,
            })
            .collect())
    }

    async fn record_mysql_schema_migration(
        &self,
        migration: SchemaMigrationDefinition,
        started_at: i64,
        success: bool,
        error: Option<String>,
    ) -> StoreResult<()> {
        let finished_at = Utc::now().timestamp();
        let execution_ms = (finished_at - started_at).max(0) * 1000;
        sqlx::query(
            "INSERT INTO pushgo_schema_migrations \
             (migration_id, description, checksum, target_schema_version, started_at, finished_at, execution_ms, success, error) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
               description = VALUES(description), \
               checksum = VALUES(checksum), \
               target_schema_version = VALUES(target_schema_version), \
               started_at = VALUES(started_at), \
               finished_at = VALUES(finished_at), \
               execution_ms = VALUES(execution_ms), \
               success = VALUES(success), \
               error = VALUES(error)",
        )
        .bind(migration.id)
        .bind(migration.description)
        .bind(migration.checksum)
        .bind(migration.target_schema_version)
        .bind(started_at)
        .bind(finished_at)
        .bind(execution_ms)
        .bind(if success { 1_i8 } else { 0_i8 })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mysql_runtime_tables_present(&self) -> StoreResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) \
             FROM information_schema.tables \
             WHERE table_schema = DATABASE() \
               AND table_name IN ('devices', 'channel_subscriptions', 'private_bindings', 'provider_pull_queue')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
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

    async fn ensure_mysql_binary_text_column(&self, table: &str, column: &str) -> StoreResult<()> {
        self.ensure_mysql_binary_varchar_column(table, column, 4096)
            .await
    }

    async fn repair_mysql_device_key_identities(&self) -> StoreResult<()> {
        let rows = sqlx::query(
            "SELECT device_id, device_key FROM devices \
             WHERE device_key IS NOT NULL ORDER BY device_key ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let route_device_id: Vec<u8> = row.get("device_id");
            let device_key = super::access::decode_mysql_text(&row, "device_key")?;
            let device_key = crate::value::DeviceKeyRef::parse(&device_key)
                .map_err(|_| StoreError::InvalidDeviceToken)?;
            let current_private_id = PrivateDeviceId::parse_compat(route_device_id.as_slice())
                .ok_or(StoreError::BinaryError)?
                .into_inner();
            let expected_private_id = PrivateDeviceId::derive(device_key.as_str()).into_inner();
            if current_private_id == expected_private_id {
                continue;
            }

            let mut tx = self.pool.begin().await?;
            let conflicting_device_id: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT device_id FROM devices WHERE device_id = ? AND device_id <> ? LIMIT 1 FOR UPDATE",
            )
            .bind(expected_private_id.as_slice())
            .bind(route_device_id.as_slice())
            .fetch_optional(&mut *tx)
            .await?;
            if conflicting_device_id.is_some() {
                return Err(StoreError::Upgrade(format!(
                    "cannot repair MySQL device identity for key {} because the derived device_id already exists",
                    crate::util::redact_text(device_key.as_str())
                )));
            }

            sqlx::query(
                "INSERT INTO channel_subscriptions \
                 (channel_id, device_id, status, created_at, updated_at) \
                 SELECT source_subscriptions.channel_id, ?, source_subscriptions.status, \
                        source_subscriptions.created_at, source_subscriptions.updated_at \
                 FROM (SELECT channel_id, status, created_at, updated_at \
                       FROM channel_subscriptions WHERE device_id = ?) AS source_subscriptions \
                 ON DUPLICATE KEY UPDATE \
                   status = IF(channel_subscriptions.status = 'active' OR VALUES(status) = 'active', 'active', VALUES(status)), \
                   created_at = LEAST(channel_subscriptions.created_at, VALUES(created_at)), \
                   updated_at = GREATEST(channel_subscriptions.updated_at, VALUES(updated_at))",
            )
            .bind(expected_private_id.as_slice())
            .bind(route_device_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                .bind(route_device_id.as_slice())
                .execute(&mut *tx)
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
                   payload_blob = VALUES(payload_blob), payload_size = VALUES(payload_size), \
                   sent_at = LEAST(provider_pull_queue.sent_at, VALUES(sent_at)), \
                   expires_at = GREATEST(provider_pull_queue.expires_at, VALUES(expires_at)), \
                   platform = VALUES(platform), provider_token = VALUES(provider_token), \
                   created_at = LEAST(provider_pull_queue.created_at, VALUES(created_at)), \
                   updated_at = GREATEST(provider_pull_queue.updated_at, VALUES(updated_at))",
            )
            .bind(expected_private_id.as_slice())
            .bind(current_private_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ?")
                .bind(current_private_id.as_slice())
                .execute(&mut *tx)
                .await?;

            sqlx::query(
                "INSERT IGNORE INTO private_outbox \
                 (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, claimed_by, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                 SELECT ?, delivery_id, status, attempts, occurred_at, created_at, claimed_at, claimed_by, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                 FROM private_outbox WHERE device_id = ?",
            )
            .bind(expected_private_id.as_slice())
            .bind(current_private_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                .bind(current_private_id.as_slice())
                .execute(&mut *tx)
                .await?;

            sqlx::query(
                "INSERT IGNORE INTO private_device_keys \
                 (device_id, key_id, key_hash, issued_at, valid_until) \
                 SELECT ?, key_id, key_hash, issued_at, valid_until \
                 FROM private_device_keys WHERE device_id = ?",
            )
            .bind(expected_private_id.as_slice())
            .bind(current_private_id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM private_device_keys WHERE device_id = ?")
                .bind(current_private_id.as_slice())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE private_sessions SET device_id = ? WHERE device_id = ?")
                .bind(expected_private_id.as_slice())
                .bind(current_private_id.as_slice())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE private_bindings SET device_id = ? WHERE device_id = ?")
                .bind(expected_private_id.as_slice())
                .bind(current_private_id.as_slice())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE devices SET device_id = ? WHERE device_id = ?")
                .bind(expected_private_id.as_slice())
                .bind(route_device_id.as_slice())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;

            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "db.mysql_device_identity_repaired",
                device_key = %(crate::util::redact_text(device_key.as_str()))
            );
        }
        Ok(())
    }

    async fn ensure_mysql_binary_varchar_column(
        &self,
        table: &str,
        column: &str,
        length: u16,
    ) -> StoreResult<()> {
        // MySQL 8.4 exposes some information_schema string columns with the
        // binary protocol BLOB type. Cast them explicitly so sqlx can decode
        // the metadata consistently across MySQL patch releases.
        let metadata: Option<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT CAST(COLUMN_TYPE AS CHAR), CAST(IS_NULLABLE AS CHAR), \
                    CAST(COLLATION_NAME AS CHAR) \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(&self.pool)
        .await?;
        let Some((column_type, is_nullable, collation)) = metadata else {
            return Err(StoreError::Upgrade(format!(
                "missing MySQL column {table}.{column}"
            )));
        };
        if column_type.eq_ignore_ascii_case(format!("varchar({length})").as_str())
            && collation.as_deref() == Some("utf8mb4_bin")
        {
            return Ok(());
        }
        let nullability = if is_nullable == "YES" {
            "NULL"
        } else {
            "NOT NULL"
        };
        let ddl = format!(
            "ALTER TABLE `{table}` MODIFY COLUMN `{column}` VARCHAR({length}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin {nullability}"
        );
        sqlx::query(&ddl).execute(&self.pool).await?;
        Ok(())
    }

    async fn ensure_mysql_provider_pull_queue_primary_key(&self) -> StoreResult<()> {
        let pk_columns: Vec<String> = sqlx::query_scalar(
            "SELECT CAST(COLUMN_NAME AS CHAR) \
             FROM information_schema.KEY_COLUMN_USAGE \
             WHERE TABLE_SCHEMA = DATABASE() \
               AND TABLE_NAME = 'provider_pull_queue' \
               AND CONSTRAINT_NAME = 'PRIMARY' \
             ORDER BY ORDINAL_POSITION",
        )
        .fetch_all(&self.pool)
        .await?;
        if pk_columns.as_slice() == ["device_id", "delivery_id"] {
            return Ok(());
        }

        let has_primary: Option<i32> = sqlx::query_scalar(
            "SELECT 1 \
             FROM information_schema.TABLE_CONSTRAINTS \
             WHERE TABLE_SCHEMA = DATABASE() \
               AND TABLE_NAME = 'provider_pull_queue' \
               AND CONSTRAINT_TYPE = 'PRIMARY KEY' \
             LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let mut clauses = vec![
            "MODIFY COLUMN device_id BINARY(16) NOT NULL",
            "MODIFY COLUMN delivery_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
        ];
        if has_primary.is_some() {
            clauses.push("DROP PRIMARY KEY");
        }
        clauses.push("ADD PRIMARY KEY (device_id, delivery_id)");
        let ddl = format!("ALTER TABLE provider_pull_queue {}", clauses.join(", "));
        sqlx::query(ddl.as_str()).execute(&self.pool).await?;
        Ok(())
    }

    async fn hard_reset_mysql_runtime_tables(&self) -> StoreResult<()> {
        for stmt in MYSQL_RUNTIME_DROP_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in MYSQL_RUNTIME_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in MYSQL_RUNTIME_INDEX_STATEMENTS {
            self.ensure_mysql_index(stmt).await?;
        }

        Ok(())
    }
}

pub(crate) struct MySqlUpgradeLockGuard {
    pool: sqlx::MySqlPool,
}

impl Drop for MySqlUpgradeLockGuard {
    fn drop(&mut self) {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("SELECT RELEASE_LOCK('pushgo_gateway_db_upgrade')")
                .execute(&pool)
                .await;
        });
    }
}

impl MySqlDb {
    pub(crate) async fn inspect_upgrade_plan(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<
        crate::storage::database::upgrade::UpgradePlan,
    > {
        let applied_migrations = if self.mysql_table_exists("pushgo_schema_migrations").await? {
            self.load_mysql_schema_migrations().await?
        } else {
            Vec::new()
        };
        validate_applied_schema_migrations(&applied_migrations)?;
        let current_version = if self.mysql_table_exists("pushgo_schema_meta").await? {
            self.load_mysql_schema_version().await?
        } else {
            None
        };
        let plan = SchemaMigrationPlan::for_state(
            current_version.as_deref(),
            self.mysql_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        Ok(crate::storage::database::upgrade::UpgradePlan::from_schema_plan(plan))
    }

    async fn mysql_table_exists(&self, table: &str) -> StoreResult<bool> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1",
        )
        .bind(table)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }
}

impl crate::storage::database::upgrade::lock::UpgradeLockAccess for MySqlDb {
    type Guard = MySqlUpgradeLockGuard;

    async fn acquire_upgrade_lock(
        &self,
        _db_url: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<Self::Guard> {
        let locked: Option<i64> =
            sqlx::query_scalar("SELECT GET_LOCK('pushgo_gateway_db_upgrade', 0)")
                .fetch_one(&self.pool)
                .await?;
        if locked != Some(1) {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade(
                    "mysql named upgrade lock is held by another process; stop other gateway instances or wait for the upgrade to finish".to_string(),
                ),
            ));
        }
        Ok(MySqlUpgradeLockGuard {
            pool: self.pool.clone(),
        })
    }
}

impl crate::storage::database::upgrade::state::UpgradeStateAccess for MySqlDb {
    async fn ensure_upgrade_state_tables(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_upgrade_runs (\
                run_id VARCHAR(64) PRIMARY KEY,\
                gateway_version TEXT NOT NULL,\
                driver TEXT NOT NULL,\
                from_schema_version TEXT NULL,\
                target_schema_version TEXT NOT NULL,\
                status VARCHAR(32) NOT NULL,\
                backup_uri TEXT NULL,\
                backup_sha256 TEXT NULL,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT NULL,\
                error TEXT NULL\
            ) ENGINE=InnoDB",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_upgrade_steps (\
                run_id VARCHAR(64) NOT NULL,\
                step_order BIGINT NOT NULL,\
                migration_id TEXT NOT NULL,\
                step_id TEXT NOT NULL,\
                description TEXT NOT NULL,\
                status VARCHAR(32) NOT NULL,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT NULL,\
                error TEXT NULL,\
                PRIMARY KEY (run_id, step_order)\
            ) ENGINE=InnoDB",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn unfinished_upgrade_runs(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<Vec<String>> {
        let rows = sqlx::query("SELECT run_id, status FROM pushgo_upgrade_runs")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let status: String = row.get("status");
                crate::storage::database::upgrade::state::UpgradeRunStatus::unfinished(
                    status.as_str(),
                )
                .then(|| row.get("run_id"))
            })
            .collect())
    }

    async fn insert_upgrade_run(
        &self,
        run_id: &str,
        driver: crate::storage::types::DatabaseKind,
        from_schema_version: Option<&str>,
        target_schema_version: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        sqlx::query(
            "INSERT INTO pushgo_upgrade_runs \
             (run_id, gateway_version, driver, from_schema_version, target_schema_version, status, started_at) \
             VALUES (?, ?, ?, ?, ?, 'planned', ?)",
        )
        .bind(run_id)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(driver.as_str())
        .bind(from_schema_version)
        .bind(target_schema_version)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_upgrade_run_status(
        &self,
        run_id: &str,
        status: crate::storage::database::upgrade::state::UpgradeRunStatus,
        backup_uri: Option<&str>,
        backup_sha256: Option<&str>,
        error: Option<&str>,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        let finished_at = matches!(
            status,
            crate::storage::database::upgrade::state::UpgradeRunStatus::Completed
                | crate::storage::database::upgrade::state::UpgradeRunStatus::Failed
                | crate::storage::database::upgrade::state::UpgradeRunStatus::RolledBack
                | crate::storage::database::upgrade::state::UpgradeRunStatus::RollbackFailed
        )
        .then(|| Utc::now().timestamp());
        sqlx::query(
            "UPDATE pushgo_upgrade_runs \
             SET status = ?, backup_uri = COALESCE(?, backup_uri), backup_sha256 = COALESCE(?, backup_sha256), finished_at = COALESCE(?, finished_at), error = COALESCE(?, error) \
             WHERE run_id = ?",
        )
        .bind(status.as_str())
        .bind(backup_uri)
        .bind(backup_sha256)
        .bind(finished_at)
        .bind(error)
        .bind(run_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        migration_id: &str,
        step_id: &str,
        description: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        sqlx::query(
            "INSERT INTO pushgo_upgrade_steps \
             (run_id, step_order, migration_id, step_id, description, status, started_at) \
             VALUES (?, ?, ?, ?, ?, 'planned', ?)",
        )
        .bind(run_id)
        .bind(step_order)
        .bind(migration_id)
        .bind(step_id)
        .bind(description)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        status: crate::storage::database::upgrade::state::UpgradeRunStatus,
        error: Option<&str>,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        let finished_at = matches!(
            status,
            crate::storage::database::upgrade::state::UpgradeRunStatus::Completed
                | crate::storage::database::upgrade::state::UpgradeRunStatus::Failed
        )
        .then(|| Utc::now().timestamp());
        sqlx::query(
            "UPDATE pushgo_upgrade_steps SET status = ?, finished_at = COALESCE(?, finished_at), error = COALESCE(?, error) WHERE run_id = ? AND step_order = ?",
        )
        .bind(status.as_str())
        .bind(finished_at)
        .bind(error)
        .bind(run_id)
        .bind(step_order)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl crate::storage::database::upgrade::backup::UpgradeBackupAccess for MySqlDb {
    async fn create_upgrade_backup(
        &self,
        db_url: &str,
        driver: crate::storage::types::DatabaseKind,
        policy: crate::storage::database::migration::BackupPolicy,
        run_id: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<
        Option<crate::storage::database::upgrade::backup::BackupArtifact>,
    > {
        if matches!(
            policy,
            crate::storage::database::migration::BackupPolicy::None
        ) {
            return Ok(None);
        }
        #[cfg(test)]
        if std::env::var_os("PUSHGO_DB_UPGRADE_BACKUP_MANIFEST").is_none() {
            return Ok(Some(
                crate::storage::database::upgrade::backup::test_external_backup_artifact(
                    driver, run_id,
                ),
            ));
        }
        #[cfg(not(test))]
        let _ = run_id;
        Ok(Some(
            crate::storage::database::upgrade::backup::load_external_backup_manifest(
                db_url, driver,
            )?,
        ))
    }

    async fn restore_upgrade_backup(
        &self,
        _db_url: &str,
        _artifact: &crate::storage::database::upgrade::backup::BackupArtifact,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        Err(crate::storage::database::upgrade::UpgradeError::Store(
            StoreError::Upgrade(
                "MySQL rollback requires manual restore from the recorded external snapshot or mysqldump artifact".to_string(),
            ),
        ))
    }
}

impl crate::storage::database::upgrade::verify::UpgradeVerifyAccess for MySqlDb {
    async fn verify_upgrade(
        &self,
        target_schema_version: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        let schema_version = self.load_mysql_schema_version().await?;
        if schema_version.as_deref() != Some(target_schema_version) {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::SchemaVersionMismatch {
                    expected: target_schema_version.to_string(),
                    actual: schema_version.unwrap_or_else(|| "none".to_string()),
                },
            ));
        }
        validate_applied_schema_migrations(&self.load_mysql_schema_migrations().await?)?;
        for table in [
            "channels",
            "devices",
            "channel_subscriptions",
            "private_payloads",
            "sender_submit_status",
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1",
            )
            .bind(table)
            .fetch_optional(&self.pool)
            .await?;
            if exists.is_none() {
                return Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!("required table missing after upgrade: {table}")),
                ));
            }
        }
        for (table, column) in [
            ("dispatch_delivery_dedupe", "dedupe_key"),
            ("dispatch_delivery_dedupe", "delivery_id"),
            ("dispatch_op_dedupe", "dedupe_key"),
            ("dispatch_op_dedupe", "delivery_id"),
            ("semantic_id_registry", "dedupe_key"),
            ("semantic_id_registry", "semantic_id"),
            ("sender_submit_status", "op_id"),
            ("private_payloads", "delivery_id"),
            ("private_outbox", "delivery_id"),
            ("provider_pull_queue", "delivery_id"),
            ("devices", "device_key"),
            ("widget_push_subscriptions", "device_key"),
            ("devices", "provider_token"),
            ("private_bindings", "provider_token"),
            ("provider_pull_queue", "provider_token"),
        ] {
            let collation: Option<String> = sqlx::query_scalar(
                "SELECT CAST(COLLATION_NAME AS CHAR) FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1",
            )
            .bind(table)
            .bind(column)
            .fetch_optional(&self.pool)
            .await?;
            if collation.as_deref() != Some("utf8mb4_bin") {
                return Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!(
                        "required binary collation missing after upgrade: {table}.{column}"
                    )),
                ));
            }
        }
        Ok(())
    }
}
