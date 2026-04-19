use super::*;
use crate::storage::database::migration::{
    AppliedSchemaMigration, SchemaMigrationDefinition, SchemaMigrationPlan,
    validate_applied_schema_migrations,
};

const MYSQL_BASE_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channels (channel_id BINARY(16) PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id VARCHAR(128) NOT NULL, payload_blob BLOB NOT NULL, payload_size INT NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (delivery_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key VARCHAR(255) NOT NULL, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key VARCHAR(255) NOT NULL, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, sent_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key VARCHAR(255) NOT NULL, semantic_id VARCHAR(128) NOT NULL, source VARCHAR(64) NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, last_seen_at BIGINT NULL, expires_at BIGINT NULL, PRIMARY KEY (dedupe_key), UNIQUE KEY semantic_id_registry_semantic_idx (semantic_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS delivery_audit (audit_id VARCHAR(128) NOT NULL, delivery_id VARCHAR(128) NOT NULL, channel_id BINARY(16) NOT NULL, device_key VARCHAR(255) NOT NULL, entity_type VARCHAR(32) NULL, entity_id VARCHAR(255) NULL, op_id VARCHAR(128) NULL, path VARCHAR(32) NOT NULL, status VARCHAR(32) NOT NULL, error_code VARCHAR(64) NULL, created_at BIGINT NOT NULL, PRIMARY KEY (audit_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BINARY(16) NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_enqueued BIGINT NOT NULL DEFAULT 0, provider_attempted BIGINT NOT NULL DEFAULT 0, provider_failed BIGINT NOT NULL DEFAULT 0, provider_success BIGINT NOT NULL DEFAULT 0, private_realtime_delivered BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour VARCHAR(16) NOT NULL, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_outbox_depth_max BIGINT NOT NULL DEFAULT 0, dedupe_pending_max BIGINT NOT NULL DEFAULT 0, active_private_sessions_max BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (bucket_hour)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key VARCHAR(64) PRIMARY KEY, state_json LONGTEXT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB",
];

const MYSQL_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BINARY(32) PRIMARY KEY, token_raw BLOB NOT NULL, platform_code SMALLINT NOT NULL, device_key VARCHAR(255) NULL, platform VARCHAR(32) NULL, channel_type VARCHAR(32) NULL, provider_token TEXT NULL, route_updated_at BIGINT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BINARY(16) NOT NULL, key_id INT NOT NULL, key_hash BLOB NOT NULL, issued_at BIGINT NOT NULL, valid_until BIGINT NULL, PRIMARY KEY (device_id, key_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id VARCHAR(128) PRIMARY KEY, device_id BINARY(16) NOT NULL, expires_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, occurred_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0, claimed_at BIGINT NULL, first_sent_at BIGINT NULL, last_attempt_at BIGINT NULL, acked_at BIGINT NULL, fallback_sent_at BIGINT NULL, next_attempt_at BIGINT NOT NULL, last_error_code VARCHAR(64) NULL, last_error_detail TEXT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BINARY(32) NOT NULL, device_id BINARY(16) NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (platform, token_hash)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BINARY(16) NOT NULL, device_id BINARY(32) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) NOT NULL, payload_blob LONGBLOB NOT NULL, payload_size INT NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, platform VARCHAR(32) NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS device_route_audit (device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, old_platform VARCHAR(32) NULL, new_platform VARCHAR(32) NULL, old_channel_type VARCHAR(32) NULL, new_channel_type VARCHAR(32) NULL, old_provider_token TEXT NULL, new_provider_token TEXT NULL, issue_reason VARCHAR(64) NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS subscription_audit (channel_id BINARY(16) NOT NULL, device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key VARCHAR(255) NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_received BIGINT NOT NULL DEFAULT 0, messages_acked BIGINT NOT NULL DEFAULT 0, private_connected_count BIGINT NOT NULL DEFAULT 0, private_pull_count BIGINT NOT NULL DEFAULT 0, provider_success_count BIGINT NOT NULL DEFAULT 0, provider_failure_count BIGINT NOT NULL DEFAULT 0, private_outbox_enqueued_count BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date)) ENGINE=InnoDB",
];

const MYSQL_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
    "CREATE INDEX delivery_audit_delivery_created_idx ON delivery_audit (delivery_id, created_at)",
    "CREATE INDEX delivery_audit_channel_created_idx ON delivery_audit (channel_id, created_at)",
    "CREATE INDEX delivery_audit_device_created_idx ON delivery_audit (device_key, created_at)",
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
    "CREATE INDEX device_route_audit_device_created_idx ON device_route_audit (device_key, created_at)",
    "CREATE INDEX subscription_audit_channel_created_idx ON subscription_audit (channel_id, created_at)",
    "CREATE INDEX subscription_audit_device_created_idx ON subscription_audit (device_key, created_at)",
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

impl MySqlDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        let pool = MySqlPool::connect(db_url).await?;
        let this = Self { pool };
        this.init_schema().await?;
        Ok(this)
    }

    async fn init_schema(&self) -> StoreResult<()> {
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
            if let Err(err) = self.hard_reset_mysql_runtime_tables().await {
                let _ = self
                    .record_mysql_schema_migration(
                        migration,
                        started_at,
                        false,
                        Some(err.to_string()),
                    )
                    .await;
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
            "ALTER TABLE provider_pull_queue ADD COLUMN provider_token TEXT NULL",
        )
        .await?;
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
        self.ensure_mysql_column(
            "delivery_audit",
            "audit_id",
            "ALTER TABLE delivery_audit ADD COLUMN audit_id VARCHAR(128) NULL",
        )
        .await?;
        for index_stmt in MYSQL_BASE_INDEX_STATEMENTS
            .iter()
            .chain(MYSQL_RUNTIME_INDEX_STATEMENTS.iter())
        {
            self.ensure_mysql_index(index_stmt).await?;
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

        self.store_mysql_schema_version(STORAGE_SCHEMA_VERSION)
            .await?;
        let migration_started_at = Utc::now().timestamp();
        for migration in &plan.pending_migrations {
            self.record_mysql_schema_migration(*migration, migration_started_at, true, None)
                .await?;
        }
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

    async fn ensure_mysql_provider_pull_queue_primary_key(&self) -> StoreResult<()> {
        let pk_columns: Vec<String> = sqlx::query_scalar(
            "SELECT COLUMN_NAME \
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
            "MODIFY COLUMN delivery_id VARCHAR(128) NOT NULL",
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
