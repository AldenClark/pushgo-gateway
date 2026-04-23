use super::*;
use crate::storage::database::migration::{
    AppliedSchemaMigration, SchemaMigrationDefinition, SchemaMigrationPlan,
    validate_applied_schema_migrations,
};

const PG_BASE_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channels (channel_id BYTEA PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id VARCHAR(128) PRIMARY KEY, payload_blob BYTEA NOT NULL, payload_size INTEGER NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key VARCHAR(255) PRIMARY KEY, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key VARCHAR(255) PRIMARY KEY, delivery_id VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, sent_at BIGINT, expires_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key VARCHAR(255) PRIMARY KEY, semantic_id VARCHAR(128) NOT NULL UNIQUE, source VARCHAR(64), created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, last_seen_at BIGINT, expires_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BYTEA NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_enqueued BIGINT NOT NULL DEFAULT 0, provider_attempted BIGINT NOT NULL DEFAULT 0, provider_failed BIGINT NOT NULL DEFAULT 0, provider_success BIGINT NOT NULL DEFAULT 0, private_realtime_delivered BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))",
    "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour VARCHAR(16) PRIMARY KEY, messages_routed BIGINT NOT NULL DEFAULT 0, deliveries_attempted BIGINT NOT NULL DEFAULT 0, deliveries_acked BIGINT NOT NULL DEFAULT 0, private_outbox_depth_max BIGINT NOT NULL DEFAULT 0, dedupe_pending_max BIGINT NOT NULL DEFAULT 0, active_private_sessions_max BIGINT NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS ops_stats_hourly (bucket_hour VARCHAR(16) NOT NULL, metric_key VARCHAR(128) NOT NULL, metric_value BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (bucket_hour, metric_key))",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key VARCHAR(64) PRIMARY KEY, state_json TEXT NOT NULL, updated_at BIGINT NOT NULL)",
];

const PG_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BYTEA PRIMARY KEY, token_raw BYTEA NOT NULL, platform_code SMALLINT NOT NULL, device_key VARCHAR(255), platform VARCHAR(32), channel_type VARCHAR(32), provider_token TEXT, route_updated_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BYTEA NOT NULL, key_id INTEGER NOT NULL, key_hash BYTEA NOT NULL, issued_at BIGINT NOT NULL, valid_until BIGINT, PRIMARY KEY (device_id, key_id))",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id VARCHAR(128) PRIMARY KEY, device_id BYTEA NOT NULL, expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0, claimed_at BIGINT, first_sent_at BIGINT, last_attempt_at BIGINT, acked_at BIGINT, fallback_sent_at BIGINT, next_attempt_at BIGINT NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BYTEA NOT NULL, device_id BYTEA NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (platform, token_hash))",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BYTEA NOT NULL, device_id BYTEA NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id))",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, payload_blob BYTEA NOT NULL, payload_size INTEGER NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, platform VARCHAR(32) NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS device_route_audit (device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, old_platform VARCHAR(32), new_platform VARCHAR(32), old_channel_type VARCHAR(32), new_channel_type VARCHAR(32), old_provider_token TEXT, new_provider_token TEXT, issue_reason VARCHAR(64), created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS subscription_audit (channel_id BYTEA NOT NULL, device_key VARCHAR(255) NOT NULL, action VARCHAR(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key VARCHAR(255) NOT NULL, bucket_date VARCHAR(10) NOT NULL, messages_received BIGINT NOT NULL DEFAULT 0, messages_acked BIGINT NOT NULL DEFAULT 0, private_connected_count BIGINT NOT NULL DEFAULT 0, private_pull_count BIGINT NOT NULL DEFAULT 0, provider_success_count BIGINT NOT NULL DEFAULT 0, provider_failure_count BIGINT NOT NULL DEFAULT 0, private_outbox_enqueued_count BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date))",
];

const PG_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
];

const PG_RUNTIME_INDEX_STATEMENTS: &[&str] = &[
    "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx ON devices (device_key)",
    "CREATE INDEX IF NOT EXISTS devices_route_platform_type_updated_idx ON devices (platform, channel_type, route_updated_at)",
    "CREATE INDEX IF NOT EXISTS devices_route_provider_token_idx ON devices (provider_token)",
    "CREATE INDEX IF NOT EXISTS private_sessions_exp_idx ON private_sessions (expires_at)",
    "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx ON private_outbox (delivery_id)",
    "CREATE INDEX IF NOT EXISTS private_outbox_due_idx ON private_outbox (status, next_attempt_at, attempts)",
    "CREATE INDEX IF NOT EXISTS private_outbox_device_status_order_idx ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
    "CREATE INDEX IF NOT EXISTS private_bindings_device_idx ON private_bindings (device_id)",
    "CREATE INDEX IF NOT EXISTS private_bindings_token_idx ON private_bindings (platform, token_hash)",
    "CREATE UNIQUE INDEX IF NOT EXISTS private_bindings_platform_token_uidx ON private_bindings (platform, token_hash)",
    "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx ON channel_subscriptions (device_id)",
    "CREATE INDEX IF NOT EXISTS channel_subscriptions_dispatch_idx ON channel_subscriptions (channel_id, status, created_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS provider_pull_queue_device_delivery_uidx ON provider_pull_queue (device_id, delivery_id)",
    "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_created_idx ON provider_pull_queue (device_id, created_at)",
    "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_expires_idx ON provider_pull_queue (device_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS device_route_audit_device_created_idx ON device_route_audit (device_key, created_at)",
    "CREATE INDEX IF NOT EXISTS subscription_audit_channel_created_idx ON subscription_audit (channel_id, created_at)",
    "CREATE INDEX IF NOT EXISTS subscription_audit_device_created_idx ON subscription_audit (device_key, created_at)",
];

const PG_RUNTIME_DROP_STATEMENTS: &[&str] = &[
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
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
const EPOCH_NORMALIZATION_META_KEY: &str = "epoch_millis_normalized_v1";

impl PostgresDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        let pool = PgPool::connect(db_url).await?;
        let this = Self { pool };
        this.init_schema().await?;
        Ok(this)
    }

    async fn init_schema(&self) -> StoreResult<()> {
        self.ensure_pg_schema_meta_table().await?;
        self.ensure_pg_schema_migrations_table().await?;
        let applied_migrations = self.load_pg_schema_migrations().await?;
        validate_applied_schema_migrations(&applied_migrations)?;
        let plan = SchemaMigrationPlan::for_state(
            self.load_pg_schema_version().await?.as_deref(),
            self.pg_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        if let Some(migration) = plan.hard_reset_migration() {
            let started_at = Utc::now().timestamp();
            if let Err(err) = self.hard_reset_pg_runtime_tables().await {
                let _ = self
                    .record_pg_schema_migration(migration, started_at, false, Some(err.to_string()))
                    .await;
                return Err(err);
            }
        }

        for stmt in PG_BASE_TABLE_STATEMENTS
            .iter()
            .chain(PG_RUNTIME_TABLE_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        self.ensure_pg_column(
            "devices",
            "token_raw",
            "ALTER TABLE devices ADD COLUMN token_raw BYTEA",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "platform_code",
            "ALTER TABLE devices ADD COLUMN platform_code SMALLINT",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "device_key",
            "ALTER TABLE devices ADD COLUMN device_key VARCHAR(255)",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "platform",
            "ALTER TABLE devices ADD COLUMN platform VARCHAR(32)",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "channel_type",
            "ALTER TABLE devices ADD COLUMN channel_type VARCHAR(32)",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "provider_token",
            "ALTER TABLE devices ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_pg_column(
            "devices",
            "route_updated_at",
            "ALTER TABLE devices ADD COLUMN route_updated_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_bindings",
            "platform",
            "ALTER TABLE private_bindings ADD COLUMN platform SMALLINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "private_bindings",
            "provider_token",
            "ALTER TABLE private_bindings ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_pg_column(
            "private_bindings",
            "token_hash",
            "ALTER TABLE private_bindings ADD COLUMN token_hash BYTEA",
        )
        .await?;
        self.ensure_pg_column(
            "private_bindings",
            "created_at",
            "ALTER TABLE private_bindings ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "private_bindings",
            "updated_at",
            "ALTER TABLE private_bindings ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "occurred_at",
            "ALTER TABLE private_outbox ADD COLUMN occurred_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "created_at",
            "ALTER TABLE private_outbox ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "claimed_at",
            "ALTER TABLE private_outbox ADD COLUMN claimed_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "first_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN first_sent_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "last_attempt_at",
            "ALTER TABLE private_outbox ADD COLUMN last_attempt_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "acked_at",
            "ALTER TABLE private_outbox ADD COLUMN acked_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "fallback_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN fallback_sent_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "private_outbox",
            "last_error_detail",
            "ALTER TABLE private_outbox ADD COLUMN last_error_detail TEXT",
        )
        .await?;
        self.ensure_pg_column(
            "channel_subscriptions",
            "status",
            "ALTER TABLE channel_subscriptions ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active'",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "device_id",
            "ALTER TABLE provider_pull_queue ADD COLUMN device_id BYTEA",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "payload_blob",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_blob BYTEA",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "payload_size",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_size INTEGER",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "sent_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN sent_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "expires_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN expires_at BIGINT",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "platform",
            "ALTER TABLE provider_pull_queue ADD COLUMN platform VARCHAR(32)",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "provider_token",
            "ALTER TABLE provider_pull_queue ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "created_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_pg_column(
            "provider_pull_queue",
            "updated_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        for stmt in PG_BASE_INDEX_STATEMENTS
            .iter()
            .chain(PG_RUNTIME_INDEX_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        sqlx::query("DROP TABLE IF EXISTS delivery_audit")
            .execute(&self.pool)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS provider_pull_retry")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM provider_pull_queue \
             WHERE device_id IS NULL OR payload_blob IS NULL OR platform IS NULL OR provider_token IS NULL",
        )
        .execute(&self.pool)
        .await?;
        self.ensure_pg_provider_pull_queue_primary_key().await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS provider_pull_queue_device_delivery_uidx ON provider_pull_queue (device_id, delivery_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_created_idx ON provider_pull_queue (device_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_expires_idx ON provider_pull_queue (device_id, expires_at)",
        )
        .execute(&self.pool)
        .await?;
        self.normalize_pg_epoch_columns_to_millis_once().await?;

        self.store_pg_schema_version(STORAGE_SCHEMA_VERSION).await?;
        let migration_started_at = Utc::now().timestamp();
        for migration in &plan.pending_migrations {
            self.record_pg_schema_migration(*migration, migration_started_at, true, None)
                .await?;
        }
        Ok(())
    }

    async fn ensure_pg_schema_meta_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_pg_schema_version(&self) -> StoreResult<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn store_pg_schema_version(&self, version: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', $1) \
             ON CONFLICT (meta_key) DO UPDATE SET meta_value = EXCLUDED.meta_value",
        )
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn normalize_pg_epoch_columns_to_millis_once(&self) -> StoreResult<()> {
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
            ("device_route_audit", &["created_at"]),
            ("subscription_audit", &["created_at"]),
        ];

        let mut tx = self.pool.begin().await?;
        let marker_exists: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = $1")
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
                     WHERE {column} IS NOT NULL AND ABS({column}) < $1"
                );
                sqlx::query(&sql)
                    .bind(EPOCH_MILLIS_THRESHOLD)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ($1, $2) \
             ON CONFLICT (meta_key) DO UPDATE SET meta_value = EXCLUDED.meta_value",
        )
        .bind(EPOCH_NORMALIZATION_META_KEY)
        .bind("1")
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn ensure_pg_schema_migrations_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (\
                migration_id VARCHAR(128) PRIMARY KEY,\
                description TEXT NOT NULL,\
                checksum VARCHAR(255) NOT NULL,\
                target_schema_version VARCHAR(255) NOT NULL,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT NOT NULL,\
                execution_ms BIGINT NOT NULL,\
                success BOOLEAN NOT NULL,\
                error TEXT\
            )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_pg_schema_migrations(&self) -> StoreResult<Vec<AppliedSchemaMigration>> {
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
                success: row.get("success"),
            })
            .collect())
    }

    async fn record_pg_schema_migration(
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
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (migration_id) DO UPDATE SET \
               description = EXCLUDED.description, \
               checksum = EXCLUDED.checksum, \
               target_schema_version = EXCLUDED.target_schema_version, \
               started_at = EXCLUDED.started_at, \
               finished_at = EXCLUDED.finished_at, \
               execution_ms = EXCLUDED.execution_ms, \
               success = EXCLUDED.success, \
               error = EXCLUDED.error",
        )
        .bind(migration.id)
        .bind(migration.description)
        .bind(migration.checksum)
        .bind(migration.target_schema_version)
        .bind(started_at)
        .bind(finished_at)
        .bind(execution_ms)
        .bind(success)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn pg_runtime_tables_present(&self) -> StoreResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) \
             FROM information_schema.tables \
             WHERE table_schema = current_schema() \
               AND table_name IN ('devices', 'channel_subscriptions', 'private_bindings', 'provider_pull_queue')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    async fn ensure_pg_column(&self, table: &str, column: &str, ddl: &str) -> StoreResult<()> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
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

    async fn ensure_pg_provider_pull_queue_primary_key(&self) -> StoreResult<()> {
        let pk_columns: Vec<String> = sqlx::query_scalar(
            "SELECT a.attname \
             FROM pg_index i \
             JOIN pg_class t ON t.oid = i.indrelid \
             JOIN pg_namespace n ON n.oid = t.relnamespace \
             JOIN unnest(i.indkey) WITH ORDINALITY AS key(attnum, ord) ON TRUE \
             JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = key.attnum \
             WHERE n.nspname = current_schema() \
               AND t.relname = 'provider_pull_queue' \
               AND i.indisprimary \
             ORDER BY key.ord",
        )
        .fetch_all(&self.pool)
        .await?;
        if pk_columns.as_slice() == ["device_id", "delivery_id"] {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        let pk_constraint: Option<String> = sqlx::query_scalar(
            "SELECT tc.constraint_name \
             FROM information_schema.table_constraints tc \
             WHERE tc.table_schema = current_schema() \
               AND tc.table_name = 'provider_pull_queue' \
               AND tc.constraint_type = 'PRIMARY KEY' \
             LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(name) = pk_constraint {
            let escaped = name.replace('"', "\"\"");
            let ddl = format!("ALTER TABLE provider_pull_queue DROP CONSTRAINT \"{escaped}\"");
            sqlx::query(ddl.as_str()).execute(&mut *tx).await?;
        }
        sqlx::query("ALTER TABLE provider_pull_queue ALTER COLUMN device_id SET NOT NULL")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE provider_pull_queue ALTER COLUMN delivery_id SET NOT NULL")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE provider_pull_queue ADD PRIMARY KEY (device_id, delivery_id)")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn hard_reset_pg_runtime_tables(&self) -> StoreResult<()> {
        for stmt in PG_RUNTIME_DROP_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in PG_RUNTIME_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in PG_RUNTIME_INDEX_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        Ok(())
    }
}
