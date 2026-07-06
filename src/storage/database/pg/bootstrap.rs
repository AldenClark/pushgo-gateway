use super::*;
use crate::runtime_config::{GatewayRuntimeProfile, RuntimeTuning};
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
    "CREATE TABLE IF NOT EXISTS sender_submit_status (op_id VARCHAR(128) PRIMARY KEY, channel_id BYTEA NOT NULL, model VARCHAR(16) NOT NULL, entity_id VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL, dispatch_status VARCHAR(64), accepted_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS live_activity_tokens (activity_key VARCHAR(255) NOT NULL, token TEXT NOT NULL, channel_id BYTEA, platform VARCHAR(32) NOT NULL, schema_version INTEGER NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT, PRIMARY KEY (activity_key, token))",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key VARCHAR(64) PRIMARY KEY, state_json TEXT NOT NULL, updated_at BIGINT NOT NULL)",
];

const PG_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BYTEA PRIMARY KEY, token_raw BYTEA NOT NULL, platform_code SMALLINT NOT NULL, device_key VARCHAR(255), platform VARCHAR(32), channel_type VARCHAR(32), provider_token TEXT, route_updated_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BYTEA NOT NULL, key_id INTEGER NOT NULL, key_hash BYTEA NOT NULL, issued_at BIGINT NOT NULL, valid_until BIGINT, PRIMARY KEY (device_id, key_id))",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id VARCHAR(128) PRIMARY KEY, device_id BYTEA NOT NULL, expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0, claimed_at BIGINT, claimed_by TEXT, first_sent_at BIGINT, last_attempt_at BIGINT, acked_at BIGINT, fallback_sent_at BIGINT, next_attempt_at BIGINT NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BYTEA NOT NULL, device_id BYTEA NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (platform, token_hash))",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BYTEA NOT NULL, device_id BYTEA NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id))",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, payload_blob BYTEA NOT NULL, payload_size INTEGER NOT NULL, sent_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, platform VARCHAR(32) NOT NULL, provider_token TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id))",
];

const PG_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
    "CREATE INDEX IF NOT EXISTS sender_submit_status_expires_idx ON sender_submit_status (expires_at)",
    "CREATE INDEX IF NOT EXISTS live_activity_tokens_channel_idx ON live_activity_tokens (channel_id, updated_at)",
    "CREATE INDEX IF NOT EXISTS live_activity_tokens_expires_idx ON live_activity_tokens (expires_at)",
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
const PG_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS: &[&str] = &[
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

impl PostgresDb {
    pub async fn new(db_url: &str, runtime_profile: GatewayRuntimeProfile) -> StoreResult<Self> {
        let tuning = RuntimeTuning::for_profile(runtime_profile).external_db;
        let pool = PgPoolOptions::new()
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
        let pool = PgPoolOptions::new()
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
            driver = %("postgres")
        );
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
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "db.schema_hard_reset_started",
                driver = %("postgres"),
                migration_id = %(migration.id)
            );
            if let Err(err) = self.hard_reset_pg_runtime_tables().await {
                let _ = self
                    .record_pg_schema_migration(migration, started_at, false, Some(err.to_string()))
                    .await;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "db.schema_hard_reset_failed",
                    driver = %("postgres"),
                    migration_id = %(migration.id),
                    error = %(err.to_string())
                );
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
            "claimed_by",
            "ALTER TABLE private_outbox ADD COLUMN claimed_by TEXT",
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
        for stmt in PG_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS {
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
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_finished",
            driver = %("postgres"),
            target_schema_version = %(STORAGE_SCHEMA_VERSION),
            pending_migrations = (plan.pending_migrations.len() as u64)
        );
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

pub(crate) struct PgUpgradeLockGuard {
    pool: sqlx::PgPool,
}

impl Drop for PgUpgradeLockGuard {
    fn drop(&mut self) {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("SELECT pg_advisory_unlock(784477031742001)")
                .execute(&pool)
                .await;
        });
    }
}

impl PostgresDb {
    pub(crate) async fn inspect_upgrade_plan(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<
        crate::storage::database::upgrade::UpgradePlan,
    > {
        let applied_migrations = if self.pg_table_exists("pushgo_schema_migrations").await? {
            self.load_pg_schema_migrations().await?
        } else {
            Vec::new()
        };
        validate_applied_schema_migrations(&applied_migrations)?;
        let current_version = if self.pg_table_exists("pushgo_schema_meta").await? {
            self.load_pg_schema_version().await?
        } else {
            None
        };
        let plan = SchemaMigrationPlan::for_state(
            current_version.as_deref(),
            self.pg_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        Ok(crate::storage::database::upgrade::UpgradePlan::from_schema_plan(plan))
    }

    async fn pg_table_exists(&self, table: &str) -> StoreResult<bool> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1::BIGINT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1 LIMIT 1",
        )
        .bind(table)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }
}

impl crate::storage::database::upgrade::lock::UpgradeLockAccess for PostgresDb {
    type Guard = PgUpgradeLockGuard;

    async fn acquire_upgrade_lock(
        &self,
        _db_url: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<Self::Guard> {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(784477031742001)")
            .fetch_one(&self.pool)
            .await?;
        if !locked {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade(
                    "postgres advisory upgrade lock is held by another process; stop other gateway instances or wait for the upgrade to finish".to_string(),
                ),
            ));
        }
        Ok(PgUpgradeLockGuard {
            pool: self.pool.clone(),
        })
    }
}

impl crate::storage::database::upgrade::state::UpgradeStateAccess for PostgresDb {
    async fn ensure_upgrade_state_tables(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_upgrade_runs (\
                run_id VARCHAR(64) PRIMARY KEY,\
                gateway_version TEXT NOT NULL,\
                driver TEXT NOT NULL,\
                from_schema_version TEXT,\
                target_schema_version TEXT NOT NULL,\
                status TEXT NOT NULL,\
                backup_uri TEXT,\
                backup_sha256 TEXT,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT,\
                error TEXT\
            )",
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
                status TEXT NOT NULL,\
                started_at BIGINT NOT NULL,\
                finished_at BIGINT,\
                error TEXT,\
                PRIMARY KEY (run_id, step_order)\
            )",
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
             VALUES ($1, $2, $3, $4, $5, 'planned', $6)",
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
             SET status = $1, backup_uri = COALESCE($2, backup_uri), backup_sha256 = COALESCE($3, backup_sha256), finished_at = COALESCE($4, finished_at), error = COALESCE($5, error) \
             WHERE run_id = $6",
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
             VALUES ($1, $2, $3, $4, $5, 'planned', $6)",
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
            "UPDATE pushgo_upgrade_steps SET status = $1, finished_at = COALESCE($2, finished_at), error = COALESCE($3, error) WHERE run_id = $4 AND step_order = $5",
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

impl crate::storage::database::upgrade::backup::UpgradeBackupAccess for PostgresDb {
    async fn create_upgrade_backup(
        &self,
        _db_url: &str,
        _driver: crate::storage::types::DatabaseKind,
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
        let snapshot = external_snapshot_or_test_default("PostgreSQL")?;
        Ok(Some(
            crate::storage::database::upgrade::backup::BackupArtifact {
                uri: format!("postgres-external-snapshot:{snapshot}:{run_id}"),
                sha256: "external".to_string(),
                bytes: 0,
            },
        ))
    }

    async fn restore_upgrade_backup(
        &self,
        _db_url: &str,
        _artifact: &crate::storage::database::upgrade::backup::BackupArtifact,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        Err(crate::storage::database::upgrade::UpgradeError::Store(
            StoreError::Upgrade(
                "PostgreSQL rollback requires manual restore from the recorded external snapshot or pg_restore artifact".to_string(),
            ),
        ))
    }
}

fn external_snapshot_or_test_default(
    driver: &str,
) -> crate::storage::database::upgrade::UpgradeResult<String> {
    match std::env::var("PUSHGO_DB_UPGRADE_EXTERNAL_SNAPSHOT") {
        Ok(value) => Ok(value),
        Err(_) => {
            #[cfg(test)]
            {
                Ok(format!("{}-test-snapshot", driver.to_ascii_lowercase()))
            }
            #[cfg(not(test))]
            {
                Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!(
                        "{driver} upgrade requires PUSHGO_DB_UPGRADE_EXTERNAL_SNAPSHOT or an operator-run dump before destructive/runtime-reset migrations"
                    )),
                ))
            }
        }
    }
}

impl crate::storage::database::upgrade::verify::UpgradeVerifyAccess for PostgresDb {
    async fn verify_upgrade(
        &self,
        target_schema_version: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        let schema_version = self.load_pg_schema_version().await?;
        if schema_version.as_deref() != Some(target_schema_version) {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::SchemaVersionMismatch {
                    expected: target_schema_version.to_string(),
                    actual: schema_version.unwrap_or_else(|| "none".to_string()),
                },
            ));
        }
        validate_applied_schema_migrations(&self.load_pg_schema_migrations().await?)?;
        for table in [
            "channels",
            "devices",
            "channel_subscriptions",
            "private_payloads",
            "sender_submit_status",
            "pushgo_upgrade_runs",
            "pushgo_upgrade_steps",
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1::BIGINT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1 LIMIT 1",
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
        Ok(())
    }
}
