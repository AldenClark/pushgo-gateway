use super::*;
use crate::storage::database::migration::{
    AppliedSchemaMigration, SchemaMigrationDefinition, SchemaMigrationPlan,
    validate_applied_schema_migrations,
};

const SQLITE_BASE_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key TEXT PRIMARY KEY, semantic_id TEXT NOT NULL UNIQUE, source TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BLOB NOT NULL, bucket_date TEXT NOT NULL, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_enqueued INTEGER NOT NULL DEFAULT 0, provider_attempted INTEGER NOT NULL DEFAULT 0, provider_failed INTEGER NOT NULL DEFAULT 0, provider_success INTEGER NOT NULL DEFAULT 0, private_realtime_delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))",
    "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour TEXT PRIMARY KEY, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_outbox_depth_max INTEGER NOT NULL DEFAULT 0, dedupe_pending_max INTEGER NOT NULL DEFAULT 0, active_private_sessions_max INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS ops_stats_hourly (bucket_hour TEXT NOT NULL, metric_key TEXT NOT NULL, metric_value INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_hour, metric_key))",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
];

const SQLITE_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, token_raw BLOB NOT NULL, platform_code INTEGER NOT NULL, device_key TEXT, platform TEXT, channel_type TEXT, provider_token TEXT, route_updated_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BLOB NOT NULL, key_id INTEGER NOT NULL, key_hash BLOB NOT NULL, issued_at INTEGER NOT NULL, valid_until INTEGER, PRIMARY KEY (device_id, key_id))",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id TEXT PRIMARY KEY, device_id BLOB NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (platform, token_hash))",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS device_route_audit (device_key TEXT NOT NULL, action TEXT NOT NULL, old_platform TEXT, new_platform TEXT, old_channel_type TEXT, new_channel_type TEXT, old_provider_token TEXT, new_provider_token TEXT, issue_reason TEXT, created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS subscription_audit (channel_id BLOB NOT NULL, device_key TEXT NOT NULL, action TEXT NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key TEXT NOT NULL, bucket_date TEXT NOT NULL, messages_received INTEGER NOT NULL DEFAULT 0, messages_acked INTEGER NOT NULL DEFAULT 0, private_connected_count INTEGER NOT NULL DEFAULT 0, private_pull_count INTEGER NOT NULL DEFAULT 0, provider_success_count INTEGER NOT NULL DEFAULT 0, provider_failure_count INTEGER NOT NULL DEFAULT 0, private_outbox_enqueued_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date))",
];

const SQLITE_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
];

const SQLITE_DISPATCH_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key TEXT PRIMARY KEY, semantic_id TEXT NOT NULL UNIQUE, source TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen_at INTEGER, expires_at INTEGER)",
];

const SQLITE_DISPATCH_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
];

const SQLITE_DELIVERY_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
];

const SQLITE_DELIVERY_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx ON private_outbox (delivery_id)",
    "CREATE INDEX IF NOT EXISTS private_outbox_due_idx ON private_outbox (status, next_attempt_at, attempts)",
    "CREATE INDEX IF NOT EXISTS private_outbox_device_status_order_idx ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS provider_pull_queue_device_delivery_uidx ON provider_pull_queue (device_id, delivery_id)",
    "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_created_idx ON provider_pull_queue (device_id, created_at)",
    "CREATE INDEX IF NOT EXISTS provider_pull_queue_device_expires_idx ON provider_pull_queue (device_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS provider_pull_queue_platform_token_idx ON provider_pull_queue (platform, provider_token)",
];

const SQLITE_RUNTIME_INDEX_STATEMENTS: &[&str] = &[
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

const SQLITE_RUNTIME_DROP_STATEMENTS: &[&str] = &[
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
const SQLITE_TELEMETRY_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BLOB NOT NULL, bucket_date TEXT NOT NULL, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_enqueued INTEGER NOT NULL DEFAULT 0, provider_attempted INTEGER NOT NULL DEFAULT 0, provider_failed INTEGER NOT NULL DEFAULT 0, provider_success INTEGER NOT NULL DEFAULT 0, private_realtime_delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))",
    "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key TEXT NOT NULL, bucket_date TEXT NOT NULL, messages_received INTEGER NOT NULL DEFAULT 0, messages_acked INTEGER NOT NULL DEFAULT 0, private_connected_count INTEGER NOT NULL DEFAULT 0, private_pull_count INTEGER NOT NULL DEFAULT 0, provider_success_count INTEGER NOT NULL DEFAULT 0, provider_failure_count INTEGER NOT NULL DEFAULT 0, private_outbox_enqueued_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date))",
    "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour TEXT PRIMARY KEY, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_outbox_depth_max INTEGER NOT NULL DEFAULT 0, dedupe_pending_max INTEGER NOT NULL DEFAULT 0, active_private_sessions_max INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS ops_stats_hourly (bucket_hour TEXT NOT NULL, metric_key TEXT NOT NULL, metric_value INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_hour, metric_key))",
];
const SQLITE_RUNTIME_SIDECAR_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
];
const SQLITE_SIDECAR_META_TABLE: &str = "CREATE TABLE IF NOT EXISTS pushgo_sidecar_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)";
const SQLITE_DISPATCH_MIGRATION_META_KEY: &str = "dispatch_migrated_from_core_v1";
const SQLITE_TELEMETRY_MIGRATION_META_KEY: &str = "telemetry_migrated_from_core_v1";
const SQLITE_RUNTIME_MIGRATION_META_KEY: &str = "runtime_migrated_from_core_v1";
const SQLITE_DELIVERY_MIGRATION_META_KEY: &str = "runtime_delivery_migrated_from_core_v1";
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
const EPOCH_NORMALIZATION_META_KEY: &str = "epoch_millis_normalized_v1";

impl SqliteDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        Self::new_with_config(db_url, None, None, true, true).await
    }

    pub async fn new_with_config(
        db_url: &str,
        telemetry_db_url: Option<&str>,
        runtime_db_url: Option<&str>,
        stats_enabled: bool,
        mcp_enabled: bool,
    ) -> StoreResult<Self> {
        ensure_sqlite_parent_dir(db_url)?;
        let core_read_pool = connect_sqlite_pool(
            db_url,
            sqlite_core_read_connections(),
            Duration::from_secs(sqlite_core_read_acquire_timeout_secs()),
        )
        .await?;
        let pool = connect_sqlite_pool(
            db_url,
            1,
            Duration::from_secs(sqlite_core_write_acquire_timeout_secs()),
        )
        .await?;
        let delivery_url = derive_sqlite_sidecar_url(db_url, "delivery");
        let dispatch_url = derive_sqlite_sidecar_url(db_url, "dispatch");
        let telemetry_url = stats_enabled.then(|| {
            telemetry_db_url
                .map(str::to_string)
                .unwrap_or_else(|| derive_sqlite_sidecar_url(db_url, "telemetry"))
        });
        let runtime_url = mcp_enabled.then(|| {
            runtime_db_url
                .map(str::to_string)
                .unwrap_or_else(|| derive_sqlite_sidecar_url(db_url, "runtime"))
        });
        ensure_sqlite_parent_dir(delivery_url.as_str())?;
        let delivery_pool = connect_sqlite_pool(
            delivery_url.as_str(),
            1,
            Duration::from_millis(sqlite_sidecar_acquire_timeout_millis()),
        )
        .await?;
        ensure_sqlite_parent_dir(dispatch_url.as_str())?;
        let dispatch_pool = connect_sqlite_pool(
            dispatch_url.as_str(),
            1,
            Duration::from_millis(sqlite_sidecar_acquire_timeout_millis()),
        )
        .await?;
        let telemetry_pool = if let Some(url) = telemetry_url.as_deref() {
            ensure_sqlite_parent_dir(url)?;
            let pool = connect_sqlite_pool(
                url,
                1,
                Duration::from_millis(sqlite_sidecar_acquire_timeout_millis()),
            )
            .await?;
            Some(pool)
        } else {
            None
        };
        let runtime_pool = if let Some(url) = runtime_url.as_deref() {
            ensure_sqlite_parent_dir(url)?;
            let pool = connect_sqlite_pool(
                url,
                1,
                Duration::from_millis(sqlite_sidecar_acquire_timeout_millis()),
            )
            .await?;
            Some(pool)
        } else {
            None
        };
        let this = Self {
            core_read_pool,
            delivery_pool,
            dispatch_pool,
            telemetry_pool,
            runtime_pool,
            pool,
        };
        this.init_schema().await?;
        this.init_delivery_sidecar(db_url, delivery_url.as_str())
            .await?;
        this.init_dispatch_sidecar(db_url, dispatch_url.as_str())
            .await?;
        if let Some(url) = telemetry_url.as_deref() {
            this.init_telemetry_sidecar(db_url, url).await?;
        }
        if let Some(url) = runtime_url.as_deref() {
            this.init_runtime_sidecar(db_url, url).await?;
        }
        Ok(this)
    }

    async fn init_schema(&self) -> StoreResult<()> {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_started",
            driver = %("sqlite")
        );
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        let busy_timeout = format!("PRAGMA busy_timeout = {}", sqlite_busy_timeout_millis());
        sqlx::query(busy_timeout.as_str())
            .execute(&self.pool)
            .await?;
        let cache_size = format!("PRAGMA cache_size = -{}", sqlite_page_cache_kib());
        sqlx::query(cache_size.as_str()).execute(&self.pool).await?;
        let wal_autocheckpoint = format!(
            "PRAGMA wal_autocheckpoint = {}",
            sqlite_wal_autocheckpoint()
        );
        sqlx::query(wal_autocheckpoint.as_str())
            .execute(&self.pool)
            .await?;

        self.ensure_sqlite_schema_meta_table().await?;
        self.ensure_sqlite_schema_migrations_table().await?;
        let applied_migrations = self.load_sqlite_schema_migrations().await?;
        validate_applied_schema_migrations(&applied_migrations)?;
        let plan = SchemaMigrationPlan::for_state(
            self.load_sqlite_schema_version().await?.as_deref(),
            self.sqlite_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        if let Some(migration) = plan.hard_reset_migration() {
            let started_at = Utc::now().timestamp();
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "db.schema_hard_reset_started",
                driver = %("sqlite"),
                migration_id = %(migration.id)
            );
            if let Err(err) = self.hard_reset_sqlite_runtime_tables().await {
                let _ = self
                    .record_sqlite_schema_migration(
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
                    driver = %("sqlite"),
                    migration_id = %(migration.id),
                    error = %(err.to_string())
                );
                return Err(err);
            }
        }

        for stmt in SQLITE_BASE_TABLE_STATEMENTS
            .iter()
            .chain(SQLITE_RUNTIME_TABLE_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        self.ensure_sqlite_column(
            "devices",
            "token_raw",
            "ALTER TABLE devices ADD COLUMN token_raw BLOB",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "platform_code",
            "ALTER TABLE devices ADD COLUMN platform_code INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "device_key",
            "ALTER TABLE devices ADD COLUMN device_key TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "platform",
            "ALTER TABLE devices ADD COLUMN platform TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "channel_type",
            "ALTER TABLE devices ADD COLUMN channel_type TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "provider_token",
            "ALTER TABLE devices ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "devices",
            "route_updated_at",
            "ALTER TABLE devices ADD COLUMN route_updated_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_bindings",
            "platform",
            "ALTER TABLE private_bindings ADD COLUMN platform INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_bindings",
            "provider_token",
            "ALTER TABLE private_bindings ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_bindings",
            "created_at",
            "ALTER TABLE private_bindings ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_bindings",
            "updated_at",
            "ALTER TABLE private_bindings ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_bindings",
            "token_hash",
            "ALTER TABLE private_bindings ADD COLUMN token_hash BLOB",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "occurred_at",
            "ALTER TABLE private_outbox ADD COLUMN occurred_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "created_at",
            "ALTER TABLE private_outbox ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "claimed_at",
            "ALTER TABLE private_outbox ADD COLUMN claimed_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "first_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN first_sent_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "last_attempt_at",
            "ALTER TABLE private_outbox ADD COLUMN last_attempt_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "acked_at",
            "ALTER TABLE private_outbox ADD COLUMN acked_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "fallback_sent_at",
            "ALTER TABLE private_outbox ADD COLUMN fallback_sent_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "last_error_detail",
            "ALTER TABLE private_outbox ADD COLUMN last_error_detail TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "status",
            "ALTER TABLE channel_subscriptions ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "device_id",
            "ALTER TABLE provider_pull_queue ADD COLUMN device_id BLOB",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "payload_blob",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_blob BLOB",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "payload_size",
            "ALTER TABLE provider_pull_queue ADD COLUMN payload_size INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "sent_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN sent_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "expires_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN expires_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "platform",
            "ALTER TABLE provider_pull_queue ADD COLUMN platform TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "provider_token",
            "ALTER TABLE provider_pull_queue ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "created_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_pull_queue",
            "updated_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        for stmt in SQLITE_BASE_INDEX_STATEMENTS
            .iter()
            .chain(SQLITE_RUNTIME_INDEX_STATEMENTS.iter())
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
        self.ensure_sqlite_provider_pull_queue_primary_key().await?;
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
        self.normalize_sqlite_epoch_columns_to_millis_once().await?;

        self.store_sqlite_schema_version(STORAGE_SCHEMA_VERSION)
            .await?;
        let migration_started_at = Utc::now().timestamp();
        for migration in &plan.pending_migrations {
            self.record_sqlite_schema_migration(*migration, migration_started_at, true, None)
                .await?;
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_finished",
            driver = %("sqlite"),
            target_schema_version = %(STORAGE_SCHEMA_VERSION),
            pending_migrations = (plan.pending_migrations.len() as u64)
        );
        Ok(())
    }

    async fn init_dispatch_sidecar(
        &self,
        core_db_url: &str,
        sidecar_db_url: &str,
    ) -> StoreResult<()> {
        sqlx::query(SQLITE_SIDECAR_META_TABLE)
            .execute(&self.dispatch_pool)
            .await?;
        for stmt in SQLITE_DISPATCH_TABLE_STATEMENTS
            .iter()
            .chain(SQLITE_DISPATCH_INDEX_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.dispatch_pool).await?;
        }
        migrate_sidecar_tables_once(
            &self.dispatch_pool,
            core_db_url,
            sidecar_db_url,
            SQLITE_DISPATCH_MIGRATION_META_KEY,
            &[
                "dispatch_delivery_dedupe",
                "dispatch_op_dedupe",
                "semantic_id_registry",
            ],
        )
        .await
    }

    async fn init_delivery_sidecar(
        &self,
        core_db_url: &str,
        sidecar_db_url: &str,
    ) -> StoreResult<()> {
        sqlx::query(SQLITE_SIDECAR_META_TABLE)
            .execute(&self.delivery_pool)
            .await?;
        for stmt in SQLITE_DELIVERY_TABLE_STATEMENTS
            .iter()
            .chain(SQLITE_DELIVERY_INDEX_STATEMENTS.iter())
        {
            sqlx::query(stmt).execute(&self.delivery_pool).await?;
        }
        if sqlite_url_without_query(core_db_url) != sqlite_url_without_query(sidecar_db_url) {
            self.sync_delivery_sidecar_from_core(core_db_url).await?;
            sqlx::query(
                "INSERT INTO pushgo_sidecar_meta (meta_key, meta_value) VALUES (?, 'done') \
                 ON CONFLICT (meta_key) DO UPDATE SET meta_value = excluded.meta_value",
            )
            .bind(SQLITE_DELIVERY_MIGRATION_META_KEY)
            .execute(&self.delivery_pool)
            .await?;
            for table in ["provider_pull_queue", "private_outbox", "private_payloads"] {
                sqlx::query(&format!("DELETE FROM {table}"))
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn sync_delivery_sidecar_from_core(&self, core_db_url: &str) -> StoreResult<()> {
        let Some(core_path) = sqlite_path_from_url(core_db_url) else {
            return Ok(());
        };
        let mut conn = self.delivery_pool.acquire().await?;
        sqlx::query("ATTACH DATABASE ? AS pushgo_core")
            .bind(core_path)
            .execute(&mut *conn)
            .await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;

        if sqlite_attached_table_exists(&mut tx, "pushgo_core", "private_payloads").await? {
            sqlx::query(
                "INSERT INTO private_payloads \
                 (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
                 SELECT delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at \
                 FROM pushgo_core.private_payloads WHERE true \
                 ON CONFLICT(delivery_id) DO UPDATE SET \
                   payload_blob = excluded.payload_blob, \
                   payload_size = excluded.payload_size, \
                   sent_at = excluded.sent_at, \
                   expires_at = excluded.expires_at, \
                   created_at = excluded.created_at, \
                   updated_at = excluded.updated_at \
                 WHERE excluded.updated_at >= private_payloads.updated_at",
            )
            .execute(&mut *tx)
            .await?;
        }
        if sqlite_attached_table_exists(&mut tx, "pushgo_core", "private_outbox").await? {
            sqlx::query(
                "INSERT INTO private_outbox \
                 (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                 SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                 FROM pushgo_core.private_outbox WHERE true \
                 ON CONFLICT(device_id, delivery_id) DO UPDATE SET \
                   status = excluded.status, \
                   attempts = excluded.attempts, \
                   occurred_at = excluded.occurred_at, \
                   created_at = excluded.created_at, \
                   claimed_at = excluded.claimed_at, \
                   first_sent_at = excluded.first_sent_at, \
                   last_attempt_at = excluded.last_attempt_at, \
                   acked_at = excluded.acked_at, \
                   fallback_sent_at = excluded.fallback_sent_at, \
                   next_attempt_at = excluded.next_attempt_at, \
                   last_error_code = excluded.last_error_code, \
                   last_error_detail = excluded.last_error_detail, \
                   updated_at = excluded.updated_at \
                 WHERE excluded.updated_at >= private_outbox.updated_at",
            )
            .execute(&mut *tx)
            .await?;
        }
        if sqlite_attached_table_exists(&mut tx, "pushgo_core", "provider_pull_queue").await? {
            sqlx::query(
                "INSERT INTO provider_pull_queue \
                 (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
                 SELECT device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at \
                 FROM pushgo_core.provider_pull_queue WHERE true \
                 ON CONFLICT(device_id, delivery_id) DO UPDATE SET \
                   payload_blob = excluded.payload_blob, \
                   payload_size = excluded.payload_size, \
                   sent_at = excluded.sent_at, \
                   expires_at = excluded.expires_at, \
                   platform = excluded.platform, \
                   provider_token = excluded.provider_token, \
                   created_at = excluded.created_at, \
                   updated_at = excluded.updated_at \
                 WHERE excluded.updated_at >= provider_pull_queue.updated_at",
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        sqlx::query("DETACH DATABASE pushgo_core")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn init_telemetry_sidecar(
        &self,
        core_db_url: &str,
        sidecar_db_url: &str,
    ) -> StoreResult<()> {
        let Some(pool) = &self.telemetry_pool else {
            return Ok(());
        };
        sqlx::query(SQLITE_SIDECAR_META_TABLE).execute(pool).await?;
        for stmt in SQLITE_TELEMETRY_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(pool).await?;
        }
        migrate_sidecar_tables_once(
            pool,
            core_db_url,
            sidecar_db_url,
            SQLITE_TELEMETRY_MIGRATION_META_KEY,
            &[
                "channel_stats_daily",
                "device_stats_daily",
                "gateway_stats_hourly",
                "ops_stats_hourly",
            ],
        )
        .await
    }

    async fn init_runtime_sidecar(
        &self,
        core_db_url: &str,
        sidecar_db_url: &str,
    ) -> StoreResult<()> {
        let Some(pool) = &self.runtime_pool else {
            return Ok(());
        };
        sqlx::query(SQLITE_SIDECAR_META_TABLE).execute(pool).await?;
        for stmt in SQLITE_RUNTIME_SIDECAR_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(pool).await?;
        }
        migrate_sidecar_tables_once(
            pool,
            core_db_url,
            sidecar_db_url,
            SQLITE_RUNTIME_MIGRATION_META_KEY,
            &["mcp_state"],
        )
        .await
    }

    async fn ensure_sqlite_schema_meta_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_sqlite_schema_version(&self) -> StoreResult<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn store_sqlite_schema_version(&self, version: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?) \
             ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value",
        )
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn normalize_sqlite_epoch_columns_to_millis_once(&self) -> StoreResult<()> {
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
             ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value",
        )
        .bind(EPOCH_NORMALIZATION_META_KEY)
        .bind("1")
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn ensure_sqlite_schema_migrations_table(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_migrations (\
                migration_id TEXT PRIMARY KEY,\
                description TEXT NOT NULL,\
                checksum TEXT NOT NULL,\
                target_schema_version TEXT NOT NULL,\
                started_at INTEGER NOT NULL,\
                finished_at INTEGER NOT NULL,\
                execution_ms INTEGER NOT NULL,\
                success INTEGER NOT NULL,\
                error TEXT\
            )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_sqlite_schema_migrations(&self) -> StoreResult<Vec<AppliedSchemaMigration>> {
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
                success: row.get::<i64, _>("success") != 0,
            })
            .collect())
    }

    async fn record_sqlite_schema_migration(
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
             ON CONFLICT(migration_id) DO UPDATE SET \
               description = excluded.description, \
               checksum = excluded.checksum, \
               target_schema_version = excluded.target_schema_version, \
               started_at = excluded.started_at, \
               finished_at = excluded.finished_at, \
               execution_ms = excluded.execution_ms, \
               success = excluded.success, \
               error = excluded.error",
        )
        .bind(migration.id)
        .bind(migration.description)
        .bind(migration.checksum)
        .bind(migration.target_schema_version)
        .bind(started_at)
        .bind(finished_at)
        .bind(execution_ms)
        .bind(if success { 1_i64 } else { 0_i64 })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn sqlite_runtime_tables_present(&self) -> StoreResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) \
             FROM sqlite_master \
             WHERE type = 'table' \
               AND name IN ('devices', 'channel_subscriptions', 'private_bindings', 'provider_pull_queue')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    async fn ensure_sqlite_column(&self, table: &str, column: &str, ddl: &str) -> StoreResult<()> {
        let rows = sqlx::query(format!("PRAGMA table_info({table})").as_str())
            .fetch_all(&self.pool)
            .await?;
        let exists = rows
            .into_iter()
            .any(|r| r.get::<String, _>("name") == column);
        if !exists {
            sqlx::query(ddl).execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn ensure_sqlite_provider_pull_queue_primary_key(&self) -> StoreResult<()> {
        let rows = sqlx::query("PRAGMA table_info(provider_pull_queue)")
            .fetch_all(&self.pool)
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut pk_columns: Vec<(i64, String)> = rows
            .into_iter()
            .filter_map(|row| {
                let pk_order = row.get::<i64, _>("pk");
                if pk_order <= 0 {
                    return None;
                }
                Some((pk_order, row.get::<String, _>("name")))
            })
            .collect();
        pk_columns.sort_by_key(|(order, _)| *order);
        let pk_names: Vec<&str> = pk_columns.iter().map(|(_, name)| name.as_str()).collect();
        if pk_names == ["device_id", "delivery_id"] {
            return Ok(());
        }

        // Legacy schema used PRIMARY KEY(delivery_id), which blocks multi-device
        // queue rows for the same delivery.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "CREATE TABLE provider_pull_queue_new (\
                device_id BLOB NOT NULL,\
                delivery_id TEXT NOT NULL,\
                payload_blob BLOB NOT NULL,\
                payload_size INTEGER NOT NULL,\
                sent_at INTEGER NOT NULL,\
                expires_at INTEGER NOT NULL,\
                platform TEXT NOT NULL,\
                provider_token TEXT NOT NULL,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                PRIMARY KEY (device_id, delivery_id)\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO provider_pull_queue_new \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             SELECT \
                 device_id,\
                 delivery_id,\
                 payload_blob,\
                 COALESCE(payload_size, 0),\
                 COALESCE(sent_at, 0),\
                 COALESCE(expires_at, 0),\
                 platform,\
                 provider_token,\
                 COALESCE(created_at, 0),\
                 COALESCE(updated_at, 0) \
             FROM provider_pull_queue \
             WHERE device_id IS NOT NULL \
               AND delivery_id IS NOT NULL \
               AND payload_blob IS NOT NULL \
               AND platform IS NOT NULL \
               AND provider_token IS NOT NULL",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE provider_pull_queue")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE provider_pull_queue_new RENAME TO provider_pull_queue")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn hard_reset_sqlite_runtime_tables(&self) -> StoreResult<()> {
        for stmt in SQLITE_RUNTIME_DROP_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in SQLITE_RUNTIME_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        for stmt in SQLITE_RUNTIME_INDEX_STATEMENTS {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        Ok(())
    }
}

fn ensure_sqlite_parent_dir(db_url: &str) -> StoreResult<()> {
    let Some(raw_path) = db_url
        .trim()
        .strip_prefix("sqlite://")
        .and_then(|rest| rest.split('?').next())
    else {
        return Ok(());
    };
    if raw_path.is_empty() || raw_path == ":memory:" {
        return Ok(());
    }
    let path_part = raw_path.strip_prefix("file:").unwrap_or(raw_path);
    if path_part.is_empty() || path_part == ":memory:" {
        return Ok(());
    }
    if let Some(parent) = Path::new(path_part).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

async fn connect_sqlite_pool(
    db_url: &str,
    max_connections: u32,
    acquire_timeout: Duration,
) -> StoreResult<SqlitePool> {
    let sqlite_idle_timeout_secs = read_env_u64("PUSHGO_SQLITE_IDLE_TIMEOUT_SECS", 60, 1, 3600);
    let sqlite_statement_cache_capacity =
        read_env_usize("PUSHGO_SQLITE_STATEMENT_CACHE_CAPACITY", 32, 0, 512);
    let sqlite_page_cache_kib = sqlite_page_cache_kib();
    let sqlite_wal_autocheckpoint = sqlite_wal_autocheckpoint();
    let connect_options = SqliteConnectOptions::from_str(db_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .statement_cache_capacity(sqlite_statement_cache_capacity)
        .busy_timeout(Duration::from_millis(sqlite_busy_timeout_millis()));
    Ok(SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(0)
        .acquire_timeout(acquire_timeout)
        .idle_timeout(Duration::from_secs(sqlite_idle_timeout_secs))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                let cache_size = format!("PRAGMA cache_size = -{sqlite_page_cache_kib}");
                conn.execute(cache_size.as_str()).await?;
                let wal_autocheckpoint =
                    format!("PRAGMA wal_autocheckpoint = {sqlite_wal_autocheckpoint}");
                conn.execute(wal_autocheckpoint.as_str()).await?;
                Ok(())
            })
        })
        .connect_with(connect_options)
        .await?)
}

async fn migrate_sidecar_tables_once(
    sidecar_pool: &SqlitePool,
    core_db_url: &str,
    sidecar_db_url: &str,
    meta_key: &str,
    tables: &[&str],
) -> StoreResult<()> {
    let migrated: Option<String> =
        sqlx::query_scalar("SELECT meta_value FROM pushgo_sidecar_meta WHERE meta_key = ?")
            .bind(meta_key)
            .fetch_optional(sidecar_pool)
            .await?;
    if migrated.is_some()
        || sqlite_url_without_query(core_db_url) == sqlite_url_without_query(sidecar_db_url)
    {
        return Ok(());
    }
    let Some(core_path) = sqlite_path_from_url(core_db_url) else {
        return Ok(());
    };
    let mut conn = sidecar_pool.acquire().await?;
    sqlx::query("ATTACH DATABASE ? AS pushgo_core")
        .bind(core_path)
        .execute(&mut *conn)
        .await?;
    let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
    for table in tables {
        if sqlite_attached_table_exists(&mut tx, "pushgo_core", table).await? {
            let sql = format!("INSERT OR IGNORE INTO {table} SELECT * FROM pushgo_core.{table}");
            sqlx::query(sql.as_str()).execute(&mut *tx).await?;
        }
    }
    sqlx::query(
        "INSERT INTO pushgo_sidecar_meta (meta_key, meta_value) VALUES (?, 'done') \
         ON CONFLICT (meta_key) DO UPDATE SET meta_value = excluded.meta_value",
    )
    .bind(meta_key)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    sqlx::query("DETACH DATABASE pushgo_core")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn sqlite_attached_table_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &str,
    table: &str,
) -> StoreResult<bool> {
    let sql =
        format!("SELECT 1 FROM {schema}.sqlite_master WHERE type = 'table' AND name = ? LIMIT 1");
    let exists: Option<i64> = sqlx::query_scalar(sql.as_str())
        .bind(table)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(exists.is_some())
}

fn derive_sqlite_sidecar_url(db_url: &str, suffix: &str) -> String {
    let (base, query) = db_url.split_once('?').unwrap_or((db_url, ""));
    let query = if query.is_empty() {
        "?mode=rwc".to_string()
    } else {
        format!("?{query}")
    };
    let sidecar_base = if let Some(prefix) = base.strip_suffix(".sqlite") {
        format!("{prefix}.{suffix}.sqlite")
    } else if let Some(prefix) = base.strip_suffix(".db") {
        format!("{prefix}.{suffix}.db")
    } else {
        format!("{base}.{suffix}.db")
    };
    sidecar_base + query.as_str()
}

fn sqlite_url_without_query(db_url: &str) -> &str {
    db_url
        .split_once('?')
        .map(|(base, _)| base)
        .unwrap_or(db_url)
}

fn sqlite_path_from_url(db_url: &str) -> Option<String> {
    let raw_path = db_url
        .trim()
        .strip_prefix("sqlite://")?
        .split('?')
        .next()
        .unwrap_or_default();
    if raw_path.is_empty() || raw_path == ":memory:" {
        return None;
    }
    Some(
        raw_path
            .strip_prefix("file:")
            .unwrap_or(raw_path)
            .to_string(),
    )
}

fn sqlite_core_read_connections() -> u32 {
    let cpu_default = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(2);
    let default = cmp::min(cpu_default, 4);
    read_env_usize("PUSHGO_SQLITE_CORE_READ_CONNECTIONS", default, 1, 16) as u32
}

fn sqlite_core_read_acquire_timeout_secs() -> u64 {
    read_env_u64("PUSHGO_SQLITE_CORE_READ_ACQUIRE_TIMEOUT_SECS", 5, 1, 60)
}

fn sqlite_core_write_acquire_timeout_secs() -> u64 {
    read_env_u64("PUSHGO_SQLITE_CORE_WRITE_ACQUIRE_TIMEOUT_SECS", 5, 1, 60)
}

fn sqlite_sidecar_acquire_timeout_millis() -> u64 {
    read_env_u64(
        "PUSHGO_SQLITE_SIDECAR_ACQUIRE_TIMEOUT_MILLIS",
        200,
        50,
        10_000,
    )
}

fn sqlite_busy_timeout_millis() -> u64 {
    read_env_u64("PUSHGO_SQLITE_BUSY_TIMEOUT_MILLIS", 30_000, 100, 120_000)
}

fn sqlite_page_cache_kib() -> i64 {
    read_env_i64("PUSHGO_SQLITE_PAGE_CACHE_KIB", 1024, 64, 262_144)
}

fn sqlite_wal_autocheckpoint() -> i64 {
    read_env_i64("PUSHGO_SQLITE_WAL_AUTOCHECKPOINT", 256, 1, 100_000)
}

fn read_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn read_env_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn read_env_i64(name: &str, default: i64, min: i64, max: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}
