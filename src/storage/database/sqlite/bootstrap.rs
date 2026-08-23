use super::*;
use crate::runtime_config::{GatewayRuntimeProfile, RuntimeTuning};
use crate::storage::database::migration::{
    AppliedSchemaMigration, SchemaMigrationDefinition, SchemaMigrationPlan,
    validate_applied_schema_migrations,
};

const SQLITE_BASE_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, request_fingerprint TEXT, state TEXT NOT NULL, provider_run_token TEXT, provider_owner TEXT, provider_lease_until INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_submission (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE, op_id TEXT NOT NULL, payload_version INTEGER NOT NULL, payload_blob BLOB NOT NULL, acceptance_order INTEGER NOT NULL DEFAULT 0, accepted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_acceptance_sequence (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), current_value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key TEXT PRIMARY KEY, semantic_id TEXT NOT NULL UNIQUE, source TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS provider_dispatch_outbox (job_id TEXT PRIMARY KEY, provider TEXT NOT NULL, delivery_id TEXT NOT NULL, op_id TEXT, dedupe_key TEXT, device_key TEXT NOT NULL, payload_blob BLOB NOT NULL, state TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, lease_owner TEXT, lease_until INTEGER, lease_generation INTEGER NOT NULL DEFAULT 0, provider_status INTEGER, provider_error_code TEXT, accepted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, coalesce_order INTEGER NOT NULL DEFAULT 0, completed_at INTEGER, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sender_submit_status (op_id TEXT PRIMARY KEY, channel_id BLOB NOT NULL, model TEXT NOT NULL, entity_id TEXT NOT NULL, status TEXT NOT NULL, dispatch_status TEXT, provider_run_token TEXT, accepted_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS live_activity_tokens (activity_key TEXT NOT NULL, token TEXT NOT NULL, channel_id BLOB, platform TEXT NOT NULL, schema_version INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER, PRIMARY KEY (activity_key, token))",
    "CREATE TABLE IF NOT EXISTS widget_push_subscriptions (device_key TEXT NOT NULL, platform TEXT NOT NULL, token TEXT NOT NULL, widget_kind TEXT NOT NULL, family TEXT NOT NULL, schema_version INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_key, platform, token, widget_kind, family))",
    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
];

const SQLITE_RUNTIME_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, token_raw BLOB NOT NULL, platform_code INTEGER NOT NULL, device_key TEXT, platform TEXT, channel_type TEXT, provider_token TEXT, route_updated_at INTEGER, route_revision INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BLOB NOT NULL, key_id INTEGER NOT NULL, key_hash BLOB NOT NULL, issued_at INTEGER NOT NULL, valid_until INTEGER, PRIMARY KEY (device_id, key_id))",
    "CREATE TABLE IF NOT EXISTS private_sessions (session_id TEXT PRIMARY KEY, device_id BLOB NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, claimed_by TEXT, claim_generation INTEGER NOT NULL DEFAULT 0, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
    "CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (platform, token_hash))",
    "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
    "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
];

const SQLITE_BASE_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_provider_lease_idx ON dispatch_op_dedupe (state, provider_lease_until)",
    "CREATE INDEX IF NOT EXISTS dispatch_submission_expires_idx ON dispatch_submission (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_due_idx ON provider_dispatch_outbox (provider, state, next_attempt_at, accepted_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_retry_expiry_idx ON provider_dispatch_outbox (provider, state, expires_at, next_attempt_at, accepted_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_lease_idx ON provider_dispatch_outbox (state, lease_until)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_delivery_idx ON provider_dispatch_outbox (delivery_id)",
    "CREATE INDEX IF NOT EXISTS sender_submit_status_expires_idx ON sender_submit_status (expires_at)",
    "CREATE INDEX IF NOT EXISTS live_activity_tokens_channel_idx ON live_activity_tokens (channel_id, updated_at)",
    "CREATE INDEX IF NOT EXISTS live_activity_tokens_expires_idx ON live_activity_tokens (expires_at)",
    "CREATE INDEX IF NOT EXISTS widget_push_subscriptions_channel_lookup_idx ON widget_push_subscriptions (device_key, widget_kind, updated_at)",
    "CREATE INDEX IF NOT EXISTS widget_push_subscriptions_token_idx ON widget_push_subscriptions (platform, token)",
];

const SQLITE_DISPATCH_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, request_fingerprint TEXT, state TEXT NOT NULL, provider_run_token TEXT, provider_owner TEXT, provider_lease_until INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS dispatch_submission (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE, op_id TEXT NOT NULL, payload_version INTEGER NOT NULL, payload_blob BLOB NOT NULL, acceptance_order INTEGER NOT NULL DEFAULT 0, accepted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_acceptance_sequence (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), current_value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key TEXT PRIMARY KEY, semantic_id TEXT NOT NULL UNIQUE, source TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen_at INTEGER, expires_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS provider_dispatch_outbox (job_id TEXT PRIMARY KEY, provider TEXT NOT NULL, delivery_id TEXT NOT NULL, op_id TEXT, dedupe_key TEXT, device_key TEXT NOT NULL, payload_blob BLOB NOT NULL, state TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, lease_owner TEXT, lease_until INTEGER, lease_generation INTEGER NOT NULL DEFAULT 0, provider_status INTEGER, provider_error_code TEXT, accepted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, coalesce_order INTEGER NOT NULL DEFAULT 0, completed_at INTEGER, updated_at INTEGER NOT NULL)",
];

const SQLITE_DISPATCH_INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
    "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_provider_lease_idx ON dispatch_op_dedupe (state, provider_lease_until)",
    "CREATE INDEX IF NOT EXISTS dispatch_submission_expires_idx ON dispatch_submission (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
    "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_due_idx ON provider_dispatch_outbox (provider, state, next_attempt_at, accepted_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_retry_expiry_idx ON provider_dispatch_outbox (provider, state, expires_at, next_attempt_at, accepted_at)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_lease_idx ON provider_dispatch_outbox (state, lease_until)",
    "CREATE INDEX IF NOT EXISTS provider_dispatch_outbox_delivery_idx ON provider_dispatch_outbox (delivery_id)",
];

const SQLITE_DELIVERY_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, claimed_by TEXT, claim_generation INTEGER NOT NULL DEFAULT 0, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
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
const SQLITE_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS delivery_audit",
    "DROP TABLE IF EXISTS subscription_audit",
    "DROP TABLE IF EXISTS device_route_audit",
    "DROP TABLE IF EXISTS channel_stats_daily",
    "DROP TABLE IF EXISTS device_stats_daily",
    "DROP TABLE IF EXISTS gateway_stats_hourly",
    "DROP TABLE IF EXISTS ops_stats_hourly",
];
const SQLITE_RUNTIME_SIDECAR_TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
];
const SQLITE_SIDECAR_META_TABLE: &str = "CREATE TABLE IF NOT EXISTS pushgo_sidecar_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)";
const SQLITE_DISPATCH_MIGRATION_META_KEY: &str = "dispatch_migrated_from_core_v1";
const SQLITE_RUNTIME_MIGRATION_META_KEY: &str = "runtime_migrated_from_core_v1";
const SQLITE_DELIVERY_MIGRATION_META_KEY: &str = "runtime_delivery_migrated_from_core_v1";
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
const EPOCH_NORMALIZATION_META_KEY: &str = "epoch_millis_normalized_v1";
const PROVIDER_TOKEN_NORMALIZATION_META_KEY: &str = "provider_token_semantics_v1";

impl SqliteDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        Self::new_with_config(db_url, GatewayRuntimeProfile::Small, true).await
    }

    pub async fn new_with_config(
        db_url: &str,
        runtime_profile: GatewayRuntimeProfile,
        mcp_enabled: bool,
    ) -> StoreResult<Self> {
        let tuning = RuntimeTuning::for_profile(runtime_profile).sqlite;
        ensure_sqlite_parent_dir(db_url)?;
        let core_read_pool = connect_sqlite_pool(
            db_url,
            tuning.core_read_connections,
            tuning.core_read_acquire_timeout,
            tuning,
        )
        .await?;
        let pool =
            connect_sqlite_pool(db_url, 1, tuning.core_write_acquire_timeout, tuning).await?;
        let delivery_url = derive_sqlite_sidecar_url(db_url, "delivery");
        let dispatch_url = derive_sqlite_sidecar_url(db_url, "dispatch");
        let runtime_url = mcp_enabled.then(|| derive_sqlite_sidecar_url(db_url, "runtime"));
        ensure_sqlite_parent_dir(delivery_url.as_str())?;
        let delivery_pool = connect_sqlite_pool(
            delivery_url.as_str(),
            1,
            tuning.sidecar_acquire_timeout,
            tuning,
        )
        .await?;
        ensure_sqlite_parent_dir(dispatch_url.as_str())?;
        let dispatch_pool = connect_sqlite_pool(
            dispatch_url.as_str(),
            1,
            tuning.sidecar_acquire_timeout,
            tuning,
        )
        .await?;
        let runtime_pool = if let Some(url) = runtime_url.as_deref() {
            ensure_sqlite_parent_dir(url)?;
            let pool = connect_sqlite_pool(url, 1, tuning.sidecar_acquire_timeout, tuning).await?;
            Some(pool)
        } else {
            None
        };
        let this = Self {
            core_db_path: sqlite_path_from_url(db_url),
            core_read_pool,
            delivery_pool,
            dispatch_pool,
            runtime_pool,
            pool,
        };
        this.init_schema(tuning).await?;
        this.init_delivery_sidecar(db_url, delivery_url.as_str())
            .await?;
        this.init_dispatch_sidecar(db_url, dispatch_url.as_str())
            .await?;
        if let Some(url) = runtime_url.as_deref() {
            this.init_runtime_sidecar(db_url, url).await?;
        }
        Ok(this)
    }

    pub(crate) async fn open_for_upgrade(
        db_url: &str,
        runtime_profile: GatewayRuntimeProfile,
        mcp_enabled: bool,
    ) -> StoreResult<Self> {
        let tuning = RuntimeTuning::for_profile(runtime_profile).sqlite;
        ensure_sqlite_parent_dir(db_url)?;
        let pool =
            connect_sqlite_pool(db_url, 1, tuning.core_write_acquire_timeout, tuning).await?;
        Ok(Self {
            core_db_path: sqlite_path_from_url(db_url),
            core_read_pool: pool.clone(),
            delivery_pool: pool.clone(),
            dispatch_pool: pool.clone(),
            runtime_pool: mcp_enabled.then(|| pool.clone()),
            pool,
        })
    }

    async fn init_schema(
        &self,
        tuning: crate::runtime_config::SqliteRuntimeTuning,
    ) -> StoreResult<()> {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.schema_init_started",
            driver = %("sqlite")
        );
        sqlx::query("PRAGMA journal_mode = DELETE")
            .execute(&self.pool)
            .await?;
        // The Gateway acknowledges correctness-bearing writes only after the
        // transaction commits. In rollback-journal DELETE mode, SQLite's
        // NORMAL setting does not preserve that durability contract across an
        // OS crash or power loss. EXTRA also syncs the directory after the
        // journal unlink, so an acknowledged commit cannot silently roll back
        // merely because the host lost power immediately afterwards.
        sqlx::query("PRAGMA synchronous = EXTRA")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        let busy_timeout = format!("PRAGMA busy_timeout = {}", tuning.busy_timeout.as_millis());
        sqlx::query(busy_timeout.as_str())
            .execute(&self.pool)
            .await?;
        let cache_size = format!("PRAGMA cache_size = -{}", tuning.page_cache_kib);
        sqlx::query(cache_size.as_str()).execute(&self.pool).await?;
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
            "dispatch_op_dedupe",
            "request_fingerprint",
            "ALTER TABLE dispatch_op_dedupe ADD COLUMN request_fingerprint TEXT",
        )
        .await?;
        for (column, ddl) in [
            (
                "provider_run_token",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_run_token TEXT",
            ),
            (
                "provider_owner",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_owner TEXT",
            ),
            (
                "provider_lease_until",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_lease_until INTEGER",
            ),
        ] {
            self.ensure_sqlite_column("dispatch_op_dedupe", column, ddl)
                .await?;
        }
        self.ensure_sqlite_column(
            "sender_submit_status",
            "provider_run_token",
            "ALTER TABLE sender_submit_status ADD COLUMN provider_run_token TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_dispatch_outbox",
            "op_id",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN op_id TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_dispatch_outbox",
            "dedupe_key",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN dedupe_key TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "dispatch_submission",
            "acceptance_order",
            "ALTER TABLE dispatch_submission ADD COLUMN acceptance_order INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_sqlite_column(
            "provider_dispatch_outbox",
            "coalesce_order",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN coalesce_order INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        reconcile_sqlite_acceptance_sequence(&self.pool).await?;

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
            "devices",
            "route_revision",
            "ALTER TABLE devices ADD COLUMN route_revision INTEGER NOT NULL DEFAULT 0",
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
            "claimed_by",
            "ALTER TABLE private_outbox ADD COLUMN claimed_by TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "private_outbox",
            "claim_generation",
            "ALTER TABLE private_outbox ADD COLUMN claim_generation INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        sqlx::query(
            "UPDATE private_outbox SET status = 'pending', claimed_at = NULL, claimed_by = NULL \
             WHERE status = 'claimed'",
        )
        .execute(&self.pool)
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
        for stmt in SQLITE_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS {
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
        self.normalize_sqlite_provider_tokens_once().await?;

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
        for stmt in SQLITE_DISPATCH_TABLE_STATEMENTS {
            sqlx::query(stmt).execute(&self.dispatch_pool).await?;
        }
        for (column, ddl) in [
            (
                "request_fingerprint",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN request_fingerprint TEXT",
            ),
            (
                "provider_run_token",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_run_token TEXT",
            ),
            (
                "provider_owner",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_owner TEXT",
            ),
            (
                "provider_lease_until",
                "ALTER TABLE dispatch_op_dedupe ADD COLUMN provider_lease_until INTEGER",
            ),
        ] {
            ensure_sqlite_column_in_pool(&self.dispatch_pool, "dispatch_op_dedupe", column, ddl)
                .await?;
        }
        ensure_sqlite_column_in_pool(
            &self.dispatch_pool,
            "provider_dispatch_outbox",
            "op_id",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN op_id TEXT",
        )
        .await?;
        ensure_sqlite_column_in_pool(
            &self.dispatch_pool,
            "dispatch_submission",
            "acceptance_order",
            "ALTER TABLE dispatch_submission ADD COLUMN acceptance_order INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        ensure_sqlite_column_in_pool(
            &self.dispatch_pool,
            "provider_dispatch_outbox",
            "coalesce_order",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN coalesce_order INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        ensure_sqlite_column_in_pool(
            &self.dispatch_pool,
            "provider_dispatch_outbox",
            "dedupe_key",
            "ALTER TABLE provider_dispatch_outbox ADD COLUMN dedupe_key TEXT",
        )
        .await?;
        for stmt in SQLITE_DISPATCH_INDEX_STATEMENTS {
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
        .await?;
        reconcile_sqlite_acceptance_sequence(&self.dispatch_pool).await?;
        reject_sqlite_legacy_pending_submissions(&self.dispatch_pool).await
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
        ensure_sqlite_column_in_pool(
            &self.delivery_pool,
            "private_outbox",
            "claimed_by",
            "ALTER TABLE private_outbox ADD COLUMN claimed_by TEXT",
        )
        .await?;
        ensure_sqlite_column_in_pool(
            &self.delivery_pool,
            "private_outbox",
            "claim_generation",
            "ALTER TABLE private_outbox ADD COLUMN claim_generation INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        sqlx::query(
            "UPDATE private_outbox SET status = 'pending', claimed_at = NULL, claimed_by = NULL \
             WHERE status = 'claimed'",
        )
        .execute(&self.delivery_pool)
        .await?;
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
        self.normalize_sqlite_delivery_provider_tokens_once()
            .await?;
        Ok(())
    }

    async fn normalize_sqlite_provider_tokens_once(&self) -> StoreResult<()> {
        let normalized: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = ?")
                .bind(PROVIDER_TOKEN_NORMALIZATION_META_KEY)
                .fetch_optional(&self.pool)
                .await?;
        if normalized.as_deref() == Some("complete") {
            return Ok(());
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
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
            let provider_token: String = row.get("provider_token");
            let canonical = provider_token.trim().to_ascii_lowercase();
            let (new_hash, _) = ProviderTokenSnapshot::from_token(&canonical).into_parts();
            let new_hash = new_hash.ok_or(StoreError::InvalidDeviceToken)?;
            sqlx::query(
                "INSERT INTO private_bindings \
                 (platform, token_hash, device_id, provider_token, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (platform, token_hash) DO UPDATE SET device_id = excluded.device_id, \
                   provider_token = excluded.provider_token, \
                   updated_at = MAX(private_bindings.updated_at, excluded.updated_at)",
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
            let canonical = row
                .get::<String, _>("provider_token")
                .trim()
                .to_ascii_lowercase();
            if !merged_routes.insert((platform.clone(), canonical.clone())) {
                continue;
            }
            let route = DeviceRouteRecordRow {
                device_key: row.get("device_key"),
                platform,
                channel_type: row.get("channel_type"),
                provider_token: Some(canonical.clone()),
                updated_at: row.get("route_updated_at"),
            };
            let values = route.persistence_values()?;
            let old_device_id: Vec<u8> = row.get("device_id");
            if old_device_id != values.device_id {
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
                 ON CONFLICT (platform, token_hash) DO UPDATE SET \
                   device_id = excluded.device_id, provider_token = excluded.provider_token, \
                   updated_at = MAX(private_bindings.updated_at, excluded.updated_at)",
            )
            .bind(values.platform_code)
            .bind(token_hash.as_deref())
            .bind(values.device_id.as_slice())
            .bind(&canonical)
            .bind(values.updated_at)
            .bind(values.updated_at)
            .execute(&mut *tx)
            .await?;
            let duplicate_device_ids =
                super::access::routes::coalesce_duplicate_provider_routes_in_tx(&mut tx, &values)
                    .await?;
            self.coalesce_delivery_device_rows(
                &duplicate_device_ids,
                values.device_id.as_slice(),
                values.platform.as_str(),
                values.provider_token.as_deref(),
            )
            .await?;
        }
        sqlx::query(
            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES (?, 'complete') \
             ON CONFLICT (meta_key) DO UPDATE SET meta_value = excluded.meta_value",
        )
        .bind(PROVIDER_TOKEN_NORMALIZATION_META_KEY)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_sqlite_delivery_provider_tokens_once(&self) -> StoreResult<()> {
        let marker = format!("{PROVIDER_TOKEN_NORMALIZATION_META_KEY}_delivery");
        let normalized: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_sidecar_meta WHERE meta_key = ?")
                .bind(&marker)
                .fetch_optional(&self.delivery_pool)
                .await?;
        if normalized.as_deref() == Some("complete") {
            return Ok(());
        }
        let mut conn = self.delivery_pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE provider_pull_queue SET provider_token = LOWER(TRIM(provider_token)) \
             WHERE platform IN ('ios', 'macos', 'watchos') AND provider_token IS NOT NULL",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO pushgo_sidecar_meta (meta_key, meta_value) VALUES (?, 'complete') \
             ON CONFLICT (meta_key) DO UPDATE SET meta_value = excluded.meta_value",
        )
        .bind(marker)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
            let claimed_by_projection = if sqlite_attached_column_exists(
                &mut tx,
                "pushgo_core",
                "private_outbox",
                "claimed_by",
            )
            .await?
            {
                "claimed_by"
            } else {
                "NULL AS claimed_by"
            };
            let sql = format!(
                "INSERT INTO private_outbox \
                 (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, claimed_by, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                 SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, {claimed_by_projection}, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                 FROM pushgo_core.private_outbox WHERE true \
                 ON CONFLICT(device_id, delivery_id) DO UPDATE SET \
                   status = excluded.status, \
                   attempts = excluded.attempts, \
                   occurred_at = excluded.occurred_at, \
                   created_at = excluded.created_at, \
                   claimed_at = excluded.claimed_at, \
                   claimed_by = excluded.claimed_by, \
                   first_sent_at = excluded.first_sent_at, \
                   last_attempt_at = excluded.last_attempt_at, \
                   acked_at = excluded.acked_at, \
                   fallback_sent_at = excluded.fallback_sent_at, \
                   next_attempt_at = excluded.next_attempt_at, \
                   last_error_code = excluded.last_error_code, \
                   last_error_detail = excluded.last_error_detail, \
                   updated_at = excluded.updated_at \
                 WHERE excluded.updated_at >= private_outbox.updated_at"
            );
            sqlx::query(sql.as_str()).execute(&mut *tx).await?;
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
        ensure_sqlite_column_in_pool(&self.pool, table, column, ddl).await
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

pub(crate) struct SqliteUpgradeLockGuard {
    path: Option<std::path::PathBuf>,
}

impl Drop for SqliteUpgradeLockGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl SqliteDb {
    pub(crate) async fn inspect_upgrade_plan(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<
        crate::storage::database::upgrade::UpgradePlan,
    > {
        let applied_migrations = if self.sqlite_table_exists("pushgo_schema_migrations").await? {
            self.load_sqlite_schema_migrations().await?
        } else {
            Vec::new()
        };
        validate_applied_schema_migrations(&applied_migrations)?;
        let current_version = if self.sqlite_table_exists("pushgo_schema_meta").await? {
            self.load_sqlite_schema_version().await?
        } else {
            None
        };
        let plan = SchemaMigrationPlan::for_state(
            current_version.as_deref(),
            self.sqlite_runtime_tables_present().await?,
            &applied_migrations,
        )?;
        Ok(crate::storage::database::upgrade::UpgradePlan::from_schema_plan(plan))
    }

    async fn sqlite_table_exists(&self, table: &str) -> StoreResult<bool> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        )
        .bind(table)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }
}

impl crate::storage::database::upgrade::lock::UpgradeLockAccess for SqliteDb {
    type Guard = SqliteUpgradeLockGuard;

    async fn acquire_upgrade_lock(
        &self,
        db_url: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<Self::Guard> {
        let Some(db_path) = sqlite_path_from_url(db_url) else {
            return Ok(SqliteUpgradeLockGuard { path: None });
        };
        let lock_path = std::path::PathBuf::from(format!("{db_path}.upgrade.lock"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path.as_path())
        {
            Ok(mut file) => {
                use std::io::Write;
                writeln!(file, "pid={}", std::process::id())?;
                Ok(SqliteUpgradeLockGuard {
                    path: Some(lock_path),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!(
                        "sqlite upgrade lock already exists at {}; another gateway may be upgrading. Stop other instances or remove the stale lock only after confirming no upgrade process is active.",
                        lock_path.display()
                    )),
                ))
            }
            Err(err) => Err(err.into()),
        }
    }
}

impl crate::storage::database::upgrade::state::UpgradeStateAccess for SqliteDb {
    async fn ensure_upgrade_state_tables(
        &self,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_upgrade_runs (\
                run_id TEXT PRIMARY KEY,\
                gateway_version TEXT NOT NULL,\
                driver TEXT NOT NULL,\
                from_schema_version TEXT,\
                target_schema_version TEXT NOT NULL,\
                status TEXT NOT NULL,\
                backup_uri TEXT,\
                backup_sha256 TEXT,\
                started_at INTEGER NOT NULL,\
                finished_at INTEGER,\
                error TEXT\
            )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_upgrade_steps (\
                run_id TEXT NOT NULL,\
                step_order INTEGER NOT NULL,\
                migration_id TEXT NOT NULL,\
                step_id TEXT NOT NULL,\
                description TEXT NOT NULL,\
                status TEXT NOT NULL,\
                started_at INTEGER NOT NULL,\
                finished_at INTEGER,\
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
             SET status = ?, \
                 backup_uri = COALESCE(?, backup_uri), \
                 backup_sha256 = COALESCE(?, backup_sha256), \
                 finished_at = COALESCE(?, finished_at), \
                 error = COALESCE(?, error) \
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
            "UPDATE pushgo_upgrade_steps \
             SET status = ?, finished_at = COALESCE(?, finished_at), error = COALESCE(?, error) \
             WHERE run_id = ? AND step_order = ?",
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

impl crate::storage::database::upgrade::backup::UpgradeBackupAccess for SqliteDb {
    async fn create_upgrade_backup(
        &self,
        db_url: &str,
        _driver: crate::storage::types::DatabaseKind,
        policy: crate::storage::database::migration::BackupPolicy,
        run_id: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<
        Option<crate::storage::database::upgrade::backup::BackupArtifact>,
    > {
        #[cfg(test)]
        if self
            .sqlite_table_exists("__pushgo_upgrade_inject_backup_failure")
            .await?
        {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade("injected upgrade backup failure".to_string()),
            ));
        }
        if matches!(
            policy,
            crate::storage::database::migration::BackupPolicy::None
        ) {
            return Ok(None);
        }
        let Some(db_path) = sqlite_path_from_url(db_url) else {
            return Ok(None);
        };
        sqlx::query("PRAGMA wal_checkpoint(FULL)")
            .execute(&self.pool)
            .await?;
        let source = std::path::PathBuf::from(db_path.as_str());
        let backup_path = std::path::PathBuf::from(format!("{db_path}.upgrade-{run_id}.bak"));
        fs::copy(source.as_path(), backup_path.as_path())?;
        let (sha256, bytes) = sha256_file(backup_path.as_path())?;
        let manifest_path = backup_path.with_extension("bak.manifest");
        let schema_version = if self.sqlite_table_exists("pushgo_schema_meta").await? {
            self.load_sqlite_schema_version().await?
        } else {
            None
        };
        let manifest = format!(
            "driver=sqlite\nschema_version={}\nbytes={bytes}\nsha256={sha256}\nsource={}\nbackup={}\n",
            schema_version.as_deref().unwrap_or("none"),
            source.display(),
            backup_path.display()
        );
        fs::write(manifest_path, manifest)?;
        let backup_url = format!("sqlite://{}?mode=ro", backup_path.to_string_lossy());
        let backup_pool = connect_sqlite_pool(
            backup_url.as_str(),
            1,
            std::time::Duration::from_secs(5),
            RuntimeTuning::for_profile(GatewayRuntimeProfile::Small).sqlite,
        )
        .await?;
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&backup_pool)
            .await?;
        backup_pool.close().await;
        if integrity != "ok" {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade(format!("sqlite backup integrity check failed: {integrity}")),
            ));
        }
        Ok(Some(
            crate::storage::database::upgrade::backup::BackupArtifact {
                uri: backup_path.to_string_lossy().to_string(),
                sha256,
                bytes,
            },
        ))
    }

    async fn restore_upgrade_backup(
        &self,
        db_url: &str,
        artifact: &crate::storage::database::upgrade::backup::BackupArtifact,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        let Some(db_path) = sqlite_path_from_url(db_url) else {
            return Ok(());
        };
        self.core_read_pool.close().await;
        self.delivery_pool.close().await;
        self.dispatch_pool.close().await;
        if let Some(pool) = &self.runtime_pool {
            pool.close().await;
        }
        self.pool.close().await;
        let target = std::path::PathBuf::from(db_path.as_str());
        fs::copy(artifact.uri.as_str(), target.as_path())?;
        let _ = fs::remove_file(format!("{db_path}-wal"));
        let _ = fs::remove_file(format!("{db_path}-shm"));
        Ok(())
    }
}

impl crate::storage::database::upgrade::verify::UpgradeVerifyAccess for SqliteDb {
    async fn verify_upgrade(
        &self,
        target_schema_version: &str,
    ) -> crate::storage::database::upgrade::UpgradeResult<()> {
        #[cfg(test)]
        if self
            .sqlite_table_exists("__pushgo_upgrade_inject_verify_failure")
            .await?
        {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade("injected upgrade verification failure".to_string()),
            ));
        }
        let schema_version = self.load_sqlite_schema_version().await?;
        if schema_version.as_deref() != Some(target_schema_version) {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::SchemaVersionMismatch {
                    expected: target_schema_version.to_string(),
                    actual: schema_version.unwrap_or_else(|| "none".to_string()),
                },
            ));
        }
        let applied = self.load_sqlite_schema_migrations().await?;
        validate_applied_schema_migrations(&applied)?;
        for table in [
            "channels",
            "devices",
            "channel_subscriptions",
            "private_payloads",
            "sender_submit_status",
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
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
        for stmt in SQLITE_DEPRECATED_OBSERVABILITY_DROP_STATEMENTS {
            let table = stmt
                .strip_prefix("DROP TABLE IF EXISTS ")
                .unwrap_or_default();
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
            )
            .bind(table)
            .fetch_optional(&self.pool)
            .await?;
            if exists.is_some() {
                return Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!(
                        "deprecated observability table remains after upgrade: {table}"
                    )),
                ));
            }
        }
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&self.pool)
            .await?;
        if integrity != "ok" {
            return Err(crate::storage::database::upgrade::UpgradeError::Store(
                StoreError::Upgrade(format!(
                    "sqlite integrity check failed after upgrade: {integrity}"
                )),
            ));
        }
        for (table, column) in [
            ("dispatch_op_dedupe", "request_fingerprint"),
            ("dispatch_op_dedupe", "provider_run_token"),
            ("dispatch_op_dedupe", "provider_owner"),
            ("dispatch_op_dedupe", "provider_lease_until"),
            ("sender_submit_status", "dispatch_status"),
            ("sender_submit_status", "provider_run_token"),
            ("private_outbox", "claim_generation"),
            ("devices", "provider_token"),
            ("devices", "route_revision"),
            ("private_bindings", "provider_token"),
            ("provider_pull_queue", "provider_token"),
        ] {
            let rows = sqlx::query(format!("PRAGMA table_info({table})").as_str())
                .fetch_all(&self.pool)
                .await?;
            if !rows
                .into_iter()
                .any(|row| row.get::<String, _>("name") == column)
            {
                return Err(crate::storage::database::upgrade::UpgradeError::Store(
                    StoreError::Upgrade(format!(
                        "required column missing after upgrade: {table}.{column}"
                    )),
                ));
            }
        }
        Ok(())
    }
}

fn sha256_file(path: &std::path::Path) -> StoreResult<(String, u64)> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(bytes.as_slice());
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((sha256, bytes.len() as u64))
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
    tuning: crate::runtime_config::SqliteRuntimeTuning,
) -> StoreResult<SqlitePool> {
    let sqlite_page_cache_kib = tuning.page_cache_kib;
    let connect_options = SqliteConnectOptions::from_str(db_url)?
        .journal_mode(SqliteJournalMode::Delete)
        .synchronous(SqliteSynchronous::Extra)
        .foreign_keys(true)
        .statement_cache_capacity(tuning.statement_cache_capacity)
        .busy_timeout(tuning.busy_timeout);
    Ok(SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(0)
        .acquire_timeout(acquire_timeout)
        .idle_timeout(tuning.idle_timeout)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                let cache_size = format!("PRAGMA cache_size = -{sqlite_page_cache_kib}");
                conn.execute(cache_size.as_str()).await?;
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

async fn ensure_sqlite_column_in_pool(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    ddl: &str,
) -> StoreResult<()> {
    let rows = sqlx::query(format!("PRAGMA table_info({table})").as_str())
        .fetch_all(pool)
        .await?;
    let exists = rows
        .into_iter()
        .any(|r| r.get::<String, _>("name") == column);
    if !exists {
        sqlx::query(ddl).execute(pool).await?;
    }
    Ok(())
}

async fn reconcile_sqlite_acceptance_sequence(pool: &SqlitePool) -> StoreResult<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO dispatch_acceptance_sequence (singleton,current_value) VALUES (1,0)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE dispatch_acceptance_sequence SET current_value=MAX(\
            current_value,\
            (SELECT COALESCE(MAX(acceptance_order),0) FROM dispatch_submission),\
            (SELECT COALESCE(MAX(coalesce_order),0) FROM provider_dispatch_outbox)\
         ) WHERE singleton=1",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn reject_sqlite_legacy_pending_submissions(pool: &SqlitePool) -> StoreResult<()> {
    let legacy_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM dispatch_submission s JOIN dispatch_op_dedupe d ON d.dedupe_key=s.dedupe_key \
         WHERE s.acceptance_order=0 AND d.state='pending'",
    )
    .fetch_one(pool)
    .await?;
    if legacy_pending > 0 {
        return Err(StoreError::LegacyAcceptanceOrderPending {
            pending: legacy_pending as usize,
        });
    }
    Ok(())
}

async fn sqlite_attached_column_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &str,
    table: &str,
    column: &str,
) -> StoreResult<bool> {
    let sql = format!("PRAGMA {schema}.table_info({table})");
    let rows = sqlx::query(sql.as_str()).fetch_all(&mut **tx).await?;
    Ok(rows
        .into_iter()
        .any(|row| row.get::<String, _>("name") == column))
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

#[cfg(test)]
mod durability_tests {
    use super::*;

    #[tokio::test]
    async fn every_sqlite_pool_uses_power_loss_durable_sync() {
        let directory = tempfile::tempdir().expect("temporary SQLite directory should exist");
        let database = directory.path().join("durability.sqlite");
        let database_url = format!("sqlite://{}?mode=rwc", database.to_string_lossy());
        let tuning = RuntimeTuning::for_profile(GatewayRuntimeProfile::Small).sqlite;
        let pool = connect_sqlite_pool(
            database_url.as_str(),
            1,
            std::time::Duration::from_secs(5),
            tuning,
        )
        .await
        .expect("SQLite pool should open");

        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .expect("journal mode should be queryable");
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await
            .expect("synchronous mode should be queryable");

        assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
        assert_eq!(synchronous, 3, "DELETE journal durability requires EXTRA");
        pool.close().await;
    }
}
