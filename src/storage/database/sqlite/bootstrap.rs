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
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
const EPOCH_NORMALIZATION_META_KEY: &str = "epoch_millis_normalized_v1";

impl SqliteDb {
    pub async fn new(db_url: &str) -> StoreResult<Self> {
        ensure_sqlite_parent_dir(db_url)?;
        let connect_options = SqliteConnectOptions::from_str(db_url)?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .connect_with(connect_options)
            .await?;
        let this = Self { pool };
        this.init_schema().await?;
        Ok(this)
    }

    async fn init_schema(&self) -> StoreResult<()> {
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 5000")
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
            if let Err(err) = self.hard_reset_sqlite_runtime_tables().await {
                let _ = self
                    .record_sqlite_schema_migration(
                        migration,
                        started_at,
                        false,
                        Some(err.to_string()),
                    )
                    .await;
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
        Ok(())
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
