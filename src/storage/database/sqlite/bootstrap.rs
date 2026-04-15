use super::*;

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

        let statements = [
            "CREATE TABLE IF NOT EXISTS channels (channel_id BLOB PRIMARY KEY, password_hash TEXT NOT NULL, alias TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, token_raw BLOB NOT NULL, platform_code INTEGER NOT NULL, device_key TEXT, platform TEXT, channel_type TEXT, provider_token TEXT, route_updated_at INTEGER)",
            "CREATE TABLE IF NOT EXISTS private_device_keys (device_id BLOB NOT NULL, key_id INTEGER NOT NULL, key_hash BLOB NOT NULL, issued_at INTEGER NOT NULL, valid_until INTEGER, PRIMARY KEY (device_id, key_id))",
            "CREATE TABLE IF NOT EXISTS private_sessions (session_id TEXT PRIMARY KEY, device_id BLOB NOT NULL, expires_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS private_sessions_exp_idx ON private_sessions (expires_at)",
            "CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, occurred_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, first_sent_at INTEGER, last_attempt_at INTEGER, acked_at INTEGER, fallback_sent_at INTEGER, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, last_error_detail TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
            "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx ON private_outbox (delivery_id)",
            "CREATE INDEX IF NOT EXISTS private_outbox_due_idx ON private_outbox (status, next_attempt_at, attempts)",
            "CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (platform, token_hash))",
            "CREATE INDEX IF NOT EXISTS private_bindings_device_idx ON private_bindings (device_id)",
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, device_key TEXT, provider_token TEXT, provider_token_hash BLOB, provider_token_preview TEXT, route_version INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active', subscribed_via TEXT, last_dispatch_at INTEGER, last_acked_at INTEGER, last_error_code TEXT, last_confirmed_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id))",
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx ON channel_subscriptions (device_id)",
            "CREATE TABLE IF NOT EXISTS private_payloads (delivery_id TEXT PRIMARY KEY, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx ON private_payloads (expires_at)",
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, payload_blob BLOB NOT NULL, payload_size INTEGER NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, platform TEXT NOT NULL, provider_token TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id))",
            "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER)",
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx ON dispatch_delivery_dedupe (expires_at)",
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx ON dispatch_delivery_dedupe (created_at)",
            "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (dedupe_key TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER, expires_at INTEGER)",
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx ON dispatch_op_dedupe (expires_at)",
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx ON dispatch_op_dedupe (created_at)",
            "CREATE TABLE IF NOT EXISTS semantic_id_registry (dedupe_key TEXT PRIMARY KEY, semantic_id TEXT NOT NULL UNIQUE, source TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen_at INTEGER, expires_at INTEGER)",
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx ON semantic_id_registry (expires_at)",
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx ON semantic_id_registry (created_at)",
            "CREATE TABLE IF NOT EXISTS device_route_audit (device_key TEXT NOT NULL, action TEXT NOT NULL, old_platform TEXT, new_platform TEXT, old_channel_type TEXT, new_channel_type TEXT, old_provider_token TEXT, new_provider_token TEXT, issue_reason TEXT, created_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS device_route_audit_device_created_idx ON device_route_audit (device_key, created_at)",
            "CREATE TABLE IF NOT EXISTS subscription_audit (channel_id BLOB NOT NULL, device_key TEXT NOT NULL, action TEXT NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS subscription_audit_channel_created_idx ON subscription_audit (channel_id, created_at)",
            "CREATE INDEX IF NOT EXISTS subscription_audit_device_created_idx ON subscription_audit (device_key, created_at)",
            "CREATE TABLE IF NOT EXISTS delivery_audit (audit_id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL, channel_id BLOB NOT NULL, device_key TEXT NOT NULL, entity_type TEXT, entity_id TEXT, op_id TEXT, path TEXT NOT NULL, status TEXT NOT NULL, error_code TEXT, created_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS delivery_audit_delivery_created_idx ON delivery_audit (delivery_id, created_at)",
            "CREATE INDEX IF NOT EXISTS delivery_audit_channel_created_idx ON delivery_audit (channel_id, created_at)",
            "CREATE INDEX IF NOT EXISTS delivery_audit_device_created_idx ON delivery_audit (device_key, created_at)",
            "CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BLOB NOT NULL, bucket_date TEXT NOT NULL, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_enqueued INTEGER NOT NULL DEFAULT 0, provider_attempted INTEGER NOT NULL DEFAULT 0, provider_failed INTEGER NOT NULL DEFAULT 0, provider_success INTEGER NOT NULL DEFAULT 0, private_realtime_delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))",
            "CREATE TABLE IF NOT EXISTS device_stats_daily (device_key TEXT NOT NULL, bucket_date TEXT NOT NULL, messages_received INTEGER NOT NULL DEFAULT 0, messages_acked INTEGER NOT NULL DEFAULT 0, private_connected_count INTEGER NOT NULL DEFAULT 0, private_pull_count INTEGER NOT NULL DEFAULT 0, provider_success_count INTEGER NOT NULL DEFAULT 0, provider_failure_count INTEGER NOT NULL DEFAULT 0, private_outbox_enqueued_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_key, bucket_date))",
            "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (bucket_hour TEXT PRIMARY KEY, messages_routed INTEGER NOT NULL DEFAULT 0, deliveries_attempted INTEGER NOT NULL DEFAULT 0, deliveries_acked INTEGER NOT NULL DEFAULT 0, private_outbox_depth_max INTEGER NOT NULL DEFAULT 0, dedupe_pending_max INTEGER NOT NULL DEFAULT 0, active_private_sessions_max INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS mcp_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
        ];

        for stmt in statements {
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
            "device_key",
            "ALTER TABLE channel_subscriptions ADD COLUMN device_key TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "provider_token",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "provider_token_hash",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token_hash BLOB",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "provider_token_preview",
            "ALTER TABLE channel_subscriptions ADD COLUMN provider_token_preview TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "route_version",
            "ALTER TABLE channel_subscriptions ADD COLUMN route_version INTEGER NOT NULL DEFAULT 1",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "status",
            "ALTER TABLE channel_subscriptions ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "subscribed_via",
            "ALTER TABLE channel_subscriptions ADD COLUMN subscribed_via TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "last_dispatch_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_dispatch_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "last_acked_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_acked_at INTEGER",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "last_error_code",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_error_code TEXT",
        )
        .await?;
        self.ensure_sqlite_column(
            "channel_subscriptions",
            "last_confirmed_at",
            "ALTER TABLE channel_subscriptions ADD COLUMN last_confirmed_at INTEGER",
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
        self.ensure_sqlite_column(
            "delivery_audit",
            "audit_id",
            "ALTER TABLE delivery_audit ADD COLUMN audit_id TEXT",
        )
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx ON devices (device_key)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS devices_route_platform_type_updated_idx ON devices (platform, channel_type, route_updated_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS devices_route_provider_token_idx ON devices (provider_token)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_bindings_device_idx ON private_bindings (device_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_bindings_token_idx ON private_bindings (platform, token_hash)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS private_bindings_platform_token_uidx ON private_bindings (platform, token_hash)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_outbox_device_status_order_idx ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_dispatch_idx ON channel_subscriptions (channel_id, status, channel_type, route_version)",
        )
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
            Some(version)
                if version == STORAGE_SCHEMA_VERSION_PREVIOUS
                    || version == STORAGE_SCHEMA_VERSION_LEGACY =>
            {
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
