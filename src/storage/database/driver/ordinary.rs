//! Concrete product-pool attachment; this is deliberately not a SQL dialect layer.
use super::*;
use crate::ordinary::{
    OrdinaryStore,
    mysql_store::MySqlDeliveryStore,
    pg_store::PgDeliveryStore,
    store::{Config, Counters, DeliveryStore, Health, KernelError},
};
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::Mutex;

impl DatabaseDriver {
    #[cfg(feature = "qa")]
    pub(crate) fn resource_pool_snapshot(&self) -> serde_json::Value {
        match self {
            Self::Sqlite(db) => db.resource_pool_snapshot(),
            Self::Postgres(db) => {
                let pool = db.ordinary_pool();
                serde_json::json!({"backend": "postgres", "pools": [{"name": "product", "size": pool.size(), "idle": pool.num_idle()}], "scope": "pool atomics only; dedicated owner connection is outside this pool"})
            }
            Self::MySql(db) => {
                let pool = db.ordinary_pool();
                serde_json::json!({"backend": "mysql", "pools": [{"name": "product", "size": pool.size(), "idle": pool.num_idle()}], "scope": "pool atomics only; pinned data session is counted busy; dedicated owner connection is outside this pool"})
            }
        }
    }

    pub(crate) async fn initialize_ordinary(
        &self,
        config: Config,
        health: Arc<Health>,
        gate: Arc<Mutex<()>>,
        counters: Arc<Counters>,
    ) -> Result<OrdinaryStore, KernelError> {
        match self {
            Self::Sqlite(db) => {
                let store =
                    DeliveryStore::from_product(db.ordinary_pool(), gate, config, health, counters)
                        .await?;
                store.set_legacy_pools(db.ordinary_dispatch_pool(), db.ordinary_delivery_pool())?;
                Ok(store.into())
            }
            Self::Postgres(db) => {
                let store = PgDeliveryStore::from_product(
                    db.ordinary_pool(),
                    gate,
                    config,
                    health,
                    counters,
                )
                .await?;
                db.set_ordinary_store(store.clone());
                Ok(store.into())
            }
            Self::MySql(db) => {
                let store = MySqlDeliveryStore::from_product(
                    db.ordinary_pool(),
                    gate,
                    config,
                    health,
                    counters,
                )
                .await?;
                db.set_ordinary_store(store.clone());
                Ok(store.into())
            }
        }
    }

    pub(crate) async fn clear_ordinary_private_channel(
        &self,
        route: &DeviceRouteRecordRow,
    ) -> StoreResult<()> {
        match self {
            Self::Sqlite(db) => db.clear_ordinary_private_channel(route).await,
            Self::Postgres(db) => db.clear_ordinary_private_channel(route).await,
            Self::MySql(db) => db.clear_ordinary_private_channel(route).await,
        }
    }

    pub(crate) async fn ordinary_private_device_key(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<String>, KernelError> {
        // Normal MySQL retains the historical BINARY(32) representation while
        // current Private identities contain 16 bytes. These two indexed seeks
        // preserve that storage compatibility without loading the device table.
        let mut padded = [0_u8; 32];
        padded[..16].copy_from_slice(&device_id);
        let keys: Vec<Option<String>> = match self {
            Self::Sqlite(db) => sqlx::query_scalar("SELECT device_key FROM devices WHERE device_id=? OR device_id=? ORDER BY device_id LIMIT 2")
                .bind(device_id.as_slice()).bind(padded.as_slice()).fetch_all(&db.ordinary_control_read_pool()).await?,
            Self::Postgres(db) => sqlx::query_scalar("SELECT device_key FROM devices WHERE device_id=$1 OR device_id=$2 ORDER BY device_id LIMIT 2")
                .bind(device_id.as_slice()).bind(padded.as_slice()).fetch_all(&db.ordinary_pool()).await?,
            // Only result metadata changes: MySQL flags utf8mb4_bin text as
            // binary, while SQLx checks String against character metadata.
            // Keep the indexed identity predicates and ambiguity check intact.
            Self::MySql(db) => sqlx::query_scalar("SELECT CAST(device_key AS CHAR CHARACTER SET utf8mb4) FROM devices WHERE device_id=? OR device_id=? ORDER BY device_id LIMIT 2")
                .bind(device_id.as_slice()).bind(padded.as_slice()).fetch_all(&db.ordinary_pool()).await?,
        };
        let mut keys = keys.into_iter().flatten();
        let key = keys.next();
        if keys.any(|other| Some(&other) != key.as_ref()) {
            return Err(KernelError::Invalid(
                "ambiguous canonical Private identity requires repair".into(),
            ));
        }
        Ok(key)
    }

    pub(crate) async fn close_product_pools(&self) {
        match self {
            Self::Sqlite(db) => db.close_product_pools().await,
            Self::Postgres(db) => db.ordinary_pool().close().await,
            Self::MySql(db) => db.ordinary_pool().close().await,
        }
    }

    /// PostgreSQL/MySQL guard their single native database in from_product.
    /// SQLite additionally has existing dispatch/delivery sidecars whose old
    /// accepted work must not become an invisible second ordinary authority.
    pub(crate) async fn assert_ordinary_cutover(&self) -> Result<(), KernelError> {
        let Self::Sqlite(db) = self else {
            return Ok(());
        };
        let at = crate::ordinary::store::now();
        let core = db.ordinary_pool();
        let dispatch = db.ordinary_dispatch_pool();
        let delivery = db.ordinary_delivery_pool();
        let status: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE model='message' AND expires_at>?)")
            .bind(at).fetch_one(&core).await?;
        if status != 0 {
            return Err(legacy_cutover_error());
        }
        for pool in [&core, &dispatch] {
            let legacy: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_id_registry WHERE dedupe_key LIKE 'semantic:%:message:%' AND (expires_at IS NULL OR expires_at>?)) OR EXISTS(SELECT 1 FROM dispatch_op_dedupe WHERE dedupe_key LIKE 'op:%:message:%' AND (expires_at IS NULL OR expires_at>?)) OR EXISTS(SELECT 1 FROM dispatch_submission WHERE dedupe_key LIKE 'op:%:message:%' AND expires_at>?) OR EXISTS(SELECT 1 FROM provider_dispatch_outbox WHERE dedupe_key LIKE 'op:%:message:%' AND state IN ('preparing','pending','retry_wait','leased') AND expires_at>?)")
                .bind(at).bind(at).bind(at).bind(at).fetch_one(pool).await?;
            if legacy != 0 {
                return Err(legacy_cutover_error());
            }
            guard_sqlite_provider_payloads(pool, at).await?;
        }
        // A body can survive a crash independently of its sender status. Scan
        // bounded pages on startup rather than assuming status rows are complete.
        for pool in [&core, &delivery] {
            guard_sqlite_private_payloads(pool, at).await?;
            guard_sqlite_pull_payloads(pool, at).await?;
        }
        Ok(())
    }
}

fn legacy_cutover_error() -> KernelError {
    KernelError::Invalid("legacy ordinary identities or pending deliveries require an explicit cutover migration; no second ledger or fallback is enabled".into())
}

fn ordinary_payload(payload: Option<Vec<u8>>, provider_job: bool) -> Result<bool, KernelError> {
    let payload = payload.ok_or_else(|| {
        KernelError::Invalid(
            "legacy payload exceeds bounded cutover inspection; explicit migration required".into(),
        )
    })?;
    if provider_job {
        let value: serde_json::Value = serde_json::from_slice(&payload).map_err(|_| {
            KernelError::Invalid(
                "unrecognized legacy provider payload requires explicit cutover migration".into(),
            )
        })?;
        if value.get("kind").and_then(serde_json::Value::as_str) == Some("widget") {
            return Ok(false);
        }
        return match value
            .pointer("/direct_payload/data/entity_type")
            .and_then(serde_json::Value::as_str)
        {
            Some("message") => Ok(true),
            Some("event" | "thing") => Ok(false),
            _ => Err(KernelError::Invalid(
                "unclassified legacy provider payload requires explicit cutover migration".into(),
            )),
        };
    }
    match crate::storage::decode_private_payload_context(&payload)
        .and_then(|context| context.entity_type)
    {
        Some(kind) if kind == "message" => Ok(true),
        Some(kind) if matches!(kind.as_str(), "event" | "thing") => Ok(false),
        _ => Err(KernelError::Invalid(
            "unclassified legacy Private payload requires explicit cutover migration".into(),
        )),
    }
}

async fn guard_sqlite_provider_payloads(
    pool: &sqlx::SqlitePool,
    at: i64,
) -> Result<(), KernelError> {
    let mut cursor = String::new();
    loop {
        let rows = sqlx::query("SELECT job_id,CASE WHEN length(payload_blob)<=131072 THEN payload_blob ELSE NULL END AS payload_blob FROM provider_dispatch_outbox WHERE state IN ('preparing','pending','retry_wait','leased') AND expires_at>? AND job_id>? ORDER BY job_id LIMIT 16")
            .bind(at).bind(&cursor).fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.get("job_id");
            if ordinary_payload(row.try_get("payload_blob")?, true)? {
                return Err(legacy_cutover_error());
            }
        }
    }
    Ok(())
}

async fn guard_sqlite_private_payloads(
    pool: &sqlx::SqlitePool,
    at: i64,
) -> Result<(), KernelError> {
    let mut cursor = String::new();
    loop {
        let rows = sqlx::query("SELECT delivery_id,CASE WHEN length(payload_blob)<=131072 THEN payload_blob ELSE NULL END AS payload_blob FROM private_payloads WHERE expires_at>? AND delivery_id>? ORDER BY delivery_id LIMIT 16")
            .bind(at).bind(&cursor).fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.get("delivery_id");
            if ordinary_payload(row.try_get("payload_blob")?, false)? {
                return Err(legacy_cutover_error());
            }
        }
    }
    Ok(())
}

async fn guard_sqlite_pull_payloads(pool: &sqlx::SqlitePool, at: i64) -> Result<(), KernelError> {
    let mut delivery_cursor = String::new();
    let mut device_cursor = Vec::<u8>::new();
    loop {
        let rows = sqlx::query("SELECT q.delivery_id,q.device_id,CASE WHEN length(COALESCE(NULLIF(q.payload_blob,X''),p.payload_blob))<=131072 THEN COALESCE(NULLIF(q.payload_blob,X''),p.payload_blob) ELSE NULL END AS payload_blob FROM provider_pull_queue q LEFT JOIN private_payloads p ON p.delivery_id=q.delivery_id WHERE q.expires_at>? AND (q.delivery_id>? OR (q.delivery_id=? AND q.device_id>?)) ORDER BY q.delivery_id,q.device_id LIMIT 16")
            .bind(at).bind(&delivery_cursor).bind(&delivery_cursor).bind(&device_cursor).fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            delivery_cursor = row.get("delivery_id");
            device_cursor = row.get("device_id");
            if ordinary_payload(row.try_get("payload_blob")?, false)? {
                return Err(legacy_cutover_error());
            }
        }
    }
    Ok(())
}
