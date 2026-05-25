use crate::storage::{
    cache::{CacheAccess, CacheMemorySnapshot, CacheStore},
    database::DatabaseDriver,
    types::*,
};
use std::sync::Arc;

#[path = "storage/channels.rs"]
mod channels;
#[path = "storage/dedupe.rs"]
mod dedupe;
#[path = "storage/private_delivery.rs"]
mod private_delivery;
#[path = "storage/system.rs"]
mod system;

const OP_DEDUPE_PENDING_STALE_MILLIS: i64 = 2 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<DatabaseDriver>,
    cache: Arc<CacheStore>,
}

#[derive(Debug, Clone, Default)]
pub struct StorageInitConfig {
    pub db_url: Option<String>,
    pub sqlite_telemetry_db_url: Option<String>,
    pub sqlite_runtime_db_url: Option<String>,
    pub stats_enabled: bool,
    pub mcp_enabled: bool,
}

impl Storage {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        Self::new_with_config(StorageInitConfig {
            db_url: db_url.map(str::to_string),
            stats_enabled: true,
            mcp_enabled: true,
            ..StorageInitConfig::default()
        })
        .await
    }

    pub async fn new_with_config(config: StorageInitConfig) -> StoreResult<Self> {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.init_started"
        );
        let driver = DatabaseDriver::new_with_config(config)
            .await
            .inspect_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "storage.init_failed",
                    error = %(err.to_string())
                );
            })?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.init_finished"
        );
        Ok(Self {
            db: Arc::new(driver),
            cache: Arc::new(CacheStore::new()),
        })
    }

    pub fn cache_memory_snapshot(&self) -> CacheMemorySnapshot {
        self.cache.memory_snapshot()
    }
}

#[cfg(test)]
#[path = "storage/tests/mod.rs"]
mod tests;
