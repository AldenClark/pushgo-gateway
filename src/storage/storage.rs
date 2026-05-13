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

impl Storage {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.init_started"
        );
        let db_url = db_url.and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        let driver = DatabaseDriver::new(db_url).await.inspect_err(|err| {
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
