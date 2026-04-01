use crate::storage::{
    cache::{CacheAccess, CacheStore},
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

const OP_DEDUPE_PENDING_STALE_SECS: i64 = 2 * 60;

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<DatabaseDriver>,
    cache: Arc<CacheStore>,
}

impl Storage {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        let db_url = db_url.and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Ok(Self {
            db: Arc::new(DatabaseDriver::new(db_url).await?),
            cache: Arc::new(CacheStore::new()),
        })
    }
}

#[cfg(test)]
#[path = "storage/tests/mod.rs"]
mod tests;
