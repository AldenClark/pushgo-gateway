use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{
    Connection, Executor, Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{fs, path::Path, str::FromStr, time::Duration};

#[path = "sqlite/access.rs"]
mod access;
#[path = "sqlite/bootstrap.rs"]
mod bootstrap;

#[derive(Debug, Clone)]
pub struct SqliteDb {
    core_db_path: Option<String>,
    core_read_pool: SqlitePool,
    delivery_pool: SqlitePool,
    dispatch_pool: SqlitePool,
    runtime_pool: Option<SqlitePool>,
    // Core writes stay serialized to match SQLite's single-writer model.
    pool: SqlitePool,
}

impl SqliteDb {
    #[cfg(feature = "qa")]
    pub(crate) fn resource_pool_snapshot(&self) -> serde_json::Value {
        let snapshot = |name: &str, pool: &SqlitePool| serde_json::json!({"name": name, "size": pool.size(), "idle": pool.num_idle()});
        let mut pools = vec![
            snapshot("core_write", &self.pool),
            snapshot("core_read", &self.core_read_pool),
            snapshot("delivery", &self.delivery_pool),
            snapshot("dispatch", &self.dispatch_pool),
        ];
        if let Some(pool) = &self.runtime_pool {
            pools.push(snapshot("runtime", pool));
        }
        serde_json::json!({"backend": "sqlite", "pools": pools, "scope": "pool atomics only; no checkout or SQL; embedded database CPU and RSS belong to Gateway"})
    }

    pub(crate) fn ordinary_pool(&self) -> SqlitePool {
        self.pool.clone()
    }

    pub(crate) fn ordinary_control_read_pool(&self) -> SqlitePool {
        self.core_read_pool.clone()
    }

    pub(crate) fn ordinary_delivery_pool(&self) -> SqlitePool {
        self.delivery_pool.clone()
    }

    pub(crate) fn ordinary_dispatch_pool(&self) -> SqlitePool {
        self.dispatch_pool.clone()
    }

    pub(crate) async fn close_product_pools(&self) {
        self.core_read_pool.close().await;
        self.delivery_pool.close().await;
        self.dispatch_pool.close().await;
        if let Some(pool) = &self.runtime_pool {
            pool.close().await;
        }
        self.pool.close().await;
    }

    fn core_read_pool(&self) -> &SqlitePool {
        &self.core_read_pool
    }

    fn delivery_pool(&self) -> &SqlitePool {
        &self.delivery_pool
    }

    fn dispatch_pool(&self) -> &SqlitePool {
        &self.dispatch_pool
    }

    fn runtime_pool(&self) -> &SqlitePool {
        self.runtime_pool.as_ref().unwrap_or(&self.pool)
    }
}
