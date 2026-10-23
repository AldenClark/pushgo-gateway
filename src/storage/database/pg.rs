use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};

#[path = "pg/access.rs"]
mod access;
#[path = "pg/bootstrap.rs"]
mod bootstrap;

#[derive(Clone)]
pub struct PostgresDb {
    pool: PgPool,
    ordinary_store: std::sync::Arc<std::sync::OnceLock<crate::ordinary::pg_store::PgDeliveryStore>>,
}

impl PostgresDb {
    pub(crate) fn set_ordinary_store(&self, store: crate::ordinary::pg_store::PgDeliveryStore) {
        let _ = self.ordinary_store.set(store);
    }
    pub(crate) fn ordinary_store(&self) -> Option<&crate::ordinary::pg_store::PgDeliveryStore> {
        self.ordinary_store.get()
    }
    /// Ordinary messages reuse the normal product database and lifecycle.
    pub(crate) fn ordinary_pool(&self) -> PgPool {
        self.pool.clone()
    }
}

impl std::fmt::Debug for PostgresDb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresDb")
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}
