use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Connection, MySqlConnection, MySqlPool, Row, mysql::MySqlPoolOptions};

#[path = "mysql/access.rs"]
mod access;
#[path = "mysql/bootstrap.rs"]
mod bootstrap;

#[derive(Clone)]
pub struct MySqlDb {
    pool: MySqlPool,
    ordinary_store:
        std::sync::Arc<std::sync::OnceLock<crate::ordinary::mysql_store::MySqlDeliveryStore>>,
}

impl MySqlDb {
    pub(crate) fn set_ordinary_store(
        &self,
        store: crate::ordinary::mysql_store::MySqlDeliveryStore,
    ) {
        let _ = self.ordinary_store.set(store);
    }

    pub(crate) fn ordinary_store(
        &self,
    ) -> Option<&crate::ordinary::mysql_store::MySqlDeliveryStore> {
        self.ordinary_store.get()
    }

    pub(crate) fn ordinary_pool(&self) -> MySqlPool {
        self.pool.clone()
    }
}

impl std::fmt::Debug for MySqlDb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MySqlDb")
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}
