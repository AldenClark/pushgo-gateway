use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};

#[path = "pg/access.rs"]
mod access;
#[path = "pg/bootstrap.rs"]
mod bootstrap;

#[derive(Debug, Clone)]
pub struct PostgresDb {
    pool: PgPool,
}
