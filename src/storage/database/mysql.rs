use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{MySqlPool, Row};

#[path = "mysql/access.rs"]
mod access;
#[path = "mysql/bootstrap.rs"]
mod bootstrap;

#[derive(Debug, Clone)]
pub struct MySqlDb {
    pool: MySqlPool,
}
