use crate::storage::types::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{
    Connection, Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{fs, path::Path, str::FromStr, time::Duration};

#[path = "sqlite/access.rs"]
mod access;
#[path = "sqlite/bootstrap.rs"]
mod bootstrap;

#[derive(Debug, Clone)]
pub struct SqliteDb {
    pool: SqlitePool,
}
