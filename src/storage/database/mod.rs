use crate::storage::{
    database::{mysql::MySqlDb, pg::PostgresDb, sqlite::SqliteDb},
    types::*,
};

#[macro_use]
mod backend_impls;
mod access;
#[path = "driver/mod.rs"]
mod driver;
pub(crate) mod migration;

pub mod mysql;
pub mod pg;
pub mod sqlite;

pub use access::DatabaseAccess;
pub(crate) use access::{
    ChannelQueryDatabaseAccess, DedupeDatabaseAccess, DeliveryAuditDatabaseAccess,
    DeviceRouteDatabaseAccess, PrivateChannelDatabaseAccess, PrivateMessageDatabaseAccess,
    ProviderPullDatabaseAccess, ProviderSubscriptionDatabaseAccess, SystemStateDatabaseAccess,
};
pub use driver::DatabaseDriver;
