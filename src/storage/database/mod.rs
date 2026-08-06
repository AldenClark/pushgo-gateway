use crate::private::protocol::PrivatePayloadEnvelope;
use crate::storage::{
    database::{mysql::MySqlDb, pg::PostgresDb, sqlite::SqliteDb},
    types::*,
};

pub(crate) fn linked_private_outbox_delivery_id(payload: &[u8]) -> Option<String> {
    let envelope = PrivatePayloadEnvelope::decode_postcard(payload)?;
    if !envelope.is_supported_version() {
        return None;
    }
    envelope
        .data
        .get("delivery_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[macro_use]
mod backend_impls;
mod access;
#[path = "driver/mod.rs"]
mod driver;
pub(crate) mod migration;
pub mod upgrade;

pub mod mysql;
pub mod pg;
pub mod sqlite;

pub use access::DatabaseAccess;
pub(crate) use access::{
    ChannelQueryDatabaseAccess, DedupeDatabaseAccess, DeviceRouteDatabaseAccess,
    PrivateChannelDatabaseAccess, PrivateMessageDatabaseAccess, ProviderPullDatabaseAccess,
    ProviderSubscriptionDatabaseAccess, SystemStateDatabaseAccess,
};
pub use driver::DatabaseDriver;
