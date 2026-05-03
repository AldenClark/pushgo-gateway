use super::*;

#[path = "access/channels.rs"]
mod channels;
#[path = "access/maintenance.rs"]
mod maintenance;
#[path = "access/outbox.rs"]
mod outbox;
#[path = "access/private_channels.rs"]
mod private_channels;
#[path = "access/provider.rs"]
mod provider;
#[path = "access/routes.rs"]
mod routes;
#[path = "access/subscriptions.rs"]
mod subscriptions;

impl_backend_database_access!(MySqlDb);

fn decode_mysql_attempts(row: &sqlx::mysql::MySqlRow) -> u32 {
    let attempts: i32 = row.get("attempts");
    attempts.max(0) as u32
}

fn decode_mysql_payload_size(row: &sqlx::mysql::MySqlRow) -> usize {
    let payload_size: i32 = row.get("payload_size");
    payload_size.max(0) as usize
}
