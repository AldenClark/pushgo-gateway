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
pub(super) mod routes;
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

pub(super) fn decode_mysql_optional_text(
    row: &sqlx::mysql::MySqlRow,
    column: &str,
) -> StoreResult<Option<String>> {
    if let Ok(value) = row.try_get::<Option<String>, _>(column) {
        return Ok(value);
    }
    let raw = row.try_get::<Option<Vec<u8>>, _>(column)?;
    raw.map(|value| String::from_utf8(value).map_err(|_| StoreError::BinaryError))
        .transpose()
}

pub(super) fn decode_mysql_text(row: &sqlx::mysql::MySqlRow, column: &str) -> StoreResult<String> {
    decode_mysql_optional_text(row, column)?.ok_or(StoreError::BinaryError)
}

fn decode_mysql_private_outbox_entry(
    row: &sqlx::mysql::MySqlRow,
) -> StoreResult<PrivateOutboxEntry> {
    Ok(PrivateOutboxEntry {
        delivery_id: decode_mysql_text(row, "delivery_id")?,
        status: row.get("status"),
        attempts: decode_mysql_attempts(row),
        occurred_at: row.get("occurred_at"),
        created_at: row.get("created_at"),
        claimed_at: row.get("claimed_at"),
        claimed_by: row.get("claimed_by"),
        claim_generation: row.get::<i64, _>("claim_generation").max(0) as u64,
        first_sent_at: row.get("first_sent_at"),
        last_attempt_at: row.get("last_attempt_at"),
        acked_at: row.get("acked_at"),
        fallback_sent_at: row.get("fallback_sent_at"),
        next_attempt_at: row.get("next_attempt_at"),
        last_error_code: row.get("last_error_code"),
        last_error_detail: row.get("last_error_detail"),
        updated_at: row.get("updated_at"),
    })
}
