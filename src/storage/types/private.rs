use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use super::{DeviceId, StoreResult};

pub const OUTBOX_STATUS_PENDING: &str = "pending";
pub const OUTBOX_STATUS_CLAIMED: &str = "claimed";
pub const OUTBOX_STATUS_SENT: &str = "sent";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateDeviceKey {
    pub key_id: u32,
    pub key_hash: Vec<u8>,
    pub issued_at: i64,
    pub valid_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSession {
    pub device_id: DeviceId,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateMessage {
    pub payload: Vec<u8>,
    pub size: usize,
    pub sent_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrivatePayloadContext {
    pub channel_id: Option<[u8; 16]>,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub op_id: Option<String>,
}

impl PrivatePayloadContext {
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let envelope = postcard::from_bytes::<PrivatePayloadEnvelopeOwned>(payload).ok()?;
        if envelope.payload_version != PRIVATE_PAYLOAD_VERSION_V1 {
            return None;
        }
        Some(Self {
            channel_id: envelope
                .data
                .get("channel_id")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .and_then(|value| crate::api::parse_channel_id(value).ok()),
            entity_type: read_non_empty_owned(&envelope.data, "entity_type"),
            entity_id: read_non_empty_owned(&envelope.data, "entity_id"),
            op_id: read_non_empty_owned(&envelope.data, "op_id"),
        })
    }
}

pub fn decode_private_payload_context(payload: &[u8]) -> Option<PrivatePayloadContext> {
    PrivatePayloadContext::decode(payload)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivateOutboxEntry {
    pub delivery_id: String,
    pub status: String,
    pub attempts: u32,
    pub occurred_at: i64,
    pub created_at: i64,
    pub claimed_at: Option<i64>,
    pub first_sent_at: Option<i64>,
    pub last_attempt_at: Option<i64>,
    pub acked_at: Option<i64>,
    pub fallback_sent_at: Option<i64>,
    pub next_attempt_at: i64,
    pub last_error_code: Option<String>,
    pub last_error_detail: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderPullItem {
    pub device_id: DeviceId,
    pub delivery_id: String,
    pub payload: Vec<u8>,
    pub sent_at: i64,
    pub expires_at: i64,
    pub platform: super::Platform,
    pub provider_token: String,
}

#[derive(Debug, Deserialize)]
struct PrivatePayloadEnvelopeOwned {
    payload_version: u8,
    data: HashMap<String, String>,
}

const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;

fn read_non_empty_owned(data: &HashMap<String, String>, key: &str) -> Option<String> {
    data.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[allow(dead_code)]
fn _store_result_marker(_: StoreResult<()>) {}
