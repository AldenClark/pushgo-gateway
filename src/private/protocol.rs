use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const WIRE_CODEC_POSTCARD: u8 = 1;
pub const WIRE_VERSION_V2: u8 = 2;
pub const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;
pub const SUPPORTED_WIRE_VERSIONS: &[u8] = &[WIRE_VERSION_V2];
pub const SUPPORTED_PAYLOAD_VERSIONS: &[u8] = &[PRIVATE_PAYLOAD_VERSION_V1];
pub const PERF_TIER_HIGH: &str = "high";
pub const PERF_TIER_BALANCED: &str = "balanced";
pub const PERF_TIER_LOW: &str = "low";
pub const APP_STATE_FOREGROUND: &str = "foreground";
pub const APP_STATE_BACKGROUND: &str = "background";

pub const fn wire_flags(codec: u8, version: u8) -> u8 {
    ((codec & 0x0F) << 4) | (version & 0x0F)
}

pub const fn wire_codec(flags: u8) -> u8 {
    (flags >> 4) & 0x0F
}

pub const fn wire_version(flags: u8) -> u8 {
    flags & 0x0F
}

pub const fn postcard_v1_flags() -> u8 {
    wire_flags(WIRE_CODEC_POSTCARD, WIRE_VERSION_V2)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    ClientHello = 1,
    ServerChallenge = 2,
    ClientProof = 3,
    ServerWelcome = 4,
    Subscribe = 5,
    Unsubscribe = 6,
    Pull = 7,
    Deliver = 8,
    Ack = 9,
    Error = 10,
    Ping = 11,
    Pong = 12,
    GoAway = 13,
}

impl FrameType {
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(FrameType::ClientHello),
            2 => Some(FrameType::ServerChallenge),
            3 => Some(FrameType::ClientProof),
            4 => Some(FrameType::ServerWelcome),
            5 => Some(FrameType::Subscribe),
            6 => Some(FrameType::Unsubscribe),
            7 => Some(FrameType::Pull),
            8 => Some(FrameType::Deliver),
            9 => Some(FrameType::Ack),
            10 => Some(FrameType::Error),
            11 => Some(FrameType::Ping),
            12 => Some(FrameType::Pong),
            13 => Some(FrameType::GoAway),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub ty: FrameType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub device_key: String,
    #[serde(default)]
    pub gateway_token: Option<String>,
    #[serde(default)]
    pub resume_token: Option<String>,
    #[serde(default)]
    pub last_acked_seq: Option<u64>,
    #[serde(default)]
    pub supported_wire_versions: Vec<u8>,
    #[serde(default)]
    pub supported_payload_versions: Vec<u8>,
    #[serde(default)]
    pub perf_tier: Option<String>,
    #[serde(default)]
    pub app_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerChallenge {
    pub nonce: Vec<u8>,
    pub ts: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientProof {
    pub hmac: Vec<u8>,
    pub ts: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerWelcome {
    pub session_id: String,
    pub resume_token: String,
    pub heartbeat_secs: u16,
    pub ping_interval_secs: u16,
    pub idle_timeout_secs: u16,
    pub max_backoff_secs: u16,
    pub max_frame_bytes: u32,
    pub negotiated_wire_version: u8,
    pub negotiated_payload_version: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelSubscribe {
    pub channel_id: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelUnsubscribe {
    pub channel_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullRequest {
    pub limit: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeliverFrame {
    pub seq: u64,
    pub delivery_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivatePayloadEnvelope {
    pub payload_version: u8,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFrame {
    #[serde(default)]
    pub seq: Option<u64>,
    pub delivery_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DeliverEnvelope {
    pub delivery_id: String,
    pub payload: Vec<u8>,
}

pub fn negotiate_version(
    preferred: u8,
    client_supported: &[u8],
    server_supported: &[u8],
) -> Option<u8> {
    if client_supported.contains(&preferred) && server_supported.contains(&preferred) {
        return Some(preferred);
    }
    client_supported
        .iter()
        .copied()
        .filter(|v| server_supported.contains(v))
        .max()
}

pub fn normalize_client_wire_versions(versions: &[u8]) -> Vec<u8> {
    if versions.is_empty() {
        vec![WIRE_VERSION_V2]
    } else {
        versions.to_vec()
    }
}

pub fn normalize_client_payload_versions(versions: &[u8]) -> Vec<u8> {
    if versions.is_empty() {
        vec![PRIVATE_PAYLOAD_VERSION_V1]
    } else {
        versions.to_vec()
    }
}
