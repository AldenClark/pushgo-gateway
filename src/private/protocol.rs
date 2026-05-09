use std::{fmt, str::FromStr};

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp_link::warp_link_core::AckStatus as WarpAckStatus;

use crate::value::ChannelId;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFlags(u8);

impl WireFlags {
    pub const fn new(codec: u8, version: u8) -> Self {
        Self(((codec & 0x0F) << 4) | (version & 0x0F))
    }

    pub const fn postcard_v1() -> Self {
        Self::new(WIRE_CODEC_POSTCARD, WIRE_VERSION_V2)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn codec(self) -> u8 {
        (self.0 >> 4) & 0x0F
    }

    pub const fn version(self) -> u8 {
        self.0 & 0x0F
    }
}

impl From<u8> for WireFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<WireFlags> for u8 {
    fn from(value: WireFlags) -> Self {
        value.bits()
    }
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

impl ClientHello {
    pub fn normalized_wire_versions(&self) -> Vec<u8> {
        Self::normalized_versions(&self.supported_wire_versions, WIRE_VERSION_V2)
    }

    pub fn normalized_payload_versions(&self) -> Vec<u8> {
        Self::normalized_versions(&self.supported_payload_versions, PRIVATE_PAYLOAD_VERSION_V1)
    }

    pub fn negotiate_wire_version(&self, preferred: u8, server_supported: &[u8]) -> Option<u8> {
        Self::negotiate_supported_version(
            preferred,
            self.normalized_wire_versions().as_slice(),
            server_supported,
        )
    }

    pub fn negotiate_payload_version(&self, preferred: u8, server_supported: &[u8]) -> Option<u8> {
        Self::negotiate_supported_version(
            preferred,
            self.normalized_payload_versions().as_slice(),
            server_supported,
        )
    }

    fn normalized_versions(versions: &[u8], default: u8) -> Vec<u8> {
        if versions.is_empty() {
            vec![default]
        } else {
            versions.to_vec()
        }
    }

    fn negotiate_supported_version(
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
            .filter(|version| server_supported.contains(version))
            .max()
    }
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

impl PrivatePayloadEnvelope {
    pub const CURRENT_VERSION: u8 = PRIVATE_PAYLOAD_VERSION_V1;

    pub fn decode_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn is_supported_version(&self) -> bool {
        self.payload_version == Self::CURRENT_VERSION
    }

    pub(crate) fn channel_id(&self) -> Option<ChannelId> {
        self.data
            .get("channel_id")
            .map(String::as_str)
            .and_then(|value| ChannelId::parse(value).ok())
    }

    pub(crate) fn parsed_channel_id(&self) -> Option<[u8; 16]> {
        self.channel_id().map(ChannelId::into_inner)
    }

    pub fn ttl(&self) -> Option<i64> {
        self.data
            .get("ttl")
            .and_then(|value| value.parse::<i64>().ok())
    }

    pub fn ttl_seconds_remaining(&self, now: i64) -> Option<u32> {
        self.ttl().and_then(|expires_at| {
            let seconds = (expires_at - now).max(0);
            u32::try_from(seconds).ok()
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFrame {
    #[serde(default)]
    pub seq: Option<u64>,
    pub delivery_id: String,
    pub status: AckFrameStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AckFrameStatus {
    Ok,
    InvalidPayload,
    Error,
}

impl AckFrameStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidPayload => "invalid_payload",
            Self::Error => "error",
        }
    }

    pub const fn to_warp(self) -> WarpAckStatus {
        match self {
            Self::Ok => WarpAckStatus::Ok,
            Self::InvalidPayload => WarpAckStatus::InvalidPayload,
            Self::Error => WarpAckStatus::Error,
        }
    }
}

impl From<WarpAckStatus> for AckFrameStatus {
    fn from(value: WarpAckStatus) -> Self {
        match value {
            WarpAckStatus::Ok => Self::Ok,
            WarpAckStatus::InvalidPayload => Self::InvalidPayload,
            WarpAckStatus::Error => Self::Error,
        }
    }
}

impl From<AckFrameStatus> for String {
    fn from(value: AckFrameStatus) -> Self {
        value.as_str().to_string()
    }
}

impl FromStr for AckFrameStatus {
    type Err = AckFrameStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ok" => Ok(Self::Ok),
            "invalid_payload" => Ok(Self::InvalidPayload),
            "error" => Ok(Self::Error),
            _ => Err(AckFrameStatusParseError),
        }
    }
}

impl TryFrom<String> for AckFrameStatus {
    type Error = AckFrameStatusParseError;

    fn try_from(value: String) -> Result<Self, AckFrameStatusParseError> {
        Self::from_str(&value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFrameStatusParseError;

impl fmt::Display for AckFrameStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ack status")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DeliverEnvelope {
    pub delivery_id: String,
    pub payload: Arc<[u8]>,
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;
    use warp_link::warp_link_core::AckStatus as WarpAckStatus;

    use super::{
        AckFrame, AckFrameStatus, ClientHello, PRIVATE_PAYLOAD_VERSION_V1, PrivatePayloadEnvelope,
        WIRE_CODEC_POSTCARD, WIRE_VERSION_V2, WireFlags,
    };

    #[test]
    fn wire_flags_round_trip_codec_and_version() {
        let flags = WireFlags::new(WIRE_CODEC_POSTCARD, WIRE_VERSION_V2);
        assert_eq!(flags.codec(), WIRE_CODEC_POSTCARD);
        assert_eq!(flags.version(), WIRE_VERSION_V2);
        assert_eq!(u8::from(flags), WireFlags::postcard_v1().bits());
    }

    #[test]
    fn client_hello_normalizes_supported_versions() {
        let hello = ClientHello {
            device_key: "device".to_string(),
            gateway_token: None,
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: Vec::new(),
            supported_payload_versions: Vec::new(),
            perf_tier: None,
            app_state: None,
        };
        assert_eq!(hello.normalized_wire_versions(), vec![WIRE_VERSION_V2]);
        assert_eq!(
            hello.normalized_payload_versions(),
            vec![PRIVATE_PAYLOAD_VERSION_V1]
        );
    }

    #[test]
    fn client_hello_negotiation_prefers_target_then_highest_common() {
        let hello = ClientHello {
            device_key: "device".to_string(),
            gateway_token: None,
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: vec![1, 2],
            supported_payload_versions: vec![1, 3],
            perf_tier: None,
            app_state: None,
        };
        assert_eq!(hello.negotiate_wire_version(2, &[2, 3]), Some(2));
        assert_eq!(hello.negotiate_payload_version(2, &[1, 4]), Some(1));
        assert_eq!(hello.negotiate_wire_version(2, &[3]), None);
    }

    #[test]
    fn payload_envelope_exposes_channel_and_ttl_helpers() {
        let channel_id = crate::api::format_channel_id(&[0x11; 16]);
        let envelope = PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data: HashMap::from([
                ("channel_id".to_string(), channel_id.clone()),
                ("ttl".to_string(), "120".to_string()),
            ]),
        };
        assert!(envelope.is_supported_version());
        assert_eq!(
            envelope.channel_id().map(|value| value.to_string()),
            Some(channel_id)
        );
        assert!(envelope.parsed_channel_id().is_some());
        assert_eq!(envelope.ttl(), Some(120));
        assert_eq!(envelope.ttl_seconds_remaining(100), Some(20));
    }

    #[test]
    fn payload_envelope_rejects_invalid_channel_id_text() {
        let envelope = PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data: HashMap::from([("channel_id".to_string(), "bad-channel".to_string())]),
        };
        assert!(envelope.channel_id().is_none());
        assert!(envelope.parsed_channel_id().is_none());
    }

    #[test]
    fn ack_status_serializes_as_stable_protocol_string() {
        let frame = AckFrame {
            seq: Some(7),
            delivery_id: "delivery-1".to_string(),
            status: AckFrameStatus::InvalidPayload,
        };
        let payload = serde_json::to_string(&frame).expect("ack frame should serialize");
        assert!(payload.contains(r#""status":"invalid_payload""#));
    }

    #[test]
    fn ack_status_rejects_unknown_text() {
        let error = serde_json::from_str::<AckFrame>(
            r#"{"seq":1,"delivery_id":"delivery-1","status":"bad"}"#,
        )
        .expect_err("invalid ack status should be rejected");
        assert!(error.to_string().contains("invalid ack status"));
    }

    #[test]
    fn ack_status_maps_to_warp_status() {
        assert_eq!(AckFrameStatus::Ok.to_warp(), WarpAckStatus::Ok);
        assert_eq!(
            AckFrameStatus::from(WarpAckStatus::InvalidPayload),
            AckFrameStatus::InvalidPayload
        );
    }
}
