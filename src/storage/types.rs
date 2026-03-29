use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use blake3::Hasher;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Unsupported database type: {0}")]
    InvalidDatabaseType(String),
    #[error("Database URL is required for {0}")]
    MissingDatabaseUrl(&'static str),
    #[error("Async runtime is not available")]
    RuntimeUnavailable,
    #[error("Invalid device token")]
    InvalidDeviceToken,
    #[error("Invalid platform")]
    InvalidPlatform,
    #[error("Binary Error")]
    BinaryError,
    #[error("Channel not found")]
    ChannelNotFound,
    #[error("Channel password mismatch")]
    ChannelPasswordMismatch,
    #[error("Channel alias missing")]
    ChannelAliasMissing,
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Password hash error: {0}")]
    PasswordHash(String),
    #[error("Schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: String, actual: String },
}

impl From<argon2::password_hash::Error> for StoreError {
    fn from(err: argon2::password_hash::Error) -> Self {
        StoreError::PasswordHash(err.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    IOS = 1,
    MACOS = 2,
    WATCHOS = 4,
    ANDROID = 5,
    WINDOWS = 6,
}

impl FromStr for Platform {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        let normalized = raw.to_ascii_lowercase();

        match normalized.as_str() {
            "ios" => Ok(Platform::IOS),
            "ipados" => Ok(Platform::IOS),
            "macos" => Ok(Platform::MACOS),
            "watchos" => Ok(Platform::WATCHOS),
            "android" => Ok(Platform::ANDROID),
            "windows" | "win" => Ok(Platform::WINDOWS),
            _ => Err(StoreError::InvalidPlatform),
        }
    }
}

impl Platform {
    #[inline]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    #[inline]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Platform::IOS),
            2 => Some(Platform::MACOS),
            4 => Some(Platform::WATCHOS),
            5 => Some(Platform::ANDROID),
            6 => Some(Platform::WINDOWS),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
    Mysql,
}

impl DatabaseKind {
    pub fn from_url(db_url: &str) -> StoreResult<Self> {
        let trimmed = db_url.trim();
        if trimmed.is_empty() {
            return Err(StoreError::MissingDatabaseUrl("sqlite/postgres/mysql"));
        }
        let Some((scheme, _)) = trimmed.split_once("://") else {
            return Err(StoreError::InvalidDatabaseType("unknown".to_string()));
        };
        let normalized = scheme.to_ascii_lowercase();
        match normalized.as_str() {
            "sqlite" => Ok(DatabaseKind::Sqlite),
            "postgres" | "postgresql" | "pg" => Ok(DatabaseKind::Postgres),
            "mysql" => Ok(DatabaseKind::Mysql),
            other => Err(StoreError::InvalidDatabaseType(other.to_string())),
        }
    }
}

pub const DEVICEINFO_TOKEN_MIN_LEN: usize = 32;
pub const DEVICEINFO_TOKEN_MAX_LEN: usize = 128;
pub const ANDROID_TOKEN_MIN_LEN: usize = 16;
pub const ANDROID_TOKEN_MAX_LEN: usize = 4096;
pub const DEVICEINFO_MAGIC: [u8; 2] = *b"DI";
pub const DEVICEINFO_VERSION: u8 = 1;
pub const STORAGE_SCHEMA_VERSION: &str = "2026-03-26-gateway-v5";
pub const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-03-18-gateway-v4";
pub const OUTBOX_STATUS_PENDING: &str = "pending";
pub const OUTBOX_STATUS_CLAIMED: &str = "claimed";
pub const OUTBOX_STATUS_SENT: &str = "sent";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub token_raw: Arc<[u8]>,
    /// Cached token string for providers (APNs hex, FCM raw).
    pub token_str: Arc<str>,
    pub platform: Platform,
}

pub type DeviceId = [u8; 16];

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
    pub delivery_id: String,
    pub payload: Vec<u8>,
    pub sent_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPullRetryEntry {
    pub delivery_id: String,
    pub platform: Platform,
    pub provider_token: String,
    pub attempts: i32,
    pub next_retry_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDedupeRecord {
    pub delivery_id: String,
    pub created_at: i64,
    pub state: DedupeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupeState {
    Pending,
    Sent,
}

impl DedupeState {
    pub fn as_str(self) -> &'static str {
        match self {
            DedupeState::Pending => "pending",
            DedupeState::Sent => "sent",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> StoreResult<Self> {
        match value {
            "pending" => Ok(DedupeState::Pending),
            "sent" => Ok(DedupeState::Sent),
            _ => Err(StoreError::BinaryError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpDedupeReservation {
    Reserved,
    Pending { delivery_id: String },
    Sent { delivery_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticIdReservation {
    Reserved,
    Existing { semantic_id: String },
    Collision,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub alias: String,
}

#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    pub channel_id: [u8; 16],
    pub alias: String,
    pub created: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventState {
    Ongoing,
    Closed,
}

impl EventState {
    pub fn as_api_str(self) -> &'static str {
        match self {
            EventState::Ongoing => "ONGOING",
            EventState::Closed => "CLOSED",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThingState {
    Active,
    Inactive,
    Decommissioned,
}

impl ThingState {
    pub fn as_api_str(self) -> &'static str {
        match self {
            ThingState::Active => "ACTIVE",
            ThingState::Inactive => "INACTIVE",
            ThingState::Decommissioned => "DECOMMISSIONED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRouteRecordRow {
    pub device_key: String,
    pub platform: String,
    pub channel_type: String,
    pub provider_token: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    Provider {
        platform: Platform,
        provider_token: String,
        device_key: Option<String>,
    },
    Private {
        device_id: DeviceId,
        device_key: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRouteAuditWrite {
    pub device_key: String,
    pub action: String,
    pub old_platform: Option<String>,
    pub new_platform: Option<String>,
    pub old_channel_type: Option<String>,
    pub new_channel_type: Option<String>,
    pub old_provider_token: Option<String>,
    pub new_provider_token: Option<String>,
    pub issue_reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionAuditWrite {
    pub channel_id: [u8; 16],
    pub device_key: String,
    pub action: String,
    pub platform: String,
    pub channel_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryAuditWrite {
    pub delivery_id: String,
    pub channel_id: [u8; 16],
    pub device_key: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub op_id: Option<String>,
    pub path: String,
    pub status: String,
    pub error_code: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ChannelStatsDailyDelta {
    pub channel_id: [u8; 16],
    pub bucket_date: String,
    pub messages_routed: i64,
    pub deliveries_attempted: i64,
    pub deliveries_acked: i64,
    pub private_enqueued: i64,
    pub provider_attempted: i64,
    pub provider_failed: i64,
    pub provider_success: i64,
    pub private_realtime_delivered: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DeviceStatsDailyDelta {
    pub device_key: String,
    pub bucket_date: String,
    pub messages_received: i64,
    pub messages_acked: i64,
    pub private_connected_count: i64,
    pub private_pull_count: i64,
    pub provider_success_count: i64,
    pub provider_failure_count: i64,
    pub private_outbox_enqueued_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GatewayStatsHourlyDelta {
    pub bucket_hour: String,
    pub messages_routed: i64,
    pub deliveries_attempted: i64,
    pub deliveries_acked: i64,
    pub private_outbox_depth_max: i64,
    pub dedupe_pending_max: i64,
    pub active_private_sessions_max: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StatsBatchWrite {
    pub channels: Vec<ChannelStatsDailyDelta>,
    pub devices: Vec<DeviceStatsDailyDelta>,
    pub gateway: Vec<GatewayStatsHourlyDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceCleanupStats {
    pub private_outbox_pruned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutomationCounts {
    pub channel_count: usize,
    pub subscription_count: usize,
    pub delivery_dedupe_pending_count: usize,
}

#[derive(Debug, Clone)]
pub struct DispatchTargetsCacheEntry {
    pub cached_at_ms: i64,
    pub targets: Vec<DispatchTarget>,
}

impl DeviceInfo {
    pub fn from_token(platform: Platform, token: &str) -> StoreResult<Self> {
        let raw = match platform {
            Platform::ANDROID | Platform::WINDOWS => decode_android_token(token)?,
            _ => decode_hex_token(token)?,
        };
        Self::from_raw(platform, raw)
    }

    pub fn from_raw(platform: Platform, raw: Vec<u8>) -> StoreResult<Self> {
        let token_str = match platform {
            Platform::ANDROID | Platform::WINDOWS => {
                String::from_utf8(raw.clone()).map_err(|_| StoreError::BinaryError)?
            }
            _ => encode_hex_lower(&raw),
        };
        Ok(DeviceInfo {
            token_raw: Arc::<[u8]>::from(raw),
            token_str: Arc::<str>::from(token_str),
            platform,
        })
    }

    pub fn to_bytes(&self) -> StoreResult<Vec<u8>> {
        let token = self.token_raw.as_ref();
        let token_len = token.len();
        if !token_len_valid(self.platform, token_len) {
            return Err(StoreError::BinaryError);
        }

        let mut out = Vec::with_capacity(2 + 1 + 1 + 2 + token_len);
        out.extend_from_slice(&DEVICEINFO_MAGIC);
        out.push(DEVICEINFO_VERSION);
        out.push(self.platform.to_byte());
        out.extend_from_slice(&(token_len as u16).to_be_bytes());
        out.extend_from_slice(token);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> StoreResult<Self> {
        if bytes.len() < 6 {
            return Err(StoreError::BinaryError);
        }

        if bytes[0..2] != DEVICEINFO_MAGIC {
            return Err(StoreError::BinaryError);
        }

        let version = bytes[2];
        if version != DEVICEINFO_VERSION {
            return Err(StoreError::BinaryError);
        }

        let platform = Platform::from_byte(bytes[3]).ok_or(StoreError::BinaryError)?;
        let token_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;

        if !token_len_valid(platform, token_len) {
            return Err(StoreError::BinaryError);
        }

        let expected_total = 6usize.saturating_add(token_len);
        if bytes.len() != expected_total {
            return Err(StoreError::BinaryError);
        }

        let token_slice = &bytes[6..];
        let raw = token_slice.to_vec();

        DeviceInfo::from_raw(platform, raw)
    }

    #[inline]
    pub fn token_str(&self) -> &str {
        self.token_str.as_ref()
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_token(s: &str) -> StoreResult<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(StoreError::InvalidDeviceToken);
    }
    let len = bytes.len() / 2;
    if !(DEVICEINFO_TOKEN_MIN_LEN..=DEVICEINFO_TOKEN_MAX_LEN).contains(&len) {
        return Err(StoreError::InvalidDeviceToken);
    }

    let mut out = Vec::with_capacity(len);
    let mut i = 0usize;
    while i < len {
        let hi = hex_nibble(bytes[i * 2]).ok_or(StoreError::InvalidDeviceToken)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(StoreError::InvalidDeviceToken)?;
        out.push((hi << 4) | lo);
        i += 1;
    }
    Ok(out)
}

fn decode_android_token(s: &str) -> StoreResult<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(StoreError::InvalidDeviceToken);
    }
    let len = trimmed.len();
    if !(ANDROID_TOKEN_MIN_LEN..=ANDROID_TOKEN_MAX_LEN).contains(&len) {
        return Err(StoreError::InvalidDeviceToken);
    }
    Ok(trimmed.as_bytes().to_vec())
}

fn token_len_valid(platform: Platform, len: usize) -> bool {
    match platform {
        Platform::ANDROID | Platform::WINDOWS => {
            (ANDROID_TOKEN_MIN_LEN..=ANDROID_TOKEN_MAX_LEN).contains(&len)
        }
        _ => (DEVICEINFO_TOKEN_MIN_LEN..=DEVICEINFO_TOKEN_MAX_LEN).contains(&len),
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0F) as usize] as char);
    }
    out
}

pub fn verify_channel_password(password_hash: &str, password: &str) -> StoreResult<()> {
    let parsed = PasswordHash::new(password_hash)?;
    let verifier = Argon2::default();
    verifier
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| StoreError::ChannelPasswordMismatch)
}

pub fn hash_channel_password(password: &str) -> StoreResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn device_id_for(platform: Platform, token_raw: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[platform.to_byte()]);
    hasher.update(token_raw);
    *hasher.finalize().as_bytes()
}

pub fn derive_private_device_id_from_key(device_key: &str) -> [u8; 16] {
    let hash = blake3::hash(device_key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

pub fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

pub fn channel_type_for_platform(platform: Platform) -> &'static str {
    match platform {
        Platform::ANDROID => "fcm",
        Platform::WINDOWS => "wns",
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => "apns",
    }
}

pub fn provider_token_hash(token: &str) -> Vec<u8> {
    blake3::hash(token.as_bytes()).as_bytes().to_vec()
}

pub fn provider_token_preview(token: &str) -> String {
    const PREFIX: usize = 6;
    const SUFFIX: usize = 4;
    if token.len() <= PREFIX + SUFFIX + 1 {
        return token.to_string();
    }
    format!("{}***{}", &token[..PREFIX], &token[token.len() - SUFFIX..])
}

pub fn normalize_delivery_audit_path(path: &str) -> &'static str {
    match path.trim().to_ascii_lowercase().as_str() {
        "private_outbox" => "private_outbox",
        "provider" => "provider",
        "direct" => "direct",
        "wakeup_pull" => "wakeup_pull",
        _ => "provider",
    }
}

pub fn normalize_delivery_audit_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "enqueued" => "enqueued",
        "enqueue_failed" => "enqueue_failed",
        "path_rejected" => "path_rejected",
        "skipped_private_realtime" => "skipped_private_realtime",
        _ => "enqueue_failed",
    }
}

pub fn normalize_delivery_audit_error_code(error_code: Option<&str>) -> Option<String> {
    let trimmed = error_code
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let mut out = trimmed.to_string();
    if out.len() > 64 {
        out.truncate(64);
    }
    Some(out)
}

pub fn parse_private_device_id(raw: &[u8]) -> Option<DeviceId> {
    if raw.len() == 16 {
        let mut id = [0u8; 16];
        id.copy_from_slice(raw);
        return Some(id);
    }
    if raw.len() == 32 && raw[16..].iter().all(|b| *b == 0) {
        let mut id = [0u8; 16];
        id.copy_from_slice(&raw[..16]);
        return Some(id);
    }
    None
}

pub fn route_device_id_from_record(route: &DeviceRouteRecordRow) -> StoreResult<Vec<u8>> {
    let channel_type = route.channel_type.trim().to_ascii_lowercase();
    if channel_type == "private" {
        let key = route.device_key.trim();
        if key.is_empty() {
            return Err(StoreError::InvalidDeviceToken);
        }
        return Ok(derive_private_device_id_from_key(key).to_vec());
    }

    let platform: Platform = route.platform.parse()?;
    let token = route
        .provider_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(StoreError::InvalidDeviceToken)?;
    let device = DeviceInfo::from_token(platform, token)?;
    Ok(device_id_for(platform, &device.token_raw).to_vec())
}

pub fn route_snapshot_fields(provider_token: Option<&str>) -> (Option<Vec<u8>>, Option<String>) {
    let token = provider_token
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let hash = token.map(provider_token_hash);
    let preview = token.map(provider_token_preview);
    (hash, preview)
}

#[derive(Debug, Deserialize)]
struct PrivatePayloadEnvelopeOwned {
    payload_version: u8,
    data: HashMap<String, String>,
}

const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;

pub fn decode_private_payload_context(payload: &[u8]) -> Option<PrivatePayloadContext> {
    let envelope = postcard::from_bytes::<PrivatePayloadEnvelopeOwned>(payload).ok()?;
    if envelope.payload_version != PRIVATE_PAYLOAD_VERSION_V1 {
        return None;
    }
    let channel_id = envelope
        .data
        .get("channel_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| crate::api::parse_channel_id(value).ok());
    let entity_type = envelope
        .data
        .get("entity_type")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let entity_id = envelope
        .data
        .get("entity_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let op_id = envelope
        .data
        .get("op_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    Some(PrivatePayloadContext {
        channel_id,
        entity_type,
        entity_id,
        op_id,
    })
}
