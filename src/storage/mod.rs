use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use blake3::Hasher;
use chrono::Utc;
use hashbrown::HashMap;
use parking_lot::RwLock;
use scc::HashCache;
use serde::{Deserialize, Serialize};
use sqlx::{
    MySqlPool, PgPool, Row, SqlitePool,
    mysql::MySqlPoolOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::Path, str::FromStr, sync::Arc, time::Duration};
use thiserror::Error;

use crate::util::{generate_hex_id_128, random_id_bytes_128};

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

type StoreResult<T> = Result<T, StoreError>;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
    fn to_byte(self) -> u8 {
        self as u8
    }

    #[inline]
    fn from_byte(b: u8) -> Option<Self> {
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
enum DatabaseKind {
    Sqlite,
    Postgres,
    Mysql,
}

impl DatabaseKind {
    fn from_url(db_url: Option<&str>) -> StoreResult<Self> {
        let Some(raw) = db_url else {
            return Err(StoreError::MissingDatabaseUrl("sqlite/postgres/mysql"));
        };
        let trimmed = raw.trim();
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

const DEVICEINFO_TOKEN_MIN_LEN: usize = 32;
const DEVICEINFO_TOKEN_MAX_LEN: usize = 128;
const ANDROID_TOKEN_MIN_LEN: usize = 16;
const ANDROID_TOKEN_MAX_LEN: usize = 4096;
const DEVICEINFO_MAGIC: [u8; 2] = *b"DI";
const DEVICEINFO_VERSION: u8 = 1;
const STORAGE_SCHEMA_VERSION: &str = "2026-03-26-gateway-v5";
const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-03-18-gateway-v4";
const OUTBOX_STATUS_PENDING: &str = "pending";
const OUTBOX_STATUS_CLAIMED: &str = "claimed";
const OUTBOX_STATUS_SENT: &str = "sent";
const CHANNEL_INFO_CACHE_MIN_CAPACITY: usize = 1024;
const CHANNEL_INFO_CACHE_MAX_CAPACITY: usize = 16384;
const CHANNEL_DEVICES_CACHE_MIN_CAPACITY: usize = 2048;
const CHANNEL_DEVICES_CACHE_MAX_CAPACITY: usize = 32768;
const DISPATCH_TARGETS_CACHE_MIN_CAPACITY: usize = 2048;
const DISPATCH_TARGETS_CACHE_MAX_CAPACITY: usize = 32768;
const DISPATCH_TARGETS_CACHE_TTL_MS_DEFAULT: i64 = 2000;
const DISPATCH_TARGETS_CACHE_TTL_MS_MIN: i64 = 200;
const DISPATCH_TARGETS_CACHE_TTL_MS_MAX: i64 = 10_000;

#[inline]
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

#[inline]
fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

#[inline]
fn channel_type_for_platform(platform: Platform) -> &'static str {
    match platform {
        Platform::ANDROID => "fcm",
        Platform::WINDOWS => "wns",
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => "apns",
    }
}

#[inline]
fn provider_token_hash(token: &str) -> Vec<u8> {
    blake3::hash(token.as_bytes()).as_bytes().to_vec()
}

fn provider_token_preview(token: &str) -> String {
    const PREFIX: usize = 6;
    const SUFFIX: usize = 4;
    if token.len() <= PREFIX + SUFFIX + 1 {
        return token.to_string();
    }
    format!("{}***{}", &token[..PREFIX], &token[token.len() - SUFFIX..])
}

fn normalize_delivery_audit_path(path: &str) -> &'static str {
    match path.trim().to_ascii_lowercase().as_str() {
        "private_outbox" => "private_outbox",
        "provider" => "provider",
        "direct" => "direct",
        "wakeup_pull" => "wakeup_pull",
        _ => "provider",
    }
}

fn normalize_delivery_audit_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "enqueued" => "enqueued",
        "enqueue_failed" => "enqueue_failed",
        "path_rejected" => "path_rejected",
        "skipped_private_realtime" => "skipped_private_realtime",
        _ => "enqueue_failed",
    }
}

fn normalize_delivery_audit_error_code(error_code: Option<&str>) -> Option<String> {
    let trimmed = error_code
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let mut out = trimmed.to_string();
    if out.len() > 64 {
        out.truncate(64);
    }
    Some(out)
}

fn parse_private_device_id(raw: &[u8]) -> Option<DeviceId> {
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

fn derive_private_device_id_from_key(device_key: &str) -> [u8; 16] {
    let hash = blake3::hash(device_key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

fn route_device_id_from_record(route: &DeviceRouteRecordRow) -> StoreResult<Vec<u8>> {
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

fn route_device_token_fields_from_record(
    route: &DeviceRouteRecordRow,
) -> StoreResult<(u8, Vec<u8>)> {
    let platform: Platform = route.platform.parse()?;
    if let Some(token) = route
        .provider_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let info = DeviceInfo::from_token(platform, token)?;
        return Ok((platform.to_byte(), info.token_raw.to_vec()));
    }

    let key = route.device_key.trim();
    if key.is_empty() {
        return Err(StoreError::InvalidDeviceToken);
    }

    // Route snapshots can exist before provider_token is bound; keep a stable,
    // parseable fallback payload derived from device_key for every platform.
    let fallback_raw = key.as_bytes().to_vec();
    Ok((platform.to_byte(), fallback_raw))
}

fn route_snapshot_fields(provider_token: Option<&str>) -> (Option<Vec<u8>>, Option<String>) {
    let token = provider_token
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let hash = token.map(provider_token_hash);
    let preview = token.map(provider_token_preview);
    (hash, preview)
}

async fn apply_route_snapshot_to_subscriptions_postgres(
    pool: &PgPool,
    device_id: &[u8],
    device_key: &str,
    platform: &str,
    channel_type: &str,
    provider_token: Option<&str>,
    now_ts: i64,
) -> StoreResult<()> {
    let (token_hash, token_preview) = route_snapshot_fields(provider_token);
    sqlx::query(
        "UPDATE channel_subscriptions \
         SET platform = $2, \
             channel_type = $3, \
             device_key = $4, \
             provider_token = $5, \
             provider_token_hash = $6, \
             provider_token_preview = $7, \
             route_version = route_version + 1, \
             updated_at = $8 \
         WHERE device_id = $1",
    )
    .bind(device_id)
    .bind(platform)
    .bind(channel_type)
    .bind(device_key)
    .bind(provider_token)
    .bind(token_hash.as_deref())
    .bind(token_preview.as_deref())
    .bind(now_ts)
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_route_snapshot_to_subscriptions_mysql(
    pool: &MySqlPool,
    device_id: &[u8],
    device_key: &str,
    platform: &str,
    channel_type: &str,
    provider_token: Option<&str>,
    now_ts: i64,
) -> StoreResult<()> {
    let (token_hash, token_preview) = route_snapshot_fields(provider_token);
    sqlx::query(
        "UPDATE channel_subscriptions \
         SET platform = ?, \
             channel_type = ?, \
             device_key = ?, \
             provider_token = ?, \
             provider_token_hash = ?, \
             provider_token_preview = ?, \
             route_version = route_version + 1, \
             updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(platform)
    .bind(channel_type)
    .bind(device_key)
    .bind(provider_token)
    .bind(token_hash.as_deref())
    .bind(token_preview.as_deref())
    .bind(now_ts)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_route_snapshot_to_subscriptions_sqlite(
    pool: &SqlitePool,
    device_id: &[u8],
    device_key: &str,
    platform: &str,
    channel_type: &str,
    provider_token: Option<&str>,
    now_ts: i64,
) -> StoreResult<()> {
    let (token_hash, token_preview) = route_snapshot_fields(provider_token);
    sqlx::query(
        "UPDATE channel_subscriptions \
         SET platform = ?, \
             channel_type = ?, \
             device_key = ?, \
             provider_token = ?, \
             provider_token_hash = ?, \
             provider_token_preview = ?, \
             route_version = route_version + 1, \
             updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(platform)
    .bind(channel_type)
    .bind(device_key)
    .bind(provider_token)
    .bind(token_hash.as_deref())
    .bind(token_preview.as_deref())
    .bind(now_ts)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PrivatePayloadEnvelopeOwned {
    payload_version: u8,
    data: HashMap<String, String>,
}

const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;

fn decode_private_payload_context(payload: &[u8]) -> Option<PrivatePayloadContext> {
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
    fn as_str(self) -> &'static str {
        match self {
            DedupeState::Pending => "pending",
            DedupeState::Sent => "sent",
        }
    }

    fn from_str(value: &str) -> StoreResult<Self> {
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

impl DeviceInfo {
    /// Parse and validate a client-provided token string.
    pub fn from_token(platform: Platform, token: &str) -> StoreResult<Self> {
        let raw = match platform {
            Platform::ANDROID | Platform::WINDOWS => decode_android_token(token)?,
            _ => decode_hex_token(token)?,
        };
        Self::from_raw(platform, raw)
    }

    /// Build from raw bytes loaded from storage.
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

    /// Binary format (v1):
    /// [ magic: "DI" ][ version: u8 ][ platform: u8 ][ token_len: u16 BE ][ token_raw bytes ].
    ///
    /// Storage keeps raw bytes; string forms are rebuilt in memory.
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

    /// Parse the custom binary format into `DeviceInfo`.
    pub fn from_bytes(bytes: &[u8]) -> StoreResult<Self> {
        // Minimum payload: magic(2) + version(1) + platform(1) + len(2).
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

fn verify_channel_password(password_hash: &str, password: &str) -> StoreResult<()> {
    let parsed = PasswordHash::new(password_hash)?;
    let verifier = Argon2::default();
    verifier
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| StoreError::ChannelPasswordMismatch)
}

fn hash_channel_password(password: &str) -> StoreResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn device_id_for(platform: Platform, token_raw: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[platform.to_byte()]);
    hasher.update(token_raw);
    *hasher.finalize().as_bytes()
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

#[async_trait]
pub trait StoreApi: Send + Sync {
    async fn load_private_outbox_entry_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>>;

    async fn channel_info_async(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>>;

    async fn subscribe_channel_async(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome>;

    async fn unsubscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool>;

    async fn retire_device_async(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize>;

    async fn migrate_device_subscriptions_async(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize>;

    async fn delete_private_device_state_async(&self, device_id: DeviceId) -> StoreResult<()>;

    async fn insert_private_message_async(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()>;

    async fn enqueue_private_outbox_async(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()>;

    async fn list_private_outbox_async(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>>;

    async fn count_private_outbox_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize>;

    async fn cleanup_private_expired_data_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize>;

    async fn cleanup_pending_op_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize>;

    async fn cleanup_semantic_id_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize>;

    async fn cleanup_delivery_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize>;

    async fn bind_private_token_async(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()>;

    async fn load_device_routes_async(&self) -> StoreResult<Vec<DeviceRouteRecordRow>>;

    async fn upsert_device_route_async(&self, route: &DeviceRouteRecordRow) -> StoreResult<()>;

    async fn append_device_route_audit_async(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()>;

    async fn append_subscription_audit_async(
        &self,
        entry: &SubscriptionAuditWrite,
    ) -> StoreResult<()>;

    async fn append_delivery_audit_async(&self, entry: &DeliveryAuditWrite) -> StoreResult<()>;

    async fn append_delivery_audit_batch_async(
        &self,
        entries: &[DeliveryAuditWrite],
    ) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        for entry in entries {
            self.append_delivery_audit_async(entry).await?;
        }
        Ok(())
    }

    async fn apply_stats_batch_async(&self, batch: &StatsBatchWrite) -> StoreResult<()>;

    async fn list_channel_devices_async(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<DeviceInfo>>;

    async fn list_channel_dispatch_targets_async(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>>;

    async fn list_subscribed_channels_for_device_async(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>>;

    async fn list_private_subscribed_channels_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>>;

    async fn channel_info_with_password_async(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>>;

    async fn rename_channel_async(
        &self,
        channel_id: [u8; 16],
        password: &str,
        alias: &str,
    ) -> StoreResult<()>;

    async fn upsert_private_channel_async(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
    ) -> StoreResult<SubscribeOutcome>;

    async fn private_subscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()>;

    async fn private_unsubscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()>;

    async fn list_private_subscribers_async(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>>;

    async fn lookup_private_device_async(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>>;

    async fn load_private_message_async(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>>;

    async fn load_private_payload_context_async(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>>;

    async fn enqueue_provider_pull_item_async(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()>;

    async fn pull_provider_item_async(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>>;

    async fn list_provider_pull_retry_due_async(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>>;

    async fn bump_provider_pull_retry_async(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool>;

    async fn clear_provider_pull_retry_async(&self, delivery_id: &str) -> StoreResult<()>;

    async fn mark_private_fallback_sent_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()>;

    async fn defer_private_fallback_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()>;

    async fn ack_private_delivery_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()>;

    async fn clear_private_outbox_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize>;

    async fn clear_private_outbox_for_device_with_entries_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>>;

    async fn list_private_outbox_due_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>>;

    async fn claim_private_outbox_due_async(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>>;

    async fn claim_private_outbox_due_for_device_async(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>>;

    async fn count_private_outbox_total_async(&self) -> StoreResult<usize>;

    async fn reserve_delivery_dedupe_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool>;

    async fn reserve_semantic_id_async(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation>;

    async fn reserve_op_dedupe_pending_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation>;

    async fn mark_op_dedupe_sent_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool>;

    async fn clear_op_dedupe_pending_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()>;

    async fn run_maintenance_cleanup_async(
        &self,
        now: i64,
        dedupe_before: i64,
    ) -> StoreResult<MaintenanceCleanupStats>;

    async fn automation_counts_async(&self) -> StoreResult<AutomationCounts>;

    async fn automation_reset_async(&self) -> StoreResult<()>;
}

pub type Store = Arc<dyn StoreApi>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceCleanupStats {
    pub private_outbox_pruned: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutomationCounts {
    pub channel_count: usize,
    pub subscription_count: usize,
    pub delivery_dedupe_pending_count: usize,
}

pub async fn new_store(db_url: Option<&str>) -> StoreResult<Store> {
    let db_url = db_url.and_then(|url| {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let kind = DatabaseKind::from_url(db_url)?;
    match kind {
        DatabaseKind::Sqlite => {
            let url = db_url.ok_or(StoreError::MissingDatabaseUrl("sqlite"))?;
            Ok(Arc::new(build_sql_store(DatabaseKind::Sqlite, url).await?))
        }
        DatabaseKind::Postgres => {
            let url = db_url.ok_or(StoreError::MissingDatabaseUrl("postgres"))?;
            Ok(Arc::new(
                build_sql_store(DatabaseKind::Postgres, url).await?,
            ))
        }
        DatabaseKind::Mysql => {
            let url = db_url.ok_or(StoreError::MissingDatabaseUrl("mysql"))?;
            Ok(Arc::new(build_sql_store(DatabaseKind::Mysql, url).await?))
        }
    }
}

async fn build_sql_store(kind: DatabaseKind, url: &str) -> StoreResult<SqlxStore> {
    SqlxStore::connect(kind, url).await
}

fn ensure_sqlite_parent_dir(db_path: &Path) -> StoreResult<()> {
    if let Some(parent) = db_path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SqlxStore {
    backend: SqlxBackend,
    device_cache: Arc<RwLock<HashMap<[u8; 32], DeviceInfo>>>,
    channel_info_cache: Arc<HashCache<[u8; 16], ChannelInfo>>,
    channel_devices_cache: Arc<HashCache<[u8; 16], Vec<DeviceInfo>>>,
    channel_dispatch_targets_cache: Arc<HashCache<[u8; 16], DispatchTargetsCacheEntry>>,
    dispatch_targets_cache_ttl_ms: i64,
}

#[derive(Debug, Clone)]
struct DispatchTargetsCacheEntry {
    cached_at_ms: i64,
    targets: Vec<DispatchTarget>,
}

#[derive(Debug, Clone)]
enum SqlxBackend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
    Mysql(MySqlPool),
}

impl SqlxStore {
    async fn connect(kind: DatabaseKind, url: &str) -> StoreResult<Self> {
        let dispatch_targets_cache_ttl_ms = std::env::var("PUSHGO_DISPATCH_TARGETS_CACHE_TTL_MS")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .map(|value| {
                value.clamp(
                    DISPATCH_TARGETS_CACHE_TTL_MS_MIN,
                    DISPATCH_TARGETS_CACHE_TTL_MS_MAX,
                )
            })
            .unwrap_or(DISPATCH_TARGETS_CACHE_TTL_MS_DEFAULT);
        let store = match kind {
            DatabaseKind::Sqlite => {
                let connect_options = SqliteConnectOptions::from_str(url)?;
                ensure_sqlite_parent_dir(connect_options.get_filename())?;
                let connect_options = connect_options
                    .create_if_missing(true)
                    .busy_timeout(Duration::from_millis(5000))
                    .foreign_keys(true);
                let pool = SqlitePoolOptions::new()
                    .max_connections(16)
                    .connect_with(connect_options)
                    .await?;
                SqlxStore {
                    backend: SqlxBackend::Sqlite(pool),
                    device_cache: Default::default(),
                    channel_info_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_INFO_CACHE_MIN_CAPACITY,
                        CHANNEL_INFO_CACHE_MAX_CAPACITY,
                    )),
                    channel_devices_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_DEVICES_CACHE_MIN_CAPACITY,
                        CHANNEL_DEVICES_CACHE_MAX_CAPACITY,
                    )),
                    channel_dispatch_targets_cache: Arc::new(HashCache::with_capacity(
                        DISPATCH_TARGETS_CACHE_MIN_CAPACITY,
                        DISPATCH_TARGETS_CACHE_MAX_CAPACITY,
                    )),
                    dispatch_targets_cache_ttl_ms,
                }
            }
            DatabaseKind::Postgres => {
                let pool = PgPoolOptions::new()
                    .max_connections(16)
                    .connect(url)
                    .await?;
                SqlxStore {
                    backend: SqlxBackend::Postgres(pool),
                    device_cache: Default::default(),
                    channel_info_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_INFO_CACHE_MIN_CAPACITY,
                        CHANNEL_INFO_CACHE_MAX_CAPACITY,
                    )),
                    channel_devices_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_DEVICES_CACHE_MIN_CAPACITY,
                        CHANNEL_DEVICES_CACHE_MAX_CAPACITY,
                    )),
                    channel_dispatch_targets_cache: Arc::new(HashCache::with_capacity(
                        DISPATCH_TARGETS_CACHE_MIN_CAPACITY,
                        DISPATCH_TARGETS_CACHE_MAX_CAPACITY,
                    )),
                    dispatch_targets_cache_ttl_ms,
                }
            }
            DatabaseKind::Mysql => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(16)
                    .connect(url)
                    .await?;
                SqlxStore {
                    backend: SqlxBackend::Mysql(pool),
                    device_cache: Default::default(),
                    channel_info_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_INFO_CACHE_MIN_CAPACITY,
                        CHANNEL_INFO_CACHE_MAX_CAPACITY,
                    )),
                    channel_devices_cache: Arc::new(HashCache::with_capacity(
                        CHANNEL_DEVICES_CACHE_MIN_CAPACITY,
                        CHANNEL_DEVICES_CACHE_MAX_CAPACITY,
                    )),
                    channel_dispatch_targets_cache: Arc::new(HashCache::with_capacity(
                        DISPATCH_TARGETS_CACHE_MIN_CAPACITY,
                        DISPATCH_TARGETS_CACHE_MAX_CAPACITY,
                    )),
                    dispatch_targets_cache_ttl_ms,
                }
            }
        };
        store.init_schema().await?;
        Ok(store)
    }

    #[inline]
    fn invalidate_channel_devices_cache(&self, channel_id: [u8; 16]) {
        let _ = self.channel_devices_cache.remove_sync(&channel_id);
        let _ = self.channel_dispatch_targets_cache.remove_sync(&channel_id);
    }

    #[inline]
    fn invalidate_all_channel_devices_cache(&self) {
        self.channel_devices_cache.clear_sync();
        self.channel_dispatch_targets_cache.clear_sync();
    }

    #[inline]
    fn cache_channel_info(&self, channel_id: [u8; 16], info: &ChannelInfo) {
        if let Some(mut entry) = self.channel_info_cache.get_sync(&channel_id) {
            *entry = info.clone();
            return;
        }
        let _ = self.channel_info_cache.put_sync(channel_id, info.clone());
    }

    #[inline]
    fn cached_channel_info(&self, channel_id: [u8; 16]) -> Option<ChannelInfo> {
        self.channel_info_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    #[inline]
    fn invalidate_channel_info_cache(&self, channel_id: [u8; 16]) {
        let _ = self.channel_info_cache.remove_sync(&channel_id);
    }

    #[inline]
    fn cache_channel_devices(&self, channel_id: [u8; 16], devices: &[DeviceInfo]) {
        let copied = devices.to_vec();
        if let Some(mut entry) = self.channel_devices_cache.get_sync(&channel_id) {
            *entry = copied;
            return;
        }
        let _ = self.channel_devices_cache.put_sync(channel_id, copied);
    }

    #[inline]
    fn cached_channel_devices(&self, channel_id: [u8; 16]) -> Option<Vec<DeviceInfo>> {
        self.channel_devices_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    #[inline]
    fn cache_channel_dispatch_targets(&self, channel_id: [u8; 16], targets: &[DispatchTarget]) {
        let entry = DispatchTargetsCacheEntry {
            cached_at_ms: Utc::now().timestamp_millis(),
            targets: targets.to_vec(),
        };
        if let Some(mut cached) = self.channel_dispatch_targets_cache.get_sync(&channel_id) {
            *cached = entry;
            return;
        }
        let _ = self
            .channel_dispatch_targets_cache
            .put_sync(channel_id, entry);
    }

    #[inline]
    fn cached_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
    ) -> Option<DispatchTargetsCacheEntry> {
        self.channel_dispatch_targets_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    async fn init_schema(&self) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("PRAGMA journal_mode = WAL")
                    .execute(pool)
                    .await?;
                sqlx::query("PRAGMA synchronous = NORMAL")
                    .execute(pool)
                    .await?;
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(pool)
                    .await?;
                sqlx::query("PRAGMA busy_timeout = 5000")
                    .execute(pool)
                    .await?;

                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS channels (\
                        channel_id BLOB PRIMARY KEY,\
                        password_hash TEXT NOT NULL,\
                        alias TEXT NOT NULL,\
                        created_at INTEGER NOT NULL,\
                        updated_at INTEGER NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS devices (\
                        device_id BLOB PRIMARY KEY,\
                        token_raw BLOB NOT NULL,\
                        platform_code INTEGER NOT NULL,\
                        device_key TEXT,\
                        platform TEXT,\
                        channel_type TEXT,\
                        provider_token TEXT,\
                        route_updated_at INTEGER\
                    )",
                )
                .execute(pool)
                .await?;
                Self::ensure_devices_route_columns_sqlite(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_device_keys (\
                        device_id BLOB NOT NULL,\
                        key_id INTEGER NOT NULL,\
                        key_id_b64 TEXT NOT NULL,\
                        key_b64 TEXT NOT NULL,\
                        algorithm TEXT NOT NULL,\
                        valid_from INTEGER NOT NULL,\
                        valid_until INTEGER,\
                        status TEXT NOT NULL,\
                        created_at INTEGER NOT NULL,\
                        PRIMARY KEY (device_id, key_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_sessions (\
                        session_id TEXT PRIMARY KEY,\
                        device_id BLOB NOT NULL,\
                        expires_at INTEGER NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_sessions_exp_idx \
                     ON private_sessions (expires_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_outbox (\
                        device_id BLOB NOT NULL,\
                        delivery_id TEXT NOT NULL,\
                        status TEXT NOT NULL,\
                        attempts INTEGER NOT NULL,\
                        occurred_at INTEGER NOT NULL DEFAULT 0,\
                        created_at INTEGER NOT NULL DEFAULT 0,\
                        claimed_at INTEGER,\
                        first_sent_at INTEGER,\
                        last_attempt_at INTEGER,\
                        acked_at INTEGER,\
                        fallback_sent_at INTEGER,\
                        next_attempt_at INTEGER NOT NULL,\
                        last_error_code TEXT,\
                        last_error_detail TEXT,\
                        updated_at INTEGER NOT NULL,\
                        PRIMARY KEY (device_id, delivery_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx \
                     ON private_outbox (delivery_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_due_idx \
                     ON private_outbox (status, next_attempt_at, attempts)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_device_status_order_idx \
                     ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
                )
                .execute(pool)
                .await?;
                Self::ensure_private_outbox_columns_sqlite(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_bindings (\
                        platform INTEGER NOT NULL,\
                        token_hash BLOB NOT NULL,\
                        device_id BLOB NOT NULL,\
                        PRIMARY KEY (platform, token_hash)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_bindings_device_idx \
                     ON private_bindings (device_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx \
                     ON devices (device_key)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS devices_route_platform_type_updated_idx \
                     ON devices (platform, channel_type, route_updated_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS devices_route_provider_token_idx \
                     ON devices (provider_token)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (\
                        meta_key TEXT PRIMARY KEY,\
                        meta_value TEXT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                Self::ensure_phase1_schema_sqlite(pool).await?;
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
                )
                .fetch_optional(pool)
                .await?;
                match current {
                    None => {
                        sqlx::query(
                            "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?)",
                        )
                        .bind(STORAGE_SCHEMA_VERSION)
                        .execute(pool)
                        .await?;
                    }
                    Some(version) if version == STORAGE_SCHEMA_VERSION => {}
                    Some(version) if version == STORAGE_SCHEMA_VERSION_PREVIOUS => {
                        sqlx::query(
                            "UPDATE pushgo_schema_meta SET meta_value = ? WHERE meta_key = 'schema_version'",
                        )
                        .bind(STORAGE_SCHEMA_VERSION)
                        .execute(pool)
                        .await?;
                    }
                    Some(version) => {
                        return Err(StoreError::SchemaVersionMismatch {
                            expected: STORAGE_SCHEMA_VERSION.to_string(),
                            actual: version,
                        });
                    }
                }
            }
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS channels (\
                        channel_id BYTEA PRIMARY KEY,\
                        password_hash TEXT NOT NULL,\
                        alias TEXT NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS devices (\
                        device_id BYTEA PRIMARY KEY,\
                        token_raw BYTEA NOT NULL,\
                        platform_code SMALLINT NOT NULL,\
                        device_key VARCHAR(255),\
                        platform VARCHAR(32),\
                        channel_type VARCHAR(32),\
                        provider_token TEXT,\
                        route_updated_at BIGINT\
                    )",
                )
                .execute(pool)
                .await?;
                Self::ensure_devices_route_columns_postgres(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_device_keys (\
                        device_id BYTEA NOT NULL,\
                        key_id INTEGER NOT NULL,\
                        key_hash BYTEA NOT NULL,\
                        issued_at BIGINT NOT NULL,\
                        valid_until BIGINT,\
                        PRIMARY KEY (device_id, key_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_sessions (\
                        session_id VARCHAR(128) PRIMARY KEY,\
                        device_id BYTEA NOT NULL,\
                        expires_at BIGINT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_outbox (\
                        device_id BYTEA NOT NULL,\
                        delivery_id VARCHAR(128) NOT NULL,\
                        status VARCHAR(16) NOT NULL,\
                        attempts INTEGER NOT NULL,\
                        occurred_at BIGINT NOT NULL DEFAULT 0,\
                        created_at BIGINT NOT NULL DEFAULT 0,\
                        claimed_at BIGINT,\
                        first_sent_at BIGINT,\
                        last_attempt_at BIGINT,\
                        acked_at BIGINT,\
                        fallback_sent_at BIGINT,\
                        next_attempt_at BIGINT NOT NULL,\
                        last_error_code TEXT,\
                        last_error_detail TEXT,\
                        updated_at BIGINT NOT NULL,\
                        PRIMARY KEY (device_id, delivery_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_delivery_idx \
                     ON private_outbox (delivery_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_due_idx \
                     ON private_outbox (status, next_attempt_at, attempts)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_outbox_device_status_order_idx \
                     ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
                )
                .execute(pool)
                .await?;
                Self::ensure_private_outbox_columns_postgres(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_bindings (\
                        platform SMALLINT NOT NULL,\
                        token_hash BYTEA NOT NULL,\
                        device_id BYTEA NOT NULL,\
                        PRIMARY KEY (platform, token_hash)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE UNIQUE INDEX IF NOT EXISTS devices_device_key_uidx \
                     ON devices (device_key)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS devices_route_platform_type_updated_idx \
                     ON devices (platform, channel_type, route_updated_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS devices_route_provider_token_idx \
                     ON devices (provider_token)",
                )
                .execute(pool)
                .await?;
                Self::ensure_phase1_schema_postgres(pool).await?;
                Self::ensure_schema_version_postgres(pool).await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS channels (\
                        channel_id BINARY(16) PRIMARY KEY,\
                        password_hash TEXT NOT NULL,\
                        alias TEXT NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS devices (\
                        device_id BINARY(32) PRIMARY KEY,\
                        token_raw BLOB NOT NULL,\
                        platform_code SMALLINT NOT NULL,\
                        device_key VARCHAR(255) NULL,\
                        platform VARCHAR(32) NULL,\
                        channel_type VARCHAR(32) NULL,\
                        provider_token TEXT NULL,\
                        route_updated_at BIGINT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                Self::ensure_devices_route_columns_mysql(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_device_keys (\
                        device_id BINARY(16) NOT NULL,\
                        key_id INT NOT NULL,\
                        key_hash BLOB NOT NULL,\
                        issued_at BIGINT NOT NULL,\
                        valid_until BIGINT NULL,\
                        PRIMARY KEY (device_id, key_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_sessions (\
                        session_id VARCHAR(128) PRIMARY KEY,\
                        device_id BINARY(16) NOT NULL,\
                        expires_at BIGINT NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_outbox (\
                        device_id BINARY(16) NOT NULL,\
                        delivery_id VARCHAR(128) NOT NULL,\
                        status VARCHAR(16) NOT NULL,\
                        attempts INT NOT NULL,\
                        occurred_at BIGINT NOT NULL DEFAULT 0,\
                        created_at BIGINT NOT NULL DEFAULT 0,\
                        claimed_at BIGINT NULL,\
                        first_sent_at BIGINT NULL,\
                        last_attempt_at BIGINT NULL,\
                        acked_at BIGINT NULL,\
                        fallback_sent_at BIGINT NULL,\
                        next_attempt_at BIGINT NOT NULL,\
                        last_error_code VARCHAR(64) NULL,\
                        last_error_detail TEXT NULL,\
                        updated_at BIGINT NOT NULL,\
                        PRIMARY KEY (device_id, delivery_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                let outbox_delivery_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'private_outbox' \
                       AND index_name = 'private_outbox_delivery_idx'",
                )
                .fetch_one(pool)
                .await?;
                if outbox_delivery_idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX private_outbox_delivery_idx ON private_outbox (delivery_id)",
                    )
                    .execute(pool)
                    .await?;
                }
                let outbox_due_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'private_outbox' \
                       AND index_name = 'private_outbox_due_idx'",
                )
                .fetch_one(pool)
                .await?;
                if outbox_due_idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX private_outbox_due_idx \
                         ON private_outbox (status, next_attempt_at, attempts)",
                    )
                    .execute(pool)
                    .await?;
                }
                let outbox_device_order_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'private_outbox' \
                       AND index_name = 'private_outbox_device_status_order_idx'",
                )
                .fetch_one(pool)
                .await?;
                if outbox_device_order_idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX private_outbox_device_status_order_idx \
                         ON private_outbox (device_id, status, occurred_at, created_at, delivery_id)",
                    )
                    .execute(pool)
                    .await?;
                }
                Self::ensure_private_outbox_columns_mysql(pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_bindings (\
                        platform SMALLINT NOT NULL,\
                        token_hash BINARY(32) NOT NULL,\
                        device_id BINARY(16) NOT NULL,\
                        PRIMARY KEY (platform, token_hash)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                let devices_route_platform_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'devices' \
                       AND index_name = 'devices_route_platform_type_updated_idx'",
                )
                .fetch_one(pool)
                .await?;
                if devices_route_platform_idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX devices_route_platform_type_updated_idx \
                         ON devices (platform, channel_type, route_updated_at)",
                    )
                    .execute(pool)
                    .await?;
                }
                let devices_route_provider_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'devices' \
                       AND index_name = 'devices_route_provider_token_idx'",
                )
                .fetch_one(pool)
                .await?;
                if devices_route_provider_idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX devices_route_provider_token_idx \
                         ON devices (provider_token(191))",
                    )
                    .execute(pool)
                    .await?;
                }
                let devices_route_key_idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'devices' \
                       AND index_name = 'devices_device_key_uidx'",
                )
                .fetch_one(pool)
                .await?;
                if devices_route_key_idx_count == 0 {
                    sqlx::query(
                        "CREATE UNIQUE INDEX devices_device_key_uidx \
                         ON devices (device_key)",
                    )
                    .execute(pool)
                    .await?;
                }
                Self::ensure_phase1_schema_mysql(pool).await?;
                Self::ensure_schema_version_mysql(pool).await?;
            }
        }
        Ok(())
    }

    async fn ensure_devices_route_columns_sqlite(pool: &SqlitePool) -> StoreResult<()> {
        let rows = sqlx::query("PRAGMA table_info(devices)")
            .fetch_all(pool)
            .await?;
        let mut existing = std::collections::HashSet::new();
        for row in rows {
            let name: String = row.try_get("name")?;
            existing.insert(name);
        }

        for (column, ddl) in [
            (
                "token_raw",
                "ALTER TABLE devices ADD COLUMN token_raw BLOB NOT NULL DEFAULT X''",
            ),
            (
                "platform_code",
                "ALTER TABLE devices ADD COLUMN platform_code INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "device_key",
                "ALTER TABLE devices ADD COLUMN device_key TEXT",
            ),
            ("platform", "ALTER TABLE devices ADD COLUMN platform TEXT"),
            (
                "channel_type",
                "ALTER TABLE devices ADD COLUMN channel_type TEXT",
            ),
            (
                "provider_token",
                "ALTER TABLE devices ADD COLUMN provider_token TEXT",
            ),
            (
                "route_updated_at",
                "ALTER TABLE devices ADD COLUMN route_updated_at INTEGER",
            ),
        ] {
            if !existing.contains(column) {
                sqlx::query(ddl).execute(pool).await?;
            }
        }
        Ok(())
    }

    async fn ensure_devices_route_columns_postgres(pool: &PgPool) -> StoreResult<()> {
        for (column, column_type) in [
            ("token_raw", "BYTEA"),
            ("platform_code", "SMALLINT"),
            ("device_key", "VARCHAR(255)"),
            ("platform", "VARCHAR(32)"),
            ("channel_type", "VARCHAR(32)"),
            ("provider_token", "TEXT"),
            ("route_updated_at", "BIGINT"),
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = 'devices' \
                   AND column_name = $1",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE devices ADD COLUMN {column} {column_type}").as_str(),
                )
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn ensure_devices_route_columns_mysql(pool: &MySqlPool) -> StoreResult<()> {
        for (column, column_type) in [
            ("token_raw", "BLOB NULL"),
            ("platform_code", "SMALLINT NULL"),
            ("device_key", "VARCHAR(255) NULL"),
            ("platform", "VARCHAR(32) NULL"),
            ("channel_type", "VARCHAR(32) NULL"),
            ("provider_token", "TEXT NULL"),
            ("route_updated_at", "BIGINT NULL"),
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'devices' \
                   AND column_name = ?",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE devices ADD COLUMN {column} {column_type}").as_str(),
                )
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn ensure_private_outbox_columns_sqlite(pool: &SqlitePool) -> StoreResult<()> {
        let rows = sqlx::query("PRAGMA table_info(private_outbox)")
            .fetch_all(pool)
            .await?;
        let mut existing = std::collections::HashSet::new();
        for row in rows {
            let name: String = row.try_get("name")?;
            existing.insert(name);
        }

        for (column, ddl) in [
            (
                "occurred_at",
                "ALTER TABLE private_outbox ADD COLUMN occurred_at INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "created_at",
                "ALTER TABLE private_outbox ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "claimed_at",
                "ALTER TABLE private_outbox ADD COLUMN claimed_at INTEGER",
            ),
            (
                "first_sent_at",
                "ALTER TABLE private_outbox ADD COLUMN first_sent_at INTEGER",
            ),
            (
                "last_attempt_at",
                "ALTER TABLE private_outbox ADD COLUMN last_attempt_at INTEGER",
            ),
            (
                "acked_at",
                "ALTER TABLE private_outbox ADD COLUMN acked_at INTEGER",
            ),
            (
                "fallback_sent_at",
                "ALTER TABLE private_outbox ADD COLUMN fallback_sent_at INTEGER",
            ),
            (
                "last_error_detail",
                "ALTER TABLE private_outbox ADD COLUMN last_error_detail TEXT",
            ),
        ] {
            if !existing.contains(column) {
                sqlx::query(ddl).execute(pool).await?;
            }
        }
        Ok(())
    }

    async fn ensure_private_outbox_columns_postgres(pool: &PgPool) -> StoreResult<()> {
        for (column, column_type) in [
            ("occurred_at", "BIGINT NOT NULL DEFAULT 0"),
            ("created_at", "BIGINT NOT NULL DEFAULT 0"),
            ("claimed_at", "BIGINT"),
            ("first_sent_at", "BIGINT"),
            ("last_attempt_at", "BIGINT"),
            ("acked_at", "BIGINT"),
            ("fallback_sent_at", "BIGINT"),
            ("last_error_detail", "TEXT"),
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = 'private_outbox' \
                   AND column_name = $1",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE private_outbox ADD COLUMN {column} {column_type}")
                        .as_str(),
                )
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn ensure_private_outbox_columns_mysql(pool: &MySqlPool) -> StoreResult<()> {
        for (column, column_type) in [
            ("occurred_at", "BIGINT NOT NULL DEFAULT 0"),
            ("created_at", "BIGINT NOT NULL DEFAULT 0"),
            ("claimed_at", "BIGINT NULL"),
            ("first_sent_at", "BIGINT NULL"),
            ("last_attempt_at", "BIGINT NULL"),
            ("acked_at", "BIGINT NULL"),
            ("fallback_sent_at", "BIGINT NULL"),
            ("last_error_detail", "TEXT NULL"),
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'private_outbox' \
                   AND column_name = ?",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE private_outbox ADD COLUMN {column} {column_type}")
                        .as_str(),
                )
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn ensure_phase1_schema_sqlite(pool: &SqlitePool) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (\
                channel_id BLOB NOT NULL,\
                device_id BLOB NOT NULL,\
                platform TEXT NOT NULL,\
                channel_type TEXT NOT NULL,\
                device_key TEXT,\
                provider_token TEXT,\
                provider_token_hash BLOB,\
                provider_token_preview TEXT,\
                route_version INTEGER NOT NULL DEFAULT 1,\
                status TEXT NOT NULL DEFAULT 'active',\
                subscribed_via TEXT NOT NULL,\
                last_dispatch_at INTEGER,\
                last_acked_at INTEGER,\
                last_error_code TEXT,\
                last_confirmed_at INTEGER,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                PRIMARY KEY (channel_id, device_id)\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx \
             ON channel_subscriptions (device_id)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_dispatch_idx \
             ON channel_subscriptions (channel_id, status, channel_type, route_version)",
        )
        .execute(pool)
        .await?;
        let cs_columns = sqlx::query("PRAGMA table_info(channel_subscriptions)")
            .fetch_all(pool)
            .await?;
        let mut cs_existing = std::collections::HashSet::new();
        for row in cs_columns {
            let name: String = row.try_get("name")?;
            cs_existing.insert(name);
        }
        for (column, ddl) in [
            (
                "device_key",
                "ALTER TABLE channel_subscriptions ADD COLUMN device_key TEXT",
            ),
            (
                "provider_token",
                "ALTER TABLE channel_subscriptions ADD COLUMN provider_token TEXT",
            ),
        ] {
            if !cs_existing.contains(column) {
                sqlx::query(ddl).execute(pool).await?;
            }
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS private_payloads (\
                delivery_id TEXT PRIMARY KEY,\
                channel_id BLOB NOT NULL,\
                payload_blob BLOB NOT NULL,\
                payload_size INTEGER NOT NULL,\
                entity_type TEXT,\
                entity_id TEXT,\
                op_id TEXT,\
                sent_at INTEGER NOT NULL,\
                expires_at INTEGER,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx \
             ON private_payloads (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_payloads_channel_sent_idx \
             ON private_payloads (channel_id, sent_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (\
                delivery_id TEXT PRIMARY KEY,\
                status TEXT NOT NULL DEFAULT 'pending',\
                pulled_at INTEGER,\
                acked_at INTEGER,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                FOREIGN KEY (delivery_id) REFERENCES private_payloads(delivery_id) ON DELETE CASCADE\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_queue_status_updated_idx \
             ON provider_pull_queue (status, updated_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_retry (\
                delivery_id TEXT PRIMARY KEY,\
                platform TEXT NOT NULL,\
                provider_token TEXT NOT NULL,\
                attempts INTEGER NOT NULL DEFAULT 0,\
                next_retry_at INTEGER NOT NULL,\
                last_attempt_at INTEGER,\
                expires_at INTEGER NOT NULL,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                FOREIGN KEY (delivery_id) REFERENCES provider_pull_queue(delivery_id) ON DELETE CASCADE\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_retry_due_idx \
             ON provider_pull_retry (next_retry_at, attempts)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (\
                dedupe_key TEXT PRIMARY KEY,\
                delivery_id TEXT NOT NULL,\
                state TEXT NOT NULL,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                expires_at INTEGER\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx \
             ON dispatch_delivery_dedupe (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx \
             ON dispatch_delivery_dedupe (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (\
                dedupe_key TEXT PRIMARY KEY,\
                delivery_id TEXT NOT NULL,\
                state TEXT NOT NULL,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                sent_at INTEGER,\
                expires_at INTEGER\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx \
             ON dispatch_op_dedupe (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx \
             ON dispatch_op_dedupe (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS semantic_id_registry (\
                dedupe_key TEXT PRIMARY KEY,\
                semantic_id TEXT NOT NULL UNIQUE,\
                source TEXT,\
                created_at INTEGER NOT NULL,\
                updated_at INTEGER NOT NULL,\
                last_seen_at INTEGER,\
                expires_at INTEGER\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx \
             ON semantic_id_registry (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx \
             ON semantic_id_registry (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_route_audit (\
                audit_id TEXT PRIMARY KEY,\
                device_key TEXT NOT NULL,\
                action TEXT NOT NULL,\
                old_platform TEXT,\
                new_platform TEXT,\
                old_channel_type TEXT,\
                new_channel_type TEXT,\
                old_provider_token_hash BLOB,\
                new_provider_token_hash BLOB,\
                issue_reason TEXT,\
                created_at INTEGER NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS device_route_audit_device_created_idx \
             ON device_route_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscription_audit (\
                audit_id TEXT PRIMARY KEY,\
                channel_id BLOB NOT NULL,\
                device_key TEXT NOT NULL,\
                action TEXT NOT NULL,\
                platform TEXT NOT NULL,\
                channel_type TEXT NOT NULL,\
                created_at INTEGER NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS subscription_audit_channel_created_idx \
             ON subscription_audit (channel_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS subscription_audit_device_created_idx \
             ON subscription_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS delivery_audit (\
                audit_id TEXT PRIMARY KEY,\
                delivery_id TEXT NOT NULL,\
                channel_id BLOB NOT NULL,\
                device_key TEXT NOT NULL,\
                entity_type TEXT,\
                entity_id TEXT,\
                op_id TEXT,\
                path TEXT NOT NULL,\
                status TEXT NOT NULL,\
                error_code TEXT,\
                created_at INTEGER NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_delivery_created_idx \
             ON delivery_audit (delivery_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_channel_created_idx \
             ON delivery_audit (channel_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_device_created_idx \
             ON delivery_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_stats_daily (\
                channel_id BLOB NOT NULL,\
                bucket_date TEXT NOT NULL,\
                messages_routed INTEGER NOT NULL DEFAULT 0,\
                deliveries_attempted INTEGER NOT NULL DEFAULT 0,\
                deliveries_acked INTEGER NOT NULL DEFAULT 0,\
                private_enqueued INTEGER NOT NULL DEFAULT 0,\
                provider_attempted INTEGER NOT NULL DEFAULT 0,\
                provider_failed INTEGER NOT NULL DEFAULT 0,\
                provider_success INTEGER NOT NULL DEFAULT 0,\
                private_realtime_delivered INTEGER NOT NULL DEFAULT 0,\
                PRIMARY KEY (channel_id, bucket_date)\
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_stats_daily (\
                device_key TEXT NOT NULL,\
                bucket_date TEXT NOT NULL,\
                messages_received INTEGER NOT NULL DEFAULT 0,\
                messages_acked INTEGER NOT NULL DEFAULT 0,\
                private_connected_count INTEGER NOT NULL DEFAULT 0,\
                private_pull_count INTEGER NOT NULL DEFAULT 0,\
                provider_success_count INTEGER NOT NULL DEFAULT 0,\
                provider_failure_count INTEGER NOT NULL DEFAULT 0,\
                private_outbox_enqueued_count INTEGER NOT NULL DEFAULT 0,\
                PRIMARY KEY (device_key, bucket_date)\
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (\
                bucket_hour TEXT PRIMARY KEY,\
                messages_routed INTEGER NOT NULL DEFAULT 0,\
                deliveries_attempted INTEGER NOT NULL DEFAULT 0,\
                deliveries_acked INTEGER NOT NULL DEFAULT 0,\
                private_outbox_depth_max INTEGER NOT NULL DEFAULT 0,\
                dedupe_pending_max INTEGER NOT NULL DEFAULT 0,\
                active_private_sessions_max INTEGER NOT NULL DEFAULT 0\
            )",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn ensure_phase1_schema_postgres(pool: &PgPool) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (\
                channel_id BYTEA NOT NULL,\
                device_id BYTEA NOT NULL,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                device_key VARCHAR(255),\
                provider_token TEXT,\
                provider_token_hash BYTEA,\
                provider_token_preview VARCHAR(128),\
                route_version BIGINT NOT NULL DEFAULT 1,\
                status VARCHAR(32) NOT NULL DEFAULT 'active',\
                subscribed_via VARCHAR(32) NOT NULL,\
                last_dispatch_at BIGINT,\
                last_acked_at BIGINT,\
                last_error_code VARCHAR(64),\
                last_confirmed_at BIGINT,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                PRIMARY KEY (channel_id, device_id)\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_device_idx \
             ON channel_subscriptions (device_id)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS channel_subscriptions_dispatch_idx \
             ON channel_subscriptions (channel_id, status, channel_type, route_version)",
        )
        .execute(pool)
        .await?;
        for (column, column_type) in [("device_key", "VARCHAR(255)"), ("provider_token", "TEXT")] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = 'channel_subscriptions' \
                   AND column_name = $1",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE channel_subscriptions ADD COLUMN {column} {column_type}")
                        .as_str(),
                )
                .execute(pool)
                .await?;
            }
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS private_payloads (\
                delivery_id VARCHAR(128) PRIMARY KEY,\
                channel_id BYTEA NOT NULL,\
                payload_blob BYTEA NOT NULL,\
                payload_size INTEGER NOT NULL,\
                entity_type VARCHAR(32),\
                entity_id VARCHAR(255),\
                op_id VARCHAR(128),\
                sent_at BIGINT NOT NULL,\
                expires_at BIGINT,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_payloads_expires_idx \
             ON private_payloads (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS private_payloads_channel_sent_idx \
             ON private_payloads (channel_id, sent_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (\
                delivery_id VARCHAR(128) PRIMARY KEY,\
                status VARCHAR(32) NOT NULL DEFAULT 'pending',\
                pulled_at BIGINT,\
                acked_at BIGINT,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                FOREIGN KEY (delivery_id) REFERENCES private_payloads(delivery_id) ON DELETE CASCADE\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_queue_status_updated_idx \
             ON provider_pull_queue (status, updated_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_retry (\
                delivery_id VARCHAR(128) PRIMARY KEY,\
                platform VARCHAR(32) NOT NULL,\
                provider_token VARCHAR(512) NOT NULL,\
                attempts INTEGER NOT NULL DEFAULT 0,\
                next_retry_at BIGINT NOT NULL,\
                last_attempt_at BIGINT,\
                expires_at BIGINT NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                FOREIGN KEY (delivery_id) REFERENCES provider_pull_queue(delivery_id) ON DELETE CASCADE\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS provider_pull_retry_due_idx \
             ON provider_pull_retry (next_retry_at, attempts)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (\
                dedupe_key VARCHAR(255) PRIMARY KEY,\
                delivery_id VARCHAR(128) NOT NULL,\
                state VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                expires_at BIGINT\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_expires_idx \
             ON dispatch_delivery_dedupe (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_delivery_dedupe_created_idx \
             ON dispatch_delivery_dedupe (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (\
                dedupe_key VARCHAR(255) PRIMARY KEY,\
                delivery_id VARCHAR(128) NOT NULL,\
                state VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                sent_at BIGINT,\
                expires_at BIGINT\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_expires_idx \
             ON dispatch_op_dedupe (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS dispatch_op_dedupe_created_idx \
             ON dispatch_op_dedupe (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS semantic_id_registry (\
                dedupe_key VARCHAR(255) PRIMARY KEY,\
                semantic_id VARCHAR(128) NOT NULL UNIQUE,\
                source VARCHAR(64),\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                last_seen_at BIGINT,\
                expires_at BIGINT\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_expires_idx \
             ON semantic_id_registry (expires_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS semantic_id_registry_created_idx \
             ON semantic_id_registry (created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_route_audit (\
                audit_id VARCHAR(128) PRIMARY KEY,\
                device_key VARCHAR(255) NOT NULL,\
                action VARCHAR(32) NOT NULL,\
                old_platform VARCHAR(32),\
                new_platform VARCHAR(32),\
                old_channel_type VARCHAR(32),\
                new_channel_type VARCHAR(32),\
                old_provider_token_hash BYTEA,\
                new_provider_token_hash BYTEA,\
                issue_reason VARCHAR(64),\
                created_at BIGINT NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS device_route_audit_device_created_idx \
             ON device_route_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscription_audit (\
                audit_id VARCHAR(128) PRIMARY KEY,\
                channel_id BYTEA NOT NULL,\
                device_key VARCHAR(255) NOT NULL,\
                action VARCHAR(32) NOT NULL,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS subscription_audit_channel_created_idx \
             ON subscription_audit (channel_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS subscription_audit_device_created_idx \
             ON subscription_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS delivery_audit (\
                audit_id VARCHAR(128) PRIMARY KEY,\
                delivery_id VARCHAR(128) NOT NULL,\
                channel_id BYTEA NOT NULL,\
                device_key VARCHAR(255) NOT NULL,\
                entity_type VARCHAR(32),\
                entity_id VARCHAR(255),\
                op_id VARCHAR(128),\
                path VARCHAR(32) NOT NULL,\
                status VARCHAR(32) NOT NULL,\
                error_code VARCHAR(64),\
                created_at BIGINT NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_delivery_created_idx \
             ON delivery_audit (delivery_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_channel_created_idx \
             ON delivery_audit (channel_id, created_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS delivery_audit_device_created_idx \
             ON delivery_audit (device_key, created_at)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_stats_daily (\
                channel_id BYTEA NOT NULL,\
                bucket_date VARCHAR(10) NOT NULL,\
                messages_routed BIGINT NOT NULL DEFAULT 0,\
                deliveries_attempted BIGINT NOT NULL DEFAULT 0,\
                deliveries_acked BIGINT NOT NULL DEFAULT 0,\
                private_enqueued BIGINT NOT NULL DEFAULT 0,\
                provider_attempted BIGINT NOT NULL DEFAULT 0,\
                provider_failed BIGINT NOT NULL DEFAULT 0,\
                provider_success BIGINT NOT NULL DEFAULT 0,\
                private_realtime_delivered BIGINT NOT NULL DEFAULT 0,\
                PRIMARY KEY (channel_id, bucket_date)\
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_stats_daily (\
                device_key VARCHAR(255) NOT NULL,\
                bucket_date VARCHAR(10) NOT NULL,\
                messages_received BIGINT NOT NULL DEFAULT 0,\
                messages_acked BIGINT NOT NULL DEFAULT 0,\
                private_connected_count BIGINT NOT NULL DEFAULT 0,\
                private_pull_count BIGINT NOT NULL DEFAULT 0,\
                provider_success_count BIGINT NOT NULL DEFAULT 0,\
                provider_failure_count BIGINT NOT NULL DEFAULT 0,\
                private_outbox_enqueued_count BIGINT NOT NULL DEFAULT 0,\
                PRIMARY KEY (device_key, bucket_date)\
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (\
                bucket_hour VARCHAR(16) PRIMARY KEY,\
                messages_routed BIGINT NOT NULL DEFAULT 0,\
                deliveries_attempted BIGINT NOT NULL DEFAULT 0,\
                deliveries_acked BIGINT NOT NULL DEFAULT 0,\
                private_outbox_depth_max BIGINT NOT NULL DEFAULT 0,\
                dedupe_pending_max BIGINT NOT NULL DEFAULT 0,\
                active_private_sessions_max BIGINT NOT NULL DEFAULT 0\
            )",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn ensure_phase1_schema_mysql(pool: &MySqlPool) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_subscriptions (\
                channel_id BINARY(16) NOT NULL,\
                device_id BINARY(32) NOT NULL,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                device_key VARCHAR(255) NULL,\
                provider_token TEXT NULL,\
                provider_token_hash BINARY(32) NULL,\
                provider_token_preview VARCHAR(128) NULL,\
                route_version BIGINT NOT NULL DEFAULT 1,\
                status VARCHAR(32) NOT NULL DEFAULT 'active',\
                subscribed_via VARCHAR(32) NOT NULL,\
                last_dispatch_at BIGINT NULL,\
                last_acked_at BIGINT NULL,\
                last_error_code VARCHAR(64) NULL,\
                last_confirmed_at BIGINT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                PRIMARY KEY (channel_id, device_id),\
                INDEX channel_subscriptions_device_idx (device_id),\
                INDEX channel_subscriptions_dispatch_idx (channel_id, status, channel_type, route_version)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;
        for (column, column_type) in [
            ("device_key", "VARCHAR(255) NULL"),
            ("provider_token", "TEXT NULL"),
        ] {
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'channel_subscriptions' \
                   AND column_name = ?",
            )
            .bind(column)
            .fetch_optional(pool)
            .await?;
            if exists.is_none() {
                sqlx::query(
                    format!("ALTER TABLE channel_subscriptions ADD COLUMN {column} {column_type}")
                        .as_str(),
                )
                .execute(pool)
                .await?;
            }
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS private_payloads (\
                delivery_id VARCHAR(128) NOT NULL,\
                channel_id BINARY(16) NOT NULL,\
                payload_blob BLOB NOT NULL,\
                payload_size INT NOT NULL,\
                entity_type VARCHAR(32) NULL,\
                entity_id VARCHAR(255) NULL,\
                op_id VARCHAR(128) NULL,\
                sent_at BIGINT NOT NULL,\
                expires_at BIGINT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                PRIMARY KEY (delivery_id),\
                INDEX private_payloads_expires_idx (expires_at),\
                INDEX private_payloads_channel_sent_idx (channel_id, sent_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_queue (\
                delivery_id VARCHAR(128) NOT NULL,\
                status VARCHAR(32) NOT NULL DEFAULT 'pending',\
                pulled_at BIGINT NULL,\
                acked_at BIGINT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                PRIMARY KEY (delivery_id),\
                INDEX provider_pull_queue_status_updated_idx (status, updated_at),\
                CONSTRAINT fk_provider_pull_queue_payload \
                    FOREIGN KEY (delivery_id) REFERENCES private_payloads(delivery_id) ON DELETE CASCADE\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS provider_pull_retry (\
                delivery_id VARCHAR(128) NOT NULL,\
                platform VARCHAR(32) NOT NULL,\
                provider_token VARCHAR(512) NOT NULL,\
                attempts INT NOT NULL DEFAULT 0,\
                next_retry_at BIGINT NOT NULL,\
                last_attempt_at BIGINT NULL,\
                expires_at BIGINT NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                PRIMARY KEY (delivery_id),\
                INDEX provider_pull_retry_due_idx (next_retry_at, attempts),\
                CONSTRAINT fk_provider_pull_retry_queue \
                    FOREIGN KEY (delivery_id) REFERENCES provider_pull_queue(delivery_id) ON DELETE CASCADE\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_delivery_dedupe (\
                dedupe_key VARCHAR(255) NOT NULL,\
                delivery_id VARCHAR(128) NOT NULL,\
                state VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                expires_at BIGINT NULL,\
                PRIMARY KEY (dedupe_key),\
                INDEX dispatch_delivery_dedupe_expires_idx (expires_at),\
                INDEX dispatch_delivery_dedupe_created_idx (created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dispatch_op_dedupe (\
                dedupe_key VARCHAR(255) NOT NULL,\
                delivery_id VARCHAR(128) NOT NULL,\
                state VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                sent_at BIGINT NULL,\
                expires_at BIGINT NULL,\
                PRIMARY KEY (dedupe_key),\
                INDEX dispatch_op_dedupe_expires_idx (expires_at),\
                INDEX dispatch_op_dedupe_created_idx (created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS semantic_id_registry (\
                dedupe_key VARCHAR(255) NOT NULL,\
                semantic_id VARCHAR(128) NOT NULL,\
                source VARCHAR(64) NULL,\
                created_at BIGINT NOT NULL,\
                updated_at BIGINT NOT NULL,\
                last_seen_at BIGINT NULL,\
                expires_at BIGINT NULL,\
                PRIMARY KEY (dedupe_key),\
                UNIQUE KEY semantic_id_registry_semantic_idx (semantic_id),\
                INDEX semantic_id_registry_expires_idx (expires_at),\
                INDEX semantic_id_registry_created_idx (created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_route_audit (\
                audit_id VARCHAR(128) NOT NULL,\
                device_key VARCHAR(255) NOT NULL,\
                action VARCHAR(32) NOT NULL,\
                old_platform VARCHAR(32) NULL,\
                new_platform VARCHAR(32) NULL,\
                old_channel_type VARCHAR(32) NULL,\
                new_channel_type VARCHAR(32) NULL,\
                old_provider_token_hash BINARY(32) NULL,\
                new_provider_token_hash BINARY(32) NULL,\
                issue_reason VARCHAR(64) NULL,\
                created_at BIGINT NOT NULL,\
                PRIMARY KEY (audit_id),\
                INDEX device_route_audit_device_created_idx (device_key, created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscription_audit (\
                audit_id VARCHAR(128) NOT NULL,\
                channel_id BINARY(16) NOT NULL,\
                device_key VARCHAR(255) NOT NULL,\
                action VARCHAR(32) NOT NULL,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                created_at BIGINT NOT NULL,\
                PRIMARY KEY (audit_id),\
                INDEX subscription_audit_channel_created_idx (channel_id, created_at),\
                INDEX subscription_audit_device_created_idx (device_key, created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS delivery_audit (\
                audit_id VARCHAR(128) NOT NULL,\
                delivery_id VARCHAR(128) NOT NULL,\
                channel_id BINARY(16) NOT NULL,\
                device_key VARCHAR(255) NOT NULL,\
                entity_type VARCHAR(32) NULL,\
                entity_id VARCHAR(255) NULL,\
                op_id VARCHAR(128) NULL,\
                path VARCHAR(32) NOT NULL,\
                status VARCHAR(32) NOT NULL,\
                error_code VARCHAR(64) NULL,\
                created_at BIGINT NOT NULL,\
                PRIMARY KEY (audit_id),\
                INDEX delivery_audit_delivery_created_idx (delivery_id, created_at),\
                INDEX delivery_audit_channel_created_idx (channel_id, created_at),\
                INDEX delivery_audit_device_created_idx (device_key, created_at)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS channel_stats_daily (\
                channel_id BINARY(16) NOT NULL,\
                bucket_date VARCHAR(10) NOT NULL,\
                messages_routed BIGINT NOT NULL DEFAULT 0,\
                deliveries_attempted BIGINT NOT NULL DEFAULT 0,\
                deliveries_acked BIGINT NOT NULL DEFAULT 0,\
                private_enqueued BIGINT NOT NULL DEFAULT 0,\
                provider_attempted BIGINT NOT NULL DEFAULT 0,\
                provider_failed BIGINT NOT NULL DEFAULT 0,\
                provider_success BIGINT NOT NULL DEFAULT 0,\
                private_realtime_delivered BIGINT NOT NULL DEFAULT 0,\
                PRIMARY KEY (channel_id, bucket_date)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_stats_daily (\
                device_key VARCHAR(255) NOT NULL,\
                bucket_date VARCHAR(10) NOT NULL,\
                messages_received BIGINT NOT NULL DEFAULT 0,\
                messages_acked BIGINT NOT NULL DEFAULT 0,\
                private_connected_count BIGINT NOT NULL DEFAULT 0,\
                private_pull_count BIGINT NOT NULL DEFAULT 0,\
                provider_success_count BIGINT NOT NULL DEFAULT 0,\
                provider_failure_count BIGINT NOT NULL DEFAULT 0,\
                private_outbox_enqueued_count BIGINT NOT NULL DEFAULT 0,\
                PRIMARY KEY (device_key, bucket_date)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS gateway_stats_hourly (\
                bucket_hour VARCHAR(16) NOT NULL,\
                messages_routed BIGINT NOT NULL DEFAULT 0,\
                deliveries_attempted BIGINT NOT NULL DEFAULT 0,\
                deliveries_acked BIGINT NOT NULL DEFAULT 0,\
                private_outbox_depth_max BIGINT NOT NULL DEFAULT 0,\
                dedupe_pending_max BIGINT NOT NULL DEFAULT 0,\
                active_private_sessions_max BIGINT NOT NULL DEFAULT 0,\
                PRIMARY KEY (bucket_hour)\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn ensure_schema_version_postgres(pool: &PgPool) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (\
                meta_key VARCHAR(128) PRIMARY KEY,\
                meta_value VARCHAR(255) NOT NULL\
            )",
        )
        .execute(pool)
        .await?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(pool)
        .await?;
        match current {
            None => {
                sqlx::query(
                    "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', $1)",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(pool)
                .await?;
                Ok(())
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION => Ok(()),
            Some(version) if version == STORAGE_SCHEMA_VERSION_PREVIOUS => {
                sqlx::query(
                    "UPDATE pushgo_schema_meta SET meta_value = $1 WHERE meta_key = 'schema_version'",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(pool)
                .await?;
                Ok(())
            }
            Some(version) => Err(StoreError::SchemaVersionMismatch {
                expected: STORAGE_SCHEMA_VERSION.to_string(),
                actual: version,
            }),
        }
    }

    async fn ensure_schema_version_mysql(pool: &MySqlPool) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (\
                meta_key VARCHAR(128) PRIMARY KEY,\
                meta_value VARCHAR(255) NOT NULL\
            ) ENGINE=InnoDB",
        )
        .execute(pool)
        .await?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key = 'schema_version'",
        )
        .fetch_optional(pool)
        .await?;
        match current {
            None => {
                sqlx::query(
                    "INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', ?)",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(pool)
                .await?;
                Ok(())
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION => Ok(()),
            Some(version) if version == STORAGE_SCHEMA_VERSION_PREVIOUS => {
                sqlx::query(
                    "UPDATE pushgo_schema_meta SET meta_value = ? WHERE meta_key = 'schema_version'",
                )
                .bind(STORAGE_SCHEMA_VERSION)
                .execute(pool)
                .await?;
                Ok(())
            }
            Some(version) => Err(StoreError::SchemaVersionMismatch {
                expected: STORAGE_SCHEMA_VERSION.to_string(),
                actual: version,
            }),
        }
    }

    async fn delete_private_payload_if_unreferenced_async(
        &self,
        delivery_id: &str,
    ) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "DELETE FROM private_payloads p \
                     WHERE p.delivery_id = $1 \
                       AND NOT EXISTS (SELECT 1 FROM private_outbox o WHERE o.delivery_id = p.delivery_id) \
                       AND NOT EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.delivery_id = p.delivery_id)",
                )
                .bind(delivery_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM private_payloads \
                     WHERE delivery_id = ? \
                       AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
                       AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
                )
                .bind(delivery_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM private_payloads \
                     WHERE delivery_id = ? \
                       AND NOT EXISTS (SELECT 1 FROM private_outbox WHERE private_outbox.delivery_id = private_payloads.delivery_id) \
                       AND NOT EXISTS (SELECT 1 FROM provider_pull_queue WHERE provider_pull_queue.delivery_id = private_payloads.delivery_id)",
                )
                .bind(delivery_id)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn delete_private_payloads_if_unreferenced_async(
        &self,
        delivery_ids: &[String],
    ) -> StoreResult<()> {
        if delivery_ids.is_empty() {
            return Ok(());
        }
        for delivery_id in delivery_ids {
            self.delete_private_payload_if_unreferenced_async(delivery_id)
                .await?;
        }
        Ok(())
    }

    async fn clear_private_outbox_for_device_entries_async(
        &self,
        device_id: &[u8],
    ) -> StoreResult<Vec<String>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id FROM private_outbox \
                     WHERE device_id = $1 \
                     ORDER BY updated_at ASC, delivery_id ASC \
                     FOR UPDATE",
                )
                .bind(device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(delivery_ids)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id FROM private_outbox \
                     WHERE device_id = ? \
                     ORDER BY updated_at ASC, delivery_id ASC \
                     FOR UPDATE",
                )
                .bind(device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(delivery_ids)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id FROM private_outbox \
                     WHERE device_id = ? \
                     ORDER BY updated_at ASC, delivery_id ASC",
                )
                .bind(device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(delivery_ids)
            }
        }
    }
}

#[async_trait]
impl StoreApi for SqlxStore {
    async fn subscribe_channel_async(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let token_raw = device_info.token_raw.to_vec();
        let platform_code = platform.to_byte() as i16;
        let platform_text = platform_name(platform);
        let channel_type = channel_type_for_platform(platform);
        let token_hash = provider_token_hash(device_info.token_str.as_ref());
        let token_preview = provider_token_preview(device_info.token_str.as_ref());
        let now = Utc::now().timestamp();
        let channel_id = channel_id.map(|id| id.to_vec());
        let alias = alias.map(str::to_string);

        let outcome = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = $1",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.clone().ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES ($1, $2, $3, $4, $5)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };

                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES ($1, $2, $3) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                        token_raw = EXCLUDED.token_raw, \
                        platform_code = EXCLUDED.platform_code",
                )
                .bind(&device_id[..])
                .bind(&token_raw)
                .bind(platform_code)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, 1, 'active', 'channel_subscribe', $8, $9) \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       platform = EXCLUDED.platform, \
                       channel_type = EXCLUDED.channel_type, \
                       provider_token = EXCLUDED.provider_token, \
                       provider_token_hash = EXCLUDED.provider_token_hash, \
                       provider_token_preview = EXCLUDED.provider_token_preview, \
                       status = EXCLUDED.status, \
                       updated_at = EXCLUDED.updated_at",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .bind(platform_text)
                .bind(channel_type)
                .bind(device_info.token_str.as_ref())
                .bind(&token_hash)
                .bind(&token_preview)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                }
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.clone().ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };

                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                        token_raw = VALUES(token_raw), \
                        platform_code = VALUES(platform_code)",
                )
                .bind(&device_id[..])
                .bind(&token_raw)
                .bind(platform_code)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, NULL, ?, ?, ?, 1, 'active', 'channel_subscribe', ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       platform = VALUES(platform), \
                       channel_type = VALUES(channel_type), \
                       provider_token = VALUES(provider_token), \
                       provider_token_hash = VALUES(provider_token_hash), \
                       provider_token_preview = VALUES(provider_token_preview), \
                       status = VALUES(status), \
                       updated_at = VALUES(updated_at)",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .bind(platform_text)
                .bind(channel_type)
                .bind(device_info.token_str.as_ref())
                .bind(&token_hash)
                .bind(&token_preview)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.clone().ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };

                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                     token_raw = excluded.token_raw, \
                     platform_code = excluded.platform_code",
                )
                .bind(&device_id[..])
                .bind(&token_raw)
                .bind(platform_code)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, NULL, ?, ?, ?, 1, 'active', 'channel_subscribe', ?, ?) \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       platform = excluded.platform, \
                       channel_type = excluded.channel_type, \
                       provider_token = excluded.provider_token, \
                       provider_token_hash = excluded.provider_token_hash, \
                       provider_token_preview = excluded.provider_token_preview, \
                       status = excluded.status, \
                       updated_at = excluded.updated_at",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .bind(platform_text)
                .bind(channel_type)
                .bind(device_info.token_str.as_ref())
                .bind(&token_hash)
                .bind(&token_preview)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                }
            }
        };
        self.device_cache.write().insert(device_id, device_info);
        self.invalidate_channel_devices_cache(outcome.channel_id);
        self.cache_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
            },
        );
        Ok(outcome)
    }

    async fn unsubscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let channel_bytes = channel_id.to_vec();
        let removed = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "DELETE FROM channel_subscriptions WHERE channel_id = $1 AND device_id = $2",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .execute(pool)
                .await?;
                result.rows_affected() > 0
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .execute(pool)
                .await?;
                result.rows_affected() > 0
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .execute(pool)
                .await?;
                result.rows_affected() > 0
            }
        };
        if removed {
            self.invalidate_channel_devices_cache(channel_id);
        }
        Ok(removed)
    }

    async fn retire_device_async(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let mut touched_channels: Vec<[u8; 16]> = Vec::new();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let touched = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions WHERE device_id = $1",
                )
                .bind(&device_id[..])
                .fetch_all(&mut *tx)
                .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                let removed = sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = $1")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize;
                sqlx::query("DELETE FROM devices WHERE device_id = $1")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&device_id);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(removed)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let touched =
                    sqlx::query("SELECT channel_id FROM channel_subscriptions WHERE device_id = ?")
                        .bind(&device_id[..])
                        .fetch_all(&mut *tx)
                        .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                let removed = sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize;
                sqlx::query("DELETE FROM devices WHERE device_id = ?")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&device_id);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(removed)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let touched =
                    sqlx::query("SELECT channel_id FROM channel_subscriptions WHERE device_id = ?")
                        .bind(&device_id[..])
                        .fetch_all(&mut *tx)
                        .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                let removed = sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?
                    .rows_affected() as usize;
                sqlx::query("DELETE FROM devices WHERE device_id = ?")
                    .bind(&device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&device_id);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(removed)
            }
        }
    }

    async fn migrate_device_subscriptions_async(
        &self,
        old_device_token: &str,
        new_device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let old_device_info = DeviceInfo::from_token(platform, old_device_token)?;
        let old_device_id = device_id_for(platform, &old_device_info.token_raw);
        let new_device_info = DeviceInfo::from_token(platform, new_device_token)?;
        let new_device_id = device_id_for(platform, &new_device_info.token_raw);
        let new_token_raw = new_device_info.token_raw.to_vec();
        let new_platform_code = new_device_info.platform.to_byte() as i16;

        if old_device_id == new_device_id {
            self.device_cache
                .write()
                .insert(new_device_id, new_device_info);
            return Ok(0);
        }

        let mut touched_channels: Vec<[u8; 16]> = Vec::new();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let touched = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions WHERE device_id = $1",
                )
                .bind(&old_device_id[..])
                .fetch_all(&mut *tx)
                .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES ($1, $2, $3) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                        token_raw = EXCLUDED.token_raw, \
                        platform_code = EXCLUDED.platform_code",
                )
                .bind(&new_device_id[..])
                .bind(&new_token_raw)
                .bind(new_platform_code)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, updated_at) \
                     SELECT channel_id, $1, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, $3 \
                     FROM channel_subscriptions WHERE device_id = $2 \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       platform = EXCLUDED.platform, \
                       channel_type = EXCLUDED.channel_type, \
                       device_key = EXCLUDED.device_key, \
                       provider_token = EXCLUDED.provider_token, \
                       provider_token_hash = EXCLUDED.provider_token_hash, \
                       provider_token_preview = EXCLUDED.provider_token_preview, \
                       route_version = EXCLUDED.route_version, \
                       status = EXCLUDED.status, \
                       subscribed_via = EXCLUDED.subscribed_via, \
                       last_dispatch_at = EXCLUDED.last_dispatch_at, \
                       last_acked_at = EXCLUDED.last_acked_at, \
                       last_error_code = EXCLUDED.last_error_code, \
                       last_confirmed_at = EXCLUDED.last_confirmed_at, \
                       updated_at = EXCLUDED.updated_at",
                )
                .bind(&new_device_id[..])
                .bind(&old_device_id[..])
                .bind(Utc::now().timestamp())
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = $1")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM devices WHERE device_id = $1")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&old_device_id);
                self.device_cache
                    .write()
                    .insert(new_device_id, new_device_info);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(moved)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let touched =
                    sqlx::query("SELECT channel_id FROM channel_subscriptions WHERE device_id = ?")
                        .bind(&old_device_id[..])
                        .fetch_all(&mut *tx)
                        .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                        token_raw = VALUES(token_raw), \
                        platform_code = VALUES(platform_code)",
                )
                .bind(&new_device_id[..])
                .bind(&new_token_raw)
                .bind(new_platform_code)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, updated_at) \
                     SELECT channel_id, ?, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, ? \
                     FROM channel_subscriptions WHERE device_id = ? \
                     ON DUPLICATE KEY UPDATE \
                       platform = VALUES(platform), \
                       channel_type = VALUES(channel_type), \
                       device_key = VALUES(device_key), \
                       provider_token = VALUES(provider_token), \
                       provider_token_hash = VALUES(provider_token_hash), \
                       provider_token_preview = VALUES(provider_token_preview), \
                       route_version = VALUES(route_version), \
                       status = VALUES(status), \
                       subscribed_via = VALUES(subscribed_via), \
                       last_dispatch_at = VALUES(last_dispatch_at), \
                       last_acked_at = VALUES(last_acked_at), \
                       last_error_code = VALUES(last_error_code), \
                       last_confirmed_at = VALUES(last_confirmed_at), \
                       updated_at = VALUES(updated_at)",
                )
                .bind(&new_device_id[..])
                .bind(Utc::now().timestamp())
                .bind(&old_device_id[..])
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM devices WHERE device_id = ?")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&old_device_id);
                self.device_cache
                    .write()
                    .insert(new_device_id, new_device_info);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(moved)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let touched =
                    sqlx::query("SELECT channel_id FROM channel_subscriptions WHERE device_id = ?")
                        .bind(&old_device_id[..])
                        .fetch_all(&mut *tx)
                        .await?;
                for row in touched {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    touched_channels.push(channel_id);
                }
                sqlx::query(
                    "INSERT INTO devices (device_id, token_raw, platform_code) VALUES (?, ?, ?) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                        token_raw = excluded.token_raw, \
                        platform_code = excluded.platform_code",
                )
                .bind(&new_device_id[..])
                .bind(&new_token_raw)
                .bind(new_platform_code)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, updated_at) \
                     SELECT channel_id, ?, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, last_dispatch_at, last_acked_at, last_error_code, last_confirmed_at, created_at, ? \
                     FROM channel_subscriptions WHERE device_id = ? \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       platform = excluded.platform, \
                       channel_type = excluded.channel_type, \
                       device_key = excluded.device_key, \
                       provider_token = excluded.provider_token, \
                       provider_token_hash = excluded.provider_token_hash, \
                       provider_token_preview = excluded.provider_token_preview, \
                       route_version = excluded.route_version, \
                       status = excluded.status, \
                       subscribed_via = excluded.subscribed_via, \
                       last_dispatch_at = excluded.last_dispatch_at, \
                       last_acked_at = excluded.last_acked_at, \
                       last_error_code = excluded.last_error_code, \
                       last_confirmed_at = excluded.last_confirmed_at, \
                       updated_at = excluded.updated_at",
                )
                .bind(&new_device_id[..])
                .bind(Utc::now().timestamp())
                .bind(&old_device_id[..])
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM channel_subscriptions WHERE device_id = ?")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM devices WHERE device_id = ?")
                    .bind(&old_device_id[..])
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.device_cache.write().remove(&old_device_id);
                self.device_cache
                    .write()
                    .insert(new_device_id, new_device_info);
                for channel_id in touched_channels {
                    self.invalidate_channel_devices_cache(channel_id);
                }
                Ok(moved)
            }
        }
    }

    async fn delete_private_device_state_async(&self, device_id: DeviceId) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        let delivery_ids = self
            .clear_private_outbox_for_device_entries_async(&device_id)
            .await?;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE device_id = $1 AND channel_type = 'private'",
                )
                .bind(&device_id)
                .execute(pool)
                .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = $1")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE device_id = ? AND channel_type = 'private'",
                )
                .bind(&device_id)
                .execute(pool)
                .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE device_id = ? AND channel_type = 'private'",
                )
                .bind(&device_id)
                .execute(pool)
                .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
        }
        self.delete_private_payloads_if_unreferenced_async(&delivery_ids)
            .await?;
        Ok(())
    }

    async fn rename_channel_async(
        &self,
        channel_id: [u8; 16],
        password: &str,
        alias: &str,
    ) -> StoreResult<()> {
        let channel_bytes = channel_id.to_vec();
        let now = Utc::now().timestamp();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let row = sqlx::query("SELECT password_hash FROM channels WHERE channel_id = $1")
                    .bind(&channel_bytes)
                    .fetch_optional(&mut *tx)
                    .await?;
                let row = row.ok_or(StoreError::ChannelNotFound)?;
                let password_hash: String = row.try_get("password_hash")?;
                verify_channel_password(&password_hash, password)?;
                sqlx::query(
                    "UPDATE channels SET alias = $1, updated_at = $2 WHERE channel_id = $3",
                )
                .bind(alias)
                .bind(now)
                .bind(&channel_bytes)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                self.cache_channel_info(
                    channel_id,
                    &ChannelInfo {
                        alias: alias.to_string(),
                    },
                );
                Ok(())
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let row = sqlx::query("SELECT password_hash FROM channels WHERE channel_id = ?")
                    .bind(&channel_bytes)
                    .fetch_optional(&mut *tx)
                    .await?;
                let row = row.ok_or(StoreError::ChannelNotFound)?;
                let password_hash: String = row.try_get("password_hash")?;
                verify_channel_password(&password_hash, password)?;
                sqlx::query("UPDATE channels SET alias = ?, updated_at = ? WHERE channel_id = ?")
                    .bind(alias)
                    .bind(now)
                    .bind(&channel_bytes)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.cache_channel_info(
                    channel_id,
                    &ChannelInfo {
                        alias: alias.to_string(),
                    },
                );
                Ok(())
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let row = sqlx::query("SELECT password_hash FROM channels WHERE channel_id = ?")
                    .bind(&channel_bytes)
                    .fetch_optional(&mut *tx)
                    .await?;
                let row = row.ok_or(StoreError::ChannelNotFound)?;
                let password_hash: String = row.try_get("password_hash")?;
                verify_channel_password(&password_hash, password)?;
                sqlx::query("UPDATE channels SET alias = ?, updated_at = ? WHERE channel_id = ?")
                    .bind(alias)
                    .bind(now)
                    .bind(&channel_bytes)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                self.cache_channel_info(
                    channel_id,
                    &ChannelInfo {
                        alias: alias.to_string(),
                    },
                );
                Ok(())
            }
        }
    }

    async fn cleanup_pending_op_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "WITH doomed AS (\
                        SELECT dedupe_key \
                        FROM dispatch_op_dedupe \
                        WHERE created_at <= $1 AND state = $2 \
                        ORDER BY created_at ASC \
                        LIMIT $3\
                     ) \
                     DELETE FROM dispatch_op_dedupe d \
                     USING doomed \
                     WHERE d.dedupe_key = doomed.dedupe_key",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_str())
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "DELETE FROM dispatch_op_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM dispatch_op_dedupe \
                            WHERE created_at <= ? AND state = ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_str())
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM dispatch_op_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM dispatch_op_dedupe \
                            WHERE created_at <= ? AND state = ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_str())
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
        }
    }

    async fn cleanup_semantic_id_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "WITH doomed AS (\
                        SELECT dedupe_key \
                        FROM semantic_id_registry \
                        WHERE created_at <= $1 \
                        ORDER BY created_at ASC \
                        LIMIT $2\
                     ) \
                     DELETE FROM semantic_id_registry d \
                     USING doomed \
                     WHERE d.dedupe_key = doomed.dedupe_key",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "DELETE FROM semantic_id_registry \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM semantic_id_registry \
                            WHERE created_at <= ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM semantic_id_registry \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM semantic_id_registry \
                            WHERE created_at <= ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
        }
    }

    async fn cleanup_delivery_dedupe_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "WITH doomed AS (\
                        SELECT dedupe_key \
                        FROM dispatch_delivery_dedupe \
                        WHERE created_at <= $1 \
                        ORDER BY created_at ASC \
                        LIMIT $2\
                     ) \
                     DELETE FROM dispatch_delivery_dedupe d \
                     USING doomed \
                     WHERE d.dedupe_key = doomed.dedupe_key",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "DELETE FROM dispatch_delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM dispatch_delivery_dedupe \
                            WHERE created_at <= ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM dispatch_delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM dispatch_delivery_dedupe \
                            WHERE created_at <= ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
        }
    }

    async fn channel_info_async(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        if let Some(cached) = self.cached_channel_info(channel_id) {
            return Ok(Some(cached));
        }
        let channel_bytes = channel_id.to_vec();
        let info = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = $1")
                    .bind(&channel_bytes)
                    .fetch_optional(pool)
                    .await?;
                match row {
                    Some(row) => {
                        let alias: String = row.try_get("alias")?;
                        Some(ChannelInfo { alias })
                    }
                    None => None,
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
                    .bind(&channel_bytes)
                    .fetch_optional(pool)
                    .await?;
                match row {
                    Some(row) => {
                        let alias: String = row.try_get("alias")?;
                        Some(ChannelInfo { alias })
                    }
                    None => None,
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
                    .bind(&channel_bytes)
                    .fetch_optional(pool)
                    .await?;
                match row {
                    Some(row) => {
                        let alias: String = row.try_get("alias")?;
                        Some(ChannelInfo { alias })
                    }
                    None => None,
                }
            }
        };
        if let Some(ref info) = info {
            self.cache_channel_info(channel_id, info);
        } else {
            self.invalidate_channel_info_cache(channel_id);
        }
        Ok(info)
    }

    async fn channel_info_with_password_async(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        let channel_bytes = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row =
                    sqlx::query("SELECT password_hash, alias FROM channels WHERE channel_id = $1")
                        .bind(&channel_bytes)
                        .fetch_optional(pool)
                        .await?;
                match row {
                    Some(row) => {
                        let password_hash: String = row.try_get("password_hash")?;
                        verify_channel_password(&password_hash, password)?;
                        let alias: String = row.try_get("alias")?;
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row =
                    sqlx::query("SELECT password_hash, alias FROM channels WHERE channel_id = ?")
                        .bind(&channel_bytes)
                        .fetch_optional(pool)
                        .await?;
                match row {
                    Some(row) => {
                        let password_hash: String = row.try_get("password_hash")?;
                        verify_channel_password(&password_hash, password)?;
                        let alias: String = row.try_get("alias")?;
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row =
                    sqlx::query("SELECT password_hash, alias FROM channels WHERE channel_id = ?")
                        .bind(&channel_bytes)
                        .fetch_optional(pool)
                        .await?;
                match row {
                    Some(row) => {
                        let password_hash: String = row.try_get("password_hash")?;
                        verify_channel_password(&password_hash, password)?;
                        let alias: String = row.try_get("alias")?;
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    async fn upsert_private_channel_async(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
    ) -> StoreResult<SubscribeOutcome> {
        let now = Utc::now().timestamp();
        let channel_id = channel_id.map(|id| id.to_vec());
        let alias = alias.map(str::to_string);
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = $1",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES ($1, $2, $3, $4, $5)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };
                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                let outcome = SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                };
                self.cache_channel_info(
                    outcome.channel_id,
                    &ChannelInfo {
                        alias: outcome.alias.clone(),
                    },
                );
                Ok(outcome)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };
                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                let outcome = SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                };
                self.cache_channel_info(
                    outcome.channel_id,
                    &ChannelInfo {
                        alias: outcome.alias.clone(),
                    },
                );
                Ok(outcome)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                    let row = sqlx::query(
                        "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                    )
                    .bind(&channel_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let row = row.ok_or(StoreError::ChannelNotFound)?;
                    let password_hash: String = row.try_get("password_hash")?;
                    verify_channel_password(&password_hash, password)?;
                    let channel_alias: String = row.try_get("alias")?;
                    (channel_id, false, channel_alias)
                } else {
                    let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                    let new_id = random_id_bytes_128().to_vec();
                    let hash = hash_channel_password(password)?;
                    sqlx::query(
                        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(&new_id)
                    .bind(hash)
                    .bind(&alias)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                    (new_id, true, alias)
                };
                tx.commit().await?;
                let mut channel_id_arr = [0u8; 16];
                channel_id_arr.copy_from_slice(&channel_bytes);
                let outcome = SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                };
                self.cache_channel_info(
                    outcome.channel_id,
                    &ChannelInfo {
                        alias: outcome.alias.clone(),
                    },
                );
                Ok(outcome)
            }
        }
    }

    async fn private_subscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        let channel_id = channel_id.to_vec();
        let device_id = device_id.to_vec();
        let created_at = Utc::now().timestamp();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES ($1, $2, 'private', 'private', NULL, NULL, NULL, NULL, 1, 'active', 'private_subscribe', $3, $3) \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       channel_type = EXCLUDED.channel_type, \
                       status = EXCLUDED.status, \
                       updated_at = EXCLUDED.updated_at",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES (?, ?, 'private', 'private', NULL, NULL, NULL, NULL, 1, 'active', 'private_subscribe', ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       channel_type = VALUES(channel_type), \
                       status = VALUES(status), \
                       updated_at = VALUES(updated_at)",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO channel_subscriptions \
                     (channel_id, device_id, platform, channel_type, device_key, provider_token, provider_token_hash, provider_token_preview, route_version, status, subscribed_via, created_at, updated_at) \
                     VALUES (?, ?, 'private', 'private', NULL, NULL, NULL, NULL, 1, 'active', 'private_subscribe', ?, ?) \
                     ON CONFLICT (channel_id, device_id) DO UPDATE SET \
                       channel_type = excluded.channel_type, \
                       status = excluded.status, \
                       updated_at = excluded.updated_at",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn private_unsubscribe_channel_async(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        let channel_id = channel_id.to_vec();
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE channel_id = $1 AND device_id = $2 AND channel_type = 'private'",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE channel_id = ? AND device_id = ? AND channel_type = 'private'",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM channel_subscriptions \
                     WHERE channel_id = ? AND device_id = ? AND channel_type = 'private'",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn list_private_subscribers_async(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        let channel_id = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id FROM channel_subscriptions \
                     WHERE channel_id = $1 AND channel_type = 'private' AND created_at <= $2",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if let Some(id) = parse_private_device_id(&device_id) {
                        out.push(id);
                    }
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id FROM channel_subscriptions \
                     WHERE channel_id = ? AND channel_type = 'private' AND created_at <= ?",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if let Some(id) = parse_private_device_id(&device_id) {
                        out.push(id);
                    }
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id FROM channel_subscriptions \
                     WHERE channel_id = ? AND channel_type = 'private' AND created_at <= ?",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if let Some(id) = parse_private_device_id(&device_id) {
                        out.push(id);
                    }
                }
                Ok(out)
            }
        }
    }

    async fn list_channel_devices_async(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<DeviceInfo>> {
        if let Some(cached) = self.cached_channel_devices(channel_id) {
            for info in &cached {
                let device_id = device_id_for(info.platform, &info.token_raw);
                self.device_cache
                    .write()
                    .entry(device_id)
                    .or_insert_with(|| info.clone());
            }
            return Ok(cached);
        }
        let channel_bytes = channel_id.to_vec();
        let rows: Vec<(Vec<u8>, Vec<u8>, i16)> = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.token_raw, d.platform_code \
                     FROM channel_subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = $1 AND s.status = 'active'",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let token_raw: Vec<u8> = row.try_get("token_raw")?;
                    let platform_code: i16 = row.try_get("platform_code")?;
                    output.push((device_id, token_raw, platform_code));
                }
                output
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.token_raw, d.platform_code \
                     FROM channel_subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = ? AND s.status = 'active'",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let token_raw: Vec<u8> = row.try_get("token_raw")?;
                    let platform_code: i16 = row.try_get("platform_code")?;
                    output.push((device_id, token_raw, platform_code));
                }
                output
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.token_raw, d.platform_code \
                     FROM channel_subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = ? AND s.status = 'active'",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let token_raw: Vec<u8> = row.try_get("token_raw")?;
                    let platform_code: i16 = row.try_get("platform_code")?;
                    output.push((device_id, token_raw, platform_code));
                }
                output
            }
        };

        let mut devices = Vec::with_capacity(rows.len());
        for (device_id, token_raw, platform_code) in rows {
            let platform =
                Platform::from_byte(platform_code as u8).ok_or(StoreError::InvalidPlatform)?;
            let info = DeviceInfo::from_raw(platform, token_raw)?;
            if device_id.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&device_id);
                self.device_cache
                    .write()
                    .entry(id)
                    .or_insert_with(|| info.clone());
            }
            devices.push(info);
        }
        self.cache_channel_devices(channel_id, &devices);
        Ok(devices)
    }

    async fn list_channel_dispatch_targets_async(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        let now_sec = Utc::now().timestamp();
        let use_cache = (effective_at - now_sec).abs() <= 5;
        if use_cache && let Some(cached) = self.cached_channel_dispatch_targets(channel_id) {
            let age_ms = Utc::now().timestamp_millis() - cached.cached_at_ms;
            if age_ms >= 0 && age_ms <= self.dispatch_targets_cache_ttl_ms {
                return Ok(cached.targets);
            }
        }
        let channel_bytes = channel_id.to_vec();
        let rows: Vec<(Vec<u8>, String, String, Option<String>, Option<String>)> = match &self
            .backend
        {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT s.device_id, s.platform, s.channel_type, s.device_key, s.provider_token \
                     FROM channel_subscriptions s \
                     WHERE s.channel_id = $1 AND s.status = 'active' AND s.created_at <= $2 \
                     ORDER BY s.channel_type ASC, s.created_at ASC, s.device_id ASC",
                )
                .bind(&channel_bytes)
                .bind(effective_at)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push((
                        row.try_get("device_id")?,
                        row.try_get("platform")?,
                        row.try_get("channel_type")?,
                        row.try_get("device_key")?,
                        row.try_get("provider_token")?,
                    ));
                }
                out
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT s.device_id, s.platform, s.channel_type, s.device_key, s.provider_token \
                     FROM channel_subscriptions s \
                     WHERE s.channel_id = ? AND s.status = 'active' AND s.created_at <= ? \
                     ORDER BY s.channel_type ASC, s.created_at ASC, s.device_id ASC",
                )
                .bind(&channel_bytes)
                .bind(effective_at)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push((
                        row.try_get("device_id")?,
                        row.try_get("platform")?,
                        row.try_get("channel_type")?,
                        row.try_get("device_key")?,
                        row.try_get("provider_token")?,
                    ));
                }
                out
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT s.device_id, s.platform, s.channel_type, s.device_key, s.provider_token \
                     FROM channel_subscriptions s \
                     WHERE s.channel_id = ? AND s.status = 'active' AND s.created_at <= ? \
                     ORDER BY s.channel_type ASC, s.created_at ASC, s.device_id ASC",
                )
                .bind(&channel_bytes)
                .bind(effective_at)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push((
                        row.try_get("device_id")?,
                        row.try_get("platform")?,
                        row.try_get("channel_type")?,
                        row.try_get("device_key")?,
                        row.try_get("provider_token")?,
                    ));
                }
                out
            }
        };

        let mut out = Vec::with_capacity(rows.len());
        for (raw_device_id, platform_raw, channel_type, device_key, provider_token) in rows {
            if channel_type.eq_ignore_ascii_case("private") {
                if let Some(device_id) = parse_private_device_id(&raw_device_id) {
                    out.push(DispatchTarget::Private {
                        device_id,
                        device_key,
                    });
                }
                continue;
            }

            let platform: Platform = platform_raw.parse()?;
            let provider_token = provider_token
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let Some(provider_token) = provider_token else {
                continue;
            };
            out.push(DispatchTarget::Provider {
                platform,
                provider_token,
                device_key,
            });
        }
        if use_cache {
            self.cache_channel_dispatch_targets(channel_id, &out);
        }
        Ok(out)
    }

    async fn list_subscribed_channels_for_device_async(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = $1 AND status = 'active'",
                )
                .bind(&device_id[..])
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = ? AND status = 'active'",
                )
                .bind(&device_id[..])
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = ? AND status = 'active'",
                )
                .bind(&device_id[..])
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
        }
    }

    async fn list_private_subscribed_channels_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = $1 AND channel_type = 'private'",
                )
                .bind(&device_id)
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = ? AND channel_type = 'private'",
                )
                .bind(&device_id)
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT channel_id FROM channel_subscriptions \
                     WHERE device_id = ? AND channel_type = 'private'",
                )
                .bind(&device_id)
                .fetch_all(pool)
                .await?;
                let mut channels = Vec::with_capacity(rows.len());
                for row in rows {
                    let channel_bytes: Vec<u8> = row.try_get("channel_id")?;
                    if channel_bytes.len() != 16 {
                        continue;
                    }
                    let mut channel_id = [0u8; 16];
                    channel_id.copy_from_slice(&channel_bytes);
                    channels.push(channel_id);
                }
                Ok(channels)
            }
        }
    }

    async fn lookup_private_device_async(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<Option<DeviceId>> {
        let token_hash = blake3::hash(token.as_bytes());
        let token_hash = token_hash.as_bytes().to_vec();
        let platform_id = platform.to_byte() as i16;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT device_id FROM private_bindings \
                     WHERE platform = $1 AND token_hash = $2",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .fetch_optional(pool)
                .await?;
                if let Some(row) = row {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    Ok(parse_private_device_id(&device_id))
                } else {
                    Ok(None)
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT device_id FROM private_bindings \
                     WHERE platform = ? AND token_hash = ?",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .fetch_optional(pool)
                .await?;
                if let Some(row) = row {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    Ok(parse_private_device_id(&device_id))
                } else {
                    Ok(None)
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT device_id FROM private_bindings \
                     WHERE platform = ? AND token_hash = ?",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .fetch_optional(pool)
                .await?;
                if let Some(row) = row {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    Ok(parse_private_device_id(&device_id))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn bind_private_token_async(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        let token_hash = blake3::hash(token.as_bytes());
        let token_hash = token_hash.as_bytes().to_vec();
        let device_id = device_id.to_vec();
        let platform_id = platform.to_byte() as i16;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO private_bindings (platform, token_hash, device_id) \
                     VALUES ($1, $2, $3) \
                     ON CONFLICT (platform, token_hash) DO UPDATE SET device_id = EXCLUDED.device_id",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO private_bindings (platform, token_hash, device_id) \
                     VALUES (?, ?, ?) \
                     ON DUPLICATE KEY UPDATE device_id = VALUES(device_id)",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_bindings (platform, token_hash, device_id) \
                     VALUES (?, ?, ?) \
                     ON CONFLICT (platform, token_hash) DO UPDATE SET device_id = excluded.device_id",
                )
                .bind(platform_id)
                .bind(&token_hash)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn load_device_routes_async(&self) -> StoreResult<Vec<DeviceRouteRecordRow>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, route_updated_at \
                     FROM devices \
                     WHERE device_key IS NOT NULL \
                       AND platform IS NOT NULL \
                       AND channel_type IS NOT NULL \
                       AND route_updated_at IS NOT NULL",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRouteRecordRow {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("route_updated_at")?,
                    });
                }
                Ok(output)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, route_updated_at \
                     FROM devices \
                     WHERE device_key IS NOT NULL \
                       AND platform IS NOT NULL \
                       AND channel_type IS NOT NULL \
                       AND route_updated_at IS NOT NULL",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRouteRecordRow {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("route_updated_at")?,
                    });
                }
                Ok(output)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, route_updated_at \
                     FROM devices \
                     WHERE device_key IS NOT NULL \
                       AND platform IS NOT NULL \
                       AND channel_type IS NOT NULL \
                       AND route_updated_at IS NOT NULL",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRouteRecordRow {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("route_updated_at")?,
                    });
                }
                Ok(output)
            }
        }
    }

    async fn upsert_device_route_async(&self, route: &DeviceRouteRecordRow) -> StoreResult<()> {
        let provider_token = route.provider_token.as_deref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let device_id = route_device_id_from_record(route)?;
        let (platform_code, token_raw) = route_device_token_fields_from_record(route)?;
        let platform = route.platform.trim().to_ascii_lowercase();
        let channel_type = route.channel_type.trim().to_ascii_lowercase();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM devices WHERE device_key = $1 AND device_id <> $2")
                    .bind(route.device_key.trim())
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO devices \
                     (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                       token_raw = EXCLUDED.token_raw, \
                       platform_code = EXCLUDED.platform_code, \
                       device_key = EXCLUDED.device_key, \
                       platform = EXCLUDED.platform, \
                       channel_type = EXCLUDED.channel_type, \
                       provider_token = EXCLUDED.provider_token, \
                       route_updated_at = EXCLUDED.route_updated_at",
                )
                .bind(&device_id)
                .bind(token_raw.as_slice())
                .bind(platform_code as i16)
                .bind(route.device_key.trim())
                .bind(platform.as_str())
                .bind(channel_type.as_str())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
                apply_route_snapshot_to_subscriptions_postgres(
                    pool,
                    &device_id,
                    route.device_key.trim(),
                    platform.as_str(),
                    channel_type.as_str(),
                    provider_token.as_deref(),
                    route.updated_at,
                )
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM devices WHERE device_key = ? AND device_id <> ?")
                    .bind(route.device_key.trim())
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO devices \
                     (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       token_raw = VALUES(token_raw), \
                       platform_code = VALUES(platform_code), \
                       device_key = VALUES(device_key), \
                       platform = VALUES(platform), \
                       channel_type = VALUES(channel_type), \
                       provider_token = VALUES(provider_token), \
                       route_updated_at = VALUES(route_updated_at)",
                )
                .bind(&device_id)
                .bind(token_raw.as_slice())
                .bind(platform_code as i16)
                .bind(route.device_key.trim())
                .bind(platform.as_str())
                .bind(channel_type.as_str())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
                apply_route_snapshot_to_subscriptions_mysql(
                    pool,
                    &device_id,
                    route.device_key.trim(),
                    platform.as_str(),
                    channel_type.as_str(),
                    provider_token.as_deref(),
                    route.updated_at,
                )
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM devices WHERE device_key = ? AND device_id <> ?")
                    .bind(route.device_key.trim())
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO devices \
                     (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                       token_raw = excluded.token_raw, \
                       platform_code = excluded.platform_code, \
                       device_key = excluded.device_key, \
                       platform = excluded.platform, \
                       channel_type = excluded.channel_type, \
                       provider_token = excluded.provider_token, \
                       route_updated_at = excluded.route_updated_at",
                )
                .bind(&device_id)
                .bind(token_raw.as_slice())
                .bind(platform_code as i16)
                .bind(route.device_key.trim())
                .bind(platform.as_str())
                .bind(channel_type.as_str())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
                apply_route_snapshot_to_subscriptions_sqlite(
                    pool,
                    &device_id,
                    route.device_key.trim(),
                    platform.as_str(),
                    channel_type.as_str(),
                    provider_token.as_deref(),
                    route.updated_at,
                )
                .await?;
            }
        }
        self.invalidate_all_channel_devices_cache();
        Ok(())
    }

    async fn append_device_route_audit_async(
        &self,
        entry: &DeviceRouteAuditWrite,
    ) -> StoreResult<()> {
        let audit_id = generate_hex_id_128();
        let old_provider_token_hash = entry
            .old_provider_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(provider_token_hash);
        let new_provider_token_hash = entry
            .new_provider_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(provider_token_hash);

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO device_route_audit \
                     (audit_id, device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token_hash, new_provider_token_hash, issue_reason, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(&audit_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.old_platform.as_deref())
                .bind(entry.new_platform.as_deref())
                .bind(entry.old_channel_type.as_deref())
                .bind(entry.new_channel_type.as_deref())
                .bind(old_provider_token_hash.as_deref())
                .bind(new_provider_token_hash.as_deref())
                .bind(entry.issue_reason.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO device_route_audit \
                     (audit_id, device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token_hash, new_provider_token_hash, issue_reason, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.old_platform.as_deref())
                .bind(entry.new_platform.as_deref())
                .bind(entry.old_channel_type.as_deref())
                .bind(entry.new_channel_type.as_deref())
                .bind(old_provider_token_hash.as_deref())
                .bind(new_provider_token_hash.as_deref())
                .bind(entry.issue_reason.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO device_route_audit \
                     (audit_id, device_key, action, old_platform, new_platform, old_channel_type, new_channel_type, old_provider_token_hash, new_provider_token_hash, issue_reason, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.old_platform.as_deref())
                .bind(entry.new_platform.as_deref())
                .bind(entry.old_channel_type.as_deref())
                .bind(entry.new_channel_type.as_deref())
                .bind(old_provider_token_hash.as_deref())
                .bind(new_provider_token_hash.as_deref())
                .bind(entry.issue_reason.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn append_subscription_audit_async(
        &self,
        entry: &SubscriptionAuditWrite,
    ) -> StoreResult<()> {
        let audit_id = generate_hex_id_128();
        let channel_id = entry.channel_id.to_vec();

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO subscription_audit \
                     (audit_id, channel_id, device_key, action, platform, channel_type, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(&audit_id)
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.platform.trim())
                .bind(entry.channel_type.trim())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO subscription_audit \
                     (audit_id, channel_id, device_key, action, platform, channel_type, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.platform.trim())
                .bind(entry.channel_type.trim())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO subscription_audit \
                     (audit_id, channel_id, device_key, action, platform, channel_type, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.action.trim())
                .bind(entry.platform.trim())
                .bind(entry.channel_type.trim())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn append_delivery_audit_async(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
        let audit_id = generate_hex_id_128();
        let channel_id = entry.channel_id.to_vec();
        let normalized_path = normalize_delivery_audit_path(entry.path.as_str());
        let normalized_status = normalize_delivery_audit_status(entry.status.as_str());
        let normalized_error_code =
            normalize_delivery_audit_error_code(entry.error_code.as_deref());

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO delivery_audit \
                     (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(&audit_id)
                .bind(entry.delivery_id.trim())
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.entity_type.as_deref())
                .bind(entry.entity_id.as_deref())
                .bind(entry.op_id.as_deref())
                .bind(normalized_path)
                .bind(normalized_status)
                .bind(normalized_error_code.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO delivery_audit \
                     (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(entry.delivery_id.trim())
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.entity_type.as_deref())
                .bind(entry.entity_id.as_deref())
                .bind(entry.op_id.as_deref())
                .bind(normalized_path)
                .bind(normalized_status)
                .bind(normalized_error_code.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO delivery_audit \
                     (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&audit_id)
                .bind(entry.delivery_id.trim())
                .bind(&channel_id)
                .bind(entry.device_key.trim())
                .bind(entry.entity_type.as_deref())
                .bind(entry.entity_id.as_deref())
                .bind(entry.op_id.as_deref())
                .bind(normalized_path)
                .bind(normalized_status)
                .bind(normalized_error_code.as_deref())
                .bind(entry.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn append_delivery_audit_batch_async(
        &self,
        entries: &[DeliveryAuditWrite],
    ) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                for entry in entries {
                    let audit_id = generate_hex_id_128();
                    let channel_id = entry.channel_id.to_vec();
                    let normalized_path = normalize_delivery_audit_path(entry.path.as_str());
                    let normalized_status = normalize_delivery_audit_status(entry.status.as_str());
                    let normalized_error_code =
                        normalize_delivery_audit_error_code(entry.error_code.as_deref());
                    sqlx::query(
                        "INSERT INTO delivery_audit \
                         (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                    )
                    .bind(&audit_id)
                    .bind(entry.delivery_id.trim())
                    .bind(&channel_id)
                    .bind(entry.device_key.trim())
                    .bind(entry.entity_type.as_deref())
                    .bind(entry.entity_id.as_deref())
                    .bind(entry.op_id.as_deref())
                    .bind(normalized_path)
                    .bind(normalized_status)
                    .bind(normalized_error_code.as_deref())
                    .bind(entry.created_at)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                for entry in entries {
                    let audit_id = generate_hex_id_128();
                    let channel_id = entry.channel_id.to_vec();
                    let normalized_path = normalize_delivery_audit_path(entry.path.as_str());
                    let normalized_status = normalize_delivery_audit_status(entry.status.as_str());
                    let normalized_error_code =
                        normalize_delivery_audit_error_code(entry.error_code.as_deref());
                    sqlx::query(
                        "INSERT INTO delivery_audit \
                         (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&audit_id)
                    .bind(entry.delivery_id.trim())
                    .bind(&channel_id)
                    .bind(entry.device_key.trim())
                    .bind(entry.entity_type.as_deref())
                    .bind(entry.entity_id.as_deref())
                    .bind(entry.op_id.as_deref())
                    .bind(normalized_path)
                    .bind(normalized_status)
                    .bind(normalized_error_code.as_deref())
                    .bind(entry.created_at)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                for entry in entries {
                    let audit_id = generate_hex_id_128();
                    let channel_id = entry.channel_id.to_vec();
                    let normalized_path = normalize_delivery_audit_path(entry.path.as_str());
                    let normalized_status = normalize_delivery_audit_status(entry.status.as_str());
                    let normalized_error_code =
                        normalize_delivery_audit_error_code(entry.error_code.as_deref());
                    sqlx::query(
                        "INSERT INTO delivery_audit \
                         (audit_id, delivery_id, channel_id, device_key, entity_type, entity_id, op_id, path, status, error_code, created_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&audit_id)
                    .bind(entry.delivery_id.trim())
                    .bind(&channel_id)
                    .bind(entry.device_key.trim())
                    .bind(entry.entity_type.as_deref())
                    .bind(entry.entity_id.as_deref())
                    .bind(entry.op_id.as_deref())
                    .bind(normalized_path)
                    .bind(normalized_status)
                    .bind(normalized_error_code.as_deref())
                    .bind(entry.created_at)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
        }
        Ok(())
    }

    async fn apply_stats_batch_async(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        if batch.channels.is_empty() && batch.devices.is_empty() && batch.gateway.is_empty() {
            return Ok(());
        }

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                for row in &batch.channels {
                    let channel_id = row.channel_id.to_vec();
                    sqlx::query(
                        "INSERT INTO channel_stats_daily \
                         (channel_id, bucket_date, messages_routed, deliveries_attempted, deliveries_acked, private_enqueued, provider_attempted, provider_failed, provider_success, private_realtime_delivered) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                         ON CONFLICT (channel_id, bucket_date) DO UPDATE SET \
                           messages_routed = channel_stats_daily.messages_routed + EXCLUDED.messages_routed, \
                           deliveries_attempted = channel_stats_daily.deliveries_attempted + EXCLUDED.deliveries_attempted, \
                           deliveries_acked = channel_stats_daily.deliveries_acked + EXCLUDED.deliveries_acked, \
                           private_enqueued = channel_stats_daily.private_enqueued + EXCLUDED.private_enqueued, \
                           provider_attempted = channel_stats_daily.provider_attempted + EXCLUDED.provider_attempted, \
                           provider_failed = channel_stats_daily.provider_failed + EXCLUDED.provider_failed, \
                           provider_success = channel_stats_daily.provider_success + EXCLUDED.provider_success, \
                           private_realtime_delivered = channel_stats_daily.private_realtime_delivered + EXCLUDED.private_realtime_delivered",
                    )
                    .bind(&channel_id)
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_enqueued)
                    .bind(row.provider_attempted)
                    .bind(row.provider_failed)
                    .bind(row.provider_success)
                    .bind(row.private_realtime_delivered)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.devices {
                    sqlx::query(
                        "INSERT INTO device_stats_daily \
                         (device_key, bucket_date, messages_received, messages_acked, private_connected_count, private_pull_count, provider_success_count, provider_failure_count, private_outbox_enqueued_count) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                         ON CONFLICT (device_key, bucket_date) DO UPDATE SET \
                           messages_received = device_stats_daily.messages_received + EXCLUDED.messages_received, \
                           messages_acked = device_stats_daily.messages_acked + EXCLUDED.messages_acked, \
                           private_connected_count = device_stats_daily.private_connected_count + EXCLUDED.private_connected_count, \
                           private_pull_count = device_stats_daily.private_pull_count + EXCLUDED.private_pull_count, \
                           provider_success_count = device_stats_daily.provider_success_count + EXCLUDED.provider_success_count, \
                           provider_failure_count = device_stats_daily.provider_failure_count + EXCLUDED.provider_failure_count, \
                           private_outbox_enqueued_count = device_stats_daily.private_outbox_enqueued_count + EXCLUDED.private_outbox_enqueued_count",
                    )
                    .bind(row.device_key.trim())
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_received)
                    .bind(row.messages_acked)
                    .bind(row.private_connected_count)
                    .bind(row.private_pull_count)
                    .bind(row.provider_success_count)
                    .bind(row.provider_failure_count)
                    .bind(row.private_outbox_enqueued_count)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.gateway {
                    sqlx::query(
                        "INSERT INTO gateway_stats_hourly \
                         (bucket_hour, messages_routed, deliveries_attempted, deliveries_acked, private_outbox_depth_max, dedupe_pending_max, active_private_sessions_max) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (bucket_hour) DO UPDATE SET \
                           messages_routed = gateway_stats_hourly.messages_routed + EXCLUDED.messages_routed, \
                           deliveries_attempted = gateway_stats_hourly.deliveries_attempted + EXCLUDED.deliveries_attempted, \
                           deliveries_acked = gateway_stats_hourly.deliveries_acked + EXCLUDED.deliveries_acked, \
                           private_outbox_depth_max = GREATEST(gateway_stats_hourly.private_outbox_depth_max, EXCLUDED.private_outbox_depth_max), \
                           dedupe_pending_max = GREATEST(gateway_stats_hourly.dedupe_pending_max, EXCLUDED.dedupe_pending_max), \
                           active_private_sessions_max = GREATEST(gateway_stats_hourly.active_private_sessions_max, EXCLUDED.active_private_sessions_max)",
                    )
                    .bind(row.bucket_hour.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_outbox_depth_max)
                    .bind(row.dedupe_pending_max)
                    .bind(row.active_private_sessions_max)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                for row in &batch.channels {
                    let channel_id = row.channel_id.to_vec();
                    sqlx::query(
                        "INSERT INTO channel_stats_daily \
                         (channel_id, bucket_date, messages_routed, deliveries_attempted, deliveries_acked, private_enqueued, provider_attempted, provider_failed, provider_success, private_realtime_delivered) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON DUPLICATE KEY UPDATE \
                           messages_routed = messages_routed + VALUES(messages_routed), \
                           deliveries_attempted = deliveries_attempted + VALUES(deliveries_attempted), \
                           deliveries_acked = deliveries_acked + VALUES(deliveries_acked), \
                           private_enqueued = private_enqueued + VALUES(private_enqueued), \
                           provider_attempted = provider_attempted + VALUES(provider_attempted), \
                           provider_failed = provider_failed + VALUES(provider_failed), \
                           provider_success = provider_success + VALUES(provider_success), \
                           private_realtime_delivered = private_realtime_delivered + VALUES(private_realtime_delivered)",
                    )
                    .bind(&channel_id)
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_enqueued)
                    .bind(row.provider_attempted)
                    .bind(row.provider_failed)
                    .bind(row.provider_success)
                    .bind(row.private_realtime_delivered)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.devices {
                    sqlx::query(
                        "INSERT INTO device_stats_daily \
                         (device_key, bucket_date, messages_received, messages_acked, private_connected_count, private_pull_count, provider_success_count, provider_failure_count, private_outbox_enqueued_count) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON DUPLICATE KEY UPDATE \
                           messages_received = messages_received + VALUES(messages_received), \
                           messages_acked = messages_acked + VALUES(messages_acked), \
                           private_connected_count = private_connected_count + VALUES(private_connected_count), \
                           private_pull_count = private_pull_count + VALUES(private_pull_count), \
                           provider_success_count = provider_success_count + VALUES(provider_success_count), \
                           provider_failure_count = provider_failure_count + VALUES(provider_failure_count), \
                           private_outbox_enqueued_count = private_outbox_enqueued_count + VALUES(private_outbox_enqueued_count)",
                    )
                    .bind(row.device_key.trim())
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_received)
                    .bind(row.messages_acked)
                    .bind(row.private_connected_count)
                    .bind(row.private_pull_count)
                    .bind(row.provider_success_count)
                    .bind(row.provider_failure_count)
                    .bind(row.private_outbox_enqueued_count)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.gateway {
                    sqlx::query(
                        "INSERT INTO gateway_stats_hourly \
                         (bucket_hour, messages_routed, deliveries_attempted, deliveries_acked, private_outbox_depth_max, dedupe_pending_max, active_private_sessions_max) \
                         VALUES (?, ?, ?, ?, ?, ?, ?) \
                         ON DUPLICATE KEY UPDATE \
                           messages_routed = messages_routed + VALUES(messages_routed), \
                           deliveries_attempted = deliveries_attempted + VALUES(deliveries_attempted), \
                           deliveries_acked = deliveries_acked + VALUES(deliveries_acked), \
                           private_outbox_depth_max = GREATEST(private_outbox_depth_max, VALUES(private_outbox_depth_max)), \
                           dedupe_pending_max = GREATEST(dedupe_pending_max, VALUES(dedupe_pending_max)), \
                           active_private_sessions_max = GREATEST(active_private_sessions_max, VALUES(active_private_sessions_max))",
                    )
                    .bind(row.bucket_hour.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_outbox_depth_max)
                    .bind(row.dedupe_pending_max)
                    .bind(row.active_private_sessions_max)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                for row in &batch.channels {
                    let channel_id = row.channel_id.to_vec();
                    sqlx::query(
                        "INSERT INTO channel_stats_daily \
                         (channel_id, bucket_date, messages_routed, deliveries_attempted, deliveries_acked, private_enqueued, provider_attempted, provider_failed, provider_success, private_realtime_delivered) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT (channel_id, bucket_date) DO UPDATE SET \
                           messages_routed = channel_stats_daily.messages_routed + excluded.messages_routed, \
                           deliveries_attempted = channel_stats_daily.deliveries_attempted + excluded.deliveries_attempted, \
                           deliveries_acked = channel_stats_daily.deliveries_acked + excluded.deliveries_acked, \
                           private_enqueued = channel_stats_daily.private_enqueued + excluded.private_enqueued, \
                           provider_attempted = channel_stats_daily.provider_attempted + excluded.provider_attempted, \
                           provider_failed = channel_stats_daily.provider_failed + excluded.provider_failed, \
                           provider_success = channel_stats_daily.provider_success + excluded.provider_success, \
                           private_realtime_delivered = channel_stats_daily.private_realtime_delivered + excluded.private_realtime_delivered",
                    )
                    .bind(&channel_id)
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_enqueued)
                    .bind(row.provider_attempted)
                    .bind(row.provider_failed)
                    .bind(row.provider_success)
                    .bind(row.private_realtime_delivered)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.devices {
                    sqlx::query(
                        "INSERT INTO device_stats_daily \
                         (device_key, bucket_date, messages_received, messages_acked, private_connected_count, private_pull_count, provider_success_count, provider_failure_count, private_outbox_enqueued_count) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT (device_key, bucket_date) DO UPDATE SET \
                           messages_received = device_stats_daily.messages_received + excluded.messages_received, \
                           messages_acked = device_stats_daily.messages_acked + excluded.messages_acked, \
                           private_connected_count = device_stats_daily.private_connected_count + excluded.private_connected_count, \
                           private_pull_count = device_stats_daily.private_pull_count + excluded.private_pull_count, \
                           provider_success_count = device_stats_daily.provider_success_count + excluded.provider_success_count, \
                           provider_failure_count = device_stats_daily.provider_failure_count + excluded.provider_failure_count, \
                           private_outbox_enqueued_count = device_stats_daily.private_outbox_enqueued_count + excluded.private_outbox_enqueued_count",
                    )
                    .bind(row.device_key.trim())
                    .bind(row.bucket_date.as_str())
                    .bind(row.messages_received)
                    .bind(row.messages_acked)
                    .bind(row.private_connected_count)
                    .bind(row.private_pull_count)
                    .bind(row.provider_success_count)
                    .bind(row.provider_failure_count)
                    .bind(row.private_outbox_enqueued_count)
                    .execute(&mut *tx)
                    .await?;
                }
                for row in &batch.gateway {
                    sqlx::query(
                        "INSERT INTO gateway_stats_hourly \
                         (bucket_hour, messages_routed, deliveries_attempted, deliveries_acked, private_outbox_depth_max, dedupe_pending_max, active_private_sessions_max) \
                         VALUES (?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT (bucket_hour) DO UPDATE SET \
                           messages_routed = gateway_stats_hourly.messages_routed + excluded.messages_routed, \
                           deliveries_attempted = gateway_stats_hourly.deliveries_attempted + excluded.deliveries_attempted, \
                           deliveries_acked = gateway_stats_hourly.deliveries_acked + excluded.deliveries_acked, \
                           private_outbox_depth_max = max(gateway_stats_hourly.private_outbox_depth_max, excluded.private_outbox_depth_max), \
                           dedupe_pending_max = max(gateway_stats_hourly.dedupe_pending_max, excluded.dedupe_pending_max), \
                           active_private_sessions_max = max(gateway_stats_hourly.active_private_sessions_max, excluded.active_private_sessions_max)",
                    )
                    .bind(row.bucket_hour.as_str())
                    .bind(row.messages_routed)
                    .bind(row.deliveries_attempted)
                    .bind(row.deliveries_acked)
                    .bind(row.private_outbox_depth_max)
                    .bind(row.dedupe_pending_max)
                    .bind(row.active_private_sessions_max)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
            }
        }

        Ok(())
    }

    async fn insert_private_message_async(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        let size = message.size as i64;
        let sent_at = message.sent_at;
        let expires_at = message.expires_at;
        let now = Utc::now().timestamp();
        let context = decode_private_payload_context(&message.payload).unwrap_or_default();
        let channel_id = context.channel_id.unwrap_or([0u8; 16]);
        let entity_type = context.entity_type.as_deref();
        let entity_id = context.entity_id.as_deref();
        let op_id = context.op_id.as_deref();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO private_payloads \
                     (delivery_id, channel_id, payload_blob, payload_size, entity_type, entity_id, op_id, sent_at, expires_at, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                       channel_id = EXCLUDED.channel_id, \
                       payload_blob = EXCLUDED.payload_blob, \
                       payload_size = EXCLUDED.payload_size, \
                       entity_type = EXCLUDED.entity_type, \
                       entity_id = EXCLUDED.entity_id, \
                       op_id = EXCLUDED.op_id, \
                       sent_at = EXCLUDED.sent_at, \
                       expires_at = EXCLUDED.expires_at, \
                       updated_at = EXCLUDED.updated_at",
                )
                .bind(delivery_id)
                .bind(&channel_id[..])
                .bind(&message.payload)
                .bind(size)
                .bind(entity_type)
                .bind(entity_id)
                .bind(op_id)
                .bind(sent_at)
                .bind(expires_at)
                .bind(now)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO private_payloads \
                     (delivery_id, channel_id, payload_blob, payload_size, entity_type, entity_id, op_id, sent_at, expires_at, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       channel_id = VALUES(channel_id), \
                       payload_blob = VALUES(payload_blob), \
                       payload_size = VALUES(payload_size), \
                       entity_type = VALUES(entity_type), \
                       entity_id = VALUES(entity_id), \
                       op_id = VALUES(op_id), \
                       sent_at = VALUES(sent_at), \
                       expires_at = VALUES(expires_at), \
                       updated_at = VALUES(updated_at)",
                )
                .bind(delivery_id)
                .bind(&channel_id[..])
                .bind(&message.payload)
                .bind(size)
                .bind(entity_type)
                .bind(entity_id)
                .bind(op_id)
                .bind(sent_at)
                .bind(expires_at)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_payloads \
                     (delivery_id, channel_id, payload_blob, payload_size, entity_type, entity_id, op_id, sent_at, expires_at, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                       channel_id = excluded.channel_id, \
                       payload_blob = excluded.payload_blob, \
                       payload_size = excluded.payload_size, \
                       entity_type = excluded.entity_type, \
                       entity_id = excluded.entity_id, \
                       op_id = excluded.op_id, \
                       sent_at = excluded.sent_at, \
                       expires_at = excluded.expires_at, \
                       updated_at = excluded.updated_at",
                )
                .bind(delivery_id)
                .bind(&channel_id[..])
                .bind(&message.payload)
                .bind(size)
                .bind(entity_type)
                .bind(entity_id)
                .bind(op_id)
                .bind(sent_at)
                .bind(expires_at)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn enqueue_private_outbox_async(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        let attempts = entry.attempts as i64;
        let occurred_at = entry.occurred_at;
        let created_at = entry.created_at;
        let next_attempt_at = entry.next_attempt_at;
        let updated_at = entry.updated_at;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                     ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                         status = EXCLUDED.status, \
                         attempts = EXCLUDED.attempts, \
                         occurred_at = EXCLUDED.occurred_at, \
                         created_at = EXCLUDED.created_at, \
                         claimed_at = EXCLUDED.claimed_at, \
                         first_sent_at = EXCLUDED.first_sent_at, \
                         last_attempt_at = EXCLUDED.last_attempt_at, \
                         acked_at = EXCLUDED.acked_at, \
                         fallback_sent_at = EXCLUDED.fallback_sent_at, \
                         next_attempt_at = EXCLUDED.next_attempt_at, \
                         last_error_code = EXCLUDED.last_error_code, \
                         last_error_detail = EXCLUDED.last_error_detail, \
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(occurred_at)
                .bind(created_at)
                .bind(entry.claimed_at)
                .bind(entry.first_sent_at)
                .bind(entry.last_attempt_at)
                .bind(entry.acked_at)
                .bind(entry.fallback_sent_at)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
                .bind(entry.last_error_detail.as_deref())
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                         status = VALUES(status), \
                         attempts = VALUES(attempts), \
                         occurred_at = VALUES(occurred_at), \
                         created_at = VALUES(created_at), \
                         claimed_at = VALUES(claimed_at), \
                         first_sent_at = VALUES(first_sent_at), \
                         last_attempt_at = VALUES(last_attempt_at), \
                         acked_at = VALUES(acked_at), \
                         fallback_sent_at = VALUES(fallback_sent_at), \
                         next_attempt_at = VALUES(next_attempt_at), \
                         last_error_code = VALUES(last_error_code), \
                         last_error_detail = VALUES(last_error_detail), \
                         updated_at = VALUES(updated_at)",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(occurred_at)
                .bind(created_at)
                .bind(entry.claimed_at)
                .bind(entry.first_sent_at)
                .bind(entry.last_attempt_at)
                .bind(entry.acked_at)
                .bind(entry.fallback_sent_at)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
                .bind(entry.last_error_detail.as_deref())
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                         status = excluded.status, \
                         attempts = excluded.attempts, \
                         occurred_at = excluded.occurred_at, \
                         created_at = excluded.created_at, \
                         claimed_at = excluded.claimed_at, \
                         first_sent_at = excluded.first_sent_at, \
                         last_attempt_at = excluded.last_attempt_at, \
                         acked_at = excluded.acked_at, \
                         fallback_sent_at = excluded.fallback_sent_at, \
                         next_attempt_at = excluded.next_attempt_at, \
                         last_error_code = excluded.last_error_code, \
                         last_error_detail = excluded.last_error_detail, \
                         updated_at = excluded.updated_at",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(occurred_at)
                .bind(created_at)
                .bind(entry.claimed_at)
                .bind(entry.first_sent_at)
                .bind(entry.last_attempt_at)
                .bind(entry.acked_at)
                .bind(entry.fallback_sent_at)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
                .bind(entry.last_error_detail.as_deref())
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn list_private_outbox_async(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let device_id = device_id.to_vec();
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4) \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT $5",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(PrivateOutboxEntry {
                        delivery_id: row.try_get("delivery_id")?,
                        status: row.try_get("status")?,
                        attempts: row.try_get::<i32, _>("attempts")? as u32,
                        occurred_at: row.try_get("occurred_at")?,
                        created_at: row.try_get("created_at")?,
                        claimed_at: row.try_get("claimed_at")?,
                        first_sent_at: row.try_get("first_sent_at")?,
                        last_attempt_at: row.try_get("last_attempt_at")?,
                        acked_at: row.try_get("acked_at")?,
                        fallback_sent_at: row.try_get("fallback_sent_at")?,
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        last_error_detail: row.try_get("last_error_detail")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(PrivateOutboxEntry {
                        delivery_id: row.try_get("delivery_id")?,
                        status: row.try_get("status")?,
                        attempts: row.try_get::<i32, _>("attempts")? as u32,
                        occurred_at: row.try_get("occurred_at")?,
                        created_at: row.try_get("created_at")?,
                        claimed_at: row.try_get("claimed_at")?,
                        first_sent_at: row.try_get("first_sent_at")?,
                        last_attempt_at: row.try_get("last_attempt_at")?,
                        acked_at: row.try_get("acked_at")?,
                        fallback_sent_at: row.try_get("fallback_sent_at")?,
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        last_error_detail: row.try_get("last_error_detail")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC LIMIT ?",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(PrivateOutboxEntry {
                        delivery_id: row.try_get("delivery_id")?,
                        status: row.try_get("status")?,
                        attempts: row.try_get::<i32, _>("attempts")? as u32,
                        occurred_at: row.try_get("occurred_at")?,
                        created_at: row.try_get("created_at")?,
                        claimed_at: row.try_get("claimed_at")?,
                        first_sent_at: row.try_get("first_sent_at")?,
                        last_attempt_at: row.try_get("last_attempt_at")?,
                        acked_at: row.try_get("acked_at")?,
                        fallback_sent_at: row.try_get("fallback_sent_at")?,
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        last_error_detail: row.try_get("last_error_detail")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
        }
    }

    async fn count_private_outbox_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize> {
        let device_id = device_id.to_vec();
        let count: i64 = match &self.backend {
            SqlxBackend::Postgres(pool) => sqlx::query_scalar(
                "SELECT COUNT(1) FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4)",
            )
            .bind(&device_id)
            .bind(OUTBOX_STATUS_PENDING)
            .bind(OUTBOX_STATUS_CLAIMED)
            .bind(OUTBOX_STATUS_SENT)
            .fetch_one(pool)
            .await?,
            SqlxBackend::Mysql(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?)",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(pool)
                .await?
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?)",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(count as usize)
    }

    async fn cleanup_private_expired_data_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut removed = 0usize;
                let expired_rows = sqlx::query(
                    "SELECT delivery_id FROM private_payloads \
                     WHERE expires_at <= $1 \
                     ORDER BY expires_at ASC \
                     LIMIT $2",
                )
                .bind(before_ts)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in expired_rows {
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query("DELETE FROM private_payloads WHERE delivery_id = $1")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    sqlx::query("DELETE FROM private_outbox WHERE delivery_id = $1")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    removed = removed.saturating_add(1);
                }

                let dangling_rows = sqlx::query(
                    "SELECT o.device_id, o.delivery_id \
                     FROM private_outbox o \
                     LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
                     WHERE m.delivery_id IS NULL \
                     LIMIT $1",
                )
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in dangling_rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query(
                        "DELETE FROM private_outbox \
                         WHERE device_id = $1 AND delivery_id = $2",
                    )
                    .bind(&device_id)
                    .bind(&delivery_id)
                    .execute(pool)
                    .await?;
                    removed = removed.saturating_add(1);
                }
                Ok(removed)
            }
            SqlxBackend::Mysql(pool) => {
                let mut removed = 0usize;
                let expired_rows = sqlx::query(
                    "SELECT delivery_id FROM private_payloads \
                     WHERE expires_at <= ? \
                     ORDER BY expires_at ASC \
                     LIMIT ?",
                )
                .bind(before_ts)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in expired_rows {
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    sqlx::query("DELETE FROM private_outbox WHERE delivery_id = ?")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    removed = removed.saturating_add(1);
                }

                let dangling_rows = sqlx::query(
                    "SELECT o.device_id, o.delivery_id \
                     FROM private_outbox o \
                     LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
                     WHERE m.delivery_id IS NULL \
                     LIMIT ?",
                )
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in dangling_rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query(
                        "DELETE FROM private_outbox \
                         WHERE device_id = ? AND delivery_id = ?",
                    )
                    .bind(&device_id)
                    .bind(&delivery_id)
                    .execute(pool)
                    .await?;
                    removed = removed.saturating_add(1);
                }
                Ok(removed)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut removed = 0usize;
                let expired_rows = sqlx::query(
                    "SELECT delivery_id FROM private_payloads \
                     WHERE expires_at <= ? \
                     ORDER BY expires_at ASC \
                     LIMIT ?",
                )
                .bind(before_ts)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in expired_rows {
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    sqlx::query("DELETE FROM private_outbox WHERE delivery_id = ?")
                        .bind(&delivery_id)
                        .execute(pool)
                        .await?;
                    removed = removed.saturating_add(1);
                }

                let dangling_rows = sqlx::query(
                    "SELECT o.device_id, o.delivery_id \
                     FROM private_outbox o \
                     LEFT JOIN private_payloads m ON m.delivery_id = o.delivery_id \
                     WHERE m.delivery_id IS NULL \
                     LIMIT ?",
                )
                .bind(limit)
                .fetch_all(pool)
                .await?;
                for row in dangling_rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let delivery_id: String = row.try_get("delivery_id")?;
                    sqlx::query(
                        "DELETE FROM private_outbox \
                         WHERE device_id = ? AND delivery_id = ?",
                    )
                    .bind(&device_id)
                    .bind(&delivery_id)
                    .execute(pool)
                    .await?;
                    removed = removed.saturating_add(1);
                }
                Ok(removed)
            }
        }
    }

    async fn load_private_message_async(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT payload_blob, payload_size, sent_at, expires_at \
                     FROM private_payloads WHERE delivery_id = $1",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("payload_size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT payload_blob, payload_size, sent_at, expires_at \
                     FROM private_payloads WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("payload_size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT payload_blob, payload_size, sent_at, expires_at \
                     FROM private_payloads WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("payload_size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
        }
    }

    async fn load_private_payload_context_async(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT channel_id, entity_type, entity_id, op_id \
                     FROM private_payloads WHERE delivery_id = $1",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => {
                        let channel_raw: Vec<u8> = row.try_get("channel_id")?;
                        let channel_id = if channel_raw.len() == 16 {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&channel_raw);
                            (id != [0u8; 16]).then_some(id)
                        } else {
                            None
                        };
                        Ok(Some(PrivatePayloadContext {
                            channel_id,
                            entity_type: row.try_get("entity_type")?,
                            entity_id: row.try_get("entity_id")?,
                            op_id: row.try_get("op_id")?,
                        }))
                    }
                    None => Ok(None),
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT channel_id, entity_type, entity_id, op_id \
                     FROM private_payloads WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => {
                        let channel_raw: Vec<u8> = row.try_get("channel_id")?;
                        let channel_id = if channel_raw.len() == 16 {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&channel_raw);
                            (id != [0u8; 16]).then_some(id)
                        } else {
                            None
                        };
                        Ok(Some(PrivatePayloadContext {
                            channel_id,
                            entity_type: row.try_get("entity_type")?,
                            entity_id: row.try_get("entity_id")?,
                            op_id: row.try_get("op_id")?,
                        }))
                    }
                    None => Ok(None),
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT channel_id, entity_type, entity_id, op_id \
                     FROM private_payloads WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => {
                        let channel_raw: Vec<u8> = row.try_get("channel_id")?;
                        let channel_id = if channel_raw.len() == 16 {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&channel_raw);
                            (id != [0u8; 16]).then_some(id)
                        } else {
                            None
                        };
                        Ok(Some(PrivatePayloadContext {
                            channel_id,
                            entity_type: row.try_get("entity_type")?,
                            entity_id: row.try_get("entity_id")?,
                            op_id: row.try_get("op_id")?,
                        }))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    async fn enqueue_provider_pull_item_async(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        let delivery_id = delivery_id.trim();
        let provider_token = provider_token.trim();
        if delivery_id.is_empty() {
            return Ok(());
        }
        if provider_token.is_empty() {
            return Ok(());
        }
        self.insert_private_message_async(delivery_id, message)
            .await?;
        let now = Utc::now().timestamp();
        let platform_text = platform_name(platform);
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO provider_pull_queue (delivery_id, status, pulled_at, acked_at, created_at, updated_at) \
                     VALUES ($1, 'pending', NULL, NULL, $2, $2) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                        status = 'pending', \
                        pulled_at = NULL, \
                        acked_at = NULL, \
                        updated_at = EXCLUDED.updated_at",
                )
                .bind(delivery_id)
                .bind(now)
                .execute(pool)
                .await?;
                sqlx::query(
                    "INSERT INTO provider_pull_retry \
                     (delivery_id, platform, provider_token, attempts, next_retry_at, last_attempt_at, expires_at, created_at, updated_at) \
                     VALUES ($1, $2, $3, 0, $4, NULL, $5, $6, $6) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                        platform = EXCLUDED.platform, \
                        provider_token = EXCLUDED.provider_token, \
                        attempts = 0, \
                        next_retry_at = EXCLUDED.next_retry_at, \
                        last_attempt_at = NULL, \
                        expires_at = EXCLUDED.expires_at, \
                        updated_at = EXCLUDED.updated_at",
                )
                .bind(delivery_id)
                .bind(platform_text)
                .bind(provider_token)
                .bind(next_retry_at)
                .bind(message.expires_at)
                .bind(now)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO provider_pull_queue (delivery_id, status, pulled_at, acked_at, created_at, updated_at) \
                     VALUES (?, 'pending', NULL, NULL, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                        status = 'pending', \
                        pulled_at = NULL, \
                        acked_at = NULL, \
                        updated_at = VALUES(updated_at)",
                )
                .bind(delivery_id)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
                sqlx::query(
                    "INSERT INTO provider_pull_retry \
                     (delivery_id, platform, provider_token, attempts, next_retry_at, last_attempt_at, expires_at, created_at, updated_at) \
                     VALUES (?, ?, ?, 0, ?, NULL, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                        platform = VALUES(platform), \
                        provider_token = VALUES(provider_token), \
                        attempts = 0, \
                        next_retry_at = VALUES(next_retry_at), \
                        last_attempt_at = NULL, \
                        expires_at = VALUES(expires_at), \
                        updated_at = VALUES(updated_at)",
                )
                .bind(delivery_id)
                .bind(platform_text)
                .bind(provider_token)
                .bind(next_retry_at)
                .bind(message.expires_at)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO provider_pull_queue (delivery_id, status, pulled_at, acked_at, created_at, updated_at) \
                     VALUES (?, 'pending', NULL, NULL, ?, ?) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                        status = 'pending', \
                        pulled_at = NULL, \
                        acked_at = NULL, \
                        updated_at = excluded.updated_at",
                )
                .bind(delivery_id)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
                sqlx::query(
                    "INSERT INTO provider_pull_retry \
                     (delivery_id, platform, provider_token, attempts, next_retry_at, last_attempt_at, expires_at, created_at, updated_at) \
                     VALUES (?, ?, ?, 0, ?, NULL, ?, ?, ?) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                        platform = excluded.platform, \
                        provider_token = excluded.provider_token, \
                        attempts = 0, \
                        next_retry_at = excluded.next_retry_at, \
                        last_attempt_at = NULL, \
                        expires_at = excluded.expires_at, \
                        updated_at = excluded.updated_at",
                )
                .bind(delivery_id)
                .bind(platform_text)
                .bind(provider_token)
                .bind(next_retry_at)
                .bind(message.expires_at)
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn pull_provider_item_async(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let delivery_id = delivery_id.trim();
        if delivery_id.is_empty() {
            return Ok(None);
        }
        let item = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT p.payload_blob, p.payload_size, p.sent_at, p.expires_at \
                     FROM provider_pull_queue q \
                     INNER JOIN private_payloads p ON p.delivery_id = q.delivery_id \
                     WHERE q.delivery_id = $1 AND q.status = 'pending' AND p.expires_at > $2",
                )
                .bind(delivery_id)
                .bind(now)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let claimed = sqlx::query(
                    "UPDATE provider_pull_queue \
                     SET status = 'pulled', pulled_at = $2, updated_at = $2 \
                     WHERE delivery_id = $1 AND status = 'pending'",
                )
                .bind(delivery_id)
                .bind(now)
                .execute(pool)
                .await?
                .rows_affected();
                if claimed == 0 {
                    return Ok(None);
                }
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = $1")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_payloads WHERE delivery_id = $1")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM provider_pull_queue WHERE delivery_id = $1")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                Some(ProviderPullItem {
                    delivery_id: delivery_id.to_string(),
                    payload: row.try_get("payload_blob")?,
                    sent_at: row.try_get("sent_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT p.payload_blob, p.payload_size, p.sent_at, p.expires_at \
                     FROM provider_pull_queue q \
                     INNER JOIN private_payloads p ON p.delivery_id = q.delivery_id \
                     WHERE q.delivery_id = ? AND q.status = 'pending' AND p.expires_at > ?",
                )
                .bind(delivery_id)
                .bind(now)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let claimed = sqlx::query(
                    "UPDATE provider_pull_queue \
                     SET status = 'pulled', pulled_at = ?, updated_at = ? \
                     WHERE delivery_id = ? AND status = 'pending'",
                )
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .execute(pool)
                .await?
                .rows_affected();
                if claimed == 0 {
                    return Ok(None);
                }
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM provider_pull_queue WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                Some(ProviderPullItem {
                    delivery_id: delivery_id.to_string(),
                    payload: row.try_get("payload_blob")?,
                    sent_at: row.try_get("sent_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT p.payload_blob, p.payload_size, p.sent_at, p.expires_at \
                     FROM provider_pull_queue q \
                     INNER JOIN private_payloads p ON p.delivery_id = q.delivery_id \
                     WHERE q.delivery_id = ? AND q.status = 'pending' AND p.expires_at > ?",
                )
                .bind(delivery_id)
                .bind(now)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let claimed = sqlx::query(
                    "UPDATE provider_pull_queue \
                     SET status = 'pulled', pulled_at = ?, updated_at = ? \
                     WHERE delivery_id = ? AND status = 'pending'",
                )
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .execute(pool)
                .await?
                .rows_affected();
                if claimed == 0 {
                    return Ok(None);
                }
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM provider_pull_queue WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
                Some(ProviderPullItem {
                    delivery_id: delivery_id.to_string(),
                    payload: row.try_get("payload_blob")?,
                    sent_at: row.try_get("sent_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            }
        };
        Ok(item)
    }

    async fn list_provider_pull_retry_due_async(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        let limit = limit.max(1) as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT r.delivery_id, r.platform, r.provider_token, r.attempts, r.next_retry_at, r.expires_at \
                     FROM provider_pull_retry r \
                     INNER JOIN provider_pull_queue q ON q.delivery_id = r.delivery_id \
                     WHERE q.status = 'pending' AND r.next_retry_at <= $1 AND r.expires_at > $1 \
                     ORDER BY r.next_retry_at ASC \
                     LIMIT $2",
                )
                .bind(now)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        let platform_text: String = row.try_get("platform")?;
                        let platform = platform_text.parse::<Platform>()?;
                        Ok(ProviderPullRetryEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            platform,
                            provider_token: row.try_get("provider_token")?,
                            attempts: row.try_get("attempts")?,
                            next_retry_at: row.try_get("next_retry_at")?,
                            expires_at: row.try_get("expires_at")?,
                        })
                    })
                    .collect()
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT r.delivery_id, r.platform, r.provider_token, r.attempts, r.next_retry_at, r.expires_at \
                     FROM provider_pull_retry r \
                     INNER JOIN provider_pull_queue q ON q.delivery_id = r.delivery_id \
                     WHERE q.status = 'pending' AND r.next_retry_at <= ? AND r.expires_at > ? \
                     ORDER BY r.next_retry_at ASC \
                     LIMIT ?",
                )
                .bind(now)
                .bind(now)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        let platform_text: String = row.try_get("platform")?;
                        let platform = platform_text.parse::<Platform>()?;
                        Ok(ProviderPullRetryEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            platform,
                            provider_token: row.try_get("provider_token")?,
                            attempts: row.try_get("attempts")?,
                            next_retry_at: row.try_get("next_retry_at")?,
                            expires_at: row.try_get("expires_at")?,
                        })
                    })
                    .collect()
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT r.delivery_id, r.platform, r.provider_token, r.attempts, r.next_retry_at, r.expires_at \
                     FROM provider_pull_retry r \
                     INNER JOIN provider_pull_queue q ON q.delivery_id = r.delivery_id \
                     WHERE q.status = 'pending' AND r.next_retry_at <= ? AND r.expires_at > ? \
                     ORDER BY r.next_retry_at ASC \
                     LIMIT ?",
                )
                .bind(now)
                .bind(now)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        let platform_text: String = row.try_get("platform")?;
                        let platform = platform_text.parse::<Platform>()?;
                        Ok(ProviderPullRetryEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            platform,
                            provider_token: row.try_get("provider_token")?,
                            attempts: row.try_get("attempts")?,
                            next_retry_at: row.try_get("next_retry_at")?,
                            expires_at: row.try_get("expires_at")?,
                        })
                    })
                    .collect()
            }
        }
    }

    async fn bump_provider_pull_retry_async(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        let delivery_id = delivery_id.trim();
        if delivery_id.is_empty() {
            return Ok(false);
        }
        let affected = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "UPDATE provider_pull_retry \
                     SET attempts = attempts + 1, \
                         next_retry_at = $2, \
                         last_attempt_at = $3, \
                         updated_at = $3 \
                     WHERE delivery_id = $1 \
                       AND expires_at > $3 \
                       AND EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.delivery_id = provider_pull_retry.delivery_id AND q.status = 'pending')",
                )
                .bind(delivery_id)
                .bind(next_retry_at)
                .bind(now)
                .execute(pool)
                .await?
                .rows_affected()
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "UPDATE provider_pull_retry \
                     SET attempts = attempts + 1, \
                         next_retry_at = ?, \
                         last_attempt_at = ?, \
                         updated_at = ? \
                     WHERE delivery_id = ? \
                       AND expires_at > ? \
                       AND EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.delivery_id = provider_pull_retry.delivery_id AND q.status = 'pending')",
                )
                .bind(next_retry_at)
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .bind(now)
                .execute(pool)
                .await?
                .rows_affected()
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE provider_pull_retry \
                     SET attempts = attempts + 1, \
                         next_retry_at = ?, \
                         last_attempt_at = ?, \
                         updated_at = ? \
                     WHERE delivery_id = ? \
                       AND expires_at > ? \
                       AND EXISTS (SELECT 1 FROM provider_pull_queue q WHERE q.delivery_id = provider_pull_retry.delivery_id AND q.status = 'pending')",
                )
                .bind(next_retry_at)
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .bind(now)
                .execute(pool)
                .await?
                .rows_affected()
            }
        };
        Ok(affected > 0)
    }

    async fn clear_provider_pull_retry_async(&self, delivery_id: &str) -> StoreResult<()> {
        let delivery_id = delivery_id.trim();
        if delivery_id.is_empty() {
            return Ok(());
        }
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = $1")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn load_private_outbox_entry_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = $1 AND delivery_id = $2",
                )
                .bind(&device_id)
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(PrivateOutboxEntry {
                    delivery_id: row.try_get("delivery_id")?,
                    status: row.try_get("status")?,
                    attempts: row.try_get::<i32, _>("attempts")? as u32,
                    occurred_at: row.try_get("occurred_at")?,
                    created_at: row.try_get("created_at")?,
                    claimed_at: row.try_get("claimed_at")?,
                    first_sent_at: row.try_get("first_sent_at")?,
                    last_attempt_at: row.try_get("last_attempt_at")?,
                    acked_at: row.try_get("acked_at")?,
                    fallback_sent_at: row.try_get("fallback_sent_at")?,
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
                    last_error_detail: row.try_get("last_error_detail")?,
                    updated_at: row.try_get("updated_at")?,
                }))
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
                )
                .bind(&device_id)
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(PrivateOutboxEntry {
                    delivery_id: row.try_get("delivery_id")?,
                    status: row.try_get("status")?,
                    attempts: row.try_get::<i32, _>("attempts")? as u32,
                    occurred_at: row.try_get("occurred_at")?,
                    created_at: row.try_get("created_at")?,
                    claimed_at: row.try_get("claimed_at")?,
                    first_sent_at: row.try_get("first_sent_at")?,
                    last_attempt_at: row.try_get("last_attempt_at")?,
                    acked_at: row.try_get("acked_at")?,
                    fallback_sent_at: row.try_get("fallback_sent_at")?,
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
                    last_error_detail: row.try_get("last_error_detail")?,
                    updated_at: row.try_get("updated_at")?,
                }))
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
                )
                .bind(&device_id)
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(PrivateOutboxEntry {
                    delivery_id: row.try_get("delivery_id")?,
                    status: row.try_get("status")?,
                    attempts: row.try_get::<i32, _>("attempts")? as u32,
                    occurred_at: row.try_get("occurred_at")?,
                    created_at: row.try_get("created_at")?,
                    claimed_at: row.try_get("claimed_at")?,
                    first_sent_at: row.try_get("first_sent_at")?,
                    last_attempt_at: row.try_get("last_attempt_at")?,
                    acked_at: row.try_get("acked_at")?,
                    fallback_sent_at: row.try_get("fallback_sent_at")?,
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
                    last_error_detail: row.try_get("last_error_detail")?,
                    updated_at: row.try_get("updated_at")?,
                }))
            }
        }
    }

    async fn count_private_outbox_total_async(&self) -> StoreResult<usize> {
        let count: i64 = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(1) FROM private_outbox WHERE status IN ($1, $2, $3)",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .fetch_one(pool)
                .await?
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN (?, ?, ?)")
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .fetch_one(pool)
                    .await?
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE status IN (?, ?, ?)")
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count as usize)
    }

    async fn reserve_delivery_dedupe_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "INSERT INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $4) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Sent.as_str())
                .bind(created_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "INSERT IGNORE INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Sent.as_str())
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "INSERT INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Sent.as_str())
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    async fn reserve_semantic_id_async(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "INSERT INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
                     VALUES ($1, $2, $3, $3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(semantic_id)
                .bind(created_at)
                .execute(pool)
                .await?;
                if result.rows_affected() > 0 {
                    return Ok(SemanticIdReservation::Reserved);
                }
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = $1",
                )
                .bind(dedupe_key)
                .fetch_optional(pool)
                .await?;
                Ok(match existing {
                    Some(semantic_id) => SemanticIdReservation::Existing { semantic_id },
                    None => SemanticIdReservation::Collision,
                })
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "INSERT IGNORE INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(dedupe_key)
                .bind(semantic_id)
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
                if result.rows_affected() > 0 {
                    return Ok(SemanticIdReservation::Reserved);
                }
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?",
                )
                .bind(dedupe_key)
                .fetch_optional(pool)
                .await?;
                Ok(match existing {
                    Some(semantic_id) => SemanticIdReservation::Existing { semantic_id },
                    None => SemanticIdReservation::Collision,
                })
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "INSERT INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
                     VALUES (?, ?, ?, ?) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(semantic_id)
                .bind(created_at)
                .bind(created_at)
                .execute(pool)
                .await?;
                if result.rows_affected() > 0 {
                    return Ok(SemanticIdReservation::Reserved);
                }
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = ?",
                )
                .bind(dedupe_key)
                .fetch_optional(pool)
                .await?;
                Ok(match existing {
                    Some(semantic_id) => SemanticIdReservation::Existing { semantic_id },
                    None => SemanticIdReservation::Collision,
                })
            }
        }
    }

    async fn reserve_op_dedupe_pending_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let inserted = sqlx::query(
                    "INSERT INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $4) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .bind(created_at)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = $1 FOR UPDATE",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: String = row.try_get("state")?;
                        match DedupeState::from_str(state.as_str())? {
                            DedupeState::Pending => OpDedupeReservation::Pending {
                                delivery_id: existing_delivery_id,
                            },
                            DedupeState::Sent => OpDedupeReservation::Sent {
                                delivery_id: existing_delivery_id,
                            },
                        }
                    } else {
                        OpDedupeReservation::Pending {
                            delivery_id: delivery_id.to_string(),
                        }
                    }
                };
                tx.commit().await?;
                Ok(outcome)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let inserted = sqlx::query(
                    "INSERT IGNORE INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .bind(created_at)
                .bind(created_at)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = ? FOR UPDATE",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: String = row.try_get("state")?;
                        match DedupeState::from_str(state.as_str())? {
                            DedupeState::Pending => OpDedupeReservation::Pending {
                                delivery_id: existing_delivery_id,
                            },
                            DedupeState::Sent => OpDedupeReservation::Sent {
                                delivery_id: existing_delivery_id,
                            },
                        }
                    } else {
                        OpDedupeReservation::Pending {
                            delivery_id: delivery_id.to_string(),
                        }
                    }
                };
                tx.commit().await?;
                Ok(outcome)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let inserted = sqlx::query(
                    "INSERT INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .bind(created_at)
                .bind(created_at)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = ?",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: String = row.try_get("state")?;
                        match DedupeState::from_str(state.as_str())? {
                            DedupeState::Pending => OpDedupeReservation::Pending {
                                delivery_id: existing_delivery_id,
                            },
                            DedupeState::Sent => OpDedupeReservation::Sent {
                                delivery_id: existing_delivery_id,
                            },
                        }
                    } else {
                        OpDedupeReservation::Pending {
                            delivery_id: delivery_id.to_string(),
                        }
                    }
                };
                tx.commit().await?;
                Ok(outcome)
            }
        }
    }

    async fn mark_op_dedupe_sent_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        let now = Utc::now().timestamp();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "UPDATE dispatch_op_dedupe \
                     SET state = $1, sent_at = $2, updated_at = $2 \
                     WHERE dedupe_key = $3 AND delivery_id = $4 AND state = $5",
                )
                .bind(DedupeState::Sent.as_str())
                .bind(now)
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "UPDATE dispatch_op_dedupe \
                     SET state = ?, sent_at = ?, updated_at = ? \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(DedupeState::Sent.as_str())
                .bind(now)
                .bind(now)
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "UPDATE dispatch_op_dedupe \
                     SET state = ?, sent_at = ?, updated_at = ? \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(DedupeState::Sent.as_str())
                .bind(now)
                .bind(now)
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    async fn clear_op_dedupe_pending_async(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "DELETE FROM dispatch_op_dedupe \
                     WHERE dedupe_key = $1 AND delivery_id = $2 AND state = $3",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM dispatch_op_dedupe \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM dispatch_op_dedupe \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_str())
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn list_private_outbox_due_async(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE next_attempt_at <= $1 AND status IN ($2, $3, $4) \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT $5",
                )
                .bind(before_ts)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            status: row.try_get("status")?,
                            attempts: row.try_get::<i32, _>("attempts")? as u32,
                            occurred_at: row.try_get("occurred_at")?,
                            created_at: row.try_get("created_at")?,
                            claimed_at: row.try_get("claimed_at")?,
                            first_sent_at: row.try_get("first_sent_at")?,
                            last_attempt_at: row.try_get("last_attempt_at")?,
                            acked_at: row.try_get("acked_at")?,
                            fallback_sent_at: row.try_get("fallback_sent_at")?,
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            last_error_detail: row.try_get("last_error_detail")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ?",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            status: row.try_get("status")?,
                            attempts: row.try_get::<i32, _>("attempts")? as u32,
                            occurred_at: row.try_get("occurred_at")?,
                            created_at: row.try_get("created_at")?,
                            claimed_at: row.try_get("claimed_at")?,
                            first_sent_at: row.try_get("first_sent_at")?,
                            last_attempt_at: row.try_get("last_attempt_at")?,
                            acked_at: row.try_get("acked_at")?,
                            fallback_sent_at: row.try_get("fallback_sent_at")?,
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            last_error_detail: row.try_get("last_error_detail")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ?",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            status: row.try_get("status")?,
                            attempts: row.try_get::<i32, _>("attempts")? as u32,
                            occurred_at: row.try_get("occurred_at")?,
                            created_at: row.try_get("created_at")?,
                            claimed_at: row.try_get("claimed_at")?,
                            first_sent_at: row.try_get("first_sent_at")?,
                            last_attempt_at: row.try_get("last_attempt_at")?,
                            acked_at: row.try_get("acked_at")?,
                            fallback_sent_at: row.try_get("fallback_sent_at")?,
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            last_error_detail: row.try_get("last_error_detail")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
        }
    }

    async fn claim_private_outbox_due_async(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "WITH candidates AS ( \
                        SELECT device_id, delivery_id \
                        FROM private_outbox \
                        WHERE status IN ($1, $2, $3) AND next_attempt_at <= $4 \
                        ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                        LIMIT $5 \
                        FOR UPDATE SKIP LOCKED \
                     ) \
                     UPDATE private_outbox o \
                     SET status = $6, claimed_at = $7, last_attempt_at = $7, next_attempt_at = $7, updated_at = $7, last_error_code = NULL, last_error_detail = NULL \
                     FROM candidates c \
                     WHERE o.device_id = c.device_id AND o.delivery_id = c.delivery_id \
                     RETURNING o.device_id, o.delivery_id, o.status, o.attempts, o.occurred_at, o.created_at, o.claimed_at, o.first_sent_at, o.last_attempt_at, o.acked_at, o.fallback_sent_at, o.next_attempt_at, o.last_error_code, o.last_error_detail, o.updated_at",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(claim_until_ts)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id: row.try_get("delivery_id")?,
                            status: row.try_get("status")?,
                            attempts: row.try_get::<i32, _>("attempts")? as u32,
                            occurred_at: row.try_get("occurred_at")?,
                            created_at: row.try_get("created_at")?,
                            claimed_at: row.try_get("claimed_at")?,
                            first_sent_at: row.try_get("first_sent_at")?,
                            last_attempt_at: row.try_get("last_attempt_at")?,
                            acked_at: row.try_get("acked_at")?,
                            fallback_sent_at: row.try_get("fallback_sent_at")?,
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            last_error_detail: row.try_get("last_error_detail")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ? FOR UPDATE",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                let mut out = Vec::new();
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let delivery_id: String = row.try_get("delivery_id")?;
                    let attempts: u32 = row.try_get::<i32, _>("attempts")? as u32;
                    let occurred_at: i64 = row.try_get("occurred_at")?;
                    let created_at: i64 = row.try_get("created_at")?;
                    let first_sent_at: Option<i64> = row.try_get("first_sent_at")?;
                    let acked_at: Option<i64> = row.try_get("acked_at")?;
                    let fallback_sent_at: Option<i64> = row.try_get("fallback_sent_at")?;
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, claimed_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(&raw_device)
                    .bind(&delivery_id)
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .bind(before_ts)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        > 0;
                    if !updated {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id,
                            status: OUTBOX_STATUS_CLAIMED.to_string(),
                            attempts,
                            occurred_at,
                            created_at,
                            claimed_at: Some(claim_until_ts),
                            first_sent_at,
                            last_attempt_at: Some(claim_until_ts),
                            acked_at,
                            fallback_sent_at,
                            next_attempt_at: claim_until_ts,
                            last_error_code: None,
                            last_error_detail: None,
                            updated_at: claim_until_ts,
                        },
                    ));
                }
                tx.commit().await?;
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ?",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                let mut out = Vec::new();
                for row in rows {
                    let raw_device: Vec<u8> = row.try_get("device_id")?;
                    if raw_device.len() != 16 {
                        continue;
                    }
                    let delivery_id: String = row.try_get("delivery_id")?;
                    let attempts: u32 = row.try_get::<i32, _>("attempts")? as u32;
                    let occurred_at: i64 = row.try_get("occurred_at")?;
                    let created_at: i64 = row.try_get("created_at")?;
                    let first_sent_at: Option<i64> = row.try_get("first_sent_at")?;
                    let acked_at: Option<i64> = row.try_get("acked_at")?;
                    let fallback_sent_at: Option<i64> = row.try_get("fallback_sent_at")?;
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, claimed_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(&raw_device)
                    .bind(&delivery_id)
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .bind(before_ts)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        > 0;
                    if !updated {
                        continue;
                    }
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&raw_device);
                    out.push((
                        device_id,
                        PrivateOutboxEntry {
                            delivery_id,
                            status: OUTBOX_STATUS_CLAIMED.to_string(),
                            attempts,
                            occurred_at,
                            created_at,
                            claimed_at: Some(claim_until_ts),
                            first_sent_at,
                            last_attempt_at: Some(claim_until_ts),
                            acked_at,
                            fallback_sent_at,
                            next_attempt_at: claim_until_ts,
                            last_error_code: None,
                            last_error_detail: None,
                            updated_at: claim_until_ts,
                        },
                    ));
                }
                tx.commit().await?;
                Ok(out)
            }
        }
    }

    async fn claim_private_outbox_due_for_device_async(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        let device_id = device_id.to_vec();
        let limit = limit as i64;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "WITH candidates AS ( \
                        SELECT delivery_id \
                        FROM private_outbox \
                        WHERE device_id = $1 AND status IN ($2, $3, $4) AND next_attempt_at <= $5 \
                        ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                        LIMIT $6 \
                        FOR UPDATE SKIP LOCKED \
                     ) \
                     UPDATE private_outbox o \
                     SET status = $7, claimed_at = $8, last_attempt_at = $8, next_attempt_at = $8, updated_at = $8, last_error_code = NULL, last_error_detail = NULL \
                     FROM candidates c \
                     WHERE o.device_id = $1 AND o.delivery_id = c.delivery_id \
                     RETURNING o.delivery_id, o.status, o.attempts, o.occurred_at, o.created_at, o.claimed_at, o.first_sent_at, o.last_attempt_at, o.acked_at, o.fallback_sent_at, o.next_attempt_at, o.last_error_code, o.last_error_detail, o.updated_at",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(claim_until_ts)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(PrivateOutboxEntry {
                        delivery_id: row.try_get("delivery_id")?,
                        status: row.try_get("status")?,
                        attempts: row.try_get::<i32, _>("attempts")? as u32,
                        occurred_at: row.try_get("occurred_at")?,
                        created_at: row.try_get("created_at")?,
                        claimed_at: row.try_get("claimed_at")?,
                        first_sent_at: row.try_get("first_sent_at")?,
                        last_attempt_at: row.try_get("last_attempt_at")?,
                        acked_at: row.try_get("acked_at")?,
                        fallback_sent_at: row.try_get("fallback_sent_at")?,
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        last_error_detail: row.try_get("last_error_detail")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE device_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ? FOR UPDATE",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                let mut out = Vec::new();
                for row in rows {
                    let delivery_id: String = row.try_get("delivery_id")?;
                    let attempts: u32 = row.try_get::<i32, _>("attempts")? as u32;
                    let occurred_at: i64 = row.try_get("occurred_at")?;
                    let created_at: i64 = row.try_get("created_at")?;
                    let first_sent_at: Option<i64> = row.try_get("first_sent_at")?;
                    let acked_at: Option<i64> = row.try_get("acked_at")?;
                    let fallback_sent_at: Option<i64> = row.try_get("fallback_sent_at")?;
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, claimed_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(&device_id)
                    .bind(&delivery_id)
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .bind(before_ts)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        > 0;
                    if !updated {
                        continue;
                    }
                    out.push(PrivateOutboxEntry {
                        delivery_id,
                        status: OUTBOX_STATUS_CLAIMED.to_string(),
                        attempts,
                        occurred_at,
                        created_at,
                        claimed_at: Some(claim_until_ts),
                        first_sent_at,
                        last_attempt_at: Some(claim_until_ts),
                        acked_at,
                        fallback_sent_at,
                        next_attempt_at: claim_until_ts,
                        last_error_code: None,
                        last_error_detail: None,
                        updated_at: claim_until_ts,
                    });
                }
                tx.commit().await?;
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, occurred_at, created_at, claimed_at, first_sent_at, last_attempt_at, acked_at, fallback_sent_at, next_attempt_at, last_error_code, last_error_detail, updated_at \
                     FROM private_outbox \
                     WHERE device_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY occurred_at ASC, created_at ASC, delivery_id ASC \
                     LIMIT ?",
                )
                .bind(&device_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                let mut out = Vec::new();
                for row in rows {
                    let delivery_id: String = row.try_get("delivery_id")?;
                    let attempts: u32 = row.try_get::<i32, _>("attempts")? as u32;
                    let occurred_at: i64 = row.try_get("occurred_at")?;
                    let created_at: i64 = row.try_get("created_at")?;
                    let first_sent_at: Option<i64> = row.try_get("first_sent_at")?;
                    let acked_at: Option<i64> = row.try_get("acked_at")?;
                    let fallback_sent_at: Option<i64> = row.try_get("fallback_sent_at")?;
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, claimed_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(claim_until_ts)
                    .bind(&device_id)
                    .bind(&delivery_id)
                    .bind(OUTBOX_STATUS_PENDING)
                    .bind(OUTBOX_STATUS_CLAIMED)
                    .bind(OUTBOX_STATUS_SENT)
                    .bind(before_ts)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        > 0;
                    if !updated {
                        continue;
                    }
                    out.push(PrivateOutboxEntry {
                        delivery_id,
                        status: OUTBOX_STATUS_CLAIMED.to_string(),
                        attempts,
                        occurred_at,
                        created_at,
                        claimed_at: Some(claim_until_ts),
                        first_sent_at,
                        last_attempt_at: Some(claim_until_ts),
                        acked_at,
                        fallback_sent_at,
                        next_attempt_at: claim_until_ts,
                        last_error_code: None,
                        last_error_detail: None,
                        updated_at: claim_until_ts,
                    });
                }
                tx.commit().await?;
                Ok(out)
            }
        }
    }

    async fn mark_private_fallback_sent_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = $3, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, $4), fallback_sent_at = $4, last_attempt_at = $4, next_attempt_at = $4, updated_at = $4, last_error_code = NULL, last_error_detail = NULL \
                     WHERE device_id = $1 AND delivery_id = $2 AND status IN ($5, $6, $7)",
                )
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_SENT)
                .bind(at_ts)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = ?, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, ?), fallback_sent_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_SENT)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = ?, attempts = attempts + 1, first_sent_at = COALESCE(first_sent_at, ?), fallback_sent_at = ?, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL, last_error_detail = NULL \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_SENT)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn defer_private_fallback_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = $3, attempts = attempts + 1, last_attempt_at = $4, next_attempt_at = $4, updated_at = $4, last_error_code = $5, last_error_detail = $5 \
                     WHERE device_id = $1 AND delivery_id = $2 AND status IN ($6, $7, $8)",
                )
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(at_ts)
                .bind("provider_dispatch_failed")
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = ?, attempts = attempts + 1, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = ?, last_error_detail = ? \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind("provider_dispatch_failed")
                .bind("provider_dispatch_failed")
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE private_outbox \
                     SET status = ?, attempts = attempts + 1, last_attempt_at = ?, next_attempt_at = ?, updated_at = ?, last_error_code = ?, last_error_detail = ? \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(at_ts)
                .bind(at_ts)
                .bind(at_ts)
                .bind("provider_dispatch_failed")
                .bind("provider_dispatch_failed")
                .bind(&device_id)
                .bind(delivery_id)
                .bind(OUTBOX_STATUS_PENDING)
                .bind(OUTBOX_STATUS_CLAIMED)
                .bind(OUTBOX_STATUS_SENT)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn ack_private_delivery_async(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        let removed = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        };
        if removed > 0 {
            self.delete_private_payload_if_unreferenced_async(delivery_id)
                .await?;
        }
        Ok(())
    }

    async fn clear_private_outbox_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize> {
        let device_id = device_id.to_vec();
        let delivery_ids = self
            .clear_private_outbox_for_device_entries_async(&device_id)
            .await?;
        self.delete_private_payloads_if_unreferenced_async(&delivery_ids)
            .await?;
        Ok(delivery_ids.len())
    }

    async fn clear_private_outbox_for_device_with_entries_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        let device_id = device_id.to_vec();
        let delivery_ids = self
            .clear_private_outbox_for_device_entries_async(&device_id)
            .await?;
        self.delete_private_payloads_if_unreferenced_async(&delivery_ids)
            .await?;
        Ok(delivery_ids)
    }

    async fn run_maintenance_cleanup_async(
        &self,
        now: i64,
        dedupe_before: i64,
    ) -> StoreResult<MaintenanceCleanupStats> {
        const OP_DEDUPE_PENDING_STALE_SECS: i64 = 2 * 60;
        let _ = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM private_sessions WHERE expires_at <= $1")
                    .bind(now)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM private_sessions WHERE expires_at <= ?")
                    .bind(now)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM private_sessions WHERE expires_at <= ?")
                    .bind(now)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
        };
        let private_outbox_pruned = self.cleanup_private_expired_data_async(now, 2048).await?;
        let _ = self
            .cleanup_pending_op_dedupe_async(now - OP_DEDUPE_PENDING_STALE_SECS, 2048)
            .await?;
        let _ = self
            .cleanup_semantic_id_dedupe_async(dedupe_before, 2048)
            .await?;
        let _ = self
            .cleanup_delivery_dedupe_async(dedupe_before, 2048)
            .await?;
        Ok(MaintenanceCleanupStats {
            private_outbox_pruned,
        })
    }

    async fn automation_counts_async(&self) -> StoreResult<AutomationCounts> {
        let (channel_count, subscription_count, delivery_dedupe_pending_count): (i64, i64, i64) =
            match &self.backend {
                SqlxBackend::Postgres(pool) => {
                    let channel_count = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
                        .fetch_one(pool)
                        .await?;
                    let subscription_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count = sqlx::query_scalar(
                        "SELECT COUNT(1) FROM dispatch_op_dedupe WHERE state = $1",
                    )
                    .bind(DedupeState::Pending.as_str())
                    .fetch_one(pool)
                    .await?;
                    (
                        channel_count,
                        subscription_count,
                        delivery_dedupe_pending_count,
                    )
                }
                SqlxBackend::Mysql(pool) => {
                    let channel_count = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
                        .fetch_one(pool)
                        .await?;
                    let subscription_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count = sqlx::query_scalar(
                        "SELECT COUNT(1) FROM dispatch_op_dedupe WHERE state = ?",
                    )
                    .bind(DedupeState::Pending.as_str())
                    .fetch_one(pool)
                    .await?;
                    (
                        channel_count,
                        subscription_count,
                        delivery_dedupe_pending_count,
                    )
                }
                SqlxBackend::Sqlite(pool) => {
                    let channel_count = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
                        .fetch_one(pool)
                        .await?;
                    let subscription_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count = sqlx::query_scalar(
                        "SELECT COUNT(1) FROM dispatch_op_dedupe WHERE state = ?",
                    )
                    .bind(DedupeState::Pending.as_str())
                    .fetch_one(pool)
                    .await?;
                    (
                        channel_count,
                        subscription_count,
                        delivery_dedupe_pending_count,
                    )
                }
            };

        Ok(AutomationCounts {
            channel_count: channel_count as usize,
            subscription_count: subscription_count as usize,
            delivery_dedupe_pending_count: delivery_dedupe_pending_count as usize,
        })
    }

    async fn automation_reset_async(&self) -> StoreResult<()> {
        self.device_cache.write().clear();
        self.channel_info_cache.clear_sync();
        self.invalidate_all_channel_devices_cache();
        let statements: &[&str] = &[
            "DELETE FROM delivery_audit",
            "DELETE FROM subscription_audit",
            "DELETE FROM device_route_audit",
            "DELETE FROM channel_stats_daily",
            "DELETE FROM device_stats_daily",
            "DELETE FROM gateway_stats_hourly",
            "DELETE FROM dispatch_op_dedupe",
            "DELETE FROM dispatch_delivery_dedupe",
            "DELETE FROM semantic_id_registry",
            "DELETE FROM channel_subscriptions",
            "DELETE FROM devices",
            "DELETE FROM channels",
            "DELETE FROM private_bindings",
            "DELETE FROM private_outbox",
            "DELETE FROM private_payloads",
            "DELETE FROM private_sessions",
            "DELETE FROM private_device_keys",
        ];

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                for statement in statements {
                    sqlx::query(statement).execute(&mut *tx).await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                for statement in statements {
                    sqlx::query(statement).execute(&mut *tx).await?;
                }
                tx.commit().await?;
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                for statement in statements {
                    sqlx::query(statement).execute(&mut *tx).await?;
                }
                tx.commit().await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use tempfile::tempdir;
    use tokio::time::{Duration, sleep};

    #[derive(Serialize)]
    struct TestPrivatePayloadEnvelope<'a> {
        payload_version: u8,
        data: &'a HashMap<String, String>,
    }

    #[test]
    fn decode_private_payload_context_extracts_structured_fields() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        data.insert("entity_type".to_string(), "event".to_string());
        data.insert("entity_id".to_string(), "evt-1".to_string());
        data.insert("op_id".to_string(), "op-1".to_string());
        let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data: &data,
        })
        .expect("payload encode should succeed");

        let context =
            decode_private_payload_context(&payload).expect("context decode should succeed");
        assert!(context.channel_id.is_some());
        assert_eq!(context.entity_type.as_deref(), Some("event"));
        assert_eq!(context.entity_id.as_deref(), Some("evt-1"));
        assert_eq!(context.op_id.as_deref(), Some("op-1"));
    }

    #[test]
    fn decode_private_payload_context_rejects_unknown_payload_version() {
        let mut data = HashMap::new();
        data.insert(
            "channel_id".to_string(),
            "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        );
        let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
            payload_version: 9,
            data: &data,
        })
        .expect("payload encode should succeed");

        assert!(decode_private_payload_context(&payload).is_none());
    }

    #[test]
    fn normalize_delivery_audit_path_and_status_defaults() {
        assert_eq!(normalize_delivery_audit_path("provider"), "provider");
        assert_eq!(normalize_delivery_audit_path("DIRECT"), "direct");
        assert_eq!(normalize_delivery_audit_path("invalid-path"), "provider");

        assert_eq!(normalize_delivery_audit_status("enqueued"), "enqueued");
        assert_eq!(
            normalize_delivery_audit_status("SKIPPED_PRIVATE_REALTIME"),
            "skipped_private_realtime"
        );
        assert_eq!(
            normalize_delivery_audit_status("unknown-status"),
            "enqueue_failed"
        );
    }

    #[test]
    fn normalize_delivery_audit_error_code_truncates_and_trims() {
        assert_eq!(normalize_delivery_audit_error_code(Some("  ")), None);
        assert_eq!(
            normalize_delivery_audit_error_code(Some(" queue_full ")).as_deref(),
            Some("queue_full")
        );
        let long = "x".repeat(128);
        let normalized = normalize_delivery_audit_error_code(Some(long.as_str()))
            .expect("normalized error code should be present");
        assert_eq!(normalized.len(), 64);
    }

    #[test]
    fn route_device_token_fields_from_record_private_fallback_is_parseable() {
        let route = DeviceRouteRecordRow {
            device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
            platform: "android".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 0,
        };
        let (platform_code, token_raw) = route_device_token_fields_from_record(&route)
            .expect("private route fallback token fields should work");
        let platform = Platform::from_byte(platform_code).expect("platform should decode");
        let parsed = DeviceInfo::from_raw(platform, token_raw).expect("raw token should decode");
        assert_eq!(parsed.platform, Platform::ANDROID);
    }

    #[test]
    fn route_device_token_fields_from_record_private_fallback_is_parseable_for_ios() {
        let route = DeviceRouteRecordRow {
            device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
            platform: "ios".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 0,
        };
        let (platform_code, token_raw) = route_device_token_fields_from_record(&route)
            .expect("private route fallback token fields should work");
        let platform = Platform::from_byte(platform_code).expect("platform should decode");
        let parsed = DeviceInfo::from_raw(platform, token_raw).expect("raw token should decode");
        assert_eq!(parsed.platform, Platform::IOS);
    }

    #[test]
    fn route_snapshot_fields_trims_empty_provider_token() {
        let (hash, preview) = route_snapshot_fields(Some("   "));
        assert!(hash.is_none());
        assert!(preview.is_none());

        let (hash2, preview2) = route_snapshot_fields(Some("abcdef123456"));
        assert!(hash2.is_some());
        assert_eq!(preview2.as_deref(), Some("abcdef***3456"));
    }

    #[tokio::test]
    async fn dispatch_targets_cache_hits_within_ttl_and_expires() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("dispatch-targets-cache.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let mut store = SqlxStore::connect(DatabaseKind::Sqlite, db_url.as_str())
            .await
            .expect("sqlite store should initialize");
        store.dispatch_targets_cache_ttl_ms = 600;
        let token = "android-token-cache-hit-0000000000000000000000000001";
        let subscribe = store
            .subscribe_channel_async(
                None,
                Some("cache-test"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed");
        let channel_id = subscribe.channel_id;
        let effective_at = Utc::now().timestamp();

        let first = store
            .list_channel_dispatch_targets_async(channel_id, effective_at)
            .await
            .expect("first fetch should succeed");
        assert_eq!(first.len(), 1);

        match &store.backend {
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ?")
                    .bind(channel_id.to_vec())
                    .execute(pool)
                    .await
                    .expect("direct delete should succeed");
            }
            _ => panic!("expected sqlite backend in test"),
        }

        let second = store
            .list_channel_dispatch_targets_async(channel_id, effective_at)
            .await
            .expect("cached fetch should succeed");
        assert_eq!(second.len(), 1);

        sleep(Duration::from_millis(750)).await;
        let third = store
            .list_channel_dispatch_targets_async(channel_id, Utc::now().timestamp())
            .await
            .expect("post-ttl fetch should succeed");
        assert_eq!(third.len(), 0);
    }

    #[tokio::test]
    async fn dispatch_targets_cache_invalidates_on_unsubscribe() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("dispatch-targets-invalidate.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let store = SqlxStore::connect(DatabaseKind::Sqlite, db_url.as_str())
            .await
            .expect("sqlite store should initialize");
        let token = "android-token-cache-invalidate-000000000000000000000001";
        let subscribe = store
            .subscribe_channel_async(
                None,
                Some("cache-invalidate"),
                "pw123456",
                token,
                Platform::ANDROID,
            )
            .await
            .expect("subscribe should succeed");
        let channel_id = subscribe.channel_id;
        let effective_at = Utc::now().timestamp();

        let first = store
            .list_channel_dispatch_targets_async(channel_id, effective_at)
            .await
            .expect("first fetch should succeed");
        assert_eq!(first.len(), 1);

        let removed = store
            .unsubscribe_channel_async(channel_id, token, Platform::ANDROID)
            .await
            .expect("unsubscribe should succeed");
        assert!(removed);

        let second = store
            .list_channel_dispatch_targets_async(channel_id, Utc::now().timestamp())
            .await
            .expect("post-invalidation fetch should succeed");
        assert_eq!(second.len(), 0);
    }

    #[tokio::test]
    async fn provider_pull_retry_lifecycle_works() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("provider-pull-retry.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let store = SqlxStore::connect(DatabaseKind::Sqlite, db_url.as_str())
            .await
            .expect("sqlite store should initialize");

        let now = Utc::now().timestamp();
        let delivery_id = "delivery-retry-001";
        let message = PrivateMessage {
            payload: vec![1, 2, 3, 4],
            size: 4,
            sent_at: now,
            expires_at: now + 300,
        };
        store
            .enqueue_provider_pull_item_async(
                delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-001",
                now - 1,
            )
            .await
            .expect("enqueue should succeed");

        let due = store
            .list_provider_pull_retry_due_async(now, 10)
            .await
            .expect("list due should succeed");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].delivery_id, delivery_id);
        assert_eq!(due[0].attempts, 0);

        store
            .bump_provider_pull_retry_async(delivery_id, now + 60, now)
            .await
            .expect("bump should succeed");
        let due_after_bump = store
            .list_provider_pull_retry_due_async(now, 10)
            .await
            .expect("second list due should succeed");
        assert!(due_after_bump.is_empty());

        let pulled = store
            .pull_provider_item_async(delivery_id, now + 1)
            .await
            .expect("pull should succeed");
        assert!(pulled.is_some());
        let pulled_again = store
            .pull_provider_item_async(delivery_id, now + 2)
            .await
            .expect("second pull should succeed");
        assert!(pulled_again.is_none());

        let payload_after_pull = store
            .load_private_message_async(delivery_id)
            .await
            .expect("payload lookup after pull should succeed");
        assert!(payload_after_pull.is_none());

        let due_after_pull = store
            .list_provider_pull_retry_due_async(now + 120, 10)
            .await
            .expect("list due after pull should succeed");
        assert!(due_after_pull.is_empty());
    }

    #[tokio::test]
    async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("private-payload-cleanup.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let store = SqlxStore::connect(DatabaseKind::Sqlite, db_url.as_str())
            .await
            .expect("sqlite store should initialize");

        let now = Utc::now().timestamp();
        let device_a: DeviceId = [1; 16];
        let device_b: DeviceId = [2; 16];

        let message = PrivateMessage {
            payload: vec![9, 8, 7, 6],
            size: 4,
            sent_at: now,
            expires_at: now + 300,
        };

        let shared_delivery_id = "delivery-private-shared-001";
        store
            .insert_private_message_async(shared_delivery_id, &message)
            .await
            .expect("insert shared payload should succeed");

        let entry_a = PrivateOutboxEntry {
            delivery_id: shared_delivery_id.to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        let entry_b = PrivateOutboxEntry {
            delivery_id: shared_delivery_id.to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        store
            .enqueue_private_outbox_async(device_a, &entry_a)
            .await
            .expect("enqueue entry a should succeed");
        store
            .enqueue_private_outbox_async(device_b, &entry_b)
            .await
            .expect("enqueue entry b should succeed");

        store
            .ack_private_delivery_async(device_a, shared_delivery_id)
            .await
            .expect("ack entry a should succeed");
        let shared_still_exists = store
            .load_private_message_async(shared_delivery_id)
            .await
            .expect("shared payload lookup should succeed");
        assert!(shared_still_exists.is_some());

        store
            .ack_private_delivery_async(device_b, shared_delivery_id)
            .await
            .expect("ack entry b should succeed");
        let shared_after_all_acked = store
            .load_private_message_async(shared_delivery_id)
            .await
            .expect("shared payload second lookup should succeed");
        assert!(shared_after_all_acked.is_none());

        let provider_delivery_id = "delivery-provider-ref-001";
        store
            .insert_private_message_async(provider_delivery_id, &message)
            .await
            .expect("insert provider payload should succeed");
        let provider_entry = PrivateOutboxEntry {
            delivery_id: provider_delivery_id.to_string(),
            status: OUTBOX_STATUS_PENDING.to_string(),
            attempts: 0,
            occurred_at: now,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: now,
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        store
            .enqueue_private_outbox_async(device_a, &provider_entry)
            .await
            .expect("enqueue provider entry should succeed");
        store
            .enqueue_provider_pull_item_async(
                provider_delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-provider-ref-001",
                now,
            )
            .await
            .expect("enqueue provider queue should succeed");

        store
            .ack_private_delivery_async(device_a, provider_delivery_id)
            .await
            .expect("ack provider entry should succeed");
        let provider_payload_after_private_ack = store
            .load_private_message_async(provider_delivery_id)
            .await
            .expect("provider payload lookup should succeed");
        assert!(provider_payload_after_private_ack.is_some());

        let pulled = store
            .pull_provider_item_async(provider_delivery_id, now + 1)
            .await
            .expect("provider pull should succeed");
        assert!(pulled.is_some());
        let provider_payload_after_pull = store
            .load_private_message_async(provider_delivery_id)
            .await
            .expect("provider payload lookup after pull should succeed");
        assert!(provider_payload_after_pull.is_none());
    }
}
