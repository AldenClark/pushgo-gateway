use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use blake3::Hasher;
use chrono::Utc;
use hashbrown::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sqlx::{
    MySqlPool, PgPool, Row, SqlitePool,
    mysql::MySqlPoolOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::Path, str::FromStr, sync::Arc, time::Duration};
use thiserror::Error;

use crate::util::{encode_lower_hex_128, random_id_bytes_128};

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
const STORAGE_SCHEMA_VERSION: &str = "2026-03-18-gateway-v4";
const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-02-25-gateway-v3";
const OUTBOX_STATUS_PENDING: &str = "pending";
const OUTBOX_STATUS_CLAIMED: &str = "claimed";
const OUTBOX_STATUS_SENT: &str = "sent";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateOutboxEntry {
    pub delivery_id: String,
    pub status: String,
    pub attempts: u32,
    pub next_attempt_at: i64,
    pub last_error_code: Option<String>,
    pub updated_at: i64,
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
    fn as_i16(self) -> i16 {
        match self {
            DedupeState::Pending => 0,
            DedupeState::Sent => 1,
        }
    }

    fn from_i16(value: i16) -> StoreResult<Self> {
        match value {
            0 => Ok(DedupeState::Pending),
            1 => Ok(DedupeState::Sent),
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
pub enum EventAction {
    Create,
    Update,
    Close,
    Reopen,
}

impl EventAction {
    pub fn as_api_str(self) -> &'static str {
        match self {
            EventAction::Create => "create",
            EventAction::Update => "update",
            EventAction::Close => "close",
            EventAction::Reopen => "reopen",
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHead {
    pub event_id: String,
    pub thing_id: Option<String>,
    pub state: EventState,
    pub event_time: i64,
    pub updated_at: i64,
    pub title: Option<String>,
    pub body: Option<String>,
    pub level: Option<String>,
    pub ttl: Option<i64>,
    pub attrs_json: Option<String>,
    pub meta_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub event_id: String,
    pub thing_id: Option<String>,
    pub action: EventAction,
    pub state: EventState,
    pub event_time: i64,
    pub received_at: i64,
    pub applied: bool,
    pub title: Option<String>,
    pub body: Option<String>,
    pub level: Option<String>,
    pub ttl: Option<i64>,
    pub attrs_json: Option<String>,
    pub meta_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThingHead {
    pub thing_id: String,
    pub state: ThingState,
    pub attrs_json: String,
    pub meta_json: Option<String>,
    pub updated_at: i64,
    pub latest_event_id: Option<String>,
    pub latest_event_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistryRoute {
    pub device_key: String,
    pub platform: String,
    pub channel_type: String,
    pub provider_token: Option<String>,
    pub updated_at: i64,
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

    async fn load_event_head_async(&self, event_id: &str) -> StoreResult<Option<EventHead>>;

    async fn upsert_event_head_async(&self, head: &EventHead) -> StoreResult<()>;

    async fn append_event_log_async(&self, entry: &EventLogEntry) -> StoreResult<()>;

    async fn load_thing_head_async(&self, thing_id: &str) -> StoreResult<Option<ThingHead>>;

    async fn upsert_thing_head_async(&self, head: &ThingHead) -> StoreResult<()>;

    async fn link_event_thing_async(
        &self,
        thing_id: &str,
        event_id: &str,
        event_time: i64,
    ) -> StoreResult<()>;

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

    async fn load_device_registry_routes_async(&self) -> StoreResult<Vec<DeviceRegistryRoute>>;

    async fn upsert_device_registry_route_async(
        &self,
        route: &DeviceRegistryRoute,
    ) -> StoreResult<()>;

    async fn list_channel_devices_async(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<DeviceInfo>>;

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
}

#[derive(Debug, Clone)]
enum SqlxBackend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
    Mysql(MySqlPool),
}

impl SqlxStore {
    async fn connect(kind: DatabaseKind, url: &str) -> StoreResult<Self> {
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
                }
            }
        };
        store.init_schema().await?;
        Ok(store)
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
                        device_blob BLOB NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS subscriptions (\
                        channel_id BLOB NOT NULL,\
                        device_id BLOB NOT NULL,\
                        PRIMARY KEY (channel_id, device_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS subscriptions_device_idx \
                    ON subscriptions (device_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_head (\
                        event_id TEXT PRIMARY KEY,\
                        thing_id TEXT,\
                        state TEXT NOT NULL,\
                        event_time INTEGER NOT NULL,\
                        updated_at INTEGER NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level TEXT,\
                        ttl INTEGER,\
                        attrs_json TEXT,\
                        meta_json TEXT\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_log (\
                        log_id TEXT PRIMARY KEY,\
                        event_id TEXT NOT NULL,\
                        thing_id TEXT,\
                        action TEXT NOT NULL,\
                        state TEXT NOT NULL,\
                        event_time INTEGER NOT NULL,\
                        received_at INTEGER NOT NULL,\
                        applied INTEGER NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level TEXT,\
                        ttl INTEGER,\
                        attrs_json TEXT,\
                        meta_json TEXT\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS event_log_event_time_idx \
                    ON event_log (event_id, event_time)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_head (\
                        thing_id TEXT PRIMARY KEY,\
                        state TEXT NOT NULL,\
                        attrs_json TEXT NOT NULL,\
                        meta_json TEXT,\
                        updated_at INTEGER NOT NULL,\
                        latest_event_id TEXT,\
                        latest_event_time INTEGER\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_event_link (\
                        thing_id TEXT NOT NULL,\
                        event_id TEXT NOT NULL,\
                        event_time INTEGER NOT NULL,\
                        PRIMARY KEY (thing_id, event_id)\
                    )",
                )
                .execute(pool)
                .await?;
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
                    "CREATE TABLE IF NOT EXISTS private_subscriptions (\
                        channel_id BLOB NOT NULL,\
                        device_id BLOB NOT NULL,\
                        created_at INTEGER NOT NULL,\
                        PRIMARY KEY (channel_id, device_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_subscriptions_device_idx \
                     ON private_subscriptions (device_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_messages (\
                        delivery_id TEXT PRIMARY KEY,\
                        payload_blob BLOB NOT NULL,\
                        size INTEGER NOT NULL,\
                        sent_at INTEGER NOT NULL,\
                        expires_at INTEGER\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_messages_exp_idx \
                     ON private_messages (expires_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_outbox (\
                        device_id BLOB NOT NULL,\
                        delivery_id TEXT NOT NULL,\
                        status TEXT NOT NULL,\
                        attempts INTEGER NOT NULL,\
                        next_attempt_at INTEGER NOT NULL,\
                        last_error_code TEXT,\
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
                    "CREATE TABLE IF NOT EXISTS device_registry_v1 (\
                        device_key TEXT PRIMARY KEY,\
                        platform TEXT NOT NULL,\
                        channel_type TEXT NOT NULL,\
                        provider_token TEXT,\
                        updated_at INTEGER NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS delivery_dedupe (\
                        dedupe_key TEXT PRIMARY KEY,\
                        delivery_id TEXT NOT NULL,\
                        created_at INTEGER NOT NULL,\
                        state INTEGER NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS delivery_dedupe_created_idx \
                     ON delivery_dedupe (created_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS semantic_id_dedupe (\
                        dedupe_key TEXT PRIMARY KEY,\
                        semantic_id TEXT NOT NULL UNIQUE,\
                        created_at INTEGER NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS semantic_id_dedupe_created_idx \
                     ON semantic_id_dedupe (created_at)",
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
                        Self::migrate_device_registry_v4_sqlite(pool).await?;
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
                        device_blob BYTEA NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS subscriptions (\
                        channel_id BYTEA NOT NULL,\
                        device_id BYTEA NOT NULL,\
                        PRIMARY KEY (channel_id, device_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS subscriptions_device_idx \
                    ON subscriptions (device_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_head (\
                        event_id VARCHAR(128) PRIMARY KEY,\
                        thing_id VARCHAR(128),\
                        state VARCHAR(32) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level VARCHAR(32),\
                        ttl BIGINT,\
                        attrs_json TEXT,\
                        meta_json TEXT\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_log (\
                        log_id VARCHAR(64) PRIMARY KEY,\
                        event_id VARCHAR(128) NOT NULL,\
                        thing_id VARCHAR(128),\
                        action VARCHAR(32) NOT NULL,\
                        state VARCHAR(32) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        received_at BIGINT NOT NULL,\
                        applied BIGINT NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level VARCHAR(32),\
                        ttl BIGINT,\
                        attrs_json TEXT,\
                        meta_json TEXT\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS event_log_event_time_idx \
                    ON event_log (event_id, event_time)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_head (\
                        thing_id VARCHAR(128) PRIMARY KEY,\
                        state VARCHAR(32) NOT NULL,\
                        attrs_json TEXT NOT NULL,\
                        meta_json TEXT,\
                        updated_at BIGINT NOT NULL,\
                        latest_event_id VARCHAR(128),\
                        latest_event_time BIGINT\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_event_link (\
                        thing_id VARCHAR(128) NOT NULL,\
                        event_id VARCHAR(128) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        PRIMARY KEY (thing_id, event_id)\
                    )",
                )
                .execute(pool)
                .await?;
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
                    "CREATE TABLE IF NOT EXISTS private_subscriptions (\
                        channel_id BYTEA NOT NULL,\
                        device_id BYTEA NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        PRIMARY KEY (channel_id, device_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS private_subscriptions_device_idx \
                    ON private_subscriptions (device_id)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_messages (\
                        delivery_id VARCHAR(128) PRIMARY KEY,\
                        payload_blob BYTEA NOT NULL,\
                        size INTEGER NOT NULL,\
                        sent_at BIGINT NOT NULL,\
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
                        next_attempt_at BIGINT NOT NULL,\
                        last_error_code TEXT,\
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
                    "CREATE TABLE IF NOT EXISTS device_registry_v1 (\
                        device_key VARCHAR(255) PRIMARY KEY,\
                        platform VARCHAR(32) NOT NULL,\
                        channel_type VARCHAR(32) NOT NULL,\
                        provider_token TEXT,\
                        updated_at BIGINT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS delivery_dedupe (\
                        dedupe_key VARCHAR(255) PRIMARY KEY,\
                        delivery_id VARCHAR(128) NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        state SMALLINT NOT NULL DEFAULT 1\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "ALTER TABLE delivery_dedupe \
                     ADD COLUMN IF NOT EXISTS state SMALLINT NOT NULL DEFAULT 1",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS delivery_dedupe_created_idx \
                     ON delivery_dedupe (created_at)",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS semantic_id_dedupe (\
                        dedupe_key VARCHAR(255) PRIMARY KEY,\
                        semantic_id VARCHAR(128) NOT NULL UNIQUE,\
                        created_at BIGINT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS semantic_id_dedupe_created_idx \
                     ON semantic_id_dedupe (created_at)",
                )
                .execute(pool)
                .await?;
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
                        device_blob BLOB NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS subscriptions (\
                        channel_id BINARY(16) NOT NULL,\
                        device_id BINARY(32) NOT NULL,\
                        PRIMARY KEY (channel_id, device_id),\
                        INDEX subscriptions_device_idx (device_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_head (\
                        event_id VARCHAR(128) PRIMARY KEY,\
                        thing_id VARCHAR(128),\
                        state VARCHAR(32) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level VARCHAR(32),\
                        ttl BIGINT,\
                        attrs_json TEXT,\
                        meta_json TEXT\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS event_log (\
                        log_id VARCHAR(64) PRIMARY KEY,\
                        event_id VARCHAR(128) NOT NULL,\
                        thing_id VARCHAR(128),\
                        action VARCHAR(32) NOT NULL,\
                        state VARCHAR(32) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        received_at BIGINT NOT NULL,\
                        applied BIGINT NOT NULL,\
                        title TEXT,\
                        body TEXT,\
                        level VARCHAR(32),\
                        ttl BIGINT,\
                        attrs_json TEXT,\
                        meta_json TEXT,\
                        INDEX event_log_event_time_idx (event_id, event_time)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_head (\
                        thing_id VARCHAR(128) PRIMARY KEY,\
                        state VARCHAR(32) NOT NULL,\
                        attrs_json TEXT NOT NULL,\
                        meta_json TEXT,\
                        updated_at BIGINT NOT NULL,\
                        latest_event_id VARCHAR(128),\
                        latest_event_time BIGINT\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS thing_event_link (\
                        thing_id VARCHAR(128) NOT NULL,\
                        event_id VARCHAR(128) NOT NULL,\
                        event_time BIGINT NOT NULL,\
                        PRIMARY KEY (thing_id, event_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
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
                    "CREATE TABLE IF NOT EXISTS private_subscriptions (\
                        channel_id BINARY(16) NOT NULL,\
                        device_id BINARY(16) NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        PRIMARY KEY (channel_id, device_id),\
                        INDEX private_subscriptions_device_idx (device_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS private_messages (\
                        delivery_id VARCHAR(128) PRIMARY KEY,\
                        payload_blob BLOB NOT NULL,\
                        size INT NOT NULL,\
                        sent_at BIGINT NOT NULL,\
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
                        next_attempt_at BIGINT NOT NULL,\
                        last_error_code VARCHAR(64) NULL,\
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
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS device_registry_v1 (\
                        device_key VARCHAR(255) NOT NULL PRIMARY KEY,\
                        platform VARCHAR(32) NOT NULL,\
                        channel_type VARCHAR(32) NOT NULL,\
                        provider_token TEXT NULL,\
                        updated_at BIGINT NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS delivery_dedupe (\
                        dedupe_key VARCHAR(255) NOT NULL,\
                        delivery_id VARCHAR(128) NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        state SMALLINT NOT NULL DEFAULT 1,\
                        PRIMARY KEY (dedupe_key),\
                        INDEX delivery_dedupe_created_idx (created_at)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS semantic_id_dedupe (\
                        dedupe_key VARCHAR(255) NOT NULL,\
                        semantic_id VARCHAR(128) NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        PRIMARY KEY (dedupe_key),\
                        UNIQUE KEY semantic_id_dedupe_semantic_idx (semantic_id),\
                        INDEX semantic_id_dedupe_created_idx (created_at)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                let dedupe_state_col_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.columns \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'delivery_dedupe' \
                       AND column_name = 'state'",
                )
                .fetch_one(pool)
                .await?;
                if dedupe_state_col_count == 0 {
                    sqlx::query(
                        "ALTER TABLE delivery_dedupe \
                         ADD COLUMN state SMALLINT NOT NULL DEFAULT 1",
                    )
                    .execute(pool)
                    .await?;
                }

                // Ensure the device_id index exists even when the table pre-dates this schema.
                let idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'subscriptions' \
                       AND index_name = 'subscriptions_device_idx'",
                )
                .fetch_one(pool)
                .await?;
                if idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX subscriptions_device_idx ON subscriptions (device_id)",
                    )
                    .execute(pool)
                    .await?;
                }
                Self::ensure_schema_version_mysql(pool).await?;
            }
        }
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
                Self::migrate_device_registry_v4_postgres(pool).await?;
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
                Self::migrate_device_registry_v4_mysql(pool).await?;
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

    async fn migrate_device_registry_v4_sqlite(pool: &SqlitePool) -> StoreResult<()> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "CREATE TABLE device_registry_v1_new (\
                device_key TEXT PRIMARY KEY,\
                platform TEXT NOT NULL,\
                channel_type TEXT NOT NULL,\
                provider_token TEXT,\
                updated_at INTEGER NOT NULL\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO device_registry_v1_new (device_key, platform, channel_type, provider_token, updated_at) \
             SELECT device_key, platform, channel_type, provider_token, updated_at FROM device_registry_v1",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE device_registry_v1")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE device_registry_v1_new RENAME TO device_registry_v1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn migrate_device_registry_v4_postgres(pool: &PgPool) -> StoreResult<()> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "CREATE TABLE device_registry_v1_new (\
                device_key VARCHAR(255) PRIMARY KEY,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                provider_token TEXT,\
                updated_at BIGINT NOT NULL\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO device_registry_v1_new (device_key, platform, channel_type, provider_token, updated_at) \
             SELECT device_key, platform, channel_type, provider_token, updated_at FROM device_registry_v1",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE device_registry_v1")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE device_registry_v1_new RENAME TO device_registry_v1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn migrate_device_registry_v4_mysql(pool: &MySqlPool) -> StoreResult<()> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "CREATE TABLE device_registry_v1_new (\
                device_key VARCHAR(255) NOT NULL PRIMARY KEY,\
                platform VARCHAR(32) NOT NULL,\
                channel_type VARCHAR(32) NOT NULL,\
                provider_token TEXT NULL,\
                updated_at BIGINT NOT NULL\
            ) ENGINE=InnoDB",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO device_registry_v1_new (device_key, platform, channel_type, provider_token, updated_at) \
             SELECT device_key, platform, channel_type, provider_token, updated_at FROM device_registry_v1",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE device_registry_v1")
            .execute(&mut *tx)
            .await?;
        sqlx::query("RENAME TABLE device_registry_v1_new TO device_registry_v1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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
        let device_blob = device_info.to_bytes()?;
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
                    "INSERT INTO devices (device_id, device_blob) VALUES ($1, $2) \
                     ON CONFLICT (device_id) DO UPDATE SET device_blob = EXCLUDED.device_blob",
                )
                .bind(&device_id[..])
                .bind(&device_blob)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO subscriptions (channel_id, device_id) VALUES ($1, $2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
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
                    "INSERT INTO devices (device_id, device_blob) VALUES (?, ?) \
                     ON DUPLICATE KEY UPDATE device_blob = VALUES(device_blob)",
                )
                .bind(&device_id[..])
                .bind(&device_blob)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT IGNORE INTO subscriptions (channel_id, device_id) VALUES (?, ?)",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
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
                    "INSERT INTO devices (device_id, device_blob) VALUES (?, ?) \
                     ON CONFLICT (device_id) DO UPDATE SET \
                     device_blob = excluded.device_blob",
                )
                .bind(&device_id[..])
                .bind(&device_blob)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO subscriptions (channel_id, device_id) VALUES (?, ?) \
                     ON CONFLICT (channel_id, device_id) DO NOTHING",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
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
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "DELETE FROM subscriptions WHERE channel_id = $1 AND device_id = $2",
                )
                .bind(&channel_bytes)
                .bind(&device_id[..])
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Mysql(pool) => {
                let result =
                    sqlx::query("DELETE FROM subscriptions WHERE channel_id = ? AND device_id = ?")
                        .bind(&channel_bytes)
                        .bind(&device_id[..])
                        .execute(pool)
                        .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Sqlite(pool) => {
                let result =
                    sqlx::query("DELETE FROM subscriptions WHERE channel_id = ? AND device_id = ?")
                        .bind(&channel_bytes)
                        .bind(&device_id[..])
                        .execute(pool)
                        .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    async fn retire_device_async(
        &self,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let removed = sqlx::query("DELETE FROM subscriptions WHERE device_id = $1")
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
                Ok(removed)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let removed = sqlx::query("DELETE FROM subscriptions WHERE device_id = ?")
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
                Ok(removed)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let removed = sqlx::query("DELETE FROM subscriptions WHERE device_id = ?")
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
        let new_device_blob = new_device_info.to_bytes()?;

        if old_device_id == new_device_id {
            self.device_cache
                .write()
                .insert(new_device_id, new_device_info);
            return Ok(0);
        }

        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO devices (device_id, device_blob) VALUES ($1, $2) \
                     ON CONFLICT (device_id) DO UPDATE SET device_blob = EXCLUDED.device_blob",
                )
                .bind(&new_device_id[..])
                .bind(&new_device_blob)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT INTO subscriptions (channel_id, device_id) \
                     SELECT channel_id, $1 FROM subscriptions WHERE device_id = $2 \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&new_device_id[..])
                .bind(&old_device_id[..])
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM subscriptions WHERE device_id = $1")
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
                Ok(moved)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO devices (device_id, device_blob) VALUES (?, ?) \
                     ON DUPLICATE KEY UPDATE device_blob = VALUES(device_blob)",
                )
                .bind(&new_device_id[..])
                .bind(&new_device_blob)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT IGNORE INTO subscriptions (channel_id, device_id) \
                     SELECT channel_id, ? FROM subscriptions WHERE device_id = ?",
                )
                .bind(&new_device_id[..])
                .bind(&old_device_id[..])
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM subscriptions WHERE device_id = ?")
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
                Ok(moved)
            }
            SqlxBackend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO devices (device_id, device_blob) VALUES (?, ?) \
                     ON CONFLICT (device_id) DO UPDATE SET device_blob = excluded.device_blob",
                )
                .bind(&new_device_id[..])
                .bind(&new_device_blob)
                .execute(&mut *tx)
                .await?;

                let moved = sqlx::query(
                    "INSERT INTO subscriptions (channel_id, device_id) \
                     SELECT channel_id, ? FROM subscriptions WHERE device_id = ? \
                     ON CONFLICT (channel_id, device_id) DO NOTHING",
                )
                .bind(&new_device_id[..])
                .bind(&old_device_id[..])
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize;

                sqlx::query("DELETE FROM subscriptions WHERE device_id = ?")
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
                Ok(moved)
            }
        }
    }

    async fn delete_private_device_state_async(&self, device_id: DeviceId) -> StoreResult<()> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM private_subscriptions WHERE device_id = $1")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = $1")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM private_subscriptions WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM private_subscriptions WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM private_bindings WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?;
            }
        }
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
                        FROM delivery_dedupe \
                        WHERE created_at <= $1 AND state = $2 \
                        ORDER BY created_at ASC \
                        LIMIT $3\
                     ) \
                     DELETE FROM delivery_dedupe d \
                     USING doomed \
                     WHERE d.dedupe_key = doomed.dedupe_key",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_i16())
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM delivery_dedupe \
                            WHERE created_at <= ? AND state = ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_i16())
                .bind(limit)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() as usize)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM delivery_dedupe \
                            WHERE created_at <= ? AND state = ? \
                            ORDER BY created_at ASC \
                            LIMIT ?\
                        ) AS t\
                     )",
                )
                .bind(before_ts)
                .bind(DedupeState::Pending.as_i16())
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
                        FROM semantic_id_dedupe \
                        WHERE created_at <= $1 \
                        ORDER BY created_at ASC \
                        LIMIT $2\
                     ) \
                     DELETE FROM semantic_id_dedupe d \
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
                    "DELETE FROM semantic_id_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM semantic_id_dedupe \
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
                    "DELETE FROM semantic_id_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM semantic_id_dedupe \
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
                        FROM delivery_dedupe \
                        WHERE created_at <= $1 \
                        ORDER BY created_at ASC \
                        LIMIT $2\
                     ) \
                     DELETE FROM delivery_dedupe d \
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
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM delivery_dedupe \
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
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key IN (\
                        SELECT dedupe_key FROM (\
                            SELECT dedupe_key \
                            FROM delivery_dedupe \
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
        let channel_bytes = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query("SELECT alias FROM channels WHERE channel_id = $1")
                    .bind(&channel_bytes)
                    .fetch_optional(pool)
                    .await?;
                match row {
                    Some(row) => {
                        let alias: String = row.try_get("alias")?;
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
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
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
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
                        Ok(Some(ChannelInfo { alias }))
                    }
                    None => Ok(None),
                }
            }
        }
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
                Ok(SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                })
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
                Ok(SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                })
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
                Ok(SubscribeOutcome {
                    channel_id: channel_id_arr,
                    alias: channel_alias,
                    created,
                })
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
                    "INSERT INTO private_subscriptions (channel_id, device_id, created_at) \
                     VALUES ($1, $2, $3) \
                     ON CONFLICT (channel_id, device_id) DO NOTHING",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT IGNORE INTO private_subscriptions (channel_id, device_id, created_at) \
                     VALUES (?, ?, ?)",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_subscriptions (channel_id, device_id, created_at) \
                     VALUES (?, ?, ?) \
                     ON CONFLICT (channel_id, device_id) DO NOTHING",
                )
                .bind(&channel_id)
                .bind(&device_id)
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
                    "DELETE FROM private_subscriptions WHERE channel_id = $1 AND device_id = $2",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM private_subscriptions WHERE channel_id = ? AND device_id = ?",
                )
                .bind(&channel_id)
                .bind(&device_id)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM private_subscriptions WHERE channel_id = ? AND device_id = ?",
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
                    "SELECT device_id FROM private_subscriptions \
                     WHERE channel_id = $1 AND created_at <= $2",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if device_id.len() != 16 {
                        continue;
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    out.push(id);
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id FROM private_subscriptions \
                     WHERE channel_id = ? AND created_at <= ?",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if device_id.len() != 16 {
                        continue;
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    out.push(id);
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id FROM private_subscriptions \
                     WHERE channel_id = ? AND created_at <= ?",
                )
                .bind(&channel_id)
                .bind(subscribed_at_or_before)
                .fetch_all(pool)
                .await?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    if device_id.len() != 16 {
                        continue;
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    out.push(id);
                }
                Ok(out)
            }
        }
    }

    async fn load_event_head_async(&self, event_id: &str) -> StoreResult<Option<EventHead>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        event_id, thing_id, state, event_time, updated_at, \
                        title, body, level, ttl, attrs_json, meta_json \
                     FROM event_head WHERE event_id = $1",
                )
                .bind(event_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(EventHead {
                    event_id: row.try_get("event_id")?,
                    thing_id: row.try_get("thing_id")?,
                    state: parse_event_state(&row.try_get::<String, _>("state")?)?,
                    event_time: row.try_get("event_time")?,
                    updated_at: row.try_get("updated_at")?,
                    title: row.try_get("title")?,
                    body: row.try_get("body")?,
                    level: row.try_get("level")?,
                    ttl: row.try_get("ttl")?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                }))
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        event_id, thing_id, state, event_time, updated_at, \
                        title, body, level, ttl, attrs_json, meta_json \
                     FROM event_head WHERE event_id = ?",
                )
                .bind(event_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(EventHead {
                    event_id: row.try_get("event_id")?,
                    thing_id: row.try_get("thing_id")?,
                    state: parse_event_state(&row.try_get::<String, _>("state")?)?,
                    event_time: row.try_get("event_time")?,
                    updated_at: row.try_get("updated_at")?,
                    title: row.try_get("title")?,
                    body: row.try_get("body")?,
                    level: row.try_get("level")?,
                    ttl: row.try_get("ttl")?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                }))
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        event_id, thing_id, state, event_time, updated_at, \
                        title, body, level, ttl, attrs_json, meta_json \
                     FROM event_head WHERE event_id = ?",
                )
                .bind(event_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(EventHead {
                    event_id: row.try_get("event_id")?,
                    thing_id: row.try_get("thing_id")?,
                    state: parse_event_state(&row.try_get::<String, _>("state")?)?,
                    event_time: row.try_get("event_time")?,
                    updated_at: row.try_get("updated_at")?,
                    title: row.try_get("title")?,
                    body: row.try_get("body")?,
                    level: row.try_get("level")?,
                    ttl: row.try_get("ttl")?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                }))
            }
        }
    }

    async fn upsert_event_head_async(&self, head: &EventHead) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO event_head \
                    (event_id, thing_id, state, event_time, updated_at, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                    ON CONFLICT (event_id) DO UPDATE SET \
                        thing_id = EXCLUDED.thing_id, \
                        state = EXCLUDED.state, \
                        event_time = EXCLUDED.event_time, \
                        updated_at = EXCLUDED.updated_at, \
                        title = EXCLUDED.title, \
                        body = EXCLUDED.body, \
                        level = EXCLUDED.level, \
                        ttl = EXCLUDED.ttl, \
                        attrs_json = EXCLUDED.attrs_json, \
                        meta_json = EXCLUDED.meta_json",
                )
                .bind(&head.event_id)
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(head.event_time)
                .bind(head.updated_at)
                .bind(&head.title)
                .bind(&head.body)
                .bind(&head.level)
                .bind(head.ttl)
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO event_head \
                    (event_id, thing_id, state, event_time, updated_at, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                    ON DUPLICATE KEY UPDATE \
                        thing_id = VALUES(thing_id), \
                        state = VALUES(state), \
                        event_time = VALUES(event_time), \
                        updated_at = VALUES(updated_at), \
                        title = VALUES(title), \
                        body = VALUES(body), \
                        level = VALUES(level), \
                        ttl = VALUES(ttl), \
                        attrs_json = VALUES(attrs_json), \
                        meta_json = VALUES(meta_json)",
                )
                .bind(&head.event_id)
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(head.event_time)
                .bind(head.updated_at)
                .bind(&head.title)
                .bind(&head.body)
                .bind(&head.level)
                .bind(head.ttl)
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO event_head \
                    (event_id, thing_id, state, event_time, updated_at, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                    ON CONFLICT (event_id) DO UPDATE SET \
                        thing_id = excluded.thing_id, \
                        state = excluded.state, \
                        event_time = excluded.event_time, \
                        updated_at = excluded.updated_at, \
                        title = excluded.title, \
                        body = excluded.body, \
                        level = excluded.level, \
                        ttl = excluded.ttl, \
                        attrs_json = excluded.attrs_json, \
                        meta_json = excluded.meta_json",
                )
                .bind(&head.event_id)
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(head.event_time)
                .bind(head.updated_at)
                .bind(&head.title)
                .bind(&head.body)
                .bind(&head.level)
                .bind(head.ttl)
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn append_event_log_async(&self, entry: &EventLogEntry) -> StoreResult<()> {
        let log_id = encode_lower_hex_128(&random_id_bytes_128());
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO event_log \
                    (log_id, event_id, thing_id, action, state, event_time, received_at, applied, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                )
                .bind(log_id)
                .bind(&entry.event_id)
                .bind(&entry.thing_id)
                .bind(entry.action.as_api_str())
                .bind(entry.state.as_api_str())
                .bind(entry.event_time)
                .bind(entry.received_at)
                .bind(if entry.applied { 1i64 } else { 0i64 })
                .bind(&entry.title)
                .bind(&entry.body)
                .bind(&entry.level)
                .bind(entry.ttl)
                .bind(&entry.attrs_json)
                .bind(&entry.meta_json)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO event_log \
                    (log_id, event_id, thing_id, action, state, event_time, received_at, applied, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(log_id)
                .bind(&entry.event_id)
                .bind(&entry.thing_id)
                .bind(entry.action.as_api_str())
                .bind(entry.state.as_api_str())
                .bind(entry.event_time)
                .bind(entry.received_at)
                .bind(if entry.applied { 1i64 } else { 0i64 })
                .bind(&entry.title)
                .bind(&entry.body)
                .bind(&entry.level)
                .bind(entry.ttl)
                .bind(&entry.attrs_json)
                .bind(&entry.meta_json)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO event_log \
                    (log_id, event_id, thing_id, action, state, event_time, received_at, applied, title, body, level, ttl, attrs_json, meta_json) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(log_id)
                .bind(&entry.event_id)
                .bind(&entry.thing_id)
                .bind(entry.action.as_api_str())
                .bind(entry.state.as_api_str())
                .bind(entry.event_time)
                .bind(entry.received_at)
                .bind(if entry.applied { 1i64 } else { 0i64 })
                .bind(&entry.title)
                .bind(&entry.body)
                .bind(&entry.level)
                .bind(entry.ttl)
                .bind(&entry.attrs_json)
                .bind(&entry.meta_json)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn load_thing_head_async(&self, thing_id: &str) -> StoreResult<Option<ThingHead>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time \
                     FROM thing_head WHERE thing_id = $1",
                )
                .bind(thing_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(ThingHead {
                    thing_id: row.try_get("thing_id")?,
                    state: parse_thing_state(&row.try_get::<String, _>("state")?)?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                    updated_at: row.try_get("updated_at")?,
                    latest_event_id: row.try_get("latest_event_id")?,
                    latest_event_time: row.try_get("latest_event_time")?,
                }))
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time \
                     FROM thing_head WHERE thing_id = ?",
                )
                .bind(thing_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(ThingHead {
                    thing_id: row.try_get("thing_id")?,
                    state: parse_thing_state(&row.try_get::<String, _>("state")?)?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                    updated_at: row.try_get("updated_at")?,
                    latest_event_id: row.try_get("latest_event_id")?,
                    latest_event_time: row.try_get("latest_event_time")?,
                }))
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT \
                        thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time \
                     FROM thing_head WHERE thing_id = ?",
                )
                .bind(thing_id)
                .fetch_optional(pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                Ok(Some(ThingHead {
                    thing_id: row.try_get("thing_id")?,
                    state: parse_thing_state(&row.try_get::<String, _>("state")?)?,
                    attrs_json: row.try_get("attrs_json")?,
                    meta_json: row.try_get("meta_json")?,
                    updated_at: row.try_get("updated_at")?,
                    latest_event_id: row.try_get("latest_event_id")?,
                    latest_event_time: row.try_get("latest_event_time")?,
                }))
            }
        }
    }

    async fn upsert_thing_head_async(&self, head: &ThingHead) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO thing_head \
                    (thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time) \
                    VALUES ($1, $2, $3, $4, $5, $6, $7) \
                    ON CONFLICT (thing_id) DO UPDATE SET \
                        state = EXCLUDED.state, \
                        attrs_json = EXCLUDED.attrs_json, \
                        meta_json = EXCLUDED.meta_json, \
                        updated_at = EXCLUDED.updated_at, \
                        latest_event_id = EXCLUDED.latest_event_id, \
                        latest_event_time = EXCLUDED.latest_event_time",
                )
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .bind(head.updated_at)
                .bind(&head.latest_event_id)
                .bind(head.latest_event_time)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO thing_head \
                    (thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time) \
                    VALUES (?, ?, ?, ?, ?, ?, ?) \
                    ON DUPLICATE KEY UPDATE \
                        state = VALUES(state), \
                        attrs_json = VALUES(attrs_json), \
                        meta_json = VALUES(meta_json), \
                        updated_at = VALUES(updated_at), \
                        latest_event_id = VALUES(latest_event_id), \
                        latest_event_time = VALUES(latest_event_time)",
                )
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .bind(head.updated_at)
                .bind(&head.latest_event_id)
                .bind(head.latest_event_time)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO thing_head \
                    (thing_id, state, attrs_json, meta_json, updated_at, latest_event_id, latest_event_time) \
                    VALUES (?, ?, ?, ?, ?, ?, ?) \
                    ON CONFLICT (thing_id) DO UPDATE SET \
                        state = excluded.state, \
                        attrs_json = excluded.attrs_json, \
                        meta_json = excluded.meta_json, \
                        updated_at = excluded.updated_at, \
                        latest_event_id = excluded.latest_event_id, \
                        latest_event_time = excluded.latest_event_time",
                )
                .bind(&head.thing_id)
                .bind(head.state.as_api_str())
                .bind(&head.attrs_json)
                .bind(&head.meta_json)
                .bind(head.updated_at)
                .bind(&head.latest_event_id)
                .bind(head.latest_event_time)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn link_event_thing_async(
        &self,
        thing_id: &str,
        event_id: &str,
        event_time: i64,
    ) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO thing_event_link (thing_id, event_id, event_time) \
                     VALUES ($1, $2, $3) \
                     ON CONFLICT (thing_id, event_id) DO UPDATE SET \
                        event_time = EXCLUDED.event_time",
                )
                .bind(thing_id)
                .bind(event_id)
                .bind(event_time)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO thing_event_link (thing_id, event_id, event_time) \
                     VALUES (?, ?, ?) \
                     ON DUPLICATE KEY UPDATE event_time = VALUES(event_time)",
                )
                .bind(thing_id)
                .bind(event_id)
                .bind(event_time)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO thing_event_link (thing_id, event_id, event_time) \
                     VALUES (?, ?, ?) \
                     ON CONFLICT (thing_id, event_id) DO UPDATE SET event_time = excluded.event_time",
                )
                .bind(thing_id)
                .bind(event_id)
                .bind(event_time)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn list_channel_devices_async(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<DeviceInfo>> {
        let channel_bytes = channel_id.to_vec();
        let rows: Vec<(Vec<u8>, Vec<u8>)> = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.device_blob \
                     FROM subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = $1",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let blob: Vec<u8> = row.try_get("device_blob")?;
                    output.push((device_id, blob));
                }
                output
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.device_blob \
                     FROM subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = ?",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let blob: Vec<u8> = row.try_get("device_blob")?;
                    output.push((device_id, blob));
                }
                output
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT d.device_id, d.device_blob \
                     FROM subscriptions s \
                     JOIN devices d ON s.device_id = d.device_id \
                     WHERE s.channel_id = ?",
                )
                .bind(&channel_bytes)
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    let device_id: Vec<u8> = row.try_get("device_id")?;
                    let blob: Vec<u8> = row.try_get("device_blob")?;
                    output.push((device_id, blob));
                }
                output
            }
        };

        let mut devices = Vec::with_capacity(rows.len());
        for (device_id, blob) in rows {
            let info = DeviceInfo::from_bytes(&blob)?;
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
        Ok(devices)
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
                    if device_id.len() != 16 {
                        return Ok(None);
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    Ok(Some(id))
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
                    if device_id.len() != 16 {
                        return Ok(None);
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    Ok(Some(id))
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
                    if device_id.len() != 16 {
                        return Ok(None);
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&device_id);
                    Ok(Some(id))
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

    async fn load_device_registry_routes_async(&self) -> StoreResult<Vec<DeviceRegistryRoute>> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, updated_at \
                     FROM device_registry_v1",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRegistryRoute {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(output)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, updated_at \
                     FROM device_registry_v1",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRegistryRoute {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(output)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_key, platform, channel_type, provider_token, updated_at \
                     FROM device_registry_v1",
                )
                .fetch_all(pool)
                .await?;
                let mut output = Vec::with_capacity(rows.len());
                for row in rows {
                    output.push(DeviceRegistryRoute {
                        device_key: row.try_get("device_key")?,
                        platform: row.try_get("platform")?,
                        channel_type: row.try_get("channel_type")?,
                        provider_token: row.try_get("provider_token")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(output)
            }
        }
    }

    async fn upsert_device_registry_route_async(
        &self,
        route: &DeviceRegistryRoute,
    ) -> StoreResult<()> {
        let provider_token = route.provider_token.as_deref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO device_registry_v1 \
                     (device_key, platform, channel_type, provider_token, updated_at) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (device_key) DO UPDATE SET \
                       platform = EXCLUDED.platform, \
                       channel_type = EXCLUDED.channel_type, \
                       provider_token = EXCLUDED.provider_token, \
                       updated_at = EXCLUDED.updated_at",
                )
                .bind(route.device_key.trim())
                .bind(route.platform.trim())
                .bind(route.channel_type.trim())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO device_registry_v1 \
                     (device_key, platform, channel_type, provider_token, updated_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       platform = VALUES(platform), \
                       channel_type = VALUES(channel_type), \
                       provider_token = VALUES(provider_token), \
                       updated_at = VALUES(updated_at)",
                )
                .bind(route.device_key.trim())
                .bind(route.platform.trim())
                .bind(route.channel_type.trim())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO device_registry_v1 \
                     (device_key, platform, channel_type, provider_token, updated_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON CONFLICT (device_key) DO UPDATE SET \
                       platform = excluded.platform, \
                       channel_type = excluded.channel_type, \
                       provider_token = excluded.provider_token, \
                       updated_at = excluded.updated_at",
                )
                .bind(route.device_key.trim())
                .bind(route.platform.trim())
                .bind(route.channel_type.trim())
                .bind(provider_token.as_deref())
                .bind(route.updated_at)
                .execute(pool)
                .await?;
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
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO private_messages (delivery_id, payload_blob, size, sent_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                       payload_blob = EXCLUDED.payload_blob, \
                       size = EXCLUDED.size, \
                       sent_at = EXCLUDED.sent_at, \
                       expires_at = EXCLUDED.expires_at",
                )
                .bind(delivery_id)
                .bind(&message.payload)
                .bind(size)
                .bind(sent_at)
                .bind(expires_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO private_messages (delivery_id, payload_blob, size, sent_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                       payload_blob = VALUES(payload_blob), \
                       size = VALUES(size), \
                       sent_at = VALUES(sent_at), \
                       expires_at = VALUES(expires_at)",
                )
                .bind(delivery_id)
                .bind(&message.payload)
                .bind(size)
                .bind(sent_at)
                .bind(expires_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_messages (delivery_id, payload_blob, size, sent_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON CONFLICT (delivery_id) DO UPDATE SET \
                       payload_blob = excluded.payload_blob, \
                       size = excluded.size, \
                       sent_at = excluded.sent_at, \
                       expires_at = excluded.expires_at",
                )
                .bind(delivery_id)
                .bind(&message.payload)
                .bind(size)
                .bind(sent_at)
                .bind(expires_at)
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
        let next_attempt_at = entry.next_attempt_at;
        let updated_at = entry.updated_at;
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                         status = EXCLUDED.status, \
                         attempts = EXCLUDED.attempts, \
                         next_attempt_at = EXCLUDED.next_attempt_at, \
                         last_error_code = EXCLUDED.last_error_code, \
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?) \
                     ON DUPLICATE KEY UPDATE \
                         status = VALUES(status), \
                         attempts = VALUES(attempts), \
                         next_attempt_at = VALUES(next_attempt_at), \
                         last_error_code = VALUES(last_error_code), \
                         updated_at = VALUES(updated_at)",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO private_outbox (device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
                         status = excluded.status, \
                         attempts = excluded.attempts, \
                         next_attempt_at = excluded.next_attempt_at, \
                         last_error_code = excluded.last_error_code, \
                         updated_at = excluded.updated_at",
                )
                .bind(&device_id)
                .bind(&entry.delivery_id)
                .bind(&entry.status)
                .bind(attempts)
                .bind(next_attempt_at)
                .bind(entry.last_error_code.as_deref())
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
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox WHERE device_id = $1 AND status IN ($2, $3, $4) \
                     ORDER BY next_attempt_at ASC LIMIT $5",
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
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
                     ORDER BY next_attempt_at ASC LIMIT ?",
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
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
                        updated_at: row.try_get("updated_at")?,
                    });
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox WHERE device_id = ? AND status IN (?, ?, ?) \
                     ORDER BY next_attempt_at ASC LIMIT ?",
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
                        next_attempt_at: row.try_get("next_attempt_at")?,
                        last_error_code: row.try_get("last_error_code")?,
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
                    "SELECT delivery_id FROM private_messages \
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
                    sqlx::query("DELETE FROM private_messages WHERE delivery_id = $1")
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
                     LEFT JOIN private_messages m ON m.delivery_id = o.delivery_id \
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
                    "SELECT delivery_id FROM private_messages \
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
                    sqlx::query("DELETE FROM private_messages WHERE delivery_id = ?")
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
                     LEFT JOIN private_messages m ON m.delivery_id = o.delivery_id \
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
                    "SELECT delivery_id FROM private_messages \
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
                    sqlx::query("DELETE FROM private_messages WHERE delivery_id = ?")
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
                     LEFT JOIN private_messages m ON m.delivery_id = o.delivery_id \
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
                    "SELECT payload_blob, size, sent_at, expires_at \
                     FROM private_messages WHERE delivery_id = $1",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT payload_blob, size, sent_at, expires_at \
                     FROM private_messages WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT payload_blob, size, sent_at, expires_at \
                     FROM private_messages WHERE delivery_id = ?",
                )
                .bind(delivery_id)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => Ok(Some(PrivateMessage {
                        payload: row.try_get("payload_blob")?,
                        size: row.try_get::<i32, _>("size")? as usize,
                        sent_at: row.try_get("sent_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })),
                    None => Ok(None),
                }
            }
        }
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
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
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
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
                    updated_at: row.try_get("updated_at")?,
                }))
            }
            SqlxBackend::Mysql(pool) => {
                let row = sqlx::query(
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
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
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
                    updated_at: row.try_get("updated_at")?,
                }))
            }
            SqlxBackend::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
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
                    next_attempt_at: row.try_get("next_attempt_at")?,
                    last_error_code: row.try_get("last_error_code")?,
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
                    "INSERT INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES ($1, $2, $3, 1) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(created_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "INSERT IGNORE INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES (?, ?, ?, 1)",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(created_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "INSERT INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES (?, ?, ?, 1) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
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
                    "INSERT INTO semantic_id_dedupe (dedupe_key, semantic_id, created_at) \
                     VALUES ($1, $2, $3) \
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
                    "SELECT semantic_id FROM semantic_id_dedupe WHERE dedupe_key = $1",
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
                    "INSERT IGNORE INTO semantic_id_dedupe (dedupe_key, semantic_id, created_at) \
                     VALUES (?, ?, ?)",
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
                    "SELECT semantic_id FROM semantic_id_dedupe WHERE dedupe_key = ?",
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
                    "INSERT INTO semantic_id_dedupe (dedupe_key, semantic_id, created_at) \
                     VALUES (?, ?, ?) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
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
                    "SELECT semantic_id FROM semantic_id_dedupe WHERE dedupe_key = ?",
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
                    "INSERT INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(created_at)
                .bind(DedupeState::Pending.as_i16())
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM delivery_dedupe WHERE dedupe_key = $1 FOR UPDATE",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: i16 = row.try_get("state")?;
                        match DedupeState::from_i16(state)? {
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
                    "INSERT IGNORE INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(created_at)
                .bind(DedupeState::Pending.as_i16())
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM delivery_dedupe WHERE dedupe_key = ? FOR UPDATE",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: i16 = row.try_get("state")?;
                        match DedupeState::from_i16(state)? {
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
                    "INSERT INTO delivery_dedupe (dedupe_key, delivery_id, created_at, state) \
                     VALUES (?, ?, ?, ?) \
                     ON CONFLICT (dedupe_key) DO NOTHING",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(created_at)
                .bind(DedupeState::Pending.as_i16())
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
                let outcome = if inserted {
                    OpDedupeReservation::Reserved
                } else {
                    let existing = sqlx::query(
                        "SELECT delivery_id, state FROM delivery_dedupe WHERE dedupe_key = ?",
                    )
                    .bind(dedupe_key)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(row) = existing {
                        let existing_delivery_id: String = row.try_get("delivery_id")?;
                        let state: i16 = row.try_get("state")?;
                        match DedupeState::from_i16(state)? {
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
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let result = sqlx::query(
                    "UPDATE delivery_dedupe \
                     SET state = $1 \
                     WHERE dedupe_key = $2 AND delivery_id = $3 AND state = $4",
                )
                .bind(DedupeState::Sent.as_i16())
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Mysql(pool) => {
                let result = sqlx::query(
                    "UPDATE delivery_dedupe \
                     SET state = ? \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(DedupeState::Sent.as_i16())
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
                .execute(pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            SqlxBackend::Sqlite(pool) => {
                let result = sqlx::query(
                    "UPDATE delivery_dedupe \
                     SET state = ? \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(DedupeState::Sent.as_i16())
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
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
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key = $1 AND delivery_id = $2 AND state = $3",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
                .execute(pool)
                .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query(
                    "DELETE FROM delivery_dedupe \
                     WHERE dedupe_key = ? AND delivery_id = ? AND state = ?",
                )
                .bind(dedupe_key)
                .bind(delivery_id)
                .bind(DedupeState::Pending.as_i16())
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
                    "SELECT device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox \
                     WHERE next_attempt_at <= $1 AND status IN ($2, $3, $4) \
                     ORDER BY next_attempt_at ASC \
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
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY next_attempt_at ASC \
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
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY next_attempt_at ASC \
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
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
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
                        ORDER BY next_attempt_at ASC \
                        LIMIT $5 \
                        FOR UPDATE SKIP LOCKED \
                     ) \
                     UPDATE private_outbox o \
                     SET status = $6, next_attempt_at = $7, updated_at = $7, last_error_code = NULL \
                     FROM candidates c \
                     WHERE o.device_id = c.device_id AND o.delivery_id = c.delivery_id \
                     RETURNING o.device_id, o.delivery_id, o.status, o.attempts, o.next_attempt_at, o.last_error_code, o.updated_at",
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
                            next_attempt_at: row.try_get("next_attempt_at")?,
                            last_error_code: row.try_get("last_error_code")?,
                            updated_at: row.try_get("updated_at")?,
                        },
                    ));
                }
                Ok(out)
            }
            SqlxBackend::Mysql(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY next_attempt_at ASC \
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
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
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
                            next_attempt_at: claim_until_ts,
                            last_error_code: None,
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
                    "SELECT device_id, delivery_id, status, attempts, next_attempt_at, last_error_code, updated_at \
                     FROM private_outbox \
                     WHERE status IN (?, ?, ?) AND next_attempt_at <= ? \
                     ORDER BY next_attempt_at ASC \
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
                    let updated = sqlx::query(
                        "UPDATE private_outbox \
                         SET status = ?, next_attempt_at = ?, updated_at = ?, last_error_code = NULL \
                         WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?) AND next_attempt_at <= ?",
                    )
                    .bind(OUTBOX_STATUS_CLAIMED)
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
                            next_attempt_at: claim_until_ts,
                            last_error_code: None,
                            updated_at: claim_until_ts,
                        },
                    ));
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
                     SET status = $3, attempts = attempts + 1, next_attempt_at = $4, updated_at = $4, last_error_code = NULL \
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
                     SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ?, last_error_code = NULL \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_SENT)
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
                     SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ?, last_error_code = NULL \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_SENT)
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
                     SET status = $3, attempts = attempts + 1, next_attempt_at = $4, updated_at = $4, last_error_code = $5 \
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
                     SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ?, last_error_code = ? \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(at_ts)
                .bind(at_ts)
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
                     SET status = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ?, last_error_code = ? \
                     WHERE device_id = ? AND delivery_id = ? AND status IN (?, ?, ?)",
                )
                .bind(OUTBOX_STATUS_PENDING)
                .bind(at_ts)
                .bind(at_ts)
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
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ? AND delivery_id = ?")
                    .bind(&device_id)
                    .bind(delivery_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn clear_private_outbox_for_device_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<usize> {
        let device_id = device_id.to_vec();
        let removed = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
                    .bind(&device_id)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
            SqlxBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                    .bind(&device_id)
                    .execute(pool)
                    .await?
                    .rows_affected() as usize
            }
        };
        Ok(removed)
    }

    async fn clear_private_outbox_for_device_with_entries_async(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        let device_id = device_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT delivery_id FROM private_outbox \
                     WHERE device_id = $1 \
                     ORDER BY updated_at ASC, delivery_id ASC \
                     FOR UPDATE",
                )
                .bind(&device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = $1")
                        .bind(&device_id)
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
                .bind(&device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                        .bind(&device_id)
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
                .bind(&device_id)
                .fetch_all(&mut *tx)
                .await?;
                let delivery_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.try_get("delivery_id"))
                    .collect::<Result<_, sqlx::Error>>()?;
                if !delivery_ids.is_empty() {
                    sqlx::query("DELETE FROM private_outbox WHERE device_id = ?")
                        .bind(&device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(delivery_ids)
            }
        }
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
                        sqlx::query_scalar("SELECT COUNT(1) FROM subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM delivery_dedupe WHERE state = $1")
                            .bind(DedupeState::Pending.as_i16())
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
                        sqlx::query_scalar("SELECT COUNT(1) FROM subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM delivery_dedupe WHERE state = ?")
                            .bind(DedupeState::Pending.as_i16())
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
                        sqlx::query_scalar("SELECT COUNT(1) FROM subscriptions")
                            .fetch_one(pool)
                            .await?;
                    let delivery_dedupe_pending_count =
                        sqlx::query_scalar("SELECT COUNT(1) FROM delivery_dedupe WHERE state = ?")
                            .bind(DedupeState::Pending.as_i16())
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
        let statements: &[&str] = &[
            "DELETE FROM thing_event_link",
            "DELETE FROM event_log",
            "DELETE FROM event_head",
            "DELETE FROM thing_head",
            "DELETE FROM subscriptions",
            "DELETE FROM devices",
            "DELETE FROM channels",
            "DELETE FROM private_bindings",
            "DELETE FROM private_outbox",
            "DELETE FROM private_messages",
            "DELETE FROM private_subscriptions",
            "DELETE FROM private_sessions",
            "DELETE FROM private_device_keys",
            "DELETE FROM device_registry_v1",
            "DELETE FROM delivery_dedupe",
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
fn parse_event_state(raw: &str) -> StoreResult<EventState> {
    let normalized = raw.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "ONGOING" => Ok(EventState::Ongoing),
        "CLOSED" => Ok(EventState::Closed),
        _ => Err(StoreError::BinaryError),
    }
}

fn parse_thing_state(raw: &str) -> StoreResult<ThingState> {
    let normalized = raw.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "ACTIVE" => Ok(ThingState::Active),
        "INACTIVE" => Ok(ThingState::Inactive),
        "DECOMMISSIONED" => Ok(ThingState::Decommissioned),
        _ => Err(StoreError::BinaryError),
    }
}
