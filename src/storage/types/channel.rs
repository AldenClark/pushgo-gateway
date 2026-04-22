use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use serde::{Deserialize, Serialize};

use super::{StoreError, StoreResult};

pub const STORAGE_SCHEMA_VERSION: &str = "2026-04-22-gateway-v9";
pub const STORAGE_SCHEMA_VERSION_MIGRATABLE: &str = "2026-04-17-gateway-v8";
pub const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-04-16-gateway-v7";
pub const STORAGE_SCHEMA_VERSION_LEGACY: &str = "2026-04-13-gateway-v6";
pub const STORAGE_SCHEMA_VERSION_OLDER_LEGACY: &str = "2026-03-26-gateway-v5";
pub const STORAGE_SCHEMA_VERSION_OLDEST_LEGACY: &str = "2026-03-18-gateway-v4";

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

pub fn verify_channel_password(password_hash: &str, password: &str) -> StoreResult<()> {
    let parsed = PasswordHash::new(password_hash)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| StoreError::ChannelPasswordMismatch)
}

pub fn hash_channel_password(password: &str) -> StoreResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}
