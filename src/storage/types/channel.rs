use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use super::{StoreError, StoreResult};

pub const STORAGE_SCHEMA_VERSION: &str = "2026-04-22-gateway-v9";
pub const STORAGE_SCHEMA_VERSION_MIGRATABLE: &str = "2026-04-17-gateway-v8";
pub const STORAGE_SCHEMA_VERSION_PREVIOUS: &str = "2026-04-16-gateway-v7";
pub const STORAGE_SCHEMA_VERSION_LEGACY: &str = "2026-04-13-gateway-v6";
pub const STORAGE_SCHEMA_VERSION_OLDER_LEGACY: &str = "2026-03-26-gateway-v5";
pub const STORAGE_SCHEMA_VERSION_OLDEST_LEGACY: &str = "2026-03-18-gateway-v4";
const BLAKE3_PASSWORD_SCHEME: &str = "pushgo-blake3";
const BLAKE3_PASSWORD_VERSION: &str = "v=1";
const BLAKE3_PASSWORD_SALT_BYTES: usize = 16;
const BLAKE3_PASSWORD_DIGEST_BYTES: usize = blake3::OUT_LEN;
const BLAKE3_PASSWORD_DOMAIN: &[u8] = b"pushgo.gateway.channel.password.v1";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelPasswordVerifyOutcome {
    Verified,
    VerifiedNeedsUpgrade,
}

impl ChannelPasswordVerifyOutcome {
    pub fn needs_upgrade(self) -> bool {
        matches!(self, Self::VerifiedNeedsUpgrade)
    }
}

pub fn verify_channel_password(
    password_hash: &str,
    password: &str,
) -> StoreResult<ChannelPasswordVerifyOutcome> {
    if password_hash.starts_with('$')
        && password_hash
            .split('$')
            .nth(1)
            .is_some_and(|scheme| scheme == BLAKE3_PASSWORD_SCHEME)
    {
        verify_blake3_password(password_hash, password)?;
        return Ok(ChannelPasswordVerifyOutcome::Verified);
    }

    let parsed = PasswordHash::new(password_hash)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| StoreError::ChannelPasswordMismatch)?;
    Ok(ChannelPasswordVerifyOutcome::VerifiedNeedsUpgrade)
}

pub fn hash_channel_password(password: &str) -> StoreResult<String> {
    let mut salt = [0u8; BLAKE3_PASSWORD_SALT_BYTES];
    rand::rng().fill(&mut salt);
    let digest = blake3_password_digest(&salt, password);
    Ok(format!(
        "${}${}${}${}",
        BLAKE3_PASSWORD_SCHEME,
        BLAKE3_PASSWORD_VERSION,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(digest)
    ))
}

pub fn hash_channel_password_argon2(password: &str) -> StoreResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_blake3_password(password_hash: &str, password: &str) -> StoreResult<()> {
    let mut parts = password_hash.split('$');
    let _leading = parts.next();
    let scheme = parts
        .next()
        .ok_or_else(|| StoreError::PasswordHash("missing password hash scheme".to_string()))?;
    if scheme != BLAKE3_PASSWORD_SCHEME {
        return Err(StoreError::PasswordHash(format!(
            "unsupported password hash scheme: {scheme}"
        )));
    }
    let version = parts
        .next()
        .ok_or_else(|| StoreError::PasswordHash("missing password hash version".to_string()))?;
    if version != BLAKE3_PASSWORD_VERSION {
        return Err(StoreError::PasswordHash(format!(
            "unsupported password hash version: {version}"
        )));
    }
    let salt_b64 = parts
        .next()
        .ok_or_else(|| StoreError::PasswordHash("missing password salt".to_string()))?;
    let digest_b64 = parts
        .next()
        .ok_or_else(|| StoreError::PasswordHash("missing password digest".to_string()))?;
    if parts.next().is_some() {
        return Err(StoreError::PasswordHash(
            "invalid password hash format".to_string(),
        ));
    }

    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64)
        .map_err(|err| StoreError::PasswordHash(format!("invalid password salt: {err}")))?;
    if salt.len() != BLAKE3_PASSWORD_SALT_BYTES {
        return Err(StoreError::PasswordHash(format!(
            "invalid password salt length: {}",
            salt.len()
        )));
    }

    let expected_digest = URL_SAFE_NO_PAD
        .decode(digest_b64)
        .map_err(|err| StoreError::PasswordHash(format!("invalid password digest: {err}")))?;
    if expected_digest.len() != BLAKE3_PASSWORD_DIGEST_BYTES {
        return Err(StoreError::PasswordHash(format!(
            "invalid password digest length: {}",
            expected_digest.len()
        )));
    }

    let actual_digest = blake3_password_digest(salt.as_slice(), password);
    if expected_digest.as_slice() != actual_digest.as_slice() {
        return Err(StoreError::ChannelPasswordMismatch);
    }
    Ok(())
}

fn blake3_password_digest(salt: &[u8], password: &str) -> [u8; BLAKE3_PASSWORD_DIGEST_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BLAKE3_PASSWORD_DOMAIN);
    hasher.update(&(salt.len() as u64).to_le_bytes());
    hasher.update(salt);
    hasher.update(password.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_roundtrip_and_no_upgrade() {
        let password = "pass-123";
        let hash = hash_channel_password(password).expect("hash");
        let outcome = verify_channel_password(&hash, password).expect("verify");
        assert_eq!(outcome, ChannelPasswordVerifyOutcome::Verified);
    }

    #[test]
    fn argon2_compatible_and_requests_upgrade() {
        let password = "pass-argon2";
        let hash = hash_channel_password_argon2(password).expect("argon2 hash");
        let outcome = verify_channel_password(&hash, password).expect("verify");
        assert_eq!(outcome, ChannelPasswordVerifyOutcome::VerifiedNeedsUpgrade);
    }
}
