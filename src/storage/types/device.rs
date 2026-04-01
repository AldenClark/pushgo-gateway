use std::sync::Arc;

use blake3::Hasher;

use super::{Platform, StoreError, StoreResult};

pub const DEVICEINFO_TOKEN_MIN_LEN: usize = 32;
pub const DEVICEINFO_TOKEN_MAX_LEN: usize = 128;
pub const ANDROID_TOKEN_MIN_LEN: usize = 16;
pub const ANDROID_TOKEN_MAX_LEN: usize = 4096;
pub const DEVICEINFO_MAGIC: [u8; 2] = *b"DI";
pub const DEVICEINFO_VERSION: u8 = 1;

pub type DeviceId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivateDeviceId(DeviceId);

impl PrivateDeviceId {
    pub fn derive(device_key: &str) -> Self {
        let hash = blake3::hash(device_key.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash.as_bytes()[..16]);
        Self(out)
    }

    pub fn parse_compat(raw: &[u8]) -> Option<Self> {
        if raw.len() == 16 {
            let mut id = [0u8; 16];
            id.copy_from_slice(raw);
            return Some(Self(id));
        }
        if raw.len() == 32 && raw[16..].iter().all(|b| *b == 0) {
            let mut id = [0u8; 16];
            id.copy_from_slice(&raw[..16]);
            return Some(Self(id));
        }
        None
    }

    pub fn into_inner(self) -> DeviceId {
        self.0
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<PrivateDeviceId> for DeviceId {
    fn from(value: PrivateDeviceId) -> Self {
        value.into_inner()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTokenSnapshot {
    hash: Option<Vec<u8>>,
    preview: Option<String>,
}

impl ProviderTokenSnapshot {
    pub fn from_option(provider_token: Option<&str>) -> Self {
        let token = provider_token
            .map(str::trim)
            .filter(|value| !value.is_empty());
        Self {
            hash: token.map(Self::hash_token),
            preview: token.map(Self::preview_token),
        }
    }

    pub fn from_token(provider_token: &str) -> Self {
        Self::from_option(Some(provider_token))
    }

    pub fn from_device(device: &DeviceInfo) -> Self {
        Self::from_token(device.token_str())
    }

    pub fn hash(&self) -> Option<&[u8]> {
        self.hash.as_deref()
    }

    pub fn preview(&self) -> Option<&str> {
        self.preview.as_deref()
    }

    pub fn into_parts(self) -> (Option<Vec<u8>>, Option<String>) {
        (self.hash, self.preview)
    }

    fn hash_token(token: &str) -> Vec<u8> {
        blake3::hash(token.as_bytes()).as_bytes().to_vec()
    }

    fn preview_token(token: &str) -> String {
        const PREFIX: usize = 6;
        const SUFFIX: usize = 4;
        if token.len() <= PREFIX + SUFFIX + 1 {
            return token.to_string();
        }
        format!("{}***{}", &token[..PREFIX], &token[token.len() - SUFFIX..])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub token_raw: Arc<[u8]>,
    pub token_str: Arc<str>,
    pub platform: Platform,
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
        Ok(Self {
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
        if bytes.len() < 6 || bytes[0..2] != DEVICEINFO_MAGIC || bytes[2] != DEVICEINFO_VERSION {
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

        Self::from_raw(platform, bytes[6..].to_vec())
    }

    #[inline]
    pub fn token_str(&self) -> &str {
        self.token_str.as_ref()
    }

    pub fn device_id(&self) -> [u8; 32] {
        Self::device_id_from_raw(self.platform, &self.token_raw)
    }

    pub fn device_id_from_raw(platform: Platform, token_raw: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&[platform.to_byte()]);
        hasher.update(token_raw);
        *hasher.finalize().as_bytes()
    }

    pub fn token_snapshot(&self) -> ProviderTokenSnapshot {
        ProviderTokenSnapshot::from_device(self)
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

#[cfg(test)]
mod tests {
    use super::{DeviceInfo, Platform, PrivateDeviceId, ProviderTokenSnapshot};

    #[test]
    fn private_device_id_parses_legacy_and_compact_formats() {
        let derived = PrivateDeviceId::derive("device-key-1");
        assert_eq!(
            PrivateDeviceId::parse_compat(&derived.to_vec())
                .expect("compact format should parse")
                .into_inner(),
            derived.into_inner()
        );

        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(&derived.into_inner());
        assert_eq!(
            PrivateDeviceId::parse_compat(&padded)
                .expect("legacy padded format should parse")
                .into_inner(),
            derived.into_inner()
        );
    }

    #[test]
    fn provider_token_snapshot_trims_and_masks_token() {
        let snapshot = ProviderTokenSnapshot::from_option(Some("  abcdef1234567890  "));
        assert!(snapshot.hash().is_some());
        assert_eq!(snapshot.preview(), Some("abcdef***7890"));

        let empty = ProviderTokenSnapshot::from_option(Some("   "));
        assert!(empty.hash().is_none());
        assert!(empty.preview().is_none());
    }

    #[test]
    fn device_info_exposes_stable_snapshot_and_device_id() {
        let token = "android-token-device-info-0001";
        let device = DeviceInfo::from_token(Platform::ANDROID, token)
            .expect("android token should be accepted");
        let snapshot = device.token_snapshot();
        assert!(snapshot.hash().is_some());
        assert_eq!(snapshot.preview(), Some("androi***0001"));
        assert_eq!(
            device.device_id(),
            DeviceInfo::device_id_from_raw(Platform::ANDROID, token.as_bytes())
        );
    }

    #[test]
    fn device_info_binary_roundtrip_and_invalid_header_rejected() {
        let token = "android-token-device-info-0002";
        let original = DeviceInfo::from_token(Platform::ANDROID, token)
            .expect("android token should be accepted");
        let bytes = original.to_bytes().expect("device info should encode");
        let decoded = DeviceInfo::from_bytes(&bytes).expect("device info should decode");
        assert_eq!(decoded.platform, Platform::ANDROID);
        assert_eq!(decoded.token_str(), token);

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(DeviceInfo::from_bytes(&bad_magic).is_err());

        let truncated = &bytes[..bytes.len() - 1];
        assert!(DeviceInfo::from_bytes(truncated).is_err());
    }
}
