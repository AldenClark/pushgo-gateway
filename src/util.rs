use std::{
    fmt,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
};

use hashbrown::HashMap;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct SharedStringMap(Arc<HashMap<String, String>>);

impl SharedStringMap {
    pub fn as_map(&self) -> &HashMap<String, String> {
        self.0.as_ref()
    }
}

impl From<HashMap<String, String>> for SharedStringMap {
    fn from(value: HashMap<String, String>) -> Self {
        Self(Arc::new(value))
    }
}

impl From<Arc<HashMap<String, String>>> for SharedStringMap {
    fn from(value: Arc<HashMap<String, String>>) -> Self {
        Self(value)
    }
}

impl Serialize for SharedStringMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base32DecodeError {
    InvalidChar { ch: u8, index: usize },
    InvalidLength { expected: usize, actual: usize },
    NonCanonicalTrailingBits,
}

impl fmt::Display for Base32DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base32DecodeError::InvalidChar { ch, index } => {
                write!(f, "invalid base32 char 0x{:02X} at index {}", ch, index)
            }
            Base32DecodeError::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {}, got {}", expected, actual)
            }
            Base32DecodeError::NonCanonicalTrailingBits => {
                write!(f, "non-canonical base32: trailing bits must be zero")
            }
        }
    }
}

impl std::error::Error for Base32DecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexDecodeError {
    InvalidChar { ch: u8, index: usize },
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexDecodeError::InvalidChar { ch, index } => {
                write!(f, "invalid hex char 0x{:02X} at index {}", ch, index)
            }
            HexDecodeError::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for HexDecodeError {}

pub const CROCKFORD_BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const CROCKFORD_128_LEN: usize = 26;
pub const HEX_128_LEN: usize = 32;
const INVALID_BASE32_DIGIT: u8 = 0xFF;
static SANDBOX_MODE: AtomicBool = AtomicBool::new(false);
static DIAGNOSTICS_MODE: AtomicBool = AtomicBool::new(false);

const CROCKFORD_DECODE_LUT: [u8; 256] = build_crockford_decode_lut();

const fn build_crockford_decode_lut() -> [u8; 256] {
    let mut lut = [INVALID_BASE32_DIGIT; 256];
    let mut index = 0usize;
    while index < CROCKFORD_BASE32_ALPHABET.len() {
        let ch = CROCKFORD_BASE32_ALPHABET[index] as usize;
        lut[ch] = index as u8;
        let lower = CROCKFORD_BASE32_ALPHABET[index].to_ascii_lowercase() as usize;
        lut[lower] = index as u8;
        index += 1;
    }
    lut[b'O' as usize] = 0;
    lut[b'o' as usize] = 0;
    lut[b'I' as usize] = 1;
    lut[b'i' as usize] = 1;
    lut[b'L' as usize] = 1;
    lut[b'l' as usize] = 1;
    lut
}

pub fn set_sandbox_mode(enabled: bool) {
    SANDBOX_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_sandbox_mode() -> bool {
    SANDBOX_MODE.load(Ordering::Relaxed)
}

pub fn set_diagnostics_mode(enabled: bool) {
    DIAGNOSTICS_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_diagnostics_mode() -> bool {
    DIAGNOSTICS_MODE.load(Ordering::Relaxed)
}

pub fn diagnostics_log(args: fmt::Arguments<'_>) {
    if is_diagnostics_mode() {
        eprintln!("{args}");
    }
}

pub fn redact_text(value: &str) -> String {
    if is_sandbox_mode() {
        return value.to_string();
    }
    mask_middle(value, 4, 4)
}

pub fn redact_debug<T: ?Sized + fmt::Debug>(value: &T) -> String {
    if is_sandbox_mode() {
        return format!("{value:?}");
    }
    "<redacted>".to_string()
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&lhs, &rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

pub fn build_wakeup_data(base: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in [
        "delivery_id",
        "channel_id",
        "entity_type",
        "entity_id",
        "message_id",
        "event_id",
        "thing_id",
        "op_id",
        "sent_at",
        "ttl",
        "schema_version",
        "payload_version",
    ] {
        if let Some(value) = base.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    out.insert("private_mode".to_string(), "wakeup".to_string());
    out.insert("private_wakeup".to_string(), "1".to_string());
    out.insert("_skip_persist".to_string(), "1".to_string());
    out
}

fn mask_middle(value: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= keep_prefix + keep_suffix {
        return "<redacted>".to_string();
    }
    let prefix: String = chars.iter().take(keep_prefix).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(keep_suffix)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}...{suffix}")
}

#[inline]
pub fn random_id_bytes_128() -> [u8; 16] {
    rand::random()
}

#[inline]
pub fn encode_lower_hex_128_into(data: &[u8; 16], out: &mut [u8; HEX_128_LEN]) {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    while input_index < data.len() {
        let byte = data[input_index];
        out[output_index] = LUT[(byte >> 4) as usize];
        out[output_index + 1] = LUT[(byte & 0x0F) as usize];
        input_index += 1;
        output_index += 2;
    }
}

#[inline]
pub fn encode_lower_hex_128(data: &[u8; 16]) -> String {
    let mut out = [0u8; HEX_128_LEN];
    encode_lower_hex_128_into(data, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
pub fn decode_lower_hex_128(input: &str) -> Result<[u8; 16], HexDecodeError> {
    let bytes = input.as_bytes();
    if bytes.len() != HEX_128_LEN {
        return Err(HexDecodeError::InvalidLength {
            expected: HEX_128_LEN,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; 16];
    let mut index = 0usize;
    while index < 16 {
        let hi = decode_hex_nibble(bytes[index * 2]).ok_or(HexDecodeError::InvalidChar {
            ch: bytes[index * 2],
            index: index * 2,
        })?;
        let lo = decode_hex_nibble(bytes[index * 2 + 1]).ok_or(HexDecodeError::InvalidChar {
            ch: bytes[index * 2 + 1],
            index: index * 2 + 1,
        })?;
        out[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(out)
}

#[inline]
pub fn generate_hex_id_128() -> String {
    let bytes = random_id_bytes_128();
    encode_lower_hex_128(&bytes)
}

#[inline]
pub fn encode_crockford_base32_128_into(data: &[u8; 16], out: &mut [u8; CROCKFORD_128_LEN]) {
    let mut value = u128::from_be_bytes(*data);
    out[CROCKFORD_128_LEN - 1] = CROCKFORD_BASE32_ALPHABET[((value & 0x7) << 2) as usize];
    value >>= 3;

    let mut index = CROCKFORD_128_LEN - 1;
    while index > 0 {
        index -= 1;
        out[index] = CROCKFORD_BASE32_ALPHABET[(value & 0x1F) as usize];
        value >>= 5;
    }
}

#[inline]
fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
pub fn encode_crockford_base32_128(data: &[u8; 16]) -> String {
    let mut out = [0u8; CROCKFORD_128_LEN];
    encode_crockford_base32_128_into(data, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

pub fn decode_crockford_base32_128(input: &str) -> Result<[u8; 16], Base32DecodeError> {
    let mut digits = [0u8; CROCKFORD_128_LEN];
    let mut digit_count = 0usize;
    for (index, b) in input.bytes().enumerate() {
        if b.is_ascii_whitespace() || b == b'-' {
            continue;
        }
        if digit_count == CROCKFORD_128_LEN {
            return Err(Base32DecodeError::InvalidLength {
                expected: CROCKFORD_128_LEN,
                actual: digit_count + 1,
            });
        }
        let value = CROCKFORD_DECODE_LUT[b as usize];
        if value == INVALID_BASE32_DIGIT {
            return Err(Base32DecodeError::InvalidChar { ch: b, index });
        }
        digits[digit_count] = value;
        digit_count += 1;
    }

    if digit_count != CROCKFORD_128_LEN {
        return Err(Base32DecodeError::InvalidLength {
            expected: CROCKFORD_128_LEN,
            actual: digit_count,
        });
    }

    let trailing = digits[CROCKFORD_128_LEN - 1];
    if trailing & 0x03 != 0 {
        return Err(Base32DecodeError::NonCanonicalTrailingBits);
    }

    let mut value = 0u128;
    let mut index = 0usize;
    while index < CROCKFORD_128_LEN - 1 {
        value = (value << 5) | u128::from(digits[index]);
        index += 1;
    }
    value = (value << 3) | u128::from(trailing >> 2);
    Ok(value.to_be_bytes())
}
