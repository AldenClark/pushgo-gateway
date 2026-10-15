use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Android,
    Ios,
    Macos,
    /// Ordinary Windows Private receiver; WNS is outside this candidate.
    Windows,
    /// Ordinary MQTT Private receiver; never a push Provider target.
    Mqtt,
}
impl Platform {
    pub fn name(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Mqtt => "mqtt",
        }
    }
    pub fn provider_name(self) -> &'static str {
        match self {
            Self::Android => "FCM",
            Self::Ios | Self::Macos => "APNS",
            Self::Windows | Self::Mqtt => "PRIVATE",
        }
    }
}
impl FromStr for Platform {
    type Err = String;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "android" => Ok(Self::Android),
            "ios" | "ipados" => Ok(Self::Ios),
            "macos" => Ok(Self::Macos),
            "windows" | "win" => Ok(Self::Windows),
            "mqtt" => Ok(Self::Mqtt),
            _ => Err("ordinary Android/iOS/macOS/Windows/MQTT only".into()),
        }
    }
}
pub(crate) fn normalize_provider_token(raw: &str, platform: Platform) -> Result<String, String> {
    let value = raw.trim();
    match platform {
        Platform::Android if (16..=4096).contains(&value.len()) => Ok(value.to_owned()),
        Platform::Ios | Platform::Macos
            if (64..=256).contains(&value.len())
                && value.len().is_multiple_of(2)
                && value.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(value.to_ascii_lowercase())
        }
        _ => Err("invalid provider token".into()),
    }
}
pub(crate) fn generate_hex_id_128() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes: [u8; 16] = rand::random();
    let mut id = String::with_capacity(32);
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 15) as usize] as char);
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_is_a_private_receiver_and_never_a_provider_token_platform() {
        for raw in ["windows", "win", " WINDOWS "] {
            let platform = Platform::from_str(raw).unwrap();
            assert_eq!(platform, Platform::Windows);
            assert_eq!(platform.name(), "windows");
            assert_eq!(platform.provider_name(), "PRIVATE");
            assert!(normalize_provider_token(&"a".repeat(64), platform).is_err());
            assert!(
                normalize_provider_token("https://synthetic.invalid/wns-token", platform).is_err()
            );
        }
    }
}
