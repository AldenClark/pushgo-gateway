use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Android,
    Ios,
    Macos,
    Watchos,
    /// Existing Windows receiver, using WNS or the canonical Private route.
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
            Self::Watchos => "watchos",
            Self::Windows => "windows",
            Self::Mqtt => "mqtt",
        }
    }
    pub fn provider_name(self) -> &'static str {
        match self {
            Self::Android => "FCM",
            Self::Ios | Self::Macos | Self::Watchos => "APNS",
            Self::Windows => "WNS",
            Self::Mqtt => "PRIVATE",
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
            "watchos" => Ok(Self::Watchos),
            "windows" | "win" => Ok(Self::Windows),
            "mqtt" => Ok(Self::Mqtt),
            _ => Err("ordinary Android/iOS/macOS/WatchOS/Windows/MQTT only".into()),
        }
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
