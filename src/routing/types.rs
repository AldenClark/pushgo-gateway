use serde::{Deserialize, Serialize};

use crate::storage::{Platform, PrivateDeviceId};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceChannelType {
    Apns,
    Fcm,
    Wns,
    Private,
}

impl DeviceChannelType {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceChannelType::Apns => "apns",
            DeviceChannelType::Fcm => "fcm",
            DeviceChannelType::Wns => "wns",
            DeviceChannelType::Private => "private",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("apns") {
            Some(DeviceChannelType::Apns)
        } else if trimmed.eq_ignore_ascii_case("fcm") {
            Some(DeviceChannelType::Fcm)
        } else if trimmed.eq_ignore_ascii_case("wns") {
            Some(DeviceChannelType::Wns)
        } else if trimmed.eq_ignore_ascii_case("private") {
            Some(DeviceChannelType::Private)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRouteRecord {
    pub platform: Platform,
    pub channel_type: DeviceChannelType,
    pub provider_token: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistryStats {
    pub total_devices: usize,
    pub ios_devices: usize,
    pub macos_devices: usize,
    pub watchos_devices: usize,
    pub android_devices: usize,
    pub windows_devices: usize,
    pub provider_routes: usize,
}

impl DeviceRouteRecord {
    pub(crate) fn normalized(mut self) -> Self {
        self.provider_token = normalize_provider_token(self.provider_token);
        self
    }
}

pub(crate) fn default_route_for_platform(platform: Platform, updated_at: i64) -> DeviceRouteRecord {
    DeviceRouteRecord {
        platform,
        channel_type: DeviceChannelType::Private,
        provider_token: None,
        updated_at,
    }
}

pub(crate) fn normalize_provider_token(provider_token: Option<String>) -> Option<String> {
    provider_token.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub(crate) fn derive_private_device_id(device_key: &str) -> [u8; 16] {
    PrivateDeviceId::derive(device_key).into_inner()
}
