use serde::{Deserialize, Serialize};

use crate::routing::{DeviceChannelType, DeviceRouteRecord};

use super::{DeviceId, DeviceInfo, Platform, PrivateDeviceId, StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteChannelType {
    Private,
    Apns,
    Fcm,
    Wns,
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
pub struct DeviceRoutePersistenceValues {
    pub device_id: Vec<u8>,
    pub token_raw: Vec<u8>,
    pub platform_code: i16,
    pub device_key: String,
    pub platform: String,
    pub channel_type: String,
    pub provider_token: Option<String>,
    pub updated_at: i64,
}

impl DeviceRouteRecordRow {
    pub fn from_registry_record(device_key: &str, route: &DeviceRouteRecord) -> Self {
        Self {
            device_key: device_key.to_string(),
            platform: route.platform.name().to_string(),
            channel_type: RouteChannelType::from(route.channel_type)
                .as_str()
                .to_string(),
            provider_token: route.provider_token.clone(),
            updated_at: route.updated_at,
        }
    }

    pub fn platform_kind(&self) -> StoreResult<Platform> {
        self.platform.parse()
    }

    pub fn channel_type_kind(&self) -> StoreResult<RouteChannelType> {
        RouteChannelType::parse(&self.channel_type)
    }

    pub fn device_id_bytes(&self) -> StoreResult<Vec<u8>> {
        let _ = self.channel_type_kind()?;
        let key = self.device_key.trim();
        if key.is_empty() {
            return Err(StoreError::InvalidDeviceToken);
        }
        Ok(PrivateDeviceId::derive(key).to_vec())
    }

    pub fn persistence_values(&self) -> StoreResult<DeviceRoutePersistenceValues> {
        let provider_token = self.provider_token.as_deref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let device_id = self.device_id_bytes()?;
        let platform = self.platform_kind()?;
        let token_raw = if let Some(token) = provider_token.as_deref() {
            DeviceInfo::from_token(platform, token)?.token_raw.to_vec()
        } else {
            self.device_key.trim().as_bytes().to_vec()
        };

        Ok(DeviceRoutePersistenceValues {
            device_id,
            token_raw,
            platform_code: platform.to_byte() as i16,
            device_key: self.device_key.trim().to_string(),
            platform: self.platform.trim().to_ascii_lowercase(),
            channel_type: self.channel_type.trim().to_ascii_lowercase(),
            provider_token,
            updated_at: self.updated_at,
        })
    }
}

impl RouteChannelType {
    pub fn parse(raw: &str) -> StoreResult<Self> {
        match DeviceChannelType::parse(raw) {
            Some(value) => Ok(Self::from(value)),
            None => Err(StoreError::InvalidPlatform),
        }
    }

    pub fn is_private(self) -> bool {
        matches!(self, Self::Private)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Apns => "apns",
            Self::Fcm => "fcm",
            Self::Wns => "wns",
        }
    }
}

impl From<DeviceChannelType> for RouteChannelType {
    fn from(value: DeviceChannelType) -> Self {
        match value {
            DeviceChannelType::Private => Self::Private,
            DeviceChannelType::Apns => Self::Apns,
            DeviceChannelType::Fcm => Self::Fcm,
            DeviceChannelType::Wns => Self::Wns,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    Provider {
        platform: Platform,
        provider_token: String,
        device_key: String,
    },
    Private {
        device_id: DeviceId,
        device_key: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::DeviceRouteRecordRow;

    #[test]
    fn private_route_device_id_uses_device_key() {
        let route = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "android".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        let device_id = route
            .device_id_bytes()
            .expect("private route should derive device id");
        assert_eq!(device_id.len(), 16);
    }

    #[test]
    fn route_row_rejects_invalid_platform_and_channel_type() {
        let invalid_platform = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "not-a-platform".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        assert!(invalid_platform.platform_kind().is_err());

        let invalid_channel = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "android".to_string(),
            channel_type: "not-a-channel".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        assert!(invalid_channel.channel_type_kind().is_err());
    }
}
