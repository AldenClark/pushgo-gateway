use serde::{Deserialize, Serialize};

use crate::routing::{DeviceChannelType, DeviceRouteRecord};
use crate::value::{DeviceKeyRef, ProviderTokenRef};

use super::{DeviceId, DeviceInfo, Platform, PrivateDeviceId, StoreError, StoreResult};

pub const SUBSCRIPTION_STATUS_ACTIVE: &str = "active";
pub const SUBSCRIPTION_STATUS_INACTIVE: &str = "inactive";
pub const SUBSCRIPTION_STATUS_FROZEN: &str = "frozen";

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
        let key =
            DeviceKeyRef::parse(&self.device_key).map_err(|_| StoreError::InvalidDeviceToken)?;
        Ok(PrivateDeviceId::derive(key.as_str()).to_vec())
    }

    pub fn persistence_values(&self) -> StoreResult<DeviceRoutePersistenceValues> {
        let channel_type = self.channel_type_kind()?;
        let platform = self.platform_kind()?;
        let provider_token = ProviderTokenRef::optional(self.provider_token.as_deref());
        let device_id = self.device_id_bytes()?;
        if channel_type.is_private() {
            if provider_token.is_some() {
                return Err(StoreError::InvalidDeviceToken);
            }
        } else if !platform.supports_provider_push() {
            return Err(StoreError::InvalidPlatform);
        }
        let device_key =
            DeviceKeyRef::parse(&self.device_key).map_err(|_| StoreError::InvalidDeviceToken)?;
        let (provider_token, token_raw) = if let Some(token) = provider_token {
            let device = DeviceInfo::from_token(platform, token.as_str())?;
            (
                Some(device.token_str().to_string()),
                device.token_raw.to_vec(),
            )
        } else {
            (None, device_key.as_str().as_bytes().to_vec())
        };

        Ok(DeviceRoutePersistenceValues {
            device_id,
            token_raw,
            platform_code: platform.to_byte() as i16,
            device_key: device_key.into_owned(),
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DispatchTarget {
    Provider {
        platform: Platform,
        provider_token: String,
        device_key: String,
        route_updated_at: i64,
    },
    Private {
        device_id: DeviceId,
        device_key: Option<String>,
        platform: Platform,
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

    #[test]
    fn mqtt_private_route_persists_as_device_key_backed_identity() {
        let route = DeviceRouteRecordRow {
            device_key: "mqtt-device-key-1".to_string(),
            platform: "mqtt".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        let values = route
            .persistence_values()
            .expect("mqtt private route should persist");
        assert_eq!(values.platform, "mqtt");
        assert_eq!(values.channel_type, "private");
        assert_eq!(values.token_raw, b"mqtt-device-key-1");
    }

    #[test]
    fn mqtt_provider_route_is_rejected_before_persistence() {
        let route = DeviceRouteRecordRow {
            device_key: "mqtt-device-key-1".to_string(),
            platform: "mqtt".to_string(),
            channel_type: "apns".to_string(),
            provider_token: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            ),
            updated_at: 1,
        };
        assert!(
            route.persistence_values().is_err(),
            "mqtt must not be persisted as a provider push route"
        );
    }

    #[test]
    fn provider_route_persists_platform_canonical_token() {
        let apple_upper = "A1".repeat(32);
        let apple = DeviceRouteRecordRow {
            device_key: "apple-device-key".to_string(),
            platform: "ios".to_string(),
            channel_type: "apns".to_string(),
            provider_token: Some(apple_upper),
            updated_at: 1,
        }
        .persistence_values()
        .expect("valid APNs route");
        assert_eq!(
            apple.provider_token.as_deref(),
            Some("a1".repeat(32).as_str())
        );

        let fcm_token = "AbCdEfGhIjKlMnOp";
        let android = DeviceRouteRecordRow {
            device_key: "android-device-key".to_string(),
            platform: "android".to_string(),
            channel_type: "fcm".to_string(),
            provider_token: Some(fcm_token.to_string()),
            updated_at: 1,
        }
        .persistence_values()
        .expect("valid FCM route");
        assert_eq!(android.provider_token.as_deref(), Some(fcm_token));
    }
}
