use serde::{Deserialize, Serialize};

use crate::routing::{DeviceChannelType, DeviceRouteRecord};

use super::{
    DeviceId, DeviceInfo, Platform, PrivateDeviceId, ProviderTokenSnapshot, StoreError, StoreResult,
};

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
        if self.channel_type_kind()?.is_private() {
            let key = self.device_key.trim();
            if key.is_empty() {
                return Err(StoreError::InvalidDeviceToken);
            }
            return Ok(PrivateDeviceId::derive(key).to_vec());
        }

        let platform = self.platform_kind()?;
        let token = self
            .provider_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(StoreError::InvalidDeviceToken)?;
        let device = DeviceInfo::from_token(platform, token)?;
        Ok(device.device_id().to_vec())
    }

    pub fn snapshot_fields(&self) -> RouteSnapshotFields {
        RouteSnapshotFields::from_provider_token(self.provider_token.as_deref())
    }

    pub fn route_snapshot(&self) -> StoreResult<DeviceRouteSnapshot> {
        Ok(DeviceRouteSnapshot {
            device_id: self.device_id_bytes()?,
            device_key: self.device_key.trim().to_string(),
            platform: self.platform_kind()?,
            channel_type: self.channel_type_kind()?,
            provider_token: self
                .provider_token
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
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
pub struct DeviceRouteSnapshot {
    pub device_id: Vec<u8>,
    pub device_key: String,
    pub platform: Platform,
    pub channel_type: RouteChannelType,
    pub provider_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    Provider {
        platform: Platform,
        provider_token: String,
        device_key: Option<String>,
    },
    Private {
        device_id: DeviceId,
        device_key: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSnapshotFields {
    pub token_hash: Option<Vec<u8>>,
    pub token_preview: Option<String>,
}

impl RouteSnapshotFields {
    pub fn from_provider_token(provider_token: Option<&str>) -> Self {
        let snapshot = ProviderTokenSnapshot::from_option(provider_token);
        Self {
            token_hash: snapshot.hash().map(ToOwned::to_owned),
            token_preview: snapshot.preview().map(ToOwned::to_owned),
        }
    }

    pub fn into_parts(self) -> (Option<Vec<u8>>, Option<String>) {
        (self.token_hash, self.token_preview)
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::{DeviceChannelType, DeviceRouteRecord};

    use super::{DeviceRouteRecordRow, RouteChannelType, RouteSnapshotFields};

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
    fn route_snapshot_fields_trim_empty_provider_token() {
        let empty = RouteSnapshotFields::from_provider_token(Some("   "));
        assert!(empty.token_hash.is_none());
        assert!(empty.token_preview.is_none());

        let populated = RouteSnapshotFields::from_provider_token(Some("abcdef123456"));
        assert!(populated.token_hash.is_some());
        assert_eq!(populated.token_preview.as_deref(), Some("abcdef***3456"));
    }

    #[test]
    fn route_snapshot_uses_typed_platform_and_channel() {
        let row = DeviceRouteRecordRow::from_registry_record(
            "device-key-1",
            &DeviceRouteRecord {
                platform: crate::storage::Platform::ANDROID,
                channel_type: DeviceChannelType::Fcm,
                provider_token: Some("android-token-1234".to_string()),
                updated_at: 1,
            },
        );
        let snapshot = row.route_snapshot().expect("snapshot should build");
        assert_eq!(snapshot.platform, crate::storage::Platform::ANDROID);
        assert_eq!(snapshot.channel_type, RouteChannelType::Fcm);
        assert_eq!(
            snapshot.provider_token.as_deref(),
            Some("android-token-1234")
        );
    }

    #[test]
    fn route_snapshot_rejects_invalid_platform_and_channel_type() {
        let invalid_platform = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "not-a-platform".to_string(),
            channel_type: "private".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        assert!(invalid_platform.route_snapshot().is_err());

        let invalid_channel = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "android".to_string(),
            channel_type: "not-a-channel".to_string(),
            provider_token: None,
            updated_at: 1,
        };
        assert!(invalid_channel.route_snapshot().is_err());
    }

    #[test]
    fn provider_route_requires_non_empty_provider_token() {
        let route = DeviceRouteRecordRow {
            device_key: "device-key-1".to_string(),
            platform: "android".to_string(),
            channel_type: "fcm".to_string(),
            provider_token: Some("   ".to_string()),
            updated_at: 1,
        };
        assert!(route.device_id_bytes().is_err());
        assert!(route.route_snapshot().is_err());
    }
}
