use crate::{
    delivery_core::error::CoreError,
    routing::derive_private_device_id,
    storage::{DeviceId, Platform},
    value::{DeviceKeyRef, ProviderTokenRef},
};

use super::{MAX_PROVIDER_TTL_MILLIS, MAX_PROVIDER_TTL_SECONDS};

const APNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const FCM_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const WNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 5120;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderDeliverySelection {
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderDeliveryPath {
    Direct,
    WakeupPull,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderTtl(u32);

pub(crate) struct ProviderStatsDeviceKey(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderPullTarget {
    pub(crate) device_id: DeviceId,
    pub(crate) platform: Platform,
    pub(crate) provider_token: String,
    pub(crate) delivery_id: String,
}

impl ProviderDeliverySelection {
    pub(crate) fn within_platform_limit(platform: Platform, len: usize) -> bool {
        let limit = Self::payload_limit_bytes(platform);
        match platform {
            Platform::WINDOWS => len < limit,
            _ => len <= limit,
        }
    }

    pub(crate) fn direct(platform: Platform, direct_len: usize) -> Option<Self> {
        Self::within_platform_limit(platform, direct_len).then_some(Self {
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit: false,
        })
    }

    pub(crate) fn wakeup_pull(
        platform: Platform,
        wakeup_len: usize,
        wakeup_pull_available: bool,
    ) -> Result<Self, CoreError> {
        if !wakeup_pull_available {
            return Err(CoreError::validation_code(
                "provider payload exceeds size limit and wakeup path is unavailable",
                "provider_payload_too_large_no_wakeup",
            ));
        }
        if Self::within_platform_limit(platform, wakeup_len) {
            return Ok(Self {
                initial_path: ProviderDeliveryPath::WakeupPull,
                wakeup_payload_within_limit: true,
            });
        }
        Err(CoreError::validation_code(
            "provider payload exceeds size limit",
            "provider_payload_too_large",
        ))
    }

    pub(crate) fn resolve(
        platform: Platform,
        direct_len: usize,
        wakeup_len: usize,
        wakeup_pull_available: bool,
    ) -> Result<Self, CoreError> {
        Self::direct(platform, direct_len)
            .map(Ok)
            .unwrap_or_else(|| Self::wakeup_pull(platform, wakeup_len, wakeup_pull_available))
    }

    fn payload_limit_bytes(platform: Platform) -> usize {
        match platform {
            Platform::ANDROID => FCM_PROVIDER_PAYLOAD_LIMIT_BYTES,
            Platform::WINDOWS => WNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
            _ => APNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
        }
    }
}

impl ProviderStatsDeviceKey {
    pub(crate) fn resolve(route_device_key: &str) -> Self {
        let normalized = DeviceKeyRef::parse(route_device_key)
            .map(DeviceKeyRef::into_owned)
            .unwrap_or_default();
        debug_assert!(
            !normalized.is_empty(),
            "provider stats key should be derived from a stable device_key"
        );
        Self(normalized)
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl ProviderTtl {
    pub(crate) fn remaining(sent_at: i64, expires_at: i64) -> Self {
        let remaining_millis = (expires_at - sent_at).clamp(0, MAX_PROVIDER_TTL_MILLIS);
        let remaining_secs = (remaining_millis / 1000).clamp(0, MAX_PROVIDER_TTL_SECONDS);
        Self(remaining_secs as u32)
    }

    pub(crate) fn into_inner(self) -> u32 {
        self.0
    }
}

impl ProviderPullTarget {
    pub(crate) fn for_provider_target(
        provider_device_key: &str,
        platform: Platform,
        provider_token: &str,
        delivery_id: &str,
    ) -> Option<Self> {
        let normalized_token = ProviderTokenRef::optional(Some(provider_token))?;
        let normalized_device_key = DeviceKeyRef::optional(Some(provider_device_key))?;
        let device_id = derive_private_device_id(normalized_device_key.as_str());
        Some(Self {
            device_id,
            platform,
            provider_token: normalized_token.into_owned(),
            delivery_id: delivery_id.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::derive_private_device_id;

    use super::{
        Platform, ProviderDeliverySelection, ProviderPullTarget, ProviderStatsDeviceKey,
        ProviderTtl,
    };

    #[test]
    fn provider_ttl_is_clamped_to_range() {
        assert_eq!(ProviderTtl::remaining(10, 5).into_inner(), 0);
        assert_eq!(
            ProviderTtl::remaining(0, super::MAX_PROVIDER_TTL_MILLIS * 2).into_inner(),
            super::MAX_PROVIDER_TTL_SECONDS as u32
        );
    }

    #[test]
    fn windows_payload_limit_is_strictly_less_than_max() {
        assert!(ProviderDeliverySelection::within_platform_limit(
            Platform::WINDOWS,
            5119
        ));
        assert!(!ProviderDeliverySelection::within_platform_limit(
            Platform::WINDOWS,
            5120
        ));
    }

    #[test]
    fn provider_pull_delivery_requires_non_empty_device_key() {
        let missing = ProviderPullTarget::for_provider_target(
            "   ",
            Platform::ANDROID,
            "fcm-token",
            "delivery-1",
        );
        assert!(missing.is_none());

        let present = ProviderPullTarget::for_provider_target(
            "device-key-1",
            Platform::ANDROID,
            "fcm-token",
            "delivery-1",
        )
        .expect("delivery should be built");
        assert_eq!(present.device_id, derive_private_device_id("device-key-1"));
    }

    #[test]
    fn provider_stats_device_key_uses_trimmed_device_key() {
        let key = ProviderStatsDeviceKey::resolve(" provider-route-key ");
        assert_eq!(key.as_str(), "provider-route-key");
    }
}
