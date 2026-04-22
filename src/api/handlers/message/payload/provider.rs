use crate::{
    api::Error,
    app::AppState,
    dispatch::{ProviderDeliveryPath, ProviderPullDelivery},
    routing::derive_private_device_id,
    storage::Platform,
};

use super::MAX_PROVIDER_TTL_SECONDS;

const APNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const FCM_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const WNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 5120;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderDeliverySelection {
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
}

pub(crate) struct ProviderRouteBinding {
    pub(crate) provider_device_key: String,
    pub(crate) stats_device_key: ProviderStatsDeviceKey,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderTtl(u32);

pub(crate) struct ProviderStatsDeviceKey(String);

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
    ) -> Result<Self, Error> {
        if !wakeup_pull_available {
            return Err(Error::validation(
                "provider payload exceeds size limit and wakeup path is unavailable",
            ));
        }
        if Self::within_platform_limit(platform, wakeup_len) {
            return Ok(Self {
                initial_path: ProviderDeliveryPath::WakeupPull,
                wakeup_payload_within_limit: true,
            });
        }
        Err(Error::validation("provider payload exceeds size limit"))
    }

    pub(crate) fn resolve(
        platform: Platform,
        direct_len: usize,
        wakeup_len: usize,
        wakeup_pull_available: bool,
    ) -> Result<Self, Error> {
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

impl ProviderRouteBinding {
    pub(crate) fn resolve(
        state: &AppState,
        platform: Platform,
        token: &str,
        dispatch_device_key: &str,
    ) -> Self {
        let provider_device_key = state
            .device_registry
            .resolve_provider_ingress_route(platform, token)
            .unwrap_or_else(|| dispatch_device_key.trim().to_string());
        let stats_device_key = ProviderStatsDeviceKey::resolve(provider_device_key.as_str());
        Self {
            provider_device_key,
            stats_device_key,
        }
    }
}

impl ProviderStatsDeviceKey {
    fn resolve(route_device_key: &str) -> Self {
        let normalized = route_device_key.trim();
        debug_assert!(
            !normalized.is_empty(),
            "provider stats key should be derived from a stable device_key"
        );
        Self(normalized.to_string())
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl ProviderTtl {
    pub(crate) fn remaining(sent_at: i64, expires_at: i64) -> Self {
        let remaining = (expires_at - sent_at).clamp(0, MAX_PROVIDER_TTL_SECONDS);
        Self(remaining as u32)
    }

    pub(crate) fn into_inner(self) -> u32 {
        self.0
    }
}

impl ProviderPullDelivery {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_provider_target(
        provider_device_key: &str,
        platform: Platform,
        provider_token: &str,
        private_payload: &[u8],
        delivery_id: &str,
        sent_at: i64,
        expires_at: i64,
    ) -> Option<Self> {
        let normalized_token = provider_token.trim();
        if normalized_token.is_empty() {
            return None;
        }
        let normalized_device_key = provider_device_key.trim();
        if normalized_device_key.is_empty() {
            return None;
        }
        let device_id = derive_private_device_id(normalized_device_key);
        Some(Self {
            device_id,
            platform,
            provider_token: std::sync::Arc::from(normalized_token.to_string().into_boxed_str()),
            delivery_id: std::sync::Arc::from(delivery_id.to_string().into_boxed_str()),
            payload: std::sync::Arc::new(private_payload.to_owned()),
            sent_at,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dispatch::ProviderPullDelivery;
    use crate::routing::derive_private_device_id;

    use super::{Platform, ProviderDeliverySelection, ProviderStatsDeviceKey, ProviderTtl};

    #[test]
    fn provider_ttl_is_clamped_to_range() {
        assert_eq!(ProviderTtl::remaining(10, 5).into_inner(), 0);
        assert_eq!(
            ProviderTtl::remaining(0, super::MAX_PROVIDER_TTL_SECONDS * 2).into_inner(),
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
        let missing = ProviderPullDelivery::for_provider_target(
            "   ",
            Platform::ANDROID,
            "fcm-token",
            b"payload",
            "delivery-1",
            100,
            200,
        );
        assert!(missing.is_none());

        let present = ProviderPullDelivery::for_provider_target(
            "device-key-1",
            Platform::ANDROID,
            "fcm-token",
            b"payload",
            "delivery-1",
            100,
            200,
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
