use crate::{
    api::Error,
    app::AppState,
    dispatch::{ProviderDeliveryPath, ProviderPullDelivery},
    routing::derive_private_device_id,
    storage::{DeliveryAuditPath, Platform},
    util::encode_lower_hex_128,
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
    pub(crate) provider_device_key: Option<String>,
    pub(crate) audit_device_key: ProviderAuditDeviceKey,
}

pub(crate) struct ProviderDeliverySkip;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderTtl(u32);

pub(crate) struct ProviderAuditDeviceKey(String);

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
    pub(crate) fn resolve(state: &AppState, platform: Platform, token: &str) -> Self {
        let provider_device_key = state
            .device_registry
            .resolve_provider_route_by_token(platform, token);
        let audit_device_key =
            ProviderAuditDeviceKey::resolve(provider_device_key.as_deref(), platform, token);
        Self {
            provider_device_key,
            audit_device_key,
        }
    }
}

impl ProviderAuditDeviceKey {
    fn resolve(route_device_key: Option<&str>, platform: Platform, token: &str) -> Self {
        let value = route_device_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                let token_hash = blake3::hash(token.as_bytes());
                let mut short = [0u8; 16];
                short.copy_from_slice(&token_hash.as_bytes()[..16]);
                format!(
                    "provider:{}:{}",
                    platform.name(),
                    encode_lower_hex_128(&short)
                )
            });
        Self(value)
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl ProviderDeliverySkip {
    pub(crate) fn should_skip(
        private_delivery_target: Option<[u8; 16]>,
        private_online: bool,
        private_realtime_delivered: &std::collections::HashSet<[u8; 16]>,
    ) -> bool {
        private_delivery_target.is_some_and(|device_id| {
            private_online && private_realtime_delivered.contains(&device_id)
        })
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

impl ProviderDeliveryPath {
    pub(crate) fn audit_path(self) -> DeliveryAuditPath {
        match self {
            Self::Direct => DeliveryAuditPath::Direct,
            Self::WakeupPull => DeliveryAuditPath::WakeupPull,
        }
    }
}

impl ProviderPullDelivery {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_provider_target(
        provider_device_key: Option<&str>,
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
        let device_id = provider_device_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(derive_private_device_id)
            .unwrap_or_else(|| {
                let token_hash = blake3::hash(normalized_token.as_bytes());
                let mut short = [0u8; 16];
                short.copy_from_slice(&token_hash.as_bytes()[..16]);
                short
            });
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
    use crate::dispatch::ProviderDeliveryPath;
    use crate::storage::DeliveryAuditPath;

    use super::{Platform, ProviderDeliverySelection, ProviderTtl};

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
    fn provider_delivery_path_maps_to_audit_path() {
        assert_eq!(
            ProviderDeliveryPath::Direct.audit_path(),
            DeliveryAuditPath::Direct
        );
        assert_eq!(
            ProviderDeliveryPath::WakeupPull.audit_path(),
            DeliveryAuditPath::WakeupPull
        );
    }
}
