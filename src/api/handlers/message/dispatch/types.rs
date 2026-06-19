use std::sync::Arc;

use hashbrown::HashMap;

use super::*;
use crate::delivery_core::execution::provider::ResolvedProviderTarget as CoreResolvedProviderTarget;

pub(super) struct ResolvedProviderTarget {
    pub(super) device: DeviceInfo,
    pub(super) device_key: Arc<str>,
    pub(super) provider_stats_key: Arc<str>,
    pub(super) wakeup_data_for_device: Arc<HashMap<String, String>>,
    pub(super) allow_inline: bool,
    pub(super) provider_pull_delivery: Option<ProviderPullDelivery>,
}

impl From<CoreResolvedProviderTarget> for ResolvedProviderTarget {
    fn from(value: CoreResolvedProviderTarget) -> Self {
        Self {
            device: value.device,
            device_key: value.device_key,
            provider_stats_key: value.provider_stats_key,
            wakeup_data_for_device: value.wakeup_data_for_device,
            allow_inline: value.allow_inline,
            provider_pull_delivery: value.provider_pull_target.map(ProviderPullDelivery::from),
        }
    }
}
