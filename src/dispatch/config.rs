use crate::runtime_config::GatewayRuntimeProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProviderLaneConfig {
    pub(super) minimum: usize,
    pub(super) maximum: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DispatchRuntimeConfig {
    pub(super) queue_capacity: usize,
    pub(super) apns: ProviderLaneConfig,
    pub(super) live_activity: ProviderLaneConfig,
    pub(super) widgets: ProviderLaneConfig,
    pub(super) fcm: ProviderLaneConfig,
    pub(super) wns: ProviderLaneConfig,
}

impl DispatchRuntimeConfig {
    pub(super) fn from_profile(_profile: GatewayRuntimeProfile) -> Self {
        // Provider throughput is independent from storage/cache deployment
        // profiles. Stable tasks sit behind a small adaptive logical limit.
        Self {
            queue_capacity: 1_024,
            apns: ProviderLaneConfig {
                minimum: 2,
                maximum: 64,
            },
            live_activity: ProviderLaneConfig {
                minimum: 1,
                maximum: 8,
            },
            widgets: ProviderLaneConfig {
                minimum: 1,
                maximum: 8,
            },
            fcm: ProviderLaneConfig {
                minimum: 2,
                maximum: 64,
            },
            wns: ProviderLaneConfig {
                minimum: 1,
                maximum: 32,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DispatchRuntimeConfig;
    use crate::runtime_config::GatewayRuntimeProfile;

    #[test]
    fn provider_lanes_are_profile_independent_and_provider_scoped() {
        let small = DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Small);
        let public = DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Public);
        assert_eq!(small, public);
        assert!(small.apns.maximum > small.widgets.maximum);
        assert!(small.apns.maximum > small.live_activity.maximum);
        assert!(small.fcm.maximum > small.wns.maximum);
        assert!(small.apns.minimum < small.apns.maximum);
    }
}
