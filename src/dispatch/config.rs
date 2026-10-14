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

impl Default for DispatchRuntimeConfig {
    fn default() -> Self {
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
    use super::{DispatchRuntimeConfig, ProviderLaneConfig};

    #[test]
    fn provider_lanes_keep_independent_adaptive_bounds() {
        let config = DispatchRuntimeConfig::default();
        assert_eq!(config.queue_capacity, 1_024);
        assert_eq!(
            config.apns,
            ProviderLaneConfig {
                minimum: 2,
                maximum: 64
            }
        );
        assert_eq!(
            config.live_activity,
            ProviderLaneConfig {
                minimum: 1,
                maximum: 8
            }
        );
        assert_eq!(
            config.widgets,
            ProviderLaneConfig {
                minimum: 1,
                maximum: 8
            }
        );
        assert_eq!(
            config.fcm,
            ProviderLaneConfig {
                minimum: 2,
                maximum: 64
            }
        );
        assert_eq!(
            config.wns,
            ProviderLaneConfig {
                minimum: 1,
                maximum: 32
            }
        );
    }
}
