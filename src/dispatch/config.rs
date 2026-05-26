use crate::runtime_config::GatewayRuntimeProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DispatchRuntimeConfig {
    pub(super) worker_count: usize,
    pub(super) queue_capacity: usize,
}

impl DispatchRuntimeConfig {
    pub(super) fn from_profile(profile: GatewayRuntimeProfile) -> Self {
        let tuning = crate::runtime_config::RuntimeTuning::for_profile(profile).dispatch;
        Self {
            worker_count: tuning.worker_count,
            queue_capacity: tuning.queue_capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DispatchRuntimeConfig;
    use crate::runtime_config::GatewayRuntimeProfile;

    #[test]
    fn dispatch_runtime_config_comes_from_profile() {
        let small = DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Small);
        assert_eq!(small.worker_count, 2);
        assert_eq!(small.queue_capacity, 256);

        let public = DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Public);
        assert!(public.worker_count >= 4);
        assert!(public.queue_capacity >= 2_048);
    }
}
