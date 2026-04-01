use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DispatchRuntimeConfig {
    pub(super) worker_count: usize,
    pub(super) queue_capacity: usize,
}

impl DispatchRuntimeConfig {
    pub(super) fn clamp_worker_count(value: usize) -> usize {
        value.clamp(2, 256)
    }

    fn default_worker_count() -> usize {
        let cpu = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        (cpu * 2).clamp(4, 64)
    }

    pub(super) fn clamp_queue_capacity(value: usize) -> usize {
        value.clamp(256, 131_072)
    }

    pub(super) fn from_env() -> Self {
        let worker_count = std::env::var("PUSHGO_DISPATCH_WORKER_COUNT")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .map(Self::clamp_worker_count)
            .unwrap_or_else(Self::default_worker_count);
        let queue_capacity = std::env::var("PUSHGO_DISPATCH_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .map(Self::clamp_queue_capacity)
            .unwrap_or((worker_count * 64).clamp(1024, 32_768));
        Self {
            worker_count,
            queue_capacity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProviderPullRetryConfig {
    pub(super) poll_ms: u64,
    pub(super) batch_size: usize,
    pub(super) timeout_secs: u64,
}

impl ProviderPullRetryConfig {
    pub(super) fn clamp_poll_ms(value: u64) -> u64 {
        value.clamp(200, 5_000)
    }

    pub(super) fn clamp_batch_size(value: usize) -> usize {
        value.clamp(1, 2_000)
    }

    pub(super) fn clamp_timeout_secs(value: u64) -> u64 {
        value.clamp(5, 600)
    }

    pub(super) fn from_env() -> Self {
        Self {
            poll_ms: std::env::var("PUSHGO_PROVIDER_PULL_RETRY_POLL_MS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Self::clamp_poll_ms)
                .unwrap_or(1_000),
            batch_size: std::env::var("PUSHGO_PROVIDER_PULL_RETRY_BATCH")
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .map(Self::clamp_batch_size)
                .unwrap_or(200),
            timeout_secs: std::env::var("PUSHGO_PROVIDER_PULL_RETRY_TIMEOUT_SECS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Self::clamp_timeout_secs)
                .unwrap_or(30),
        }
    }

    pub(super) fn poll_interval(self) -> Duration {
        Duration::from_millis(self.poll_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::DispatchRuntimeConfig;

    #[test]
    fn dispatch_runtime_config_clamps_values() {
        assert_eq!(DispatchRuntimeConfig::clamp_worker_count(9_999), 256);
        assert_eq!(DispatchRuntimeConfig::clamp_queue_capacity(1), 256);
    }
}
