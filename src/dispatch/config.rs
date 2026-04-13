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

#[cfg(test)]
mod tests {
    use super::DispatchRuntimeConfig;

    #[test]
    fn dispatch_runtime_config_clamps_values() {
        assert_eq!(DispatchRuntimeConfig::clamp_worker_count(9_999), 256);
        assert_eq!(DispatchRuntimeConfig::clamp_queue_capacity(1), 256);
    }
}
