use crate::runtime_config::GatewayRuntimeProfile;
use crate::storage::{
    cache::{CacheAccess, CacheMemorySnapshot, CacheStore},
    database::DatabaseDriver,
    types::*,
};
use std::sync::Arc;

#[path = "storage/channels.rs"]
mod channels;
#[path = "storage/dedupe.rs"]
mod dedupe;
#[path = "storage/private_capacity_recovery.rs"]
mod private_capacity_recovery;
#[path = "storage/private_delivery.rs"]
mod private_delivery;
#[path = "storage/provider_dispatch.rs"]
mod provider_dispatch;
#[path = "storage/system.rs"]
mod system;

const OP_DEDUPE_PENDING_STALE_MILLIS: i64 = 2 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<DatabaseDriver>,
    cache: Arc<CacheStore>,
    channel_password_gate: Arc<channels::ChannelPasswordGate>,
    private_capacity_recovery: Arc<private_capacity_recovery::PrivateCapacityRecovery>,
    /// Single-instance linearization gate for hard-cap admission and delivery
    /// terminality. Database transactions remain the durable boundary; this
    /// closes COUNT/INSERT and ACK/replay races between concurrent request
    /// tasks in the currently supported one-process deployment model.
    durable_write_gate: Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    provider_finalize_failures_remaining: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    live_activity_enqueue_failures_remaining: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    submission_release_failures_remaining: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct StorageInitConfig {
    pub db_url: Option<String>,
    pub runtime_profile: GatewayRuntimeProfile,
    pub mcp_enabled: bool,
    pub managed_upgrade: bool,
}

impl Default for StorageInitConfig {
    fn default() -> Self {
        Self {
            db_url: None,
            runtime_profile: GatewayRuntimeProfile::Small,
            mcp_enabled: false,
            managed_upgrade: true,
        }
    }
}

impl Storage {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        Self::new_with_config(StorageInitConfig {
            db_url: db_url.map(str::to_string),
            mcp_enabled: true,
            ..StorageInitConfig::default()
        })
        .await
    }

    pub async fn new_with_config(config: StorageInitConfig) -> StoreResult<Self> {
        let runtime_profile = config.runtime_profile;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.init_started"
        );
        if config.managed_upgrade {
            crate::storage::database::upgrade::UpgradeManager::new(config.clone())
                .run(crate::storage::database::upgrade::UpgradeMode::Execute)
                .await
                .map_err(|err| StoreError::Upgrade(err.to_string()))?;
        }
        let mut driver_config = config;
        driver_config.managed_upgrade = false;
        let driver = DatabaseDriver::new_with_config(driver_config)
            .await
            .inspect_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "storage.init_failed",
                    error = %(err.to_string())
                );
            })?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "storage.init_finished"
        );
        Ok(Self {
            db: Arc::new(driver),
            cache: Arc::new(CacheStore::with_profile(runtime_profile)),
            channel_password_gate: Arc::new(channels::ChannelPasswordGate::new()),
            private_capacity_recovery: Arc::new(
                private_capacity_recovery::PrivateCapacityRecovery::default(),
            ),
            durable_write_gate: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            provider_finalize_failures_remaining: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            live_activity_enqueue_failures_remaining: Arc::new(
                std::sync::atomic::AtomicUsize::new(0),
            ),
            #[cfg(test)]
            submission_release_failures_remaining: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub fn cache_memory_snapshot(&self) -> CacheMemorySnapshot {
        self.cache.memory_snapshot()
    }

    #[cfg(test)]
    pub(crate) fn reset_channel_password_kdf_runs(&self) {
        self.channel_password_gate.reset_kdf_runs();
    }

    #[cfg(test)]
    pub(crate) fn channel_password_kdf_runs(&self) -> usize {
        self.channel_password_gate.kdf_runs()
    }

    #[cfg(test)]
    pub(crate) fn inject_provider_finalize_failures(&self, count: usize) {
        self.provider_finalize_failures_remaining
            .store(count, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn consume_provider_finalize_failure(&self) -> bool {
        self.provider_finalize_failures_remaining
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn provider_finalize_failures_remaining(&self) -> usize {
        self.provider_finalize_failures_remaining
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn inject_live_activity_enqueue_failures(&self, count: usize) {
        self.live_activity_enqueue_failures_remaining
            .store(count, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    fn consume_live_activity_enqueue_failure(&self) -> bool {
        self.live_activity_enqueue_failures_remaining
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn inject_submission_release_failures(&self, count: usize) {
        self.submission_release_failures_remaining
            .store(count, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    fn consume_submission_release_failure(&self) -> bool {
        self.submission_release_failures_remaining
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
    }
}

#[cfg(test)]
#[path = "storage/tests/mod.rs"]
mod tests;
