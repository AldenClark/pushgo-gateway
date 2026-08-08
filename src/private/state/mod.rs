use super::*;

#[path = "delivery.rs"]
mod delivery;
#[path = "fallback.rs"]
mod fallback;
#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "sessions.rs"]
mod sessions;
#[path = "types.rs"]
mod types;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use types::PrivateAutomationStats;
pub(crate) use types::{
    BootstrapQueues, EnqueuePrivateMessageOutcome, PreparedSessionBootstrap,
    RegisterConnectionOutcome, RetransmitPollResult,
};

pub struct PrivateState {
    pub hub: Arc<PrivateHub>,
    pub config: PrivateConfig,
    pub device_registry: Arc<DeviceRegistry>,
    pub runtime_counters: Arc<RuntimeCounterCollector>,
    pub metrics: Arc<metrics::PrivateMetrics>,
    pub(super) fallback_tasks: Option<Arc<FallbackTaskEngine>>,
    session_coordinator: Arc<InMemoryCoordinator>,
    session_coord_owner: String,
    revoked_devices: RwLock<HashMap<DeviceId, ()>>,
    session_controls: RwLock<HashMap<String, SessionControl>>,
    session_devices: RwLock<HashMap<String, DeviceId>>,
    session_admission: Arc<tokio::sync::Semaphore>,
    handshake_admission: Arc<tokio::sync::Semaphore>,
    runtime_tasks: Mutex<Vec<PrivateRuntimeTask>>,
    shutting_down: AtomicBool,
    shutdown_notify: tokio::sync::Notify,
}

struct PrivateRuntimeTask {
    name: &'static str,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrivateShutdownReport {
    pub joined: usize,
    pub panicked: usize,
    pub aborted: usize,
}
