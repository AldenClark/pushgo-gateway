use std::sync::Arc;

use tokio::sync::mpsc;

use crate::runtime::types::{AckEvent, FallbackCmd, NotificationIntent, ProviderJob, SessionCmd};

#[derive(Debug, Clone)]
pub struct RuntimeCapacity {
    pub ingress: usize,
    pub planner: usize,
    pub session: usize,
    pub provider: usize,
    pub fallback: usize,
    pub ack: usize,
}

impl RuntimeCapacity {
    pub fn auto() -> Self {
        let cpu = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(4);
        Self {
            ingress: (cpu * 512).clamp(1024, 32768),
            planner: (cpu * 1024).clamp(2048, 65536),
            session: (cpu * 2048).clamp(4096, 131072),
            provider: (cpu * 512).clamp(1024, 32768),
            fallback: (cpu * 1024).clamp(2048, 65536),
            ack: (cpu * 512).clamp(1024, 32768),
        }
    }
}

#[derive(Debug)]
pub struct RuntimeBus {
    pub intent_tx: mpsc::Sender<NotificationIntent>,
    pub plan_tx: mpsc::Sender<NotificationIntent>,
    pub session_tx: mpsc::Sender<SessionCmd>,
    pub provider_tx: mpsc::Sender<ProviderJob>,
    pub fallback_tx: mpsc::Sender<FallbackCmd>,
    pub ack_tx: mpsc::Sender<AckEvent>,
}

pub struct RuntimeReceivers {
    pub intent_rx: mpsc::Receiver<NotificationIntent>,
    pub plan_rx: mpsc::Receiver<NotificationIntent>,
    pub session_rx: mpsc::Receiver<SessionCmd>,
    pub provider_rx: mpsc::Receiver<ProviderJob>,
    pub fallback_rx: mpsc::Receiver<FallbackCmd>,
    pub ack_rx: mpsc::Receiver<AckEvent>,
}

pub fn build_runtime_bus(capacity: RuntimeCapacity) -> (Arc<RuntimeBus>, RuntimeReceivers) {
    let (intent_tx, intent_rx) = mpsc::channel(capacity.ingress);
    let (plan_tx, plan_rx) = mpsc::channel(capacity.planner);
    let (session_tx, session_rx) = mpsc::channel(capacity.session);
    let (provider_tx, provider_rx) = mpsc::channel(capacity.provider);
    let (fallback_tx, fallback_rx) = mpsc::channel(capacity.fallback);
    let (ack_tx, ack_rx) = mpsc::channel(capacity.ack);

    (
        Arc::new(RuntimeBus {
            intent_tx,
            plan_tx,
            session_tx,
            provider_tx,
            fallback_tx,
            ack_tx,
        }),
        RuntimeReceivers {
            intent_rx,
            plan_rx,
            session_rx,
            provider_rx,
            fallback_rx,
            ack_rx,
        },
    )
}
