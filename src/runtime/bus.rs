use std::sync::Arc;

use flume::{Receiver, Sender};

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
    pub intent_tx: Sender<NotificationIntent>,
    pub plan_tx: Sender<NotificationIntent>,
    pub session_tx: Sender<SessionCmd>,
    pub provider_tx: Sender<ProviderJob>,
    pub fallback_tx: Sender<FallbackCmd>,
    pub ack_tx: Sender<AckEvent>,
}

pub struct RuntimeReceivers {
    pub intent_rx: Receiver<NotificationIntent>,
    pub plan_rx: Receiver<NotificationIntent>,
    pub session_rx: Receiver<SessionCmd>,
    pub provider_rx: Receiver<ProviderJob>,
    pub fallback_rx: Receiver<FallbackCmd>,
    pub ack_rx: Receiver<AckEvent>,
}

pub fn build_runtime_bus(capacity: RuntimeCapacity) -> (Arc<RuntimeBus>, RuntimeReceivers) {
    let (intent_tx, intent_rx) = flume::bounded(capacity.ingress);
    let (plan_tx, plan_rx) = flume::bounded(capacity.planner);
    let (session_tx, session_rx) = flume::bounded(capacity.session);
    let (provider_tx, provider_rx) = flume::bounded(capacity.provider);
    let (fallback_tx, fallback_rx) = flume::bounded(capacity.fallback);
    let (ack_tx, ack_rx) = flume::bounded(capacity.ack);

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
