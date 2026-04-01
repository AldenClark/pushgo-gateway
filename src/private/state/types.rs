use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrivateAutomationStats {
    pub revoked_device_count: usize,
    pub session_count: usize,
    pub device_bound_session_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RegisterConnectionOutcome {
    pub superseded_conn_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalDeliveryDisposition {
    Acked,
    Dropped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EnqueuePrivateMessageOutcome {
    pub(crate) private_outbox_pruned: usize,
}

#[derive(Debug, Default)]
pub(crate) struct BootstrapQueues {
    pub inflight: VecDeque<(u64, protocol::DeliverEnvelope)>,
    pub pending: VecDeque<protocol::DeliverEnvelope>,
}

#[derive(Debug)]
pub(crate) struct PreparedSessionBootstrap {
    pub resume: ResumeHandshake,
    pub bootstrap: BootstrapQueues,
}

#[derive(Debug, Default)]
pub(crate) struct RetransmitPollResult {
    pub exhausted_count: usize,
    pub outbound: Option<(u64, protocol::DeliverEnvelope)>,
}
