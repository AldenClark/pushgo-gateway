use std::sync::Arc;

use hashbrown::HashMap;

use crate::runtime_counters::DeviceRuntimeCounterDelta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCounterEvent {
    SubmitAccepted,
    DeliveryQueued,
    DeliveryFailed,
}

pub(crate) trait RuntimeCounterSink {
    fn record(&self, event: RuntimeCounterEvent);

    #[allow(clippy::too_many_arguments)]
    fn record_dispatch_counters(
        &self,
        _channel_id: [u8; 16],
        _occurred_at: i64,
        _messages_routed: i64,
        _deliveries_attempted: i64,
        _provider_attempted: i64,
        _provider_success: i64,
        _provider_failed: i64,
        _private_realtime_delivered: i64,
        _device_stats: HashMap<Arc<str>, DeviceRuntimeCounterDelta>,
    ) {
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopRuntimeCounterSink;

impl RuntimeCounterSink for NoopRuntimeCounterSink {
    fn record(&self, _event: RuntimeCounterEvent) {}
}
