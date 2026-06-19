use std::sync::Arc;

use hashbrown::HashMap;

use crate::{
    app::AppState,
    runtime_counters::{DeviceRuntimeCounterDelta, DispatchCounterEvent},
};

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_dispatch_counters(
    state: &AppState,
    channel_id: [u8; 16],
    occurred_at: i64,
    messages_routed: i64,
    deliveries_attempted: i64,
    provider_attempted: i64,
    provider_success: i64,
    provider_failed: i64,
    private_realtime_delivered: i64,
    device_stats: HashMap<Arc<str>, DeviceRuntimeCounterDelta>,
) {
    let active_private_sessions_max = state
        .private
        .as_ref()
        .map(|private| private.automation_stats().session_count as i64)
        .unwrap_or(0);

    state
        .runtime_counters
        .record_dispatch(DispatchCounterEvent {
            channel_id,
            occurred_at,
            messages_routed,
            deliveries_attempted,
            deliveries_acked: 0,
            private_enqueued: device_stats
                .values()
                .map(|value| value.private_outbox_enqueued_count)
                .sum(),
            provider_attempted,
            provider_failed,
            provider_success,
            private_realtime_delivered,
            active_private_sessions_max,
            device_deltas: device_stats
                .into_iter()
                .map(|(device_key, delta)| DeviceRuntimeCounterDelta {
                    device_key: device_key.to_string(),
                    ..delta
                })
                .collect(),
        });
}
