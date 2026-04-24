use std::sync::Arc;

use hashbrown::HashMap;

use crate::{
    app::AppState,
    stats::{DeviceDispatchDelta, DispatchStatsEvent},
};

const PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT: usize = 50;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_FLOOR: usize = 2;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_CEIL: usize = 16;

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct PrivateEnqueueStats {
    pub attempted: usize,
    failed: usize,
    too_busy_failed: usize,
}

impl PrivateEnqueueStats {
    pub(super) fn record_success(&mut self) {
        self.attempted = self.attempted.saturating_add(1);
    }

    pub(super) fn record_failure(
        &mut self,
        _stage: &str,
        _device_id: [u8; 16],
        error: &crate::Error,
    ) {
        self.attempted = self.attempted.saturating_add(1);
        self.failed = self.failed.saturating_add(1);
        if matches!(error, crate::Error::TooBusy) {
            self.too_busy_failed = self.too_busy_failed.saturating_add(1);
        }
    }

    pub(super) fn has_failures(self) -> bool {
        self.failed > 0
    }

    pub(super) fn is_too_busy(self) -> bool {
        if self.attempted == 0 || self.too_busy_failed == 0 {
            return false;
        }
        let dynamic_min_failed = (self.attempted / 4).clamp(
            PRIVATE_ENQUEUE_TOO_BUSY_MIN_FLOOR,
            PRIVATE_ENQUEUE_TOO_BUSY_MIN_CEIL,
        );
        self.too_busy_failed >= dynamic_min_failed
            && self.too_busy_failed * 100
                >= self.attempted * PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT
    }
}

pub(super) fn merge_device_dispatch_delta(
    aggregates: &mut HashMap<Arc<str>, DeviceDispatchDelta>,
    device_key: Arc<str>,
    delta: DeviceDispatchDelta,
) {
    let entry = aggregates.entry(device_key).or_default();
    entry.messages_received += delta.messages_received;
    entry.messages_acked += delta.messages_acked;
    entry.private_connected_count += delta.private_connected_count;
    entry.private_pull_count += delta.private_pull_count;
    entry.provider_success_count += delta.provider_success_count;
    entry.provider_failure_count += delta.provider_failure_count;
    entry.private_outbox_enqueued_count += delta.private_outbox_enqueued_count;
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_dispatch_stats(
    state: &AppState,
    channel_id: [u8; 16],
    occurred_at: i64,
    messages_routed: i64,
    deliveries_attempted: i64,
    provider_attempted: i64,
    provider_success: i64,
    provider_failed: i64,
    private_realtime_delivered: i64,
    device_stats: HashMap<Arc<str>, DeviceDispatchDelta>,
) {
    let active_private_sessions_max = state
        .private
        .as_ref()
        .map(|private| private.automation_stats().session_count as i64)
        .unwrap_or(0);

    state.stats.record_dispatch(DispatchStatsEvent {
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
            .map(|(device_key, delta)| DeviceDispatchDelta {
                device_key: device_key.to_string(),
                ..delta
            })
            .collect(),
    });
}

#[cfg(test)]
mod tests {
    use super::PrivateEnqueueStats;

    #[test]
    fn too_busy_threshold_ignores_non_too_busy_failures() {
        let mut stats = PrivateEnqueueStats::default();
        for _ in 0..8 {
            stats.record_failure(
                "private.enqueue",
                [0; 16],
                &crate::Error::Internal("io".into()),
            );
        }
        assert!(stats.has_failures());
        assert!(
            !stats.is_too_busy(),
            "non-TooBusy failures must not trigger too-busy safety threshold"
        );
    }

    #[test]
    fn too_busy_threshold_tracks_too_busy_ratio() {
        let mut stats = PrivateEnqueueStats::default();
        for _ in 0..4 {
            stats.record_failure("private.enqueue", [1; 16], &crate::Error::TooBusy);
        }
        for _ in 0..4 {
            stats.record_success();
        }
        assert!(stats.is_too_busy());
    }
}
