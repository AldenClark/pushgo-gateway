use std::sync::Arc;

use hashbrown::HashMap;

use crate::{runtime_counters::DeviceRuntimeCounterDelta, storage::DeviceId};

const PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT: usize = 50;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_FLOOR: usize = 2;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_CEIL: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BusyKind {
    PrivateEnqueueBackpressure,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PrivateEnqueueProgress {
    pub(crate) attempted: usize,
    failed: usize,
    too_busy_failed: usize,
}

impl PrivateEnqueueProgress {
    pub(crate) fn record_success(&mut self) {
        self.attempted = self.attempted.saturating_add(1);
    }

    pub(crate) fn record_failure(
        &mut self,
        _stage: &str,
        _device_id: [u8; 16],
        error: &crate::Error,
    ) {
        self.attempted = self.attempted.saturating_add(1);
        self.failed = self.failed.saturating_add(1);
        if Self::classify_busy(error) == Some(BusyKind::PrivateEnqueueBackpressure) {
            self.too_busy_failed = self.too_busy_failed.saturating_add(1);
        }
    }

    fn classify_busy(error: &crate::Error) -> Option<BusyKind> {
        matches!(error, crate::Error::TooBusy).then_some(BusyKind::PrivateEnqueueBackpressure)
    }

    pub(crate) fn has_failures(self) -> bool {
        self.failed > 0
    }

    pub(crate) fn is_too_busy(self) -> bool {
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

#[derive(Default)]
pub(crate) struct DispatchProgress {
    pub(crate) private_enqueued: hashbrown::HashSet<DeviceId>,
    pub(crate) private_realtime_delivered: hashbrown::HashSet<DeviceId>,
    pub(crate) mqtt_delivered: hashbrown::HashSet<DeviceId>,
    pub(crate) mqtt_failed: usize,
    pub(crate) private_enqueue_stats: PrivateEnqueueProgress,
    pub(crate) provider_attempted: i64,
    pub(crate) provider_queued: i64,
    pub(crate) provider_failed: i64,
    pub(crate) rejected: usize,
    pub(crate) dispatch_closed: bool,
    pub(crate) device_stats: HashMap<Arc<str>, DeviceRuntimeCounterDelta>,
}

impl DispatchProgress {
    pub(crate) fn record_private_success(&mut self, device_id: DeviceId) {
        self.private_enqueued.insert(device_id);
        let private_stats_key = Arc::<str>::from(
            format!("private:{}", crate::util::encode_lower_hex_128(&device_id)).into_boxed_str(),
        );
        merge_device_counter_delta(
            &mut self.device_stats,
            private_stats_key,
            DeviceRuntimeCounterDelta {
                messages_received: 1,
                private_outbox_enqueued_count: 1,
                ..DeviceRuntimeCounterDelta::default()
            },
        );
    }

    pub(crate) fn record_provider_queued(&mut self) {
        self.provider_attempted += 1;
        self.provider_queued += 1;
    }

    pub(crate) fn record_mqtt_success(&mut self, device_id: DeviceId) {
        self.mqtt_delivered.insert(device_id);
        let mqtt_stats_key = Arc::<str>::from(
            format!("mqtt:{}", crate::util::encode_lower_hex_128(&device_id)).into_boxed_str(),
        );
        merge_device_counter_delta(
            &mut self.device_stats,
            mqtt_stats_key,
            DeviceRuntimeCounterDelta {
                messages_received: 1,
                ..DeviceRuntimeCounterDelta::default()
            },
        );
    }

    pub(crate) fn record_mqtt_failure(&mut self) {
        self.rejected = self.rejected.saturating_add(1);
        self.mqtt_failed = self.mqtt_failed.saturating_add(1);
    }

    pub(crate) fn record_provider_failure(&mut self, provider_stats_key: Arc<str>) {
        self.rejected += 1;
        self.provider_attempted += 1;
        self.provider_failed += 1;
        merge_device_counter_delta(
            &mut self.device_stats,
            provider_stats_key,
            DeviceRuntimeCounterDelta {
                provider_failure_count: 1,
                ..DeviceRuntimeCounterDelta::default()
            },
        );
    }
}

pub(crate) fn merge_device_counter_delta(
    aggregates: &mut HashMap<Arc<str>, DeviceRuntimeCounterDelta>,
    device_key: Arc<str>,
    delta: DeviceRuntimeCounterDelta,
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

#[cfg(test)]
mod tests {
    use super::{BusyKind, DispatchProgress, PrivateEnqueueProgress};

    #[test]
    fn provider_queue_acceptance_does_not_record_provider_success() {
        let mut progress = DispatchProgress::default();
        progress.record_provider_queued();

        assert_eq!(progress.provider_attempted, 1);
        assert_eq!(progress.provider_queued, 1);
        assert_eq!(progress.provider_failed, 0);
        assert!(
            progress.device_stats.is_empty(),
            "provider success/failure counters are worker-send outcomes"
        );
    }

    #[test]
    fn too_busy_threshold_ignores_non_too_busy_failures() {
        let mut stats = PrivateEnqueueProgress::default();
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
        let mut stats = PrivateEnqueueProgress::default();
        for _ in 0..4 {
            stats.record_failure("private.enqueue", [1; 16], &crate::Error::TooBusy);
        }
        for _ in 0..4 {
            stats.record_success();
        }
        assert!(stats.is_too_busy());
    }

    #[test]
    fn busy_kind_classifies_private_enqueue_backpressure() {
        assert_eq!(
            PrivateEnqueueProgress::classify_busy(&crate::Error::TooBusy),
            Some(BusyKind::PrivateEnqueueBackpressure)
        );
        assert_eq!(
            PrivateEnqueueProgress::classify_busy(&crate::Error::Internal("io".into())),
            None
        );
    }
}
