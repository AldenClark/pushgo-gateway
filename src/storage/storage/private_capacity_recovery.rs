use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::storage::DeviceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockedPrivateSubmission {
    pub(crate) dedupe_key: String,
    pub(crate) delivery_id: String,
    pub(crate) owner: String,
}

#[derive(Debug)]
struct BlockedPrivateSubmissionState {
    sequence: u64,
    submission: BlockedPrivateSubmission,
    devices: Vec<DeviceId>,
}

#[derive(Debug, Default)]
struct RegistryState {
    next_sequence: u64,
    by_submission: HashMap<String, BlockedPrivateSubmissionState>,
    global_order: BTreeMap<u64, String>,
    by_device: HashMap<DeviceId, BTreeMap<u64, String>>,
}

/// Single-process accelerator for durable submissions blocked by private
/// outbox capacity. The database lease remains the correctness boundary; this
/// index only lets an ACK release one matching retry without polling every
/// frozen manifest or creating a retry storm at the hard capacity.
#[derive(Debug, Default)]
pub(crate) struct PrivateCapacityRecovery {
    state: Mutex<RegistryState>,
    epoch: AtomicU64,
    notify: Arc<Notify>,
}

impl PrivateCapacityRecovery {
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(crate) fn notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub(crate) fn register(&self, submission: BlockedPrivateSubmission, devices: &[DeviceId]) {
        let mut devices = devices.to_vec();
        devices.sort_unstable();
        devices.dedup();

        let mut state = self.state.lock();
        Self::remove_locked(&mut state, submission.dedupe_key.as_str());
        state.next_sequence = state.next_sequence.wrapping_add(1).max(1);
        let sequence = state.next_sequence;
        for device in &devices {
            state
                .by_device
                .entry(*device)
                .or_default()
                .insert(sequence, submission.dedupe_key.clone());
        }
        state
            .global_order
            .insert(sequence, submission.dedupe_key.clone());
        state.by_submission.insert(
            submission.dedupe_key.clone(),
            BlockedPrivateSubmissionState {
                sequence,
                submission,
                devices,
            },
        );
    }

    pub(crate) fn clear(&self, dedupe_key: &str) {
        Self::remove_locked(&mut self.state.lock(), dedupe_key);
    }

    pub(crate) fn note_capacity_released(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
    }

    /// Selects candidates without removing them. A database lease release is
    /// the commit point; callers clear a candidate only after that operation
    /// has definitively succeeded or proved the registration stale. Keeping
    /// the entry here on a transient database error preserves the fast path.
    pub(crate) fn select_for_release(
        &self,
        device_id: Option<DeviceId>,
        limit: usize,
    ) -> Vec<BlockedPrivateSubmission> {
        let state = self.state.lock();
        let mut selected = Vec::with_capacity(limit.min(state.by_submission.len()));
        let mut seen = HashSet::with_capacity(limit.min(state.by_submission.len()));
        let targeted = device_id
            .and_then(|device| state.by_device.get(&device))
            .into_iter()
            .flat_map(|entries| entries.values());
        for key in targeted.chain(state.global_order.values()) {
            if selected.len() >= limit {
                break;
            }
            if seen.insert(key.as_str())
                && let Some(blocked) = state.by_submission.get(key)
            {
                selected.push(blocked.submission.clone());
            }
        }
        selected
    }

    fn remove_locked(
        state: &mut RegistryState,
        dedupe_key: &str,
    ) -> Option<BlockedPrivateSubmissionState> {
        let blocked = state.by_submission.remove(dedupe_key)?;
        state.global_order.remove(&blocked.sequence);
        for device in &blocked.devices {
            let remove_device = if let Some(entries) = state.by_device.get_mut(device) {
                entries.remove(&blocked.sequence);
                entries.is_empty()
            } else {
                false
            };
            if remove_device {
                state.by_device.remove(device);
            }
        }
        Some(blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockedPrivateSubmission, PrivateCapacityRecovery};

    fn blocked(key: &str) -> BlockedPrivateSubmission {
        BlockedPrivateSubmission {
            dedupe_key: key.to_string(),
            delivery_id: format!("delivery-{key}"),
            owner: format!("owner-{key}"),
        }
    }

    #[test]
    fn device_release_prefers_a_matching_submission_and_removes_all_indexes() {
        let recovery = PrivateCapacityRecovery::default();
        recovery.register(blocked("other"), &[[2; 16]]);
        recovery.register(blocked("matching"), &[[1; 16], [3; 16]]);

        let selected = recovery.select_for_release(Some([1; 16]), 1);
        assert_eq!(selected, vec![blocked("matching")]);
        assert_eq!(
            recovery.select_for_release(Some([3; 16]), 1),
            vec![blocked("matching")],
            "selection must remain registered until the database release commits"
        );
        recovery.clear("matching");
        assert_eq!(
            recovery.select_for_release(Some([3; 16]), 1),
            vec![blocked("other")],
            "the global fallback may use capacity released by another device"
        );
        recovery.clear("other");
        assert_eq!(
            recovery.select_for_release(None, 8),
            Vec::<BlockedPrivateSubmission>::new()
        );
    }

    #[test]
    fn re_register_replaces_the_previous_owner_without_leaving_stale_entries() {
        let recovery = PrivateCapacityRecovery::default();
        recovery.register(blocked("same"), &[[1; 16]]);
        let replacement = BlockedPrivateSubmission {
            dedupe_key: "same".to_string(),
            delivery_id: "delivery-same".to_string(),
            owner: "new-owner".to_string(),
        };
        recovery.register(replacement.clone(), &[[2; 16]]);

        let selected = recovery.select_for_release(Some([1; 16]), 1);
        assert_eq!(selected, vec![replacement]);
        recovery.clear("same");
        assert!(recovery.select_for_release(None, 1).is_empty());
    }
}
