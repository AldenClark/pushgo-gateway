use std::{
    collections::VecDeque,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use dashmap::DashMap;
use flume::{Receiver, Sender};
use parking_lot::Mutex;
use tokio::time::Instant;
use warp_link::warp_link_core::{SessionControl, TransportKind};

use crate::{private::protocol::DeliverEnvelope, storage::DeviceId};

pub(super) struct PreparedOutbound {
    pub seq: Option<u64>,
    pub envelope: DeliverEnvelope,
}

pub(super) enum PendingOutbound {
    Running(tokio::task::JoinHandle<Option<PreparedOutbound>>),
    Ready(PreparedOutbound),
}

/// One finite, in-memory handoff reservation; it never owns durable delivery
/// responsibility. Explicit ACK and the existing outbox remain authoritative.
#[derive(Clone, Debug)]
pub(super) struct HandoffBinding {
    pub peer: String,
    pub id: String,
    pub deadline: Instant,
}

#[derive(Debug)]
pub(super) enum HandoffState {
    Active(Option<HandoffBinding>),
    Prepared(HandoffBinding),
    Freezing(HandoffBinding),
    Frozen(HandoffBinding),
    Retired,
}

impl HandoffState {
    pub(super) fn can_send(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    pub(super) fn binding(&self) -> Option<&HandoffBinding> {
        match self {
            Self::Active(binding) => binding.as_ref(),
            Self::Prepared(binding) | Self::Freezing(binding) | Self::Frozen(binding) => {
                Some(binding)
            }
            Self::Retired => None,
        }
    }
}

pub(super) struct SessionRuntime {
    pub device_id: DeviceId,
    pub conn_id: u64,
    pub transport: TransportKind,
    pub sender: Sender<DeliverEnvelope>,
    pub resume_token: String,
    pub handoff_enabled: bool,
    pub handoff: Arc<Mutex<HandoffState>>,
    pub ordinary_route_generation: Option<i64>,
    pub ordinary_first: Arc<AtomicBool>,
    pub terminate_requested: Arc<AtomicBool>,
    pub control: Arc<Mutex<Option<SessionControl>>>,
    pub outbound_stop: Arc<tokio::sync::Notify>,
    pub receiver: Receiver<DeliverEnvelope>,
    pub bootstrap_inflight: Arc<Mutex<VecDeque<(u64, DeliverEnvelope)>>>,
    pub bootstrap_pending: Arc<Mutex<VecDeque<DeliverEnvelope>>>,
    /// Warp may cancel the borrow when an inbound/control branch wins. The
    /// single owned operation itself survives until completion or disconnect.
    pub pending_outbound: tokio::sync::Mutex<Option<PendingOutbound>>,
    pub failure_store: Option<crate::ordinary::OrdinaryStore>,
}

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        if let Some(pending) = self.pending_outbound.get_mut().take() {
            if let Some(store) = &self.failure_store {
                store.fail("Private outbound owner dropped before joined completion");
            }
            if let PendingOutbound::Running(task) = pending {
                task.abort();
            }
        }
    }
}

impl SessionRuntime {
    pub(super) fn request_termination(&self) {
        let already_requested = self.terminate_requested.swap(true, Ordering::SeqCst);
        self.outbound_stop.notify_waiters();
        if already_requested {
            return;
        }
        let control = self.control.lock().clone();
        if let Some(control) = control {
            control.expire_now();
        }
    }

    pub(super) fn attach_control(&self, control: SessionControl) {
        let terminate_now = self.terminate_requested.load(Ordering::SeqCst);
        {
            let mut slot = self.control.lock();
            *slot = Some(control.clone());
        }
        if terminate_now {
            control.expire_now();
        }
    }

    pub(super) fn detach_control(&self) {
        let mut slot = self.control.lock();
        *slot = None;
    }

    pub(super) fn is_terminating(&self) -> bool {
        self.terminate_requested.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionConnKey {
    device_id: DeviceId,
    conn_id: u64,
}

const SESSION_REGISTRY_SHARDS: usize = 64;
const LOGICAL_PARTITION_COUNT: u16 = 4096;

pub(super) struct SessionRegistry {
    shards: Vec<DashMap<String, Arc<SessionRuntime>>>,
    by_conn: DashMap<SessionConnKey, String>,
    // Only short, synchronous handoff transitions. Never held over database,
    // transport, or task joins; no new scheduling owner is introduced.
    pub(super) handoff_gate: Mutex<()>,
}

impl SessionRegistry {
    pub(super) fn new() -> Self {
        let mut shards = Vec::with_capacity(SESSION_REGISTRY_SHARDS);
        for _ in 0..SESSION_REGISTRY_SHARDS {
            shards.push(DashMap::new());
        }
        Self {
            shards,
            by_conn: DashMap::new(),
            handoff_gate: Mutex::new(()),
        }
    }

    pub(super) fn insert(&self, session_id: String, runtime: Arc<SessionRuntime>) {
        let index = self.shard_for_session(session_id.as_str());
        self.by_conn.insert(
            SessionConnKey {
                device_id: runtime.device_id,
                conn_id: runtime.conn_id,
            },
            session_id.clone(),
        );
        self.shards[index].insert(session_id, runtime);
    }

    pub(super) fn get(&self, session_id: &str) -> Option<Arc<SessionRuntime>> {
        let index = self.shard_for_session(session_id);
        self.shards[index]
            .get(session_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    pub(super) fn remove(&self, session_id: &str) -> Option<Arc<SessionRuntime>> {
        self.cancel_handoff(session_id);
        let index = self.shard_for_session(session_id);
        let runtime = self.shards[index]
            .remove(session_id)
            .map(|(_, runtime)| runtime);
        if let Some(runtime) = runtime.as_ref() {
            self.by_conn.remove(&SessionConnKey {
                device_id: runtime.device_id,
                conn_id: runtime.conn_id,
            });
        }
        runtime
    }

    pub(super) fn request_termination(&self, device_id: DeviceId, conn_id: u64) -> bool {
        let Some(session_id) = self
            .by_conn
            .get(&SessionConnKey { device_id, conn_id })
            .map(|entry| entry.value().clone())
        else {
            return false;
        };
        let Some(runtime) = self.get(session_id.as_str()) else {
            return false;
        };
        runtime.request_termination();
        true
    }

    pub(super) fn attach_control(&self, session_id: &str, control: SessionControl) -> bool {
        let Some(runtime) = self.get(session_id) else {
            return false;
        };
        runtime.attach_control(control);
        true
    }

    pub(super) fn detach_control(&self, session_id: &str) {
        if let Some(runtime) = self.get(session_id) {
            runtime.detach_control();
        }
    }

    pub(super) fn has_other_live_session(&self, device_id: DeviceId, allowed: &[&str]) -> bool {
        self.shards.iter().any(|shard| {
            shard.iter().any(|entry| {
                entry.device_id == device_id
                    && !allowed.contains(&entry.key().as_str())
                    && !entry.is_terminating()
                    && !matches!(*entry.handoff.lock(), HandoffState::Retired)
            })
        })
    }

    /// Losing a prepared candidate restores only its still-bound primary.
    /// After activation the old primary is Retired and can never be revived.
    pub(super) fn cancel_handoff(&self, session_id: &str) {
        let _gate = self.handoff_gate.lock();
        self.cancel_handoff_locked(session_id);
    }

    pub(super) fn cancel_handoff_locked(&self, session_id: &str) {
        let Some(runtime) = self.get(session_id) else {
            return;
        };
        let (binding, candidate) = {
            let state = runtime.handoff.lock();
            let Some(binding) = state.binding().cloned() else {
                return;
            };
            (binding, matches!(*state, HandoffState::Prepared(_)))
        };
        if let Some(peer) = self.get(&binding.peer) {
            let mut peer_state = peer.handoff.lock();
            let matches = peer_state
                .binding()
                .is_some_and(|other| other.peer == session_id && other.id == binding.id);
            if matches {
                if candidate {
                    *peer_state = HandoffState::Active(None);
                    peer.outbound_stop.notify_waiters();
                } else if matches!(*peer_state, HandoffState::Prepared(_)) {
                    *peer_state = HandoffState::Retired;
                    drop(peer_state);
                    peer.request_termination();
                }
            }
        }
        let mut own_state = runtime.handoff.lock();
        if candidate {
            *own_state = HandoffState::Retired;
            drop(own_state);
            runtime.request_termination();
        } else if !matches!(*own_state, HandoffState::Retired) {
            *own_state = HandoffState::Active(None);
            runtime.outbound_stop.notify_waiters();
        }
    }

    pub(super) fn expire_handoff(&self, session_id: &str) {
        // Ordinary active sends have no reservation. Do not acquire a global
        // transition lock for each frame; only expired pairs need coordination.
        let expired = self.get(session_id).is_some_and(|runtime| {
            runtime
                .handoff
                .lock()
                .binding()
                .is_some_and(|binding| Instant::now() >= binding.deadline)
        });
        if !expired {
            return;
        }
        let _gate = self.handoff_gate.lock();
        let expired = self.get(session_id).is_some_and(|runtime| {
            runtime
                .handoff
                .lock()
                .binding()
                .is_some_and(|binding| Instant::now() >= binding.deadline)
        });
        if expired {
            self.cancel_handoff_locked(session_id);
        }
    }

    pub(super) fn cancel_device_handoffs(&self, device: DeviceId) {
        let _gate = self.handoff_gate.lock();
        self.cancel_device_handoffs_locked(device);
    }

    pub(super) fn cancel_device_handoffs_locked(&self, device: DeviceId) {
        let candidates: Vec<String> = self
            .shards
            .iter()
            .flat_map(|shard| {
                shard
                    .iter()
                    .filter_map(|entry| {
                        (entry.device_id == device
                            && matches!(*entry.handoff.lock(), HandoffState::Prepared(_)))
                        .then(|| entry.key().clone())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        for candidate in candidates {
            self.cancel_handoff_locked(&candidate);
        }
    }

    fn shard_for_session(&self, session_id: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }
}

pub(super) fn logical_partition_for_device(device_id: DeviceId) -> u16 {
    let hash = blake3::hash(&device_id);
    let raw = u16::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]);
    raw % LOGICAL_PARTITION_COUNT
}

#[cfg(test)]
mod handoff_tests {
    use super::*;
    use std::time::Duration;

    fn runtime(conn: u64, state: HandoffState) -> Arc<SessionRuntime> {
        let (sender, receiver) = flume::bounded(2);
        Arc::new(SessionRuntime {
            device_id: [7; 16],
            conn_id: conn,
            transport: TransportKind::Tcp,
            sender,
            receiver,
            resume_token: "synthetic-resume-token".into(),
            handoff_enabled: true,
            handoff: Arc::new(Mutex::new(state)),
            ordinary_route_generation: None,
            ordinary_first: Arc::new(AtomicBool::new(true)),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            control: Arc::new(Mutex::new(None)),
            outbound_stop: Arc::new(tokio::sync::Notify::new()),
            bootstrap_inflight: Arc::new(Mutex::new(VecDeque::new())),
            bootstrap_pending: Arc::new(Mutex::new(VecDeque::new())),
            pending_outbound: tokio::sync::Mutex::new(None),
            failure_store: None,
        })
    }

    fn pair(
        frozen: bool,
        expired: bool,
    ) -> (SessionRegistry, Arc<SessionRuntime>, Arc<SessionRuntime>) {
        let deadline = if expired {
            Instant::now() - Duration::from_secs(1)
        } else {
            Instant::now() + Duration::from_secs(15)
        };
        let old_binding = HandoffBinding {
            peer: "candidate".into(),
            id: "same-reservation".into(),
            deadline,
        };
        let old = runtime(
            1,
            if frozen {
                HandoffState::Frozen(old_binding)
            } else {
                HandoffState::Active(Some(old_binding))
            },
        );
        let candidate = runtime(
            2,
            HandoffState::Prepared(HandoffBinding {
                peer: "old".into(),
                id: "same-reservation".into(),
                deadline,
            }),
        );
        let registry = SessionRegistry::new();
        registry.insert("old".into(), old.clone());
        registry.insert("candidate".into(), candidate.clone());
        (registry, old, candidate)
    }

    #[test]
    fn expired_prepared_and_frozen_reservations_restore_only_the_bound_primary() {
        for phase in 0..3 {
            let frozen = phase != 0;
            let (registry, old, candidate) = pair(frozen, true);
            if phase == 1 {
                let binding = old.handoff.lock().binding().unwrap().clone();
                *old.handoff.lock() = HandoffState::Freezing(binding);
            }
            registry.expire_handoff("candidate");
            assert!(matches!(*old.handoff.lock(), HandoffState::Active(None)));
            assert!(!old.is_terminating());
            assert!(matches!(*candidate.handoff.lock(), HandoffState::Retired));
            assert!(candidate.is_terminating());
            registry.expire_handoff("old");
            assert!(matches!(*old.handoff.lock(), HandoffState::Active(None)));
        }
    }

    #[test]
    fn candidate_disconnect_preserves_the_existing_prepared_work_owner() {
        let (registry, old, candidate) = pair(true, false);
        *old.pending_outbound.try_lock().unwrap() =
            Some(PendingOutbound::Ready(PreparedOutbound {
                seq: None,
                envelope: DeliverEnvelope {
                    delivery_id: "unacknowledged".into(),
                    payload: Arc::from([8_u8]),
                    ordinary: true,
                    ordinary_expires_at: Some(i64::MAX),
                },
            }));
        registry.remove("candidate").unwrap();
        assert!(matches!(*old.handoff.lock(), HandoffState::Active(None)));
        assert!(candidate.is_terminating());
        assert!(
            matches!(old.pending_outbound.try_lock().unwrap().as_ref(), Some(PendingOutbound::Ready(work)) if work.envelope.delivery_id == "unacknowledged")
        );
    }

    #[test]
    fn activated_handoff_never_revives_the_retired_primary() {
        let (registry, old, candidate) = pair(true, true);
        // These two transitions are made under the production registry gate at
        // activation commit; no deadline/cancel may undo a committed transfer.
        *old.handoff.lock() = HandoffState::Retired;
        *candidate.handoff.lock() = HandoffState::Active(None);
        registry.expire_handoff("old");
        registry.remove("candidate").unwrap();
        assert!(matches!(*old.handoff.lock(), HandoffState::Retired));
        assert!(!old.handoff.lock().can_send());
    }

    #[test]
    fn stale_candidate_disconnect_cannot_thaw_a_newer_reservation() {
        let (registry, old, _) = pair(true, false);
        *old.handoff.lock() = HandoffState::Frozen(HandoffBinding {
            peer: "new-candidate".into(),
            id: "newer-reservation".into(),
            deadline: Instant::now() + Duration::from_secs(15),
        });
        registry.remove("candidate").unwrap();
        assert!(
            matches!(&*old.handoff.lock(), HandoffState::Frozen(binding) if binding.peer == "new-candidate" && binding.id == "newer-reservation")
        );
    }
}
