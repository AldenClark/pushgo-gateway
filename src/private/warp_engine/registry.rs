use std::{
    collections::VecDeque,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use dashmap::DashMap;
use flume::Receiver;
use parking_lot::Mutex;
use warp_link::warp_link_core::SessionControl;

use crate::{private::protocol::DeliverEnvelope, storage::DeviceId};

pub(super) struct SessionRuntime {
    pub device_id: DeviceId,
    pub conn_id: u64,
    pub terminate_requested: AtomicBool,
    pub control: Mutex<Option<SessionControl>>,
    pub receiver: Receiver<DeliverEnvelope>,
    pub bootstrap_inflight: Mutex<VecDeque<(u64, DeliverEnvelope)>>,
    pub bootstrap_pending: Mutex<VecDeque<DeliverEnvelope>>,
}

impl SessionRuntime {
    pub(super) fn request_termination(&self) {
        let already_requested = self.terminate_requested.swap(true, Ordering::SeqCst);
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
