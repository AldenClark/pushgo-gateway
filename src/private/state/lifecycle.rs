use super::*;
use crate::routing::derive_private_device_id;

impl PrivateState {
    pub fn new(
        store: Storage,
        config: PrivateConfig,
        device_registry: Arc<DeviceRegistry>,
        stats: Arc<StatsCollector>,
    ) -> Self {
        let hub = Arc::new(PrivateHub::new(store, &config));
        let owner = format!("gateway-{}", std::process::id());
        let fallback_tasks = (config.ack_timeout_secs > 0).then(FallbackTaskEngine::new);
        PrivateState {
            hub,
            config,
            device_registry,
            stats,
            metrics: Arc::new(metrics::PrivateMetrics::default()),
            fallback_tasks,
            session_coordinator: Arc::new(InMemoryCoordinator::new()),
            session_coord_owner: owner,
            revoked_devices: RwLock::new(HashMap::new()),
            session_controls: RwLock::new(HashMap::new()),
            session_devices: RwLock::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            shutdown_notify: tokio::sync::Notify::new(),
        }
    }

    pub fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }

        for control in self.session_controls.read().values() {
            control.expire_now();
        }

        self.shutdown_notify.notify_waiters();
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        self.shutdown_notify.notified().await;
    }

    pub fn revoke_device_key(&self, device_key: &str) {
        let device_id = derive_private_device_id(device_key);
        self.revoked_devices.write().insert(device_id, ());
        let _ = self.set_device_auth_expiry_by_id(device_id, Some(0), 0, None);
    }

    pub fn unrevoke_device_key(&self, device_key: &str) {
        let device_id = derive_private_device_id(device_key);
        self.revoked_devices.write().remove(&device_id);
    }

    pub fn is_device_revoked(&self, device_id: DeviceId) -> bool {
        self.revoked_devices.read().contains_key(&device_id)
    }

    pub fn register_session_control(
        &self,
        session_id: &str,
        device_id: DeviceId,
        control: SessionControl,
    ) {
        self.session_controls
            .write()
            .insert(session_id.to_string(), control);
        self.session_devices
            .write()
            .insert(session_id.to_string(), device_id);
    }

    pub fn unregister_session_control(&self, session_id: &str) {
        self.session_controls.write().remove(session_id);
        self.session_devices.write().remove(session_id);
    }

    pub fn expire_other_device_sessions(
        &self,
        device_id: DeviceId,
        keep_session_id: &str,
    ) -> usize {
        self.set_device_auth_expiry_by_id(device_id, Some(0), 0, Some(keep_session_id))
    }

    pub fn set_device_auth_expiry(
        &self,
        device_key: &str,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) -> usize {
        let device_id = derive_private_device_id(device_key);
        self.set_device_auth_expiry_by_id(
            device_id,
            auth_expires_at_unix_secs,
            auth_refresh_before_secs,
            None,
        )
    }

    pub fn set_session_auth_expiry(
        &self,
        session_id: &str,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) -> bool {
        let Some(control) = self.session_controls.read().get(session_id).cloned() else {
            return false;
        };
        control.set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
        true
    }

    pub fn session_coordinator(&self) -> Arc<dyn SessionCoordinator> {
        self.session_coordinator.clone()
    }

    pub fn session_coord_owner(&self) -> String {
        self.session_coord_owner.clone()
    }

    pub fn automation_reset(&self) {
        self.metrics.reset();
        self.revoked_devices.write().clear();
        self.session_controls.write().clear();
        self.session_devices.write().clear();
    }

    pub fn automation_stats(&self) -> PrivateAutomationStats {
        PrivateAutomationStats {
            revoked_device_count: self.revoked_devices.read().len(),
            session_count: self.session_controls.read().len(),
            device_bound_session_count: self.session_devices.read().len(),
        }
    }

    fn set_device_auth_expiry_by_id(
        &self,
        device_id: DeviceId,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
        skip_session_id: Option<&str>,
    ) -> usize {
        let mut target_sessions = Vec::new();
        let session_devices = self.session_devices.read();
        for (session_id, bound_device_id) in session_devices.iter() {
            if *bound_device_id != device_id {
                continue;
            }
            if skip_session_id.is_some_and(|skip| skip == session_id.as_str()) {
                continue;
            }
            target_sessions.push(session_id.clone());
        }
        drop(session_devices);
        let mut affected = 0usize;
        let session_controls = self.session_controls.read();
        for session_id in target_sessions {
            if let Some(control) = session_controls.get(session_id.as_str()) {
                control
                    .clone()
                    .set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
                affected = affected.saturating_add(1);
            }
        }
        affected
    }
}
