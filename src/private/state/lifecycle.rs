use super::*;
use crate::routing::derive_private_device_id;

impl PrivateState {
    pub fn new(
        store: Storage,
        config: PrivateConfig,
        device_registry: Arc<DeviceRegistry>,
        runtime_counters: Arc<RuntimeCounterCollector>,
    ) -> Self {
        let hub = Arc::new(PrivateHub::new(store, &config));
        let owner = format!("gateway-{}", std::process::id());
        let fallback_tasks =
            (config.ack_timeout_secs > 0).then(|| FallbackTaskEngine::new(config.runtime_profile));
        let max_sessions = crate::private::warp_engine::default_server_config()
            .max_concurrent_sessions
            .max(1);
        let state = PrivateState {
            hub,
            config,
            device_registry,
            runtime_counters,
            metrics: Arc::new(metrics::PrivateMetrics::default()),
            fallback_tasks,
            session_coordinator: Arc::new(InMemoryCoordinator::new()),
            session_coord_owner: owner,
            revoked_devices: RwLock::new(HashMap::new()),
            session_controls: RwLock::new(HashMap::new()),
            session_devices: RwLock::new(HashMap::new()),
            session_admission: Arc::new(tokio::sync::Semaphore::new(max_sessions)),
            handshake_admission: Arc::new(tokio::sync::Semaphore::new(
                (max_sessions / 16).clamp(32, 512),
            )),
            runtime_tasks: Mutex::new(Vec::new()),
            shutting_down: AtomicBool::new(false),
            shutdown_notify: tokio::sync::Notify::new(),
        };
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.state_initialized",
            fallback_tasks_enabled = (state.fallback_tasks.is_some())
        );
        state
    }

    pub fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.state_shutdown_started"
        );

        for control in self.session_controls.read().values() {
            control.expire_now();
        }

        self.handshake_admission.close();
        self.session_admission.close();
        self.shutdown_notify.notify_waiters();
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.state_shutdown_signaled",
            active_sessions = (self.session_controls.read().len() as u64)
        );
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub async fn wait_for_shutdown(&self) {
        loop {
            // `notify_waiters` does not retain a permit. Register the waiter
            // before re-checking the atomic flag so shutdown cannot land in
            // the check/await gap and strand this task forever.
            let notified = self.shutdown_notify.notified();
            if self.is_shutting_down() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn try_acquire_session_admission(
        &self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.session_admission).try_acquire_owned().ok()
    }

    pub(crate) fn try_acquire_handshake_admission(
        &self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.handshake_admission)
            .try_acquire_owned()
            .ok()
    }

    pub(crate) fn spawn_runtime_task<F>(self: &Arc<Self>, name: &'static str, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.runtime_tasks.lock();
        if self.is_shutting_down() {
            return false;
        }
        let handle = tokio::spawn(future);
        tasks.push(PrivateRuntimeTask { name, handle });
        true
    }

    pub async fn shutdown_runtime(&self, grace: Duration) -> PrivateShutdownReport {
        self.begin_shutdown();
        let mut tasks = std::mem::take(&mut *self.runtime_tasks.lock());
        let deadline = TokioInstant::now() + grace;
        let mut report = PrivateShutdownReport::default();

        for task in &mut tasks {
            match tokio::time::timeout_at(deadline, &mut task.handle).await {
                Ok(Ok(())) => report.joined = report.joined.saturating_add(1),
                Ok(Err(join_error)) => {
                    report.panicked = report.panicked.saturating_add(1);
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::ERROR,
                        event = "private.runtime_task_join_failed",
                        task = %(task.name),
                        cancelled = (join_error.is_cancelled()),
                        panicked = (join_error.is_panic())
                    );
                }
                Err(_) => {
                    task.handle.abort();
                    let _ = (&mut task.handle).await;
                    report.aborted = report.aborted.saturating_add(1);
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "private.runtime_task_aborted",
                        task = %(task.name)
                    );
                }
            }
        }

        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.runtime_shutdown_finished",
            joined = (report.joined as u64),
            panicked = (report.panicked as u64),
            aborted = (report.aborted as u64)
        );
        report
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
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_registered",
            session_id = %(crate::util::redact_text(session_id)),
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id)))
        );
    }

    pub fn unregister_session_control(&self, session_id: &str) {
        self.session_controls.write().remove(session_id);
        self.session_devices.write().remove(session_id);
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_unregistered",
            session_id = %(crate::util::redact_text(session_id))
        );
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
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "private.session_auth_expiry_update_skipped",
                session_id = %(crate::util::redact_text(session_id)),
                reason = %("session_not_found")
            );
            return false;
        };
        control.set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_auth_expiry_updated",
            session_id = %(crate::util::redact_text(session_id)),
            auth_expires_at_unix_secs = (auth_expires_at_unix_secs.unwrap_or(-1)),
            auth_refresh_before_secs = (u64::from(auth_refresh_before_secs))
        );
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

    pub fn memory_snapshot(&self) -> PrivateStateMemorySnapshot {
        let fallback_task_queue_depth = self
            .fallback_tasks
            .as_ref()
            .map(|engine| engine.depth())
            .unwrap_or(0);
        PrivateStateMemorySnapshot {
            revoked_device_count: self.revoked_devices.read().len(),
            session_control_count: self.session_controls.read().len(),
            session_device_count: self.session_devices.read().len(),
            fallback_task_queue_depth,
            fallback_task_queue_capacity: self
                .fallback_tasks
                .as_ref()
                .map(|engine| engine.capacity())
                .unwrap_or(0),
            hub: self.hub.memory_snapshot(),
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
        if affected > 0 {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "private.device_auth_expiry_updated",
                device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                affected_sessions = (affected as u64),
                auth_expires_at_unix_secs = (auth_expires_at_unix_secs.unwrap_or(-1))
            );
        }
        affected
    }
}
