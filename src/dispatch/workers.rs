use super::runtime::ProviderDispatchFailureLog;
use super::*;
use crate::delivery_core::execution::provider::{
    ProviderInvalidTokenCleanup, cleanup_invalid_provider_token,
};
use crate::runtime_counters::RuntimeCounterCollector;
use tokio::time::Instant;
use tracing::Instrument;

pub(crate) struct DispatchWorkerTasks {
    tasks: Vec<DispatchWorkerTask>,
}

struct DispatchWorkerTask {
    provider: &'static str,
    worker_slot: usize,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DispatchWorkerShutdownReport {
    pub joined: usize,
    pub panicked: usize,
    pub aborted: usize,
}

impl DispatchWorkerTasks {
    pub(crate) async fn shutdown_until(
        mut self,
        deadline: Instant,
    ) -> DispatchWorkerShutdownReport {
        let mut report = DispatchWorkerShutdownReport::default();
        for task in &mut self.tasks {
            match tokio::time::timeout_at(deadline, &mut task.handle).await {
                Ok(Ok(())) => report.joined = report.joined.saturating_add(1),
                Ok(Err(join_error)) => {
                    report.panicked = report.panicked.saturating_add(1);
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::ERROR,
                        event = "dispatch.worker_join_failed",
                        provider = %(task.provider),
                        worker_slot = (task.worker_slot as u64),
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
                        ::tracing::Level::ERROR,
                        event = "dispatch.worker_aborted",
                        provider = %(task.provider),
                        worker_slot = (task.worker_slot as u64),
                        reason = %("shutdown_deadline_exceeded")
                    );
                }
            }
        }
        report
    }
}

pub(crate) struct DispatchWorkerDeps {
    pub apns: Arc<dyn ApnsClient>,
    pub fcm: Arc<dyn FcmClient>,
    pub wns: Arc<dyn WnsClient>,
    pub store: Storage,
    pub private: Option<Arc<PrivateState>>,
    pub runtime_counters: Arc<RuntimeCounterCollector>,
    pub runtime_profile: GatewayRuntimeProfile,
}

impl DispatchWorkerDeps {
    pub(crate) fn spawn(self, receivers: DispatchWorkerReceivers) -> DispatchWorkerTasks {
        let runtime = DispatchWorkerRuntime {
            store: self.store,
            private: self.private,
            runtime_counters: self.runtime_counters,
        };
        let pool = DispatchWorkerPool {
            apns: self.apns,
            fcm: self.fcm,
            wns: self.wns,
            runtime,
            config: DispatchRuntimeConfig::from_profile(self.runtime_profile),
        };
        pool.spawn(receivers)
    }
}

struct DispatchWorkerPool {
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
    runtime: DispatchWorkerRuntime,
    config: DispatchRuntimeConfig,
}

impl DispatchWorkerPool {
    fn spawn(self, receivers: DispatchWorkerReceivers) -> DispatchWorkerTasks {
        let mut tasks = Vec::with_capacity(self.config.worker_count.saturating_mul(4));
        self.spawn_apns_workers(receivers.apns, &mut tasks);
        self.spawn_widget_push_workers(receivers.widget_push, &mut tasks);
        self.spawn_fcm_workers(receivers.fcm, &mut tasks);
        self.spawn_wns_workers(receivers.wns, &mut tasks);
        DispatchWorkerTasks { tasks }
    }

    fn spawn_apns_workers(&self, apns_rx: Receiver<ApnsJob>, tasks: &mut Vec<DispatchWorkerTask>) {
        for worker_slot in 0..self.config.worker_count {
            let apns_rx = apns_rx.clone();
            let apns = Arc::clone(&self.apns);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "APNS",
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started("APNS", worker_slot);
                    while let Ok(job) = apns_rx.recv_async().await {
                        if let Some(outcome) = job.outcome.as_ref()
                            && !outcome.wait_until_committed().await
                        {
                            continue;
                        }
                        let apns_client = Arc::clone(&apns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let mut actual_path = job.initial_path;
                        let mut payload = match actual_path {
                            ProviderDeliveryPath::Direct => Arc::clone(&job.direct_payload),
                            ProviderDeliveryPath::WakeupPull => Arc::clone(
                                job.wakeup_payload
                                    .as_ref()
                                    .expect("wakeup payload required for wakeup path"),
                            ),
                        };
                        let mut dispatch = apns_client
                            .send_to_device(
                                job.device_token.as_ref(),
                                job.platform,
                                Arc::clone(&payload),
                                job.collapse_id.clone(),
                            )
                            .await;
                        if !dispatch.success
                            && actual_path == ProviderDeliveryPath::Direct
                            && dispatch.is_payload_too_large()
                            && job.wakeup_payload_within_limit
                            && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                        {
                            actual_path = ProviderDeliveryPath::WakeupPull;
                            emit_provider_path_downgraded(
                                "APNS",
                                job.correlation_id.as_ref(),
                                job.delivery_id.as_ref(),
                                &channel_id,
                                job.platform.name(),
                                job.device_token.as_ref(),
                            );
                            payload = Arc::clone(wakeup_payload);
                            dispatch = apns_client
                                .send_to_device(
                                    job.device_token.as_ref(),
                                    job.platform,
                                    Arc::clone(&payload),
                                    job.collapse_id.clone(),
                                )
                                .await;
                        }
                        runtime.record_provider_dispatch_result(
                            "APNS",
                            job.channel_id,
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(job.platform),
                            job.device_token.as_ref(),
                            job.device_key.as_ref(),
                            &dispatch,
                        );
                        if let Some(outcome) = job.outcome.as_ref()
                            && outcome.record_provider_result(dispatch.success)
                        {
                            runtime.finalize_provider_dispatch_outcome(outcome).await;
                        }
                        if !dispatch.success {
                            runtime.log_provider_dispatch_failure(
                                ProviderDispatchFailureLog {
                                    provider: "APNS",
                                    correlation_id: job.correlation_id.as_ref(),
                                    channel_id: &channel_id,
                                    path: actual_path,
                                    platform: Some(job.platform),
                                    device_token: job.device_token.as_ref(),
                                },
                                &dispatch,
                            );
                        }
                        if dispatch.is_invalid_token() {
                            cleanup_invalid_provider_token(ProviderInvalidTokenCleanup {
                                store: &runtime.store,
                                private: runtime.private.as_deref(),
                                runtime_counters: runtime.runtime_counters.as_ref(),
                                channel_id: job.channel_id,
                                channel_id_text: &channel_id,
                                device_key: job.device_key.as_ref(),
                                platform: job.platform,
                                device_token: job.device_token.as_ref(),
                                route_updated_at: job.route_updated_at,
                                provider: "APNS",
                                correlation_id: job.correlation_id.as_ref(),
                            })
                            .await;
                        }
                    }
                    emit_dispatch_worker_stopped("APNS", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
            tasks.push(DispatchWorkerTask {
                provider: "APNS",
                worker_slot,
                handle,
            });
        }
    }

    fn spawn_widget_push_workers(
        &self,
        widget_push_rx: Receiver<WidgetPushJob>,
        tasks: &mut Vec<DispatchWorkerTask>,
    ) {
        for worker_slot in 0..self.config.worker_count {
            let widget_push_rx = widget_push_rx.clone();
            let apns = Arc::clone(&self.apns);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "APNS_WIDGETS",
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started("APNS_WIDGETS", worker_slot);
                    while let Ok(job) = widget_push_rx.recv_async().await {
                        let apns_client = Arc::clone(&apns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let payload = Arc::new(ApnsPayload::widgets());
                        let dispatch = apns_client
                            .send_to_device(
                                job.device_token.as_ref(),
                                job.platform,
                                Arc::clone(&payload),
                                job.collapse_id.clone(),
                            )
                            .await;
                        runtime.record_provider_dispatch_result(
                            "APNS_WIDGETS",
                            job.channel_id,
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            ProviderDeliveryPath::Direct,
                            Some(job.platform),
                            job.device_token.as_ref(),
                            job.device_key.as_ref(),
                            &dispatch,
                        );
                        if !dispatch.success {
                            runtime.log_provider_dispatch_failure(
                                ProviderDispatchFailureLog {
                                    provider: "APNS_WIDGETS",
                                    correlation_id: job.correlation_id.as_ref(),
                                    channel_id: &channel_id,
                                    path: ProviderDeliveryPath::Direct,
                                    platform: Some(job.platform),
                                    device_token: job.device_token.as_ref(),
                                },
                                &dispatch,
                            );
                        }
                        if dispatch.is_invalid_token() {
                            match runtime
                                .store
                                .delete_widget_push_token(job.platform, job.device_token.as_ref())
                                .await
                            {
                                Ok(deleted) => emit_widget_push_invalid_token_cleaned(
                                    job.correlation_id.as_ref(),
                                    job.delivery_id.as_ref(),
                                    &channel_id,
                                    job.platform,
                                    job.device_key.as_ref(),
                                    job.widget_kinds.as_ref(),
                                    deleted,
                                ),
                                Err(err) => emit_widget_push_invalid_token_cleanup_failed(
                                    job.correlation_id.as_ref(),
                                    job.delivery_id.as_ref(),
                                    &channel_id,
                                    job.platform,
                                    job.device_key.as_ref(),
                                    err.to_string(),
                                ),
                            }
                        }
                    }
                    emit_dispatch_worker_stopped("APNS_WIDGETS", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
            tasks.push(DispatchWorkerTask {
                provider: "APNS_WIDGETS",
                worker_slot,
                handle,
            });
        }
    }

    fn spawn_fcm_workers(&self, fcm_rx: Receiver<FcmJob>, tasks: &mut Vec<DispatchWorkerTask>) {
        for worker_slot in 0..self.config.worker_count {
            let fcm_rx = fcm_rx.clone();
            let fcm = Arc::clone(&self.fcm);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "FCM",
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started("FCM", worker_slot);
                    while let Ok(job) = fcm_rx.recv_async().await {
                        if let Some(outcome) = job.outcome.as_ref()
                            && !outcome.wait_until_committed().await
                        {
                            continue;
                        }
                        let fcm_client = Arc::clone(&fcm);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let mut actual_path = job.initial_path;
                        let mut payload = match actual_path {
                            ProviderDeliveryPath::Direct => Arc::clone(&job.direct_payload),
                            ProviderDeliveryPath::WakeupPull => Arc::clone(
                                job.wakeup_payload
                                    .as_ref()
                                    .expect("wakeup payload required for wakeup path"),
                            ),
                        };
                        let mut body = match actual_path {
                            ProviderDeliveryPath::Direct => Arc::clone(&job.direct_body),
                            ProviderDeliveryPath::WakeupPull => Arc::clone(
                                job.wakeup_body
                                    .as_ref()
                                    .expect("wakeup body required for wakeup path"),
                            ),
                        };
                        let mut dispatch = fcm_client
                            .send_to_device(
                                job.device_token.as_ref(),
                                Arc::clone(&payload),
                                Some(body),
                            )
                            .await;
                        if !dispatch.success
                            && actual_path == ProviderDeliveryPath::Direct
                            && dispatch.is_payload_too_large()
                            && job.wakeup_payload_within_limit
                            && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                        {
                            actual_path = ProviderDeliveryPath::WakeupPull;
                            emit_provider_path_downgraded(
                                "FCM",
                                job.correlation_id.as_ref(),
                                job.delivery_id.as_ref(),
                                &channel_id,
                                Platform::ANDROID.name(),
                                job.device_token.as_ref(),
                            );
                            payload = Arc::clone(wakeup_payload);
                            body = Arc::clone(
                                job.wakeup_body
                                    .as_ref()
                                    .expect("wakeup body required when wakeup payload exists"),
                            );
                            dispatch = fcm_client
                                .send_to_device(
                                    job.device_token.as_ref(),
                                    Arc::clone(&payload),
                                    Some(body),
                                )
                                .await;
                        }
                        runtime.record_provider_dispatch_result(
                            "FCM",
                            job.channel_id,
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(Platform::ANDROID),
                            job.device_token.as_ref(),
                            job.device_key.as_ref(),
                            &dispatch,
                        );
                        if let Some(outcome) = job.outcome.as_ref()
                            && outcome.record_provider_result(dispatch.success)
                        {
                            runtime.finalize_provider_dispatch_outcome(outcome).await;
                        }
                        if !dispatch.success {
                            runtime.log_provider_dispatch_failure(
                                ProviderDispatchFailureLog {
                                    provider: "FCM",
                                    correlation_id: job.correlation_id.as_ref(),
                                    channel_id: &channel_id,
                                    path: actual_path,
                                    platform: Some(Platform::ANDROID),
                                    device_token: job.device_token.as_ref(),
                                },
                                &dispatch,
                            );
                        }
                        if dispatch.is_invalid_token() {
                            cleanup_invalid_provider_token(ProviderInvalidTokenCleanup {
                                store: &runtime.store,
                                private: runtime.private.as_deref(),
                                runtime_counters: runtime.runtime_counters.as_ref(),
                                channel_id: job.channel_id,
                                channel_id_text: &channel_id,
                                device_key: job.device_key.as_ref(),
                                platform: Platform::ANDROID,
                                device_token: job.device_token.as_ref(),
                                route_updated_at: job.route_updated_at,
                                provider: "FCM",
                                correlation_id: job.correlation_id.as_ref(),
                            })
                            .await;
                        }
                    }
                    emit_dispatch_worker_stopped("FCM", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
            tasks.push(DispatchWorkerTask {
                provider: "FCM",
                worker_slot,
                handle,
            });
        }
    }

    fn spawn_wns_workers(&self, wns_rx: Receiver<WnsJob>, tasks: &mut Vec<DispatchWorkerTask>) {
        for worker_slot in 0..self.config.worker_count {
            let wns_rx = wns_rx.clone();
            let wns = Arc::clone(&self.wns);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "WNS",
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started("WNS", worker_slot);
                    while let Ok(job) = wns_rx.recv_async().await {
                        if let Some(outcome) = job.outcome.as_ref()
                            && !outcome.wait_until_committed().await
                        {
                            continue;
                        }
                        let wns_client = Arc::clone(&wns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let mut actual_path = job.initial_path;
                        let mut payload = match actual_path {
                            ProviderDeliveryPath::Direct => Arc::clone(&job.direct_payload),
                            ProviderDeliveryPath::WakeupPull => Arc::clone(
                                job.wakeup_payload
                                    .as_ref()
                                    .expect("wakeup payload required for wakeup path"),
                            ),
                        };
                        let mut dispatch = wns_client
                            .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                            .await;
                        if !dispatch.success
                            && actual_path == ProviderDeliveryPath::Direct
                            && dispatch.is_payload_too_large()
                            && job.wakeup_payload_within_limit
                            && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                        {
                            actual_path = ProviderDeliveryPath::WakeupPull;
                            emit_provider_path_downgraded(
                                "WNS",
                                job.correlation_id.as_ref(),
                                job.delivery_id.as_ref(),
                                &channel_id,
                                Platform::WINDOWS.name(),
                                job.device_token.as_ref(),
                            );
                            payload = Arc::clone(wakeup_payload);
                            dispatch = wns_client
                                .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                                .await;
                        }
                        runtime.record_provider_dispatch_result(
                            "WNS",
                            job.channel_id,
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(Platform::WINDOWS),
                            job.device_token.as_ref(),
                            job.device_key.as_ref(),
                            &dispatch,
                        );
                        if let Some(outcome) = job.outcome.as_ref()
                            && outcome.record_provider_result(dispatch.success)
                        {
                            runtime.finalize_provider_dispatch_outcome(outcome).await;
                        }
                        if !dispatch.success {
                            runtime.log_provider_dispatch_failure(
                                ProviderDispatchFailureLog {
                                    provider: "WNS",
                                    correlation_id: job.correlation_id.as_ref(),
                                    channel_id: &channel_id,
                                    path: actual_path,
                                    platform: Some(Platform::WINDOWS),
                                    device_token: job.device_token.as_ref(),
                                },
                                &dispatch,
                            );
                        }
                        if dispatch.is_invalid_token() {
                            cleanup_invalid_provider_token(ProviderInvalidTokenCleanup {
                                store: &runtime.store,
                                private: runtime.private.as_deref(),
                                runtime_counters: runtime.runtime_counters.as_ref(),
                                channel_id: job.channel_id,
                                channel_id_text: &channel_id,
                                device_key: job.device_key.as_ref(),
                                platform: Platform::WINDOWS,
                                device_token: job.device_token.as_ref(),
                                route_updated_at: job.route_updated_at,
                                provider: "WNS",
                                correlation_id: job.correlation_id.as_ref(),
                            })
                            .await;
                        }
                    }
                    emit_dispatch_worker_stopped("WNS", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
            tasks.push(DispatchWorkerTask {
                provider: "WNS",
                worker_slot,
                handle,
            });
        }
    }
}

fn emit_dispatch_worker_started(provider: &'static str, worker_slot: usize) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.worker_started",
        provider = %(provider),
        worker_slot = (worker_slot as u64)
    );
}

fn emit_dispatch_worker_stopped(provider: &'static str, worker_slot: usize, reason: &'static str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.worker_stopped",
        provider = %(provider),
        worker_slot = (worker_slot as u64),
        reason = %(reason)
    );
}

fn emit_widget_push_invalid_token_cleaned(
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    platform: Platform,
    device_key: &str,
    widget_kinds: &[String],
    deleted: usize,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "widget_push.invalid_token_cleaned",
        correlation_id = %(crate::util::redact_text(correlation_id)),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        channel_id = %(crate::util::redact_text(channel_id)),
        platform = %(platform.name()),
        device_key = %(crate::util::redact_text(device_key)),
        widget_kinds = %(widget_kinds.join(",")),
        deleted = (deleted as u64)
    );
}

fn emit_widget_push_invalid_token_cleanup_failed(
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    platform: Platform,
    device_key: &str,
    error: String,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "widget_push.invalid_token_cleanup_failed",
        correlation_id = %(crate::util::redact_text(correlation_id)),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        channel_id = %(crate::util::redact_text(channel_id)),
        platform = %(platform.name()),
        device_key = %(crate::util::redact_text(device_key)),
        error = %(error.as_str())
    );
}

fn emit_provider_path_downgraded(
    provider: &'static str,
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    platform: &str,
    device_token: &str,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.provider_path_downgraded",
        provider = %(provider),
        correlation_id = %(crate::util::redact_text(correlation_id)),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        channel_id = %(crate::util::redact_text(channel_id)),
        platform = %(platform),
        from_path = %(ProviderDeliveryPath::Direct.as_str()),
        to_path = %(ProviderDeliveryPath::WakeupPull.as_str()),
        device_token = %(crate::util::redact_text(device_token))
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        providers::{ApnsClient, BoxFuture, FcmClient, TokenInfo, WnsClient},
        storage::{
            DedupeState, OpDedupeReservation, SenderSubmitStatusKind, SenderSubmitStatusRecord,
        },
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use tokio::time::{Duration, sleep};

    struct StaticFcmClient {
        success: bool,
        calls: AtomicUsize,
    }

    impl FcmClient for StaticFcmClient {
        fn send_to_device<'a>(
            &'a self,
            _device_token: &'a str,
            _payload: Arc<FcmPayload>,
            _prepared_body: Option<Arc<[u8]>>,
        ) -> BoxFuture<'a, DispatchResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let success = self.success;
            Box::pin(async move {
                if success {
                    DispatchResult::success(200)
                } else {
                    DispatchResult::from_error(503, crate::Error::Internal("injected".into()))
                }
            })
        }

        fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }

        fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }
    }

    struct UnusedApnsClient;

    impl ApnsClient for UnusedApnsClient {
        fn send_to_device<'a>(
            &'a self,
            _device_token: &'a str,
            _platform: Platform,
            _payload: Arc<ApnsPayload>,
            _collapse_id: Option<Arc<str>>,
        ) -> BoxFuture<'a, DispatchResult> {
            Box::pin(async { panic!("APNS should not be called in the FCM worker test") })
        }

        fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }

        fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }
    }

    struct UnusedWnsClient;

    impl WnsClient for UnusedWnsClient {
        fn send_to_device<'a>(
            &'a self,
            _device_token: &'a str,
            _payload: Arc<WnsPayload>,
        ) -> BoxFuture<'a, DispatchResult> {
            Box::pin(async { panic!("WNS should not be called in the FCM worker test") })
        }

        fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }

        fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }
    }

    async fn assert_fcm_worker_persists_final_provider_result(
        success: bool,
        finalize_failures: usize,
    ) {
        let dir = tempdir().expect("worker test tempdir");
        let outcome_name = if success { "success" } else { "failure" };
        let db_path = dir.path().join(format!(
            "provider-worker-{outcome_name}-{finalize_failures}.sqlite"
        ));
        std::fs::File::create(&db_path).expect("worker sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("worker test storage should initialize");
        let op_id = if success {
            "provider-worker-success-op"
        } else {
            "provider-worker-failure-op"
        };
        let delivery_id = if success {
            "provider-worker-success-delivery"
        } else {
            "provider-worker-failure-delivery"
        };
        let now = chrono::Utc::now().timestamp_millis();
        assert!(matches!(
            store
                .reserve_op_dedupe_pending(op_id, delivery_id, now)
                .await
                .expect("reserve op dedupe"),
            OpDedupeReservation::Reserved
        ));
        assert!(
            store
                .mark_op_dedupe_finalized(op_id, delivery_id, DedupeState::ProviderQueued)
                .await
                .expect("mark provider queued")
        );
        store
            .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
                op_id: op_id.to_string(),
                channel_id: [7; 16],
                model: "message".to_string(),
                entity_id: "provider-worker-entity".to_string(),
                status: SenderSubmitStatusKind::ProviderQueued,
                dispatch_status: Some("provider_queued".to_string()),
                accepted_at: now,
                updated_at: now,
                expires_at: now + 60_000,
            })
            .await
            .expect("insert sender status");
        store.inject_provider_finalize_failures(finalize_failures);

        let fcm = Arc::new(StaticFcmClient {
            success,
            calls: AtomicUsize::new(0),
        });
        let (dispatch, receivers) = DispatchChannels::new();
        let runtime_counters = RuntimeCounterCollector::spawn(store.clone());
        let workers = DispatchWorkerDeps {
            apns: Arc::new(UnusedApnsClient),
            fcm: fcm.clone(),
            wns: Arc::new(UnusedWnsClient),
            store: store.clone(),
            private: None,
            runtime_counters: Arc::clone(&runtime_counters),
            runtime_profile: GatewayRuntimeProfile::Small,
        }
        .spawn(receivers);

        let outcome = Arc::new(ProviderDispatchOutcome::new(
            Arc::from(op_id),
            Arc::from(delivery_id),
        ));
        outcome.configure(1, 0);
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        dispatch
            .try_send_fcm(FcmJob {
                channel_id: [7; 16],
                correlation_id: Arc::from(op_id),
                delivery_id: Arc::from(delivery_id),
                device_key: Arc::from("provider-worker-device"),
                device_token: Arc::from("provider-worker-token"),
                route_updated_at: now,
                direct_payload: payload,
                direct_body: Arc::from(Vec::<u8>::new()),
                wakeup_payload: None,
                wakeup_body: None,
                initial_path: ProviderDeliveryPath::Direct,
                wakeup_payload_within_limit: false,
                outcome: Some(outcome.clone()),
            })
            .expect("enqueue FCM job");
        assert_eq!(
            fcm.calls.load(Ordering::SeqCst),
            0,
            "worker must wait for commit"
        );
        outcome.commit();

        if finalize_failures > 0 {
            for _ in 0..100 {
                if store.provider_finalize_failures_remaining() < finalize_failures {
                    break;
                }
                sleep(Duration::from_millis(1)).await;
            }
            assert!(
                store.provider_finalize_failures_remaining() < finalize_failures,
                "worker should attempt provider outcome persistence"
            );
            let pending_record = store
                .load_sender_submit_status(op_id)
                .await
                .expect("load pending worker sender status")
                .expect("pending worker sender status should exist");
            assert_eq!(
                pending_record.status,
                SenderSubmitStatusKind::ProviderQueued,
                "a failed finalization attempt must not be treated as completion"
            );
        }

        let expected_status = if success {
            SenderSubmitStatusKind::Sent
        } else {
            SenderSubmitStatusKind::PartiallyFailed
        };
        let mut final_record = None;
        for _ in 0..100 {
            let record = store
                .load_sender_submit_status(op_id)
                .await
                .expect("load worker sender status")
                .expect("worker sender status should exist");
            if record.status == expected_status {
                final_record = Some(record);
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        let final_record = final_record.expect("worker result should reach a durable final state");
        assert_eq!(fcm.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            final_record.dispatch_status.as_deref(),
            Some(if success {
                "provider_success"
            } else {
                "provider_failed"
            })
        );
        let replay = store
            .reserve_op_dedupe_pending(op_id, delivery_id, now + 1)
            .await
            .expect("load final op dedupe state");
        assert!(
            matches!(
                (success, replay),
                (true, OpDedupeReservation::Sent { .. })
                    | (false, OpDedupeReservation::PartialFailure { .. })
            ),
            "provider result and op dedupe must finalize together"
        );

        drop(dispatch);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let worker_report = workers.shutdown_until(deadline).await;
        assert_eq!(worker_report.panicked, 0);
        assert_eq!(worker_report.aborted, 0);
        assert_eq!(
            worker_report.joined,
            DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Small).worker_count * 4
        );

        let counter_report = runtime_counters.shutdown_until(deadline).await;
        assert_eq!(counter_report.panicked, 0);
        assert_eq!(counter_report.aborted, 0);
        assert_eq!(counter_report.joined, 1);
    }

    #[tokio::test]
    async fn fcm_worker_persists_provider_success_after_actual_send() {
        assert_fcm_worker_persists_final_provider_result(true, 0).await;
    }

    #[tokio::test]
    async fn fcm_worker_persists_provider_failure_after_actual_send() {
        assert_fcm_worker_persists_final_provider_result(false, 0).await;
    }

    #[tokio::test]
    async fn fcm_worker_retries_provider_success_until_final_state_is_persisted() {
        assert_fcm_worker_persists_final_provider_result(true, 2).await;
    }

    #[tokio::test]
    async fn fcm_worker_retries_provider_failure_until_final_state_is_persisted() {
        assert_fcm_worker_persists_final_provider_result(false, 2).await;
    }
}
