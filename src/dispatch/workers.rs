use super::runtime::ProviderDispatchFailureLog;
use super::*;
use crate::stats::StatsCollector;
use tracing::Instrument;

pub(crate) struct DispatchWorkerDeps {
    pub apns: Arc<dyn ApnsClient>,
    pub fcm: Arc<dyn FcmClient>,
    pub wns: Arc<dyn WnsClient>,
    pub store: Storage,
    pub private: Option<Arc<PrivateState>>,
    pub stats: Arc<StatsCollector>,
    pub runtime_profile: GatewayRuntimeProfile,
}

impl DispatchWorkerDeps {
    pub(crate) fn spawn(self, receivers: DispatchWorkerReceivers) {
        let runtime = DispatchWorkerRuntime {
            store: self.store,
            private: self.private,
            stats: self.stats,
        };
        let pool = DispatchWorkerPool {
            apns: self.apns,
            fcm: self.fcm,
            wns: self.wns,
            runtime,
            config: DispatchRuntimeConfig::from_profile(self.runtime_profile),
        };
        pool.spawn(receivers);
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
    fn spawn(self, receivers: DispatchWorkerReceivers) {
        self.spawn_apns_workers(receivers.apns);
        self.spawn_fcm_workers(receivers.fcm);
        self.spawn_wns_workers(receivers.wns);
    }

    fn spawn_apns_workers(&self, apns_rx: Receiver<ApnsJob>) {
        for worker_slot in 0..self.config.worker_count {
            let apns_rx = apns_rx.clone();
            let apns = Arc::clone(&self.apns);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "APNS",
                worker_slot = worker_slot
            );
            tokio::spawn(
                async move {
                    emit_dispatch_worker_started("APNS", worker_slot);
                    while let Ok(job) = apns_rx.recv_async().await {
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
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(job.platform),
                            job.device_token.as_ref(),
                            &dispatch,
                        );
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
                            let _ = runtime
                                .store
                                .unsubscribe_channel_for_device_key(
                                    job.channel_id,
                                    job.device_key.as_ref(),
                                )
                                .await;
                            runtime
                                .cleanup_private_outbox_on_invalid_token(
                                    job.platform,
                                    job.device_token.as_ref(),
                                    "APNS",
                                    job.correlation_id.as_ref(),
                                    &channel_id,
                                )
                                .await;
                        }
                    }
                    emit_dispatch_worker_stopped("APNS", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
        }
    }

    fn spawn_fcm_workers(&self, fcm_rx: Receiver<FcmJob>) {
        for worker_slot in 0..self.config.worker_count {
            let fcm_rx = fcm_rx.clone();
            let fcm = Arc::clone(&self.fcm);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "FCM",
                worker_slot = worker_slot
            );
            tokio::spawn(
                async move {
                    emit_dispatch_worker_started("FCM", worker_slot);
                    while let Ok(job) = fcm_rx.recv_async().await {
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
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(Platform::ANDROID),
                            job.device_token.as_ref(),
                            &dispatch,
                        );
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
                            let _ = runtime
                                .store
                                .unsubscribe_channel_for_device_key(
                                    job.channel_id,
                                    job.device_key.as_ref(),
                                )
                                .await;
                            runtime
                                .cleanup_private_outbox_on_invalid_token(
                                    Platform::ANDROID,
                                    job.device_token.as_ref(),
                                    "FCM",
                                    job.correlation_id.as_ref(),
                                    &channel_id,
                                )
                                .await;
                        }
                    }
                    emit_dispatch_worker_stopped("FCM", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
        }
    }

    fn spawn_wns_workers(&self, wns_rx: Receiver<WnsJob>) {
        for worker_slot in 0..self.config.worker_count {
            let wns_rx = wns_rx.clone();
            let wns = Arc::clone(&self.wns);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "WNS",
                worker_slot = worker_slot
            );
            tokio::spawn(
                async move {
                    emit_dispatch_worker_started("WNS", worker_slot);
                    while let Ok(job) = wns_rx.recv_async().await {
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
                            job.correlation_id.as_ref(),
                            job.delivery_id.as_ref(),
                            &channel_id,
                            actual_path,
                            Some(Platform::WINDOWS),
                            job.device_token.as_ref(),
                            &dispatch,
                        );
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
                            let _ = runtime
                                .store
                                .unsubscribe_channel_for_device_key(
                                    job.channel_id,
                                    job.device_key.as_ref(),
                                )
                                .await;
                            runtime
                                .cleanup_private_outbox_on_invalid_token(
                                    Platform::WINDOWS,
                                    job.device_token.as_ref(),
                                    "WNS",
                                    job.correlation_id.as_ref(),
                                    &channel_id,
                                )
                                .await;
                        }
                    }
                    emit_dispatch_worker_stopped("WNS", worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
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
