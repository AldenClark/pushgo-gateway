use std::{sync::Arc, time::Duration};

use flume::{Receiver, Sender, TrySendError};
use hashbrown::HashMap;

pub(crate) mod audit;

use self::audit::{DispatchAuditLog, DispatchAuditRecord};

use crate::{
    private::PrivateState,
    providers::{
        ApnsClient, DispatchResult, FcmClient, WnsClient, apns::ApnsPayload, fcm::FcmPayload,
        wns::WnsPayload,
    },
    storage::{Platform, PrivateMessage, Storage},
    util::{build_wakeup_data, encode_crockford_base32_128},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderDeliveryPath {
    Direct,
    WakeupPull,
}

#[derive(Clone)]
pub(crate) struct PrivateWakeupDelivery {
    pub device_id: [u8; 16],
    pub platform: Platform,
    pub provider_token: Arc<str>,
    pub delivery_id: Arc<str>,
    pub payload: Arc<Vec<u8>>,
    pub sent_at: i64,
    pub expires_at: i64,
}

pub(crate) struct ApnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_token: Arc<str>,
    pub platform: Platform,
    pub direct_payload: Arc<ApnsPayload>,
    pub wakeup_payload: Option<Arc<ApnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
    pub collapse_id: Option<Arc<str>>,
}

pub(crate) struct FcmJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_token: Arc<str>,
    pub direct_payload: Arc<FcmPayload>,
    pub direct_body: Arc<[u8]>,
    pub wakeup_payload: Option<Arc<FcmPayload>>,
    pub wakeup_body: Option<Arc<[u8]>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
}

pub(crate) struct WnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_token: Arc<str>,
    pub direct_payload: Arc<WnsPayload>,
    pub wakeup_payload: Option<Arc<WnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
}

#[derive(Clone)]
pub(crate) struct DispatchChannels {
    apns_tx: Sender<ApnsJob>,
    fcm_tx: Sender<FcmJob>,
    wns_tx: Sender<WnsJob>,
}

#[derive(Debug)]
pub(crate) enum DispatchError {
    QueueFull,
    ChannelClosed,
}

impl DispatchChannels {
    pub(crate) fn try_send_apns(&self, job: ApnsJob) -> Result<(), DispatchError> {
        match self.apns_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(DispatchError::ChannelClosed),
        }
    }

    pub(crate) fn try_send_fcm(&self, job: FcmJob) -> Result<(), DispatchError> {
        match self.fcm_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(DispatchError::ChannelClosed),
        }
    }

    pub(crate) fn try_send_wns(&self, job: WnsJob) -> Result<(), DispatchError> {
        match self.wns_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(DispatchError::ChannelClosed),
        }
    }
}

pub(crate) fn create_dispatch_channels() -> (
    DispatchChannels,
    Receiver<ApnsJob>,
    Receiver<FcmJob>,
    Receiver<WnsJob>,
) {
    let capacity = auto_dispatch_queue_capacity();
    let (apns_tx, apns_rx) = flume::bounded(capacity);
    let (fcm_tx, fcm_rx) = flume::bounded(capacity);
    let (wns_tx, wns_rx) = flume::bounded(capacity);
    (
        DispatchChannels {
            apns_tx,
            fcm_tx,
            wns_tx,
        },
        apns_rx,
        fcm_rx,
        wns_rx,
    )
}

pub(crate) struct DispatchWorkerDeps {
    pub apns: Arc<dyn ApnsClient>,
    pub fcm: Arc<dyn FcmClient>,
    pub wns: Arc<dyn WnsClient>,
    pub store: Storage,
    pub private: Option<Arc<PrivateState>>,
    pub audit: Arc<DispatchAuditLog>,
}

pub(crate) fn spawn_dispatch_workers(
    apns_rx: Receiver<ApnsJob>,
    fcm_rx: Receiver<FcmJob>,
    wns_rx: Receiver<WnsJob>,
    deps: DispatchWorkerDeps,
) {
    let DispatchWorkerDeps {
        apns,
        fcm,
        wns,
        store,
        private,
        audit,
    } = deps;
    spawn_apns_worker(apns_rx, apns, store.clone(), private.clone(), audit.clone());
    spawn_fcm_worker(fcm_rx, fcm, store.clone(), private.clone(), audit.clone());
    spawn_wns_worker(wns_rx, wns, store, private, audit);
}

fn spawn_apns_worker(
    apns_rx: Receiver<ApnsJob>,
    apns: Arc<dyn ApnsClient>,
    store: Storage,
    private: Option<Arc<PrivateState>>,
    audit: Arc<DispatchAuditLog>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let apns_rx = apns_rx.clone();
        let apns = Arc::clone(&apns);
        let store = store.clone();
        let private = private.clone();
        let audit = audit.clone();
        tokio::spawn(async move {
            while let Ok(job) = apns_rx.recv_async().await {
                let apns_client = Arc::clone(&apns);
                let store_api = store.clone();
                let private_state = private.clone();
                let channel_id = encode_crockford_base32_128(&job.channel_id);
                let actual_path = job.initial_path;
                let mut payload = match actual_path {
                    ProviderDeliveryPath::Direct => Arc::clone(&job.direct_payload),
                    ProviderDeliveryPath::WakeupPull => Arc::clone(
                        job.wakeup_payload
                            .as_ref()
                            .expect("wakeup payload required for wakeup path"),
                    ),
                };
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    let _ = enqueue_private_wakeup_delivery(
                        &store_api,
                        private_state.as_deref(),
                        private_meta,
                        "APNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
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
                    && dispatch.payload_too_large
                    && job.wakeup_payload_within_limit
                    && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                {
                    payload = Arc::clone(wakeup_payload);
                    if let Some(private_meta) = job.private_wakeup.as_ref() {
                        let _ = enqueue_private_wakeup_delivery(
                            &store_api,
                            private_state.as_deref(),
                            private_meta,
                            "APNS",
                            job.correlation_id.as_ref(),
                            &channel_id,
                        )
                        .await;
                    }
                    dispatch = apns_client
                        .send_to_device(
                            job.device_token.as_ref(),
                            job.platform,
                            Arc::clone(&payload),
                            job.collapse_id.clone(),
                        )
                        .await;
                }
                record_provider_dispatch_result(
                    &audit,
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
                    log_provider_dispatch_failure(
                        "APNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                        actual_path,
                        Some(job.platform),
                        job.device_token.as_ref(),
                        &dispatch,
                    );
                }
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel(
                            job.channel_id,
                            job.device_token.as_ref(),
                            job.platform,
                        )
                        .await;
                    cleanup_private_outbox_on_invalid_token(
                        &store_api,
                        private_state.as_deref(),
                        job.platform,
                        job.device_token.as_ref(),
                        "APNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
            }
        });
    }
}

fn spawn_fcm_worker(
    fcm_rx: Receiver<FcmJob>,
    fcm: Arc<dyn FcmClient>,
    store: Storage,
    private: Option<Arc<PrivateState>>,
    audit: Arc<DispatchAuditLog>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let fcm_rx = fcm_rx.clone();
        let fcm = Arc::clone(&fcm);
        let store = store.clone();
        let private = private.clone();
        let audit = audit.clone();
        tokio::spawn(async move {
            while let Ok(job) = fcm_rx.recv_async().await {
                let fcm_client = Arc::clone(&fcm);
                let store_api = store.clone();
                let private_state = private.clone();
                let channel_id = encode_crockford_base32_128(&job.channel_id);
                let actual_path = job.initial_path;
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
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    let _ = enqueue_private_wakeup_delivery(
                        &store_api,
                        private_state.as_deref(),
                        private_meta,
                        "FCM",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
                let mut dispatch = fcm_client
                    .send_to_device(
                        job.device_token.as_ref(),
                        Arc::clone(&payload),
                        Some(Arc::clone(&body)),
                    )
                    .await;
                if !dispatch.success
                    && actual_path == ProviderDeliveryPath::Direct
                    && dispatch.payload_too_large
                    && job.wakeup_payload_within_limit
                    && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                {
                    payload = Arc::clone(wakeup_payload);
                    body = Arc::clone(
                        job.wakeup_body
                            .as_ref()
                            .expect("wakeup body required when wakeup payload exists"),
                    );
                    if let Some(private_meta) = job.private_wakeup.as_ref() {
                        let _ = enqueue_private_wakeup_delivery(
                            &store_api,
                            private_state.as_deref(),
                            private_meta,
                            "FCM",
                            job.correlation_id.as_ref(),
                            &channel_id,
                        )
                        .await;
                    }
                    dispatch = fcm_client
                        .send_to_device(job.device_token.as_ref(), Arc::clone(&payload), Some(body))
                        .await;
                }
                record_provider_dispatch_result(
                    &audit,
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
                    log_provider_dispatch_failure(
                        "FCM",
                        job.correlation_id.as_ref(),
                        &channel_id,
                        actual_path,
                        Some(Platform::ANDROID),
                        job.device_token.as_ref(),
                        &dispatch,
                    );
                }
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel(
                            job.channel_id,
                            job.device_token.as_ref(),
                            Platform::ANDROID,
                        )
                        .await;
                    cleanup_private_outbox_on_invalid_token(
                        &store_api,
                        private_state.as_deref(),
                        Platform::ANDROID,
                        job.device_token.as_ref(),
                        "FCM",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
            }
        });
    }
}

fn spawn_wns_worker(
    wns_rx: Receiver<WnsJob>,
    wns: Arc<dyn WnsClient>,
    store: Storage,
    private: Option<Arc<PrivateState>>,
    audit: Arc<DispatchAuditLog>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let wns_rx = wns_rx.clone();
        let wns = Arc::clone(&wns);
        let store = store.clone();
        let private = private.clone();
        let audit = audit.clone();
        tokio::spawn(async move {
            while let Ok(job) = wns_rx.recv_async().await {
                let wns_client = Arc::clone(&wns);
                let store_api = store.clone();
                let private_state = private.clone();
                let channel_id = encode_crockford_base32_128(&job.channel_id);
                let actual_path = job.initial_path;
                let mut payload = match actual_path {
                    ProviderDeliveryPath::Direct => Arc::clone(&job.direct_payload),
                    ProviderDeliveryPath::WakeupPull => Arc::clone(
                        job.wakeup_payload
                            .as_ref()
                            .expect("wakeup payload required for wakeup path"),
                    ),
                };
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    let _ = enqueue_private_wakeup_delivery(
                        &store_api,
                        private_state.as_deref(),
                        private_meta,
                        "WNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
                let mut dispatch = wns_client
                    .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                    .await;
                if !dispatch.success
                    && actual_path == ProviderDeliveryPath::Direct
                    && dispatch.payload_too_large
                    && job.wakeup_payload_within_limit
                    && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                {
                    payload = Arc::clone(wakeup_payload);
                    if let Some(private_meta) = job.private_wakeup.as_ref() {
                        let _ = enqueue_private_wakeup_delivery(
                            &store_api,
                            private_state.as_deref(),
                            private_meta,
                            "WNS",
                            job.correlation_id.as_ref(),
                            &channel_id,
                        )
                        .await;
                    }
                    dispatch = wns_client
                        .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                        .await;
                }
                record_provider_dispatch_result(
                    &audit,
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
                    log_provider_dispatch_failure(
                        "WNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                        actual_path,
                        Some(Platform::WINDOWS),
                        job.device_token.as_ref(),
                        &dispatch,
                    );
                }
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel(
                            job.channel_id,
                            job.device_token.as_ref(),
                            Platform::WINDOWS,
                        )
                        .await;
                    cleanup_private_outbox_on_invalid_token(
                        &store_api,
                        private_state.as_deref(),
                        Platform::WINDOWS,
                        job.device_token.as_ref(),
                        "WNS",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
            }
        });
    }
}

async fn enqueue_private_wakeup_delivery(
    store: &Storage,
    private: Option<&PrivateState>,
    delivery: &PrivateWakeupDelivery,
    provider: &str,
    correlation_id: &str,
    channel_id: &str,
) -> bool {
    let message = PrivateMessage {
        payload: delivery.payload.as_ref().clone(),
        size: delivery.payload.len(),
        sent_at: delivery.sent_at,
        expires_at: delivery.expires_at,
    };
    match store
        .enqueue_provider_pull_item(
            delivery.delivery_id.as_ref(),
            &message,
            delivery.platform,
            delivery.provider_token.as_ref(),
            delivery
                .sent_at
                .saturating_add(provider_pull_retry_timeout_secs() as i64),
        )
        .await
    {
        Ok(()) => true,
        Err(err) => {
            if let Some(private_state) = private {
                private_state.metrics.mark_enqueue_failure();
            }
            crate::util::diagnostics_log(format_args!(
                "provider wakeup pull cache enqueue failed provider={} correlation_id={} channel_id={} device_id={} delivery_id={} error={}",
                provider,
                correlation_id,
                channel_id,
                encode_crockford_base32_128(&delivery.device_id),
                delivery.delivery_id,
                err,
            ));
            false
        }
    }
}

async fn cleanup_private_outbox_on_invalid_token(
    store: &Storage,
    private: Option<&PrivateState>,
    platform: Platform,
    device_token: &str,
    provider: &str,
    correlation_id: &str,
    channel_id: &str,
) {
    let device_id = match store.lookup_private_device(platform, device_token).await {
        Ok(value) => value,
        Err(err) => {
            crate::util::diagnostics_log(format_args!(
                "invalid token cleanup lookup failed provider={} correlation_id={} channel_id={} platform={} device_token={} error={}",
                provider,
                correlation_id,
                channel_id,
                platform_label(platform),
                redact_device_token(device_token),
                err,
            ));
            return;
        }
    };
    let Some(device_id) = device_id else {
        return;
    };
    let cleared_result = if let Some(private_state) = private {
        private_state.clear_device_outbox(device_id).await
    } else {
        store
            .clear_private_outbox_for_device(device_id)
            .await
            .map(|entries| entries.len())
            .map_err(|err| crate::Error::Internal(err.to_string()))
    };
    match cleared_result {
        Ok(_cleared) => {}
        Err(err) => {
            crate::util::diagnostics_log(format_args!(
                "invalid token cleanup outbox clear failed provider={} correlation_id={} channel_id={} platform={} device_id={} error={}",
                provider,
                correlation_id,
                channel_id,
                platform_label(platform),
                encode_crockford_base32_128(&device_id),
                err,
            ));
        }
    }
}

fn log_provider_dispatch_failure(
    provider: &str,
    correlation_id: &str,
    channel_id: &str,
    path: ProviderDeliveryPath,
    platform: Option<Platform>,
    device_token: &str,
    dispatch: &DispatchResult,
) {
    let error = dispatch
        .error
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    crate::util::diagnostics_log(format_args!(
        "provider dispatch failed provider={} correlation_id={} channel_id={} path={} platform={} device_token={} status_code={} invalid_token={} payload_too_large={} error={}",
        provider,
        correlation_id,
        channel_id,
        delivery_path_label(path),
        platform.map(platform_label).unwrap_or("unknown"),
        redact_device_token(device_token),
        dispatch.status_code,
        dispatch.invalid_token,
        dispatch.payload_too_large,
        error,
    ));
}

#[allow(clippy::too_many_arguments)]
fn record_provider_dispatch_result(
    audit: &DispatchAuditLog,
    provider: &'static str,
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    path: ProviderDeliveryPath,
    platform: Option<Platform>,
    device_token: &str,
    dispatch: &DispatchResult,
) {
    audit.record(DispatchAuditRecord {
        stage: "provider_send_result",
        correlation_id,
        delivery_id: Some(delivery_id),
        channel_id: Some(channel_id),
        provider: Some(provider),
        platform,
        path: Some(delivery_path_label(path)),
        device_token: Some(device_token),
        success: Some(dispatch.success),
        status_code: Some(dispatch.status_code),
        invalid_token: Some(dispatch.invalid_token),
        payload_too_large: Some(dispatch.payload_too_large),
        detail: dispatch.error.as_ref().map(|err| err.to_string().into()),
    });
}

pub(crate) fn spawn_provider_pull_retry_worker(
    store: Storage,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
    audit: Arc<DispatchAuditLog>,
) {
    tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now().timestamp();
            let due_entries = match store
                .list_provider_pull_retry_due(now, provider_pull_retry_batch_size())
                .await
            {
                Ok(entries) => entries,
                Err(err) => {
                    crate::util::diagnostics_log(format_args!(
                        "provider pull retry load due failed error={}",
                        err
                    ));
                    tokio::time::sleep(Duration::from_millis(provider_pull_retry_poll_ms())).await;
                    continue;
                }
            };

            for entry in due_entries {
                let dispatch = send_provider_retry_wakeup(
                    &entry,
                    Arc::clone(&apns),
                    Arc::clone(&fcm),
                    Arc::clone(&wns),
                )
                .await;
                audit.record(DispatchAuditRecord {
                    stage: "provider_pull_retry_send_result",
                    correlation_id: "provider_pull_retry",
                    delivery_id: Some(entry.delivery_id.as_str()),
                    channel_id: None,
                    provider: Some(provider_name_for_platform(entry.platform)),
                    platform: Some(entry.platform),
                    path: Some("wakeup_pull"),
                    device_token: Some(entry.provider_token.as_str()),
                    success: Some(dispatch.success),
                    status_code: Some(dispatch.status_code),
                    invalid_token: Some(dispatch.invalid_token),
                    payload_too_large: Some(dispatch.payload_too_large),
                    detail: dispatch.error.as_ref().map(|err| err.to_string().into()),
                });

                if dispatch.invalid_token || entry.expires_at <= now {
                    let _ = store
                        .clear_provider_pull_retry(entry.delivery_id.as_str())
                        .await;
                    continue;
                }

                let next_retry_at = now.saturating_add(provider_pull_retry_timeout_secs() as i64);
                let _ = store
                    .bump_provider_pull_retry(entry.delivery_id.as_str(), next_retry_at, now)
                    .await;
            }

            tokio::time::sleep(Duration::from_millis(provider_pull_retry_poll_ms())).await;
        }
    });
}

async fn send_provider_retry_wakeup(
    entry: &crate::storage::ProviderPullRetryEntry,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
) -> DispatchResult {
    let data = provider_retry_wakeup_data(entry.delivery_id.as_str());
    match entry.platform {
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => {
            let payload = Arc::new(ApnsPayload::wakeup(
                None,
                None,
                Some(entry.expires_at),
                data,
            ));
            apns.send_to_device(entry.provider_token.as_str(), entry.platform, payload, None)
                .await
        }
        Platform::ANDROID => {
            let payload = Arc::new(FcmPayload::new(data, "HIGH", None));
            fcm.send_to_device(entry.provider_token.as_str(), payload, None)
                .await
        }
        Platform::WINDOWS => {
            let payload = Arc::new(WnsPayload::new(data, "high", None));
            wns.send_to_device(entry.provider_token.as_str(), payload)
                .await
        }
    }
}

fn provider_retry_wakeup_data(delivery_id: &str) -> HashMap<String, String> {
    let mut base = HashMap::new();
    base.insert("delivery_id".to_string(), delivery_id.to_string());
    build_wakeup_data(&base)
}

fn delivery_path_label(path: ProviderDeliveryPath) -> &'static str {
    match path {
        ProviderDeliveryPath::Direct => "direct",
        ProviderDeliveryPath::WakeupPull => "wakeup_pull",
    }
}

fn provider_name_for_platform(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => "APNS",
        Platform::ANDROID => "FCM",
        Platform::WINDOWS => "WNS",
    }
}

fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}

fn auto_dispatch_worker_count() -> usize {
    if let Some(configured) = std::env::var("PUSHGO_DISPATCH_WORKER_COUNT")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return configured.clamp(2, 256);
    }
    let cpu = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    (cpu * 2).clamp(4, 64)
}

fn auto_dispatch_queue_capacity() -> usize {
    if let Some(configured) = std::env::var("PUSHGO_DISPATCH_QUEUE_CAPACITY")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return configured.clamp(256, 131_072);
    }
    (auto_dispatch_worker_count() * 64).clamp(1024, 32_768)
}

fn provider_pull_retry_poll_ms() -> u64 {
    std::env::var("PUSHGO_PROVIDER_PULL_RETRY_POLL_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(200, 5_000))
        .unwrap_or(1_000)
}

fn provider_pull_retry_batch_size() -> usize {
    std::env::var("PUSHGO_PROVIDER_PULL_RETRY_BATCH")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(1, 2_000))
        .unwrap_or(200)
}

fn provider_pull_retry_timeout_secs() -> u64 {
    std::env::var("PUSHGO_PROVIDER_PULL_RETRY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(5, 600))
        .unwrap_or(30)
}

#[cfg(test)]
mod tests {
    use super::provider_retry_wakeup_data;

    #[test]
    fn provider_retry_wakeup_data_contains_wakeup_markers() {
        let data = provider_retry_wakeup_data("delivery-001");
        assert_eq!(
            data.get("delivery_id").map(String::as_str),
            Some("delivery-001")
        );
        assert_eq!(data.get("private_mode").map(String::as_str), Some("wakeup"));
        assert_eq!(data.get("private_wakeup").map(String::as_str), Some("1"));
    }
}
