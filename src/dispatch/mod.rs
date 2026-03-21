use std::sync::Arc;

use async_channel::{Receiver, Sender, TrySendError};

use crate::{
    private::PrivateState,
    providers::{
        ApnsClient, FcmClient, WnsClient, apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload,
    },
    storage::{Platform, Store},
    util::encode_crockford_base32_128,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderDeliveryPath {
    Direct,
    WakeupPull,
}

#[derive(Clone)]
pub(crate) struct PrivateWakeupDelivery {
    pub device_id: [u8; 16],
    pub delivery_id: Arc<str>,
    pub payload: Arc<Vec<u8>>,
    pub sent_at: i64,
    pub expires_at: i64,
}

pub(crate) struct ApnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub device_token: Arc<str>,
    pub platform: Platform,
    pub direct_payload: Arc<ApnsPayload>,
    pub wakeup_payload: Option<Arc<ApnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
    pub private_wakeup_enqueued: bool,
    pub collapse_id: Option<Arc<str>>,
}

pub(crate) struct FcmJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub device_token: Arc<str>,
    pub direct_payload: Arc<FcmPayload>,
    pub wakeup_payload: Option<Arc<FcmPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
    pub private_wakeup_enqueued: bool,
}

pub(crate) struct WnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub device_token: Arc<str>,
    pub direct_payload: Arc<WnsPayload>,
    pub wakeup_payload: Option<Arc<WnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub private_wakeup: Option<PrivateWakeupDelivery>,
    pub private_wakeup_enqueued: bool,
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
            Err(TrySendError::Closed(_)) => Err(DispatchError::ChannelClosed),
        }
    }

    pub(crate) fn try_send_fcm(&self, job: FcmJob) -> Result<(), DispatchError> {
        match self.fcm_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(DispatchError::ChannelClosed),
        }
    }

    pub(crate) fn try_send_wns(&self, job: WnsJob) -> Result<(), DispatchError> {
        match self.wns_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(DispatchError::ChannelClosed),
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
    let (apns_tx, apns_rx) = async_channel::bounded(capacity);
    let (fcm_tx, fcm_rx) = async_channel::bounded(capacity);
    let (wns_tx, wns_rx) = async_channel::bounded(capacity);
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
    pub store: Store,
    pub private: Option<Arc<PrivateState>>,
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
    } = deps;
    spawn_apns_worker(apns_rx, apns, Arc::clone(&store), private.clone());
    spawn_fcm_worker(fcm_rx, fcm, Arc::clone(&store), private.clone());
    spawn_wns_worker(wns_rx, wns, store, private);
}

fn spawn_apns_worker(
    apns_rx: Receiver<ApnsJob>,
    apns: Arc<dyn ApnsClient>,
    store: Store,
    private: Option<Arc<PrivateState>>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let apns_rx = apns_rx.clone();
        let apns = Arc::clone(&apns);
        let store = Arc::clone(&store);
        let private = private.clone();
        tokio::spawn(async move {
            while let Ok(job) = apns_rx.recv().await {
                let apns_client = Arc::clone(&apns);
                let store_api = Arc::clone(&store);
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
                let mut private_wakeup_enqueued = job.private_wakeup_enqueued;
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && !private_wakeup_enqueued
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    private_wakeup_enqueued = enqueue_private_wakeup_delivery(
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
                    if !private_wakeup_enqueued
                        && let Some(private_meta) = job.private_wakeup.as_ref()
                    {
                        let _ = enqueue_private_wakeup_delivery(
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
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel_async(
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
    store: Store,
    private: Option<Arc<PrivateState>>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let fcm_rx = fcm_rx.clone();
        let fcm = Arc::clone(&fcm);
        let store = Arc::clone(&store);
        let private = private.clone();
        tokio::spawn(async move {
            while let Ok(job) = fcm_rx.recv().await {
                let fcm_client = Arc::clone(&fcm);
                let store_api = Arc::clone(&store);
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
                let mut private_wakeup_enqueued = job.private_wakeup_enqueued;
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && !private_wakeup_enqueued
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    private_wakeup_enqueued = enqueue_private_wakeup_delivery(
                        private_state.as_deref(),
                        private_meta,
                        "FCM",
                        job.correlation_id.as_ref(),
                        &channel_id,
                    )
                    .await;
                }
                let mut dispatch = fcm_client
                    .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                    .await;
                if !dispatch.success
                    && actual_path == ProviderDeliveryPath::Direct
                    && dispatch.payload_too_large
                    && job.wakeup_payload_within_limit
                    && let Some(wakeup_payload) = job.wakeup_payload.as_ref()
                {
                    payload = Arc::clone(wakeup_payload);
                    if !private_wakeup_enqueued
                        && let Some(private_meta) = job.private_wakeup.as_ref()
                    {
                        let _ = enqueue_private_wakeup_delivery(
                            private_state.as_deref(),
                            private_meta,
                            "FCM",
                            job.correlation_id.as_ref(),
                            &channel_id,
                        )
                        .await;
                    }
                    dispatch = fcm_client
                        .send_to_device(job.device_token.as_ref(), Arc::clone(&payload))
                        .await;
                }
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel_async(
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
    store: Store,
    private: Option<Arc<PrivateState>>,
) {
    for _ in 0..auto_dispatch_worker_count() {
        let wns_rx = wns_rx.clone();
        let wns = Arc::clone(&wns);
        let store = Arc::clone(&store);
        let private = private.clone();
        tokio::spawn(async move {
            while let Ok(job) = wns_rx.recv().await {
                let wns_client = Arc::clone(&wns);
                let store_api = Arc::clone(&store);
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
                let mut private_wakeup_enqueued = job.private_wakeup_enqueued;
                if actual_path == ProviderDeliveryPath::WakeupPull
                    && !private_wakeup_enqueued
                    && let Some(private_meta) = job.private_wakeup.as_ref()
                {
                    private_wakeup_enqueued = enqueue_private_wakeup_delivery(
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
                    if !private_wakeup_enqueued
                        && let Some(private_meta) = job.private_wakeup.as_ref()
                    {
                        let _ = enqueue_private_wakeup_delivery(
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
                if dispatch.invalid_token {
                    let _ = store_api
                        .unsubscribe_channel_async(
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
    private: Option<&PrivateState>,
    delivery: &PrivateWakeupDelivery,
    _provider: &str,
    _correlation_id: &str,
    _channel_id: &str,
) -> bool {
    let Some(private_state) = private else {
        return false;
    };
    match private_state
        .enqueue_private_delivery(
            delivery.device_id,
            delivery.delivery_id.as_ref(),
            delivery.payload.as_ref().clone(),
            delivery.sent_at,
            delivery.expires_at,
        )
        .await
    {
        Ok(()) => true,
        Err(_err) => {
            private_state.metrics.mark_enqueue_failure();
            false
        }
    }
}

async fn cleanup_private_outbox_on_invalid_token(
    store: &Store,
    private: Option<&PrivateState>,
    platform: Platform,
    device_token: &str,
    _provider: &str,
    _correlation_id: &str,
    _channel_id: &str,
) {
    let device_id = match store
        .lookup_private_device_async(platform, device_token)
        .await
    {
        Ok(value) => value,
        Err(_err) => {
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
            .clear_private_outbox_for_device_async(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    };
    match cleared_result {
        Ok(_cleared) => {}
        Err(_err) => {}
    }
}

fn auto_dispatch_worker_count() -> usize {
    let cpu = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    (cpu * 8).clamp(8, 256)
}

fn auto_dispatch_queue_capacity() -> usize {
    (auto_dispatch_worker_count() * 64).clamp(2048, 65_536)
}
