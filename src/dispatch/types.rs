use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderDeliveryPath {
    Direct,
    WakeupPull,
}

impl ProviderDeliveryPath {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProviderDeliveryPath::Direct => "direct",
            ProviderDeliveryPath::WakeupPull => "wakeup_pull",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProviderPullDelivery {
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
}

#[derive(Clone)]
pub(crate) struct DispatchChannels {
    apns_tx: Sender<ApnsJob>,
    fcm_tx: Sender<FcmJob>,
    wns_tx: Sender<WnsJob>,
}

pub(crate) struct DispatchWorkerReceivers {
    pub(super) apns: Receiver<ApnsJob>,
    pub(super) fcm: Receiver<FcmJob>,
    pub(super) wns: Receiver<WnsJob>,
}

#[derive(Debug)]
pub(crate) enum DispatchError {
    QueueFull,
    ChannelClosed,
}

impl DispatchChannels {
    pub(crate) fn new() -> (Self, DispatchWorkerReceivers) {
        let config = DispatchRuntimeConfig::from_env();
        let (apns_tx, apns_rx) = flume::bounded(config.queue_capacity);
        let (fcm_tx, fcm_rx) = flume::bounded(config.queue_capacity);
        let (wns_tx, wns_rx) = flume::bounded(config.queue_capacity);
        (
            Self {
                apns_tx,
                fcm_tx,
                wns_tx,
            },
            DispatchWorkerReceivers {
                apns: apns_rx,
                fcm: fcm_rx,
                wns: wns_rx,
            },
        )
    }

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
