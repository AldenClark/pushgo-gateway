use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

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
}

pub(crate) struct ProviderDispatchOutcome {
    op_id: Arc<str>,
    delivery_id: Arc<str>,
    expected: AtomicUsize,
    completed: AtomicUsize,
    failed: AtomicUsize,
    committed: AtomicBool,
    cancelled: AtomicBool,
    commit_notify: Notify,
    #[cfg(test)]
    before_wait_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// Owns the pre-send decision for provider jobs. If the dispatch lifecycle
/// unwinds or its task is aborted before a decision is published, dropping the
/// lease cancels every waiting worker instead of leaving it blocked forever.
pub(crate) struct ProviderDispatchOutcomeLease {
    outcome: Arc<ProviderDispatchOutcome>,
    decided: bool,
}

impl ProviderDispatchOutcomeLease {
    pub(crate) fn new(outcome: Arc<ProviderDispatchOutcome>) -> Self {
        Self {
            outcome,
            decided: false,
        }
    }

    pub(crate) fn commit(&mut self) -> Option<bool> {
        self.decided = true;
        self.outcome.commit()
    }

    pub(crate) fn cancel(&mut self) {
        self.decided = true;
        self.outcome.cancel();
    }
}

impl Drop for ProviderDispatchOutcomeLease {
    fn drop(&mut self) {
        if !self.decided {
            self.outcome.cancel();
        }
    }
}

impl ProviderDispatchOutcome {
    pub(crate) fn new(op_id: Arc<str>, delivery_id: Arc<str>) -> Self {
        Self {
            op_id,
            delivery_id,
            expected: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            committed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            commit_notify: Notify::new(),
            #[cfg(test)]
            before_wait_hook: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn configure(&self, expected: usize, already_failed: usize) {
        self.expected.store(expected, Ordering::Release);
        self.completed.store(already_failed, Ordering::Release);
        self.failed.store(already_failed, Ordering::Release);
    }

    pub(crate) fn record_failure(&self) {
        self.record_failures(1);
    }

    pub(crate) fn record_failures(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.failed.fetch_add(count, Ordering::AcqRel);
        self.completed.fetch_add(count, Ordering::AcqRel);
    }

    pub(crate) fn record_provider_result(&self, success: bool) -> bool {
        if !success {
            self.failed.fetch_add(1, Ordering::AcqRel);
        }
        let completed = self.completed.fetch_add(1, Ordering::AcqRel) + 1;
        completed >= self.expected.load(Ordering::Acquire)
    }

    pub(crate) fn final_success(&self) -> Option<bool> {
        let expected = self.expected.load(Ordering::Acquire);
        if expected == 0 || self.completed.load(Ordering::Acquire) < expected {
            return None;
        }
        Some(self.failed.load(Ordering::Acquire) == 0)
    }

    pub(crate) fn commit(&self) -> Option<bool> {
        self.committed.store(true, Ordering::Release);
        self.commit_notify.notify_waiters();
        self.final_success()
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.commit_notify.notify_waiters();
    }

    pub(crate) async fn wait_until_committed(&self) -> bool {
        loop {
            let notified = self.commit_notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return false;
            }
            if self.committed.load(Ordering::Acquire) {
                return true;
            }
            #[cfg(test)]
            if let Some(hook) = self
                .before_wait_hook
                .lock()
                .expect("provider dispatch wait hook mutex poisoned")
                .take()
            {
                hook();
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn set_before_wait_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_wait_hook
            .lock()
            .expect("provider dispatch wait hook mutex poisoned") = Some(Box::new(hook));
    }

    pub(crate) fn op_id(&self) -> &str {
        self.op_id.as_ref()
    }

    pub(crate) fn delivery_id(&self) -> &str {
        self.delivery_id.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderDispatchOutcome, ProviderDispatchOutcomeLease};
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn wait_observes_commit_between_state_check_and_await() {
        let outcome = Arc::new(ProviderDispatchOutcome::new(
            Arc::from("race-op"),
            Arc::from("race-delivery"),
        ));
        let racing_outcome = Arc::clone(&outcome);
        outcome.set_before_wait_hook(move || {
            racing_outcome.commit();
        });

        let committed =
            tokio::time::timeout(Duration::from_millis(250), outcome.wait_until_committed())
                .await
                .expect("commit notification must not be lost");

        assert!(committed);
    }

    #[tokio::test]
    async fn wait_observes_cancel_between_state_check_and_await() {
        let outcome = Arc::new(ProviderDispatchOutcome::new(
            Arc::from("cancel-race-op"),
            Arc::from("cancel-race-delivery"),
        ));
        let racing_outcome = Arc::clone(&outcome);
        outcome.set_before_wait_hook(move || {
            racing_outcome.cancel();
        });

        let committed =
            tokio::time::timeout(Duration::from_millis(250), outcome.wait_until_committed())
                .await
                .expect("cancel notification must not be lost");

        assert!(!committed);
    }

    #[tokio::test]
    async fn dropping_undecided_lease_releases_waiting_workers() {
        let outcome = Arc::new(ProviderDispatchOutcome::new(
            Arc::from("lease-drop-op"),
            Arc::from("lease-drop-delivery"),
        ));
        let waiting_outcome = Arc::clone(&outcome);
        let waiter = tokio::spawn(async move { waiting_outcome.wait_until_committed().await });

        drop(ProviderDispatchOutcomeLease::new(outcome));

        let committed = tokio::time::timeout(Duration::from_millis(250), waiter)
            .await
            .expect("lease drop must wake provider workers")
            .expect("worker wait task must not panic");
        assert!(!committed);
    }
}

pub(crate) struct ApnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_key: Arc<str>,
    pub device_token: Arc<str>,
    pub route_updated_at: i64,
    pub platform: Platform,
    pub direct_payload: Arc<ApnsPayload>,
    pub wakeup_payload: Option<Arc<ApnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub collapse_id: Option<Arc<str>>,
    pub outcome: Option<Arc<ProviderDispatchOutcome>>,
}

pub(crate) struct WidgetPushJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_key: Arc<str>,
    pub device_token: Arc<str>,
    pub platform: Platform,
    pub widget_kinds: Arc<[String]>,
    pub collapse_id: Option<Arc<str>>,
}

pub(crate) struct FcmJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_key: Arc<str>,
    pub device_token: Arc<str>,
    pub route_updated_at: i64,
    pub direct_payload: Arc<FcmPayload>,
    pub direct_body: Arc<[u8]>,
    pub wakeup_payload: Option<Arc<FcmPayload>>,
    pub wakeup_body: Option<Arc<[u8]>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub outcome: Option<Arc<ProviderDispatchOutcome>>,
}

pub(crate) struct WnsJob {
    pub channel_id: [u8; 16],
    pub correlation_id: Arc<str>,
    pub delivery_id: Arc<str>,
    pub device_key: Arc<str>,
    pub device_token: Arc<str>,
    pub route_updated_at: i64,
    pub direct_payload: Arc<WnsPayload>,
    pub wakeup_payload: Option<Arc<WnsPayload>>,
    pub initial_path: ProviderDeliveryPath,
    pub wakeup_payload_within_limit: bool,
    pub outcome: Option<Arc<ProviderDispatchOutcome>>,
}

#[derive(Clone)]
pub(crate) struct DispatchChannels {
    apns_tx: Sender<ApnsJob>,
    widget_push_tx: Sender<WidgetPushJob>,
    fcm_tx: Sender<FcmJob>,
    wns_tx: Sender<WnsJob>,
}

pub(crate) struct DispatchWorkerReceivers {
    pub(super) apns: Receiver<ApnsJob>,
    pub(super) widget_push: Receiver<WidgetPushJob>,
    pub(super) fcm: Receiver<FcmJob>,
    pub(super) wns: Receiver<WnsJob>,
}

#[cfg(test)]
impl DispatchWorkerReceivers {
    pub(crate) async fn recv_apns_for_test(&self) -> Result<ApnsJob, flume::RecvError> {
        self.apns.recv_async().await
    }

    pub(crate) async fn recv_widget_push_for_test(
        &self,
    ) -> Result<WidgetPushJob, flume::RecvError> {
        self.widget_push.recv_async().await
    }
}

#[derive(Debug)]
pub(crate) enum DispatchError {
    QueueFull,
    ChannelClosed,
}

impl DispatchChannels {
    #[cfg(test)]
    pub(crate) fn new() -> (Self, DispatchWorkerReceivers) {
        Self::with_profile(GatewayRuntimeProfile::Small)
    }

    pub(crate) fn with_profile(profile: GatewayRuntimeProfile) -> (Self, DispatchWorkerReceivers) {
        let config = DispatchRuntimeConfig::from_profile(profile);
        let (apns_tx, apns_rx) = flume::bounded(config.queue_capacity);
        let (widget_push_tx, widget_push_rx) = flume::bounded(config.queue_capacity);
        let (fcm_tx, fcm_rx) = flume::bounded(config.queue_capacity);
        let (wns_tx, wns_rx) = flume::bounded(config.queue_capacity);
        (
            Self {
                apns_tx,
                widget_push_tx,
                fcm_tx,
                wns_tx,
            },
            DispatchWorkerReceivers {
                apns: apns_rx,
                widget_push: widget_push_rx,
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

    pub(crate) fn try_send_widget_push(&self, job: WidgetPushJob) -> Result<(), DispatchError> {
        match self.widget_push_tx.try_send(job) {
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
