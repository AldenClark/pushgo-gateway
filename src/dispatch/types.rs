use super::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    dedupe_key: Arc<str>,
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
    pub(crate) fn new(op_id: Arc<str>, dedupe_key: Arc<str>, delivery_id: Arc<str>) -> Self {
        Self {
            op_id,
            dedupe_key,
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

    pub(crate) fn dedupe_key(&self) -> &str {
        self.dedupe_key.as_ref()
    }

    pub(crate) fn delivery_id(&self) -> &str {
        self.delivery_id.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DurableProviderJob, ProviderDispatchOutcome, ProviderDispatchOutcomeLease, WidgetPushJob,
    };
    use crate::storage::Platform;
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn wait_observes_commit_between_state_check_and_await() {
        let outcome = Arc::new(ProviderDispatchOutcome::new(
            Arc::from("race-op"),
            Arc::from("op:race-scope:race-op"),
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
            Arc::from("op:cancel-scope:cancel-race-op"),
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
            Arc::from("op:lease-scope:lease-drop-op"),
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

    #[test]
    fn widget_job_identity_coalesces_latest_state_across_message_deliveries() {
        let make = |delivery_id: &'static str| WidgetPushJob {
            channel_id: [4; 16],
            correlation_id: Arc::from(delivery_id),
            delivery_id: Arc::from(delivery_id),
            device_key: Arc::from("widget-device"),
            device_token: Arc::from("widget-token"),
            platform: Platform::IOS,
            widget_kinds: vec!["unread".to_string()].into(),
            collapse_id: Some(Arc::from("widgets:message:channel")),
        };
        let first = DurableProviderJob::from_widget(&make("delivery-1"));
        let second = DurableProviderJob::from_widget(&make("delivery-2"));

        assert_eq!(first.job_id(), second.job_id());
        assert!(first.is_coalescible());
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
    pub route_fenced: bool,
    pub coalescible: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DurableProviderJob {
    Apns {
        op_id: Option<String>,
        #[serde(default)]
        dedupe_key: Option<String>,
        channel_id: [u8; 16],
        correlation_id: String,
        delivery_id: String,
        device_key: String,
        device_token: String,
        route_updated_at: i64,
        platform: Platform,
        direct_payload: Box<crate::providers::apns::ApnsPayloadSnapshot>,
        wakeup_payload: Option<Box<crate::providers::apns::ApnsPayloadSnapshot>>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
        collapse_id: Option<String>,
        #[serde(default = "default_true")]
        route_fenced: bool,
        #[serde(default)]
        coalescible: bool,
    },
    Widget {
        op_id: Option<String>,
        #[serde(default)]
        dedupe_key: Option<String>,
        channel_id: [u8; 16],
        correlation_id: String,
        delivery_id: String,
        device_key: String,
        device_token: String,
        platform: Platform,
        widget_kinds: Vec<String>,
        collapse_id: Option<String>,
    },
    Fcm {
        op_id: Option<String>,
        #[serde(default)]
        dedupe_key: Option<String>,
        channel_id: [u8; 16],
        correlation_id: String,
        delivery_id: String,
        device_key: String,
        device_token: String,
        route_updated_at: i64,
        direct_payload: crate::providers::fcm::FcmPayloadSnapshot,
        wakeup_payload: Option<crate::providers::fcm::FcmPayloadSnapshot>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
    },
    Wns {
        op_id: Option<String>,
        #[serde(default)]
        dedupe_key: Option<String>,
        channel_id: [u8; 16],
        correlation_id: String,
        delivery_id: String,
        device_key: String,
        device_token: String,
        route_updated_at: i64,
        direct_payload: crate::providers::wns::WnsPayloadSnapshot,
        wakeup_payload: Option<crate::providers::wns::WnsPayloadSnapshot>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
    },
}

fn default_true() -> bool {
    true
}

impl DurableProviderJob {
    pub(crate) fn from_apns(job: &ApnsJob) -> Self {
        Self::Apns {
            op_id: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.op_id().to_string()),
            dedupe_key: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.dedupe_key().to_string()),
            channel_id: job.channel_id,
            correlation_id: job.correlation_id.to_string(),
            delivery_id: job.delivery_id.to_string(),
            device_key: job.device_key.to_string(),
            device_token: job.device_token.to_string(),
            route_updated_at: job.route_updated_at,
            platform: job.platform,
            direct_payload: Box::new(job.direct_payload.snapshot()),
            wakeup_payload: job
                .wakeup_payload
                .as_ref()
                .map(|payload| Box::new(payload.snapshot())),
            initial_path: job.initial_path,
            wakeup_payload_within_limit: job.wakeup_payload_within_limit,
            collapse_id: job.collapse_id.as_ref().map(ToString::to_string),
            route_fenced: job.route_fenced,
            coalescible: job.coalescible,
        }
    }

    pub(crate) fn from_widget(job: &WidgetPushJob) -> Self {
        Self::Widget {
            op_id: None,
            dedupe_key: None,
            channel_id: job.channel_id,
            correlation_id: job.correlation_id.to_string(),
            delivery_id: job.delivery_id.to_string(),
            device_key: job.device_key.to_string(),
            device_token: job.device_token.to_string(),
            platform: job.platform,
            widget_kinds: job.widget_kinds.to_vec(),
            collapse_id: job.collapse_id.as_ref().map(ToString::to_string),
        }
    }

    pub(crate) fn from_fcm(job: &FcmJob) -> Self {
        Self::Fcm {
            op_id: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.op_id().to_string()),
            dedupe_key: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.dedupe_key().to_string()),
            channel_id: job.channel_id,
            correlation_id: job.correlation_id.to_string(),
            delivery_id: job.delivery_id.to_string(),
            device_key: job.device_key.to_string(),
            device_token: job.device_token.to_string(),
            route_updated_at: job.route_updated_at,
            direct_payload: job.direct_payload.snapshot(),
            wakeup_payload: job
                .wakeup_payload
                .as_ref()
                .map(|payload| payload.snapshot()),
            initial_path: job.initial_path,
            wakeup_payload_within_limit: job.wakeup_payload_within_limit,
        }
    }

    pub(crate) fn from_wns(job: &WnsJob) -> Self {
        Self::Wns {
            op_id: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.op_id().to_string()),
            dedupe_key: job
                .outcome
                .as_ref()
                .map(|outcome| outcome.dedupe_key().to_string()),
            channel_id: job.channel_id,
            correlation_id: job.correlation_id.to_string(),
            delivery_id: job.delivery_id.to_string(),
            device_key: job.device_key.to_string(),
            device_token: job.device_token.to_string(),
            route_updated_at: job.route_updated_at,
            direct_payload: job.direct_payload.snapshot(),
            wakeup_payload: job
                .wakeup_payload
                .as_ref()
                .map(|payload| payload.snapshot()),
            initial_path: job.initial_path,
            wakeup_payload_within_limit: job.wakeup_payload_within_limit,
        }
    }

    pub(crate) fn provider(&self) -> &'static str {
        match self {
            Self::Apns { .. } => "APNS",
            Self::Widget { .. } => "APNS_WIDGETS",
            Self::Fcm { .. } => "FCM",
            Self::Wns { .. } => "WNS",
        }
    }

    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            Self::Apns { op_id, .. }
            | Self::Widget { op_id, .. }
            | Self::Fcm { op_id, .. }
            | Self::Wns { op_id, .. } => op_id.as_deref(),
        }
    }

    pub(crate) fn dedupe_key(&self) -> Option<&str> {
        match self {
            Self::Apns { dedupe_key, .. }
            | Self::Widget { dedupe_key, .. }
            | Self::Fcm { dedupe_key, .. }
            | Self::Wns { dedupe_key, .. } => dedupe_key.as_deref(),
        }
    }

    pub(crate) fn delivery_id(&self) -> &str {
        match self {
            Self::Apns { delivery_id, .. }
            | Self::Widget { delivery_id, .. }
            | Self::Fcm { delivery_id, .. }
            | Self::Wns { delivery_id, .. } => delivery_id,
        }
    }

    pub(crate) fn device_key(&self) -> &str {
        match self {
            Self::Apns { device_key, .. }
            | Self::Widget { device_key, .. }
            | Self::Fcm { device_key, .. }
            | Self::Wns { device_key, .. } => device_key,
        }
    }

    pub(crate) fn job_id(&self) -> String {
        let mut material =
            String::with_capacity(self.delivery_id().len() + self.device_key().len() + 32);
        material.push_str(self.provider());
        material.push('\0');
        match self {
            Self::Widget {
                collapse_id: Some(collapse_id),
                ..
            } => material.push_str(collapse_id),
            _ => material.push_str(self.delivery_id()),
        }
        material.push('\0');
        material.push_str(self.device_key());
        format!(
            "{}:{}",
            self.provider().to_ascii_lowercase(),
            blake3::hash(material.as_bytes()).to_hex()
        )
    }

    pub(crate) fn to_record(
        &self,
        state: &str,
        accepted_at: i64,
        expires_at: i64,
    ) -> Result<crate::storage::ProviderDispatchOutboxRecord, serde_json::Error> {
        Ok(crate::storage::ProviderDispatchOutboxRecord {
            job_id: self.job_id(),
            provider: self.provider().to_string(),
            delivery_id: self.delivery_id().to_string(),
            op_id: self.op_id().map(str::to_string),
            dedupe_key: self.dedupe_key().map(str::to_string),
            device_key: self.device_key().to_string(),
            payload_blob: serde_json::to_vec(self)?,
            state: state.to_string(),
            next_attempt_at: accepted_at,
            accepted_at,
            expires_at,
            coalesce_order: 0,
            coalescible: self.is_coalescible(),
        })
    }

    pub(crate) fn is_coalescible(&self) -> bool {
        match self {
            Self::Apns { coalescible, .. } => *coalescible,
            Self::Widget { .. } => true,
            Self::Fcm { .. } | Self::Wns { .. } => false,
        }
    }

    pub(crate) fn into_apns(self) -> Option<ApnsJob> {
        let Self::Apns {
            channel_id,
            correlation_id,
            delivery_id,
            device_key,
            device_token,
            route_updated_at,
            platform,
            direct_payload,
            wakeup_payload,
            initial_path,
            wakeup_payload_within_limit,
            collapse_id,
            route_fenced,
            coalescible,
            ..
        } = self
        else {
            return None;
        };
        Some(ApnsJob {
            channel_id,
            correlation_id: Arc::from(correlation_id),
            delivery_id: Arc::from(delivery_id),
            device_key: Arc::from(device_key),
            device_token: Arc::from(device_token),
            route_updated_at,
            platform,
            direct_payload: Arc::new(ApnsPayload::from_snapshot(*direct_payload)),
            wakeup_payload: wakeup_payload
                .map(|payload| ApnsPayload::from_snapshot(*payload))
                .map(Arc::new),
            initial_path,
            wakeup_payload_within_limit,
            collapse_id: collapse_id.map(Arc::from),
            route_fenced,
            coalescible,
            outcome: None,
        })
    }

    pub(crate) fn into_widget(self) -> Option<WidgetPushJob> {
        let Self::Widget {
            channel_id,
            correlation_id,
            delivery_id,
            device_key,
            device_token,
            platform,
            widget_kinds,
            collapse_id,
            ..
        } = self
        else {
            return None;
        };
        Some(WidgetPushJob {
            channel_id,
            correlation_id: Arc::from(correlation_id),
            delivery_id: Arc::from(delivery_id),
            device_key: Arc::from(device_key),
            device_token: Arc::from(device_token),
            platform,
            widget_kinds: widget_kinds.into(),
            collapse_id: collapse_id.map(Arc::from),
        })
    }

    pub(crate) fn into_fcm(self) -> Option<FcmJob> {
        let Self::Fcm {
            channel_id,
            correlation_id,
            delivery_id,
            device_key,
            device_token,
            route_updated_at,
            direct_payload,
            wakeup_payload,
            initial_path,
            wakeup_payload_within_limit,
            ..
        } = self
        else {
            return None;
        };
        let direct_payload = Arc::new(FcmPayload::from_snapshot(direct_payload));
        let direct_body = direct_payload.encoded_body(&device_token).ok()?;
        let wakeup_payload = wakeup_payload.map(FcmPayload::from_snapshot).map(Arc::new);
        let wakeup_body = wakeup_payload
            .as_ref()
            .and_then(|payload| payload.encoded_body(&device_token).ok());
        Some(FcmJob {
            channel_id,
            correlation_id: Arc::from(correlation_id),
            delivery_id: Arc::from(delivery_id),
            device_key: Arc::from(device_key),
            device_token: Arc::from(device_token),
            route_updated_at,
            direct_payload,
            direct_body,
            wakeup_payload,
            wakeup_body,
            initial_path,
            wakeup_payload_within_limit,
            outcome: None,
        })
    }

    pub(crate) fn into_wns(self) -> Option<WnsJob> {
        let Self::Wns {
            channel_id,
            correlation_id,
            delivery_id,
            device_key,
            device_token,
            route_updated_at,
            direct_payload,
            wakeup_payload,
            initial_path,
            wakeup_payload_within_limit,
            ..
        } = self
        else {
            return None;
        };
        Some(WnsJob {
            channel_id,
            correlation_id: Arc::from(correlation_id),
            delivery_id: Arc::from(delivery_id),
            device_key: Arc::from(device_key),
            device_token: Arc::from(device_token),
            route_updated_at,
            direct_payload: Arc::new(WnsPayload::from_snapshot(direct_payload)),
            wakeup_payload: wakeup_payload.map(WnsPayload::from_snapshot).map(Arc::new),
            initial_path,
            wakeup_payload_within_limit,
            outcome: None,
        })
    }
}

#[derive(Clone)]
pub(crate) struct DispatchChannels {
    apns_tx: Sender<ApnsJob>,
    live_activity_tx: Sender<ApnsJob>,
    widget_push_tx: Sender<WidgetPushJob>,
    fcm_tx: Sender<FcmJob>,
    wns_tx: Sender<WnsJob>,
}

pub(crate) struct DispatchWorkerReceivers {
    pub(super) apns: Receiver<ApnsJob>,
    pub(super) live_activity: Receiver<ApnsJob>,
    pub(super) widget_push: Receiver<WidgetPushJob>,
    pub(super) fcm: Receiver<FcmJob>,
    pub(super) wns: Receiver<WnsJob>,
}

#[cfg(test)]
impl DispatchWorkerReceivers {
    pub(crate) async fn recv_live_activity_for_test(&self) -> Result<ApnsJob, flume::RecvError> {
        self.live_activity.recv_async().await
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
    DurableEncoding(String),
    DurableStorage(String),
}

impl DispatchChannels {
    #[cfg(test)]
    pub(crate) fn new() -> (Self, DispatchWorkerReceivers) {
        Self::with_profile(GatewayRuntimeProfile::Small)
    }

    pub(crate) fn with_profile(profile: GatewayRuntimeProfile) -> (Self, DispatchWorkerReceivers) {
        let config = DispatchRuntimeConfig::from_profile(profile);
        let (apns_tx, apns_rx) = flume::bounded(config.queue_capacity);
        let (live_activity_tx, live_activity_rx) = flume::bounded(config.queue_capacity);
        let (widget_push_tx, widget_push_rx) = flume::bounded(config.queue_capacity);
        let (fcm_tx, fcm_rx) = flume::bounded(config.queue_capacity);
        let (wns_tx, wns_rx) = flume::bounded(config.queue_capacity);
        (
            Self {
                apns_tx,
                live_activity_tx,
                widget_push_tx,
                fcm_tx,
                wns_tx,
            },
            DispatchWorkerReceivers {
                apns: apns_rx,
                live_activity: live_activity_rx,
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

    pub(crate) fn try_send_live_activity(&self, job: ApnsJob) -> Result<(), DispatchError> {
        match self.live_activity_tx.try_send(job) {
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
