use async_trait::async_trait;

use crate::storage::{
    DeviceId, Platform, PrivateMessage, PrivateOutboxBatchEntry, PrivateOutboxEntry, Storage,
    StoreResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueueWorkerId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueLease {
    pub(crate) lease_until_ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueAttempt {
    pub(crate) attempt_no: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueRetry {
    pub(crate) retry_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueClaimState {
    Pending,
    Claimed,
    Succeeded,
    FailedRetryable,
    FailedPermanent,
}

#[derive(Debug, Clone)]
pub(crate) struct QueueClaimRequest {
    pub(crate) due_before_ts: i64,
    pub(crate) limit: usize,
    pub(crate) lease: QueueLease,
    pub(crate) worker_id: QueueWorkerId,
}

#[derive(Debug, Clone)]
pub(crate) struct QueueClaimedTarget {
    pub(crate) device_id: DeviceId,
    pub(crate) entry: PrivateOutboxEntry,
    pub(crate) claim_state: QueueClaimState,
    pub(crate) lease: QueueLease,
    pub(crate) worker_id: QueueWorkerId,
    pub(crate) attempt: QueueAttempt,
    pub(crate) retry: QueueRetry,
}

impl QueueWorkerId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        if value.trim().is_empty() {
            Self("unknown-worker".to_string())
        } else {
            Self(value)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl QueueClaimRequest {
    pub(crate) fn new(
        due_before_ts: i64,
        limit: usize,
        lease_until_ts: i64,
        worker_id: QueueWorkerId,
    ) -> Self {
        Self {
            due_before_ts,
            limit,
            lease: QueueLease { lease_until_ts },
            worker_id,
        }
    }
}

impl QueueClaimedTarget {
    pub(crate) fn from_private_outbox(
        device_id: DeviceId,
        entry: PrivateOutboxEntry,
        fallback_worker_id: &QueueWorkerId,
    ) -> Self {
        let worker_id = entry
            .claimed_by
            .as_deref()
            .map(QueueWorkerId::new)
            .unwrap_or_else(|| fallback_worker_id.clone());
        let claim_state = match entry.status.as_str() {
            "pending" => QueueClaimState::Pending,
            "claimed" => QueueClaimState::Claimed,
            "sent" => QueueClaimState::Succeeded,
            _ => QueueClaimState::FailedRetryable,
        };
        Self {
            device_id,
            lease: QueueLease {
                lease_until_ts: entry.claimed_at.unwrap_or(entry.updated_at),
            },
            attempt: QueueAttempt {
                attempt_no: entry.attempts,
            },
            retry: QueueRetry {
                retry_at: entry.next_attempt_at,
            },
            entry,
            claim_state,
            worker_id,
        }
    }
}

#[async_trait]
pub(crate) trait DeliveryQueueStore {
    async fn insert_private_payload(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()>;

    async fn enqueue_private_outbox_batch(
        &self,
        entries: &[PrivateOutboxBatchEntry],
        max_pending_per_device: usize,
        global_max_pending: usize,
        protected_delivery_id: Option<&str>,
    ) -> StoreResult<usize>;

    async fn enqueue_provider_pull_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()>;

    async fn claim_private_outbox_due(
        &self,
        request: QueueClaimRequest,
    ) -> StoreResult<Vec<QueueClaimedTarget>>;
}

#[async_trait]
impl DeliveryQueueStore for Storage {
    async fn insert_private_payload(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        self.insert_private_message(delivery_id, message).await
    }

    async fn enqueue_private_outbox_batch(
        &self,
        entries: &[PrivateOutboxBatchEntry],
        max_pending_per_device: usize,
        global_max_pending: usize,
        protected_delivery_id: Option<&str>,
    ) -> StoreResult<usize> {
        self.enqueue_private_outbox_batch(
            entries,
            max_pending_per_device,
            global_max_pending,
            protected_delivery_id,
        )
        .await
    }

    async fn enqueue_provider_pull_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        self.enqueue_provider_pull_item(device_id, delivery_id, message, platform, provider_token)
            .await
    }

    async fn claim_private_outbox_due(
        &self,
        request: QueueClaimRequest,
    ) -> StoreResult<Vec<QueueClaimedTarget>> {
        let worker_id = request.worker_id.clone();
        self.claim_private_outbox_due(request).await.map(|items| {
            items
                .into_iter()
                .map(|(device_id, entry)| {
                    QueueClaimedTarget::from_private_outbox(device_id, entry, &worker_id)
                })
                .collect()
        })
    }
}
