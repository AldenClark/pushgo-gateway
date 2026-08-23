use super::runtime::ProviderDispatchFailureLog;
use super::*;
use crate::delivery_core::execution::provider::{
    ProviderInvalidTokenCleanup, cleanup_invalid_provider_token,
};
use crate::runtime_counters::RuntimeCounterCollector;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use tokio::time::Instant;
use tracing::Instrument;

// Hints wake fresh work immediately. This sweep is only the lost-hint/restart
// safety net, so keeping it at one second avoids turning every idle worker into
// a high-frequency database poller.
const PROVIDER_DISPATCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
// The base lease remains long enough to survive one missed heartbeat plus
// ordinary database jitter. Live external work renews it every five seconds;
// crashed attempts still become recoverable promptly.
const PROVIDER_DISPATCH_LEASE_MILLIS: i64 = 30_000;
const PROVIDER_DISPATCH_LEASE_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);
const PROVIDER_DISPATCH_LEASE_EXPIRY_GUARD_MILLIS: i64 = 5_000;
const MAX_FRESH_HINT_CLAIMS_BEFORE_RETRY_PROBE: usize = 3;
// Concurrency alone does not bound the rate of fast failures (for example a
// refused local credential-service connection). Four consecutive retryable
// lane failures open a short probe circuit before another durable job is
// claimed. A success closes it immediately.
const PROVIDER_FAILURE_CIRCUIT_THRESHOLD: usize = 4;
const PROVIDER_FAILURE_CIRCUIT_COOLDOWN_MILLIS: i64 = 1_000;

struct ClaimedProviderJob<T> {
    job: T,
    lease: crate::storage::ProviderDispatchOutboxLease,
    op_id: Option<String>,
    dedupe_key: Option<String>,
}

#[derive(Default)]
struct ProviderClaimFairness {
    fresh_hint_claims: usize,
}

impl ProviderClaimFairness {
    fn retry_probe_due(&self) -> bool {
        self.fresh_hint_claims >= MAX_FRESH_HINT_CLAIMS_BEFORE_RETRY_PROBE
    }

    fn record_fresh_hint_claim(&mut self) {
        self.fresh_hint_claims = self.fresh_hint_claims.saturating_add(1);
    }

    fn record_retry_probe(&mut self) {
        self.fresh_hint_claims = 0;
    }
}

fn worker_owner(provider: &str, worker_slot: usize) -> String {
    format!("gateway:{}:{provider}:{worker_slot}", std::process::id())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderLeaseHeartbeatError {
    LeaseLost,
    RenewalDeadlineExceeded,
}

async fn run_with_provider_lease_heartbeat<T>(
    runtime: &DispatchWorkerRuntime,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    confirmed_until: &mut i64,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, ProviderLeaseHeartbeatError> {
    run_with_provider_lease_heartbeat_config(
        runtime,
        lease,
        confirmed_until,
        PROVIDER_DISPATCH_LEASE_HEARTBEAT,
        PROVIDER_DISPATCH_LEASE_MILLIS,
        PROVIDER_DISPATCH_LEASE_EXPIRY_GUARD_MILLIS,
        operation,
    )
    .await
}

async fn run_with_provider_lease_heartbeat_config<T>(
    runtime: &DispatchWorkerRuntime,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    confirmed_until: &mut i64,
    heartbeat_interval: std::time::Duration,
    lease_window_millis: i64,
    expiry_guard_millis: i64,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, ProviderLeaseHeartbeatError> {
    let mut operation = Box::pin(operation);
    let heartbeat = async {
        let mut interval = tokio::time::interval(heartbeat_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = chrono::Utc::now().timestamp_millis();
            let renewal_deadline = confirmed_until.saturating_sub(expiry_guard_millis);
            let remaining = renewal_deadline.saturating_sub(now);
            if remaining <= 0 {
                return ProviderLeaseHeartbeatError::RenewalDeadlineExceeded;
            }
            let lease_until = now.saturating_add(lease_window_millis);
            let renewal = tokio::time::timeout(
                std::time::Duration::from_millis(u64::try_from(remaining).unwrap_or(1).max(1)),
                runtime
                    .store
                    .renew_provider_dispatch_job_lease(lease, now, lease_until),
            )
            .await;
            match renewal {
                Ok(Ok(true)) => *confirmed_until = lease_until,
                Ok(Ok(false)) => return ProviderLeaseHeartbeatError::LeaseLost,
                Ok(Err(err)) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "dispatch.provider_lease_renewal_failed",
                        provider = %(lease.record.provider),
                        error = %(err.to_string())
                    );
                }
                Err(_) => return ProviderLeaseHeartbeatError::RenewalDeadlineExceeded,
            }
        }
    };
    tokio::pin!(heartbeat);
    tokio::select! {
        result = &mut operation => Ok(result),
        error = &mut heartbeat => Err(error),
    }
}

fn emit_provider_lease_lost(
    provider: &str,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    error: ProviderLeaseHeartbeatError,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::ERROR,
        event = "dispatch.provider_live_attempt_lease_lost",
        provider = %provider,
        job_id = %(crate::util::redact_text(lease.record.job_id.as_str())),
        lease_generation = lease.lease_generation,
        reason = ?error
    );
}

async fn claim_apns_job(
    rx: &Receiver<ApnsJob>,
    runtime: &DispatchWorkerRuntime,
    owner: &str,
    provider: &'static str,
    fairness: &mut ProviderClaimFairness,
) -> Option<ClaimedProviderJob<ApnsJob>> {
    if fairness.retry_probe_due() {
        fairness.record_retry_probe();
        if let Some(claimed) =
            claim_persisted_retry_job(runtime, provider, owner, DurableProviderJob::into_apns).await
        {
            return Some(claimed);
        }
    }
    let mut hinted = rx.try_recv().ok();
    if hinted.is_none() {
        if let Some(claimed) =
            claim_persisted_job(runtime, provider, owner, DurableProviderJob::into_apns).await
        {
            return Some(claimed);
        }
        hinted = tokio::time::timeout(PROVIDER_DISPATCH_POLL_INTERVAL, rx.recv_async())
            .await
            .ok()
            .and_then(Result::ok);
    }
    if let Some(job) = hinted {
        if let Some(outcome) = job.outcome.as_ref()
            && !outcome.wait_until_committed().await
        {
            return None;
        }
        let durable = DurableProviderJob::from_apns(&job);
        let coalescible = durable.is_coalescible();
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(Some(lease)) = runtime
            .store
            .claim_provider_dispatch_job(
                provider,
                Some(&durable.job_id()),
                owner,
                now,
                now + PROVIDER_DISPATCH_LEASE_MILLIS,
            )
            .await
        {
            let job = if coalescible {
                let (job, _, _) =
                    decode_leased_payload(runtime, provider, &lease, DurableProviderJob::into_apns)
                        .await?;
                job
            } else {
                job
            };
            fairness.record_fresh_hint_claim();
            return Some(ClaimedProviderJob {
                job,
                lease,
                op_id: durable.op_id().map(str::to_string),
                dedupe_key: durable.dedupe_key().map(str::to_string),
            });
        }
    }
    claim_persisted_job(runtime, provider, owner, DurableProviderJob::into_apns).await
}

async fn claim_widget_job(
    rx: &Receiver<WidgetPushJob>,
    runtime: &DispatchWorkerRuntime,
    owner: &str,
    fairness: &mut ProviderClaimFairness,
) -> Option<ClaimedProviderJob<WidgetPushJob>> {
    if fairness.retry_probe_due() {
        fairness.record_retry_probe();
        if let Some(claimed) = claim_persisted_retry_job(
            runtime,
            "APNS_WIDGETS",
            owner,
            DurableProviderJob::into_widget,
        )
        .await
        {
            return Some(claimed);
        }
    }
    let mut hinted = rx.try_recv().ok();
    if hinted.is_none() {
        if let Some(claimed) = claim_persisted_job(
            runtime,
            "APNS_WIDGETS",
            owner,
            DurableProviderJob::into_widget,
        )
        .await
        {
            return Some(claimed);
        }
        hinted = tokio::time::timeout(PROVIDER_DISPATCH_POLL_INTERVAL, rx.recv_async())
            .await
            .ok()
            .and_then(Result::ok);
    }
    if let Some(job) = hinted {
        let durable = DurableProviderJob::from_widget(&job);
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(Some(lease)) = runtime
            .store
            .claim_provider_dispatch_job(
                "APNS_WIDGETS",
                Some(&durable.job_id()),
                owner,
                now,
                now + PROVIDER_DISPATCH_LEASE_MILLIS,
            )
            .await
        {
            // Coalescible work can have a stale in-memory hint after a newer
            // generation replaced the durable row. The leased row is the
            // source of truth; settling it after sending the hint payload
            // would otherwise discard the newest generation.
            let (job, _, _) = decode_leased_payload(
                runtime,
                "APNS_WIDGETS",
                &lease,
                DurableProviderJob::into_widget,
            )
            .await?;
            fairness.record_fresh_hint_claim();
            return Some(ClaimedProviderJob {
                job,
                lease,
                op_id: None,
                dedupe_key: None,
            });
        }
    }
    claim_persisted_job(
        runtime,
        "APNS_WIDGETS",
        owner,
        DurableProviderJob::into_widget,
    )
    .await
}

async fn claim_fcm_job(
    rx: &Receiver<FcmJob>,
    runtime: &DispatchWorkerRuntime,
    owner: &str,
    fairness: &mut ProviderClaimFairness,
) -> Option<ClaimedProviderJob<FcmJob>> {
    if fairness.retry_probe_due() {
        fairness.record_retry_probe();
        if let Some(claimed) =
            claim_persisted_retry_job(runtime, "FCM", owner, DurableProviderJob::into_fcm).await
        {
            return Some(claimed);
        }
    }
    let mut hinted = rx.try_recv().ok();
    if hinted.is_none() {
        if let Some(claimed) =
            claim_persisted_job(runtime, "FCM", owner, DurableProviderJob::into_fcm).await
        {
            return Some(claimed);
        }
        hinted = tokio::time::timeout(PROVIDER_DISPATCH_POLL_INTERVAL, rx.recv_async())
            .await
            .ok()
            .and_then(Result::ok);
    }
    if let Some(job) = hinted {
        if let Some(outcome) = job.outcome.as_ref()
            && !outcome.wait_until_committed().await
        {
            return None;
        }
        let durable = DurableProviderJob::from_fcm(&job);
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(Some(lease)) = runtime
            .store
            .claim_provider_dispatch_job(
                "FCM",
                Some(&durable.job_id()),
                owner,
                now,
                now + PROVIDER_DISPATCH_LEASE_MILLIS,
            )
            .await
        {
            fairness.record_fresh_hint_claim();
            return Some(ClaimedProviderJob {
                job,
                lease,
                op_id: durable.op_id().map(str::to_string),
                dedupe_key: durable.dedupe_key().map(str::to_string),
            });
        }
    }
    claim_persisted_job(runtime, "FCM", owner, DurableProviderJob::into_fcm).await
}

async fn claim_wns_job(
    rx: &Receiver<WnsJob>,
    runtime: &DispatchWorkerRuntime,
    owner: &str,
    fairness: &mut ProviderClaimFairness,
) -> Option<ClaimedProviderJob<WnsJob>> {
    if fairness.retry_probe_due() {
        fairness.record_retry_probe();
        if let Some(claimed) =
            claim_persisted_retry_job(runtime, "WNS", owner, DurableProviderJob::into_wns).await
        {
            return Some(claimed);
        }
    }
    let mut hinted = rx.try_recv().ok();
    if hinted.is_none() {
        if let Some(claimed) =
            claim_persisted_job(runtime, "WNS", owner, DurableProviderJob::into_wns).await
        {
            return Some(claimed);
        }
        hinted = tokio::time::timeout(PROVIDER_DISPATCH_POLL_INTERVAL, rx.recv_async())
            .await
            .ok()
            .and_then(Result::ok);
    }
    if let Some(job) = hinted {
        if let Some(outcome) = job.outcome.as_ref()
            && !outcome.wait_until_committed().await
        {
            return None;
        }
        let durable = DurableProviderJob::from_wns(&job);
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(Some(lease)) = runtime
            .store
            .claim_provider_dispatch_job(
                "WNS",
                Some(&durable.job_id()),
                owner,
                now,
                now + PROVIDER_DISPATCH_LEASE_MILLIS,
            )
            .await
        {
            fairness.record_fresh_hint_claim();
            return Some(ClaimedProviderJob {
                job,
                lease,
                op_id: durable.op_id().map(str::to_string),
                dedupe_key: durable.dedupe_key().map(str::to_string),
            });
        }
    }
    claim_persisted_job(runtime, "WNS", owner, DurableProviderJob::into_wns).await
}

async fn claim_persisted_job<T>(
    runtime: &DispatchWorkerRuntime,
    provider: &str,
    owner: &str,
    decode: impl FnOnce(DurableProviderJob) -> Option<T>,
) -> Option<ClaimedProviderJob<T>> {
    let now = chrono::Utc::now().timestamp_millis();
    let lease = match runtime
        .store
        .claim_provider_dispatch_job(
            provider,
            None,
            owner,
            now,
            now + PROVIDER_DISPATCH_LEASE_MILLIS,
        )
        .await
    {
        Ok(value) => value?,
        Err(err) => {
            ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::ERROR,
                event = "dispatch.provider_outbox_claim_failed", provider = %provider, error = %(err.to_string()));
            return None;
        }
    };
    let (job, op_id, dedupe_key) = decode_leased_payload(runtime, provider, &lease, decode).await?;
    Some(ClaimedProviderJob {
        job,
        lease,
        op_id,
        dedupe_key,
    })
}

async fn claim_persisted_retry_job<T>(
    runtime: &DispatchWorkerRuntime,
    provider: &str,
    owner: &str,
    decode: impl FnOnce(DurableProviderJob) -> Option<T>,
) -> Option<ClaimedProviderJob<T>> {
    let now = chrono::Utc::now().timestamp_millis();
    let lease = match runtime
        .store
        .claim_due_provider_dispatch_retry_job(
            provider,
            owner,
            now,
            now + PROVIDER_DISPATCH_LEASE_MILLIS,
        )
        .await
    {
        Ok(value) => value?,
        Err(err) => {
            ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::ERROR,
                event = "dispatch.provider_retry_claim_failed", provider = %provider, error = %(err.to_string()));
            return None;
        }
    };
    let (job, op_id, dedupe_key) = decode_leased_payload(runtime, provider, &lease, decode).await?;
    Some(ClaimedProviderJob {
        job,
        lease,
        op_id,
        dedupe_key,
    })
}

async fn decode_leased_payload<T>(
    runtime: &DispatchWorkerRuntime,
    provider: &str,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    decode: impl FnOnce(DurableProviderJob) -> Option<T>,
) -> Option<(T, Option<String>, Option<String>)> {
    let now = chrono::Utc::now().timestamp_millis();
    let durable: DurableProviderJob = match serde_json::from_slice(&lease.record.payload_blob) {
        Ok(value) => value,
        Err(err) => {
            let _ = runtime
                .store
                .settle_provider_dispatch_job(
                    lease,
                    crate::storage::ProviderDispatchSettlement::PermanentFailure,
                    now,
                    0,
                    Some("corrupt_payload"),
                    now,
                )
                .await;
            ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::ERROR,
                event = "dispatch.provider_outbox_decode_failed", provider = %provider, error = %(err.to_string()));
            return None;
        }
    };
    let op_id = durable.op_id().map(str::to_string);
    let dedupe_key = durable.dedupe_key().map(str::to_string);
    let Some(job) = decode(durable) else {
        let _ = runtime
            .store
            .settle_provider_dispatch_job(
                lease,
                crate::storage::ProviderDispatchSettlement::PermanentFailure,
                now,
                0,
                Some("payload_kind_mismatch"),
                now,
            )
            .await;
        return None;
    };
    Some((job, op_id, dedupe_key))
}

async fn settle_provider_attempt(
    runtime: &DispatchWorkerRuntime,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    dedupe_key: Option<&str>,
    op_id: Option<&str>,
    dispatch: &DispatchResult,
) -> bool {
    let now = chrono::Utc::now().timestamp_millis();
    let terminal = dispatch.success || !dispatch.is_retryable();
    let settlement = if dispatch.success {
        crate::storage::ProviderDispatchSettlement::Accepted
    } else if dispatch.is_retryable() {
        crate::storage::ProviderDispatchSettlement::Retry
    } else {
        crate::storage::ProviderDispatchSettlement::PermanentFailure
    };
    let next_attempt_at = if terminal {
        now
    } else {
        now.saturating_add(
            provider_retry_delay_millis(lease).max(dispatch.retry_after_millis.unwrap_or_default()),
        )
    };
    let settled = runtime
        .store
        .settle_provider_dispatch_job(
            lease,
            settlement,
            next_attempt_at,
            dispatch.status_code,
            (!dispatch.success).then(|| dispatch.failure_kind_name()),
            now,
        )
        .await
        .unwrap_or(false);
    if settled
        && terminal
        && let (Some(dedupe_key), Some(op_id)) = (dedupe_key, op_id)
        && let Ok(Some(success)) = runtime
            .store
            .provider_dispatch_terminal_success(&lease.record.delivery_id)
            .await
    {
        runtime
            .store
            .finalize_provider_dispatch_outcome_durably(
                dedupe_key,
                op_id,
                &lease.record.delivery_id,
                success,
            )
            .await;
    }
    terminal && settled
}

fn provider_retry_delay_millis(lease: &crate::storage::ProviderDispatchOutboxLease) -> i64 {
    let exponent = u32::try_from(lease.attempt_count.max(0))
        .unwrap_or(0)
        .min(6);
    let base = 1_000_i64.saturating_mul(1_i64 << exponent).min(60_000);
    let digest = blake3::hash(lease.record.job_id.as_bytes());
    let jitter = i64::from(digest.as_bytes()[0]) * base / 1024;
    base.saturating_add(jitter)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderRouteDecision {
    Send,
    Superseded,
    Deferred,
}

struct ProviderRouteClaim<'a> {
    dedupe_key: Option<&'a str>,
    op_id: Option<&'a str>,
    platform: Platform,
    channel_type: crate::storage::RouteChannelType,
    device_key: &'a str,
    provider_token: &'a str,
    route_updated_at: i64,
}

#[derive(Default)]
struct ProviderLaneFeedback {
    successes: AtomicUsize,
    retryable_failures: AtomicUsize,
    global_throttles: AtomicUsize,
    consecutive_retryable_failures: AtomicUsize,
    paused_until_millis: AtomicI64,
    probe_in_flight: AtomicBool,
    probe_changed: tokio::sync::Notify,
}

struct ProviderProbePermit {
    feedback: Arc<ProviderLaneFeedback>,
    is_probe: bool,
    completed: bool,
}

impl ProviderProbePermit {
    fn finish(mut self, provider: &str, dispatch: &DispatchResult) {
        self.feedback
            .record_with_probe_state(provider, dispatch, self.is_probe);
        self.completed = true;
        if self.is_probe {
            self.feedback
                .probe_in_flight
                .store(false, Ordering::Release);
            self.feedback.probe_changed.notify_waiters();
        }
    }
}

impl Drop for ProviderProbePermit {
    fn drop(&mut self) {
        if self.is_probe && !self.completed {
            self.feedback
                .probe_in_flight
                .store(false, Ordering::Release);
            self.feedback.probe_changed.notify_waiters();
        }
    }
}

struct ProviderLaneGate {
    active: AtomicUsize,
    closed: AtomicBool,
    changed: tokio::sync::Notify,
}

impl ProviderLaneGate {
    fn new(active: usize) -> Self {
        Self {
            active: AtomicUsize::new(active),
            closed: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn load(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn store(&self, active: usize) {
        self.active.store(active, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait_until_active(&self, worker_slot: usize) -> bool {
        loop {
            let notified = self.changed.notified();
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            if worker_slot < self.load() {
                return true;
            }
            notified.await;
        }
    }
}

impl ProviderLaneFeedback {
    #[cfg(test)]
    fn record(&self, provider: &str, dispatch: &DispatchResult) {
        self.record_with_probe_state(provider, dispatch, false);
    }

    fn record_with_probe_state(&self, provider: &str, dispatch: &DispatchResult, is_probe: bool) {
        if dispatch.success {
            self.successes.fetch_add(1, Ordering::Relaxed);
            // A pre-circuit request can complete while the half-open probe is
            // live. Its result is useful telemetry, but only the sole probe
            // may close that half-open generation and release parked workers.
            if is_probe || !self.probe_in_flight.load(Ordering::Acquire) {
                self.consecutive_retryable_failures
                    .store(0, Ordering::Release);
                self.paused_until_millis.store(0, Ordering::Release);
                self.probe_changed.notify_waiters();
            }
        } else if dispatch.status_code == 429 && !provider.starts_with("APNS") {
            // FCM/WNS 429 is credential/project/package pressure. APNs 429 is
            // commonly token scoped and remains a per-job retry signal unless
            // aggregate failures independently show lane congestion.
            self.global_throttles.fetch_add(1, Ordering::Relaxed);
            self.record_retryable_failure_for_circuit();
        } else if dispatch.is_retryable() {
            self.retryable_failures.fetch_add(1, Ordering::Relaxed);
            self.record_retryable_failure_for_circuit();
        } else {
            if is_probe || !self.probe_in_flight.load(Ordering::Acquire) {
                self.consecutive_retryable_failures
                    .store(0, Ordering::Release);
                self.paused_until_millis.store(0, Ordering::Release);
                self.probe_changed.notify_waiters();
            }
        }
    }

    fn record_retryable_failure_for_circuit(&self) {
        let consecutive = self
            .consecutive_retryable_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if consecutive >= PROVIDER_FAILURE_CIRCUIT_THRESHOLD {
            let pause_until = chrono::Utc::now()
                .timestamp_millis()
                .saturating_add(PROVIDER_FAILURE_CIRCUIT_COOLDOWN_MILLIS);
            self.paused_until_millis
                .fetch_max(pause_until, Ordering::AcqRel);
        }
    }

    async fn acquire_probe_permit(self: &Arc<Self>) -> ProviderProbePermit {
        loop {
            let notified = self.probe_changed.notified();
            let now = chrono::Utc::now().timestamp_millis();
            let pause_until = self.paused_until_millis.load(Ordering::Acquire);
            if pause_until == 0 {
                return ProviderProbePermit {
                    feedback: Arc::clone(self),
                    is_probe: false,
                    completed: false,
                };
            }
            if pause_until <= now
                && self
                    .probe_in_flight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return ProviderProbePermit {
                    feedback: Arc::clone(self),
                    is_probe: true,
                    completed: false,
                };
            }
            if pause_until <= now {
                notified.await;
                continue;
            }
            let delay = u64::try_from(pause_until.saturating_sub(now)).unwrap_or(1);
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_millis(delay.max(1))) => {}
                () = notified => {}
            }
        }
    }
}

async fn validate_claimed_provider_route(
    runtime: &DispatchWorkerRuntime,
    lease: &crate::storage::ProviderDispatchOutboxLease,
    route: ProviderRouteClaim<'_>,
) -> ProviderRouteDecision {
    let now = chrono::Utc::now().timestamp_millis();
    match runtime
        .store
        .provider_route_is_current(
            route.device_key,
            route.platform,
            route.channel_type,
            route.provider_token,
            route.route_updated_at,
        )
        .await
    {
        Ok(true) => ProviderRouteDecision::Send,
        Ok(false) => {
            let settled = runtime
                .store
                .settle_provider_dispatch_job(
                    lease,
                    crate::storage::ProviderDispatchSettlement::Superseded,
                    now,
                    0,
                    Some("route_superseded"),
                    now,
                )
                .await
                .unwrap_or(false);
            if settled
                && let (Some(dedupe_key), Some(op_id)) = (route.dedupe_key, route.op_id)
                && let Ok(Some(success)) = runtime
                    .store
                    .provider_dispatch_terminal_success(&lease.record.delivery_id)
                    .await
            {
                runtime
                    .store
                    .finalize_provider_dispatch_outcome_durably(
                        dedupe_key,
                        op_id,
                        &lease.record.delivery_id,
                        success,
                    )
                    .await;
            }
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "dispatch.provider_route_superseded",
                provider = %lease.record.provider,
                delivery_id = %lease.record.delivery_id,
                device_key = %route.device_key,
                route_updated_at = route.route_updated_at,
                settled = settled
            );
            if settled {
                ProviderRouteDecision::Superseded
            } else {
                ProviderRouteDecision::Deferred
            }
        }
        Err(err) => {
            let next_attempt_at = now.saturating_add(provider_retry_delay_millis(lease));
            let _ = runtime
                .store
                .settle_provider_dispatch_job(
                    lease,
                    crate::storage::ProviderDispatchSettlement::Retry,
                    next_attempt_at,
                    0,
                    Some("route_validation_unavailable"),
                    now,
                )
                .await;
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "dispatch.provider_route_validation_failed",
                provider = %lease.record.provider,
                delivery_id = %lease.record.delivery_id,
                device_key = %route.device_key,
                error = %err
            );
            ProviderRouteDecision::Deferred
        }
    }
}

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
        // Alert, Live Activity, and Widget lanes retain independent queues and
        // adaptive feedback, while this fair semaphore prevents their combined
        // APNs request concurrency from exceeding the proven alert-lane cap.
        let apns_global_limit = Arc::new(tokio::sync::Semaphore::new(self.config.apns.maximum));
        let mut tasks = Vec::with_capacity(
            self.config.apns.maximum
                + self.config.live_activity.maximum
                + self.config.widgets.maximum
                + self.config.fcm.maximum
                + self.config.wns.maximum
                + 5,
        );
        self.spawn_apns_workers(
            "APNS",
            receivers.apns,
            self.config.apns,
            Arc::clone(&apns_global_limit),
            &mut tasks,
        );
        self.spawn_apns_workers(
            "APNS_LIVE_ACTIVITY",
            receivers.live_activity,
            self.config.live_activity,
            Arc::clone(&apns_global_limit),
            &mut tasks,
        );
        self.spawn_widget_push_workers(receivers.widget_push, apns_global_limit, &mut tasks);
        self.spawn_fcm_workers(receivers.fcm, &mut tasks);
        self.spawn_wns_workers(receivers.wns, &mut tasks);
        DispatchWorkerTasks { tasks }
    }

    fn spawn_apns_workers(
        &self,
        provider: &'static str,
        apns_rx: Receiver<ApnsJob>,
        lane: super::config::ProviderLaneConfig,
        apns_global_limit: Arc<tokio::sync::Semaphore>,
        tasks: &mut Vec<DispatchWorkerTask>,
    ) {
        let (gate, lane_closed, feedback) = self.spawn_adaptive_controller(provider, lane, tasks);
        for worker_slot in 0..lane.maximum {
            let gate = Arc::clone(&gate);
            let lane_closed = Arc::clone(&lane_closed);
            let feedback = Arc::clone(&feedback);
            let apns_rx = apns_rx.clone();
            let apns = Arc::clone(&self.apns);
            let apns_global_limit = Arc::clone(&apns_global_limit);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = provider,
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started(provider, worker_slot);
                    let owner = worker_owner(provider, worker_slot);
                    let mut claim_fairness = ProviderClaimFairness::default();
                    loop {
                        if apns_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        if !gate.wait_until_active(worker_slot).await {
                            break;
                        }
                        let probe_permit = feedback.acquire_probe_permit().await;
                        // The sender may disconnect while this worker is parked behind the
                        // adaptive gate or provider failure circuit. Re-check before claiming
                        // durable work so shutdown drains only attempts that were already in
                        // flight; unclaimed backlog remains available to the next runtime.
                        if apns_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        let Some(claimed) = claim_apns_job(
                            &apns_rx,
                            &runtime,
                            &owner,
                            provider,
                            &mut claim_fairness,
                        )
                        .await
                        else {
                            if apns_rx.is_disconnected() {
                                lane_closed.store(true, Ordering::Release);
                                gate.close();
                                break;
                            }
                            continue;
                        };
                        let mut lease_confirmed_until = claimed.lease.lease_until;
                        let _apns_global_permit = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            Arc::clone(&apns_global_limit).acquire_owned(),
                        )
                        .await
                        {
                            Ok(Ok(permit)) => permit,
                            Ok(Err(_)) => break,
                            Err(err) => {
                                emit_provider_lease_lost(provider, &claimed.lease, err);
                                continue;
                            }
                        };
                        let route_decision = if claimed.job.route_fenced {
                            match run_with_provider_lease_heartbeat(
                                &runtime,
                                &claimed.lease,
                                &mut lease_confirmed_until,
                                validate_claimed_provider_route(
                                    &runtime,
                                    &claimed.lease,
                                    ProviderRouteClaim {
                                        dedupe_key: claimed.dedupe_key.as_deref(),
                                        op_id: claimed.op_id.as_deref(),
                                        platform: claimed.job.platform,
                                        channel_type: crate::storage::RouteChannelType::Apns,
                                        device_key: claimed.job.device_key.as_ref(),
                                        provider_token: claimed.job.device_token.as_ref(),
                                        route_updated_at: claimed.job.route_updated_at,
                                    },
                                ),
                            )
                            .await
                            {
                                Ok(decision) => decision,
                                Err(err) => {
                                    emit_provider_lease_lost(provider, &claimed.lease, err);
                                    continue;
                                }
                            }
                        } else {
                            ProviderRouteDecision::Send
                        };
                        if route_decision != ProviderRouteDecision::Send {
                            if route_decision == ProviderRouteDecision::Superseded
                                && let Some(outcome) = claimed.job.outcome.as_ref()
                                && outcome.record_provider_result(true)
                            {
                                runtime.finalize_provider_dispatch_outcome(outcome).await;
                            }
                            continue;
                        }
                        let job = claimed.job;
                        let apns_client = Arc::clone(&apns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let provider_attempt = async {
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
                                    provider,
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
                            (dispatch, actual_path)
                        };
                        let (dispatch, actual_path) = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            provider_attempt,
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                emit_provider_lease_lost(provider, &claimed.lease, err);
                                continue;
                            }
                        };
                        runtime.record_provider_dispatch_result(
                            provider,
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
                        probe_permit.finish(provider, &dispatch);
                        let terminal = settle_provider_attempt(
                            &runtime,
                            &claimed.lease,
                            claimed.dedupe_key.as_deref(),
                            claimed.op_id.as_deref(),
                            &dispatch,
                        )
                        .await;
                        if terminal
                            && let Some(outcome) = job.outcome.as_ref()
                            && outcome.record_provider_result(dispatch.success)
                        {
                            runtime.finalize_provider_dispatch_outcome(outcome).await;
                        }
                        if !dispatch.success {
                            runtime.log_provider_dispatch_failure(
                                ProviderDispatchFailureLog {
                                    provider,
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
                            if provider == "APNS_LIVE_ACTIVITY" {
                                if let Some(activity_key) = job.collapse_id.as_deref()
                                    && let Err(err) = runtime
                                        .store
                                        .delete_live_activity_token(
                                            activity_key,
                                            Some(job.device_token.as_ref()),
                                        )
                                        .await
                                {
                                    ::tracing::event!(
                                        target: "gateway.trace_event",
                                        ::tracing::Level::WARN,
                                        event = "activity.invalid_token_cleanup_failed",
                                        activity_key = %(crate::util::redact_text(activity_key)),
                                        error = %(err.to_string())
                                    );
                                }
                            } else {
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
                                    provider,
                                    correlation_id: job.correlation_id.as_ref(),
                                })
                                .await;
                            }
                        }
                    }
                    emit_dispatch_worker_stopped(provider, worker_slot, "channel_closed");
                }
                .instrument(worker_span),
            );
            tasks.push(DispatchWorkerTask {
                provider,
                worker_slot,
                handle,
            });
        }
    }

    fn spawn_widget_push_workers(
        &self,
        widget_push_rx: Receiver<WidgetPushJob>,
        apns_global_limit: Arc<tokio::sync::Semaphore>,
        tasks: &mut Vec<DispatchWorkerTask>,
    ) {
        let (gate, lane_closed, feedback) =
            self.spawn_adaptive_controller("APNS_WIDGETS", self.config.widgets, tasks);
        for worker_slot in 0..self.config.widgets.maximum {
            let gate = Arc::clone(&gate);
            let lane_closed = Arc::clone(&lane_closed);
            let feedback = Arc::clone(&feedback);
            let widget_push_rx = widget_push_rx.clone();
            let apns = Arc::clone(&self.apns);
            let apns_global_limit = Arc::clone(&apns_global_limit);
            let runtime = self.runtime.clone();
            let worker_span = tracing::info_span!(
                "gateway.dispatch.worker",
                provider = "APNS_WIDGETS",
                worker_slot = worker_slot
            );
            let handle = tokio::spawn(
                async move {
                    emit_dispatch_worker_started("APNS_WIDGETS", worker_slot);
                    let owner = worker_owner("APNS_WIDGETS", worker_slot);
                    let mut claim_fairness = ProviderClaimFairness::default();
                    loop {
                        if widget_push_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        if !gate.wait_until_active(worker_slot).await {
                            break;
                        }
                        let probe_permit = feedback.acquire_probe_permit().await;
                        if widget_push_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        let Some(claimed) = claim_widget_job(
                            &widget_push_rx,
                            &runtime,
                            &owner,
                            &mut claim_fairness,
                        )
                        .await
                        else {
                            if widget_push_rx.is_disconnected() {
                                lane_closed.store(true, Ordering::Release);
                                gate.close();
                                break;
                            }
                            continue;
                        };
                        let mut lease_confirmed_until = claimed.lease.lease_until;
                        let _apns_global_permit = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            Arc::clone(&apns_global_limit).acquire_owned(),
                        )
                        .await
                        {
                            Ok(Ok(permit)) => permit,
                            Ok(Err(_)) => break,
                            Err(err) => {
                                emit_provider_lease_lost("APNS_WIDGETS", &claimed.lease, err);
                                continue;
                            }
                        };
                        let job = claimed.job;
                        let apns_client = Arc::clone(&apns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let payload = Arc::new(ApnsPayload::widgets());
                        let dispatch = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            apns_client.send_to_device(
                                job.device_token.as_ref(),
                                job.platform,
                                Arc::clone(&payload),
                                job.collapse_id.clone(),
                            ),
                        )
                        .await
                        {
                            Ok(dispatch) => dispatch,
                            Err(err) => {
                                emit_provider_lease_lost("APNS_WIDGETS", &claimed.lease, err);
                                continue;
                            }
                        };
                        probe_permit.finish("APNS_WIDGETS", &dispatch);
                        let _ = settle_provider_attempt(
                            &runtime,
                            &claimed.lease,
                            None,
                            None,
                            &dispatch,
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
        let (gate, lane_closed, feedback) =
            self.spawn_adaptive_controller("FCM", self.config.fcm, tasks);
        for worker_slot in 0..self.config.fcm.maximum {
            let gate = Arc::clone(&gate);
            let lane_closed = Arc::clone(&lane_closed);
            let feedback = Arc::clone(&feedback);
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
                    let owner = worker_owner("FCM", worker_slot);
                    let mut claim_fairness = ProviderClaimFairness::default();
                    loop {
                        if fcm_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        if !gate.wait_until_active(worker_slot).await {
                            break;
                        }
                        let probe_permit = feedback.acquire_probe_permit().await;
                        if fcm_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        let Some(claimed) =
                            claim_fcm_job(&fcm_rx, &runtime, &owner, &mut claim_fairness).await
                        else {
                            if fcm_rx.is_disconnected() {
                                lane_closed.store(true, Ordering::Release);
                                gate.close();
                                break;
                            }
                            continue;
                        };
                        let mut lease_confirmed_until = claimed.lease.lease_until;
                        let route_decision = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            validate_claimed_provider_route(
                                &runtime,
                                &claimed.lease,
                                ProviderRouteClaim {
                                    dedupe_key: claimed.dedupe_key.as_deref(),
                                    op_id: claimed.op_id.as_deref(),
                                    platform: Platform::ANDROID,
                                    channel_type: crate::storage::RouteChannelType::Fcm,
                                    device_key: claimed.job.device_key.as_ref(),
                                    provider_token: claimed.job.device_token.as_ref(),
                                    route_updated_at: claimed.job.route_updated_at,
                                },
                            ),
                        )
                        .await
                        {
                            Ok(decision) => decision,
                            Err(err) => {
                                emit_provider_lease_lost("FCM", &claimed.lease, err);
                                continue;
                            }
                        };
                        if route_decision != ProviderRouteDecision::Send {
                            if route_decision == ProviderRouteDecision::Superseded
                                && let Some(outcome) = claimed.job.outcome.as_ref()
                                && outcome.record_provider_result(true)
                            {
                                runtime.finalize_provider_dispatch_outcome(outcome).await;
                            }
                            continue;
                        }
                        let job = claimed.job;
                        let fcm_client = Arc::clone(&fcm);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let provider_attempt = async {
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
                            (dispatch, actual_path)
                        };
                        let (dispatch, actual_path) = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            provider_attempt,
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                emit_provider_lease_lost("FCM", &claimed.lease, err);
                                continue;
                            }
                        };
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
                        probe_permit.finish("FCM", &dispatch);
                        let terminal = settle_provider_attempt(
                            &runtime,
                            &claimed.lease,
                            claimed.dedupe_key.as_deref(),
                            claimed.op_id.as_deref(),
                            &dispatch,
                        )
                        .await;
                        if terminal
                            && let Some(outcome) = job.outcome.as_ref()
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
        let (gate, lane_closed, feedback) =
            self.spawn_adaptive_controller("WNS", self.config.wns, tasks);
        for worker_slot in 0..self.config.wns.maximum {
            let gate = Arc::clone(&gate);
            let lane_closed = Arc::clone(&lane_closed);
            let feedback = Arc::clone(&feedback);
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
                    let owner = worker_owner("WNS", worker_slot);
                    let mut claim_fairness = ProviderClaimFairness::default();
                    loop {
                        if wns_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        if !gate.wait_until_active(worker_slot).await {
                            break;
                        }
                        let probe_permit = feedback.acquire_probe_permit().await;
                        if wns_rx.is_disconnected() {
                            lane_closed.store(true, Ordering::Release);
                            gate.close();
                            break;
                        }
                        let Some(claimed) =
                            claim_wns_job(&wns_rx, &runtime, &owner, &mut claim_fairness).await
                        else {
                            if wns_rx.is_disconnected() {
                                lane_closed.store(true, Ordering::Release);
                                gate.close();
                                break;
                            }
                            continue;
                        };
                        let mut lease_confirmed_until = claimed.lease.lease_until;
                        let route_decision = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            validate_claimed_provider_route(
                                &runtime,
                                &claimed.lease,
                                ProviderRouteClaim {
                                    dedupe_key: claimed.dedupe_key.as_deref(),
                                    op_id: claimed.op_id.as_deref(),
                                    platform: Platform::WINDOWS,
                                    channel_type: crate::storage::RouteChannelType::Wns,
                                    device_key: claimed.job.device_key.as_ref(),
                                    provider_token: claimed.job.device_token.as_ref(),
                                    route_updated_at: claimed.job.route_updated_at,
                                },
                            ),
                        )
                        .await
                        {
                            Ok(decision) => decision,
                            Err(err) => {
                                emit_provider_lease_lost("WNS", &claimed.lease, err);
                                continue;
                            }
                        };
                        if route_decision != ProviderRouteDecision::Send {
                            if route_decision == ProviderRouteDecision::Superseded
                                && let Some(outcome) = claimed.job.outcome.as_ref()
                                && outcome.record_provider_result(true)
                            {
                                runtime.finalize_provider_dispatch_outcome(outcome).await;
                            }
                            continue;
                        }
                        let job = claimed.job;
                        let wns_client = Arc::clone(&wns);
                        let runtime = runtime.clone();
                        let channel_id = encode_crockford_base32_128(&job.channel_id);
                        let provider_attempt = async {
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
                            (dispatch, actual_path)
                        };
                        let (dispatch, actual_path) = match run_with_provider_lease_heartbeat(
                            &runtime,
                            &claimed.lease,
                            &mut lease_confirmed_until,
                            provider_attempt,
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                emit_provider_lease_lost("WNS", &claimed.lease, err);
                                continue;
                            }
                        };
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
                        probe_permit.finish("WNS", &dispatch);
                        let terminal = settle_provider_attempt(
                            &runtime,
                            &claimed.lease,
                            claimed.dedupe_key.as_deref(),
                            claimed.op_id.as_deref(),
                            &dispatch,
                        )
                        .await;
                        if terminal
                            && let Some(outcome) = job.outcome.as_ref()
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

    fn spawn_adaptive_controller(
        &self,
        provider: &'static str,
        lane: super::config::ProviderLaneConfig,
        tasks: &mut Vec<DispatchWorkerTask>,
    ) -> (
        Arc<ProviderLaneGate>,
        Arc<AtomicBool>,
        Arc<ProviderLaneFeedback>,
    ) {
        let gate = Arc::new(ProviderLaneGate::new(lane.minimum));
        let closed = Arc::new(AtomicBool::new(false));
        let feedback = Arc::new(ProviderLaneFeedback::default());
        let controller_gate = Arc::clone(&gate);
        let controller_closed = Arc::clone(&closed);
        let controller_feedback = Arc::clone(&feedback);
        let store = self.runtime.store.clone();
        let handle = tokio::spawn(async move {
            let mut idle_windows = 0_u8;
            let mut cooldown_windows = 0_u8;
            let mut maintenance_ticks = 0_u8;
            let mut maintenance_failures = 0_u64;
            loop {
                if controller_closed.load(Ordering::Acquire) {
                    break;
                }
                let now = chrono::Utc::now().timestamp_millis();
                if provider == "APNS" && maintenance_ticks == 0 {
                    let maintenance: crate::storage::StoreResult<()> = async {
                        store.recover_expired_provider_dispatch_leases(now).await?;
                        store
                            .reconcile_preparing_provider_dispatch_jobs(now)
                            .await?;
                        // A process can die after the durable provider row is
                        // terminal but before sender/dedupe finalization. Jobs
                        // may also become terminal by TTL expiry without a
                        // worker attempt. Reconcile those terminal operations
                        // continuously; the storage query skips open work even
                        // while its operation lease is still live.
                        store.recover_interrupted_provider_dispatches(now).await?;
                        Ok(())
                    }
                    .await;
                    match maintenance {
                        Ok(()) => {
                            if maintenance_failures > 0 {
                                ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::INFO,
                                    event = "dispatch.provider_maintenance_recovered",
                                    failed_attempts = maintenance_failures);
                                maintenance_failures = 0;
                            }
                        }
                        Err(err) => {
                            maintenance_failures = maintenance_failures.saturating_add(1);
                            if maintenance_failures <= 8 || maintenance_failures.is_power_of_two() {
                                ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::WARN,
                                    event = "dispatch.provider_maintenance_failed",
                                    failed_attempts = maintenance_failures,
                                    error = %(err.to_string()));
                            }
                        }
                    }
                }
                maintenance_ticks = (maintenance_ticks + 1) % 4;
                let backlog = store
                    .count_pending_provider_dispatch_jobs(provider)
                    .await
                    .unwrap_or(0);
                let successes = controller_feedback.successes.swap(0, Ordering::AcqRel);
                let retryable_failures = controller_feedback
                    .retryable_failures
                    .swap(0, Ordering::AcqRel);
                let global_throttles = controller_feedback
                    .global_throttles
                    .swap(0, Ordering::AcqRel);
                let current = controller_gate.load();
                let completed = successes.saturating_add(retryable_failures);
                let unhealthy_retry_ratio =
                    completed >= 4 && retryable_failures.saturating_mul(10) > completed;
                cooldown_windows = cooldown_windows.saturating_sub(1);
                let next = if global_throttles > 0 {
                    idle_windows = 0;
                    cooldown_windows = 4;
                    current.div_ceil(2).max(lane.minimum)
                } else if unhealthy_retry_ratio {
                    idle_windows = 0;
                    cooldown_windows = 4;
                    current.saturating_mul(7).div_ceil(10).max(lane.minimum)
                } else if cooldown_windows == 0
                    && backlog > current.saturating_mul(2)
                    && successes > 0
                {
                    idle_windows = 0;
                    current.saturating_mul(2).max(current + 1).min(lane.maximum)
                } else if backlog == 0 {
                    idle_windows = idle_windows.saturating_add(1);
                    if idle_windows >= 4 {
                        current.saturating_sub(1).max(lane.minimum)
                    } else {
                        current
                    }
                } else {
                    idle_windows = 0;
                    current
                };
                if next != current {
                    controller_gate.store(next);
                    ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::INFO,
                        event = "dispatch.provider_concurrency_changed", provider = %provider,
                        previous = (current as u64), active = (next as u64), backlog = (backlog as u64),
                        successes = (successes as u64), retryable_failures = (retryable_failures as u64),
                        global_throttles = (global_throttles as u64), cooldown_windows = (cooldown_windows as u64));
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        tasks.push(DispatchWorkerTask {
            provider,
            worker_slot: usize::MAX,
            handle,
        });
        (gate, closed, feedback)
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
            DedupeState, DeviceRouteRecordRow, OpDedupeReservation, SenderSubmitStatusKind,
            SenderSubmitStatusRecord,
        },
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use tokio::time::{Duration, sleep, timeout};

    struct StaticFcmClient {
        success: bool,
        calls: AtomicUsize,
    }

    struct RetryableFcmClient {
        calls: AtomicUsize,
    }

    struct SlowSuccessFcmClient {
        calls: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl FcmClient for SlowSuccessFcmClient {
        fn send_to_device<'a>(
            &'a self,
            _device_token: &'a str,
            _payload: Arc<FcmPayload>,
            _prepared_body: Option<Arc<[u8]>>,
        ) -> BoxFuture<'a, DispatchResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let concurrent = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(concurrent, Ordering::SeqCst);
            Box::pin(async move {
                sleep(Duration::from_millis(50)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                DispatchResult::success(200)
            })
        }

        fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }

        fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }
    }

    impl FcmClient for RetryableFcmClient {
        fn send_to_device<'a>(
            &'a self,
            _device_token: &'a str,
            _payload: Arc<FcmPayload>,
            _prepared_body: Option<Arc<[u8]>>,
        ) -> BoxFuture<'a, DispatchResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                DispatchResult::transport(crate::Error::Internal(
                    "injected transient outage".into(),
                ))
            })
        }

        fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }

        fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
            Box::pin(async { Err(crate::Error::Internal("unused".into())) })
        }
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

    #[test]
    fn provider_lease_has_room_for_a_missed_heartbeat_and_database_jitter() {
        let request_timeout = i64::try_from(crate::providers::PROVIDER_REQUEST_TIMEOUT.as_millis())
            .expect("provider timeout should fit i64 milliseconds");
        assert!(PROVIDER_DISPATCH_LEASE_MILLIS > request_timeout);
        let heartbeat = i64::try_from(PROVIDER_DISPATCH_LEASE_HEARTBEAT.as_millis())
            .expect("heartbeat should fit i64 milliseconds");
        assert!(
            PROVIDER_DISPATCH_LEASE_MILLIS
                >= heartbeat * 2 + PROVIDER_DISPATCH_LEASE_EXPIRY_GUARD_MILLIS
        );
    }

    #[test]
    fn consecutive_retryable_failures_open_and_success_closes_lane_probe_circuit() {
        let feedback = ProviderLaneFeedback::default();
        let failure = DispatchResult::transport(crate::Error::Internal(
            "injected fast provider failure".to_string(),
        ));
        for _ in 1..PROVIDER_FAILURE_CIRCUIT_THRESHOLD {
            feedback.record("APNS", &failure);
        }
        assert_eq!(feedback.paused_until_millis.load(Ordering::Acquire), 0);

        feedback.record("APNS", &failure);
        assert!(
            feedback.paused_until_millis.load(Ordering::Acquire)
                > chrono::Utc::now().timestamp_millis()
        );

        feedback.record("APNS", &DispatchResult::success(200));
        assert_eq!(feedback.paused_until_millis.load(Ordering::Acquire), 0);
        assert_eq!(
            feedback
                .consecutive_retryable_failures
                .load(Ordering::Acquire),
            0
        );
    }

    #[tokio::test]
    async fn half_open_circuit_allows_only_one_concurrent_probe() {
        let feedback = Arc::new(ProviderLaneFeedback::default());
        let failure = DispatchResult::transport(crate::Error::Internal(
            "injected fast provider failure".to_string(),
        ));
        for _ in 0..PROVIDER_FAILURE_CIRCUIT_THRESHOLD {
            feedback.record("FCM", &failure);
        }
        feedback
            .paused_until_millis
            .store(chrono::Utc::now().timestamp_millis() - 1, Ordering::Release);

        let first = feedback.acquire_probe_permit().await;
        assert!(first.is_probe);

        let contender_feedback = Arc::clone(&feedback);
        let contender =
            tokio::spawn(async move { contender_feedback.acquire_probe_permit().await });
        sleep(Duration::from_millis(25)).await;
        assert!(
            !contender.is_finished(),
            "a second half-open attempt must remain parked while the probe is live"
        );
        feedback.record("FCM", &DispatchResult::success(200));
        sleep(Duration::from_millis(10)).await;
        assert!(
            !contender.is_finished(),
            "an older in-flight success must not bypass the sole half-open probe"
        );

        first.finish("FCM", &DispatchResult::success(200));
        let contender = timeout(Duration::from_millis(250), contender)
            .await
            .expect("closing the circuit should release parked workers")
            .expect("contender task should not panic");
        assert!(!contender.is_probe);
    }

    #[tokio::test]
    async fn heartbeat_keeps_a_live_attempt_owned_across_its_original_lease() {
        let dir = tempdir().expect("provider heartbeat tempdir");
        let db_path = dir.path().join("provider-worker-heartbeat.sqlite");
        std::fs::File::create(&db_path).expect("provider heartbeat sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("provider heartbeat storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        let job = FcmJob {
            channel_id: [21; 16],
            correlation_id: Arc::from("heartbeat-op"),
            delivery_id: Arc::from("heartbeat-delivery"),
            device_key: Arc::from("heartbeat-device"),
            device_token: Arc::from("heartbeat-token"),
            route_updated_at: now,
            direct_payload: Arc::new(FcmPayload::new(
                hashbrown::HashMap::<String, String>::new(),
                "NORMAL",
                None,
            )),
            direct_body: Arc::from(Vec::<u8>::new()),
            wakeup_payload: None,
            wakeup_body: None,
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit: false,
            outcome: None,
        };
        store
            .enqueue_provider_dispatch_job(
                &DurableProviderJob::from_fcm(&job)
                    .to_record("pending", now, now + 60_000)
                    .expect("encode heartbeat job"),
            )
            .await
            .expect("persist heartbeat job");
        let lease = store
            .claim_provider_dispatch_job("FCM", None, "heartbeat-owner", now, now + 5_000)
            .await
            .expect("heartbeat claim should succeed")
            .expect("heartbeat job should exist");
        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let runtime = DispatchWorkerRuntime {
            store: store.clone(),
            private: None,
            runtime_counters: Arc::clone(&runtime_counters),
        };
        let mut wrong_owner = lease.clone();
        wrong_owner.owner = "not-the-owner".to_string();
        assert!(
            !store
                .renew_provider_dispatch_job_lease(&wrong_owner, now + 1, now + 500)
                .await
                .expect("wrong-owner renewal query should run")
        );
        let mut wrong_generation = lease.clone();
        wrong_generation.lease_generation += 1;
        assert!(
            !store
                .renew_provider_dispatch_job_lease(&wrong_generation, now + 1, now + 500)
                .await
                .expect("wrong-generation renewal query should run")
        );

        // Keep setup latency outside the lease window under test. Shared CI
        // runners can spend well over the old 120 ms window on the two
        // negative SQLite checks above even though the heartbeat itself is
        // healthy. Start a fresh, still aggressively short lease here so this
        // oracle measures renewal behavior rather than scheduler contention.
        let heartbeat_started_at = chrono::Utc::now().timestamp_millis();
        let original_test_lease_until = heartbeat_started_at + 500;
        assert!(
            store
                .renew_provider_dispatch_job_lease(
                    &lease,
                    heartbeat_started_at,
                    original_test_lease_until,
                )
                .await
                .expect("initial heartbeat test lease should renew")
        );
        let mut confirmed_until = original_test_lease_until;
        let live_attempt = run_with_provider_lease_heartbeat_config(
            &runtime,
            &lease,
            &mut confirmed_until,
            Duration::from_millis(50),
            500,
            100,
            sleep(Duration::from_millis(1_200)),
        );
        let competing_claim = async {
            sleep(Duration::from_millis(700)).await;
            let reclaim_at = chrono::Utc::now().timestamp_millis();
            let recovered = store
                .recover_expired_provider_dispatch_leases(reclaim_at)
                .await
                .expect("lease recovery should run");
            let claimed = store
                .claim_provider_dispatch_job(
                    "FCM",
                    None,
                    "competing-owner",
                    reclaim_at,
                    reclaim_at + 500,
                )
                .await
                .expect("competing claim query should run");
            (recovered, claimed)
        };
        let (attempt, (recovered, competing)) = tokio::join!(live_attempt, competing_claim);
        assert_eq!(attempt, Ok(()));
        assert_eq!(recovered, 0, "maintenance must not reclaim a live attempt");
        assert!(
            competing.is_none(),
            "a live lease must remain exclusively owned"
        );
        assert!(
            confirmed_until > original_test_lease_until,
            "the heartbeat must retain its latest confirmed database deadline"
        );

        let second_stage = run_with_provider_lease_heartbeat_config(
            &runtime,
            &lease,
            &mut confirmed_until,
            Duration::from_millis(50),
            500,
            100,
            sleep(Duration::from_millis(600)),
        );
        let competing_second_stage = async {
            sleep(Duration::from_millis(350)).await;
            let reclaim_at = chrono::Utc::now().timestamp_millis();
            let recovered = store
                .recover_expired_provider_dispatch_leases(reclaim_at)
                .await
                .expect("second-stage lease recovery should run");
            let claimed = store
                .claim_provider_dispatch_job(
                    "FCM",
                    None,
                    "second-competing-owner",
                    reclaim_at,
                    reclaim_at + 500,
                )
                .await
                .expect("second competing claim query should run");
            (recovered, claimed)
        };
        let (second_result, (second_recovered, second_competing)) =
            tokio::join!(second_stage, competing_second_stage);
        assert_eq!(
            second_result,
            Ok(()),
            "a later provider stage must inherit the first stage's renewed deadline"
        );
        assert_eq!(
            second_recovered, 0,
            "maintenance must not reclaim a live second-stage attempt"
        );
        assert!(
            second_competing.is_none(),
            "a second provider stage must retain exclusive lease ownership"
        );

        let settled_at = chrono::Utc::now().timestamp_millis();
        assert!(
            store
                .settle_provider_dispatch_job(
                    &lease,
                    crate::storage::ProviderDispatchSettlement::Accepted,
                    settled_at,
                    200,
                    None,
                    settled_at,
                )
                .await
                .expect("heartbeat lease should settle")
        );
        let report = runtime_counters
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert_eq!(report.aborted, 0);
        assert_eq!(report.panicked, 0);
    }

    #[tokio::test]
    async fn due_retry_is_claimed_within_three_fresh_hints_and_nearest_ttl_wins() {
        let dir = tempdir().expect("provider fairness tempdir");
        let db_path = dir.path().join("provider-worker-fairness.sqlite");
        std::fs::File::create(&db_path).expect("provider fairness sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("provider fairness storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        let make_job = |delivery: String| FcmJob {
            channel_id: [22; 16],
            correlation_id: Arc::from(format!("{delivery}-op")),
            delivery_id: Arc::from(delivery.clone()),
            device_key: Arc::from(format!("{delivery}-device")),
            device_token: Arc::from(format!("{delivery}-token")),
            route_updated_at: now,
            direct_payload: Arc::clone(&payload),
            direct_body: Arc::from(Vec::<u8>::new()),
            wakeup_payload: None,
            wakeup_body: None,
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit: false,
            outcome: None,
        };

        for (delivery, expires_at) in [
            ("retry-far".to_string(), now + 50_000),
            ("retry-near".to_string(), now + 20_000),
        ] {
            let retry_job = make_job(delivery);
            let durable = DurableProviderJob::from_fcm(&retry_job);
            store
                .enqueue_provider_dispatch_job(
                    &durable
                        .to_record("pending", now, expires_at)
                        .expect("encode retry job"),
                )
                .await
                .expect("persist retry job");
            let lease = store
                .claim_provider_dispatch_job(
                    "FCM",
                    Some(&durable.job_id()),
                    "retry-seeder",
                    now,
                    now + 1_000,
                )
                .await
                .expect("seed retry claim")
                .expect("seed retry row should claim");
            assert!(
                store
                    .settle_provider_dispatch_job(
                        &lease,
                        crate::storage::ProviderDispatchSettlement::Retry,
                        now,
                        503,
                        Some("injected"),
                        now,
                    )
                    .await
                    .expect("seed retry settlement")
            );
        }

        let (dispatch, receivers) = DispatchChannels::new();
        for index in 0..4 {
            let fresh = make_job(format!("fresh-{index}"));
            store
                .enqueue_provider_dispatch_job(
                    &DurableProviderJob::from_fcm(&fresh)
                        .to_record("pending", now + index, now + 60_000)
                        .expect("encode fresh job"),
                )
                .await
                .expect("persist fresh job");
            dispatch.try_send_fcm(fresh).expect("queue fresh hint");
        }
        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let runtime = DispatchWorkerRuntime {
            store: store.clone(),
            private: None,
            runtime_counters: Arc::clone(&runtime_counters),
        };
        let mut fairness = ProviderClaimFairness::default();

        for index in 0..MAX_FRESH_HINT_CLAIMS_BEFORE_RETRY_PROBE {
            let claimed = claim_fcm_job(&receivers.fcm, &runtime, "fair-worker", &mut fairness)
                .await
                .expect("fresh hint should claim");
            assert_eq!(claimed.job.delivery_id.as_ref(), format!("fresh-{index}"));
            assert!(
                store
                    .settle_provider_dispatch_job(
                        &claimed.lease,
                        crate::storage::ProviderDispatchSettlement::Accepted,
                        now,
                        200,
                        None,
                        now,
                    )
                    .await
                    .expect("fresh hint should settle")
            );
        }
        let retry = claim_fcm_job(&receivers.fcm, &runtime, "fair-worker", &mut fairness)
            .await
            .expect("due retry must preempt the fourth continuous hint");
        assert_eq!(retry.job.delivery_id.as_ref(), "retry-near");

        drop(dispatch);
        let report = runtime_counters
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert_eq!(report.aborted, 0);
        assert_eq!(report.panicked, 0);
    }

    #[tokio::test]
    async fn recovered_fcm_backlog_is_claimed_without_waiting_for_the_hint_poll_interval() {
        let dir = tempdir().expect("recovered FCM backlog tempdir");
        let db_path = dir.path().join("provider-worker-recovered-backlog.sqlite");
        std::fs::File::create(&db_path).expect("recovered backlog sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("recovered backlog storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));

        for index in 0..8 {
            let job = FcmJob {
                channel_id: [8; 16],
                correlation_id: Arc::from(format!("recovered-fcm-op-{index}")),
                delivery_id: Arc::from(format!("recovered-fcm-delivery-{index}")),
                device_key: Arc::from(format!("recovered-fcm-device-{index}")),
                device_token: Arc::from(format!("recovered-fcm-token-{index}")),
                route_updated_at: now,
                direct_payload: Arc::clone(&payload),
                direct_body: Arc::from(Vec::<u8>::new()),
                wakeup_payload: None,
                wakeup_body: None,
                initial_path: ProviderDeliveryPath::Direct,
                wakeup_payload_within_limit: false,
                outcome: None,
            };
            let durable = DurableProviderJob::from_fcm(&job);
            store
                .enqueue_provider_dispatch_job(
                    &durable
                        .to_record("pending", now, now + 60_000)
                        .expect("encode recovered FCM job"),
                )
                .await
                .expect("persist recovered FCM job");
        }

        // Simulate restart/lost hints: durable rows exist but the in-memory
        // channel is empty and still connected.
        let (_dispatch, receivers) = DispatchChannels::new();
        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let runtime = DispatchWorkerRuntime {
            store,
            private: None,
            runtime_counters,
        };
        let mut fairness = ProviderClaimFairness::default();

        timeout(Duration::from_millis(750), async {
            for index in 0..8 {
                let claimed = claim_fcm_job(
                    &receivers.fcm,
                    &runtime,
                    &format!("recovered-worker-{index}"),
                    &mut fairness,
                )
                .await;
                assert!(
                    claimed.is_some(),
                    "durable recovered job {index} should be claimed"
                );
            }
        })
        .await
        .expect("durable backlog claims must not sleep for the hint poll interval");
    }

    #[tokio::test]
    async fn coalescible_live_activity_claim_sends_latest_durable_generation_not_stale_hint() {
        let dir = tempdir().expect("Live Activity coalescing tempdir");
        let db_path = dir.path().join("live-activity-stale-hint.sqlite");
        std::fs::File::create(&db_path).expect("Live Activity sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("Live Activity storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        let make_job = |title: &str, correlation: &str| ApnsJob {
            channel_id: [12; 16],
            correlation_id: Arc::from(correlation.to_string()),
            delivery_id: Arc::from("liveactivity:event:stale-hint"),
            device_key: Arc::from("liveactivity:event:stale-hint:token-hash"),
            device_token: Arc::from(
                "5555555555555555555555555555555555555555555555555555555555555555",
            ),
            route_updated_at: now,
            platform: Platform::IOS,
            direct_payload: Arc::new(ApnsPayload::live_activity(
                title.to_string(),
                Some("open".to_string()),
                None,
                now,
                "update",
                "io.ethan.pushgo.push-type.liveactivity",
            )),
            wakeup_payload: None,
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit: false,
            collapse_id: Some(Arc::from("event:stale-hint")),
            route_fenced: false,
            coalescible: true,
            outcome: None,
        };
        let old = make_job("old", "activity-old");
        let new = make_job("new", "activity-new");
        let mut old_record = DurableProviderJob::from_apns(&old)
            .to_record("pending", now, now + 60_000)
            .expect("old Activity job should encode");
        old_record.provider = "APNS_LIVE_ACTIVITY".to_string();
        store
            .enqueue_provider_dispatch_job(&old_record)
            .await
            .expect("old Activity job should persist");

        let (dispatch, receivers) = DispatchChannels::new();
        dispatch
            .try_send_live_activity(old)
            .expect("old Activity hint should queue");
        let mut new_record = DurableProviderJob::from_apns(&new)
            .to_record("pending", now + 1, now + 60_001)
            .expect("new Activity job should encode");
        new_record.provider = "APNS_LIVE_ACTIVITY".to_string();
        store
            .enqueue_provider_dispatch_job(&new_record)
            .await
            .expect("new Activity generation should replace the durable row");

        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let runtime = DispatchWorkerRuntime {
            store: store.clone(),
            private: None,
            runtime_counters: Arc::clone(&runtime_counters),
        };
        let mut fairness = ProviderClaimFairness::default();
        let claimed = claim_apns_job(
            &receivers.live_activity,
            &runtime,
            "activity-stale-hint-worker",
            "APNS_LIVE_ACTIVITY",
            &mut fairness,
        )
        .await
        .expect("latest Activity generation should claim");
        let payload = serde_json::to_value(claimed.job.direct_payload.as_ref())
            .expect("claimed Activity payload should serialize");
        assert_eq!(payload["aps"]["content-state"]["title"], "new");

        store
            .settle_provider_dispatch_job(
                &claimed.lease,
                crate::storage::ProviderDispatchSettlement::Accepted,
                now + 2,
                200,
                None,
                now + 2,
            )
            .await
            .expect("claimed Activity generation should settle");
        drop(dispatch);
        let report = runtime_counters
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert_eq!(report.aborted, 0);
        assert_eq!(report.panicked, 0);
    }

    #[tokio::test]
    async fn graceful_shutdown_preserves_future_retry_without_waiting_for_its_due_time() {
        let dir = tempdir().expect("retry shutdown tempdir");
        let db_path = dir.path().join("provider-worker-retry-shutdown.sqlite");
        std::fs::File::create(&db_path).expect("retry shutdown sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("retry shutdown storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        store
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: "retry-shutdown-device".to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: crate::storage::RouteChannelType::Fcm.as_str().to_string(),
                provider_token: Some("retry-shutdown-token".to_string()),
                updated_at: now,
            })
            .await
            .expect("retry shutdown route should exist");

        let fcm = Arc::new(RetryableFcmClient {
            calls: AtomicUsize::new(0),
        });
        let (dispatch, receivers) = DispatchChannels::new();
        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let workers = DispatchWorkerDeps {
            apns: Arc::new(UnusedApnsClient),
            fcm: fcm.clone(),
            wns: Arc::new(UnusedWnsClient),
            store: store.clone(),
            private: None,
            runtime_counters,
            runtime_profile: GatewayRuntimeProfile::Small,
        }
        .spawn(receivers);
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        let job = FcmJob {
            channel_id: [9; 16],
            correlation_id: Arc::from("retry-shutdown-op"),
            delivery_id: Arc::from("retry-shutdown-delivery"),
            device_key: Arc::from("retry-shutdown-device"),
            device_token: Arc::from("retry-shutdown-token"),
            route_updated_at: now,
            direct_payload: payload,
            direct_body: Arc::from(Vec::<u8>::new()),
            wakeup_payload: None,
            wakeup_body: None,
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit: false,
            outcome: None,
        };
        let durable = DurableProviderJob::from_fcm(&job);
        store
            .enqueue_provider_dispatch_job(
                &durable
                    .to_record("pending", now, now + 60_000)
                    .expect("encode retry shutdown job"),
            )
            .await
            .expect("persist retry shutdown job");
        dispatch
            .try_send_fcm(job)
            .expect("enqueue retry shutdown hint");

        timeout(Duration::from_millis(500), async {
            while fcm.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first provider attempt should run");
        drop(dispatch);

        let report = workers
            .shutdown_until(tokio::time::Instant::now() + Duration::from_millis(750))
            .await;
        assert_eq!(report.panicked, 0);
        assert_eq!(
            report.aborted, 0,
            "future durable retries must survive shutdown without holding it open"
        );
        assert_eq!(fcm.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            store
                .count_pending_provider_dispatch_jobs("FCM")
                .await
                .expect("pending retry count"),
            1,
            "the retry row must remain durable for the next runtime"
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_claiming_due_backlog_and_preserves_it_for_restart() {
        const JOBS: usize = 128;

        let dir = tempdir().expect("due backlog shutdown tempdir");
        let db_path = dir
            .path()
            .join("provider-worker-due-backlog-shutdown.sqlite");
        std::fs::File::create(&db_path).expect("due backlog shutdown sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("due backlog shutdown storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        store
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: "due-backlog-device".to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: crate::storage::RouteChannelType::Fcm.as_str().to_string(),
                provider_token: Some("due-backlog-token".to_string()),
                updated_at: now,
            })
            .await
            .expect("due backlog route should exist");

        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        for index in 0..JOBS {
            let job = FcmJob {
                channel_id: [11; 16],
                correlation_id: Arc::from(format!("due-backlog-op-{index}")),
                delivery_id: Arc::from(format!("due-backlog-delivery-{index}")),
                device_key: Arc::from("due-backlog-device"),
                device_token: Arc::from("due-backlog-token"),
                route_updated_at: now,
                direct_payload: Arc::clone(&payload),
                direct_body: Arc::from(Vec::<u8>::new()),
                wakeup_payload: None,
                wakeup_body: None,
                initial_path: ProviderDeliveryPath::Direct,
                wakeup_payload_within_limit: false,
                outcome: None,
            };
            let durable = DurableProviderJob::from_fcm(&job);
            store
                .enqueue_provider_dispatch_job(
                    &durable
                        .to_record("pending", now, now + 60_000)
                        .expect("encode due backlog job"),
                )
                .await
                .expect("persist due backlog job");
        }

        let fcm = Arc::new(RetryableFcmClient {
            calls: AtomicUsize::new(0),
        });
        let (dispatch, receivers) = DispatchChannels::new();
        let runtime_counters = RuntimeCounterCollector::spawn_with_mode(
            store.clone(),
            false,
            GatewayRuntimeProfile::Small,
        );
        let workers = DispatchWorkerDeps {
            apns: Arc::new(UnusedApnsClient),
            fcm: fcm.clone(),
            wns: Arc::new(UnusedWnsClient),
            store: store.clone(),
            private: None,
            runtime_counters,
            runtime_profile: GatewayRuntimeProfile::Small,
        }
        .spawn(receivers);

        timeout(Duration::from_secs(1), async {
            while fcm.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("at least one due provider attempt should start");
        drop(dispatch);

        let report = workers
            .shutdown_until(tokio::time::Instant::now() + Duration::from_millis(1_500))
            .await;
        assert_eq!(report.panicked, 0);
        assert_eq!(
            report.aborted, 0,
            "shutdown must not try to drain the entire durable due backlog"
        );
        let attempts = fcm.calls.load(Ordering::SeqCst);
        assert!(attempts < JOBS, "shutdown kept claiming durable jobs");
        assert_eq!(
            store
                .count_pending_provider_dispatch_jobs("FCM")
                .await
                .expect("pending due backlog count"),
            JOBS,
            "every unaccepted provider job must remain durable for restart"
        );
    }

    #[tokio::test]
    async fn recovered_fcm_backlog_expands_beyond_the_minimum_lane() {
        const JOBS: usize = 100;
        let dir = tempdir().expect("adaptive FCM backlog tempdir");
        let db_path = dir.path().join("provider-worker-adaptive-backlog.sqlite");
        std::fs::File::create(&db_path).expect("adaptive backlog sqlite file");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(&db_url))
            .await
            .expect("adaptive backlog storage should initialize");
        let now = chrono::Utc::now().timestamp_millis();
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        for index in 0..JOBS {
            let device_key = format!("adaptive-fcm-device-{index}");
            let device_token = format!("adaptive-fcm-token-{index}");
            store
                .upsert_device_route(&DeviceRouteRecordRow {
                    device_key: device_key.clone(),
                    platform: Platform::ANDROID.name().to_string(),
                    channel_type: crate::storage::RouteChannelType::Fcm.as_str().to_string(),
                    provider_token: Some(device_token.clone()),
                    updated_at: now,
                })
                .await
                .expect("adaptive route should persist");
            let job = FcmJob {
                channel_id: [10; 16],
                correlation_id: Arc::from(format!("adaptive-fcm-op-{index}")),
                delivery_id: Arc::from(format!("adaptive-fcm-delivery-{index}")),
                device_key: Arc::from(device_key),
                device_token: Arc::from(device_token),
                route_updated_at: now,
                direct_payload: Arc::clone(&payload),
                direct_body: Arc::from(Vec::<u8>::new()),
                wakeup_payload: None,
                wakeup_body: None,
                initial_path: ProviderDeliveryPath::Direct,
                wakeup_payload_within_limit: false,
                outcome: None,
            };
            let durable = DurableProviderJob::from_fcm(&job);
            store
                .enqueue_provider_dispatch_job(
                    &durable
                        .to_record("pending", now, now + 60_000)
                        .expect("encode adaptive FCM job"),
                )
                .await
                .expect("persist adaptive FCM job");
        }

        let fcm = Arc::new(SlowSuccessFcmClient {
            calls: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        });
        let (dispatch, receivers) = DispatchChannels::new();
        let workers = DispatchWorkerDeps {
            apns: Arc::new(UnusedApnsClient),
            fcm: fcm.clone(),
            wns: Arc::new(UnusedWnsClient),
            store: store.clone(),
            private: None,
            runtime_counters: RuntimeCounterCollector::spawn_with_mode(
                store.clone(),
                false,
                GatewayRuntimeProfile::Small,
            ),
            runtime_profile: GatewayRuntimeProfile::Small,
        }
        .spawn(receivers);

        timeout(Duration::from_secs(3), async {
            while fcm.max_in_flight.load(Ordering::SeqCst) <= 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("healthy recovered backlog should expand beyond the two-lane minimum");
        timeout(Duration::from_secs(5), async {
            while fcm.calls.load(Ordering::SeqCst) < JOBS {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("adaptive workers should drain the recovered backlog");

        drop(dispatch);
        let report = workers
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert_eq!(report.panicked, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(
            store
                .count_pending_provider_dispatch_jobs("FCM")
                .await
                .expect("adaptive pending count"),
            0
        );
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
        let dedupe_key = format!("op:worker:message:provider-worker-entity:{op_id}");
        let now = chrono::Utc::now().timestamp_millis();
        assert!(matches!(
            store
                .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now)
                .await
                .expect("reserve op dedupe"),
            OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
        ));
        assert!(
            store
                .mark_op_dedupe_finalized(&dedupe_key, delivery_id, DedupeState::ProviderQueued,)
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
        store
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: "provider-worker-device".to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: crate::storage::RouteChannelType::Fcm.as_str().to_string(),
                provider_token: Some("provider-worker-token".to_string()),
                updated_at: now,
            })
            .await
            .expect("worker route should exist before the fenced send");

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
            Arc::from(dedupe_key.as_str()),
            Arc::from(delivery_id),
        ));
        outcome.configure(1, 0);
        let payload = Arc::new(FcmPayload::new(
            hashbrown::HashMap::<String, String>::new(),
            "NORMAL",
            None,
        ));
        let job = FcmJob {
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
        };
        let durable = DurableProviderJob::from_fcm(&job);
        store
            .enqueue_provider_dispatch_job(
                &durable
                    .to_record("pending", now, now + 60_000)
                    .expect("encode durable FCM job"),
            )
            .await
            .expect("persist durable FCM job");
        dispatch.try_send_fcm(job).expect("enqueue FCM hint");
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
            if pending_record.status != SenderSubmitStatusKind::ProviderQueued {
                // The periodic terminal reconciler is intentionally allowed to
                // race this observation. It reconstructs the terminal result
                // directly from the durable provider row, so it need not
                // consume failures injected only into the worker wrapper.
                assert_eq!(
                    pending_record.status,
                    if success {
                        SenderSubmitStatusKind::Sent
                    } else {
                        SenderSubmitStatusKind::PartiallyFailed
                    }
                );
            }
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
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now + 1)
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
        assert_eq!(worker_report.joined, {
            let config = DispatchRuntimeConfig::from_profile(GatewayRuntimeProfile::Small);
            config.apns.maximum
                + config.live_activity.maximum
                + config.widgets.maximum
                + config.fcm.maximum
                + config.wns.maximum
                + 5
        });

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
