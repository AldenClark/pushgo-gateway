use super::ordinary_store::OrdinaryStore;
use super::store::{ClaimBatch, Counters, KernelError, Result, Ticket, now};
use super::{
    transport::{BoxFuture, DispatchResult},
    types::Platform,
};
use crate::dispatch::ProviderBudgets;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, watch},
    task::JoinHandle,
    time::Instant,
};

pub trait ProviderTransport: Send + Sync {
    /// Release provider-local idle resources after all owned attempts and the
    /// preserved claim have drained. Durable retry work remains in SQL.
    fn quiesce(&self, _provider: &str) {}
    #[allow(clippy::too_many_arguments)] // Preserve the existing experimental transport boundary.
    fn send<'a>(
        &'a self,
        provider: &'a str,
        platform: Platform,
        token: &'a str,
        payload: serde_json::Value,
        delivery: &'a str,
        device: &'a str,
        accepted: i64,
        expiry: i64,
        watch_alert_deadline: Option<i64>,
    ) -> BoxFuture<'a, DispatchResult>;
}
#[derive(Default, Debug)]
pub struct ShutdownReport {
    pub joined: usize,
    pub panicked: usize,
    pub aborted: usize,
    pub failed: usize,
}
pub struct DeliveryRuntime {
    pub store: OrdinaryStore,
    stop: watch::Sender<bool>,
    failure: watch::Receiver<Option<String>>,
    tasks: Vec<JoinHandle<Result<()>>>,
}
impl DeliveryRuntime {
    pub(crate) async fn start_from_store(
        store: OrdinaryStore,
        transport: Arc<dyn ProviderTransport>,
        budgets: Arc<ProviderBudgets>,
    ) -> Result<Self> {
        store.health.ensure()?;
        let (stop, stop_rx) = watch::channel(false);
        let failure = store.health.subscribe();
        let mut tasks = Vec::new();
        for (index, provider) in ["FCM", "APNS", "WNS"].into_iter().enumerate() {
            let driver_store = store.clone();
            let transport = transport.clone();
            let stop_rx = stop_rx.clone();
            let stop_tx = stop.clone();
            let health = store.health.clone();
            let budget = budgets.for_provider(provider);
            let limit = budgets.limit(provider).min(store.config.provider_budget);
            tasks.push(tokio::spawn(async move {
                let counters = driver_store.counters.clone();
                let _alive = AliveGuard::new(counters.clone());
                let outcome = AssertUnwindSafe(pump(
                    driver_store,
                    transport,
                    budget,
                    limit,
                    index,
                    provider,
                    stop_rx,
                ))
                .catch_unwind()
                .await;
                let result = match outcome {
                    Ok(result) => result,
                    Err(_) => Err(KernelError::Invalid("provider pump panicked".into())),
                };
                if let Err(error) = &result {
                    counters.db_errors.fetch_add(1, Ordering::Relaxed);
                    health.fail(&error.to_string());
                    stop_tx.send_replace(true);
                }
                result
            }));
        }
        Ok(Self {
            store,
            stop,
            failure,
            tasks,
        })
    }
    pub async fn wait_failure(&mut self) -> String {
        loop {
            if let Some(error) = self.failure.borrow().clone() {
                return error;
            }
            if self.failure.changed().await.is_err() {
                return "provider driver ownership ended unexpectedly".into();
            }
        }
    }
    pub(crate) fn stop_requester(&self) -> watch::Sender<bool> {
        self.stop.clone()
    }
    #[cfg(test)]
    pub(super) fn stop_probe(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }
    /// The product owner first closes ingress, then drains this bounded runtime.
    /// Storage and its exclusive lock remain owned by normal product lifecycle.
    pub async fn shutdown(mut self) -> ShutdownReport {
        self.stop.send_replace(true);
        let mut report = ShutdownReport::default();
        for task in self.tasks.drain(..) {
            match task.await {
                Ok(result) => {
                    report.joined += 1;
                    if result.is_err() {
                        report.failed += 1;
                    }
                }
                Err(error) if error.is_cancelled() => report.aborted += 1,
                Err(_) => report.panicked += 1,
            }
        }
        report
    }
}
impl Drop for DeliveryRuntime {
    fn drop(&mut self) {
        if !*self.stop.borrow() {
            self.store
                .health
                .fail("delivery runtime dropped; product-owner restart required");
        }
        self.stop.send_replace(true);
    }
}
struct AliveGuard(Arc<Counters>);
impl AliveGuard {
    fn new(counters: Arc<Counters>) -> Self {
        counters.num_alive.fetch_add(1, Ordering::Relaxed);
        Self(counters)
    }
}
impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.num_alive.fetch_sub(1, Ordering::Relaxed);
    }
}
struct AttemptGuard(Arc<Counters>, usize);
impl AttemptGuard {
    fn new(counters: Arc<Counters>, index: usize) -> Self {
        let n = counters.owned_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        counters.peak_owned_attempts.fetch_max(n, Ordering::Relaxed);
        counters.provider_owned[index].fetch_add(1, Ordering::Relaxed);
        Self(counters, index)
    }
}
// A reservation remains live through COMMIT and result adoption, including
// postcommit test barriers. It is not a spawned task or a loaded payload.
struct ClaimReservation {
    counters: Arc<Counters>,
    index: usize,
}
impl ClaimReservation {
    fn new(counters: Arc<Counters>, index: usize, amount: usize) -> Self {
        counters.claim_reservations[index].store(amount as u64, Ordering::Relaxed);
        counters.peak_claim_reservations[index].fetch_max(amount as u64, Ordering::Relaxed);
        Self { counters, index }
    }
}
impl Drop for ClaimReservation {
    fn drop(&mut self) {
        self.counters.claim_reservations[self.index].store(0, Ordering::Relaxed);
    }
}
struct PhaseGuard<'a>(&'a std::sync::atomic::AtomicU64);
impl<'a> PhaseGuard<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicU64, peak: &std::sync::atomic::AtomicU64) -> Self {
        let current = counter.fetch_add(1, Ordering::Relaxed) + 1;
        peak.fetch_max(current, Ordering::Relaxed);
        Self(counter)
    }
}
impl Drop for PhaseGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.0.owned_attempts.fetch_sub(1, Ordering::Relaxed);
        self.0.provider_owned[self.1].fetch_sub(1, Ordering::Relaxed);
    }
}
type ClaimFuture = Pin<
    Box<
        dyn Future<
                Output = Result<(
                    ClaimBatch,
                    Vec<OwnedSemaphorePermit>,
                    Option<ClaimReservation>,
                )>,
            > + Send,
    >,
>;
type AttemptFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

async fn pump(
    store: OrdinaryStore,
    transport: Arc<dyn ProviderTransport>,
    budget: Arc<tokio::sync::Semaphore>,
    limit: usize,
    index: usize,
    provider: &'static str,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut attempts: FuturesUnordered<AttemptFuture> = FuturesUnordered::new();
    let mut claim: Option<ClaimFuture> = None;
    let mut next_due = None;
    let mut needs_claim = true;
    let mut retry_first = false;
    let mut health = store.health.subscribe();
    loop {
        if *stop.borrow() {
            // No new network attempt is adopted after stop. Existing attempts
            // retain their Provider permit through receipt COMMIT and drain
            // concurrently with the preserved claim, avoiding a gate wait cycle.
            let drain = async {
                while let Some(result) = attempts.next().await {
                    result?;
                }
                Ok::<(), KernelError>(())
            };
            if let Some(pending) = claim.take() {
                let (_, ()) = tokio::try_join!(pending, drain)?;
            } else {
                drain.await?;
            }
            store.counters.provider_targets[index].store(0, Ordering::Relaxed);
            return Ok(());
        }
        let free = limit.saturating_sub(attempts.len());
        if claim.is_none() && needs_claim && free > 0 {
            let reserved = free.min(store.config.claim_quantum);
            let store = store.clone();
            let budget = Arc::clone(&budget);
            let mut claim_stop = stop.clone();
            claim = Some(Box::pin(async move {
                // Budget -> ledger transaction -> network -> receipt transaction.
                // No database gate is held while waiting for the fair semaphore.
                // Cancellation is allowed only before entering claim SQL.
                let first = tokio::select! {
                    biased;
                    _ = async {
                        while !*claim_stop.borrow() {
                            if claim_stop.changed().await.is_err() { break; }
                        }
                    } => return Ok((ClaimBatch {
                        tickets: Vec::new(), next_due: None, has_more: false,
                    }, Vec::new(), None)),
                    permit = Arc::clone(&budget).acquire_owned() =>
                        permit.map_err(|_| KernelError::Invalid("provider budget closed".into()))?,
                };
                let mut permits = vec![first];
                while permits.len() < reserved {
                    let Ok(permit) = Arc::clone(&budget).try_acquire_owned() else {
                        break;
                    };
                    permits.push(permit);
                }
                let reservation =
                    ClaimReservation::new(store.counters.clone(), index, permits.len());
                let batch = store
                    .claim_reserved(provider, permits.len(), retry_first)
                    .await?;
                Ok((batch, permits, Some(reservation)))
            }));
            needs_claim = false;
            retry_first = !retry_first;
        }
        let delay =
            next_due.map(|due: i64| Duration::from_millis(due.saturating_sub(now()).max(1) as u64));
        tokio::select! {
            biased;
            _=health.changed()=>{store.health.ensure()?;}
            changed=stop.changed()=>{if changed.is_err(){return Err(KernelError::Invalid("stop owner disappeared".into()));}}
            outcome=async {claim.as_mut().unwrap().await},if claim.is_some()=>{
                // Keep the future outside select: ordinary wake/receipt never
                // drops a claim COMMIT whose result has not yet been adopted.
                claim=None;
                let (batch, permits, reservation)=outcome?;next_due=batch.next_due;
                if batch.tickets.len() > permits.len() {
                    return Err(KernelError::Invalid("claim exceeded reserved Provider budget".into()));
                }
                // The empty committed claim proves no immediately eligible
                // backlog. Dropping idle pool ownership never cancels sends:
                // all adopted attempts have drained before this call.
                if attempts.is_empty() && batch.tickets.is_empty() && !batch.has_more {
                    transport.quiesce(provider);
                }
                let active = !attempts.is_empty() || !batch.tickets.is_empty() || batch.next_due.is_some();
                store.counters.provider_targets[index].store(
                    if active { limit as u64 } else { 0 }, Ordering::Relaxed);
                // Synchronous ownership transfer: no await between releasing
                // the reservation and adopting its committed grants.
                drop(reservation);
                needs_claim |= batch.has_more;
                for (ticket, permit) in batch.tickets.into_iter().zip(permits){
                    let guard=AttemptGuard::new(store.counters.clone(), index);let store=store.clone();let transport=transport.clone();
                    attempts.push(Box::pin(async move{let _guard=guard;let _permit=permit;attempt(store,transport,ticket).await}));
                }
            }
            result=attempts.next(),if !attempts.is_empty()=>{
                result.unwrap()?;needs_claim=true;
                // A pending COMMIT may already own unadopted grants. Its
                // metadata-phase target must survive unrelated completions.
                if claim.is_none() && attempts.is_empty() && next_due.is_none() {
                    store.counters.provider_targets[index].store(0, Ordering::Relaxed);
                }
            }
            _=store.wake[index].notified()=>{needs_claim=true;}
            _=async {tokio::time::sleep(delay.unwrap()).await},if delay.is_some()&&free>0&&claim.is_none()=>{needs_claim=true;next_due=None;}
        }
    }
}
pub(super) async fn attempt(
    store: impl Into<OrdinaryStore>,
    transport: Arc<dyn ProviderTransport>,
    mut ticket: Ticket,
) -> Result<()> {
    let store = store.into();
    if !store.authorize_ticket(&ticket).await? {
        let state = if ticket.expires_at <= now() {
            "expired"
        } else {
            "superseded_route"
        };
        let _receipt = PhaseGuard::new(
            &store.counters.receipts_owned,
            &store.counters.peak_receipts_owned,
        );
        let receipt_started = Instant::now();
        let settled = store
            .settle(
                &ticket,
                state,
                0,
                "route_or_client_no_longer_eligible",
                now(),
                None,
            )
            .await;
        record_duration(
            receipt_started,
            &store.counters.receipt_samples,
            &store.counters.receipt_total_us,
            &store.counters.receipt_max_us,
        );
        return settled;
    }
    let platform = super::store::supported_platform(&ticket.platform)?;
    store
        .counters
        .network_attempts
        .fetch_add(1, Ordering::Relaxed);
    let network = PhaseGuard::new(
        &store.counters.network_inflight,
        &store.counters.peak_network_inflight,
    );
    let network_started = Instant::now();
    if ticket.attempts == 1 {
        store.counters.timings.queue.record(Duration::from_millis(
            now().saturating_sub(ticket.accepted_at).max(0) as u64,
        ));
    }
    let result = transport
        .send(
            &ticket.provider,
            platform,
            &ticket.token,
            std::mem::take(&mut ticket.payload),
            &ticket.delivery_id,
            &ticket.device_key,
            ticket.accepted_at,
            ticket.expires_at,
            ticket.watch_alert_deadline,
        )
        .await;
    store
        .counters
        .timings
        .network
        .record(network_started.elapsed());
    record_duration(
        network_started,
        &store.counters.network_samples,
        &store.counters.network_total_us,
        &store.counters.network_max_us,
    );
    drop(network);
    let receipt_started = Instant::now();
    let _receipt = PhaseGuard::new(
        &store.counters.receipts_owned,
        &store.counters.peak_receipts_owned,
    );
    let at = now();
    let (state, due) = if result.failure_kind
        == Some(crate::providers::ProviderFailureKind::DeliveryExpired)
        || (!result.success && super::expiry::is_expired(ticket.expires_at, at))
    {
        ("expired", at)
    } else if result.success {
        ("provider_accepted", at)
    } else if result.is_retryable() {
        let floor = if result.status_code == 429 {
            60_000
        } else {
            10_000
        };
        let backoff = (1000_i64 * (1_i64 << ticket.attempts.min(6))).max(floor);
        (
            "retry_wait",
            at + result.retry_after_millis.unwrap_or(backoff).max(floor),
        )
    } else {
        ("permanent_failed", at)
    };
    // A late 429 still describes Provider pressure even when this particular
    // delivery has expired and will never be retried.
    let cooldown = (result.status_code == 429).then(|| {
        due.max(at.saturating_add(result.retry_after_millis.unwrap_or(60_000).max(60_000)))
    });
    let settled = store
        .settle(
            &ticket,
            state,
            result.status_code,
            result.failure_kind_name(),
            due,
            cooldown,
        )
        .await;
    record_duration(
        receipt_started,
        &store.counters.receipt_samples,
        &store.counters.receipt_total_us,
        &store.counters.receipt_max_us,
    );
    store
        .counters
        .timings
        .receipt
        .record(receipt_started.elapsed());
    if settled.is_ok() && state != "retry_wait" {
        store
            .counters
            .timings
            .end_to_end
            .record(Duration::from_millis(
                now().saturating_sub(ticket.accepted_at).max(0) as u64,
            ));
    }
    settled
}
fn record_duration(
    started: Instant,
    samples: &std::sync::atomic::AtomicU64,
    total: &std::sync::atomic::AtomicU64,
    maximum: &std::sync::atomic::AtomicU64,
) {
    let micros = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
    samples.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(micros, Ordering::Relaxed);
    maximum.fetch_max(micros, Ordering::Relaxed);
}
