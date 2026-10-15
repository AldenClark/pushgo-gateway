use super::store::{
    ClaimBatch, Config, Counters, DeliveryStore, KernelError, OwnerLock, Result, Ticket, now,
};
use crate::{
    transport::{BoxFuture, DispatchResult},
    types::Platform,
};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle, time::Instant};

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
    pub store: DeliveryStore,
    owner: Option<OwnerLock>,
    stop: watch::Sender<bool>,
    failure: watch::Receiver<Option<String>>,
    tasks: Vec<JoinHandle<Result<()>>>,
}
impl DeliveryRuntime {
    pub async fn start(
        db_url: &str,
        config: Config,
        transport: Arc<dyn ProviderTransport>,
    ) -> Result<Self> {
        let (store, owner) = DeliveryStore::open(db_url, config).await?;
        let (stop, stop_rx) = watch::channel(false);
        let (failure_tx, failure) = watch::channel(None);
        let mut tasks = Vec::new();
        for (index, provider) in ["FCM", "APNS"].into_iter().enumerate() {
            let driver_store = store.clone();
            let transport = transport.clone();
            let stop_rx = stop_rx.clone();
            let stop_tx = stop.clone();
            let failure_tx = failure_tx.clone();
            tasks.push(tokio::spawn(async move {
                let counters = driver_store.counters.clone();
                let _alive = AliveGuard::new(counters.clone());
                let outcome =
                    AssertUnwindSafe(pump(driver_store, transport, index, provider, stop_rx))
                        .catch_unwind()
                        .await;
                let result = match outcome {
                    Ok(result) => result,
                    Err(_) => Err(KernelError::Invalid("provider pump panicked".into())),
                };
                if let Err(error) = &result {
                    counters.db_errors.fetch_add(1, Ordering::Relaxed);
                    failure_tx.send_replace(Some(error.to_string()));
                    stop_tx.send_replace(true);
                }
                result
            }));
        }
        Ok(Self {
            store,
            owner: Some(owner),
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
    #[cfg(test)]
    pub(super) fn stop_probe(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }
    /// Caller must first stop and join HTTP handlers. This waits for pumps and
    /// SQLx connections before releasing the exclusive authority lock.
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
        self.store.pool.close().await;
        if let Some(owner) = self.owner.take() {
            owner.release();
        }
        report
    }
}
impl Drop for DeliveryRuntime {
    fn drop(&mut self) {
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
    fn new(counter: &'a std::sync::atomic::AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}
impl Drop for PhaseGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
struct ConcurrencyTarget {
    value: usize,
    warm_until: Instant,
}
impl ConcurrencyTarget {
    fn observe(&mut self, owned: usize, ready: usize, cap: usize, demand: bool) {
        let desired = owned.saturating_add(ready).min(cap);
        let at = Instant::now();
        if !demand {
            self.value = cap;
        } else if desired == 0 {
            self.value = 0;
        } else if desired > self.value {
            self.value = desired;
            self.warm_until = at + Duration::from_secs(2);
        } else if at >= self.warm_until {
            self.value = desired;
        }
    }
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.0.owned_attempts.fetch_sub(1, Ordering::Relaxed);
        self.0.provider_owned[self.1].fetch_sub(1, Ordering::Relaxed);
    }
}
type ClaimFuture = Pin<Box<dyn Future<Output = Result<ClaimBatch>> + Send>>;
type AttemptFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

async fn pump(
    store: DeliveryStore,
    transport: Arc<dyn ProviderTransport>,
    index: usize,
    provider: &'static str,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut attempts: FuturesUnordered<AttemptFuture> = FuturesUnordered::new();
    let mut claim: Option<ClaimFuture> = None;
    let mut reservation = None;
    let mut target = ConcurrencyTarget {
        value: 0,
        warm_until: Instant::now(),
    };
    let mut next_due = None;
    let mut needs_claim = true;
    let mut retry_first = false;
    loop {
        if *stop.borrow() {
            // Receipt futures can hold the mutation gate and SQL transaction.
            // Cancel them first, releasing the gate and queuing SQLx rollback,
            // before awaiting a preserved claim that may need the same gate.
            // Their durable running grants remain recoverable by the next owner.
            drop(attempts);
            // A pending transaction must reach its result; committed grants may
            // remain running for the next exclusive owner, never be discarded
            // as an empty live queue. Attempt cancellation likewise stays durable.
            if let Some(pending) = claim.take() {
                pending.await?;
            }
            store.counters.provider_targets[index].store(0, Ordering::Relaxed);
            return Ok(());
        }
        let free = store.config.provider_budget - attempts.len();
        if claim.is_none() && needs_claim && free > 0 {
            let reserved = free.min(store.config.claim_quantum);
            let owned = attempts.len();
            let warm_target = if Instant::now() < target.warm_until {
                target.value
            } else {
                owned
            };
            reservation = Some(ClaimReservation::new(
                store.counters.clone(),
                index,
                reserved,
            ));
            let store = store.clone();
            claim = Some(Box::pin(async move {
                store
                    .claim_reserved(provider, reserved, retry_first, free, owned, warm_target)
                    .await
            }));
            needs_claim = false;
            retry_first = !retry_first;
        }
        let delay =
            next_due.map(|due: i64| Duration::from_millis(due.saturating_sub(now()).max(1) as u64));
        tokio::select! {
            biased;
            changed=stop.changed()=>{if changed.is_err(){return Err(KernelError::Invalid("stop owner disappeared".into()));}}
            outcome=async {claim.as_mut().unwrap().await},if claim.is_some()=>{
                // Keep the future outside select: ordinary wake/receipt never
                // drops a claim COMMIT whose result has not yet been adopted.
                claim=None;
                let batch=outcome?;next_due=batch.next_due;
                // The empty committed claim proves no immediately eligible
                // backlog. Dropping idle pool ownership never cancels sends:
                // all adopted attempts have drained before this call.
                if attempts.is_empty() && batch.tickets.is_empty() && !batch.has_more {
                    transport.quiesce(provider);
                }
                target.observe(attempts.len(), batch.ready, store.config.provider_budget, store.config.demand_scaling);
                store.counters.provider_targets[index].store(target.value as u64, Ordering::Relaxed);
                // Synchronous ownership transfer: no await between releasing
                // the reservation and adopting its committed grants.
                drop(reservation.take());
                needs_claim |= batch.has_more;
                for ticket in batch.tickets{
                    let guard=AttemptGuard::new(store.counters.clone(), index);let store=store.clone();let transport=transport.clone();
                    attempts.push(Box::pin(async move{let _guard=guard;attempt(store,transport,ticket).await}));
                }
            }
            result=attempts.next(),if !attempts.is_empty()=>{
                result.unwrap()?;needs_claim=true;
                // A pending COMMIT may already own unadopted grants. Its
                // metadata-phase target must survive unrelated completions.
                if claim.is_none() {
                    target.observe(attempts.len(), 0, store.config.provider_budget, store.config.demand_scaling);
                    store.counters.provider_targets[index].store(target.value as u64, Ordering::Relaxed);
                }
            }
            _=store.wake[index].notified()=>{needs_claim=true;}
            _=async {tokio::time::sleep(delay.unwrap()).await},if delay.is_some()&&free>0&&claim.is_none()=>{needs_claim=true;next_due=None;}
        }
    }
}
pub(super) async fn attempt(
    store: DeliveryStore,
    transport: Arc<dyn ProviderTransport>,
    mut ticket: Ticket,
) -> Result<()> {
    if !store.authorize_ticket(&ticket).await? {
        let state = if ticket.expires_at <= now() {
            "expired"
        } else {
            "superseded_route"
        };
        let _receipt = PhaseGuard::new(&store.counters.receipts_owned);
        return store
            .settle(
                &ticket,
                state,
                0,
                "route_or_client_no_longer_eligible",
                now(),
                None,
            )
            .await;
    }
    let platform = super::store::supported_platform(&ticket.platform)?;
    store
        .counters
        .network_attempts
        .fetch_add(1, Ordering::Relaxed);
    let network = PhaseGuard::new(&store.counters.network_inflight);
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
        )
        .await;
    drop(network);
    let _receipt = PhaseGuard::new(&store.counters.receipts_owned);
    let at = now();
    let (state, due) = if result.success {
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
    let cooldown = (result.status_code == 429).then_some(due);
    store
        .settle(
            &ticket,
            state,
            result.status_code,
            result.failure_kind_name(),
            due,
            cooldown,
        )
        .await
}
