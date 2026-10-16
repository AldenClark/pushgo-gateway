// Ordinary delivery uses this existing Hub's transport/resume owner. It never
// enters the legacy Private payload table, outbox, cache, or fallback scheduler.
use crate::ordinary::{
    OrdinaryStore,
    private_model::{PrivateRoute, PrivateTicket},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct OrdinaryPrivateWork {
    groups: tokio::sync::Mutex<BTreeMap<DeviceId, OrdinaryPrivateGroup>>,
    slots: Arc<Semaphore>,
    limit: usize,
    per_device: usize,
    payload_bytes: AtomicUsize,
}

struct OrdinaryPrivateGroup {
    id: String,
    route: PrivateRoute,
    work: BTreeMap<String, OrdinaryPrivateDelivery>,
}

struct OrdinaryPrivateDelivery {
    ticket: PrivateTicket,
    payload: Arc<[u8]>,
    store: OrdinaryStore,
    permit: Option<OwnedSemaphorePermit>,
}

impl OrdinaryPrivateDelivery {
    fn committed(mut self) {
        drop(self.permit.take());
    }
}

impl Drop for OrdinaryPrivateDelivery {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            // A vanished capability is not evidence that ACK/release committed.
            // Fence the shared product store before its reservation can be reused.
            self.store
                .fail("ordinary Private capability dropped before durable completion");
            permit.forget();
        }
    }
}

struct OrdinaryPrivateOperation {
    store: OrdinaryStore,
    armed: bool,
}

impl OrdinaryPrivateOperation {
    fn new(store: &OrdinaryStore) -> Self {
        Self {
            store: store.clone(),
            armed: true,
        }
    }

    fn completed(mut self) {
        self.armed = false;
    }
}

impl Drop for OrdinaryPrivateOperation {
    fn drop(&mut self) {
        if self.armed {
            self.store
                .fail("ordinary Private transaction interrupted before its result was adopted");
        }
    }
}

impl OrdinaryPrivateWork {
    fn new(config: &PrivateConfig) -> Self {
        // Reuse the normal runtime profile's bounded active-body budget. This
        // reserves work, not a maximum-sized buffer for each idle connection.
        let limit = config.hot_cache_capacity.clamp(1, 4096);
        Self {
            groups: tokio::sync::Mutex::new(BTreeMap::new()),
            slots: Arc::new(Semaphore::new(limit)),
            limit,
            per_device: config.pull_limit.clamp(1, 96),
            payload_bytes: AtomicUsize::new(0),
        }
    }
}

fn ordinary_private_error(error: impl std::fmt::Display) -> crate::Error {
    crate::Error::Internal(error.to_string())
}

/// The established Private payload encoding. Sorting affects byte order only;
/// all canonical JSON values survive as the same protocol string values.
fn encode_ordinary_private_payload(canonical: &[u8]) -> Result<Arc<[u8]>, crate::Error> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(canonical).map_err(ordinary_private_error)?;
    let data = object
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                serde_json::Value::String(value) => value,
                other => other.to_string(),
            };
            (key, value)
        })
        .collect::<BTreeMap<_, _>>();
    #[derive(serde::Serialize)]
    struct SortedEnvelope {
        payload_version: u8,
        data: BTreeMap<String, String>,
    }
    postcard::to_allocvec(&SortedEnvelope {
        payload_version: 1,
        data,
    })
    .map(Arc::from)
    .map_err(ordinary_private_error)
}

/// Deterministic cancellation negative control using the exact production
/// adoption guard. The pause represents COMMIT returned, not yet adopted by
/// its bounded transport owner; it does not replace native database tests.
#[cfg(test)]
pub(crate) async fn ordinary_adoption_guard_probe(
    store: OrdinaryStore,
    reached: tokio::sync::oneshot::Sender<()>,
    adopt: tokio::sync::oneshot::Receiver<()>,
) -> Option<warp_link::warp_link_core::OutboundMsg> {
    let operation = OrdinaryPrivateOperation::new(&store);
    let _ = reached.send(());
    let _ = adopt.await;
    operation.completed();
    None
}

impl PrivateHub {
    fn ordinary_is_inflight(&self, device: DeviceId, delivery: &str) -> bool {
        self.with_resume_state(device, |state| {
            state
                .inflight
                .values()
                .any(|item| item.delivery.ordinary && item.delivery.delivery_id == delivery)
        })
        .unwrap_or(false)
    }

    fn forget_ordinary_resume(&self, device: DeviceId, delivery: &str) {
        let _ = self.with_resume_state_mut(device, |state| {
            state
                .inflight
                .retain(|_, item| item.delivery.delivery_id != delivery);
        });
    }

    /// A wakeup is a hint only. The durable claim and its route authorization
    /// below remain authoritative; no accepted body is copied to a second queue.
    pub(crate) async fn wait_ordinary_changed(&self) {
        if let Some(store) = self.store.ordinary_handle() {
            store.private_changed().await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    pub(crate) fn ordinary_notifier(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.store
            .ordinary_handle()
            .map(|store| store.private_notifier())
    }

    pub(crate) async fn validate_ordinary_session_route(
        &self,
        device: DeviceId,
        generation: Option<i64>,
    ) -> Result<bool, crate::Error> {
        if self.store.ordinary_handle().is_none() {
            return Ok(generation.is_none());
        }
        let Some(generation) = generation else {
            return Ok(false);
        };
        match self.store.ordinary_private_route(device).await {
            Ok(route) => Ok(route.route_generation == generation),
            Err(
                crate::ordinary::store::KernelError::Control { .. }
                | crate::ordinary::store::KernelError::Unauthorized
                | crate::ordinary::store::KernelError::NotFound,
            ) => Ok(false),
            Err(error) => Err(ordinary_private_error(error)),
        }
    }

    /// Claim at most one item on demand. Work stays reserved until a committed
    /// ACK or release, including all waiting time behind the database gate.
    pub(crate) async fn ordinary_outbound(
        &self,
        device: DeviceId,
        generation: Option<i64>,
    ) -> Result<Option<protocol::DeliverEnvelope>, crate::Error> {
        let Some(store) = self.store.ordinary_handle() else {
            return Ok(None);
        };
        let mut groups = self.ordinary.groups.lock().await;
        if let Some(group) = groups.get(&device)
            && Some(group.route.route_generation) == generation
        {
            if let Some((delivery, work)) = group
                .work
                .iter()
                .find(|(delivery, _)| !self.ordinary_is_inflight(device, delivery))
            {
                return Ok(Some(protocol::DeliverEnvelope {
                    delivery_id: delivery.clone(),
                    payload: work.payload.clone(),
                    ordinary: true,
                    ordinary_expires_at: Some(work.ticket.expires_at),
                }));
            }
            if group.work.len() >= self.ordinary.per_device {
                return Ok(None);
            }
        }
        let route = match self.store.ordinary_private_route(device).await {
            Ok(route) => route,
            Err(
                crate::ordinary::store::KernelError::Control { .. }
                | crate::ordinary::store::KernelError::Unauthorized
                | crate::ordinary::store::KernelError::NotFound,
            ) => {
                let operation = OrdinaryPrivateOperation::new(&store);
                if let Some(group) = groups.get(&device) {
                    self.release_ordinary_group(device, group, &store).await?;
                }
                if let Some(group) = groups.remove(&device) {
                    for (delivery, work) in group.work {
                        self.forget_ordinary_resume(device, &delivery);
                        self.ordinary
                            .payload_bytes
                            .fetch_sub(work.payload.len(), Ordering::Relaxed);
                        work.committed();
                    }
                }
                operation.completed();
                return Ok(None);
            }
            Err(error) => return Err(ordinary_private_error(error)),
        };
        if Some(route.route_generation) != generation {
            return Ok(None);
        }
        let operation = OrdinaryPrivateOperation::new(&store);
        if let Some(group) = groups.get(&device)
            && (group.route.device_key != route.device_key
                || group.route.route_generation != route.route_generation)
        {
            self.release_ordinary_group(device, group, &store).await?;
            if let Some(group) = groups.remove(&device) {
                for (delivery, work) in group.work {
                    self.forget_ordinary_resume(device, &delivery);
                    self.ordinary
                        .payload_bytes
                        .fetch_sub(work.payload.len(), Ordering::Relaxed);
                    work.committed();
                }
            }
        }
        let Ok(permit) = self.ordinary.slots.clone().try_acquire_owned() else {
            operation.completed();
            return Ok(None);
        };
        let group_id = groups
            .get(&device)
            .map(|group| group.id.clone())
            .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));
        let mut claimed = store
            .private_claim(&route, &group_id, 1)
            .await
            .map_err(ordinary_private_error)?;
        if let Some(mut ticket) = claimed.pop() {
            let payload = match encode_ordinary_private_payload(&ticket.payload) {
                Ok(payload) => payload,
                Err(error) => {
                    store
                        .private_release(&group_id, &[ticket.claim_token.clone()])
                        .await
                        .map_err(ordinary_private_error)?;
                    operation.completed();
                    store.fail("ordinary Private canonical payload could not be encoded");
                    return Err(error);
                }
            };
            // Only the encoded active representation remains in memory. The
            // single canonical JSON body is still owned by the durable ledger.
            ticket.payload = Vec::new();
            let delivery = ticket.delivery_id.clone();
            let envelope = protocol::DeliverEnvelope {
                delivery_id: delivery.clone(),
                payload: payload.clone(),
                ordinary: true,
                ordinary_expires_at: Some(ticket.expires_at),
            };
            self.ordinary
                .payload_bytes
                .fetch_add(payload.len(), Ordering::Relaxed);
            groups
                .entry(device)
                .or_insert_with(|| OrdinaryPrivateGroup {
                    id: group_id,
                    route,
                    work: BTreeMap::new(),
                })
                .work
                .insert(
                    delivery,
                    OrdinaryPrivateDelivery {
                        ticket,
                        payload,
                        store: store.clone(),
                        permit: Some(permit),
                    },
                );
            operation.completed();
            Ok(Some(envelope))
        } else {
            operation.completed();
            Ok(None)
        }
    }

    /// This runs immediately before every ordinary send, including bootstrap,
    /// retransmit, and a copy already waiting in a bounded transport queue.
    pub(crate) async fn authorize_ordinary_outbound(
        &self,
        device: DeviceId,
        envelope: &protocol::DeliverEnvelope,
    ) -> Result<bool, crate::Error> {
        if !envelope.ordinary {
            return Ok(true);
        }
        let Some(store) = self.store.ordinary_handle() else {
            return Ok(false);
        };
        let mut groups = self.ordinary.groups.lock().await;
        let Some(group) = groups.get_mut(&device) else {
            return Ok(false);
        };
        let Some(work) = group.work.get(&envelope.delivery_id) else {
            return Ok(false);
        };
        let authorized = store
            .private_authorize(&work.ticket)
            .await
            .map_err(ordinary_private_error)?;
        // SQL may have waited behind another operation long enough to cross
        // expiry. Keep this same absolute deadline on queued/replayed frames.
        let at = chrono::Utc::now().timestamp_millis();
        let authorized = authorized
            && !crate::ordinary::expiry::is_expired(work.ticket.expires_at, at)
            && !envelope.ordinary_expired_at(at);
        if !authorized {
            let operation = OrdinaryPrivateOperation::new(&store);
            store
                .private_release(&group.id, &[work.ticket.claim_token.clone()])
                .await
                .map_err(ordinary_private_error)?;
            if let Some(work) = group.work.remove(&envelope.delivery_id) {
                self.ordinary
                    .payload_bytes
                    .fetch_sub(work.payload.len(), Ordering::Relaxed);
                work.committed();
            }
            self.forget_ordinary_resume(device, &envelope.delivery_id);
            if group.work.is_empty() {
                groups.remove(&device);
            }
            operation.completed();
        }
        Ok(authorized)
    }

    /// The last handoff may be cancelled by Warp's normal inbound/control
    /// select. Keep it read-only: a failed check is cleaned up by the single
    /// owned outbound operation, never by a cancellable transaction here.
    pub(crate) async fn ordinary_outbound_is_current(
        &self,
        device: DeviceId,
        envelope: &protocol::DeliverEnvelope,
    ) -> Result<bool, crate::Error> {
        if !envelope.ordinary {
            return Ok(true);
        }
        let Some(store) = self.store.ordinary_handle() else {
            return Ok(false);
        };
        let ticket = {
            let groups = self.ordinary.groups.lock().await;
            let Some(work) = groups
                .get(&device)
                .and_then(|group| group.work.get(&envelope.delivery_id))
            else {
                return Ok(false);
            };
            // The active ticket's canonical payload was cleared on adoption;
            // this snapshot copies capability metadata, not another body.
            work.ticket.clone()
        };
        let current = store
            .private_authorize(&ticket)
            .await
            .map_err(ordinary_private_error)?;
        let at = chrono::Utc::now().timestamp_millis();
        if !current
            || crate::ordinary::expiry::is_expired(ticket.expires_at, at)
            || envelope.ordinary_expired_at(at)
        {
            return Ok(false);
        }
        let groups = self.ordinary.groups.lock().await;
        // ACK/release may have committed while the read was in flight. A ready
        // result must still refer to the same owned capability at handoff.
        Ok(groups
            .get(&device)
            .and_then(|group| group.work.get(&envelope.delivery_id))
            .is_some_and(|work| {
                work.ticket.claim_token == ticket.claim_token
                    && work.ticket.delivery_epoch == ticket.delivery_epoch
                    && work.ticket.route_generation == ticket.route_generation
            }))
    }

    /// None selects the legacy non-ordinary data source. An issued ordinary
    /// capability never falls back to that source after a false/failed ACK.
    pub(crate) async fn ack_ordinary_delivery(
        &self,
        device: DeviceId,
        delivery: &str,
        generation: Option<i64>,
    ) -> Result<Option<bool>, crate::Error> {
        self.settle_ordinary_delivery(device, delivery, generation, false)
            .await
    }

    pub(crate) async fn reject_ordinary_delivery(
        &self,
        device: DeviceId,
        delivery: &str,
        generation: Option<i64>,
    ) -> Result<Option<bool>, crate::Error> {
        self.settle_ordinary_delivery(device, delivery, generation, true)
            .await
    }

    async fn settle_ordinary_delivery(
        &self,
        device: DeviceId,
        delivery: &str,
        generation: Option<i64>,
        invalid_payload: bool,
    ) -> Result<Option<bool>, crate::Error> {
        let Some(store) = self.store.ordinary_handle() else {
            return Ok(None);
        };
        let mut groups = self.ordinary.groups.lock().await;
        let Some(group) = groups.get_mut(&device) else {
            return Ok(None);
        };
        let Some(work) = group.work.get(delivery) else {
            return Ok(None);
        };
        if !self.ordinary_is_inflight(device, delivery)
            || generation.is_some_and(|generation| generation != group.route.route_generation)
        {
            return Ok(Some(false));
        }
        let operation = OrdinaryPrivateOperation::new(&store);
        let consumed = if invalid_payload {
            store
                .private_reject(&group.route, &work.ticket, "invalid_payload")
                .await
        } else {
            store.private_ack(&group.route, &work.ticket).await
        }
        .map_err(ordinary_private_error)?;
        if !consumed {
            store
                .private_release(&group.id, &[work.ticket.claim_token.clone()])
                .await
                .map_err(ordinary_private_error)?;
        }
        if let Some(work) = group.work.remove(delivery) {
            self.ordinary
                .payload_bytes
                .fetch_sub(work.payload.len(), Ordering::Relaxed);
            work.committed();
        }
        if consumed {
            self.forget_delivery_after_commit(device, delivery);
        } else {
            self.forget_ordinary_resume(device, delivery);
        }
        if group.work.is_empty() {
            groups.remove(&device);
        }
        operation.completed();
        Ok(Some(consumed))
    }

    pub(crate) async fn ordinary_channel_id(
        &self,
        device: DeviceId,
        delivery: &str,
    ) -> Option<[u8; 16]> {
        let groups = self.ordinary.groups.lock().await;
        let work = groups.get(&device)?.work.get(delivery)?;
        protocol::PrivatePayloadEnvelope::decode_postcard(work.payload.as_ref())?
            .parsed_channel_id()
    }

    async fn release_ordinary_group(
        &self,
        _device: DeviceId,
        group: &OrdinaryPrivateGroup,
        store: &OrdinaryStore,
    ) -> Result<(), crate::Error> {
        let tokens = group
            .work
            .values()
            .map(|work| work.ticket.claim_token.clone())
            .collect::<Vec<_>>();
        store
            .private_release(&group.id, &tokens)
            .await
            .map_err(ordinary_private_error)?;
        Ok(())
    }

    /// Call after removing a disconnected transport's presence. Other active
    /// transports still share the same group, sequence state and reservation.
    pub(crate) async fn release_ordinary_if_offline(
        &self,
        device: DeviceId,
    ) -> Result<(), crate::Error> {
        if self
            .presence
            .get(&device)
            .is_some_and(|p| p.has_active() || !p.draining.is_empty())
        {
            return Ok(());
        }
        self.release_ordinary_device(device).await
    }

    async fn release_ordinary_device(&self, device: DeviceId) -> Result<(), crate::Error> {
        let Some(store) = self.store.ordinary_handle() else {
            return Ok(());
        };
        let mut groups = self.ordinary.groups.lock().await;
        let Some(group) = groups.get(&device) else {
            return Ok(());
        };
        let operation = OrdinaryPrivateOperation::new(&store);
        self.release_ordinary_group(device, group, &store).await?;
        if let Some(group) = groups.remove(&device) {
            for (delivery, work) in group.work {
                self.forget_ordinary_resume(device, &delivery);
                self.ordinary
                    .payload_bytes
                    .fetch_sub(work.payload.len(), Ordering::Relaxed);
                work.committed();
            }
        }
        operation.completed();
        Ok(())
    }

    /// Product shutdown calls this only after all existing Private transports
    /// have joined. Database and exclusive-owner guard must outlive this step.
    pub(crate) async fn shutdown_ordinary(&self) -> Result<(), crate::Error> {
        loop {
            let device = self.ordinary.groups.lock().await.keys().next().copied();
            let Some(device) = device else { return Ok(()) };
            self.release_ordinary_device(device).await?;
        }
    }
}

#[cfg(test)]
mod ordinary_private_tests {
    use super::*;

    fn envelope() -> protocol::DeliverEnvelope {
        protocol::DeliverEnvelope {
            delivery_id: "00000000000000000000000000000001".to_owned(),
            payload: Arc::from([1_u8]),
            ordinary: true,
            ordinary_expires_at: Some(i64::MAX),
        }
    }

    #[test]
    fn resume_watermark_keeps_issued_delivery_until_durable_settle() {
        let now = Instant::now();
        let mut state = ResumeState::fresh(now);
        let (seq, envelope) = state.track_outbound(envelope(), now);
        assert_eq!(
            state.ack_up_to(seq, now),
            vec![envelope.delivery_id.clone()]
        );
        assert_eq!(
            state.inflight_snapshot().len(),
            1,
            "client watermark cannot erase an uncommitted ACK capability"
        );
        assert_eq!(
            state.ack_up_to(seq, now),
            vec![envelope.delivery_id.clone()],
            "a failed durable settle must remain retryable"
        );
        assert_eq!(
            state.ack_by_seq(seq, Some(&envelope.delivery_id), now),
            Some(envelope.delivery_id)
        );
        assert!(state.inflight_snapshot().is_empty());
    }

    #[test]
    fn ordinary_retransmission_reuses_issued_sequence_and_shared_body() {
        let now = Instant::now();
        let mut state = ResumeState::fresh(now);
        let first = envelope();
        let body = first.payload.clone();
        let (original, _) = state.track_outbound(first.clone(), now);
        let (replayed, replay) = state.track_outbound(first, now);
        assert_eq!(original, replayed);
        assert_eq!(state.inflight.len(), 1);
        assert!(Arc::ptr_eq(&body, &replay.payload));
    }

    #[test]
    fn ordinary_encoding_preserves_text_and_structured_values() {
        let raw = serde_json::json!({
            "message_id": "stable-id",
            "body": "中文🙂\\\"\n".repeat(1024),
            "metadata": {"negative": -42, "fraction": 1.25, "items": [1, 2, 3]},
            "timestamp": 1792123456789_i64
        });
        let encoded = encode_ordinary_private_payload(&serde_json::to_vec(&raw).unwrap()).unwrap();
        let decoded = protocol::PrivatePayloadEnvelope::decode_postcard(&encoded).unwrap();
        assert_eq!(
            decoded.data.get("message_id").map(String::as_str),
            Some("stable-id")
        );
        assert_eq!(
            decoded.data.get("body"),
            raw.get("body")
                .and_then(|value| value.as_str())
                .map(|value| value.to_owned())
                .as_ref()
        );
        let metadata: serde_json::Value =
            serde_json::from_str(decoded.data.get("metadata").unwrap()).unwrap();
        assert_eq!(metadata, raw["metadata"]);
        assert_eq!(
            decoded.data.get("timestamp").map(String::as_str),
            Some("1792123456789")
        );
    }
}
