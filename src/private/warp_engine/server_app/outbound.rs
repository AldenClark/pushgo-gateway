use std::{
    collections::VecDeque,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use warp_link::warp_link_core::{OutboundMsg, SessionControl, SessionCtx};

use crate::{
    private::{ConnectionMode, PrivateState, protocol::DeliverEnvelope},
    storage::DeviceId,
};

use super::{
    super::registry::{HandoffState, PendingOutbound, PreparedOutbound, SessionRuntime},
    PushgoServerApp,
};

fn fresh_source_order(preference: &AtomicBool) -> [bool; 2] {
    let ordinary = preference.load(Ordering::Relaxed);
    [ordinary, !ordinary]
}

fn record_fresh_handoff(preference: &AtomicBool, ordinary: bool, seq: Option<u64>) {
    if seq.is_none() {
        preference.store(!ordinary, Ordering::Relaxed);
    }
}

/// Poll a tracked preparation without taking ownership of its JoinHandle. An
/// inbound/control branch may cancel this borrow; the one bounded task keeps
/// making progress even if ACK needs a lock held by its native transaction.
async fn poll_pending_outbound(
    pending: &mut Option<PendingOutbound>,
) -> Result<bool, tokio::task::JoinError> {
    let Some(operation) = pending.as_mut() else {
        return Ok(false);
    };
    if let PendingOutbound::Running(task) = operation {
        match task.await {
            Ok(Some(prepared)) => *pending = Some(PendingOutbound::Ready(prepared)),
            Ok(None) => *pending = None,
            Err(error) => {
                *pending = None;
                return Err(error);
            }
        }
    }
    Ok(pending.is_some())
}

/// Shared last application handoff for fresh work, reconnect bootstrap and
/// retransmit. Expiry never creates an ACK and never renews the original TTL.
fn outbound_from_queue_at(
    envelope: &DeliverEnvelope,
    seq: Option<u64>,
    at: i64,
) -> Option<OutboundMsg> {
    if envelope.ordinary_expired_at(at) {
        return None;
    }
    Some(OutboundMsg {
        seq,
        id: envelope.delivery_id.clone(),
        payload: envelope.payload.to_vec().into(),
    })
}

impl PushgoServerApp {
    pub(super) async fn wait_outbound_message(
        &self,
        session: &SessionCtx,
        max_wait_ms: u64,
    ) -> Option<OutboundMsg> {
        self.sessions.expire_handoff(&session.session_id);
        let runtime = self.sessions.get(session.session_id.as_str())?.clone();
        if runtime.is_terminating() || self.state.is_shutting_down() {
            runtime.request_termination();
            return pending::<Option<OutboundMsg>>().await;
        }
        if !runtime.handoff.lock().can_send() {
            // A prepared candidate owns no delivery; a frozen primary may still
            // receive/ACK. The existing session select owns this finite wait.
            let wake = runtime.outbound_stop.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let deadline = runtime.handoff.lock().binding().map(|value| value.deadline);
            let wait = deadline
                .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()))
                .unwrap_or_default()
                .min(Duration::from_millis(max_wait_ms.max(1)));
            tokio::select! {
                _ = wake => {}
                _ = tokio::time::sleep(wait.max(Duration::from_millis(1))) => {}
            }
            self.sessions.expire_handoff(&session.session_id);
            return None;
        }
        let context = OutboundContext::new(self.state.clone(), runtime.as_ref());
        let mut pending = runtime.pending_outbound.lock().await;
        let stopped = context.outbound_stop.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if runtime.is_terminating() {
            return None;
        }
        // Register before a fresh durable read, including when a prior read was
        // cancelled by inbound and later completed with no work.
        let notify = context
            .state
            .hub
            .ordinary_notifier()
            .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new()));
        let changed = notify.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let ack_timeout = Duration::from_secs(context.state.config.ack_timeout_secs.max(2));
        if pending.is_some()
            && let Some(outbound) = context.finish_pending(&mut pending).await
        {
            return Some(outbound);
        }
        if runtime.is_terminating() {
            return None;
        }
        let preparing = context.clone();
        *pending = Some(PendingOutbound::Running(tokio::spawn(async move {
            preparing.take_outbound_ready(ack_timeout).await
        })));
        if let Some(outbound) = context.finish_pending(&mut pending).await {
            return Some(outbound);
        }
        if runtime.is_terminating() {
            return None;
        }
        let retransmit_wait = context
            .state
            .hub
            .next_retransmit_due_in(context.device_id, ack_timeout)
            .unwrap_or_else(|| Duration::from_millis(max_wait_ms.max(1)));
        let wait = retransmit_wait
            .min(Duration::from_millis(max_wait_ms.max(1)))
            .max(Duration::from_millis(1));
        // Idle connections add no preparation task. Only a notification,
        // bounded transport queue item or the existing retransmit timer starts
        // another operation; at most one task/result occupies this slot.
        let received = tokio::select! {
            _ = stopped => return None,
            _ = changed => None,
            result = context.receiver.recv_async() => {
                match result { Ok(envelope) => Some(envelope), Err(_) => return None }
            }
            _ = tokio::time::sleep(wait) => None,
        };
        let preparing = context.clone();
        *pending = Some(PendingOutbound::Running(tokio::spawn(async move {
            match received {
                Some(envelope) => preparing.authorized_new_outbound(envelope).await,
                None => preparing.take_outbound_ready(ack_timeout).await,
            }
        })));
        context.finish_pending(&mut pending).await
    }
}

#[derive(Clone)]
struct OutboundContext {
    state: Arc<PrivateState>,
    device_id: DeviceId,
    conn_id: u64,
    handoff: Arc<parking_lot::Mutex<HandoffState>>,
    ordinary_route_generation: Option<i64>,
    ordinary_first: Arc<AtomicBool>,
    terminate_requested: Arc<AtomicBool>,
    outbound_stop: Arc<tokio::sync::Notify>,
    control: Arc<parking_lot::Mutex<Option<SessionControl>>>,
    receiver: flume::Receiver<DeliverEnvelope>,
    bootstrap_inflight: Arc<parking_lot::Mutex<VecDeque<(u64, DeliverEnvelope)>>>,
    bootstrap_pending: Arc<parking_lot::Mutex<VecDeque<DeliverEnvelope>>>,
}

impl OutboundContext {
    fn new(state: Arc<PrivateState>, runtime: &SessionRuntime) -> Self {
        Self {
            state,
            device_id: runtime.device_id,
            conn_id: runtime.conn_id,
            handoff: runtime.handoff.clone(),
            ordinary_route_generation: runtime.ordinary_route_generation,
            ordinary_first: runtime.ordinary_first.clone(),
            terminate_requested: runtime.terminate_requested.clone(),
            outbound_stop: runtime.outbound_stop.clone(),
            control: runtime.control.clone(),
            receiver: runtime.receiver.clone(),
            bootstrap_inflight: runtime.bootstrap_inflight.clone(),
            bootstrap_pending: runtime.bootstrap_pending.clone(),
        }
    }

    fn request_termination(&self) {
        if !self.terminate_requested.swap(true, Ordering::SeqCst)
            && let Some(control) = self.control.lock().clone()
        {
            control.expire_now();
        }
        self.outbound_stop.notify_waiters();
    }

    async fn finish_pending(&self, pending: &mut Option<PendingOutbound>) -> Option<OutboundMsg> {
        loop {
            match poll_pending_outbound(pending).await {
                Ok(true) => {}
                Ok(false) => return None,
                Err(_) => {
                    self.state
                        .record_session_task_failure("Private outbound preparation task failed");
                    self.request_termination();
                    return None;
                }
            }
            let Some(PendingOutbound::Ready(prepared)) = pending.as_ref() else {
                return None;
            };
            if self.terminate_requested.load(Ordering::SeqCst) || self.state.is_shutting_down() {
                return None;
            }
            if !self.handoff.lock().can_send() {
                return None;
            }
            // A completed task may have waited behind inbound ACK or control.
            // This last query is read-only and holds no Hub lock across await:
            // cancellation leaves Ready intact and next handoff reads again.
            let current = match self
                .state
                .hub
                .ordinary_outbound_is_current(self.device_id, &prepared.envelope)
                .await
            {
                Ok(current) => current,
                Err(_) => {
                    self.state.record_session_task_failure(
                        "Private outbound handoff authorization failed",
                    );
                    self.request_termination();
                    return None;
                }
            };
            if !current
                || prepared
                    .envelope
                    .ordinary_expired_at(chrono::Utc::now().timestamp_millis())
            {
                let Some(PendingOutbound::Ready(prepared)) = pending.take() else {
                    return None;
                };
                let context = self.clone();
                *pending = Some(PendingOutbound::Running(tokio::spawn(async move {
                    // An expired/retired reservation is released only by the
                    // same tracked durable-operation owner, never this read.
                    if context
                        .state
                        .hub
                        .authorize_ordinary_outbound(context.device_id, &prepared.envelope)
                        .await
                        .is_err()
                    {
                        context.state.record_session_task_failure(
                            "Private outbound reservation release failed",
                        );
                        context.request_termination();
                    }
                    None
                })));
                continue;
            }
            let Some(PendingOutbound::Ready(prepared)) = pending.take() else {
                return None;
            };
            // Freeze is published synchronously by the same session auth owner
            // before it joins this slot. No sequence is allocated past it.
            if !self.handoff.lock().can_send() {
                *pending = Some(PendingOutbound::Ready(prepared));
                return None;
            }
            if matches!(
                self.state.hub.connection_mode(self.device_id, self.conn_id),
                ConnectionMode::Stale
            ) {
                self.request_termination();
                return None;
            }
            let mut outbound = outbound_from_queue_at(
                &prepared.envelope,
                prepared.seq,
                chrono::Utc::now().timestamp_millis(),
            )?;
            record_fresh_handoff(
                &self.ordinary_first,
                prepared.envelope.ordinary,
                prepared.seq,
            );
            if let Some(seq) = prepared.seq {
                self.state.hub.mark_delivery_sent(self.device_id, seq);
                self.state.metrics.mark_deliver_retransmit_sent();
            } else {
                let (seq, _) = self
                    .state
                    .hub
                    .track_sent_outbound(self.device_id, prepared.envelope);
                outbound.seq = Some(seq);
                self.state.metrics.mark_deliver_sent();
            }
            return Some(outbound);
        }
    }

    async fn authorized_new_outbound(&self, envelope: DeliverEnvelope) -> Option<PreparedOutbound> {
        match self
            .state
            .hub
            .authorize_ordinary_outbound(self.device_id, &envelope)
            .await
        {
            Ok(true) => Some(PreparedOutbound {
                seq: None,
                envelope,
            }),
            Ok(false) => None,
            Err(error) => {
                tracing::error!(error = %error, "ordinary Private send authorization failed");
                self.request_termination();
                None
            }
        }
    }

    async fn authorized_retransmit(
        &self,
        seq: u64,
        envelope: DeliverEnvelope,
    ) -> Option<PreparedOutbound> {
        match self
            .state
            .hub
            .authorize_ordinary_outbound(self.device_id, &envelope)
            .await
        {
            Ok(true) => Some(PreparedOutbound {
                seq: Some(seq),
                envelope,
            }),
            Ok(false) => None,
            Err(error) => {
                tracing::error!(error = %error, "ordinary Private retransmit authorization failed");
                self.request_termination();
                None
            }
        }
    }

    async fn take_outbound_ready(&self, ack_timeout: Duration) -> Option<PreparedOutbound> {
        if self.terminate_requested.load(Ordering::SeqCst) || self.state.is_shutting_down() {
            self.request_termination();
            return None;
        }
        if !self.handoff.lock().can_send() {
            return None;
        }
        if !self
            .state
            .hub
            .validate_ordinary_session_route(self.device_id, self.ordinary_route_generation)
            .await
            .unwrap_or(false)
        {
            self.request_termination();
            return None;
        }
        if matches!(
            self.state.hub.connection_mode(self.device_id, self.conn_id),
            ConnectionMode::Stale
        ) {
            self.request_termination();
            return None;
        }
        let bootstrap_inflight = self.bootstrap_inflight.lock().pop_front();
        if let Some((seq, envelope)) = bootstrap_inflight
            && let Some(prepared) = self.authorized_retransmit(seq, envelope).await
        {
            return Some(prepared);
        }
        let bootstrap_pending = self.bootstrap_pending.lock().pop_front();
        if let Some(envelope) = bootstrap_pending
            && let Some(prepared) = self.authorized_new_outbound(envelope).await
        {
            return Some(prepared);
        }
        let retransmit = self
            .state
            .hub
            .poll_retransmit_outbound(self.device_id, ack_timeout);
        if retransmit.exhausted_count > 0 {
            self.state
                .metrics
                .mark_retransmit_exhausted(retransmit.exhausted_count);
        }
        if let Some((seq, envelope)) = retransmit.outbound
            && let Some(prepared) = self.authorized_retransmit(seq, envelope).await
        {
            return Some(prepared);
        }
        // A single preference bit alternates successful fresh handoffs. A
        // source with no work or execution budget never blocks the other one.
        // Already-owned bootstrap/retransmit work above keeps its prior order.
        for ordinary in fresh_source_order(&self.ordinary_first) {
            if ordinary {
                match self
                    .state
                    .hub
                    .ordinary_outbound(self.device_id, self.ordinary_route_generation)
                    .await
                {
                    Ok(Some(envelope)) => {
                        if let Some(prepared) = self.authorized_new_outbound(envelope).await {
                            return Some(prepared);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(error = %error, "ordinary Private claim failed");
                        self.request_termination();
                        return None;
                    }
                }
            } else if let Ok(envelope) = self.receiver.try_recv()
                && let Some(prepared) = self.authorized_new_outbound(envelope).await
            {
                return Some(prepared);
            }
        }
        None
    }
}

#[cfg(test)]
mod ordinary_expiry_tests {
    use super::*;
    use crate::private::protocol::DeliverEnvelope;
    use std::sync::Arc;

    fn ordinary(expires_at: i64) -> DeliverEnvelope {
        DeliverEnvelope {
            delivery_id: "stable-delivery".to_owned(),
            payload: Arc::from([1_u8, 2, 3]),
            ordinary: true,
            ordinary_expires_at: Some(expires_at),
        }
    }

    #[test]
    fn ordinary_queue_handoff_uses_inclusive_absolute_expiry() {
        let frame = ordinary(100);
        assert!(outbound_from_queue_at(&frame, None, 99).is_some());
        assert!(outbound_from_queue_at(&frame, None, 100).is_none());
        assert!(outbound_from_queue_at(&frame, None, 101).is_none());
    }

    #[test]
    fn ordinary_queued_frame_cannot_outlive_its_original_deadline() {
        let frame = ordinary(100);
        let queue = flume::bounded(1);
        queue.0.send(frame).unwrap();
        let queued = queue.1.recv().unwrap();
        assert!(outbound_from_queue_at(&queued, None, 100).is_none());
        assert_eq!(queued.delivery_id, "stable-delivery");
        assert_eq!(queued.ordinary_expires_at, Some(100));
    }

    #[test]
    fn ordinary_reconnect_and_retransmit_share_the_expiry_handoff() {
        let frame = ordinary(100);
        for seq in [Some(1), Some(2)] {
            let bootstrap = frame.clone();
            assert!(outbound_from_queue_at(&bootstrap, seq, 99).is_some());
            assert!(outbound_from_queue_at(&bootstrap, seq, 100).is_none());
        }
    }

    #[test]
    fn nonordinary_queue_handoff_keeps_its_existing_policy() {
        let mut frame = ordinary(100);
        frame.ordinary = false;
        frame.ordinary_expires_at = None;
        assert!(outbound_from_queue_at(&frame, Some(1), 100).is_some());
    }

    #[test]
    fn ordinary_queue_cannot_drop_its_durable_expiry_metadata() {
        let mut frame = ordinary(100);
        frame.ordinary_expires_at = None;
        assert!(outbound_from_queue_at(&frame, Some(1), 99).is_none());
    }

    #[test]
    fn ordinary_and_retained_fresh_sources_alternate_without_blocking_on_an_empty_source() {
        let preference = AtomicBool::new(true);
        let mut handed = [0usize; 2];
        for _ in 0..128 {
            let order = fresh_source_order(&preference);
            let source = order[0];
            handed[usize::from(source)] += 1;
            record_fresh_handoff(&preference, source, None);
            assert_eq!(fresh_source_order(&preference)[0], !source);
        }
        assert_eq!(handed, [64, 64]);
        // A full ordinary execution window is equivalent to no immediately
        // available work: the second source remains eligible in this turn.
        let selected = fresh_source_order(&preference)
            .into_iter()
            .find(|ordinary| !ordinary)
            .unwrap();
        assert!(!selected);
        record_fresh_handoff(&preference, selected, None);
        assert_eq!(fresh_source_order(&preference), [true, false]);
        record_fresh_handoff(&preference, true, Some(7));
        assert_eq!(
            fresh_source_order(&preference),
            [true, false],
            "owned retransmission must not alter fresh-source preference"
        );
    }

    async fn adoption_probe_store() -> (
        tempfile::TempDir,
        crate::storage::Storage,
        crate::ordinary::OrdinaryStore,
        Arc<crate::ordinary::store::Health>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_with_config(crate::storage::StorageInitConfig {
            db_url: Some(format!(
                "sqlite://{}?mode=rwc",
                directory.path().join("adoption-product.db").display()
            )),
            managed_upgrade: false,
            ..crate::storage::StorageInitConfig::default()
        })
        .await
        .unwrap();
        let health = Arc::new(crate::ordinary::store::Health::default());
        let ordinary = storage
            .initialize_ordinary(crate::ordinary::Config::default(), health.clone())
            .await
            .unwrap();
        (directory, storage, ordinary, health)
    }

    #[tokio::test]
    async fn ordinary_select_negative_control_drops_unadopted_claim_and_fences_health() {
        let (_directory, storage, ordinary, health) = adoption_probe_store().await;
        let failures = health.subscribe();
        let (reached, arrived) = tokio::sync::oneshot::channel();
        let (_adopt, adoption) = tokio::sync::oneshot::channel();
        let mut old_wait = Box::pin(crate::private::hub::ordinary_adoption_guard_probe(
            ordinary, reached, adoption,
        ));
        // The old Warp select owns and drops this future when inbound wins.
        tokio::select! {
            _ = old_wait.as_mut() => panic!("claim adopted before the controlled boundary"),
            result = arrived => result.unwrap(),
        }
        drop(old_wait);
        assert_eq!(
            failures.borrow().as_deref(),
            Some("ordinary Private transaction interrupted before its result was adopted")
        );
        assert!(health.ensure().is_err());
        storage.close_ordinary_storage().await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_select_cancellation_keeps_one_owned_claim_until_adoption() {
        let (_directory, storage, ordinary, health) = adoption_probe_store().await;
        let failures = health.subscribe();
        let (reached, arrived) = tokio::sync::oneshot::channel();
        let (adopt, adoption) = tokio::sync::oneshot::channel();
        let mut slot = Some(PendingOutbound::Running(tokio::spawn(async move {
            crate::private::hub::ordinary_adoption_guard_probe(ordinary, reached, adoption).await;
            None
        })));
        // Exercise the same borrowed poll used by the production ServerApp.
        // Its cancellation leaves the single future in the existing owner.
        tokio::select! {
            biased;
            _ = poll_pending_outbound(&mut slot) => panic!("claim adopted before the controlled boundary"),
            result = arrived => result.unwrap(),
        }
        assert!(slot.is_some());
        assert!(failures.borrow().is_none());
        health.ensure().unwrap();
        adopt.send(()).unwrap();
        assert!(!poll_pending_outbound(&mut slot).await.unwrap());
        assert!(slot.is_none());
        assert!(failures.borrow().is_none());
        health.ensure().unwrap();
        storage.close_ordinary_storage().await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_disconnect_drains_the_owned_claim_before_releasing_it() {
        let (_directory, storage, ordinary, health) = adoption_probe_store().await;
        let (reached, arrived) = tokio::sync::oneshot::channel();
        let (adopt, adoption) = tokio::sync::oneshot::channel();
        let mut slot = Some(PendingOutbound::Running(tokio::spawn(async move {
            crate::private::hub::ordinary_adoption_guard_probe(ordinary, reached, adoption).await;
            None
        })));
        tokio::select! {
            biased;
            _ = poll_pending_outbound(&mut slot) => panic!("claim adopted before the controlled boundary"),
            result = arrived => result.unwrap(),
        }
        let PendingOutbound::Running(draining) = slot.take().unwrap() else {
            panic!("claim must still be running at the controlled boundary");
        };
        adopt.send(()).unwrap();
        assert!(draining.await.unwrap().is_none());
        assert!(slot.is_none());
        health.ensure().unwrap();
        storage.close_ordinary_storage().await.unwrap();
    }
}
