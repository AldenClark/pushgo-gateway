use std::{future::pending, time::Duration};

use warp_link::warp_link_core::{OutboundMsg, SessionCtx};

use crate::{private::ConnectionMode, storage::DeviceId};

use super::{super::registry::SessionRuntime, PushgoServerApp};

/// Shared last application handoff for fresh work, reconnect bootstrap and
/// retransmit. Expiry never creates an ACK and never renews the original TTL.
fn outbound_from_queue_at(
    envelope: &crate::private::protocol::DeliverEnvelope,
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
        let runtime = self.sessions.get(session.session_id.as_str())?.clone();
        if runtime.is_terminating() || self.state.is_shutting_down() {
            runtime.request_termination();
            return pending::<Option<OutboundMsg>>().await;
        }
        if !self
            .state
            .hub
            .validate_ordinary_session_route(runtime.device_id, runtime.ordinary_route_generation)
            .await
            .unwrap_or(false)
        {
            runtime.request_termination();
            return None;
        }
        match self
            .state
            .hub
            .connection_mode(runtime.device_id, runtime.conn_id)
        {
            ConnectionMode::Stale => {
                runtime.request_termination();
                return pending::<Option<OutboundMsg>>().await;
            }
            ConnectionMode::Active | ConnectionMode::Draining => {}
        }

        // Register before the durable read. Admission/ACK can notify while that
        // read is in progress; an idle session needs no new polling task/timer.
        let notify = self
            .state
            .hub
            .ordinary_notifier()
            .unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Notify::new()));
        let changed = notify.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let ack_timeout = Duration::from_secs(self.state.config.ack_timeout_secs.max(2));
        if let Some(outbound) = self
            .take_outbound_ready(runtime.as_ref(), ack_timeout)
            .await
        {
            return Some(outbound);
        }
        let retransmit_wait = self
            .state
            .hub
            .next_retransmit_due_in(runtime.device_id, ack_timeout)
            .unwrap_or_else(|| Duration::from_millis(max_wait_ms.max(1)));
        let wait = retransmit_wait
            .min(Duration::from_millis(max_wait_ms.max(1)))
            .max(Duration::from_millis(1));
        tokio::select! {
            _ = changed => self.take_outbound_ready(runtime.as_ref(), ack_timeout).await,
            result = runtime.receiver.recv_async() => {
                match result {
                    Ok(envelope) => self.authorized_new_outbound(runtime.as_ref(), envelope).await,
                    Err(_) => None,
                }
            }
            _ = tokio::time::sleep(wait) => self.take_outbound_ready(runtime.as_ref(), ack_timeout).await,
        }
    }

    async fn authorized_new_outbound(
        &self,
        runtime: &SessionRuntime,
        envelope: crate::private::protocol::DeliverEnvelope,
    ) -> Option<OutboundMsg> {
        match self
            .state
            .hub
            .authorize_ordinary_outbound(runtime.device_id, &envelope)
            .await
        {
            Ok(true) => {
                let outbound = self.track_new_outbound(runtime.device_id, envelope.clone());
                if outbound.is_none() {
                    // Expired after the SQL result returned. Adopt a durable
                    // release before its owned reservation can become reusable.
                    let _ = self
                        .state
                        .hub
                        .authorize_ordinary_outbound(runtime.device_id, &envelope)
                        .await;
                }
                outbound
            }
            Ok(false) => None,
            Err(error) => {
                tracing::error!(error = %error, "ordinary Private send authorization failed");
                runtime.request_termination();
                None
            }
        }
    }

    async fn authorized_retransmit(
        &self,
        runtime: &SessionRuntime,
        seq: u64,
        envelope: crate::private::protocol::DeliverEnvelope,
    ) -> Option<OutboundMsg> {
        match self
            .state
            .hub
            .authorize_ordinary_outbound(runtime.device_id, &envelope)
            .await
        {
            Ok(true) => {
                let outbound = outbound_from_queue_at(
                    &envelope,
                    Some(seq),
                    chrono::Utc::now().timestamp_millis(),
                );
                if outbound.is_none() {
                    let _ = self
                        .state
                        .hub
                        .authorize_ordinary_outbound(runtime.device_id, &envelope)
                        .await;
                    return None;
                }
                self.state.hub.mark_delivery_sent(runtime.device_id, seq);
                self.state.metrics.mark_deliver_retransmit_sent();
                outbound
            }
            Ok(false) => None,
            Err(error) => {
                tracing::error!(error = %error, "ordinary Private retransmit authorization failed");
                runtime.request_termination();
                None
            }
        }
    }

    async fn take_outbound_ready(
        &self,
        runtime: &SessionRuntime,
        ack_timeout: Duration,
    ) -> Option<OutboundMsg> {
        if self.state.is_shutting_down() {
            runtime.request_termination();
            return None;
        }
        if !self
            .state
            .hub
            .validate_ordinary_session_route(runtime.device_id, runtime.ordinary_route_generation)
            .await
            .unwrap_or(false)
        {
            runtime.request_termination();
            return None;
        }
        // Every collection here is bounded by the normal connection/window
        // configuration. Never hold a parking_lot guard across a database await.
        let bootstrap_inflight = runtime.bootstrap_inflight.lock().pop_front();
        if let Some((seq, envelope)) = bootstrap_inflight {
            if let Some(outbound) = self.authorized_retransmit(runtime, seq, envelope).await {
                return Some(outbound);
            }
        }
        let bootstrap_pending = runtime.bootstrap_pending.lock().pop_front();
        if let Some(envelope) = bootstrap_pending {
            if let Some(outbound) = self.authorized_new_outbound(runtime, envelope).await {
                return Some(outbound);
            }
        }
        let retransmit = self
            .state
            .hub
            .poll_retransmit_outbound(runtime.device_id, ack_timeout);
        if retransmit.exhausted_count > 0 {
            self.state
                .metrics
                .mark_retransmit_exhausted(retransmit.exhausted_count);
        }
        if let Some((seq, envelope)) = retransmit.outbound {
            if let Some(outbound) = self.authorized_retransmit(runtime, seq, envelope).await {
                return Some(outbound);
            }
        }
        if let Ok(envelope) = runtime.receiver.try_recv() {
            if let Some(outbound) = self.authorized_new_outbound(runtime, envelope).await {
                return Some(outbound);
            }
        }
        match self
            .state
            .hub
            .ordinary_outbound(runtime.device_id, runtime.ordinary_route_generation)
            .await
        {
            Ok(Some(envelope)) => self.authorized_new_outbound(runtime, envelope).await,
            Ok(None) => None,
            Err(error) => {
                tracing::error!(error = %error, "ordinary Private claim failed");
                runtime.request_termination();
                None
            }
        }
    }

    fn track_new_outbound(
        &self,
        device_id: DeviceId,
        envelope: crate::private::protocol::DeliverEnvelope,
    ) -> Option<OutboundMsg> {
        let mut outbound =
            outbound_from_queue_at(&envelope, None, chrono::Utc::now().timestamp_millis())?;
        let (seq, _) = self.state.hub.track_sent_outbound(device_id, envelope);
        outbound.seq = Some(seq);
        self.state.metrics.mark_deliver_sent();
        Some(outbound)
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
}
