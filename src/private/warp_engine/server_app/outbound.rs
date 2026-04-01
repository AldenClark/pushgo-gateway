use std::{future::pending, time::Duration};

use tokio::time::timeout;
use warp_link::warp_link_core::{OutboundMsg, SessionCtx};

use crate::{private::ConnectionMode, storage::DeviceId};

use super::{super::registry::SessionRuntime, PushgoServerApp};

impl PushgoServerApp {
    pub(super) async fn wait_outbound_message(
        &self,
        session: &SessionCtx,
        max_wait_ms: u64,
    ) -> Option<OutboundMsg> {
        let runtime = self.sessions.get(session.session_id.as_str())?.clone();
        if runtime.is_terminating() {
            return pending::<Option<OutboundMsg>>().await;
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
        let wait_ms = retransmit_wait
            .as_millis()
            .min(u128::from(max_wait_ms.max(1))) as u64;
        let wait_ms = wait_ms.max(1);

        let result = timeout(
            Duration::from_millis(wait_ms),
            runtime.receiver.recv_async(),
        )
        .await;

        match result {
            Ok(Ok(envelope)) => Some(self.track_new_outbound(runtime.device_id, envelope)),
            Ok(Err(_)) | Err(_) => {
                self.take_outbound_ready(runtime.as_ref(), ack_timeout)
                    .await
            }
        }
    }

    async fn take_outbound_ready(
        &self,
        runtime: &SessionRuntime,
        ack_timeout: Duration,
    ) -> Option<OutboundMsg> {
        let retransmit = self
            .state
            .hub
            .poll_retransmit_outbound(runtime.device_id, ack_timeout);
        if retransmit.exhausted_count > 0 {
            self.state
                .metrics
                .mark_retransmit_exhausted(retransmit.exhausted_count);
        }

        if let Some((seq, envelope)) = runtime.bootstrap_inflight.lock().pop_front() {
            self.state.hub.mark_delivery_sent(runtime.device_id, seq);
            self.state.metrics.mark_deliver_retransmit_sent();
            return Some(OutboundMsg {
                seq: Some(seq),
                id: envelope.delivery_id,
                payload: envelope.payload.into(),
            });
        }

        if let Some(envelope) = runtime.bootstrap_pending.lock().pop_front() {
            return Some(self.track_new_outbound(runtime.device_id, envelope));
        }

        if let Some((seq, envelope)) = retransmit.outbound {
            self.state.metrics.mark_deliver_retransmit_sent();
            return Some(OutboundMsg {
                seq: Some(seq),
                id: envelope.delivery_id,
                payload: envelope.payload.into(),
            });
        }

        match runtime.receiver.try_recv() {
            Ok(envelope) => Some(self.track_new_outbound(runtime.device_id, envelope)),
            Err(flume::TryRecvError::Empty) | Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    fn track_new_outbound(
        &self,
        device_id: DeviceId,
        envelope: crate::private::protocol::DeliverEnvelope,
    ) -> OutboundMsg {
        let (seq, tracked) = self.state.hub.track_sent_outbound(device_id, envelope);
        self.state.metrics.mark_deliver_sent();
        OutboundMsg {
            seq: Some(seq),
            id: tracked.delivery_id,
            payload: tracked.payload.into(),
        }
    }
}
