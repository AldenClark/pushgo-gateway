use warp_link::warp_link_core::{
    AckMsg, AckStatus, DisconnectReason, PeerMeta, SessionControl, SessionCtx, WarpLinkError,
};

use crate::routing::derive_private_device_id;

use super::{super::registry::PendingOutbound, PushgoServerApp};

impl PushgoServerApp {
    pub(super) async fn handle_ack(&self, session: &SessionCtx, ack: AckMsg) {
        let Some(runtime) = self.sessions.get(session.session_id.as_str()) else {
            self.state.metrics.mark_ack_non_ok();
            return;
        };
        if self.state.is_shutting_down()
            || runtime.is_terminating()
            || matches!(
                self.state
                    .hub
                    .connection_mode(runtime.device_id, runtime.conn_id),
                crate::private::ConnectionMode::Stale
            )
            || !self
                .state
                .hub
                .validate_ordinary_session_route(
                    runtime.device_id,
                    runtime.ordinary_route_generation,
                )
                .await
                .unwrap_or(false)
        {
            runtime.request_termination();
            self.state.metrics.mark_ack_non_ok();
            return;
        }
        self.state
            .hub
            .collapse_draining_delivery_window_if_active(runtime.device_id, runtime.conn_id);
        match ack.status {
            AckStatus::Ok => {
                let Some(seq) = ack.seq else {
                    self.state.metrics.mark_ack_non_ok();
                    return;
                };
                match self
                    .state
                    .complete_terminal_delivery_from_session(
                        runtime.device_id,
                        ack.id.as_str(),
                        Some(seq),
                        runtime.ordinary_route_generation,
                    )
                    .await
                {
                    Ok(true) => {
                        self.state.metrics.mark_ack_ok();
                    }
                    Ok(false) | Err(_) => self.state.metrics.mark_ack_non_ok(),
                }
            }
            AckStatus::InvalidPayload => {
                let _ = self
                    .state
                    .reject_terminal_delivery_from_session(
                        runtime.device_id,
                        ack.id.as_str(),
                        ack.seq,
                        runtime.ordinary_route_generation,
                    )
                    .await;
                self.state.metrics.mark_ack_non_ok();
            }
            AckStatus::Error => {
                self.state.metrics.mark_ack_non_ok();
            }
        }
    }

    pub(super) async fn handle_disconnect(&self, session: &SessionCtx, reason: DisconnectReason) {
        self.sessions.detach_control(session.session_id.as_str());
        if let Some(runtime) = self.sessions.remove(session.session_id.as_str()) {
            runtime.request_termination();
            let pending = runtime.pending_outbound.lock().await.take();
            if let Some(pending) = pending {
                // Losing Warp's select branch is normal. Finish adopting any
                // COMMIT result, then discard an unsent frame without ACKing it.
                match pending {
                    PendingOutbound::Running(task) => {
                        if task.await.is_err() {
                            self.state.record_session_task_failure(
                                "Private outbound task failed during disconnect join",
                            );
                        }
                    }
                    PendingOutbound::Ready(_) => {}
                }
            }
            self.state
                .hub
                .unregister_connection(runtime.device_id, runtime.conn_id);
            if let Err(error) = self
                .state
                .hub
                .release_ordinary_if_offline(runtime.device_id)
                .await
            {
                tracing::error!(error = %error, "ordinary Private disconnect release failed");
            }
        }
        self.state
            .unregister_session_control(session.session_id.as_str());
        if matches!(reason, DisconnectReason::IdleTimeout) {
            self.state.metrics.mark_idle_timeout();
        }
    }

    pub(super) async fn handle_handshake_failure(&self, peer: PeerMeta, error: &WarpLinkError) {
        match error {
            WarpLinkError::Timeout(_) => {
                self.state.metrics.mark_hello_timeout();
                self.mark_connect_failure(peer.transport);
            }
            WarpLinkError::Transport(_)
            | WarpLinkError::Wire(_)
            | WarpLinkError::Protocol(_)
            | WarpLinkError::Internal(_)
            | WarpLinkError::Coordination(_)
            | WarpLinkError::Reconnect(_)
            | WarpLinkError::Unsupported(_) => self.mark_connect_failure(peer.transport),
            WarpLinkError::Auth(_) => {}
        }
    }

    pub(super) fn register_session_control(&self, session: &SessionCtx, control: SessionControl) {
        let device_id = derive_private_device_id(session.identity.as_str());
        let _ = self
            .sessions
            .attach_control(session.session_id.as_str(), control.clone());
        self.state
            .register_session_control(session.session_id.as_str(), device_id, control);
    }
}
