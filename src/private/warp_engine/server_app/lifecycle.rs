use warp_link::warp_link_core::{
    AckMsg, AckStatus, DisconnectReason, PeerMeta, SessionControl, SessionCtx, WarpLinkError,
};

use crate::routing::derive_private_device_id;

use super::PushgoServerApp;

impl PushgoServerApp {
    pub(super) async fn handle_ack(&self, session: &SessionCtx, ack: AckMsg) {
        let Some(runtime) = self.sessions.get(session.session_id.as_str()) else {
            self.state.metrics.mark_ack_non_ok();
            return;
        };
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
                    .complete_terminal_delivery(runtime.device_id, ack.id.as_str(), Some(seq))
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
                    .complete_terminal_delivery(runtime.device_id, ack.id.as_str(), ack.seq)
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
            self.state
                .hub
                .unregister_connection(runtime.device_id, runtime.conn_id);
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
