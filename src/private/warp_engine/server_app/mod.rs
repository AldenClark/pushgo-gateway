use std::sync::Arc;

use async_trait::async_trait;
use pushgo_warp_profile::PushgoWireProfile;
use warp_link::warp_link_core::{
    AckMsg, AuthError, AuthRequest, AuthResponse, DisconnectReason, OutboundMsg, PeerMeta,
    ServerApp, SessionControl, SessionCtx, WarpLinkError,
};

use crate::{private::PrivateState, util::constant_time_eq};

use super::registry::SessionRegistry;

#[path = "auth.rs"]
mod auth;
#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "outbound.rs"]
mod outbound;

pub struct PushgoServerApp {
    state: Arc<PrivateState>,
    profile: Arc<PushgoWireProfile>,
    sessions: SessionRegistry,
}

impl PushgoServerApp {
    pub fn new(state: Arc<PrivateState>) -> Self {
        Self {
            state,
            profile: Arc::new(PushgoWireProfile::new()),
            sessions: SessionRegistry::new(),
        }
    }

    fn mark_connect_attempt(&self, transport: warp_link::warp_link_core::TransportKind) {
        match transport {
            warp_link::warp_link_core::TransportKind::Quic => {
                self.state.metrics.mark_quic_connect_attempt()
            }
            warp_link::warp_link_core::TransportKind::Wss => {
                self.state.metrics.mark_wss_connect_attempt()
            }
            warp_link::warp_link_core::TransportKind::Tcp => {
                self.state.metrics.mark_tcp_connect_attempt()
            }
        }
    }

    fn mark_connect_success(&self, transport: warp_link::warp_link_core::TransportKind) {
        match transport {
            warp_link::warp_link_core::TransportKind::Quic => {
                self.state.metrics.mark_quic_connect_success()
            }
            warp_link::warp_link_core::TransportKind::Wss => {
                self.state.metrics.mark_wss_connect_success()
            }
            warp_link::warp_link_core::TransportKind::Tcp => {
                self.state.metrics.mark_tcp_connect_success()
            }
        }
    }

    fn mark_connect_failure(&self, transport: warp_link::warp_link_core::TransportKind) {
        match transport {
            warp_link::warp_link_core::TransportKind::Quic => {
                self.state.metrics.mark_quic_connect_failure()
            }
            warp_link::warp_link_core::TransportKind::Wss => {
                self.state.metrics.mark_wss_connect_failure()
            }
            warp_link::warp_link_core::TransportKind::Tcp => {
                self.state.metrics.mark_tcp_connect_failure()
            }
        }
    }

    fn verify_gateway_token(&self, provided: Option<&str>) -> Result<(), AuthError> {
        let Some(required_token) = self.state.config.gateway_token.as_deref() else {
            return Ok(());
        };
        let provided_token = provided.unwrap_or("").trim();
        let token_ok = constant_time_eq(provided_token.as_bytes(), required_token.as_bytes());
        if provided_token.is_empty() || !token_ok {
            self.state.metrics.mark_auth_failure();
            return Err(AuthError::Unauthorized("gateway token invalid".to_string()));
        }
        Ok(())
    }
}

#[async_trait]
impl ServerApp for PushgoServerApp {
    fn wire_profile(&self) -> Arc<dyn warp_link::warp_link_core::WireProfile> {
        self.profile.clone()
    }

    async fn auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        self.handle_auth_request(request).await
    }

    async fn wait_outbound(&self, session: &SessionCtx, max_wait_ms: u64) -> Option<OutboundMsg> {
        self.wait_outbound_message(session, max_wait_ms).await
    }

    async fn on_ack(&self, session: &SessionCtx, ack: AckMsg) {
        self.handle_ack(session, ack).await;
    }

    async fn on_disconnect(&self, session: &SessionCtx, reason: DisconnectReason) {
        self.handle_disconnect(session, reason).await;
    }

    async fn on_handshake_failure(&self, peer: PeerMeta, error: &WarpLinkError) {
        self.handle_handshake_failure(peer, error).await;
    }

    fn on_session_control(&self, session: &SessionCtx, control: SessionControl) {
        self.register_session_control(session, control);
    }

    fn session_coordinator(
        &self,
    ) -> Option<Arc<dyn warp_link::warp_link_core::SessionCoordinator>> {
        None
    }

    fn session_coord_owner(&self) -> Option<String> {
        None
    }
}
