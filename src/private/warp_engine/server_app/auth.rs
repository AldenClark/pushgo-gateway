use std::sync::{Arc, atomic::AtomicBool};

use flume::{Receiver, Sender};
use parking_lot::Mutex;
use pushgo_warp_profile::negotiate_hello_versions;
use warp_link::warp_link_core::{
    AuthCheckPhase, AuthError, AuthRequest, AuthResponse, SessionAuthState, SessionCtx,
};

use crate::{
    private::{ConnectionMode, protocol::DeliverEnvelope},
    routing::{DeviceChannelType, derive_private_device_id},
};

use super::{
    super::{
        registry::{SessionRuntime, logical_partition_for_device},
        tuning::resolve_tuning,
    },
    PushgoServerApp,
};

impl PushgoServerApp {
    pub(super) async fn handle_auth_request(
        &self,
        request: AuthRequest,
    ) -> Result<AuthResponse, AuthError> {
        match request.phase {
            AuthCheckPhase::Connect => self.handle_connect_auth(request).await,
            AuthCheckPhase::RefreshWindow | AuthCheckPhase::InBandReauth => {
                self.handle_reauth_state(request).await
            }
        }
    }

    async fn handle_connect_auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let peer = request
            .peer
            .ok_or_else(|| AuthError::Internal("missing_connect_peer".to_string()))?;
        let hello = request
            .hello
            .ok_or_else(|| AuthError::Internal("missing_connect_hello".to_string()))?;
        self.mark_connect_attempt(peer.transport);
        let device_key = hello.identity.trim();
        if device_key.is_empty() {
            self.state.metrics.mark_auth_failure();
            self.mark_connect_failure(peer.transport);
            return Err(AuthError::Unauthorized(
                "device_key is required".to_string(),
            ));
        }

        let Some(route) = self.state.device_registry.get(device_key) else {
            self.state.metrics.mark_auth_failure();
            self.mark_connect_failure(peer.transport);
            return Err(AuthError::Unauthorized("device_key not found".to_string()));
        };
        if route.channel_type != DeviceChannelType::Private {
            self.state.metrics.mark_auth_failure();
            self.mark_connect_failure(peer.transport);
            return Err(AuthError::Unauthorized(
                "device not on private channel".to_string(),
            ));
        }
        if let Err(err) = self.verify_gateway_token(hello.auth_token.as_deref()) {
            self.mark_connect_failure(peer.transport);
            return Err(err);
        }

        let (negotiated_wire_version, negotiated_payload_version) =
            negotiate_hello_versions(&hello)
                .map_err(|err| AuthError::Unauthorized(err.to_string()))?;

        let device_id = derive_private_device_id(device_key);
        if self.state.is_device_revoked(device_id) {
            self.state.metrics.mark_auth_failure();
            self.mark_connect_failure(peer.transport);
            return Err(AuthError::Unauthorized("device revoked".to_string()));
        }
        let prepared = self
            .state
            .prepare_session_bootstrap(
                device_id,
                hello.resume_token.as_deref(),
                hello.last_acked_seq.unwrap_or(0),
            )
            .await
            .map_err(|err| AuthError::Internal(err.to_string()))?;

        let tuning = resolve_tuning(hello.perf_tier.as_deref(), hello.app_state.as_deref());
        let conn_id = rand::random::<u64>();
        let (tx, rx): (Sender<DeliverEnvelope>, Receiver<DeliverEnvelope>) = flume::bounded(256);
        let registration =
            self.state
                .hub
                .register_connection(device_id, conn_id, peer.transport, tx);
        self.state.request_fallback_resync();
        let logical_partition = logical_partition_for_device(device_id);

        if !prepared.bootstrap.pending.is_empty() {
            self.state
                .metrics
                .mark_replay_bootstrap_enqueued(prepared.bootstrap.pending.len());
        }

        let session_id = format!("w-{:04x}-{:016x}", logical_partition, rand::random::<u64>());
        self.sessions.insert(
            session_id.clone(),
            Arc::new(SessionRuntime {
                device_id,
                conn_id,
                terminate_requested: AtomicBool::new(false),
                control: Mutex::new(None),
                receiver: rx,
                bootstrap_inflight: Mutex::new(prepared.bootstrap.inflight),
                bootstrap_pending: Mutex::new(prepared.bootstrap.pending),
            }),
        );
        if let Some(superseded_conn_id) = registration.superseded_conn_id {
            self.sessions
                .request_termination(device_id, superseded_conn_id);
        }
        self.mark_connect_success(peer.transport);

        Ok(AuthResponse::ConnectAccepted(SessionCtx {
            session_id,
            identity: hello.identity,
            resume_token: Some(prepared.resume.resume_token),
            heartbeat_secs: tuning.heartbeat_secs,
            ping_interval_secs: tuning.ping_interval_secs,
            idle_timeout_secs: tuning.idle_timeout_secs,
            max_backoff_secs: tuning.max_backoff_secs,
            auth_expires_at_unix_secs: None,
            auth_refresh_before_secs: 0,
            max_frame_bytes: 32 * 1024,
            negotiated_wire_version,
            negotiated_payload_version,
            metadata: std::collections::BTreeMap::new(),
        }))
    }

    async fn handle_reauth_state(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let session = request
            .session
            .ok_or_else(|| AuthError::Internal("missing_session".to_string()))?;
        let guardrail_state = match self.verify_session_guardrails(&session).await {
            Ok(_) => SessionAuthState::Valid,
            Err(state) => state,
        };
        if !matches!(guardrail_state, SessionAuthState::Valid) {
            return Ok(AuthResponse::State(guardrail_state));
        }

        let state = match request.phase {
            AuthCheckPhase::RefreshWindow => {
                if let Some(expires_at) = session.auth_expires_at_unix_secs {
                    let now = chrono::Utc::now().timestamp();
                    if now >= expires_at {
                        self.state.metrics.mark_auth_expired();
                        SessionAuthState::Expired("session_expired".to_string())
                    } else {
                        let refresh_before = i64::from(session.auth_refresh_before_secs);
                        if refresh_before > 0 && now >= expires_at.saturating_sub(refresh_before) {
                            self.state.metrics.mark_auth_refresh_required();
                            SessionAuthState::RefreshRequired("renew_window".to_string())
                        } else {
                            SessionAuthState::Valid
                        }
                    }
                } else {
                    SessionAuthState::Valid
                }
            }
            AuthCheckPhase::InBandReauth => {
                let Some(hello) = request.hello else {
                    self.state.metrics.mark_auth_failure();
                    return Ok(AuthResponse::State(SessionAuthState::RefreshRequired(
                        "missing_reauth_hello".to_string(),
                    )));
                };
                if hello.identity.trim() != session.identity {
                    self.state.metrics.mark_auth_failure();
                    SessionAuthState::Revoked("identity_mismatch".to_string())
                } else if self
                    .verify_gateway_token(hello.auth_token.as_deref())
                    .is_err()
                {
                    self.state.metrics.mark_auth_revoked();
                    SessionAuthState::Revoked("gateway_token_invalid".to_string())
                } else {
                    SessionAuthState::Valid
                }
            }
            AuthCheckPhase::Connect => SessionAuthState::Valid,
        };
        Ok(AuthResponse::State(state))
    }

    async fn verify_session_guardrails(
        &self,
        session: &SessionCtx,
    ) -> Result<crate::storage::DeviceId, SessionAuthState> {
        let Some(runtime) = self.sessions.get(session.session_id.as_str()) else {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked("session_not_found".to_string()));
        };
        if !matches!(
            self.state
                .hub
                .connection_mode(runtime.device_id, runtime.conn_id),
            ConnectionMode::Active | ConnectionMode::Draining
        ) {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked(
                "superseded_connection".to_string(),
            ));
        }
        let device_id = runtime.device_id;

        if self.state.is_device_revoked(device_id) {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked("device_revoked".to_string()));
        }
        let Some(route) = self.state.device_registry.get(session.identity.as_str()) else {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked(
                "device_key_not_found".to_string(),
            ));
        };
        if route.channel_type != DeviceChannelType::Private {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked(
                "device_channel_changed".to_string(),
            ));
        }

        Ok(device_id)
    }
}
