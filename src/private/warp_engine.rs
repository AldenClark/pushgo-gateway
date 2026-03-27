use std::collections::VecDeque;
use std::future::pending;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use flume::{Receiver, Sender};
use parking_lot::Mutex;
use pushgo_warp_profile::{PushgoWireProfile, negotiate_hello_versions};
use tokio::time::timeout;
use warp_link::warp_link_core::{
    AckMsg, AckStatus, AuthCheckPhase, AuthError, AuthRequest, AuthResponse, DisconnectReason,
    OutboundMsg, PeerMeta, ServerApp, ServerConfig, SessionAuthState, SessionControl, SessionCtx,
    TlsMode, TransportKind, WarpLinkError,
};

use crate::{
    device_registry::{DeviceChannelType, DeviceRegistry},
    private::{
        ConnectionMode, PrivateState,
        protocol::{
            APP_STATE_BACKGROUND, APP_STATE_FOREGROUND, DeliverEnvelope, PERF_TIER_BALANCED,
            PERF_TIER_HIGH, PERF_TIER_LOW,
        },
    },
    storage::DeviceId,
    util::constant_time_eq,
};

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

    fn mark_connect_attempt(&self, transport: TransportKind) {
        match transport {
            TransportKind::Quic => self.state.metrics.mark_quic_connect_attempt(),
            TransportKind::Wss => self.state.metrics.mark_wss_connect_attempt(),
            TransportKind::Tcp => self.state.metrics.mark_tcp_connect_attempt(),
        }
    }

    fn mark_connect_success(&self, transport: TransportKind) {
        match transport {
            TransportKind::Quic => self.state.metrics.mark_quic_connect_success(),
            TransportKind::Wss => self.state.metrics.mark_wss_connect_success(),
            TransportKind::Tcp => self.state.metrics.mark_tcp_connect_success(),
        }
    }

    fn mark_connect_failure(&self, transport: TransportKind) {
        match transport {
            TransportKind::Quic => self.state.metrics.mark_quic_connect_failure(),
            TransportKind::Wss => self.state.metrics.mark_wss_connect_failure(),
            TransportKind::Tcp => self.state.metrics.mark_tcp_connect_failure(),
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

    async fn verify_session_guardrails(
        &self,
        session: &SessionCtx,
    ) -> Result<DeviceId, SessionAuthState> {
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
            Err(flume::TryRecvError::Empty) => None,
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    fn track_new_outbound(&self, device_id: DeviceId, envelope: DeliverEnvelope) -> OutboundMsg {
        let (seq, tracked) = self.state.hub.track_sent_outbound(device_id, envelope);
        self.state.metrics.mark_deliver_sent();
        OutboundMsg {
            seq: Some(seq),
            id: tracked.delivery_id,
            payload: tracked.payload.into(),
        }
    }
}

struct SessionRuntime {
    device_id: DeviceId,
    conn_id: u64,
    terminate_requested: AtomicBool,
    control: Mutex<Option<SessionControl>>,
    receiver: Receiver<DeliverEnvelope>,
    bootstrap_inflight: Mutex<VecDeque<(u64, DeliverEnvelope)>>,
    bootstrap_pending: Mutex<VecDeque<DeliverEnvelope>>,
}

impl SessionRuntime {
    fn request_termination(&self) {
        let already_requested = self.terminate_requested.swap(true, Ordering::SeqCst);
        if already_requested {
            return;
        }
        let control = self.control.lock().clone();
        if let Some(control) = control {
            control.expire_now();
        }
    }

    fn attach_control(&self, control: SessionControl) {
        let terminate_now = self.terminate_requested.load(Ordering::SeqCst);
        {
            let mut slot = self.control.lock();
            *slot = Some(control.clone());
        }
        if terminate_now {
            control.expire_now();
        }
    }

    fn detach_control(&self) {
        let mut slot = self.control.lock();
        *slot = None;
    }

    fn is_terminating(&self) -> bool {
        self.terminate_requested.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionConnKey {
    device_id: DeviceId,
    conn_id: u64,
}

const SESSION_REGISTRY_SHARDS: usize = 64;
const LOGICAL_PARTITION_COUNT: u16 = 4096;

struct SessionRegistry {
    shards: Vec<DashMap<String, Arc<SessionRuntime>>>,
    by_conn: DashMap<SessionConnKey, String>,
}

impl SessionRegistry {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(SESSION_REGISTRY_SHARDS);
        for _ in 0..SESSION_REGISTRY_SHARDS {
            shards.push(DashMap::new());
        }
        Self {
            shards,
            by_conn: DashMap::new(),
        }
    }

    fn insert(&self, session_id: String, runtime: Arc<SessionRuntime>) {
        let index = self.shard_for_session(session_id.as_str());
        self.by_conn.insert(
            SessionConnKey {
                device_id: runtime.device_id,
                conn_id: runtime.conn_id,
            },
            session_id.clone(),
        );
        self.shards[index].insert(session_id, runtime);
    }

    fn get(&self, session_id: &str) -> Option<Arc<SessionRuntime>> {
        let index = self.shard_for_session(session_id);
        self.shards[index]
            .get(session_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    fn remove(&self, session_id: &str) -> Option<Arc<SessionRuntime>> {
        let index = self.shard_for_session(session_id);
        let runtime = self.shards[index]
            .remove(session_id)
            .map(|(_, runtime)| runtime);
        if let Some(runtime) = runtime.as_ref() {
            self.by_conn.remove(&SessionConnKey {
                device_id: runtime.device_id,
                conn_id: runtime.conn_id,
            });
        }
        runtime
    }

    fn request_termination(&self, device_id: DeviceId, conn_id: u64) -> bool {
        let Some(session_id) = self
            .by_conn
            .get(&SessionConnKey { device_id, conn_id })
            .map(|entry| entry.value().clone())
        else {
            return false;
        };
        let Some(runtime) = self.get(session_id.as_str()) else {
            return false;
        };
        runtime.request_termination();
        true
    }

    fn attach_control(&self, session_id: &str, control: SessionControl) -> bool {
        let Some(runtime) = self.get(session_id) else {
            return false;
        };
        runtime.attach_control(control);
        true
    }

    fn detach_control(&self, session_id: &str) {
        if let Some(runtime) = self.get(session_id) {
            runtime.detach_control();
        }
    }

    fn shard_for_session(&self, session_id: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }
}

fn logical_partition_for_device(device_id: DeviceId) -> u16 {
    let hash = blake3::hash(&device_id);
    let raw = u16::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]);
    raw % LOGICAL_PARTITION_COUNT
}

#[async_trait]
impl ServerApp for PushgoServerApp {
    fn wire_profile(&self) -> Arc<dyn warp_link::warp_link_core::WireProfile> {
        self.profile.clone()
    }

    async fn auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        match request.phase {
            AuthCheckPhase::Connect => {
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
                    match negotiate_hello_versions(&hello) {
                        Ok(value) => value,
                        Err(err) => return Err(AuthError::Unauthorized(err.to_string())),
                    };

                let device_id = DeviceRegistry::derive_private_device_id(device_key);
                if self.state.is_device_revoked(device_id) {
                    self.state.metrics.mark_auth_failure();
                    self.mark_connect_failure(peer.transport);
                    return Err(AuthError::Unauthorized("device revoked".to_string()));
                }
                let prepared = match self
                    .state
                    .prepare_session_bootstrap(
                        device_id,
                        hello.resume_token.as_deref(),
                        hello.last_acked_seq.unwrap_or(0),
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(err) => return Err(AuthError::Internal(err.to_string())),
                };
                let tuning = resolve_tuning(hello.perf_tier.as_deref(), hello.app_state.as_deref());
                let conn_id = rand::random::<u64>();
                let (tx, rx): (Sender<DeliverEnvelope>, Receiver<DeliverEnvelope>) =
                    flume::bounded(256);
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

                let session_id =
                    format!("w-{:04x}-{:016x}", logical_partition, rand::random::<u64>());
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
            AuthCheckPhase::RefreshWindow | AuthCheckPhase::InBandReauth => {
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
                                if refresh_before > 0
                                    && now >= expires_at.saturating_sub(refresh_before)
                                {
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
        }
    }

    async fn wait_outbound(&self, session: &SessionCtx, max_wait_ms: u64) -> Option<OutboundMsg> {
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

    async fn on_ack(&self, session: &SessionCtx, ack: AckMsg) {
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

    async fn on_disconnect(&self, session: &SessionCtx, reason: DisconnectReason) {
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

    async fn on_handshake_failure(&self, peer: PeerMeta, error: &WarpLinkError) {
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

    fn on_session_control(&self, session: &SessionCtx, control: SessionControl) {
        let device_id = DeviceRegistry::derive_private_device_id(session.identity.as_str());
        let _ = self
            .sessions
            .attach_control(session.session_id.as_str(), control.clone());
        self.state
            .register_session_control(session.session_id.as_str(), device_id, control);
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

pub fn default_server_config() -> ServerConfig {
    ServerConfig {
        hello_timeout_ms: 8_000,
        idle_timeout_ms: 72_000,
        max_outbound_wait_ms: 15_000,
        min_outbound_wait_ms: 5,
        quic_tls_mode: TlsMode::TerminateInWarp,
        tcp_tls_mode: TlsMode::TerminateInWarp,
        write_timeout_ms: 10_000,
        max_concurrent_sessions: 8_192,
        ..ServerConfig::default()
    }
}

#[derive(Clone, Copy)]
struct SessionTuning {
    heartbeat_secs: u16,
    ping_interval_secs: u16,
    idle_timeout_secs: u16,
    max_backoff_secs: u16,
}

fn resolve_tuning(perf_tier: Option<&str>, app_state: Option<&str>) -> SessionTuning {
    let tier = perf_tier
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| PERF_TIER_BALANCED.to_string());
    let state = app_state
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| APP_STATE_FOREGROUND.to_string());
    let background = state == APP_STATE_BACKGROUND;
    match (tier.as_str(), background) {
        (PERF_TIER_HIGH, false) => SessionTuning {
            heartbeat_secs: 12,
            ping_interval_secs: 6,
            idle_timeout_secs: 48,
            max_backoff_secs: 8,
        },
        (PERF_TIER_HIGH, true) => SessionTuning {
            heartbeat_secs: 18,
            ping_interval_secs: 9,
            idle_timeout_secs: 72,
            max_backoff_secs: 10,
        },
        (PERF_TIER_LOW, false) => SessionTuning {
            heartbeat_secs: 24,
            ping_interval_secs: 12,
            idle_timeout_secs: 84,
            max_backoff_secs: 16,
        },
        (PERF_TIER_LOW, true) => SessionTuning {
            heartbeat_secs: 40,
            ping_interval_secs: 20,
            idle_timeout_secs: 120,
            max_backoff_secs: 24,
        },
        (_, true) => SessionTuning {
            heartbeat_secs: 28,
            ping_interval_secs: 14,
            idle_timeout_secs: 96,
            max_backoff_secs: 14,
        },
        _ => SessionTuning {
            heartbeat_secs: 18,
            ping_interval_secs: 9,
            idle_timeout_secs: 72,
            max_backoff_secs: 10,
        },
    }
}
