use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::time::Instant;

use flume::{Receiver, Sender};
use parking_lot::Mutex;
use pushgo_warp_profile::negotiate_hello_versions;
use warp_link::warp_link_core::{
    AuthCheckPhase, AuthError, AuthRequest, AuthResponse, HelloCtx, SessionAuthState, SessionCtx,
    handoff,
};

use crate::{
    private::{ConnectionMode, protocol::DeliverEnvelope},
    routing::{DeviceChannelType, derive_private_device_id},
};

use super::{
    super::{
        registry::{
            HandoffBinding, HandoffState, PendingOutbound, SessionRuntime,
            logical_partition_for_device,
        },
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
        if self.state.is_shutting_down() {
            return Err(AuthError::Internal("server_shutting_down".to_string()));
        }
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

        if let Err(err) = self.verify_gateway_token(hello.auth_token.as_deref()) {
            self.mark_connect_failure(peer.transport);
            return Err(err);
        }

        let (negotiated_wire_version, negotiated_payload_version) =
            negotiate_hello_versions(&hello)
                .map_err(|err| AuthError::Unauthorized(err.to_string()))?;

        let device_id = derive_private_device_id(device_key);
        let ordinary_route_generation = if self.state.hub.store().ordinary_handle().is_some() {
            Some(
                self.state
                    .hub
                    .store()
                    .ordinary_private_route(device_id)
                    .await
                    .map_err(|error| AuthError::Unauthorized(error.to_string()))?
                    .route_generation,
            )
        } else {
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
            None
        };
        if self.state.is_device_revoked(device_id) {
            self.state.metrics.mark_auth_failure();
            self.mark_connect_failure(peer.transport);
            return Err(AuthError::Unauthorized("device revoked".to_string()));
        }
        let handoff_enabled =
            hello.metadata.get(handoff::VERSION_KEY).map(String::as_str) == Some(handoff::VERSION);
        let prepare = hello.metadata.get(handoff::PHASE_KEY).map(String::as_str);
        if prepare.is_some_and(|phase| phase != "prepare")
            || (prepare.is_some() && !handoff_enabled)
        {
            return Err(AuthError::Unauthorized("invalid_handoff_phase".into()));
        }
        let staged = if prepare.is_some() {
            let (old_id, id) = handoff_request(&hello)?;
            let old = self
                .sessions
                .get(&old_id)
                .ok_or_else(|| AuthError::Unauthorized("handoff_primary_missing".into()))?;
            if old.device_id != device_id
                || !old.handoff_enabled
                || old.is_terminating()
                || old.ordinary_route_generation != ordinary_route_generation
                || hello.resume_token.as_deref() != Some(old.resume_token.as_str())
                || !self
                    .state
                    .hub
                    .resume_token_matches(device_id, &old.resume_token)
            {
                return Err(AuthError::Unauthorized("handoff_primary_mismatch".into()));
            }
            Some((old_id, id, old))
        } else {
            // A separate new connection cannot inherit an in-progress handoff.
            self.sessions.cancel_device_handoffs(device_id);
            None
        };
        let prepared = if staged.is_none() {
            Some(
                self.state
                    .prepare_session_bootstrap(
                        device_id,
                        hello.resume_token.as_deref(),
                        hello.last_acked_seq.unwrap_or(0),
                    )
                    .await
                    .map_err(|err| AuthError::Internal(err.to_string()))?,
            )
        } else {
            None
        };

        let tuning = resolve_tuning(hello.perf_tier.as_deref(), hello.app_state.as_deref());
        let conn_id = rand::random::<u64>();
        let connection_queue_capacity =
            crate::private::private_connection_queue_capacity(self.state.config.runtime_profile);
        let (tx, rx): (Sender<DeliverEnvelope>, Receiver<DeliverEnvelope>) =
            flume::bounded(connection_queue_capacity);
        self.state
            .hub
            .store()
            .record_device_activity_best_effort(
                device_id,
                chrono::Utc::now().timestamp_millis(),
                "private_connect",
            )
            .await;
        if self.state.is_shutting_down() {
            return Err(AuthError::Internal("server_shutting_down".to_string()));
        }
        // No cancellable await after this point: every reservation has a
        // registered session owner whose disconnect releases the pair.
        let logical_partition = logical_partition_for_device(device_id);
        let session_id = format!("w-{:04x}-{:016x}", logical_partition, rand::random::<u64>());
        let mut metadata = BTreeMap::new();
        if handoff_enabled {
            metadata.insert(handoff::VERSION_KEY.into(), handoff::VERSION.into());
        }
        let (resume_token, bootstrap_inflight, bootstrap_pending, initial_handoff, auth_expiry) =
            if let Some((old_id, id, old)) = staged.as_ref() {
                let binding = HandoffBinding {
                    peer: old_id.clone(),
                    id: id.clone(),
                    deadline: Instant::now() + Duration::from_secs(15),
                };
                metadata = handoff_metadata("prepared", old_id, id);
                (
                    old.resume_token.clone(),
                    VecDeque::new(),
                    VecDeque::new(),
                    HandoffState::Prepared(binding),
                    Some(chrono::Utc::now().timestamp() + 15),
                )
            } else {
                let prepared = prepared.expect("non-staged authentication has bootstrap");
                if !prepared.bootstrap.pending.is_empty() {
                    self.state
                        .metrics
                        .mark_replay_bootstrap_enqueued(prepared.bootstrap.pending.len());
                }
                (
                    prepared.resume.resume_token,
                    prepared.bootstrap.inflight,
                    prepared.bootstrap.pending,
                    HandoffState::Active(None),
                    None,
                )
            };
        let runtime = Arc::new(SessionRuntime {
            device_id,
            conn_id,
            transport: peer.transport,
            sender: tx.clone(),
            resume_token: resume_token.clone(),
            handoff_enabled,
            handoff: Arc::new(Mutex::new(initial_handoff)),
            ordinary_route_generation,
            ordinary_first: Arc::new(AtomicBool::new(true)),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            control: Arc::new(Mutex::new(None)),
            outbound_stop: Arc::new(tokio::sync::Notify::new()),
            receiver: rx,
            bootstrap_inflight: Arc::new(Mutex::new(bootstrap_inflight)),
            bootstrap_pending: Arc::new(Mutex::new(bootstrap_pending)),
            pending_outbound: tokio::sync::Mutex::new(None),
            failure_store: self.state.hub.store().ordinary_handle(),
        });
        {
            let _gate = self.sessions.handoff_gate.lock();
            if let Some((old_id, id, old)) = staged {
                let mut old_state = old.handoff.lock();
                if !matches!(*old_state, HandoffState::Active(None))
                    || old.is_terminating()
                    || self.sessions.has_other_live_session(device_id, &[&old_id])
                    || !matches!(
                        self.state.hub.connection_mode(device_id, old.conn_id),
                        ConnectionMode::Active
                    )
                {
                    return Err(AuthError::Unauthorized("handoff_primary_busy".into()));
                }
                let deadline = runtime
                    .handoff
                    .lock()
                    .binding()
                    .expect("prepared binding")
                    .deadline;
                *old_state = HandoffState::Active(Some(HandoffBinding {
                    peer: session_id.clone(),
                    id,
                    deadline,
                }));
                self.sessions.insert(session_id.clone(), runtime);
            } else {
                self.sessions.cancel_device_handoffs_locked(device_id);
                let registration =
                    self.state
                        .hub
                        .register_connection(device_id, conn_id, peer.transport, tx);
                self.sessions.insert(session_id.clone(), runtime);
                if let Some(superseded) = registration.superseded_conn_id {
                    self.sessions.request_termination(device_id, superseded);
                }
            }
        }
        self.state.request_fallback_resync();
        self.mark_connect_success(peer.transport);

        Ok(AuthResponse::ConnectAccepted(SessionCtx {
            session_id,
            identity: hello.identity,
            resume_token: Some(resume_token),
            heartbeat_secs: tuning.heartbeat_secs,
            ping_interval_secs: tuning.ping_interval_secs,
            idle_timeout_secs: tuning.idle_timeout_secs,
            max_backoff_secs: tuning.max_backoff_secs,
            auth_expires_at_unix_secs: auth_expiry,
            auth_refresh_before_secs: 0,
            max_frame_bytes: warp_link::warp_link_core::MAX_FRAME_BYTES as u32,
            negotiated_wire_version,
            negotiated_payload_version,
            metadata,
        }))
    }

    async fn handle_reauth_state(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let session = request
            .session
            .ok_or_else(|| AuthError::Internal("missing_session".to_string()))?;
        self.sessions.expire_handoff(&session.session_id);
        if let Some(hello) = request.hello.as_ref()
            && hello.metadata.contains_key(handoff::PHASE_KEY)
        {
            return self.handle_handoff_command(session, hello).await;
        }
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

    async fn handle_handoff_command(
        &self,
        session: SessionCtx,
        hello: &HelloCtx,
    ) -> Result<AuthResponse, AuthError> {
        let runtime = self
            .sessions
            .get(&session.session_id)
            .ok_or_else(|| AuthError::Unauthorized("handoff_session_missing".into()))?;
        if !runtime.handoff_enabled
            || hello.metadata.get(handoff::VERSION_KEY).map(String::as_str)
                != Some(handoff::VERSION)
            || hello.identity.trim() != session.identity
            || hello.resume_token.as_deref() != Some(runtime.resume_token.as_str())
            || !self
                .state
                .hub
                .resume_token_matches(runtime.device_id, &runtime.resume_token)
        {
            return Err(AuthError::Unauthorized("handoff_context_mismatch".into()));
        }
        self.verify_gateway_token(hello.auth_token.as_deref())?;
        if self.verify_session_guardrails(&session).await.is_err() {
            return Err(AuthError::Unauthorized("handoff_session_retired".into()));
        }
        let (peer, id) = handoff_request(hello)?;
        if peer == session.session_id {
            // A peer is another owned socket. Reject aliasing before any pair
            // locks so malformed input cannot lock one runtime twice.
            return Err(AuthError::Unauthorized("handoff_self_peer".into()));
        }
        match hello.metadata.get(handoff::PHASE_KEY).map(String::as_str) {
            Some("freeze") => self.freeze_primary(session, runtime, peer, id).await,
            Some("activate") => self.activate_candidate(session, runtime, peer, id).await,
            Some("resume") => {
                {
                    let _gate = self.sessions.handoff_gate.lock();
                    let state = runtime.handoff.lock();
                    let allowed = matches!(*state, HandoffState::Active(None))
                        || matches!(
                            *state,
                            HandoffState::Active(_)
                                | HandoffState::Freezing(_)
                                | HandoffState::Frozen(_)
                        ) && state
                            .binding()
                            .is_some_and(|value| value.peer == peer && value.id == id);
                    if !allowed {
                        return Err(AuthError::Unauthorized("handoff_resume_mismatch".into()));
                    }
                    drop(state);
                    self.sessions.cancel_handoff_locked(&session.session_id);
                }
                Ok(handoff_reply(session, "resumed", &peer, &id, None))
            }
            _ => Err(AuthError::Unauthorized("invalid_handoff_phase".into())),
        }
    }

    async fn freeze_primary(
        &self,
        session: SessionCtx,
        old: Arc<SessionRuntime>,
        candidate_id: String,
        id: String,
    ) -> Result<AuthResponse, AuthError> {
        {
            let _gate = self.sessions.handoff_gate.lock();
            if matches!(*old.handoff.lock(), HandoffState::Active(None)) {
                // Candidate cancellation/expiry may win across sockets before
                // an already-written freeze arrives. This is an abort, not a
                // reason to revoke the still-healthy primary.
                return Ok(handoff_reply(session, "resumed", &candidate_id, &id, None));
            }
        }
        let candidate = match self.sessions.get(&candidate_id) {
            Some(candidate) => candidate,
            None => {
                let _gate = self.sessions.handoff_gate.lock();
                let state = old.handoff.lock();
                let cancelled = matches!(*state, HandoffState::Active(None))
                    || state
                        .binding()
                        .is_some_and(|binding| binding.peer == candidate_id && binding.id == id);
                drop(state);
                if cancelled {
                    self.sessions.cancel_handoff_locked(&session.session_id);
                    return Ok(handoff_reply(session, "resumed", &candidate_id, &id, None));
                }
                return Err(AuthError::Unauthorized("handoff_candidate_missing".into()));
            }
        };
        let deadline = {
            let _gate = self.sessions.handoff_gate.lock();
            let old_state = old.handoff.lock();
            let binding = old_state
                .binding()
                .filter(|binding| binding.peer == candidate_id && binding.id == id)
                .cloned()
                .ok_or_else(|| AuthError::Unauthorized("handoff_freeze_mismatch".into()))?;
            if Instant::now() >= binding.deadline {
                drop(old_state);
                self.sessions.cancel_handoff_locked(&session.session_id);
                return Ok(handoff_reply(session, "resumed", &candidate_id, &id, None));
            }
            if !matches!(
                *old_state,
                HandoffState::Active(_) | HandoffState::Freezing(_) | HandoffState::Frozen(_)
            ) || !candidate_is_prepared(&candidate, &session.session_id, &id, binding.deadline)
                || old.device_id != candidate.device_id
                || self
                    .sessions
                    .has_other_live_session(old.device_id, &[&session.session_id, &candidate_id])
            {
                return Err(AuthError::Unauthorized("handoff_freeze_unavailable".into()));
            }
            drop(old_state);
            *old.handoff.lock() = HandoffState::Freezing(binding.clone());
            old.outbound_stop.notify_waiters();
            binding.deadline
        };
        // The previous wait_outbound borrow was cancelled by this in-band HELLO.
        // Its owned database preparation is joined/adopted, never detached or
        // silently discarded. It has not allocated a transport sequence yet.
        let adopted = match tokio::time::timeout_at(deadline, old.pending_outbound.lock()).await {
            Ok(mut pending) => {
                if let Some(PendingOutbound::Running(task)) = pending.as_mut() {
                    match tokio::time::timeout_at(deadline, task).await {
                        Ok(Ok(prepared)) => {
                            *pending = prepared.map(PendingOutbound::Ready);
                            true
                        }
                        Ok(Err(_)) => {
                            *pending = None;
                            self.state.record_session_task_failure(
                                "Private handoff preparation join failed",
                            );
                            old.request_termination();
                            false
                        }
                        Err(_) => false,
                    }
                } else {
                    true
                }
            }
            Err(_) => false,
        };
        let valid = {
            let _gate = self.sessions.handoff_gate.lock();
            let valid = adopted
                && self.handoff_pair_is_owned(
                    &session.session_id,
                    &old,
                    &candidate_id,
                    &candidate,
                    &id,
                );
            if valid {
                let binding = old
                    .handoff
                    .lock()
                    .binding()
                    .expect("owned freezing binding")
                    .clone();
                *old.handoff.lock() = HandoffState::Frozen(binding);
            }
            valid
        };
        if !valid {
            // This await may finish after A was cancelled and a new B reserved
            // this primary. Only A is ours to cancel, never its newer B.
            self.sessions.cancel_handoff(&candidate_id);
            return Ok(handoff_reply(session, "resumed", &candidate_id, &id, None));
        }
        // Warp writes this reply in the old socket's existing serialized write
        // owner, strictly after every earlier DELIVER on that same connection.
        Ok(handoff_reply(session, "drained", &candidate_id, &id, None))
    }

    fn handoff_pair_is_owned(
        &self,
        old_id: &str,
        old: &SessionRuntime,
        candidate_id: &str,
        candidate: &SessionRuntime,
        id: &str,
    ) -> bool {
        let old_state = old.handoff.lock();
        let binding = match &*old_state {
            HandoffState::Freezing(binding) | HandoffState::Frozen(binding) => binding,
            _ => return false,
        };
        binding.peer == candidate_id
            && binding.id == id
            && Instant::now() < binding.deadline
            && !old.is_terminating()
            && !candidate.is_terminating()
            && old.device_id == candidate.device_id
            && self.sessions.get(old_id).is_some()
            && self.sessions.get(candidate_id).is_some()
            && candidate_is_prepared(candidate, old_id, id, binding.deadline)
            && self
                .state
                .hub
                .resume_token_matches(old.device_id, &old.resume_token)
            && !self
                .sessions
                .has_other_live_session(old.device_id, &[old_id, candidate_id])
    }

    async fn activate_candidate(
        &self,
        mut session: SessionCtx,
        candidate: Arc<SessionRuntime>,
        old_id: String,
        id: String,
    ) -> Result<AuthResponse, AuthError> {
        let old = self
            .sessions
            .get(&old_id)
            .ok_or_else(|| AuthError::Unauthorized("handoff_primary_missing".into()))?;
        let deadline = {
            let _gate = self.sessions.handoff_gate.lock();
            let drained = matches!(*old.handoff.lock(), HandoffState::Frozen(_));
            if !drained
                || !self.handoff_pair_is_owned(&old_id, &old, &session.session_id, &candidate, &id)
            {
                return Err(AuthError::Unauthorized(
                    "handoff_activation_not_frozen".into(),
                ));
            }
            candidate
                .handoff
                .lock()
                .binding()
                .expect("prepared binding")
                .deadline
        };
        let bootstrap = match tokio::time::timeout_at(
            deadline,
            self.state
                .hub
                .build_bootstrap_queues(candidate.device_id, self.state.config.pull_limit),
        )
        .await
        {
            Ok(Ok(bootstrap)) => bootstrap,
            Ok(Err(error)) => {
                self.sessions.cancel_handoff(&session.session_id);
                return Err(AuthError::Internal(error.to_string()));
            }
            Err(_) => {
                self.sessions.cancel_handoff(&session.session_id);
                return Err(AuthError::Internal("handoff_activation_deadline".into()));
            }
        };
        {
            let _gate = self.sessions.handoff_gate.lock();
            let drained = matches!(*old.handoff.lock(), HandoffState::Frozen(_));
            if !drained
                || !self.handoff_pair_is_owned(&old_id, &old, &session.session_id, &candidate, &id)
            {
                self.sessions.cancel_handoff_locked(&session.session_id);
                return Err(AuthError::Unauthorized("handoff_activation_expired".into()));
            }
            *candidate.bootstrap_inflight.lock() = bootstrap.inflight;
            *candidate.bootstrap_pending.lock() = bootstrap.pending;
            *old.handoff.lock() = HandoffState::Retired;
            *candidate.handoff.lock() = HandoffState::Active(None);
            let registration = self.state.hub.register_connection(
                candidate.device_id,
                candidate.conn_id,
                candidate.transport,
                candidate.sender.clone(),
            );
            if let Some(superseded) = registration.superseded_conn_id {
                self.sessions
                    .request_termination(candidate.device_id, superseded);
            }
            old.request_termination();
            candidate.outbound_stop.notify_waiters();
        }
        self.state.request_fallback_resync();
        session.auth_expires_at_unix_secs = None;
        Ok(handoff_reply(session, "active", &old_id, &id, None))
    }

    async fn verify_session_guardrails(
        &self,
        session: &SessionCtx,
    ) -> Result<crate::storage::DeviceId, SessionAuthState> {
        if self.state.is_shutting_down() {
            return Err(SessionAuthState::Revoked("server_shutting_down".to_owned()));
        }
        let Some(runtime) = self.sessions.get(session.session_id.as_str()) else {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked("session_not_found".to_string()));
        };
        let passive = matches!(*runtime.handoff.lock(), HandoffState::Prepared(_));
        if runtime.is_terminating()
            || (!passive
                && !matches!(
                    self.state
                        .hub
                        .connection_mode(runtime.device_id, runtime.conn_id),
                    ConnectionMode::Active | ConnectionMode::Draining
                ))
        {
            self.state.metrics.mark_auth_revoked();
            return Err(SessionAuthState::Revoked(
                "superseded_connection".to_string(),
            ));
        }
        let device_id = runtime.device_id;

        if runtime.ordinary_route_generation.is_some() {
            return match self
                .state
                .hub
                .validate_ordinary_session_route(device_id, runtime.ordinary_route_generation)
                .await
            {
                Ok(true) if !self.state.is_device_revoked(device_id) => Ok(device_id),
                Ok(_) | Err(_) => {
                    self.state.metrics.mark_auth_revoked();
                    Err(SessionAuthState::Revoked(
                        "device_route_retired".to_string(),
                    ))
                }
            };
        }

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

fn handoff_request(hello: &HelloCtx) -> Result<(String, String), AuthError> {
    let peer = hello
        .metadata
        .get(handoff::PEER_KEY)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| AuthError::Unauthorized("handoff_peer_missing".into()))?;
    let id = hello
        .metadata
        .get(handoff::ID_KEY)
        .filter(|value| {
            (16..=64).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        .ok_or_else(|| AuthError::Unauthorized("handoff_id_invalid".into()))?;
    Ok((peer.clone(), id.clone()))
}

fn handoff_metadata(phase: &str, peer: &str, id: &str) -> BTreeMap<String, String> {
    [
        (handoff::VERSION_KEY, handoff::VERSION),
        (handoff::PHASE_KEY, phase),
        (handoff::PEER_KEY, peer),
        (handoff::ID_KEY, id),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

fn handoff_reply(
    mut session: SessionCtx,
    phase: &str,
    peer: &str,
    id: &str,
    expiry: Option<i64>,
) -> AuthResponse {
    session.metadata.extend(handoff_metadata(phase, peer, id));
    session.auth_expires_at_unix_secs = expiry;
    AuthResponse::SessionUpdated(session)
}

fn candidate_is_prepared(
    candidate: &SessionRuntime,
    old_id: &str,
    id: &str,
    deadline: Instant,
) -> bool {
    matches!(&*candidate.handoff.lock(), HandoffState::Prepared(binding)
        if binding.peer == old_id && binding.id == id && binding.deadline == deadline)
}
