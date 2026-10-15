//! One bounded owner for live Private groups. Database COMMIT owns completion;
//! transport futures may disappear without cancelling a queued ACK/release.
use crate::{
    ordinary_store::OrdinaryStore,
    private_model::{PrivateRoute, PrivateTicket},
    store::{Health, KernelError, Result},
};
use async_trait::async_trait;
use bytes::Bytes;
use pushgo_warp_profile::{PushgoWireProfile, negotiate_hello_versions};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};
use warp_link::warp_link_core::{
    AckMsg, AckStatus, AuthCheckPhase, AuthError, AuthRequest, AuthResponse, DisconnectReason,
    OutboundMsg, ServerApp, SessionAuthState, SessionControl, SessionCtx, TransportKind,
    WireProfile,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateTransport {
    Quic,
    Tcp,
    Wss,
    Mqtt,
}
impl From<TransportKind> for PrivateTransport {
    fn from(t: TransportKind) -> Self {
        match t {
            TransportKind::Quic => Self::Quic,
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Wss => Self::Wss,
        }
    }
}
#[derive(Clone, Debug)]
pub struct PrivateRuntimeConfig {
    pub max_connections: usize,
    pub window: usize,
    pub owned_slots: usize,
    pub command_capacity: usize,
    pub retransmit: Duration,
    pub drain: Duration,
}
impl Default for PrivateRuntimeConfig {
    fn default() -> Self {
        let small = pushgo_gateway::runtime_config::RuntimeTuning::for_profile(
            pushgo_gateway::runtime_config::GatewayRuntimeProfile::Small,
        );
        Self {
            max_connections: 8192,
            window: small.private.pull_limit,
            owned_slots: small.private.hot_cache_capacity,
            command_capacity: 8192,
            retransmit: Duration::from_secs(8),
            drain: Duration::from_secs(8),
        }
    }
}
struct Shared {
    store: OrdinaryStore,
    config: PrivateRuntimeConfig,
    token_hash: Option<blake3::Hash>,
    connections: Arc<Semaphore>,
    io_connections: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    stopping: AtomicBool,
    controls: Mutex<BTreeMap<String, SessionControl>>,
    abandoned: Mutex<BTreeSet<(String, String)>>,
    maintenance: tokio::sync::Notify,
}
impl Shared {
    fn token_ok(&self, token: Option<&str>) -> bool {
        self.token_hash.as_ref().is_none_or(|expected| {
            token.is_some_and(|s| {
                !s.is_empty() && s.len() <= 4096 && blake3::hash(s.as_bytes()) == *expected
            })
        })
    }
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        for control in self.controls.lock().unwrap().values() {
            control.expire_now();
        }
    }
    fn fence(&self, reason: &str) {
        self.store.health.fail(reason);
        self.stop();
    }
    fn ensure(&self) -> Result<()> {
        self.store.health.ensure()?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(KernelError::Unavailable);
        }
        Ok(())
    }
}
struct RuntimeInner {
    shared: Arc<Shared>,
    tx: mpsc::Sender<Command>,
    join: tokio::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    closed: AtomicBool,
}
impl Drop for RuntimeInner {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            self.shared
                .fence("PrivateRuntime dropped without joined shutdown");
        }
    }
}
#[derive(Clone)]
pub struct PrivateRuntime {
    inner: Arc<RuntimeInner>,
}
impl PrivateRuntime {
    pub fn new(
        store: OrdinaryStore,
        token: Option<String>,
        config: PrivateRuntimeConfig,
    ) -> Result<Self> {
        if config.max_connections == 0
            || config.max_connections > 8192
            || config.window == 0
            || config.window > 96
            || config.owned_slots == 0
            || config.owned_slots > 4096
            || config.command_capacity == 0
            || config.command_capacity > 8192
            || config.drain > Duration::from_secs(30)
            || config.retransmit.is_zero()
        {
            return Err(KernelError::Invalid(
                "bounded Private runtime configuration required".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(config.command_capacity);
        let shared = Arc::new(Shared {
            connections: Arc::new(Semaphore::new(config.max_connections)),
            io_connections: Arc::new(Semaphore::new(config.max_connections)),
            slots: Arc::new(Semaphore::new(config.owned_slots)),
            token_hash: token.map(|v| blake3::hash(v.as_bytes())),
            config,
            store,
            stopping: AtomicBool::new(false),
            controls: Mutex::new(BTreeMap::new()),
            abandoned: Mutex::new(BTreeSet::new()),
            maintenance: tokio::sync::Notify::new(),
        });
        let owned = shared.clone();
        let join = tokio::spawn(async move { Owner::new(owned).run(rx).await });
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                shared,
                tx,
                join: tokio::sync::Mutex::new(Some(join)),
                closed: AtomicBool::new(false),
            }),
        })
    }
    pub fn try_io_permit(&self) -> Result<OwnedSemaphorePermit> {
        self.inner.shared.ensure()?;
        self.inner
            .shared
            .io_connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| KernelError::Unavailable)
    }
    pub(crate) fn fence(&self, reason: &str) {
        self.inner.shared.fence(reason);
    }
    pub(crate) fn control(&self, session: &SessionCtx, control: SessionControl) {
        if self.is_stopping() {
            control.expire_now();
        }
        self.inner
            .shared
            .controls
            .lock()
            .unwrap()
            .insert(session.session_id.clone(), control);
        let _ = self.inner.tx.try_send(Command::ControlChanged);
    }
    async fn check_route(&self, session: &SessionCtx) -> bool {
        let (reply, rx) = oneshot::channel();
        if self
            .inner
            .tx
            .send(Command::CheckRoute {
                identity: session.identity.clone(),
                id: session.session_id.clone(),
                reply,
            })
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }
    pub fn app(&self) -> Arc<dyn ServerApp> {
        Arc::new(PrivateApp(self.clone()))
    }
    /// Stop HTTP/transport acceptors and join their tasks before shutdown().
    pub fn begin_shutdown(&self) {
        self.inner.shared.stop();
    }
    pub fn is_stopping(&self) -> bool {
        self.inner.shared.stopping.load(Ordering::Acquire)
            || self.inner.shared.store.health.ensure().is_err()
    }
    pub fn available_owned_slots(&self) -> usize {
        self.inner.shared.slots.available_permits()
    }
    pub fn resource_snapshot(&self) -> serde_json::Value {
        let s = &self.inner.shared;
        serde_json::json!({
            "connection_limit":s.config.max_connections,
            "authenticated_connections":s.config.max_connections-s.connections.available_permits(),
            "transport_io_connections":s.config.max_connections-s.io_connections.available_permits(),
            "owned_limit":s.config.owned_slots,
            "reserved_or_owned_work":s.config.owned_slots-s.slots.available_permits(),
            "per_device_window":s.config.window,
            "command_queue_limit":s.config.command_capacity,
            "queued_commands":s.config.command_capacity-self.inner.tx.capacity(),
            "stopping":self.is_stopping()
        })
    }
    pub(crate) async fn register_mqtt(
        &self,
        requested: Option<&str>,
        token: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.inner.shared.ensure()?;
        if !self.inner.shared.token_ok(token) {
            return Err(KernelError::Unauthorized);
        }
        if requested.is_some_and(|s| s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(KernelError::Invalid(
                "MQTT client identifier invalid".into(),
            ));
        }
        let result = self
            .inner
            .shared
            .store
            .register_device("mqtt", requested)
            .await;
        if matches!(&result, Err(KernelError::Database(_))) {
            self.inner
                .shared
                .fence("MQTT registration database failure");
        }
        result
    }
    pub(crate) async fn subscribe_mqtt(
        &self,
        session: &SessionCtx,
        channel: &str,
        auth: &str,
    ) -> Result<()> {
        self.inner.shared.ensure()?;
        if !self.check_route(session).await {
            return Err(KernelError::Unauthorized);
        }
        // Some(channel)/None(name) selects the existing-only branch. Its native
        // gate/transaction validates channel/password and never creates a row.
        let result = self
            .inner
            .shared
            .store
            .subscribe(&session.identity, Some(channel), None, auth)
            .await;
        if matches!(&result, Err(KernelError::Database(_))) {
            self.inner.shared.fence("MQTT subscribe database failure");
        }
        result.map(|_| ())
    }
    pub(crate) async fn unsubscribe_mqtt(&self, session: &SessionCtx, channel: &str) -> Result<()> {
        self.inner.shared.ensure()?;
        if !self.check_route(session).await {
            return Err(KernelError::Unauthorized);
        }
        let result = self
            .inner
            .shared
            .store
            .unsubscribe(&session.identity, channel)
            .await;
        if matches!(&result, Err(KernelError::Database(_))) {
            self.inner.shared.fence("MQTT unsubscribe database failure");
        }
        result.map(|_| ())
    }
    pub(crate) async fn connect(
        &self,
        identity: String,
        token: Option<&str>,
        transport: PrivateTransport,
    ) -> Result<SessionCtx> {
        self.inner.shared.ensure()?;
        if identity.is_empty()
            || identity.len() != 32
            || !identity.bytes().all(|b| b.is_ascii_hexdigit())
            || !self.inner.shared.token_ok(token)
        {
            return Err(KernelError::Invalid(
                "unauthorized Private connection".into(),
            ));
        }
        let permit = self
            .inner
            .shared
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| KernelError::Unavailable)?;
        let (reply, rx) = oneshot::channel();
        self.inner
            .tx
            .send(Command::Connect {
                identity,
                transport,
                permit,
                reply,
            })
            .await
            .map_err(|_| KernelError::Unavailable)?;
        let mut connected = rx.await.map_err(|_| KernelError::Unavailable)??;
        connected.grant.adopted = true;
        Ok(connected.session)
    }
    pub(crate) async fn outbound(&self, session: &SessionCtx, wait_ms: u64) -> Option<OutboundMsg> {
        self.outbound_mode(session, wait_ms, false).await
    }
    pub(crate) async fn outbound_mode(
        &self,
        session: &SessionCtx,
        wait_ms: u64,
        only_issued: bool,
    ) -> Option<OutboundMsg> {
        if self.inner.shared.ensure().is_err() {
            return None;
        }
        let (reply, rx) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(1, 15_000));
        self.inner
            .tx
            .send(Command::Next {
                identity: session.identity.clone(),
                id: session.session_id.clone(),
                deadline,
                only_issued,
                reply,
            })
            .await
            .ok()?;
        tokio::time::timeout_at(deadline, rx)
            .await
            .ok()?
            .ok()
            .flatten()
    }
    pub(crate) async fn acknowledge(&self, session: &SessionCtx, ack: AckMsg) {
        if ack.status == AckStatus::Error {
            return;
        }
        let Some(seq) = ack.seq else {
            return;
        };
        let (reply, rx) = oneshot::channel();
        if self
            .inner
            .tx
            .send(Command::Ack {
                identity: session.identity.clone(),
                id: session.session_id.clone(),
                seq,
                delivery: ack.id,
                reply,
            })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }
    pub(crate) async fn disconnect(&self, session: &SessionCtx) {
        let (reply, rx) = oneshot::channel();
        if self
            .inner
            .tx
            .send(Command::Disconnect {
                identity: session.identity.clone(),
                id: session.session_id.clone(),
                reply,
            })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
        self.inner
            .shared
            .controls
            .lock()
            .unwrap()
            .remove(&session.session_id);
    }
    /// Requires all transport/HTTP session tasks already joined. Never aborts the
    /// owner task; an ACK already queued remains owned through its DB COMMIT.
    pub async fn shutdown(&self) -> Result<()> {
        self.begin_shutdown();
        let (reply, rx) = oneshot::channel();
        self.inner
            .tx
            .send(Command::Stop { reply })
            .await
            .map_err(|_| KernelError::Unavailable)?;
        rx.await.map_err(|_| KernelError::Unavailable)??;
        if let Some(join) = self.inner.join.lock().await.take() {
            join.await.map_err(|_| KernelError::Unavailable)??;
        }
        self.inner.closed.store(true, Ordering::Release);
        Ok(())
    }
}
struct PrivateApp(PrivateRuntime);
#[async_trait]
impl ServerApp for PrivateApp {
    fn wire_profile(&self) -> Arc<dyn WireProfile> {
        Arc::new(PushgoWireProfile::new())
    }
    async fn auth(&self, request: AuthRequest) -> std::result::Result<AuthResponse, AuthError> {
        if request.phase != AuthCheckPhase::Connect {
            let session = request
                .session
                .ok_or_else(|| AuthError::Unauthorized("session required".into()))?;
            if self.0.inner.shared.ensure().is_err() {
                return Ok(AuthResponse::State(SessionAuthState::Revoked(
                    "private stopped".into(),
                )));
            }
            if let Some(hello) = request.hello {
                if hello.identity != session.identity
                    || !self.0.inner.shared.token_ok(hello.auth_token.as_deref())
                {
                    return Ok(AuthResponse::State(SessionAuthState::Revoked(
                        "identity or token changed".into(),
                    )));
                }
            }
            if !self.0.check_route(&session).await {
                return Ok(AuthResponse::State(SessionAuthState::Revoked(
                    "Private route generation revoked".into(),
                )));
            }
            return Ok(AuthResponse::State(SessionAuthState::Valid));
        }
        let hello = request
            .hello
            .ok_or_else(|| AuthError::Unauthorized("HELLO required".into()))?;
        let peer = request
            .peer
            .ok_or_else(|| AuthError::Unauthorized("transport required".into()))?;
        let (wire, payload) =
            negotiate_hello_versions(&hello).map_err(|e| AuthError::Unauthorized(e.to_string()))?;
        let mut session = self
            .0
            .connect(
                hello.identity,
                hello.auth_token.as_deref(),
                peer.transport.into(),
            )
            .await
            .map_err(|_| AuthError::Unauthorized("Private route or capacity unavailable".into()))?;
        session.negotiated_wire_version = wire;
        session.negotiated_payload_version = payload;
        Ok(AuthResponse::ConnectAccepted(session))
    }
    async fn wait_outbound(&self, session: &SessionCtx, max_wait_ms: u64) -> Option<OutboundMsg> {
        self.0.outbound(session, max_wait_ms).await
    }
    async fn on_ack(&self, session: &SessionCtx, ack: AckMsg) {
        self.0.acknowledge(session, ack).await;
    }
    async fn on_disconnect(&self, session: &SessionCtx, _reason: DisconnectReason) {
        self.0.disconnect(session).await;
    }
    fn on_session_control(&self, session: &SessionCtx, control: SessionControl) {
        self.0.control(session, control);
    }
}
struct Connected {
    session: SessionCtx,
    grant: ConnectionGrant,
}
// A cancelled auth receiver transfers cleanup to the existing owner task.
// It never spawns a callback or drops a durable grant in a destructor.
struct ConnectionGrant {
    shared: Arc<Shared>,
    identity: String,
    id: String,
    adopted: bool,
}
impl Drop for ConnectionGrant {
    fn drop(&mut self) {
        if !self.adopted {
            self.shared
                .abandoned
                .lock()
                .unwrap()
                .insert((self.identity.clone(), self.id.clone()));
            self.shared.maintenance.notify_one();
        }
    }
}
enum Command {
    CheckRoute {
        identity: String,
        id: String,
        reply: oneshot::Sender<bool>,
    },
    ControlChanged,
    Connect {
        identity: String,
        transport: PrivateTransport,
        permit: OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<Connected>>,
    },
    Next {
        identity: String,
        id: String,
        deadline: Instant,
        only_issued: bool,
        reply: oneshot::Sender<Option<OutboundMsg>>,
    },
    Ack {
        identity: String,
        id: String,
        seq: u64,
        delivery: String,
        reply: oneshot::Sender<()>,
    },
    Disconnect {
        identity: String,
        id: String,
        reply: oneshot::Sender<()>,
    },
    Stop {
        reply: oneshot::Sender<Result<()>>,
    },
}
struct Pending {
    deadline: Instant,
    only_issued: bool,
    reply: oneshot::Sender<Option<OutboundMsg>>,
}
struct Connection {
    terminated: bool,
    transport: PrivateTransport,
    draining: Option<Instant>,
    issued: BTreeMap<u64, Instant>,
    pending: Option<Pending>,
    _permit: OwnedSemaphorePermit,
}
struct Work {
    ticket: PrivateTicket,
    permit: Option<OwnedSemaphorePermit>,
    health: Arc<Health>,
}
impl Work {
    fn committed(mut self) {
        drop(self.permit.take());
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            permit.forget();
            self.health
                .fail("Private capability dropped before durable completion; owned slot fenced");
        }
    }
}
struct Group {
    route_dirty: bool,
    route_valid: bool,
    abandon_failed: bool,
    route: PrivateRoute,
    id: String,
    resume: String,
    next_seq: u64,
    next_claim: Instant,
    connections: BTreeMap<String, Connection>,
    work: BTreeMap<u64, Work>,
}
struct Owner {
    shared: Arc<Shared>,
    groups: BTreeMap<String, Group>,
}
impl Owner {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            groups: BTreeMap::new(),
        }
    }
    async fn release(&self, group: &mut Group) -> Result<()> {
        if group.work.is_empty() {
            return Ok(());
        }
        if group.abandon_failed {
            return Err(KernelError::Unavailable);
        }
        let tokens = group
            .work
            .values()
            .map(|w| w.ticket.claim_token.clone())
            .collect::<Vec<_>>();
        if let Err(e) = self.shared.store.private_release(&group.id, &tokens).await {
            group.abandon_failed = true;
            return Err(e);
        }
        for (_, work) in std::mem::take(&mut group.work) {
            work.committed();
        }
        for connection in group.connections.values_mut() {
            connection.issued.clear();
        }
        Ok(())
    }
    async fn command(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::ControlChanged => {}
            Command::CheckRoute {
                identity,
                id,
                reply,
            } => {
                let mut valid = false;
                let mut route_revoked = false;
                if let Some(group) = self.groups.get_mut(&identity) {
                    if self.shared.ensure().is_ok()
                        && group
                            .connections
                            .get(&id)
                            .is_some_and(|c| c.draining.is_none_or(|until| until > Instant::now()))
                    {
                        match self.shared.store.private_route(&identity).await {
                            Ok(route) => {
                                valid = route.device_key == group.route.device_key
                                    && route.route_generation == group.route.route_generation
                                    && group.route_valid;
                                route_revoked = !valid;
                            }
                            Err(KernelError::Database(_)) => {
                                self.shared.fence("Private auth route read failed")
                            }
                            Err(_) => {
                                route_revoked = true;
                            }
                        }
                    }
                    if route_revoked {
                        group.route_valid = false;
                        for (sid, c) in &mut group.connections {
                            c.draining = Some(Instant::now());
                            if let Some(control) = self.shared.controls.lock().unwrap().get(sid) {
                                control.expire_now();
                            }
                        }
                    }
                    if !valid {
                        if let Some(c) = group.connections.get_mut(&id) {
                            c.draining = Some(Instant::now());
                        }
                        if let Some(control) = self.shared.controls.lock().unwrap().get(&id) {
                            control.expire_now();
                        }
                    }
                }
                let _ = reply.send(valid);
            }
            Command::Connect {
                identity,
                transport,
                permit,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(false);
                }
                if let Err(e) = self.shared.ensure() {
                    let _ = reply.send(Err(e));
                    return Ok(false);
                }
                let route = match self.shared.store.private_route(&identity).await {
                    Ok(route) => route,
                    Err(e) => {
                        if matches!(e, KernelError::Database(_)) {
                            self.shared.fence("Private route read failed");
                        }
                        let _ = reply.send(Err(e));
                        return Ok(false);
                    }
                };
                if reply.is_closed() {
                    return Ok(false);
                }
                let mut group = self.groups.remove(&identity).unwrap_or_else(|| Group {
                    route_dirty: false,
                    route_valid: true,
                    abandon_failed: false,
                    route: route.clone(),
                    id: id(),
                    resume: id(),
                    next_seq: 1,
                    next_claim: Instant::now(),
                    connections: BTreeMap::new(),
                    work: BTreeMap::new(),
                });
                if group.route.device_key != route.device_key
                    || group.route.route_generation != route.route_generation
                {
                    for (sid, c) in &mut group.connections {
                        c.draining = Some(Instant::now());
                        if let Some(control) = self.shared.controls.lock().unwrap().get(sid) {
                            control.expire_now();
                        }
                    }
                    if let Err(e) = self.release(&mut group).await {
                        self.groups.insert(identity, group);
                        let _ = reply.send(Err(e));
                        return Err(KernelError::Unavailable);
                    }
                    group.route = route;
                    group.resume = id();
                }
                group.route_valid = true;
                if group
                    .connections
                    .values()
                    .filter(|c| c.draining.is_some())
                    .count()
                    >= 16
                {
                    self.groups.insert(identity, group);
                    let _ = reply.send(Err(KernelError::Unavailable));
                    return Ok(false);
                }
                for connection in group.connections.values_mut() {
                    if connection.transport == transport && connection.draining.is_none() {
                        connection.draining = Some(Instant::now() + self.shared.config.drain);
                        if let Some(p) = connection.pending.take() {
                            let _ = p.reply.send(None);
                        }
                    }
                }
                let sid = id();
                let session = SessionCtx {
                    session_id: sid.clone(),
                    identity: identity.clone(),
                    resume_token: Some(group.resume.clone()),
                    heartbeat_secs: 24,
                    ping_interval_secs: 24,
                    idle_timeout_secs: 72,
                    max_backoff_secs: 30,
                    auth_expires_at_unix_secs: None,
                    auth_refresh_before_secs: 0,
                    max_frame_bytes: 32768,
                    negotiated_wire_version: 2,
                    negotiated_payload_version: 1,
                    metadata: BTreeMap::new(),
                };
                group.connections.insert(
                    sid.clone(),
                    Connection {
                        terminated: false,
                        transport,
                        draining: None,
                        issued: BTreeMap::new(),
                        pending: None,
                        _permit: permit,
                    },
                );
                group.next_claim = Instant::now();
                let grant = ConnectionGrant {
                    shared: self.shared.clone(),
                    identity: identity.clone(),
                    id: sid.clone(),
                    adopted: false,
                };
                if reply.send(Ok(Connected { session, grant })).is_err() {
                    group.connections.remove(&sid);
                }
                self.groups.insert(identity, group);
            }
            Command::Next {
                identity,
                id,
                deadline,
                only_issued,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(false);
                }
                if let Some(connection) = self
                    .groups
                    .get_mut(&identity)
                    .and_then(|g| g.connections.get_mut(&id))
                {
                    connection.pending = Some(Pending {
                        deadline,
                        only_issued,
                        reply,
                    });
                }
            }
            Command::Ack {
                identity,
                id,
                seq,
                delivery,
                reply,
            } => {
                if let Some(group) = self.groups.get_mut(&identity) {
                    let issued = group
                        .connections
                        .get(&id)
                        .is_some_and(|c| c.issued.contains_key(&seq));
                    if issued
                        && group
                            .work
                            .get(&seq)
                            .is_some_and(|w| w.ticket.delivery_id == delivery)
                    {
                        let ticket = &group.work.get(&seq).unwrap().ticket;
                        match self.shared.store.private_ack(&group.route, ticket).await {
                            Ok(consumed) => {
                                if !consumed {
                                    self.shared
                                        .store
                                        .private_release(&group.id, &[ticket.claim_token.clone()])
                                        .await?;
                                }
                                if let Some(w) = group.work.remove(&seq) {
                                    w.committed();
                                }
                                for c in group.connections.values_mut() {
                                    c.issued.remove(&seq);
                                }
                                group.next_claim = Instant::now();
                            }
                            Err(e) => {
                                self.shared.fence("Private ACK COMMIT failed");
                                let _ = reply.send(());
                                return Err(e);
                            }
                        }
                    }
                }
                let _ = reply.send(());
            }
            Command::Disconnect {
                identity,
                id,
                reply,
            } => {
                if let Some(group) = self.groups.get_mut(&identity) {
                    group.connections.remove(&id);
                }
                self.reap_empty().await?;
                let _ = reply.send(());
            }
            Command::Stop { reply } => {
                if self.groups.values().any(|g| !g.connections.is_empty()) {
                    let _ = reply.send(Err(KernelError::Invalid(
                        "join Private transport sessions before runtime shutdown".into(),
                    )));
                    return Ok(false);
                }
                self.reap_empty().await?;
                if self.shared.slots.available_permits() != self.shared.config.owned_slots {
                    let _ = reply.send(Err(KernelError::Unavailable));
                    return Ok(false);
                }
                let _ = reply.send(Ok(()));
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn reap_empty(&mut self) -> Result<()> {
        let keys = self
            .groups
            .iter()
            .filter(|(_, g)| g.connections.is_empty())
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        for key in keys {
            let mut group = self.groups.remove(&key).unwrap();
            if let Err(e) = self.release(&mut group).await {
                self.groups.insert(key, group);
                self.shared.fence("Private abandon COMMIT failed");
                return Err(e);
            }
        }
        Ok(())
    }
    async fn service(&mut self) -> Result<()> {
        let abandoned = std::mem::take(&mut *self.shared.abandoned.lock().unwrap());
        for (identity, id) in abandoned {
            if let Some(group) = self.groups.get_mut(&identity) {
                group.connections.remove(&id);
            }
            self.shared.controls.lock().unwrap().remove(&id);
        }
        self.reap_empty().await?;
        let now = Instant::now();
        for group in self.groups.values_mut() {
            if group.route_dirty && self.shared.ensure().is_ok() {
                group.route_dirty = false;
                let valid = match self
                    .shared
                    .store
                    .private_route(&group.route.device_key)
                    .await
                {
                    Ok(route) => {
                        route.device_key == group.route.device_key
                            && route.route_generation == group.route.route_generation
                    }
                    Err(KernelError::Database(e)) => return Err(KernelError::Database(e)),
                    Err(_) => false,
                };
                if !valid {
                    group.route_valid = false;
                    for c in group.connections.values_mut() {
                        c.draining = Some(now);
                    }
                }
            }
            for (sid, c) in &mut group.connections {
                if c.draining.is_some_and(|until| now >= until) {
                    c.terminated = true;
                    if let Some(control) = self.shared.controls.lock().unwrap().get(sid) {
                        control.expire_now();
                    }
                }
                if c.pending.as_ref().is_some_and(|p| {
                    p.reply.is_closed()
                        || p.deadline <= now
                        || c.draining.is_some_and(|until| now >= until)
                        || self.shared.ensure().is_err()
                }) {
                    if let Some(p) = c.pending.take() {
                        let _ = p.reply.send(None);
                    }
                }
            }
            if self.shared.ensure().is_err() || !group.route_valid {
                continue;
            }
            let active_waiter = group
                .connections
                .values()
                .any(|c| c.draining.is_none() && c.pending.is_some());
            if active_waiter
                && now >= group.next_claim
                && group.work.len() < self.shared.config.window
            {
                if group.next_seq > u64::MAX - self.shared.config.window as u64 {
                    self.shared.fence("Private sequence exhausted");
                    return Err(KernelError::Unavailable);
                }
                let mut reserved = Vec::new();
                for _ in group.work.len()..self.shared.config.window {
                    match self.shared.slots.clone().try_acquire_owned() {
                        Ok(permit) => reserved.push(permit),
                        Err(_) => break,
                    }
                }
                if !reserved.is_empty() {
                    let claimed = match self
                        .shared
                        .store
                        .private_claim(&group.route, &group.id, reserved.len())
                        .await
                    {
                        Ok(claimed) => claimed,
                        Err(e) => {
                            for permit in reserved {
                                permit.forget();
                            }
                            self.shared
                                .fence("Private claim COMMIT failed; reserved slots fenced");
                            return Err(e);
                        }
                    };
                    if claimed.len() > reserved.len() {
                        for p in reserved {
                            p.forget();
                        }
                        self.shared
                            .fence("Private store exceeded reserved claim limit");
                        return Err(KernelError::Unavailable);
                    }
                    for (ticket, permit) in claimed.into_iter().zip(reserved.into_iter()) {
                        let seq = group.next_seq;
                        group.next_seq = seq.checked_add(1).ok_or_else(|| {
                            KernelError::Invalid("Private sequence exhausted".into())
                        })?;
                        group.work.insert(
                            seq,
                            Work {
                                ticket,
                                permit: Some(permit),
                                health: self.shared.store.health.clone(),
                            },
                        );
                    }
                }
                group.next_claim = now + Duration::from_secs(15);
            }
            let ids = group.connections.keys().cloned().collect::<Vec<_>>();
            for sid in ids {
                let connection = group.connections.get(&sid).unwrap();
                if connection.draining.is_some() || connection.pending.is_none() {
                    continue;
                }
                let selected = group
                    .work
                    .iter()
                    .find(|(seq, _)| {
                        (!connection.pending.as_ref().unwrap().only_issued
                            || connection.issued.contains_key(seq))
                            && connection.issued.get(seq).is_none_or(|sent| {
                                now.duration_since(*sent) >= self.shared.config.retransmit
                            })
                    })
                    .map(|(seq, _)| *seq);
                let Some(seq) = selected else {
                    continue;
                };
                let ticket = &group.work.get(&seq).unwrap().ticket;
                if !self.shared.store.private_authorize(ticket).await? {
                    // A false authorization means route/mode/retirement invalidated
                    // this grant. Release its claim by COMMIT before slot reuse.
                    self.shared
                        .store
                        .private_release(&group.id, &[ticket.claim_token.clone()])
                        .await?;
                    group.work.remove(&seq).unwrap().committed();
                    for c in group.connections.values_mut() {
                        c.issued.remove(&seq);
                    }
                    continue;
                }
                let payload = encode_payload(&ticket.payload)?;
                let connection = group.connections.get_mut(&sid).unwrap();
                if let Some(pending) = connection.pending.take() {
                    if pending
                        .reply
                        .send(Some(OutboundMsg {
                            seq: Some(seq),
                            id: ticket.delivery_id.clone(),
                            payload,
                        }))
                        .is_ok()
                    {
                        connection.issued.insert(seq, now);
                    }
                }
            }
        }
        Ok(())
    }
    fn deadline(&self) -> Instant {
        let mut deadline = Instant::now() + Duration::from_secs(15);
        for group in self.groups.values() {
            for c in group.connections.values() {
                if let Some(until) = c.draining.filter(|_| !c.terminated) {
                    deadline = deadline.min(until);
                }
                if let Some(p) = &c.pending {
                    deadline = deadline.min(p.deadline);
                    for sent in c.issued.values() {
                        deadline = deadline
                            .min((*sent + self.shared.config.retransmit).max(Instant::now()));
                    }
                }
            }
        }
        deadline
    }
    async fn run(mut self, mut rx: mpsc::Receiver<Command>) -> Result<()> {
        let mut health = self.shared.store.health.subscribe();
        loop {
            let deadline = self.deadline();
            tokio::select! {
                command=rx.recv()=>match command { Some(command)=> { match self.command(command).await { Ok(true)=>return Ok(()),Ok(false)=>{},Err(_)=>self.shared.fence("Private owner command failed") } },None=> { self.shared.stop();for group in self.groups.values_mut() { group.connections.clear(); }self.reap_empty().await?;return Ok(()); } },
                _=self.shared.maintenance.notified()=>{},
                _=self.shared.store.private_wake.notified()=> { for group in self.groups.values_mut() { group.next_claim=Instant::now();group.route_dirty=true; } },
                changed=health.changed(),if !self.shared.stopping.load(Ordering::Acquire)=> { if changed.is_ok() { self.shared.stop(); } },
                _=tokio::time::sleep_until(deadline),if !self.groups.is_empty()=>{},
            }
            if self.service().await.is_err() {
                self.shared
                    .fence("Private owner database or payload failure");
            }
        }
    }
}
fn id() -> String {
    format!("{:032x}", rand::random::<u128>())
}
pub(crate) fn encode_payload(canonical: &[u8]) -> Result<Bytes> {
    let object: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(canonical)?;
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
    .map(Bytes::from)
    .map_err(|_| KernelError::Invalid("Private postcard payload encoding failed".into()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use pushgo_warp_profile::PrivatePayloadEnvelope;
    #[test]
    fn canonical_payload_uses_public_profile_and_preserves_fields() {
        let raw=br#"{"message_id":"m","channel_id":"c","ttl":123,"base_url":"https://example.test","first":"1","images":["a"]}"#;
        let bytes = encode_payload(raw).unwrap();
        let decoded: PrivatePayloadEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload_version, 1);
        assert_eq!(decoded.data["ttl"], "123");
        assert_eq!(decoded.data["first"], "1");
        assert_eq!(decoded.data["images"], r#"["a"]"#);
        assert_eq!(decoded.data["base_url"], "https://example.test");
    }
    #[test]
    fn small_budget_is_independent_of_provider_h32() {
        let c = PrivateRuntimeConfig::default();
        assert_eq!(
            (c.max_connections, c.window, c.owned_slots),
            (8192, 96, 4096)
        );
    }
}
