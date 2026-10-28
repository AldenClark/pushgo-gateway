//! TASK-ONLY cross-repository integration. Production Warp handoff/receive/ACK
//! functions call the actual Gateway app over loopback WebSocket frames. Only
//! fixture visibility and these tests are added to the temporary source overlay.
//! This is not the TLS connector, a platform app, or the outer reconnect loop.
use super::*;
use pushgo_gateway::private::warp_engine::{default_server_config, handoff_fixture::Product};
use pushgo_warp_profile::PushgoWireProfile;
use sqlx::SqlitePool;
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::TcpStream,
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tokio_tungstenite::{MaybeTlsStream, accept_async, client_async};
use warp_link_core::{DeliverMsg, WelcomeMsg, WireProfile};

const DEVICE: &str = "handoff-wire-device";
const BOUND: Duration = Duration::from_secs(3);

struct Gate {
    released: Mutex<bool>,
    ready: Condvar,
    entered: Notify,
}
impl Gate {
    fn new() -> Self {
        Self {
            released: Mutex::new(false),
            ready: Condvar::new(),
            entered: Notify::new(),
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.ready.notify_all();
    }
    fn wait(&self) -> bool {
        self.entered.notify_one();
        let released = self.released.lock().unwrap();
        let (released, _) = self
            .ready
            .wait_timeout_while(released, BOUND, |value| !*value)
            .unwrap();
        *released
    }
}
struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct App {
    database: SqlitePool,
    runtime: tokio::runtime::Handle,
    saved: Mutex<Vec<(String, Option<u64>)>>,
    attempts: Mutex<Vec<(String, Option<u64>)>>,
    gate: Option<Arc<Gate>>,
    active: AtomicUsize,
    maximum_active: AtomicUsize,
}
impl App {
    async fn open(product: &Product, gate: Option<Arc<Gate>>) -> Arc<Self> {
        let database = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!(
                "sqlite://{}?mode=rwc",
                product
                    .directory
                    .path()
                    .join("combined-client.db")
                    .display()
            ))
            .await
            .unwrap();
        sqlx::query("CREATE TABLE client_messages(delivery_id TEXT PRIMARY KEY,seq INTEGER,payload BLOB NOT NULL)")
            .execute(&database).await.unwrap();
        Arc::new(Self {
            database,
            runtime: tokio::runtime::Handle::current(),
            saved: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
            gate,
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
        })
    }
    fn saved_ids(&self) -> Vec<String> {
        self.saved
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }
    async fn durable_rows(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM client_messages")
            .fetch_one(&self.database)
            .await
            .unwrap()
    }
}
impl ClientApp for App {
    fn on_hello(&self) -> HelloCtx {
        HelloCtx {
            identity: DEVICE.into(),
            supported_wire_versions: vec![2],
            supported_payload_versions: vec![1],
            ..HelloCtx::default()
        }
    }
    fn on_event(&self, event: ClientEvent) -> AppDecision {
        let ClientEvent::Message { msg, .. } = event else {
            return AppDecision::AckOk;
        };
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum_active.fetch_max(active, Ordering::SeqCst);
        self.attempts
            .lock()
            .unwrap()
            .push((msg.id.clone(), msg.seq));
        let permitted = msg.seq != Some(8) || self.gate.as_ref().is_none_or(|gate| gate.wait());
        let saved = if permitted {
            self.runtime.block_on(async {
                let mut tx = self.database.begin().await?;
                let inserted = sqlx::query("INSERT INTO client_messages(delivery_id,seq,payload) VALUES(?,?,?) ON CONFLICT(delivery_id) DO NOTHING")
                    .bind(&msg.id).bind(msg.seq.map(|n| n as i64)).bind(msg.payload.as_ref()).execute(&mut *tx).await?.rows_affected();
                let original: Vec<u8> = sqlx::query_scalar("SELECT payload FROM client_messages WHERE delivery_id=?")
                    .bind(&msg.id).fetch_one(&mut *tx).await?;
                assert_eq!(original.as_slice(), msg.payload.as_ref(), "a replay must retain the original payload");
                tx.commit().await?;
                Ok::<_, sqlx::Error>(inserted > 0)
            })
        } else {
            Err(sqlx::Error::Protocol(
                "bounded callback gate was not released".into(),
            ))
        };
        self.active.fetch_sub(1, Ordering::SeqCst);
        match saved {
            Ok(inserted) => {
                if inserted {
                    self.saved.lock().unwrap().push((msg.id, msg.seq));
                }
                AppDecision::AckOk
            }
            Err(error) => {
                eprintln!(
                    "COMBINED_CLIENT_SAVE_REJECTED seq={:?} error={error}",
                    msg.seq
                );
                AppDecision::RetryLater
            }
        }
    }
}

type ConcreteServerIo = WsServerIo<TungsteniteWsIo<TcpStream>>;
struct ObservedServer {
    inner: ConcreteServerIo,
    written: mpsc::Sender<(TransportKind, Option<u64>, String)>,
    transport: TransportKind,
}
#[async_trait]
impl ServerSessionIo for ObservedServer {
    async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), WarpLinkError> {
        self.inner.send_frame(bytes).await?;
        if let DecodedServerFrame::Deliver(msg) = PushgoWireProfile.decode_server_frame(bytes)? {
            self.written
                .try_send((self.transport, msg.seq, msg.id))
                .expect("bounded nine-message observation capacity");
        }
        Ok(())
    }
    async fn recv_frame(&mut self, wait: u64) -> Result<Vec<u8>, WarpLinkError> {
        self.inner.recv_frame(wait).await
    }
}

async fn pair(
    product: &Product,
    transport: TransportKind,
    written: mpsc::Sender<(TransportKind, Option<u64>, String)>,
) -> (ClientIo, JoinHandle<Result<(), WarpLinkError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(
        async {
            let socket = TcpStream::connect(address).await.unwrap();
            client_async(
                format!("ws://{address}/private/ws"),
                MaybeTlsStream::Plain(socket),
            )
            .await
            .unwrap()
            .0
        },
        async {
            let (socket, _) = listener.accept().await.unwrap();
            accept_async(socket).await.unwrap()
        }
    );
    let mut server = ObservedServer {
        inner: WsServerIo {
            inner: TungsteniteWsIo {
                ws: server,
                remote_addr: Some(address.to_string()),
                max_frame_bytes: TRANSPORT_MAX_FRAME_BYTES as usize,
            },
            write_timeout_ms: 1000,
        },
        written,
        transport,
    };
    let app: Arc<dyn ServerApp> = product.app.clone();
    let server_task = tokio::spawn(async move {
        run_server_session(
            &default_server_config(),
            app,
            &mut server,
            PeerMeta {
                transport,
                remote_addr: Some(address.to_string()),
            },
        )
        .await
    });
    (
        ClientIo::Wss {
            stream: Box::new(client),
        },
        server_task,
    )
}

struct Session {
    config: ClientConfig,
    app: Arc<App>,
    continuity: ClientContinuityState,
    power: ClientPowerRuntime,
    transport: TransportKind,
    io: ClientIo,
    pending_ping_sent_at: Option<Instant>,
    pending_ping_source: Option<ProbeRttSource>,
    health_tracker: HealthTracker,
    mobility_tracker: MobilityTracker,
}
impl Session {
    async fn open(
        product: &Product,
        app: Arc<App>,
        written: mpsc::Sender<(TransportKind, Option<u64>, String)>,
    ) -> (Self, JoinHandle<Result<(), WarpLinkError>>, WelcomeMsg) {
        let (mut io, server) = pair(product, TransportKind::Tcp, written).await;
        let mut config = super::tests::sample_client_config();
        config.wire_profile = Arc::new(PushgoWireProfile);
        config.policy.scheduler_v2_enabled = true;
        config.policy.connect_timeout_ms = 2000;
        config.policy.drain_timeout_ms = 2000;
        config.policy.cutover_guard_ms = 1000;
        config.policy.write_timeout_ms = 1000;
        let mut continuity = ClientContinuityState::default();
        let mut hello = app.on_hello();
        continuity.apply_to_hello(&mut hello);
        io.send_frame(
            &config.wire_profile.encode_client_hello(&hello).unwrap(),
            1000,
        )
        .await
        .unwrap();
        let bytes = io.recv_frame(2000).await.unwrap();
        let DecodedServerFrame::Welcome(welcome) =
            config.wire_profile.decode_server_frame(&bytes).unwrap()
        else {
            panic!("actual Gateway WELCOME");
        };
        validate_welcome_negotiation(&hello, &welcome).unwrap();
        continuity.note_session_welcome(&welcome);
        assert!(continuity.handoff_supported);
        (
            Self {
                config,
                app,
                continuity,
                power: ClientPowerRuntime::new(Instant::now()),
                transport: TransportKind::Tcp,
                io,
                pending_ping_sent_at: None,
                pending_ping_source: None,
                health_tracker: HealthTracker::new(Instant::now()),
                mobility_tracker: MobilityTracker::new(Instant::now(), false),
            },
            server,
            welcome,
        )
    }
    async fn handle(&mut self, bytes: Vec<u8>) -> Result<(), WarpLinkError> {
        handle_primary_frame(
            &self.config,
            self.app.clone(),
            self.transport,
            bytes,
            PrimaryFrameState {
                continuity: &mut self.continuity,
                power_runtime: &mut self.power,
                io: &mut self.io,
                pending_ping_sent_at: &mut self.pending_ping_sent_at,
                pending_ping_source: &mut self.pending_ping_source,
                health_tracker: &mut self.health_tracker,
                mobility_tracker: &mut self.mobility_tracker,
            },
        )
        .await
    }
    async fn delivery(&mut self) -> Result<DeliverMsg, WarpLinkError> {
        for _ in 0..16 {
            let bytes = self.io.recv_frame(2000).await?;
            let decoded = self.config.wire_profile.decode_server_frame(&bytes)?;
            let message = match decoded {
                DecodedServerFrame::Deliver(message) => Some(message),
                _ => None,
            };
            self.handle(bytes).await?;
            if let Some(message) = message {
                return Ok(message);
            }
        }
        panic!("bounded control frames cannot conceal a delivery");
    }
    async fn fence(&mut self) {
        self.io
            .send_frame(&self.config.wire_profile.encode_client_ping(), 1000)
            .await
            .unwrap();
        for _ in 0..16 {
            let bytes = self.io.recv_frame(2000).await.unwrap();
            if matches!(
                self.config
                    .wire_profile
                    .decode_server_frame(&bytes)
                    .unwrap(),
                DecodedServerFrame::Pong
            ) {
                return;
            }
            self.handle(bytes).await.unwrap();
        }
        panic!("bounded explicit-ACK fence");
    }
    async fn cutover(&mut self, candidate: ClientIo) -> Result<Option<WelcomeMsg>, WarpLinkError> {
        commit_candidate_cutover(
            &self.config,
            self.app.clone(),
            ActiveTransport {
                continuity: &mut self.continuity,
                power_runtime: &mut self.power,
                transport: &mut self.transport,
                io: &mut self.io,
            },
            TransportKind::Wss,
            candidate,
            77,
            PrimaryProgress {
                pending_ping_sent_at: &mut self.pending_ping_sent_at,
                pending_ping_source: &mut self.pending_ping_source,
                health_tracker: &mut self.health_tracker,
                mobility_tracker: &mut self.mobility_tracker,
            },
        )
        .await
    }
}

async fn warmup(product: &Product, session: &mut Session) {
    for seq in 1..=7 {
        let id = product.accept(&format!("combined-warmup-{seq}")).await;
        let delivered = session.delivery().await.unwrap();
        assert_eq!(delivered.id, id);
        assert_eq!(delivered.seq, Some(seq));
    }
    session.fence().await;
}
async fn written_sequence(
    receiver: &mut mpsc::Receiver<(TransportKind, Option<u64>, String)>,
    expected: u64,
) -> String {
    timeout(BOUND, async {
        while let Some((_, seq, id)) = receiver.recv().await {
            if seq == Some(expected) {
                return id;
            }
        }
        panic!("owned server observation channel closed");
    })
    .await
    .expect("real server write must reach bounded barrier")
}
async fn joined(task: JoinHandle<Result<(), WarpLinkError>>) {
    let _ = timeout(BOUND, task)
        .await
        .expect("owned server session must stop")
        .expect("server task did not panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_gateway_and_warp_handoff_preserves_persistence_order_and_no_early_terminal() {
    let product = Product::open().await;
    let gate = Arc::new(Gate::new());
    let _release_on_failure = ReleaseOnDrop(gate.clone());
    let app = App::open(&product, Some(gate.clone())).await;
    let (written, mut writes) = mpsc::channel(32);
    let (mut session, primary_server, _) =
        Session::open(&product, app.clone(), written.clone()).await;
    warmup(&product, &mut session).await;
    let eight = product.accept("combined-eight").await;
    assert_eq!(written_sequence(&mut writes, 8).await, eight);
    let (candidate, candidate_server) = pair(&product, TransportKind::Wss, written).await;
    let nine;
    {
        let handoff = session.cutover(candidate);
        tokio::pin!(handoff);
        timeout(BOUND, async { tokio::select! {
        result = &mut handoff => panic!("handoff ended before old8 persistence barrier: {result:?}"),
        _ = gate.entered.notified() => {}
    }}).await.expect("old8 callback must start during handoff");
        nine = product.accept("combined-nine").await;
        assert_eq!(product.snapshot(&eight).await.0, 1);
        assert_eq!(product.snapshot(&nine).await.0, 1);
        assert_eq!(
            app.durable_rows().await,
            7,
            "neither8 nor9 persisted while8 callback is held"
        );
        gate.release();
        assert!(
            timeout(BOUND, &mut handoff)
                .await
                .unwrap()
                .unwrap()
                .is_some()
        );
    }
    timeout(BOUND, async {
        while app.saved_ids().len() < 9 {
            session.delivery().await.unwrap();
        }
    })
    .await
    .expect("remaining candidate work has one bounded completion deadline");
    session.fence().await;
    assert_eq!(&app.saved_ids()[7..], &[eight.clone(), nine.clone()]);
    assert_eq!(app.maximum_active.load(Ordering::SeqCst), 1);
    assert_eq!(product.snapshot(&eight).await, (0, 0));
    assert_eq!(product.snapshot(&nine).await, (0, 0));
    assert_eq!(app.durable_rows().await, 9);
    eprintln!(
        "COMBINED_REAL saved_order=[8,9] max_callback_owners=1 held_callback_rows=7 no_early_terminal=true final_bodies=[0,0]"
    );
    drop(session);
    joined(primary_server).await;
    joined(candidate_server).await;
    app.database.close().await;
    product.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_gateway_and_warp_failed_old_persistence_replays_after_interrupted_handoff() {
    let product = Product::open().await;
    let app = App::open(&product, None).await;
    let (written, mut writes) = mpsc::channel(32);
    let (mut session, primary_server, _) =
        Session::open(&product, app.clone(), written.clone()).await;
    warmup(&product, &mut session).await;
    sqlx::query("CREATE TRIGGER reject_eight BEFORE INSERT ON client_messages WHEN NEW.seq=8 BEGIN SELECT RAISE(ABORT,'injected old8 persistence failure'); END")
        .execute(&app.database).await.unwrap();
    let eight = product.accept("combined-failed-eight").await;
    assert_eq!(written_sequence(&mut writes, 8).await, eight);
    let nine = product.accept("combined-held-nine").await;
    let (candidate, candidate_server) = pair(&product, TransportKind::Wss, written.clone()).await;
    assert!(
        session.cutover(candidate).await.is_err(),
        "RetryLater must abort ownership transfer"
    );
    assert_eq!(product.snapshot(&eight).await.0, 1);
    assert_eq!(product.snapshot(&nine).await.0, 1);
    assert!(product.snapshot(&eight).await.1 > 0 && product.snapshot(&nine).await.1 > 0);
    assert_eq!(app.durable_rows().await, 7);
    drop(session);
    joined(primary_server).await;
    joined(candidate_server).await;
    sqlx::query("DROP TRIGGER reject_eight")
        .execute(&app.database)
        .await
        .unwrap();
    let (mut recovered, recovery_server, _) = Session::open(&product, app.clone(), written).await;
    let first = recovered.delivery().await.unwrap();
    let second = recovered.delivery().await.unwrap();
    assert_ne!(first.id, second.id);
    assert!(
        [eight.clone(), nine.clone()].contains(&first.id)
            && [eight.clone(), nine.clone()].contains(&second.id)
    );
    // A fresh resume token defines a fresh transport sequence scope. Durable
    // identities, payloads and explicit ACKs survive, not an inferred seq+1.
    recovered.fence().await;
    assert_eq!(app.durable_rows().await, 9);
    assert_eq!(app.maximum_active.load(Ordering::SeqCst), 1);
    assert_eq!(product.snapshot(&eight).await, (0, 0));
    assert_eq!(product.snapshot(&nine).await, (0, 0));
    eprintln!(
        "COMBINED_REAL_SAVE_FAILURE pending_before_recovery=[8,9] persisted_rows_before=7 final_unique_rows=9 exact_ack_only=true fresh_sequence_scope=true"
    );
    drop(recovered);
    joined(recovery_server).await;
    app.database.close().await;
    product.stop().await;
}
