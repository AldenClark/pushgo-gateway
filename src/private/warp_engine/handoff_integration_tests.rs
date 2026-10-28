//! Real loopback frames through Warp's server engine and PushgoServerApp,
//! using the ordinary product SQLite authority. The peer deliberately withholds
//! an ACK when its separate synthetic client database rejects persistence.
//! This is not a TLS, Android/Windows runtime or external Provider test.
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use pushgo_warp_profile::PushgoWireProfile;
use sqlx::{Connection, SqliteConnection};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use warp_link::{
    ServerSessionIo,
    warp_link_core::{
        AckMsg, AckStatus, AuthCheckPhase, AuthRequest, AuthResponse, DecodedClientFrame,
        DecodedServerFrame, DeliverMsg, DisconnectReason, HelloCtx, PeerMeta, ServerApp,
        SessionCtx, TransportKind, WarpLinkError, WelcomeMsg, WireProfile,
    },
    warp_link_transport::{FramedReader, write_prefixed_frame},
};

use super::PushgoServerApp;
use crate::{
    ordinary::{
        AcceptRequest, Config, OrdinaryStore,
        owner::ProductOwner,
        private_model::PrivateLedgerConfig,
        store::{Health, now},
    },
    private::{PrivateConfig, PrivateState},
    routing::DeviceRegistry,
    runtime_config::GatewayRuntimeProfile,
    runtime_counters::RuntimeCounterCollector,
    storage::{
        DeviceRouteRecordRow, MaintenanceCleanupConfig, PrivateDeviceId, Storage, StorageInitConfig,
    },
};

const DEVICE: &str = "handoff-wire-device";

struct Product {
    directory: tempfile::TempDir,
    storage: Storage,
    ordinary: OrdinaryStore,
    owner: ProductOwner,
    state: Arc<PrivateState>,
    app: Arc<PushgoServerApp>,
    channel: [u8; 16],
    client_db: SqliteConnection,
}

impl Product {
    async fn open() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("product.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url),
            mcp_enabled: false,
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let ordinary = storage
            .initialize_ordinary(
                Config {
                    private: PrivateLedgerConfig {
                        enabled: true,
                        ..PrivateLedgerConfig::default()
                    },
                    ..Config::default()
                },
                health,
            )
            .await
            .unwrap();
        let channel = storage
            .upsert_private_channel(
                None,
                Some("handoff synthetic"),
                &crate::util::generate_hex_id_128(),
            )
            .await
            .unwrap()
            .channel_id;
        storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: DEVICE.into(),
                platform: "windows".into(),
                channel_type: "private".into(),
                provider_token: None,
                updated_at: now(),
            })
            .await
            .unwrap();
        storage
            .private_subscribe_channel(channel, PrivateDeviceId::derive(DEVICE).into())
            .await
            .unwrap();
        let state = state(&storage);
        let app = Arc::new(PushgoServerApp::new(state.clone()));
        let mut client_db = SqliteConnection::connect(&format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("client.db").display()
        ))
        .await
        .unwrap();
        sqlx::query("CREATE TABLE saved(delivery_id TEXT PRIMARY KEY,payload BLOB NOT NULL)")
            .execute(&mut client_db)
            .await
            .unwrap();
        Self {
            directory,
            storage,
            ordinary,
            owner,
            state,
            app,
            channel,
            client_db,
        }
    }

    async fn accept(&self, operation: &str) -> String {
        self.ordinary
            .accept(AcceptRequest {
                channel_id: crate::value::ChannelId::from(self.channel).to_string(),
                authorized_channel: Some(self.channel),
                op_id: Some(operation.into()),
                title: format!("synthetic {operation}"),
                body: Some("durable body".into()),
                ..AcceptRequest::default()
            })
            .await
            .unwrap()
            .delivery_id
    }

    async fn connect(&self, resume: Option<&str>, maximum: Option<u64>) -> (Peer, WelcomeMsg) {
        self.connect_with_fault(resume, maximum, None).await
    }

    async fn connect_with_fault(
        &self,
        resume: Option<&str>,
        maximum: Option<u64>,
        drop_ack: Option<Arc<DropAck>>,
    ) -> (Peer, WelcomeMsg) {
        self.connect_on_transport(resume, maximum, drop_ack, TransportKind::Tcp)
            .await
    }

    async fn connect_on_transport(
        &self,
        resume: Option<&str>,
        maximum: Option<u64>,
        drop_ack: Option<Arc<DropAck>>,
        transport: TransportKind,
    ) -> (Peer, WelcomeMsg) {
        self.connect_metadata(resume, maximum, drop_ack, transport, BTreeMap::new())
            .await
    }

    async fn connect_metadata(
        &self,
        resume: Option<&str>,
        maximum: Option<u64>,
        drop_ack: Option<Arc<DropAck>>,
        transport: TransportKind,
        metadata: BTreeMap<String, String>,
    ) -> (Peer, WelcomeMsg) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (read, write) = tokio::io::split(server);
        let mut io = Frames {
            reader: FramedReader::new(read),
            writer: write,
            drop_ack,
        };
        let app: Arc<dyn ServerApp> = self.app.clone();
        let task = tokio::spawn(async move {
            warp_link::run_server_session(
                &super::default_server_config(),
                app,
                &mut io,
                PeerMeta {
                    transport,
                    remote_addr: Some("loopback synthetic".into()),
                },
            )
            .await
        });
        let (read, write) = tokio::io::split(socket);
        let mut peer = Peer {
            reader: FramedReader::new(read),
            writer: write,
            task,
        };
        peer.send(
            &PushgoWireProfile
                .encode_client_hello(&HelloCtx {
                    identity: DEVICE.into(),
                    resume_token: resume.map(str::to_owned),
                    last_acked_seq: maximum,
                    supported_wire_versions: vec![2],
                    supported_payload_versions: vec![1],
                    metadata,
                    ..HelloCtx::default()
                })
                .unwrap(),
        )
        .await;
        let DecodedServerFrame::Welcome(welcome) = peer.receive().await else {
            panic!("actual Gateway must send WELCOME");
        };
        (peer, welcome)
    }

    async fn snapshot(&self, id: &str) -> (i64, i64) {
        let mut inspect = SqliteConnection::connect(&format!(
            "sqlite://{}?mode=ro",
            self.directory.path().join("product.db").display()
        ))
        .await
        .unwrap();
        sqlx::query_as("SELECT (SELECT COUNT(*) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id AND t.device_key=? AND t.acked_at IS NULL),m.payload_bytes FROM ordinary_messages m WHERE m.delivery_id=?")
            .bind(DEVICE).bind(id).fetch_one(&mut inspect).await.unwrap()
    }

    async fn save(&mut self, message: &DeliverMsg) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO saved(delivery_id,payload) VALUES(?,?) ON CONFLICT(delivery_id) DO NOTHING")
            .bind(&message.id).bind(message.payload.as_ref()).execute(&mut self.client_db).await?;
        Ok(())
    }

    async fn reopen_server_storage_and_session_owner(&mut self) {
        let report = self.state.shutdown_runtime(Duration::from_secs(1)).await;
        assert_eq!(report.failed, 0);
        self.storage.close_ordinary_storage().await.unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(format!(
                "sqlite://{}?mode=rwc",
                self.directory.path().join("product.db").display()
            )),
            mcp_enabled: false,
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        self.ordinary = storage
            .initialize_ordinary(
                Config {
                    private: PrivateLedgerConfig {
                        enabled: true,
                        ..PrivateLedgerConfig::default()
                    },
                    ..Config::default()
                },
                Arc::new(Health::default()),
            )
            .await
            .unwrap();
        self.state = state(&storage);
        self.app = Arc::new(PushgoServerApp::new(self.state.clone()));
        self.storage = storage;
    }

    async fn stop(self) {
        let shutdown = self.state.shutdown_runtime(Duration::from_secs(1)).await;
        assert_eq!(shutdown.failed, 0);
        self.storage.close_ordinary_storage().await.unwrap();
        self.owner.shutdown().await.unwrap();
    }
}

fn state(storage: &Storage) -> Arc<PrivateState> {
    Arc::new(PrivateState::new(
        storage.clone(),
        config(),
        Arc::new(DeviceRegistry::new()),
        RuntimeCounterCollector::spawn_with_mode(
            storage.clone(),
            false,
            GatewayRuntimeProfile::Small,
        ),
    ))
}

fn config() -> PrivateConfig {
    PrivateConfig {
        runtime_profile: GatewayRuntimeProfile::Small,
        private_quic_bind: None,
        private_tcp_bind: None,
        mqtt: None,
        tcp_tls_enabled: false,
        tcp_proxy_protocol: false,
        private_tls_cert_path: None,
        private_tls_key_path: None,
        session_ttl_secs: 60,
        grace_window_secs: 10,
        max_pending_per_device: 32,
        global_max_pending: 64,
        pull_limit: 32,
        ack_timeout_secs: 5,
        fallback_max_attempts: 3,
        fallback_max_backoff_secs: 60,
        retransmit_window_secs: 30,
        retransmit_max_per_window: 10,
        retransmit_max_per_tick: 16,
        retransmit_max_retries: 3,
        hot_cache_capacity: 64,
        default_ttl_secs: 60,
        online_fast_path_enabled: false,
        maintenance_cleanup: MaintenanceCleanupConfig::default(),
        gateway_token: None,
    }
    .normalized()
}

struct Frames {
    reader: FramedReader<ReadHalf<TcpStream>>,
    writer: WriteHalf<TcpStream>,
    drop_ack: Option<Arc<DropAck>>,
}

struct DropAck {
    delivery_id: String,
    count: AtomicUsize,
}
#[async_trait]
impl ServerSessionIo for Frames {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        write_prefixed_frame(&mut self.writer, frame).await
    }
    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        timeout(Duration::from_millis(timeout_ms), async {
            loop {
                let frame = self.reader.read_frame().await?;
                if let Some(drop_ack) = &self.drop_ack
                    && let Ok(DecodedClientFrame::Ack(ack)) =
                        PushgoWireProfile.decode_client_frame(&frame)
                    && ack.id == drop_ack.delivery_id
                    && drop_ack.count.fetch_add(1, Ordering::SeqCst) == 0
                {
                    // The peer completed its actual socket write. Drop exactly
                    // this ACK at the wire adapter, before production decoding.
                    continue;
                }
                return Ok(frame);
            }
        })
        .await
        .map_err(|_| WarpLinkError::Timeout("synthetic read bound".into()))?
    }
}

struct Peer {
    reader: FramedReader<ReadHalf<TcpStream>>,
    writer: WriteHalf<TcpStream>,
    task: JoinHandle<Result<(), WarpLinkError>>,
}
impl Peer {
    async fn send(&mut self, frame: &[u8]) {
        write_prefixed_frame(&mut self.writer, frame).await.unwrap();
    }
    async fn receive(&mut self) -> DecodedServerFrame {
        let bytes = timeout(Duration::from_secs(3), self.reader.read_frame())
            .await
            .expect("bounded actual wire frame")
            .unwrap();
        PushgoWireProfile.decode_server_frame(&bytes).unwrap()
    }
    async fn delivery(&mut self) -> DeliverMsg {
        loop {
            match self.receive().await {
                DecodedServerFrame::Deliver(delivery) => return delivery,
                DecodedServerFrame::Ping => {
                    self.send(&PushgoWireProfile.encode_client_pong()).await
                }
                other => panic!("unexpected wire frame: {other:?}"),
            }
        }
    }
    async fn acknowledge(&mut self, delivery: &DeliverMsg) {
        self.send(
            &PushgoWireProfile
                .encode_client_ack(&AckMsg {
                    seq: delivery.seq,
                    id: delivery.id.clone(),
                    status: AckStatus::Ok,
                })
                .unwrap(),
        )
        .await;
    }
    async fn transition(
        &mut self,
        welcome: &WelcomeMsg,
        phase: &str,
        peer: &str,
        id: &str,
    ) -> WelcomeMsg {
        self.send(
            &PushgoWireProfile
                .encode_client_hello(&HelloCtx {
                    identity: DEVICE.into(),
                    resume_token: welcome.resume_token.clone(),
                    supported_wire_versions: vec![2],
                    supported_payload_versions: vec![1],
                    metadata: handoff_metadata(Some((phase, peer, id))),
                    ..HelloCtx::default()
                })
                .unwrap(),
        )
        .await;
        let DecodedServerFrame::Welcome(reply) = self.receive().await else {
            panic!("handoff phase {phase} must produce its own authenticated WELCOME barrier");
        };
        reply
    }
    async fn fence(&mut self) {
        self.send(&PushgoWireProfile.encode_client_ping()).await;
        assert!(
            matches!(self.receive().await, DecodedServerFrame::Pong),
            "PING/PONG fences preceding exact ACK processing only, not cross-stream drain"
        );
    }
    async fn close(self) {
        let Peer {
            reader,
            writer,
            mut task,
        } = self;
        drop(reader);
        drop(writer);
        let _ = timeout(Duration::from_secs(3), &mut task)
            .await
            .expect("owned server must stop");
    }
}

fn handoff_metadata(phase: Option<(&str, &str, &str)>) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([("wl_handoff".into(), "1".into())]);
    if let Some((phase, peer, id)) = phase {
        metadata.insert("wl_handoff_phase".into(), phase.into());
        metadata.insert("wl_handoff_peer".into(), peer.into());
        metadata.insert("wl_handoff_id".into(), id.into());
    }
    metadata
}

fn assert_handoff_reply(reply: &WelcomeMsg, phase: &str, peer: &str, id: &str) {
    assert_eq!(
        reply.metadata.get("wl_handoff").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        reply.metadata.get("wl_handoff_phase").map(String::as_str),
        Some(phase)
    );
    assert_eq!(
        reply.metadata.get("wl_handoff_peer").map(String::as_str),
        Some(peer)
    );
    assert_eq!(
        reply.metadata.get("wl_handoff_id").map(String::as_str),
        Some(id)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_resume_maximum_cannot_ack_failed_lower_message_in_product_ledger() {
    let mut product = Product::open().await;
    let (mut peer, welcome) = product.connect(None, None).await;
    let mut failed = None;
    for sequence in 1..=9_u64 {
        let accepted = product.accept(&format!("wire-handoff-{sequence}")).await;
        let delivered = peer.delivery().await;
        assert_eq!(delivered.id, accepted);
        assert_eq!(delivered.seq, Some(sequence));
        if sequence == 8 {
            sqlx::query("CREATE TRIGGER reject_save BEFORE INSERT ON saved BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END").execute(&mut product.client_db).await.unwrap();
            assert!(product.save(&delivered).await.is_err());
            sqlx::query("DROP TRIGGER reject_save")
                .execute(&mut product.client_db)
                .await
                .unwrap();
            failed = Some(delivered);
        } else {
            product.save(&delivered).await.unwrap();
            peer.acknowledge(&delivered).await;
        }
    }
    peer.fence().await;
    let failed = failed.unwrap();
    let before = product.snapshot(&failed.id).await;
    assert!(before.0 == 1 && before.1 > 0);
    // Keep the primary alive: a complete offline disconnect legitimately
    // releases its ordinary claim and would conceal the live handoff bug.
    // Only the production peer transport tag differs here; both test sockets
    // are prefixed loopback TCP, not a WSS/TLS transport validation.
    let (mut resumed, _) = product
        .connect_on_transport(
            welcome.resume_token.as_deref(),
            Some(9),
            None,
            TransportKind::Wss,
        )
        .await;
    let after = product.snapshot(&failed.id).await;
    eprintln!(
        "HANDOFF_WIRE_LEDGER before={before:?} after={after:?} failed_client_save=true HELLO_max=9 explicit_ack_8=false"
    );
    assert!(
        after.0 == 1 && after.1 > 0,
        "unpersisted sequence8 must remain pending with its original body; only exact ACK9 succeeded"
    );
    let replay = resumed.delivery().await;
    assert_eq!(replay.id, failed.id);
    product.save(&replay).await.unwrap();
    resumed.acknowledge(&replay).await;
    resumed.fence().await;
    let terminal = product.snapshot(&failed.id).await;
    assert_eq!(terminal.0, 0);
    assert_eq!(
        terminal.1, 0,
        "body release follows actual successful persistence and exact ACK"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM saved")
        .fetch_one(&mut product.client_db)
        .await
        .unwrap();
    assert_eq!(count, 9);
    peer.close().await;
    resumed.close().await;
    product.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_ack_loss_reopens_product_storage_and_replays_without_duplicate_business_row() {
    let mut product = Product::open().await;
    let id = product.accept("wire-persisted-ack-lost").await;
    let dropped = Arc::new(DropAck {
        delivery_id: id.clone(),
        count: AtomicUsize::new(0),
    });
    let (mut peer, welcome) = product
        .connect_with_fault(None, None, Some(dropped.clone()))
        .await;
    let delivery = peer.delivery().await;
    assert_eq!(delivery.id, id);
    product.save(&delivery).await.unwrap();
    peer.acknowledge(&delivery).await;
    peer.fence().await;
    assert_eq!(dropped.count.load(Ordering::SeqCst), 1);
    let pending = product.snapshot(&id).await;
    assert!(pending.0 == 1 && pending.1 > 0);
    peer.close().await;
    product.reopen_server_storage_and_session_owner().await;
    let (mut resumed, _) = product
        .connect(welcome.resume_token.as_deref(), delivery.seq)
        .await;
    let replay = resumed.delivery().await;
    assert_eq!(replay.id, id);
    assert_eq!(replay.payload, delivery.payload);
    product.save(&replay).await.unwrap();
    resumed.acknowledge(&replay).await;
    resumed.fence().await;
    let terminal = product.snapshot(&id).await;
    assert_eq!(terminal.0, 0);
    assert_eq!(terminal.1, 0);
    // The exact duplicate ACK is harmless, even after the original capability
    // left the volatile inflight map. It cannot select any other target.
    resumed.acknowledge(&replay).await;
    resumed.fence().await;
    assert_eq!(product.snapshot(&id).await, terminal);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM saved")
        .fetch_one(&mut product.client_db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    eprintln!(
        "HANDOFF_WIRE_ACK_LOSS actual_dropped_ack=1 storage_reopened=true replay_same_identity=true client_rows=1 terminal={terminal:?}"
    );
    resumed.close().await;
    product.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_staged_handoff_replays_failed_old_delivery_before_fresh_work() {
    let mut product = Product::open().await;
    let (mut primary, old_welcome) = product
        .connect_metadata(None, None, None, TransportKind::Tcp, handoff_metadata(None))
        .await;
    assert_eq!(
        old_welcome.metadata.get("wl_handoff").map(String::as_str),
        Some("1")
    );
    let id = "handoffwireprepared01";
    let (mut candidate, candidate_welcome) = product
        .connect_metadata(
            old_welcome.resume_token.as_deref(),
            Some(9),
            None,
            TransportKind::Wss,
            handoff_metadata(Some(("prepare", &old_welcome.session_id, id))),
        )
        .await;
    assert_handoff_reply(&candidate_welcome, "prepared", &old_welcome.session_id, id);
    // A passive candidate responds to control traffic but cannot consume work.
    candidate.fence().await;
    let failed_id = product.accept("staged-old-save-failure").await;
    let failed = primary.delivery().await;
    assert_eq!(failed.id, failed_id);
    sqlx::query("CREATE TRIGGER reject_save BEFORE INSERT ON saved BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END").execute(&mut product.client_db).await.unwrap();
    assert!(product.save(&failed).await.is_err());
    sqlx::query("DROP TRIGGER reject_save")
        .execute(&mut product.client_db)
        .await
        .unwrap();
    primary.fence().await;
    let before = product.snapshot(&failed_id).await;
    assert!(before.0 == 1 && before.1 > 0);

    let drained = primary
        .transition(&old_welcome, "freeze", &candidate_welcome.session_id, id)
        .await;
    assert_handoff_reply(&drained, "drained", &candidate_welcome.session_id, id);
    let fresh_id = product.accept("staged-new-after-drain").await;
    // Fresh work must not leak out on a prepared candidate before activation.
    candidate.fence().await;
    let active = candidate
        .transition(&candidate_welcome, "activate", &old_welcome.session_id, id)
        .await;
    assert_handoff_reply(&active, "active", &old_welcome.session_id, id);
    let replay = candidate.delivery().await;
    assert_eq!(
        replay.id, failed_id,
        "snapshot after the old allocation barrier must replay the failed old identity before fresh work"
    );
    assert_eq!(replay.seq, failed.seq);
    assert_eq!(replay.payload, failed.payload);
    product.save(&replay).await.unwrap();
    candidate.acknowledge(&replay).await;
    let fresh = candidate.delivery().await;
    assert_eq!(fresh.id, fresh_id);
    assert!(fresh.seq > replay.seq);
    product.save(&fresh).await.unwrap();
    candidate.acknowledge(&fresh).await;
    candidate.fence().await;
    assert_eq!(product.snapshot(&failed_id).await, (0, 0));
    assert_eq!(product.snapshot(&fresh_id).await, (0, 0));
    eprintln!(
        "HANDOFF_STAGED_WIRE old_failed_unacked_before={before:?} replay_order=[{:?},{:?}] both_terminal_only_after_client_save_and_exact_ack=true",
        replay.seq, fresh.seq
    );
    primary.close().await;
    candidate.close().await;
    product.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_prepared_candidate_disconnect_thaws_old_owner_without_losing_work() {
    let mut product = Product::open().await;
    let (mut primary, old_welcome) = product
        .connect_metadata(None, None, None, TransportKind::Tcp, handoff_metadata(None))
        .await;
    let id = "handoffwirecancelled1";
    let (mut candidate, candidate_welcome) = product
        .connect_metadata(
            old_welcome.resume_token.as_deref(),
            None,
            None,
            TransportKind::Wss,
            handoff_metadata(Some(("prepare", &old_welcome.session_id, id))),
        )
        .await;
    assert_handoff_reply(&candidate_welcome, "prepared", &old_welcome.session_id, id);
    let drained = primary
        .transition(&old_welcome, "freeze", &candidate_welcome.session_id, id)
        .await;
    assert_handoff_reply(&drained, "drained", &candidate_welcome.session_id, id);
    candidate.fence().await;
    candidate.close().await;
    // close() joins the real server disconnect callback; no polling sleep is
    // used to assume the old owner has been restored.
    // A previously queued freeze can arrive after that callback. It belongs to
    // a now-cancelled reservation and must not revoke the healthy old session.
    let cancelled = primary
        .transition(&old_welcome, "freeze", &candidate_welcome.session_id, id)
        .await;
    assert_handoff_reply(&cancelled, "resumed", &candidate_welcome.session_id, id);
    let accepted = product.accept("handoff-cancel-healthy").await;
    let delivered = primary.delivery().await;
    assert_eq!(delivered.id, accepted);
    product.save(&delivered).await.unwrap();
    primary.acknowledge(&delivered).await;
    primary.fence().await;
    assert_eq!(product.snapshot(&accepted).await, (0, 0));
    eprintln!(
        "HANDOFF_CANCEL_WIRE candidate_disconnect_joined=true primary_resumed_exact_ack=true"
    );
    primary.close().await;
    product.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_self_peer_handoff_is_rejected_without_revoking_healthy_primary() {
    let mut product = Product::open().await;
    let (mut primary, old_welcome) = product
        .connect_metadata(None, None, None, TransportKind::Tcp, handoff_metadata(None))
        .await;
    let id = "handoffwireselfpeer01";
    let (mut candidate, prepared) = product
        .connect_metadata(
            old_welcome.resume_token.as_deref(),
            None,
            None,
            TransportKind::Wss,
            handoff_metadata(Some(("prepare", &old_welcome.session_id, id))),
        )
        .await;
    candidate
        .send(
            &PushgoWireProfile
                .encode_client_hello(&HelloCtx {
                    identity: DEVICE.into(),
                    resume_token: prepared.resume_token.clone(),
                    supported_wire_versions: vec![2],
                    supported_payload_versions: vec![1],
                    metadata: handoff_metadata(Some(("activate", &prepared.session_id, id))),
                    ..HelloCtx::default()
                })
                .unwrap(),
        )
        .await;
    assert!(
        matches!(candidate.receive().await, DecodedServerFrame::GoAway(_)),
        "self-peer must be rejected before any paired runtime lock"
    );
    candidate.close().await;
    let accepted = product.accept("self-peer-unrelated-healthy").await;
    let delivered = primary.delivery().await;
    assert_eq!(delivered.id, accepted);
    product.save(&delivered).await.unwrap();
    primary.acknowledge(&delivered).await;
    primary.fence().await;
    assert_eq!(product.snapshot(&accepted).await, (0, 0));
    primary.close().await;
    product.stop().await;
}

async fn native_connect_context(
    product: &Product,
    metadata: BTreeMap<String, String>,
    resume: Option<&str>,
    transport: TransportKind,
) -> SessionCtx {
    let response = product
        .app
        .auth(AuthRequest {
            phase: AuthCheckPhase::Connect,
            session: None,
            hello: Some(HelloCtx {
                identity: DEVICE.into(),
                resume_token: resume.map(str::to_owned),
                supported_wire_versions: vec![2],
                supported_payload_versions: vec![1],
                metadata,
                ..HelloCtx::default()
            }),
            peer: Some(PeerMeta {
                transport,
                remote_addr: Some("synthetic auth interleaving".into()),
            }),
        })
        .await
        .unwrap();
    let AuthResponse::ConnectAccepted(session) = response else {
        panic!("native initial context must be accepted");
    };
    session
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_stale_freeze_continuation_cannot_cancel_a_new_candidate_reservation() {
    use super::registry::PendingOutbound;

    let product = Product::open().await;
    let old =
        native_connect_context(&product, handoff_metadata(None), None, TransportKind::Tcp).await;
    let id_a = "nativefreezeold01";
    let candidate_a = native_connect_context(
        &product,
        handoff_metadata(Some(("prepare", &old.session_id, id_a))),
        old.resume_token.as_deref(),
        TransportKind::Wss,
    )
    .await;
    let runtime = product
        .app
        .runtime_for_handoff_test(&old.session_id)
        .unwrap();
    let (release, blocked) = tokio::sync::oneshot::channel::<()>();
    *runtime.pending_outbound.lock().await =
        Some(PendingOutbound::Running(tokio::spawn(async move {
            blocked.await.unwrap();
            None
        })));
    let stopped = runtime.outbound_stop.notified();
    tokio::pin!(stopped);
    stopped.as_mut().enable();
    let app = product.app.clone();
    let old_for_freeze = old.clone();
    let peer_for_freeze = candidate_a.session_id.clone();
    let freeze = tokio::spawn(async move {
        app.auth(AuthRequest {
            phase: AuthCheckPhase::InBandReauth,
            session: Some(old_for_freeze.clone()),
            peer: None,
            hello: Some(HelloCtx {
                identity: DEVICE.into(),
                resume_token: old_for_freeze.resume_token,
                supported_wire_versions: vec![2],
                supported_payload_versions: vec![1],
                metadata: handoff_metadata(Some(("freeze", &peer_for_freeze, id_a))),
                ..HelloCtx::default()
            }),
        })
        .await
    });
    timeout(Duration::from_secs(3), stopped)
        .await
        .expect("freeze publishes stop before awaiting existing operation");
    assert!(!runtime.handoff.lock().can_send());
    let premature = timeout(
        Duration::from_secs(3),
        product.app.auth(AuthRequest {
            phase: AuthCheckPhase::InBandReauth,
            session: Some(candidate_a.clone()),
            peer: None,
            hello: Some(HelloCtx {
                identity: DEVICE.into(),
                resume_token: candidate_a.resume_token.clone(),
                supported_wire_versions: vec![2],
                supported_payload_versions: vec![1],
                metadata: handoff_metadata(Some(("activate", &old.session_id, id_a))),
                ..HelloCtx::default()
            }),
        }),
    )
    .await
    .expect("premature activation must be bounded, not wait behind the outstanding old operation");
    assert!(
        premature.is_err(),
        "a stop request is not yet the completed drain barrier; candidate cannot activate before the old preparation join"
    );
    assert!(!runtime.handoff.lock().can_send());
    product
        .app
        .on_disconnect(&candidate_a, DisconnectReason::RemoteClosed)
        .await;
    let id_b = "nativefreezenew02";
    let candidate_b = native_connect_context(
        &product,
        handoff_metadata(Some(("prepare", &old.session_id, id_b))),
        old.resume_token.as_deref(),
        TransportKind::Wss,
    )
    .await;
    release.send(()).unwrap();
    let _reply = timeout(Duration::from_secs(3), freeze)
        .await
        .expect("bounded stale freeze join")
        .unwrap();
    {
        let state = runtime.handoff.lock();
        assert!(
            state.can_send(),
            "old primary remains active while candidate B prepares"
        );
        let binding = state
            .binding()
            .expect("stale freeze A must not erase reservation B");
        assert_eq!(binding.peer, candidate_b.session_id);
        assert_eq!(binding.id, id_b);
    }
    let b = product
        .app
        .runtime_for_handoff_test(&candidate_b.session_id)
        .unwrap();
    assert!(!b.is_terminating());
    assert!(!b.handoff.lock().can_send());
    assert_eq!(b.handoff.lock().binding().unwrap().peer, old.session_id);
    eprintln!(
        "HANDOFF_NATIVE stale_freeze_A_joined=true newer_reservation_B_preserved=true no_background_owner=true"
    );
    product
        .app
        .on_disconnect(&candidate_b, DisconnectReason::RemoteClosed)
        .await;
    product
        .app
        .on_disconnect(&old, DisconnectReason::RemoteClosed)
        .await;
    product.stop().await;
}
