//! Real loopback drafts, registered/run only after the baseline freezes.
//! TLS tests use explicit synthetic CA/leaf/key with ordinary PKIX and hostname
//! verification plus an exact synthetic-leaf pin; no insecure verifier exists.
use crate::{
    AcceptRequest, Config, OrdinaryStore,
    private_listeners::{self, PrivateListener},
    private_runtime::{PrivateRuntime, PrivateRuntimeConfig},
    store::OwnerLock,
};
use bytes::BytesMut;
use mqttbytes::{
    QoS,
    v5::{
        self, Connect, ConnectProperties, Packet, PubAck, PubAckReason, Subscribe,
        SubscribeProperties, SubscribeReasonCode, UnsubAckReason, Unsubscribe,
    },
};
use pushgo_warp_profile::{PrivatePayloadEnvelope, PushgoWireProfile};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    time::timeout,
};
use warp_link::{
    warp_link_core::{AckMsg, AckStatus, DecodedServerFrame, HelloCtx, TlsMode, WireProfile},
    warp_link_transport::{ClientIo, FramedReader, write_prefixed_frame},
};
struct Fixture {
    _dir: tempfile::TempDir,
    store: OrdinaryStore,
    owner: Option<OwnerLock>,
    device: String,
    channel: String,
    auth: String,
}
impl Fixture {
    async fn new() -> Self {
        Self::new_with_base(None).await
    }
    async fn new_with_base(base: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("private.sqlite").display());
        let mut config = Config::default();
        config.private.enabled = true;
        if let Some(base) = base {
            config.public_base_url = base;
        }
        let (store, owner) = OrdinaryStore::open(&url, config).await.unwrap();
        let device = store.register("android").await.unwrap();
        store
            .update_route(&device, None, "PRIVATE", None)
            .await
            .unwrap();
        let auth = crate::types::generate_hex_id_128();
        let channel = store
            .subscribe(&device, None, Some("transport fixture"), &auth)
            .await
            .unwrap()["channel_id"]
            .as_str()
            .unwrap()
            .to_owned();
        Self {
            _dir: dir,
            store,
            owner: Some(owner),
            device,
            channel,
            auth,
        }
    }
    async fn accept(&self, op: &str) -> crate::Accepted {
        let accepted = self
            .store
            .accept(AcceptRequest {
                channel_id: self.channel.clone(),
                password: self.auth.clone(),
                title: "Private transport synthetic".into(),
                op_id: Some(op.into()),
                ttl: Some(crate::store::now() + 180_000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(accepted.dispatch_status, "attempted_accepted");
        let persisted: String =
            sqlx::query_scalar("SELECT status FROM messages WHERE delivery_id=?")
                .bind(&accepted.delivery_id)
                .fetch_one(&self.store.sqlite_store().unwrap().pool)
                .await
                .unwrap();
        assert_eq!(
            persisted, "sent",
            "wire admission result is distinct from durable Private status"
        );
        accepted
    }
    fn runtime(&self) -> PrivateRuntime {
        PrivateRuntime::new(
            self.store.clone(),
            Some(self.auth.clone()),
            PrivateRuntimeConfig::default(),
        )
        .unwrap()
    }
    fn hello(&self) -> HelloCtx {
        HelloCtx {
            identity: self.device.clone(),
            auth_token: Some(self.auth.clone()),
            supported_wire_versions: vec![2],
            supported_payload_versions: vec![1],
            ..Default::default()
        }
    }
    async fn close(mut self) {
        self.store.close().await;
        self.owner.take().unwrap().release();
    }
    async fn live_claims(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM targets WHERE private_claim IS NOT NULL")
            .fetch_one(&self.store.sqlite_store().unwrap().pool)
            .await
            .unwrap()
    }
    async fn wait_consumed(&self) {
        timeout(Duration::from_secs(5), async {
            loop {
                let n: i64 =
                    sqlx::query_scalar("SELECT targets FROM ledger_usage WHERE singleton=1")
                        .fetch_one(&self.store.sqlite_store().unwrap().pool)
                        .await
                        .unwrap();
                if n == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("Private ACK did not commit in fixed budget");
    }
}
struct PlainPeer {
    reader: FramedReader<ReadHalf<TcpStream>>,
    writer: WriteHalf<TcpStream>,
}
impl PlainPeer {
    async fn connect(addr: SocketAddr, hello: HelloCtx) -> (Self, String) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = tokio::io::split(stream);
        let mut peer = Self {
            reader: FramedReader::new(reader),
            writer,
        };
        let profile = PushgoWireProfile::new();
        write_prefixed_frame(
            &mut peer.writer,
            &profile.encode_client_hello(&hello).unwrap(),
        )
        .await
        .unwrap();
        let frame = timeout(Duration::from_secs(5), peer.reader.read_frame())
            .await
            .unwrap()
            .unwrap();
        let DecodedServerFrame::Welcome(welcome) = profile.decode_server_frame(&frame).unwrap()
        else {
            panic!("real TCP expected WELCOME")
        };
        assert_eq!(
            welcome.max_frame_bytes,
            warp_link::warp_link_core::MAX_FRAME_BYTES as u32
        );
        (peer, welcome.resume_token.unwrap())
    }
    async fn delivery(&mut self) -> warp_link::warp_link_core::DeliverMsg {
        loop {
            let frame = timeout(Duration::from_secs(5), self.reader.read_frame())
                .await
                .unwrap()
                .unwrap();
            match PushgoWireProfile::new()
                .decode_server_frame(&frame)
                .unwrap()
            {
                DecodedServerFrame::Deliver(message) => return message,
                DecodedServerFrame::Ping => write_prefixed_frame(
                    &mut self.writer,
                    &PushgoWireProfile::new().encode_client_pong(),
                )
                .await
                .unwrap(),
                other => panic!("unexpected real TCP frame {other:?}"),
            }
        }
    }
    async fn ack(&mut self, message: &warp_link::warp_link_core::DeliverMsg, status: AckStatus) {
        let frame = PushgoWireProfile::new()
            .encode_client_ack(&AckMsg {
                seq: message.seq,
                id: message.id.clone(),
                status,
            })
            .unwrap();
        write_prefixed_frame(&mut self.writer, &frame)
            .await
            .unwrap();
    }
}
async fn start_plain(f: &Fixture) -> (PrivateRuntime, PrivateListener) {
    let runtime = f.runtime();
    let mut config = private_listeners::server_config();
    config.tcp_listen_addr = Some("127.0.0.1:0".into());
    config.tcp_tls_mode = TlsMode::OffloadAtEdge;
    let listener = private_listeners::start_tcp(runtime.clone(), config)
        .await
        .unwrap();
    (runtime, listener)
}
#[tokio::test]
async fn real_tcp_ack_commit_and_http_private_ack_isolation() {
    let f = Fixture::new().await;
    let accepted = f.accept("tcp-real-ack").await;
    let (runtime, mut listener) = start_plain(&f).await;
    let (mut peer, _) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    let message = peer.delivery().await;
    assert_eq!(message.id, accepted.delivery_id);
    let payload: PrivatePayloadEnvelope = postcard::from_bytes(&message.payload).unwrap();
    assert_eq!(payload.data["message_id"], accepted.message_id);
    assert_eq!(payload.data["base_url"], f.store.config.public_base_url);
    assert_eq!(
        f.store
            .ack(&f.device, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    assert_eq!(f.live_claims().await, 1);
    assert_eq!(runtime.available_owned_slots(), 4095);
    peer.ack(&message, AckStatus::Ok).await;
    f.wait_consumed().await;
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.available_owned_slots(), 4096);
    f.close().await;
}
#[tokio::test]
async fn real_tcp_lost_ack_runtime_restart_replays_same_delivery_with_new_resume_token() {
    let f = Fixture::new().await;
    let accepted = f.accept("tcp-lost-wire-ack").await;
    let (runtime, mut listener) = start_plain(&f).await;
    let (mut peer, old_token) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    let old = peer.delivery().await;
    assert_eq!(old.id, accepted.delivery_id);
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(f.live_claims().await, 0);
    let (runtime, mut listener) = start_plain(&f).await;
    let (mut peer, new_token) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    assert_ne!(old_token, new_token);
    let replay = peer.delivery().await;
    assert_eq!(replay.id, old.id);
    let before: PrivatePayloadEnvelope = postcard::from_bytes(&old.payload).unwrap();
    let after: PrivatePayloadEnvelope = postcard::from_bytes(&replay.payload).unwrap();
    assert_eq!(before.data, after.data);
    peer.ack(&replay, AckStatus::InvalidPayload).await;
    f.wait_consumed().await;
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    f.close().await;
}
async fn mqtt_read(stream: &mut TcpStream, buffer: &mut BytesMut) -> Packet {
    timeout(Duration::from_secs(5), async {
        loop {
            match v5::read(buffer, crate::private_mqtt::MAX_PACKET) {
                Ok(p) => return p,
                Err(mqttbytes::Error::InsufficientBytes(_)) => {}
                Err(e) => panic!("real MQTT codec {e:?}"),
            }
            use tokio::io::AsyncReadExt;
            let mut bytes = [0; 2048];
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(n > 0);
            buffer.extend_from_slice(&bytes[..n]);
        }
    })
    .await
    .unwrap()
}
fn mqtt_connect(auth: &str) -> Connect {
    let mut connect = Connect::new("");
    connect.set_login(auth, "");
    connect.properties = Some(ConnectProperties {
        session_expiry_interval: None,
        receive_maximum: None,
        max_packet_size: None,
        topic_alias_max: None,
        request_response_info: None,
        request_problem_info: None,
        user_properties: vec![("device_type".into(), "subscribe".into())],
        authentication_method: None,
        authentication_data: None,
    });
    connect
}
async fn mqtt_subscribe(
    stream: &mut TcpStream,
    buffer: &mut BytesMut,
    channel: &str,
    auth: &str,
    pkid: u16,
) -> SubscribeReasonCode {
    let mut subscribe = Subscribe::new(channel, QoS::AtLeastOnce);
    subscribe.pkid = pkid;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![("pushgo-password".into(), auth.into())],
    });
    let mut bytes = BytesMut::new();
    subscribe.write(&mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
    let Packet::SubAck(ack) = mqtt_read(stream, buffer).await else {
        panic!("MQTT SUBACK required")
    };
    assert_eq!(ack.pkid, pkid);
    ack.return_codes[0]
}
#[tokio::test]
async fn real_mqtt5_registration_subscribe_puback_unsubscribe_existing_and_future_fanout() {
    let f = Fixture::new().await;
    f.store.unsubscribe(&f.device, &f.channel).await.unwrap();
    let runtime = f.runtime();
    let mut listener =
        crate::private_mqtt::start_mqtt(runtime.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
    let mut stream = TcpStream::connect(listener.local_addr).await.unwrap();
    let mut bytes = BytesMut::new();
    mqtt_connect(&f.auth).write(&mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut read = BytesMut::new();
    let Packet::ConnAck(ack) = mqtt_read(&mut stream, &mut read).await else {
        panic!("CONNACK required")
    };
    assert_eq!(ack.code, v5::ConnectReturnCode::Success);
    let device = ack
        .properties
        .unwrap()
        .assigned_client_identifier
        .expect("new MQTT registration must assign identity");
    assert_ne!(device, f.device);
    let platform: String = sqlx::query_scalar("SELECT platform FROM devices WHERE device_key=?")
        .bind(&device)
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    assert_eq!(platform, "mqtt");
    assert_eq!(
        mqtt_subscribe(
            &mut stream,
            &mut read,
            "00000000000000000000000000",
            &f.auth,
            1
        )
        .await,
        SubscribeReasonCode::NotAuthorized
    );
    let unrelated = crate::types::generate_hex_id_128();
    assert_eq!(
        mqtt_subscribe(&mut stream, &mut read, &f.channel, &unrelated, 2).await,
        SubscribeReasonCode::NotAuthorized
    );
    let channels: i64 = sqlx::query_scalar("SELECT count(*) FROM channels")
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    assert_eq!(channels, 1);
    assert_eq!(
        mqtt_subscribe(&mut stream, &mut read, &f.channel, &f.auth, 3).await,
        SubscribeReasonCode::QoS1
    );
    let accepted = f.accept("mqtt-real-ack").await;
    let Packet::Publish(publish) = mqtt_read(&mut stream, &mut read).await else {
        panic!("MQTT downlink publish required")
    };
    assert_eq!(publish.qos, QoS::AtLeastOnce);
    assert_eq!(publish.topic, f.channel);
    let body: serde_json::Value = serde_json::from_slice(&publish.payload).unwrap();
    assert_eq!(body["schema"], "pushgo.mqtt.delivery.v1");
    assert_eq!(body["delivery_id"], accepted.delivery_id);
    let mut unsubscribe = Unsubscribe::new(&f.channel);
    unsubscribe.pkid = 4;
    let mut bytes = BytesMut::new();
    unsubscribe.write(&mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
    let Packet::UnsubAck(ack) = mqtt_read(&mut stream, &mut read).await else {
        panic!("UNSUBACK required")
    };
    assert_eq!(ack.reasons, vec![UnsubAckReason::Success]);
    assert_eq!(
        f.live_claims().await,
        1,
        "unsubscribe preserves accepted capability"
    );
    let mut ack = PubAck::new(publish.pkid);
    ack.reason = PubAckReason::Success;
    let mut bytes = BytesMut::new();
    ack.write(&mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
    f.wait_consumed().await;
    let after_unsubscribe = f
        .store
        .accept(AcceptRequest {
            channel_id: f.channel.clone(),
            password: f.auth.clone(),
            title: "after unsubscribe".into(),
            op_id: Some("mqtt-after-unsubscribe".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let new_targets: i64 = sqlx::query_scalar("SELECT count(*) FROM targets WHERE delivery_id=?")
        .bind(&after_unsubscribe.delivery_id)
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    assert_eq!(new_targets, 0);
    let targets: i64 = sqlx::query_scalar("SELECT targets FROM ledger_usage WHERE singleton=1")
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    assert_eq!(targets, 0, "no future fanout after unsubscribe");
    drop(stream);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    f.close().await;
}
#[tokio::test]
async fn real_mqtt_bad_shared_token_has_no_registration_side_effect() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let mut listener =
        crate::private_mqtt::start_mqtt(runtime.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(listener.local_addr).await.unwrap();
    let wrong = crate::types::generate_hex_id_128();
    assert_ne!(wrong, f.auth);
    let mut bytes = BytesMut::new();
    mqtt_connect(&wrong).write(&mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut read = BytesMut::new();
    let Packet::ConnAck(ack) = mqtt_read(&mut stream, &mut read).await else {
        panic!("denied CONNACK required")
    };
    assert_eq!(ack.code, v5::ConnectReturnCode::BadUserNamePassword);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&f.store.sqlite_store().unwrap().pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    drop(stream);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    f.close().await;
}

fn tls_fixtures() -> (String, String, rustls::ClientConfig, Vec<u8>) {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let cert = std::env::var("PUSHGO_C6_CERT_PEM").expect("explicit synthetic leaf required");
    let key = std::env::var("PUSHGO_C6_KEY_PEM").expect("explicit synthetic key required");
    let ca = std::env::var("PUSHGO_C6_CA_PEM").expect("explicit synthetic CA required");
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let leaf = CertificateDer::pem_file_iter(&cert)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (cert, key, client, leaf)
}
async fn public_client_ack(io: &mut ClientIo, hello: HelloCtx, delivery: &str) {
    let profile = PushgoWireProfile::new();
    io.send_frame(&profile.encode_client_hello(&hello).unwrap(), 5000)
        .await
        .unwrap();
    let frame = io.recv_frame(5000).await.unwrap();
    assert!(matches!(
        profile.decode_server_frame(&frame).unwrap(),
        DecodedServerFrame::Welcome(_)
    ));
    let frame = io.recv_frame(5000).await.unwrap();
    let DecodedServerFrame::Deliver(message) = profile.decode_server_frame(&frame).unwrap() else {
        panic!("locked public ClientIo expected DELIVER")
    };
    assert_eq!(message.id, delivery);
    io.send_frame(
        &profile
            .encode_client_ack(&AckMsg {
                seq: message.seq,
                id: message.id,
                status: AckStatus::Ok,
            })
            .unwrap(),
        5000,
    )
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "explicit synthetic CA/leaf/key paths required; PKIX/hostname and leaf pin retained"]
async fn real_tcp_tls_public_warp_client_io_ack() {
    let f = Fixture::new().await;
    let accepted = f.accept("tcp-tls-real-ack").await;
    let (cert, key, mut client, leaf) = tls_fixtures();
    let runtime = f.runtime();
    let mut config = private_listeners::server_config();
    config.tcp_listen_addr = Some("127.0.0.1:0".into());
    config.tls_cert_path = Some(cert);
    config.tls_key_path = Some(key);
    let mut listener = private_listeners::start_tcp(runtime.clone(), config)
        .await
        .unwrap();
    client.alpn_protocols = vec![b"pushgo-tcp".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(listener.local_addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0].as_ref(),
        leaf
    );
    let (reader, writer) = tokio::io::split(stream);
    let mut io = ClientIo::Tcp {
        reader: FramedReader::new(reader),
        writer,
    };
    public_client_ack(&mut io, f.hello(), &accepted.delivery_id).await;
    f.wait_consumed().await;
    drop(io);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    f.close().await;
}
#[tokio::test]
#[ignore = "explicit synthetic CA/leaf/key paths required; PKIX/hostname and leaf pin retained"]
async fn real_quic_public_warp_client_io_ack() {
    use rustls::pki_types::CertificateDer;
    let f = Fixture::new().await;
    let accepted = f.accept("quic-real-ack").await;
    let (cert, key, mut client, leaf) = tls_fixtures();
    let runtime = f.runtime();
    let mut config = private_listeners::server_config();
    config.quic_listen_addr = Some("127.0.0.1:0".into());
    config.tls_cert_path = Some(cert);
    config.tls_key_path = Some(key);
    let mut listener = private_listeners::start_quic(runtime.clone(), config)
        .await
        .unwrap();
    client.alpn_protocols = vec![b"pushgo-quic".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint
        .connect(listener.local_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let peer = connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    assert_eq!(peer[0].as_ref(), leaf);
    let (send, recv) = connection.open_bi().await.unwrap();
    let mut io = ClientIo::Quic {
        send,
        recv: FramedReader::new(recv),
        _endpoint: endpoint,
    };
    public_client_ack(&mut io, f.hello(), &accepted.delivery_id).await;
    f.wait_consumed().await;
    drop(io);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    f.close().await;
}

#[tokio::test]
async fn real_tcp_single_slot_waits_for_ack_transaction_commit_before_second_claim() {
    use sqlx::Connection;
    let f = Fixture::new().await;
    let first = f.accept("single-slot-first").await;
    let second = f.accept("single-slot-second").await;
    let config = PrivateRuntimeConfig {
        owned_slots: 1,
        window: 1,
        ..Default::default()
    };
    let runtime = PrivateRuntime::new(f.store.clone(), Some(f.auth.clone()), config).unwrap();
    let mut server = private_listeners::server_config();
    server.tcp_listen_addr = Some("127.0.0.1:0".into());
    server.tcp_tls_mode = TlsMode::OffloadAtEdge;
    let mut listener = private_listeners::start_tcp(runtime.clone(), server)
        .await
        .unwrap();
    let (mut peer, _) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    let message = peer.delivery().await;
    assert!(message.id == first.delivery_id || message.id == second.delivery_id);
    let remaining = if message.id == first.delivery_id {
        second.delivery_id.clone()
    } else {
        first.delivery_id.clone()
    };
    assert_eq!(runtime.available_owned_slots(), 0);
    assert_eq!(f.live_claims().await, 1);
    // A wire PING/PONG after ACK Error proves that callback completed. Error is
    // nonterminal and cannot release the one slot or claim the second item.
    peer.ack(&message, AckStatus::Error).await;
    let profile = PushgoWireProfile::new();
    write_prefixed_frame(&mut peer.writer, &profile.encode_client_ping())
        .await
        .unwrap();
    let frame = timeout(Duration::from_secs(1), peer.reader.read_frame())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        profile.decode_server_frame(&frame).unwrap(),
        DecodedServerFrame::Pong
    ));
    assert_eq!(runtime.available_owned_slots(), 0);
    assert_eq!(f.live_claims().await, 1);
    // Hold a real independent SQLite writer transaction. The Private ACK gets
    // its gate and then blocks inside native BEGIN IMMEDIATE; no fake result or
    // new fixture hook supplies this fault. Its COMMIT has not completed.
    let url = format!(
        "sqlite://{}",
        f._dir.path().join("private.sqlite").display()
    );
    let mut blocker = sqlx::SqliteConnection::connect(&url).await.unwrap();
    let mut transaction = blocker.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let before =
        f.store.counters.profile.snapshot()["paths"]["ack"]["phases"]["gate_wait"]["samples"]
            .as_u64()
            .unwrap();
    peer.ack(&message, AckStatus::Ok).await;
    timeout(Duration::from_secs(1),async { loop { let samples=f.store.counters.profile.snapshot()["paths"]["ack"]["phases"]["gate_wait"]["samples"].as_u64().unwrap();if samples>before { break; }tokio::task::yield_now().await; } }).await.expect("wire ACK never entered the native transaction");
    assert_eq!(
        runtime.available_owned_slots(),
        0,
        "slot must remain held before ACK COMMIT"
    );
    let claimed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM targets WHERE private_claim IS NOT NULL")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
    assert_eq!(claimed, 1);
    let untouched: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM targets WHERE delivery_id=? AND private_claim IS NULL",
    )
    .bind(&remaining)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(
        untouched, 1,
        "second delivery must not be claimed before first ACK COMMIT"
    );
    transaction.commit().await.unwrap();
    blocker.close().await.unwrap();
    let message = peer.delivery().await;
    assert_eq!(message.id, remaining);
    assert_eq!(runtime.available_owned_slots(), 0);
    peer.ack(&message, AckStatus::Ok).await;
    f.wait_consumed().await;
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.available_owned_slots(), 1);
    f.close().await;
}

// Real ws:// loopback represents an explicit TLS-offload edge. It proves the
// WSS binary protocol/HTTP authorization/ledger boundary, not external PKIX.
struct WsPeer {
    io: ClientIo,
}
impl WsPeer {
    async fn socket(
        url: &str,
        auth: Option<&str>,
        subprotocol: Option<&str>,
    ) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = url.into_client_request().unwrap();
        if let Some(auth) = auth {
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {auth}").parse().unwrap());
        }
        if let Some(protocol) = subprotocol {
            request
                .headers_mut()
                .insert("sec-websocket-protocol", protocol.parse().unwrap());
        }
        let (socket, response) = tokio_tungstenite::connect_async(request).await?;
        assert_eq!(response.status().as_u16(), 101);
        assert_eq!(
            response.headers()["sec-websocket-protocol"],
            "pushgo-private.v1"
        );
        Ok(Self {
            io: ClientIo::Wss {
                stream: Box::new(socket),
            },
        })
    }
    async fn connect(url: &str, f: &Fixture) -> (Self, String) {
        let mut peer = Self::socket(url, Some(&f.auth), Some("pushgo-private.v1"))
            .await
            .unwrap();
        let profile = PushgoWireProfile::new();
        peer.io
            .send_frame(&profile.encode_client_hello(&f.hello()).unwrap(), 5000)
            .await
            .unwrap();
        let DecodedServerFrame::Welcome(welcome) = peer.receive().await else {
            panic!("real WS expected WELCOME")
        };
        (peer, welcome.resume_token.unwrap())
    }
    async fn receive(&mut self) -> DecodedServerFrame {
        loop {
            let bytes = self.io.recv_frame(5000).await.unwrap();
            let profile = PushgoWireProfile::new();
            let frame = profile.decode_server_frame(&bytes).unwrap();
            if matches!(frame, DecodedServerFrame::Ping) {
                self.io
                    .send_frame(&profile.encode_client_pong(), 5000)
                    .await
                    .unwrap();
                continue;
            }
            return frame;
        }
    }
    async fn delivery(&mut self) -> warp_link::warp_link_core::DeliverMsg {
        let DecodedServerFrame::Deliver(message) = self.receive().await else {
            panic!("real WS expected DELIVER")
        };
        message
    }
    async fn ack(
        &mut self,
        message: &warp_link::warp_link_core::DeliverMsg,
    ) -> Result<(), warp_link::warp_link_core::WarpLinkError> {
        let profile = PushgoWireProfile::new();
        self.io
            .send_frame(
                &profile
                    .encode_client_ack(&AckMsg {
                        seq: message.seq,
                        id: message.id.clone(),
                        status: AckStatus::Ok,
                    })
                    .unwrap(),
                5000,
            )
            .await
    }
    async fn ping_barrier(&mut self) {
        self.io
            .send_frame(&PushgoWireProfile::new().encode_client_ping(), 5000)
            .await
            .unwrap();
        assert!(
            matches!(self.receive().await, DecodedServerFrame::Pong),
            "old transport must not receive an unissued new delivery"
        );
    }
}
struct WsHarness {
    private: crate::private_http::PrivateHttp,
    stop: tokio::sync::watch::Sender<bool>,
    http: tokio::task::JoinHandle<std::io::Result<()>>,
    url: String,
}
impl WsHarness {
    async fn start(
        f: &Fixture,
        runtime: &PrivateRuntime,
        listener: tokio::net::TcpListener,
    ) -> Self {
        let addr = listener.local_addr().unwrap();
        let profile = crate::private_http::discovery_profile(
            &f.store.config.public_base_url,
            None,
            None,
            None,
            true,
            addr.port(),
        );
        let url = profile["transport"]["wss_url"].as_str().unwrap().to_owned();
        let private = crate::private_http::PrivateHttp::new(
            runtime.clone(),
            private_listeners::server_config(),
            profile,
        );
        let router = crate::http::router_with_private(
            f.store.clone(),
            Arc::new(|| serde_json::json!({})),
            Some(&f.auth),
            Some(private.clone()),
        );
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let counters = f.store.counters.clone();
        let http = tokio::spawn(crate::serve(
            listener,
            router,
            crate::HttpLimits::default(),
            counters,
            stopped,
        ));
        Self {
            private,
            stop,
            http,
            url,
        }
    }
    async fn shutdown(self, runtime: &PrivateRuntime) {
        runtime.begin_shutdown();
        self.stop.send_replace(true);
        timeout(Duration::from_secs(5), self.http)
            .await
            .expect("real HTTP tasks failed to join")
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(10), self.private.shutdown())
            .await
            .expect("real WSS upgrade tasks failed to join")
            .unwrap();
    }
}
#[tokio::test]
async fn real_ws_edge_prefix_http_bearer_hello_auth_and_durable_ack_join() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/edge", listener.local_addr().unwrap());
    let f = Fixture::new_with_base(Some(base.clone())).await;
    let accepted = f.accept("ws-real-ack").await;
    let runtime = f.runtime();
    let http = WsHarness::start(&f, &runtime, listener).await;
    match WsPeer::socket(&http.url, None, Some("pushgo-private.v1")).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 401)
        }
        _ => panic!("real HTTP Bearer must be required before upgrade"),
    }
    match WsPeer::socket(&http.url, Some(&f.auth), None).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 400)
        }
        _ => panic!("real WS subprotocol must be required"),
    }
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let profile: serde_json::Value = client
        .get(format!("{base}/gateway/profile"))
        .bearer_auth(&f.auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile["data"]["transport"]["wss_url"], http.url);
    assert!(http.url.ends_with("/edge/private/ws"));
    assert_eq!(
        client
            .get(format!(
                "{}/gateway/profile",
                base.trim_end_matches("/edge")
            ))
            .bearer_auth(&f.auth)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let mut denied = WsPeer::socket(&http.url, Some(&f.auth), Some("pushgo-private.v1"))
        .await
        .unwrap();
    let mut wrong = f.hello();
    wrong.auth_token = Some(crate::types::generate_hex_id_128());
    denied
        .io
        .send_frame(
            &PushgoWireProfile::new()
                .encode_client_hello(&wrong)
                .unwrap(),
            5000,
        )
        .await
        .unwrap();
    assert!(
        matches!(denied.receive().await,DecodedServerFrame::Error { code,.. } if code=="auth_failed")
    );
    drop(denied);
    assert_eq!(runtime.available_owned_slots(), 4096);
    let (mut peer, _) = WsPeer::connect(&http.url, &f).await;
    let message = peer.delivery().await;
    assert_eq!(message.id, accepted.delivery_id);
    let payload: PrivatePayloadEnvelope = postcard::from_bytes(&message.payload).unwrap();
    assert_eq!(payload.data["message_id"], accepted.message_id);
    assert_eq!(payload.data["base_url"], base);
    assert_eq!(f.live_claims().await, 1);
    peer.ack(&message).await.unwrap();
    f.wait_consumed().await;
    drop(peer);
    drop(client);
    http.shutdown(&runtime).await;
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.available_owned_slots(), 4096);
    f.close().await;
}
#[tokio::test]
async fn real_ws_replacement_coexists_with_tcp_and_revoked_stream_cannot_consume_provider_pull() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/edge", listener.local_addr().unwrap());
    let f = Fixture::new_with_base(Some(base.clone())).await;
    let runtime = f.runtime();
    let mut config = private_listeners::server_config();
    config.tcp_listen_addr = Some("127.0.0.1:0".into());
    config.tcp_tls_mode = TlsMode::OffloadAtEdge;
    let mut tcp_listener = private_listeners::start_tcp(runtime.clone(), config)
        .await
        .unwrap();
    let http = WsHarness::start(&f, &runtime, listener).await;
    let (mut old, _) = WsPeer::connect(&http.url, &f).await;
    let (mut tcp, _) = PlainPeer::connect(tcp_listener.local_addr, f.hello()).await;
    let accepted = f.accept("multi-transport-first").await;
    let issued_old = old.delivery().await;
    let issued_tcp = tcp.delivery().await;
    assert_eq!(issued_old.id, accepted.delivery_id);
    assert_eq!(issued_tcp.id, issued_old.id);
    assert_eq!(issued_tcp.seq, issued_old.seq);
    assert_eq!(
        f.live_claims().await,
        1,
        "broadcast shares one durable capability"
    );
    assert_eq!(runtime.available_owned_slots(), 4095);
    let (mut replacement, _) = WsPeer::connect(&http.url, &f).await;
    let resumed = replacement.delivery().await;
    assert_eq!(resumed.id, issued_old.id);
    assert_eq!(resumed.seq, issued_old.seq);
    // Same-transport replacement retains the old transport's issued ACK grant.
    // PING/PONG orders this assertion after the real old-stream ACK callback.
    old.ack(&issued_old).await.unwrap();
    old.ping_barrier().await;
    f.wait_consumed().await;
    let accepted = f.accept("multi-transport-second").await;
    let issued_new = replacement.delivery().await;
    let issued_tcp = tcp.delivery().await;
    assert_eq!(issued_new.id, accepted.delivery_id);
    assert_eq!(issued_tcp.id, issued_new.id);
    assert_eq!(issued_tcp.seq, issued_new.seq);
    old.ping_barrier().await;
    let canonical: PrivatePayloadEnvelope = postcard::from_bytes(&issued_new.payload).unwrap();
    let route_value = crate::types::generate_hex_id_128();
    f.store
        .update_route(&f.device, None, "FCM", Some(&route_value))
        .await
        .unwrap();
    // The previous socket either sends its stale ACK or is already fenced shut.
    // Neither permits it to consume the migrated provider-mode obligation.
    let _ = replacement.ack(&issued_new).await;
    match replacement.io.recv_frame(5000).await {
        Err(_) => {}
        Ok(bytes) => assert!(
            matches!(
                PushgoWireProfile::new()
                    .decode_server_frame(&bytes)
                    .unwrap(),
                DecodedServerFrame::GoAway(_) | DecodedServerFrame::Error { .. }
            ),
            "route exit must revoke the real old stream"
        ),
    }
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let pulled: serde_json::Value = client
        .post(format!("{base}/v2/messages/pull"))
        .bearer_auth(&f.auth)
        .json(&serde_json::json!({"device_key":f.device.clone()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let item = pulled["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["delivery_id"] == accepted.delivery_id)
        .expect("stale stream must leave original provider Pull identity intact");
    assert_eq!(item["payload"]["message_id"], canonical.data["message_id"]);
    assert_eq!(item["payload"]["ttl"], canonical.data["ttl"]);
    assert_eq!(item["payload"]["base_url"], base);
    let acked:serde_json::Value=client.post(format!("{base}/v2/messages/ack")).bearer_auth(&f.auth).json(&serde_json::json!({"device_key":f.device.clone(),"delivery_ids":[accepted.delivery_id.clone()]})).send().await.unwrap().json().await.unwrap();
    assert_eq!(acked["data"]["removed_count"], 1);
    f.wait_consumed().await;
    drop(old);
    drop(replacement);
    drop(tcp);
    drop(client);
    tcp_listener.stop_accepting();
    runtime.begin_shutdown();
    http.shutdown(&runtime).await;
    tcp_listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.available_owned_slots(), 4096);
    f.close().await;
}

/// The former32768HTTP/33057DELIVER case is expanded to the approved48KiB HTTP boundary and must travel intact,
/// commit ACK, and preserve the second accepted body's first identity across
/// authority restart and Private->Provider route exit. No wakeup or chunking.
#[tokio::test]
async fn real_tcp_full_http_boundary_ack_restart_and_route_preserve_canonical_identity() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    async fn admit(f: &Fixture, op: &str) -> serde_json::Value {
        let input = crate::private_boundary_tests::legal_http_input(&f.channel, &f.auth, "text");
        let input = String::from_utf8(input)
            .unwrap()
            .replace("private-wire-boundary", op)
            .into_bytes();
        assert_eq!(input.len(), crate::MESSAGE_SUBMISSION_BODY_BYTES);
        let response = crate::router(f.store.clone(), Arc::new(|| serde_json::json!({})))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/message")
                    .header("content-type", "application/json")
                    .body(Body::from(input))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let accepted: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        accepted["data"].clone()
    }
    async fn snapshot(f: &Fixture, id: &str) -> (String, String, i64, i64, i64, Vec<u8>) {
        sqlx::query_as("SELECT delivery_id,message_id,accepted_at,expires_at,dedupe_until,payload_blob FROM messages WHERE delivery_id=?").bind(id).fetch_one(&f.store.sqlite_store().unwrap().pool).await.unwrap()
    }
    let mut f = Fixture::new().await;
    let first = admit(&f, "private-wire-boundary").await;
    let (runtime, mut listener) = start_plain(&f).await;
    let (mut peer, _) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    let delivered = peer.delivery().await;
    let frame = PushgoWireProfile::new()
        .encode_server_deliver(&delivered)
        .unwrap();
    println!(
        "C8_TCP_BOUNDARY {}",
        serde_json::json!({"http_bytes":crate::MESSAGE_SUBMISSION_BODY_BYTES,"complete_frame_bytes":frame.len(),"delivery_id":delivered.id})
    );
    assert!(frame.len() > crate::MESSAGE_SUBMISSION_BODY_BYTES);
    assert!(frame.len() > 32770 && frame.len() <= warp_link::warp_link_core::MAX_FRAME_BYTES);
    let original: PrivatePayloadEnvelope = postcard::from_bytes(&delivered.payload).unwrap();
    assert_eq!(
        delivered.id.as_str(),
        first["delivery_id"].as_str().unwrap()
    );
    assert_eq!(
        original.data["message_id"].as_str(),
        first["message_id"].as_str().unwrap()
    );
    assert_eq!(
        original.data["body"],
        serde_json::from_slice::<serde_json::Value>(
            &crate::private_boundary_tests::legal_http_input(&f.channel, &f.auth, "text")
        )
        .unwrap()["body"]
            .as_str()
            .unwrap()
    );
    peer.ack(&delivered, AckStatus::Ok).await;
    f.wait_consumed().await;
    let replay = admit(&f, "private-wire-boundary").await;
    assert_eq!(replay["delivery_id"], first["delivery_id"]);
    assert_eq!(replay["message_id"], first["message_id"]);

    let second = admit(&f, "private-wire-boundarz").await;
    let id = second["delivery_id"].as_str().unwrap().to_owned();
    let before = snapshot(&f, &id).await;
    let pending = peer.delivery().await;
    assert_eq!(pending.id, id);
    let frozen: PrivatePayloadEnvelope = postcard::from_bytes(&pending.payload).unwrap();
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(f.live_claims().await, 0);
    let config = f.store.config.clone();
    f.store.close().await;
    f.owner.take().unwrap().release();
    let (store, owner) = OrdinaryStore::open(
        &format!(
            "sqlite://{}",
            f._dir.path().join("private.sqlite").display()
        ),
        config,
    )
    .await
    .unwrap();
    f.store = store;
    f.owner = Some(owner);
    assert_eq!(snapshot(&f, &id).await, before);
    let (runtime, mut listener) = start_plain(&f).await;
    let (mut peer, _) = PlainPeer::connect(listener.local_addr, f.hello()).await;
    let recovered = peer.delivery().await;
    assert_eq!(recovered.id, id);
    assert_eq!(recovered.payload, pending.payload);
    f.store
        .update_route(&f.device, None, "FCM", Some("synthetic-c7-route-exit"))
        .await
        .unwrap();
    let stale = PushgoWireProfile::new()
        .encode_client_ack(&AckMsg {
            seq: recovered.seq,
            id: recovered.id.clone(),
            status: AckStatus::Ok,
        })
        .unwrap();
    let _ = write_prefixed_frame(&mut peer.writer, &stale).await;
    let fenced = timeout(Duration::from_secs(5), peer.reader.read_frame())
        .await
        .expect("route exit fences old stream within original budget");
    if let Ok(frame) = fenced {
        assert!(matches!(
            PushgoWireProfile::new()
                .decode_server_frame(&frame)
                .unwrap(),
            DecodedServerFrame::GoAway(_) | DecodedServerFrame::Error { .. }
        ));
    }
    assert_eq!(snapshot(&f, &id).await, before);
    let pulled = f.store.pull(&f.device, Some(&id)).await.unwrap();
    let item = &pulled["items"][0];
    assert_eq!(item["delivery_id"], id);
    assert_eq!(item["payload"]["message_id"], frozen.data["message_id"]);
    assert_eq!(item["payload"]["body"], frozen.data["body"]);
    assert_eq!(item["payload"]["sent_at"], frozen.data["sent_at"]);
    assert_eq!(f.store.ack(&f.device, vec![id]).await.unwrap(), 1);
    f.wait_consumed().await;
    drop(peer);
    listener.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    assert_eq!(runtime.available_owned_slots(), 4096);
    f.close().await;
}
