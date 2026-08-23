use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use mqttbytes::v5::{
    ConnectProperties, LastWill, PubAck, PubAckReason, Publish, PublishProperties, SubscribeFilter,
    SubscribeProperties, UnsubscribeProperties, WillProperties,
};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

use super::*;
use crate::{
    api::ChannelId,
    app::{AppState, AuthMode, DeviceOperationGuards, PrivateTransportProfile},
    dispatch::DispatchChannels,
    mqtt::{MqttConfig, MqttPublishDedupe},
    private::{PrivateConfig, PrivateState},
    routing::{DeviceRegistry, DeviceRouteRecord},
    runtime_config::GatewayRuntimeProfile,
    runtime_counters::RuntimeCounterCollector,
    services::{ChannelCommandSource, MessageSendCommand, send_message},
    storage::{DeviceRouteRecordRow, MaintenanceCleanupConfig, Platform, Storage},
};

struct MqttFlowTestContext {
    _dir: TempDir,
    state: Arc<AppState>,
    private: Arc<PrivateState>,
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl MqttFlowTestContext {
    async fn new() -> Self {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("gateway-mqtt-flow.sqlite");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let store = Storage::new(Some(db_url.as_str()))
            .await
            .expect("storage should initialize");
        let runtime_counters = RuntimeCounterCollector::spawn(store.clone());
        let registry = Arc::new(DeviceRegistry::new());
        let private = Arc::new(PrivateState::new(
            store.clone(),
            test_private_config(),
            Arc::clone(&registry),
            Arc::clone(&runtime_counters),
        ));
        let (dispatch, _receivers) = DispatchChannels::new();
        let state = Arc::new(AppState {
            dispatch,
            auth: AuthMode::Disabled,
            private_channel_enabled: true,
            public_base_url: None,
            device_registry: registry,
            device_operation_guards: Arc::new(DeviceOperationGuards::default()),
            runtime_counters,
            private_transport_profile: PrivateTransportProfile {
                quic_enabled: false,
                quic_port: None,
                tcp_enabled: false,
                tcp_port: 5223,
                wss_enabled: false,
                wss_port: 443,
                wss_path: Arc::from("/private/ws"),
                ws_subprotocol: Arc::from("pushgo-private.v1"),
                mqtt_enabled: true,
                mqtt_port: Some(1883),
                mqtt_tls_required: false,
            },
            private: Some(Arc::clone(&private)),
            store,
            mcp: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test MQTT listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let runtime = MqttRuntime {
            state: Arc::clone(&state),
            private: Arc::clone(&private),
            config: MqttConfig {
                bind_addr: addr.to_string(),
                advertised_port: addr.port(),
                max_packet_bytes: 32 * 1024,
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
            },
            publish_dedupe: MqttPublishDedupe::new(),
        };
        let server = tokio::spawn(async move {
            let _ = listener::serve_mqtt_listener(runtime, listener, addr, None).await;
        });
        Self {
            _dir: dir,
            state,
            private,
            addr,
            server: Some(server),
        }
    }

    async fn restore_private_route(&self, device_key: &str) {
        let route = DeviceRouteRecord {
            platform: Platform::MQTT,
            channel_type: DeviceChannelType::Private,
            provider_token: None,
            updated_at: chrono::Utc::now().timestamp(),
        };
        self.state
            .device_registry
            .restore_route(device_key, route.clone())
            .expect("route restore should succeed");
        self.state
            .store
            .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
                device_key, &route,
            ))
            .await
            .expect("route should persist");
    }

    async fn create_channel(&self, device_key: &str, password: &str) -> String {
        crate::services::subscribe_private_device_to_channel(
            &self.state,
            ChannelSubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: None,
                channel_name: Some(format!("mqtt-flow-{device_key}")),
                password: password.to_string(),
                source: ChannelCommandSource::Mqtt,
                allow_create_channel: true,
            },
        )
        .await
        .expect("channel should be created")
        .channel_id
    }

    async fn shutdown(mut self) {
        self.private.begin_shutdown();
        let server = self.server.take().expect("MQTT listener task should exist");
        timeout(Duration::from_secs(2), server)
            .await
            .expect("MQTT listener should stop within the shutdown deadline")
            .expect("MQTT listener task should not panic");
    }
}

impl Drop for MqttFlowTestContext {
    fn drop(&mut self) {
        self.private.begin_shutdown();
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

fn test_private_config() -> PrivateConfig {
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
        max_pending_per_device: 16,
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
        online_fast_path_enabled: true,
        maintenance_cleanup: MaintenanceCleanupConfig::default(),
        gateway_token: None,
    }
    .normalized()
}

async fn connect_client(addr: SocketAddr, device_key: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("MQTT stream should connect");
    let connect = connect_with_device_type(device_key, "subscribe");
    write_client_packet(&mut stream, ClientPacket::Connect(connect)).await;
    match read_server_packet(&mut stream).await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    stream
}

async fn connect_publish_client(addr: SocketAddr, client_id: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type(client_id, "publish")),
    )
    .await;
    match read_server_packet(&mut stream).await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    stream
}

fn connect_with_device_type(client_id: &str, device_type: &str) -> Connect {
    let mut connect = Connect::new(client_id);
    connect.properties = Some(ConnectProperties {
        session_expiry_interval: None,
        receive_maximum: None,
        max_packet_size: None,
        topic_alias_max: None,
        request_response_info: None,
        request_problem_info: None,
        user_properties: vec![(
            MQTT_DEVICE_TYPE_PROPERTY.to_string(),
            device_type.to_string(),
        )],
        authentication_method: None,
        authentication_data: None,
    });
    connect
}

fn connect_with_will(
    client_id: &str,
    device_type: &str,
    topic: String,
    password: Option<&str>,
    payload: Vec<u8>,
    qos: QoS,
    retain: bool,
) -> Connect {
    let mut connect = connect_with_device_type(client_id, device_type);
    let mut will = LastWill::new(topic, payload, qos, retain);
    will.properties = Some(WillProperties {
        delay_interval: None,
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        content_type: Some("application/json".to_string()),
        response_topic: None,
        correlation_data: None,
        user_properties: password
            .map(|password| vec![(MQTT_PASSWORD_PROPERTY.to_string(), password.to_string())])
            .unwrap_or_default(),
    });
    connect.last_will = Some(will);
    connect
}

fn publish_properties(password: Option<&str>) -> PublishProperties {
    PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: password
            .map(|password| vec![(MQTT_PASSWORD_PROPERTY.to_string(), password.to_string())])
            .unwrap_or_default(),
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".to_string()),
    }
}

fn message_publish_payload(data: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": "message",
        "data": data,
    }))
    .expect("message publish envelope should encode")
}

fn entity_publish_payload(model_type: &str, action: &str, data: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": model_type,
        "action": action,
        "data": data,
    }))
    .expect("entity publish envelope should encode")
}

fn connect_with_device_type_and_keep_alive(
    client_id: &str,
    device_type: &str,
    keep_alive: u16,
) -> Connect {
    let mut connect = connect_with_device_type(client_id, device_type);
    connect.keep_alive = keep_alive;
    connect
}

enum ClientPacket {
    Connect(Connect),
    Publish(Publish),
    PubAck(PubAck),
    Subscribe(Subscribe),
    Unsubscribe(Unsubscribe),
    Disconnect(Disconnect),
}

async fn write_client_packet(stream: &mut TcpStream, packet: ClientPacket) {
    let mut out = BytesMut::new();
    match packet {
        ClientPacket::Connect(packet) => packet.write(&mut out),
        ClientPacket::Publish(packet) => packet.write(&mut out),
        ClientPacket::PubAck(packet) => packet.write(&mut out),
        ClientPacket::Subscribe(packet) => packet.write(&mut out),
        ClientPacket::Unsubscribe(packet) => packet.write(&mut out),
        ClientPacket::Disconnect(packet) => packet.write(&mut out),
    }
    .expect("packet should encode");
    stream.write_all(&out).await.expect("packet should write");
}

async fn read_server_packet(stream: &mut TcpStream) -> Packet {
    read_server_packet_labeled(stream, "server packet").await
}

async fn read_server_packet_labeled(stream: &mut TcpStream, label: &str) -> Packet {
    read_server_packet_with_timeout(stream, Duration::from_secs(2))
        .await
        .unwrap_or_else(|| panic!("{label} should arrive"))
}

async fn read_server_packet_with_timeout(
    stream: &mut TcpStream,
    read_timeout: Duration,
) -> Option<Packet> {
    let mut buffer = BytesMut::with_capacity(4096);
    loop {
        match v5::read(&mut buffer, 32 * 1024) {
            Ok(packet) => return Some(packet),
            Err(mqttbytes::Error::InsufficientBytes(_)) => {
                let mut tmp = [0u8; 4096];
                let Ok(read_result) = timeout(read_timeout, stream.read(&mut tmp)).await else {
                    return None;
                };
                let n = read_result.expect("server packet read should succeed");
                assert!(n > 0, "server closed connection before packet");
                buffer.extend_from_slice(&tmp[..n]);
            }
            Err(err) => panic!("server packet should decode: {err:?}"),
        }
    }
}

static MQTT_TEST_DEVICE_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn setup_connected_channel() -> (MqttFlowTestContext, TcpStream, String, String, String) {
    let ctx = MqttFlowTestContext::new().await;
    let id = MQTT_TEST_DEVICE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let device_key = format!("mqtt-negative-device-{id}");
    let channel_password = "mqtt-pass-987";
    ctx.restore_private_route(device_key.as_str()).await;
    let channel_id = ctx
        .create_channel(device_key.as_str(), channel_password)
        .await;
    let stream = connect_client(ctx.addr, device_key.as_str()).await;
    (
        ctx,
        stream,
        device_key,
        channel_id,
        channel_password.to_string(),
    )
}

#[tokio::test]
async fn shutdown_closes_listener_and_authenticated_sessions() {
    let ctx = MqttFlowTestContext::new().await;
    let mut stream = connect_publish_client(ctx.addr, "mqtt-shutdown-client").await;

    ctx.shutdown().await;

    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("shutdown should close the client stream promptly")
        .expect("client read should complete");
    assert_eq!(read, 0, "server must close established MQTT sessions");
}

async fn subscribe_stream_to_channel(
    stream: &mut TcpStream,
    channel_id: &str,
    channel_password: &str,
    pkid: u16,
) {
    let mut subscribe = Subscribe::new(MqttMessageTopic::format(channel_id), QoS::AtLeastOnce);
    subscribe.pkid = pkid;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(stream, ClientPacket::Subscribe(subscribe)).await;
    loop {
        match read_server_packet_labeled(stream, "SUBACK").await {
            Packet::SubAck(suback) => {
                assert_eq!(suback.pkid, pkid);
                assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS1]);
                break;
            }
            Packet::Publish(publish) => {
                write_client_packet(stream, ClientPacket::PubAck(PubAck::new(publish.pkid))).await;
            }
            packet => panic!("expected SUBACK, got {packet:?}"),
        }
    }
}

async fn read_publish_with_title(stream: &mut TcpStream, expected_title: &str) -> Publish {
    loop {
        let publish = match read_server_packet_labeled(stream, "downlink PUBLISH").await {
            Packet::Publish(publish) => publish,
            packet => panic!("expected downlink PUBLISH, got {packet:?}"),
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&publish.payload).expect("downlink should be JSON");
        let title = payload
            .get("data")
            .and_then(|data| data.get("title"))
            .and_then(|v| v.as_str());
        if title == Some(expected_title) {
            return publish;
        }
        write_client_packet(stream, ClientPacket::PubAck(PubAck::new(publish.pkid))).await;
    }
}

#[tokio::test]
async fn mqtt_flow_covers_connect_subscribe_publish_receive_ack_unsubscribe_disconnect() {
    let ctx = MqttFlowTestContext::new().await;
    let device_key = "mqtt-flow-device";
    let channel_password = "mqtt-pass-123";
    ctx.restore_private_route(device_key).await;
    let channel_id = ctx.create_channel(device_key, channel_password).await;
    let mut stream = connect_client(ctx.addr, device_key).await;

    let mut subscribe = Subscribe::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    subscribe.pkid = 7;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe)).await;
    match read_server_packet_labeled(&mut stream, "SUBACK").await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 7);
            assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS1]);
        }
        packet => panic!("expected SUBACK, got {packet:?}"),
    }

    let inbound_payload = serde_json::json!({
        "title": "MQTT inbound",
        "body": "published by mqtt",
        "tags": ["mqtt", "flow"],
        "metadata": {"source": "mqtt-flow-test"}
    });
    let device_id = derive_private_device_id(device_key);
    let outbox_before_publish = ctx
        .state
        .store
        .list_private_outbox(device_id, 16)
        .await
        .expect("outbox should list")
        .len();
    let mut inbound = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        message_publish_payload(inbound_payload),
    );
    inbound.pkid = 8;
    inbound.properties = Some(PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".to_string()),
    });
    write_client_packet(&mut stream, ClientPacket::Publish(inbound)).await;
    match read_server_packet_labeled(&mut stream, "PUBACK inbound publish").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 8);
            assert_eq!(puback.reason, PubAckReason::Success);
        }
        packet => panic!("expected PUBACK, got {packet:?}"),
    }
    assert_eq!(
        ctx.state
            .store
            .list_private_outbox(device_id, 16)
            .await
            .expect("outbox should list")
            .len(),
        outbox_before_publish + 1,
        "accepted MQTT downlink should be durable until the receiver sends PUBACK"
    );
    write_client_packet(
        &mut stream,
        ClientPacket::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            properties: None,
        }),
    )
    .await;
    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { !private.hub.is_online(device_id) }
    })
    .await;

    let mut stream = connect_client(ctx.addr, device_key).await;
    let mut subscribe = Subscribe::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    subscribe.pkid = 10;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe)).await;
    loop {
        match read_server_packet_labeled(&mut stream, "second SUBACK").await {
            Packet::SubAck(suback) => {
                assert_eq!(suback.pkid, 10);
                assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS1]);
                break;
            }
            Packet::Publish(publish) => {
                write_client_packet(&mut stream, ClientPacket::PubAck(PubAck::new(publish.pkid)))
                    .await;
            }
            packet => panic!("expected second SUBACK, got {packet:?}"),
        }
    }

    let ack_ok_before_downlink = ctx.private.metrics.snapshot().frames_ack_ok;
    send_message(
        &ctx.state,
        MessageSendCommand {
            channel_id: channel_id.clone(),
            password: channel_password.to_string(),
            op_id: None,
            thing_id: None,
            occurred_at: None,
            title: "MQTT downlink".to_string(),
            body: Some("received by mqtt".to_string()),
            severity: None,
            ttl: None,
            url: None,
            images: Vec::new(),
            ciphertext: None,
            tags: vec!["downlink".to_string()],
            metadata: serde_json::Map::new(),
            source: crate::delivery_core::source::IngressSource::HttpMessage,
        },
    )
    .await
    .expect("message send should succeed");

    let mut downlink = None;
    let mut acknowledged_downlinks = 0usize;
    while downlink.is_none() {
        let publish = match read_server_packet_labeled(&mut stream, "downlink PUBLISH").await {
            Packet::Publish(publish) => publish,
            packet => panic!("expected downlink PUBLISH, got {packet:?}"),
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&publish.payload).expect("downlink should be JSON");
        let title = payload
            .get("data")
            .and_then(|data| data.get("title"))
            .and_then(|v| v.as_str());
        if title == Some("MQTT downlink") {
            downlink = Some((publish, payload));
        } else {
            write_client_packet(&mut stream, ClientPacket::PubAck(PubAck::new(publish.pkid))).await;
            acknowledged_downlinks = acknowledged_downlinks.saturating_add(1);
        }
    }
    let (downlink, delivery) = downlink.expect("downlink should be found");
    assert_eq!(
        downlink.topic,
        MqttMessageTopic::format(channel_id.as_str())
    );
    assert_eq!(downlink.qos, QoS::AtLeastOnce);
    assert_ne!(downlink.pkid, 0);
    assert_eq!(
        delivery.get("schema").and_then(|v| v.as_str()),
        Some("pushgo.mqtt.delivery.v1")
    );
    assert_eq!(
        delivery.get("type").and_then(|v| v.as_str()),
        Some("message")
    );
    assert_eq!(
        delivery
            .get("data")
            .and_then(|data| data.get("title"))
            .and_then(|v| v.as_str()),
        Some("MQTT downlink")
    );
    let delivery_id = delivery
        .get("delivery_id")
        .and_then(|v| v.as_str())
        .expect("delivery_id should exist")
        .to_string();
    assert!(
        ctx.state
            .store
            .load_private_outbox_entry(device_id, delivery_id.as_str())
            .await
            .expect("outbox should load")
            .is_some(),
        "MQTT QoS1 downlink must remain in the durable outbox until PUBACK"
    );

    write_client_packet(
        &mut stream,
        ClientPacket::PubAck(PubAck::new(downlink.pkid)),
    )
    .await;
    acknowledged_downlinks = acknowledged_downlinks.saturating_add(1);
    while let Some(Packet::Publish(extra)) =
        read_server_packet_with_timeout(&mut stream, Duration::from_millis(100)).await
    {
        write_client_packet(&mut stream, ClientPacket::PubAck(PubAck::new(extra.pkid))).await;
        acknowledged_downlinks = acknowledged_downlinks.saturating_add(1);
    }
    let terminal = ctx
        .state
        .store
        .load_private_outbox_entry(device_id, delivery_id.as_str())
        .await
        .expect("outbox should load")
        .expect("PUBACK should retain a replay-suppression tombstone");
    assert_eq!(terminal.status, crate::storage::OUTBOX_STATUS_ACKED);
    let active = ctx
        .state
        .store
        .list_private_outbox(device_id, 128)
        .await
        .expect("active outbox should load");
    assert!(
        active.iter().all(|entry| entry.delivery_id != delivery_id),
        "the PUBACK tombstone must not remain in the active outbox"
    );

    let mut unsubscribe = Unsubscribe::new(MqttMessageTopic::format(channel_id.as_str()));
    unsubscribe.pkid = 9;
    unsubscribe.properties = Some(UnsubscribeProperties {
        user_properties: Vec::new(),
    });
    write_client_packet(&mut stream, ClientPacket::Unsubscribe(unsubscribe)).await;
    match read_server_packet_labeled(&mut stream, "UNSUBACK").await {
        Packet::UnsubAck(unsuback) => {
            assert_eq!(unsuback.pkid, 9);
            assert_eq!(unsuback.reasons, vec![UnsubAckReason::Success]);
        }
        packet => panic!("expected UNSUBACK, got {packet:?}"),
    }
    let subscribed = ctx
        .state
        .store
        .list_private_subscribed_channels_for_device(device_id)
        .await
        .expect("subscriptions should load");
    let parsed_channel = ChannelId::parse(channel_id.as_str())
        .expect("channel id should parse")
        .into_inner();
    assert!(!subscribed.contains(&parsed_channel));

    write_client_packet(
        &mut stream,
        ClientPacket::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            properties: None,
        }),
    )
    .await;
    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { !private.hub.is_online(device_id) }
    })
    .await;

    let metrics = ctx.private.metrics.snapshot();
    assert_eq!(metrics.mqtt_connect_success, 2);
    assert_eq!(metrics.mqtt_subscribe_success, 2);
    assert_eq!(metrics.mqtt_publish_success, 1);
    assert!(metrics.mqtt_downlink_sent >= 1);
    assert_eq!(metrics.mqtt_unsubscribe_success, 1);
    assert!(
        metrics.frames_ack_ok.saturating_sub(ack_ok_before_downlink)
            >= acknowledged_downlinks as u64
    );
}

#[tokio::test]
async fn mqtt_subscribe_connect_registers_and_assigns_device_key() {
    let ctx = MqttFlowTestContext::new().await;
    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");

    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type("", "SUBSCRIBE")),
    )
    .await;

    match read_server_packet(&mut stream).await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::Success);
            let assigned = connack
                .properties
                .and_then(|props| props.assigned_client_identifier)
                .expect("subscribe connect should assign client id");
            let route = ctx
                .state
                .device_registry
                .get(assigned.as_str())
                .expect("assigned device should be registered");
            assert_eq!(route.platform, Platform::MQTT);
            assert_eq!(route.channel_type, DeviceChannelType::Private);
            let row = ctx
                .state
                .store
                .load_device_routes()
                .await
                .expect("routes should load")
                .into_iter()
                .find(|row| row.device_key == assigned)
                .expect("assigned device route should persist");
            assert_eq!(row.platform, "mqtt");
        }
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    let metrics = ctx.private.metrics.snapshot();
    assert_eq!(metrics.mqtt_connect_attempts, 1);
    assert_eq!(metrics.mqtt_connect_success, 1);
}

#[tokio::test]
async fn mqtt_subscribe_connect_reuses_existing_device_key_without_reassignment() {
    let ctx = MqttFlowTestContext::new().await;
    let device_key = "mqtt-existing-device-key";
    ctx.restore_private_route(device_key).await;
    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");

    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type(device_key, "subscribe")),
    )
    .await;

    match read_server_packet_labeled(&mut stream, "CONNACK").await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::Success);
            let props = connack.properties.expect("connack should include props");
            assert!(
                props.assigned_client_identifier.is_none(),
                "existing MQTT device key should not be reassigned"
            );
            assert_eq!(props.session_expiry_interval, Some(0));
        }
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    assert!(
        ctx.private
            .hub
            .is_online(derive_private_device_id(device_key))
    );
    let rows = ctx
        .state
        .store
        .load_device_routes()
        .await
        .expect("routes should load");
    assert_eq!(
        rows.iter()
            .filter(|row| row.device_key == device_key)
            .count(),
        1
    );
}

#[tokio::test]
async fn mqtt_connack_advertises_server_keep_alive_when_client_is_unbounded() {
    let ctx = MqttFlowTestContext::new().await;
    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");

    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type_and_keep_alive("", "subscribe", 0)),
    )
    .await;

    match read_server_packet_labeled(&mut stream, "CONNACK").await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::Success);
            let props = connack
                .properties
                .expect("connack should include properties");
            assert_eq!(props.session_expiry_interval, Some(0));
            assert_eq!(props.receive_max, Some(MAX_INFLIGHT as u16));
            assert_eq!(props.topic_alias_max, Some(0));
            assert_eq!(props.server_keep_alive, Some(MQTT_SERVER_KEEP_ALIVE_SECS));
        }
        packet => panic!("expected CONNACK, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_publish_connect_is_temporary_and_cannot_subscribe() {
    let ctx = MqttFlowTestContext::new().await;
    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");

    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type("", "publish")),
    )
    .await;
    match read_server_packet(&mut stream).await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::Success);
            assert!(
                connack
                    .properties
                    .and_then(|props| props.assigned_client_identifier)
                    .is_none(),
                "publish-only connection should not receive a device key"
            );
        }
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    assert!(
        ctx.state
            .store
            .load_device_routes()
            .await
            .expect("routes should load")
            .is_empty(),
        "publish-only connect should not persist a device route"
    );

    let mut subscribe = Subscribe::new("57T3MX35F1YJ0JRNEHXW6NX544", QoS::AtLeastOnce);
    subscribe.pkid = 77;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            "mqtt-pass-987".to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe)).await;
    match read_server_packet(&mut stream).await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 77);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::NotAuthorized]
            );
        }
        packet => panic!("expected SUBACK rejection, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_publish_connect_ignores_client_id_and_can_publish_without_route() {
    let ctx = MqttFlowTestContext::new().await;
    let owner_key = "mqtt-publish-only-channel-owner";
    let channel_password = "mqtt-pub-only-pass";
    ctx.restore_private_route(owner_key).await;
    let channel_id = ctx.create_channel(owner_key, channel_password).await;
    let mut stream = connect_publish_client(ctx.addr, "publish-client-id-is-ignored").await;

    assert!(
        ctx.state
            .store
            .load_device_routes()
            .await
            .expect("routes should load")
            .iter()
            .all(|row| row.device_key != "publish-client-id-is-ignored"),
        "publish-only client id must not be persisted"
    );

    let mut publish = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        message_publish_payload(serde_json::json!({"title":"publish-only message"})),
    );
    publish.pkid = 41;
    publish.properties = Some(publish_properties(Some(channel_password)));
    write_client_packet(&mut stream, ClientPacket::Publish(publish)).await;

    match read_server_packet_labeled(&mut stream, "publish-only PUBACK").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 41);
            assert_eq!(puback.reason, PubAckReason::Success);
            let props = puback.properties.expect("puback should include props");
            assert!(
                user_property(&props.user_properties, "pushgo-op-id").is_some(),
                "successful mqtt publish should return gateway op_id"
            );
        }
        packet => panic!("expected PUBACK success, got {packet:?}"),
    }
    assert_eq!(ctx.private.metrics.snapshot().mqtt_publish_success, 1);
}

#[tokio::test]
async fn mqtt_publish_accepts_event_and_thing_payloads() {
    let ctx = MqttFlowTestContext::new().await;
    let owner_key = "mqtt-entity-publish-channel-owner";
    let channel_password = "mqtt-entity-pass";
    ctx.restore_private_route(owner_key).await;
    let channel_id = ctx.create_channel(owner_key, channel_password).await;
    let mut stream = connect_publish_client(ctx.addr, "entity-publisher").await;

    let cases = [
        (
            42,
            entity_publish_payload(
                "event",
                "create",
                serde_json::json!({
                    "event_time": 1_710_000_000,
                    "title": "event over mqtt"
                }),
            ),
        ),
        (
            43,
            entity_publish_payload(
                "thing",
                "update",
                serde_json::json!({
                    "thing_id": "thing-1",
                    "observed_at": 1_710_000_001,
                    "title": "thing over mqtt"
                }),
            ),
        ),
    ];

    for (pkid, payload) in cases {
        let mut publish = Publish::new(
            MqttMessageTopic::format(channel_id.as_str()),
            QoS::AtLeastOnce,
            payload,
        );
        publish.pkid = pkid;
        publish.properties = Some(publish_properties(Some(channel_password)));
        write_client_packet(&mut stream, ClientPacket::Publish(publish)).await;

        match read_server_packet_labeled(&mut stream, "entity publish PUBACK").await {
            Packet::PubAck(puback) => {
                assert_eq!(puback.pkid, pkid);
                assert_eq!(puback.reason, PubAckReason::Success);
            }
            packet => panic!("expected PUBACK success, got {packet:?}"),
        }
    }
}

#[tokio::test]
async fn mqtt_qos1_publish_without_op_id_uses_short_window_fallback_dedupe() {
    let ctx = MqttFlowTestContext::new().await;
    let receiver_key = "mqtt-fallback-dedupe-receiver";
    let channel_password = "mqtt-fallback-dedupe-pass";
    ctx.restore_private_route(receiver_key).await;
    let channel_id = ctx.create_channel(receiver_key, channel_password).await;
    let mut receiver = connect_client(ctx.addr, receiver_key).await;
    subscribe_stream_to_channel(&mut receiver, channel_id.as_str(), channel_password, 92).await;

    let mut publisher = connect_publish_client(ctx.addr, "mqtt-fallback-dedupe-publisher").await;
    let payload = message_publish_payload(serde_json::json!({
        "title": "fallback dedupe title",
        "body": "same MQTT QoS1 publish body"
    }));
    for _ in 0..2 {
        let mut publish = Publish::new(
            MqttMessageTopic::format(channel_id.as_str()),
            QoS::AtLeastOnce,
            payload.clone(),
        );
        publish.pkid = 42;
        publish.properties = Some(publish_properties(Some(channel_password)));
        write_client_packet(&mut publisher, ClientPacket::Publish(publish)).await;
        match read_server_packet_labeled(&mut publisher, "fallback dedupe PUBACK").await {
            Packet::PubAck(puback) => {
                assert_eq!(puback.pkid, 42);
                assert_eq!(puback.reason, PubAckReason::Success);
            }
            packet => panic!("expected PUBACK success, got {packet:?}"),
        }
    }

    let first = read_publish_with_title(&mut receiver, "fallback dedupe title").await;
    write_client_packet(&mut receiver, ClientPacket::PubAck(PubAck::new(first.pkid))).await;
    assert!(
        read_server_packet_with_timeout(&mut receiver, Duration::from_millis(250))
            .await
            .is_none(),
        "duplicate QoS1 publish without op_id should not enqueue a second message"
    );

    let mut changed_packet = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        payload,
    );
    changed_packet.pkid = 43;
    changed_packet.properties = Some(publish_properties(Some(channel_password)));
    write_client_packet(&mut publisher, ClientPacket::Publish(changed_packet)).await;
    match read_server_packet_labeled(&mut publisher, "changed packet PUBACK").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 43);
            assert_eq!(puback.reason, PubAckReason::Success);
        }
        packet => panic!("expected PUBACK success, got {packet:?}"),
    }
    let second = read_publish_with_title(&mut receiver, "fallback dedupe title").await;
    write_client_packet(
        &mut receiver,
        ClientPacket::PubAck(PubAck::new(second.pkid)),
    )
    .await;
}

#[tokio::test]
async fn mqtt_qos1_fallback_dedupe_clears_failed_publish_for_retry() {
    let ctx = MqttFlowTestContext::new().await;
    let receiver_key = "mqtt-fallback-dedupe-retry-receiver";
    let channel_password = "mqtt-fallback-dedupe-retry-pass";
    ctx.restore_private_route(receiver_key).await;
    let channel_id = ctx.create_channel(receiver_key, channel_password).await;
    let mut receiver = connect_client(ctx.addr, receiver_key).await;
    subscribe_stream_to_channel(&mut receiver, channel_id.as_str(), channel_password, 93).await;

    let mut publisher =
        connect_publish_client(ctx.addr, "mqtt-fallback-dedupe-retry-publisher").await;
    let payload = message_publish_payload(serde_json::json!({
        "title": "fallback retry title"
    }));
    let mut failed = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        payload.clone(),
    );
    failed.pkid = 44;
    failed.properties = Some(publish_properties(Some("wrong-password")));
    write_client_packet(&mut publisher, ClientPacket::Publish(failed)).await;
    match read_server_packet_labeled(&mut publisher, "failed fallback PUBACK").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 44);
            assert_eq!(puback.reason, PubAckReason::NotAuthorized);
        }
        packet => panic!("expected PUBACK auth failure, got {packet:?}"),
    }

    let mut retried = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        payload,
    );
    retried.pkid = 44;
    retried.properties = Some(publish_properties(Some(channel_password)));
    write_client_packet(&mut publisher, ClientPacket::Publish(retried)).await;
    match read_server_packet_labeled(&mut publisher, "retried fallback PUBACK").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 44);
            assert_eq!(puback.reason, PubAckReason::Success);
        }
        packet => panic!("expected PUBACK retry success, got {packet:?}"),
    }
    let publish = read_publish_with_title(&mut receiver, "fallback retry title").await;
    write_client_packet(
        &mut receiver,
        ClientPacket::PubAck(PubAck::new(publish.pkid)),
    )
    .await;
}

#[tokio::test]
async fn mqtt_subscribe_device_will_is_sent_on_abnormal_disconnect_to_any_channel() {
    let ctx = MqttFlowTestContext::new().await;
    let receiver_key = "mqtt-will-receiver";
    let will_owner_key = "mqtt-will-owner";
    let channel_password = "mqtt-will-pass";
    ctx.restore_private_route(receiver_key).await;
    ctx.restore_private_route(will_owner_key).await;
    let channel_id = ctx.create_channel(receiver_key, channel_password).await;
    let mut receiver = connect_client(ctx.addr, receiver_key).await;
    subscribe_stream_to_channel(&mut receiver, channel_id.as_str(), channel_password, 91).await;

    let mut will_owner = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut will_owner,
        ClientPacket::Connect(connect_with_will(
            will_owner_key,
            "subscribe",
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password),
            message_publish_payload(serde_json::json!({
                "title": "will abnormal",
                "body": "sent on socket close"
            })),
            QoS::AtLeastOnce,
            false,
        )),
    )
    .await;
    match read_server_packet_labeled(&mut will_owner, "will owner CONNACK").await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    drop(will_owner);

    let publish = read_publish_with_title(&mut receiver, "will abnormal").await;
    assert_eq!(publish.topic, MqttMessageTopic::format(channel_id.as_str()));
    assert_eq!(publish.qos, QoS::AtLeastOnce);
    write_client_packet(
        &mut receiver,
        ClientPacket::PubAck(PubAck::new(publish.pkid)),
    )
    .await;

    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { private.metrics.snapshot().mqtt_will_sent == 1 }
    })
    .await;
    let metrics = ctx.private.metrics.snapshot();
    assert_eq!(metrics.mqtt_will_sent, 1);
    assert_eq!(metrics.mqtt_will_failures, 0);
    assert_eq!(metrics.mqtt_will_rejected, 0);
}

#[tokio::test]
async fn mqtt_will_is_not_sent_on_normal_disconnect() {
    let ctx = MqttFlowTestContext::new().await;
    let receiver_key = "mqtt-will-normal-receiver";
    let will_owner_key = "mqtt-will-normal-owner";
    let channel_password = "mqtt-will-normal-pass";
    ctx.restore_private_route(receiver_key).await;
    ctx.restore_private_route(will_owner_key).await;
    let channel_id = ctx.create_channel(receiver_key, channel_password).await;
    let mut receiver = connect_client(ctx.addr, receiver_key).await;
    subscribe_stream_to_channel(&mut receiver, channel_id.as_str(), channel_password, 92).await;

    let mut will_owner = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut will_owner,
        ClientPacket::Connect(connect_with_will(
            will_owner_key,
            "subscribe",
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password),
            message_publish_payload(serde_json::json!({"title": "will normal"})),
            QoS::AtLeastOnce,
            false,
        )),
    )
    .await;
    match read_server_packet_labeled(&mut will_owner, "will owner CONNACK").await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    write_client_packet(
        &mut will_owner,
        ClientPacket::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            properties: None,
        }),
    )
    .await;

    while let Some(packet) =
        read_server_packet_with_timeout(&mut receiver, Duration::from_millis(250)).await
    {
        let Packet::Publish(publish) = packet else {
            panic!("expected optional PUBLISH, got {packet:?}");
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&publish.payload).expect("downlink should be JSON");
        assert_ne!(
            payload
                .get("data")
                .and_then(|data| data.get("title"))
                .and_then(|v| v.as_str()),
            Some("will normal"),
            "normal DISCONNECT must not publish the will"
        );
        write_client_packet(
            &mut receiver,
            ClientPacket::PubAck(PubAck::new(publish.pkid)),
        )
        .await;
    }
    assert_eq!(ctx.private.metrics.snapshot().mqtt_will_sent, 0);
}

#[tokio::test]
async fn mqtt_disconnect_with_will_reason_sends_will() {
    let ctx = MqttFlowTestContext::new().await;
    let receiver_key = "mqtt-will-reason-receiver";
    let will_owner_key = "mqtt-will-reason-owner";
    let channel_password = "mqtt-will-reason-pass";
    ctx.restore_private_route(receiver_key).await;
    ctx.restore_private_route(will_owner_key).await;
    let channel_id = ctx.create_channel(receiver_key, channel_password).await;
    let mut receiver = connect_client(ctx.addr, receiver_key).await;
    subscribe_stream_to_channel(&mut receiver, channel_id.as_str(), channel_password, 93).await;

    let mut will_owner = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut will_owner,
        ClientPacket::Connect(connect_with_will(
            will_owner_key,
            "subscribe",
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password),
            message_publish_payload(serde_json::json!({"title": "will by disconnect reason"})),
            QoS::AtLeastOnce,
            false,
        )),
    )
    .await;
    match read_server_packet_labeled(&mut will_owner, "will owner CONNACK").await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    will_owner
        .write_all(&[0xE0, 0x02, 0x04, 0x00])
        .await
        .expect("DisconnectWithWillMessage should write");

    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move {
            let metrics = private.metrics.snapshot();
            metrics.mqtt_will_sent + metrics.mqtt_will_failures > 0
        }
    })
    .await;
    assert_eq!(ctx.private.metrics.snapshot().mqtt_will_failures, 0);
    let publish = read_publish_with_title(&mut receiver, "will by disconnect reason").await;
    write_client_packet(
        &mut receiver,
        ClientPacket::PubAck(PubAck::new(publish.pkid)),
    )
    .await;
    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { private.metrics.snapshot().mqtt_will_sent == 1 }
    })
    .await;
}

#[tokio::test]
async fn mqtt_will_connect_rejects_publish_only_and_invalid_will_contract() {
    let ctx = MqttFlowTestContext::new().await;
    let owner_key = "mqtt-will-validation-owner";
    let channel_password = "mqtt-will-validation-pass";
    ctx.restore_private_route(owner_key).await;
    let channel_id = ctx.create_channel(owner_key, channel_password).await;
    let valid_payload = message_publish_payload(serde_json::json!({"title": "will validation"}));
    let unsupported_payload = serde_json::to_vec(&serde_json::json!({
        "type": "event",
        "data": {"title": "unsupported"}
    }))
    .expect("unsupported payload should encode");

    let cases = vec![
        (
            connect_with_will(
                "",
                "publish",
                MqttMessageTopic::format(channel_id.as_str()),
                Some(channel_password),
                valid_payload.clone(),
                QoS::AtLeastOnce,
                false,
            ),
            ConnectReturnCode::ImplementationSpecificError,
            "mqtt_will_publish_only_not_supported",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                MqttMessageTopic::format(channel_id.as_str()),
                Some(channel_password),
                valid_payload.clone(),
                QoS::AtMostOnce,
                false,
            ),
            ConnectReturnCode::QoSNotSupported,
            "mqtt_will_qos_required",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                MqttMessageTopic::format(channel_id.as_str()),
                Some(channel_password),
                valid_payload.clone(),
                QoS::AtLeastOnce,
                true,
            ),
            ConnectReturnCode::RetainNotSupported,
            "mqtt_will_retain_not_supported",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                format!("pushgo/{channel_id}/messages"),
                Some(channel_password),
                valid_payload.clone(),
                QoS::AtLeastOnce,
                false,
            ),
            ConnectReturnCode::TopicNameInvalid,
            "mqtt_will_topic_invalid",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                MqttMessageTopic::format(channel_id.as_str()),
                None,
                valid_payload.clone(),
                QoS::AtLeastOnce,
                false,
            ),
            ConnectReturnCode::BadUserNamePassword,
            "mqtt_will_password_required",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                MqttMessageTopic::format(channel_id.as_str()),
                Some("wrong-will-pass"),
                valid_payload,
                QoS::AtLeastOnce,
                false,
            ),
            ConnectReturnCode::BadUserNamePassword,
            "mqtt_will_channel_not_authorized",
        ),
        (
            connect_with_will(
                owner_key,
                "subscribe",
                MqttMessageTopic::format(channel_id.as_str()),
                Some(channel_password),
                unsupported_payload,
                QoS::AtLeastOnce,
                false,
            ),
            ConnectReturnCode::PayloadFormatInvalid,
            "mqtt_will_payload_invalid",
        ),
    ];

    for (connect, expected_code, expected_reason) in cases {
        let mut stream = TcpStream::connect(ctx.addr)
            .await
            .expect("MQTT stream should connect");
        write_client_packet(&mut stream, ClientPacket::Connect(connect)).await;
        match read_server_packet_labeled(&mut stream, "will rejection CONNACK").await {
            Packet::ConnAck(connack) => {
                assert_eq!(connack.code, expected_code);
                assert_eq!(
                    connack
                        .properties
                        .and_then(|props| props.reason_string)
                        .as_deref(),
                    Some(expected_reason)
                );
            }
            packet => panic!("expected CONNACK rejection, got {packet:?}"),
        }
    }
    assert_eq!(ctx.private.metrics.snapshot().mqtt_will_rejected, 7);
}

#[tokio::test]
async fn mqtt_will_durably_queues_thing_scoped_message_for_reconnect() {
    let ctx = MqttFlowTestContext::new().await;
    let owner_key = "mqtt-will-thing-owner";
    let channel_password = "mqtt-will-thing-pass";
    ctx.restore_private_route(owner_key).await;
    let channel_id = ctx.create_channel(owner_key, channel_password).await;
    let device_id = derive_private_device_id(owner_key);
    let outbox_before = ctx
        .state
        .store
        .list_private_outbox(device_id, 16)
        .await
        .expect("outbox should list")
        .len();

    let mut will_owner = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut will_owner,
        ClientPacket::Connect(connect_with_will(
            owner_key,
            "subscribe",
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password),
            message_publish_payload(serde_json::json!({
                "title": "thing scoped will",
                "thing_id": "thing_1",
                "occurred_at": 1_700_000_000_000i64
            })),
            QoS::AtLeastOnce,
            false,
        )),
    )
    .await;
    match read_server_packet_labeled(&mut will_owner, "thing will CONNACK").await {
        Packet::ConnAck(connack) => assert_eq!(connack.code, ConnectReturnCode::Success),
        packet => panic!("expected CONNACK success, got {packet:?}"),
    }
    drop(will_owner);

    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { private.metrics.snapshot().mqtt_will_sent == 1 }
    })
    .await;
    let outbox_after = ctx
        .state
        .store
        .list_private_outbox(device_id, 16)
        .await
        .expect("outbox should list")
        .len();
    assert_eq!(
        outbox_after,
        outbox_before + 1,
        "thing-scoped MQTT will delivery must remain durable until PUBACK"
    );
}

#[tokio::test]
async fn mqtt_connect_requires_device_type() {
    let ctx = MqttFlowTestContext::new().await;
    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(&mut stream, ClientPacket::Connect(Connect::new(""))).await;
    match read_server_packet(&mut stream).await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::BadUserNamePassword);
            assert_eq!(
                connack
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("device_type_required")
            );
        }
        packet => panic!("expected CONNACK rejection, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_connect_rejects_non_v5_invalid_device_type_and_non_connect_first_packet() {
    let ctx = MqttFlowTestContext::new().await;

    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    stream
        .write_all(&[
            0x10, 0x14, // CONNECT, remaining length
            0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, // MQTT 3.1.1
            0x02, // clean session
            0x00, 0x0A, // keep alive
            0x00, 0x08, b'm', b'q', b't', b't', b'-', b'v', b'4', b'x',
        ])
        .await
        .expect("MQTT v4 CONNECT should write");
    match read_server_packet_labeled(&mut stream, "non-v5 CONNACK").await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::UnsupportedProtocolVersion);
            assert_eq!(
                connack
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("mqtt5_required")
            );
        }
        packet => panic!("expected CONNACK protocol rejection, got {packet:?}"),
    }

    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    write_client_packet(
        &mut stream,
        ClientPacket::Connect(connect_with_device_type("", "sidecar")),
    )
    .await;
    match read_server_packet_labeled(&mut stream, "invalid device_type CONNACK").await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::PayloadFormatInvalid);
            assert_eq!(
                connack
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("device_type_invalid")
            );
        }
        packet => panic!("expected CONNACK device type rejection, got {packet:?}"),
    }

    let mut stream = TcpStream::connect(ctx.addr)
        .await
        .expect("MQTT stream should connect");
    stream
        .write_all(&[0xC0, 0x00])
        .await
        .expect("PINGREQ should write");
    match read_server_packet_labeled(&mut stream, "first packet CONNACK").await {
        Packet::ConnAck(connack) => {
            assert_eq!(connack.code, ConnectReturnCode::ProtocolError);
            assert_eq!(
                connack
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("first packet must be CONNECT")
            );
        }
        packet => panic!("expected CONNACK first-packet rejection, got {packet:?}"),
    }

    let metrics = ctx.private.metrics.snapshot();
    assert_eq!(metrics.mqtt_connect_attempts, 3);
    assert_eq!(metrics.mqtt_connect_failures, 3);
    assert_eq!(metrics.mqtt_protocol_errors, 1);
}

#[tokio::test]
async fn mqtt_rejects_publish_retain_and_bad_password_with_puback_reason() {
    let (_ctx, mut stream, _device_key, channel_id, channel_password) =
        setup_connected_channel().await;

    let mut retained = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        message_publish_payload(serde_json::json!({"title":"retained"})),
    );
    retained.pkid = 11;
    retained.retain = true;
    retained.properties = Some(PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".to_string()),
    });
    write_client_packet(&mut stream, ClientPacket::Publish(retained)).await;
    match read_server_packet(&mut stream).await {
        Packet::Disconnect(disconnect) => {
            assert_eq!(
                disconnect.reason_code,
                DisconnectReasonCode::RetainNotSupported
            );
        }
        packet => panic!("expected DISCONNECT retain rejection, got {packet:?}"),
    }

    let mut stream = connect_client(_ctx.addr, _device_key.as_str()).await;
    let mut bad_password = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        message_publish_payload(serde_json::json!({"title":"bad password"})),
    );
    bad_password.pkid = 12;
    bad_password.properties = Some(PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            "wrong-pass-987".to_string(),
        )],
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".to_string()),
    });
    write_client_packet(&mut stream, ClientPacket::Publish(bad_password)).await;
    match read_server_packet(&mut stream).await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 12);
            assert_eq!(puback.reason, PubAckReason::NotAuthorized);
        }
        packet => panic!("expected PUBACK password rejection, got {packet:?}"),
    }

    let mut stream = connect_client(_ctx.addr, _device_key.as_str()).await;
    let mut alias_publish = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
        message_publish_payload(serde_json::json!({"title":"alias"})),
    );
    alias_publish.pkid = 13;
    alias_publish.properties = Some(PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: Some(1),
        response_topic: None,
        correlation_data: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".to_string()),
    });
    write_client_packet(&mut stream, ClientPacket::Publish(alias_publish)).await;
    match read_server_packet(&mut stream).await {
        Packet::Disconnect(disconnect) => {
            assert_eq!(
                disconnect.reason_code,
                DisconnectReasonCode::TopicAliasInvalid
            );
        }
        packet => panic!("expected DISCONNECT topic alias rejection, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_publish_errors_map_to_mqtt5_reason_codes_and_properties() {
    let (ctx, mut stream, device_key, channel_id, channel_password) =
        setup_connected_channel().await;

    let cases = [
        (
            format!("pushgo/{channel_id}/events"),
            Some(channel_password.as_str()),
            message_publish_payload(serde_json::json!({"title":"bad topic"})),
            PubAckReason::TopicNameInvalid,
            "mqtt_topic_invalid",
        ),
        (
            MqttMessageTopic::format(channel_id.as_str()),
            None,
            message_publish_payload(serde_json::json!({"title":"missing password"})),
            PubAckReason::NotAuthorized,
            "channel_password_required",
        ),
        (
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password.as_str()),
            message_publish_payload(serde_json::json!({"body":"missing title"})),
            PubAckReason::PayloadFormatInvalid,
            "payload_invalid",
        ),
        (
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password.as_str()),
            serde_json::to_vec(&serde_json::json!({
                "type": "event",
                "data": {"title": "missing action"}
            }))
            .expect("missing action payload should encode"),
            PubAckReason::PayloadFormatInvalid,
            "mqtt_action_required",
        ),
        (
            MqttMessageTopic::format(channel_id.as_str()),
            Some(channel_password.as_str()),
            serde_json::to_vec(&serde_json::json!({
                "type": "unknown",
                "data": {"title": "unsupported model"}
            }))
            .expect("unsupported model payload should encode"),
            PubAckReason::PayloadFormatInvalid,
            "mqtt_model_not_supported",
        ),
    ];

    for (idx, (topic, password, payload, reason, error_code)) in cases.into_iter().enumerate() {
        let pkid = 50 + idx as u16;
        let mut publish = Publish::new(topic, QoS::AtLeastOnce, payload);
        publish.pkid = pkid;
        publish.properties = Some(publish_properties(password));
        write_client_packet(&mut stream, ClientPacket::Publish(publish)).await;
        match read_server_packet_labeled(&mut stream, "error PUBACK").await {
            Packet::PubAck(puback) => {
                assert_eq!(puback.pkid, pkid);
                assert_eq!(puback.reason, reason);
                let props = puback.properties.expect("puback should include props");
                assert_eq!(
                    user_property(&props.user_properties, "pushgo-error-code"),
                    Some(error_code)
                );
                assert!(props.reason_string.is_some());
            }
            packet => panic!("expected PUBACK error, got {packet:?}"),
        }
    }

    let mut stream = connect_client(ctx.addr, device_key.as_str()).await;
    let mut wildcard_topic = Publish::new(
        "pushgo/+/messages",
        QoS::AtLeastOnce,
        message_publish_payload(serde_json::json!({"title":"wildcard publish topic"})),
    );
    wildcard_topic.pkid = 60;
    wildcard_topic.properties = Some(publish_properties(Some(channel_password.as_str())));
    write_client_packet(&mut stream, ClientPacket::Publish(wildcard_topic)).await;
    match read_server_packet_labeled(&mut stream, "wildcard topic PUBACK").await {
        Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 60);
            assert_eq!(puback.reason, PubAckReason::TopicNameInvalid);
            let props = puback.properties.expect("puback should include props");
            assert_eq!(
                user_property(&props.user_properties, "pushgo-error-code"),
                Some("mqtt_topic_filter_not_supported")
            );
        }
        packet => panic!("expected PUBACK wildcard topic rejection, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_rejects_no_local_subscription_and_qos0_publish() {
    let (_ctx, mut stream, _device_key, channel_id, channel_password) =
        setup_connected_channel().await;

    let mut filter = SubscribeFilter::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    filter.set_nolocal(true);
    let mut subscribe = Subscribe::new_many([filter]);
    subscribe.pkid = 21;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe)).await;
    match read_server_packet(&mut stream).await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 21);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::ImplementationSpecific]
            );
        }
        packet => panic!("expected SUBACK No Local rejection, got {packet:?}"),
    }

    let qos0 = Publish::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtMostOnce,
        message_publish_payload(serde_json::json!({"title":"qos0"})),
    );
    write_client_packet(&mut stream, ClientPacket::Publish(qos0)).await;
    match read_server_packet(&mut stream).await {
        Packet::Disconnect(disconnect) => {
            assert_eq!(
                disconnect.reason_code,
                DisconnectReasonCode::QoSNotSupported
            );
        }
        packet => panic!("expected DISCONNECT for QoS0, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_rejects_unsupported_subscribe_options() {
    let (_ctx, mut stream, _device_key, channel_id, channel_password) =
        setup_connected_channel().await;

    let mut multi_subscribe = Subscribe::new_many([
        SubscribeFilter::new(
            MqttMessageTopic::format(channel_id.as_str()),
            QoS::AtLeastOnce,
        ),
        SubscribeFilter::new(
            MqttMessageTopic::format(channel_id.as_str()),
            QoS::AtLeastOnce,
        ),
    ]);
    multi_subscribe.pkid = 30;
    multi_subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(multi_subscribe)).await;
    match read_server_packet(&mut stream).await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 30);
            assert_eq!(
                suback.return_codes,
                vec![
                    SubscribeReasonCode::ImplementationSpecific,
                    SubscribeReasonCode::ImplementationSpecific
                ]
            );
            assert_eq!(
                suback
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("subscribe one channel per packet")
            );
        }
        packet => panic!("expected SUBACK multi-topic rejection, got {packet:?}"),
    }

    let mut subscribe_with_id = Subscribe::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    subscribe_with_id.pkid = 31;
    subscribe_with_id.properties = Some(SubscribeProperties {
        id: Some(7),
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe_with_id)).await;
    match read_server_packet(&mut stream).await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 31);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::ImplementationSpecific]
            );
            assert_eq!(
                suback
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("subscription identifiers are not supported")
            );
        }
        packet => panic!("expected SUBACK subscription id rejection, got {packet:?}"),
    }

    let mut filter = SubscribeFilter::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    filter.set_preserve_retain(true);
    filter.set_retain_forward_rule(RetainForwardRule::Never);
    let mut subscribe_retain = Subscribe::new_many([filter]);
    subscribe_retain.pkid = 32;
    subscribe_retain.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe_retain)).await;
    match read_server_packet(&mut stream).await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 32);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::ImplementationSpecific]
            );
            assert_eq!(
                suback
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("retained subscription options are not supported")
            );
        }
        packet => panic!("expected SUBACK retain options rejection, got {packet:?}"),
    }
}

#[tokio::test]
async fn mqtt_subscribe_and_unsubscribe_report_auth_topic_and_idempotent_results() {
    let (ctx, mut stream, device_key, channel_id, channel_password) =
        setup_connected_channel().await;

    let mut missing_password = Subscribe::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    missing_password.pkid = 70;
    missing_password.properties = Some(SubscribeProperties {
        id: None,
        user_properties: Vec::new(),
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(missing_password)).await;
    match read_server_packet_labeled(&mut stream, "missing password SUBACK").await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 70);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::NotAuthorized]
            );
            assert_eq!(
                suback
                    .properties
                    .and_then(|props| props.reason_string)
                    .as_deref(),
                Some("pushgo-password is required")
            );
        }
        packet => panic!("expected SUBACK missing password rejection, got {packet:?}"),
    }

    let mut wildcard = Subscribe::new("pushgo/+/messages", QoS::AtLeastOnce);
    wildcard.pkid = 71;
    wildcard.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(wildcard)).await;
    match read_server_packet_labeled(&mut stream, "wildcard SUBACK").await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 71);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::WildcardSubscriptionsNotSupported]
            );
        }
        packet => panic!("expected SUBACK wildcard rejection, got {packet:?}"),
    }

    let mut subscribe = Subscribe::new(
        MqttMessageTopic::format(channel_id.as_str()),
        QoS::AtLeastOnce,
    );
    subscribe.pkid = 72;
    subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: vec![(
            MQTT_PASSWORD_PROPERTY.to_string(),
            channel_password.to_string(),
        )],
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(subscribe)).await;
    match read_server_packet_labeled(&mut stream, "valid SUBACK").await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 72);
            assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS1]);
        }
        packet => panic!("expected SUBACK success, got {packet:?}"),
    }

    let device_id = derive_private_device_id(device_key.as_str());
    let parsed_channel = ChannelId::parse(channel_id.as_str())
        .expect("channel id should parse")
        .into_inner();
    let subscribed = ctx
        .state
        .store
        .list_private_subscribed_channels_for_device(device_id)
        .await
        .expect("subscriptions should load");
    assert!(subscribed.contains(&parsed_channel));

    let mut empty_subscribe = Subscribe::new_many(Vec::<SubscribeFilter>::new());
    empty_subscribe.pkid = 76;
    empty_subscribe.properties = Some(SubscribeProperties {
        id: None,
        user_properties: Vec::new(),
    });
    write_client_packet(&mut stream, ClientPacket::Subscribe(empty_subscribe)).await;
    match read_server_packet_labeled(&mut stream, "empty SUBACK").await {
        Packet::SubAck(suback) => {
            assert_eq!(suback.pkid, 76);
            assert_eq!(
                suback.return_codes,
                vec![SubscribeReasonCode::TopicFilterInvalid]
            );
        }
        packet => panic!("expected SUBACK empty topic rejection, got {packet:?}"),
    }

    for pkid in [73, 74] {
        let mut unsubscribe = Unsubscribe::new(MqttMessageTopic::format(channel_id.as_str()));
        unsubscribe.pkid = pkid;
        unsubscribe.properties = Some(UnsubscribeProperties {
            user_properties: Vec::new(),
        });
        write_client_packet(&mut stream, ClientPacket::Unsubscribe(unsubscribe)).await;
        match read_server_packet_labeled(&mut stream, "UNSUBACK").await {
            Packet::UnsubAck(unsuback) => {
                assert_eq!(unsuback.pkid, pkid);
                assert_eq!(unsuback.reasons, vec![UnsubAckReason::Success]);
            }
            packet => panic!("expected UNSUBACK success, got {packet:?}"),
        }
    }

    let mut invalid_unsubscribe = Unsubscribe::new(format!("pushgo/{channel_id}/events"));
    invalid_unsubscribe.pkid = 75;
    invalid_unsubscribe.properties = Some(UnsubscribeProperties {
        user_properties: Vec::new(),
    });
    write_client_packet(&mut stream, ClientPacket::Unsubscribe(invalid_unsubscribe)).await;
    match read_server_packet_labeled(&mut stream, "invalid UNSUBACK").await {
        Packet::UnsubAck(unsuback) => {
            assert_eq!(unsuback.pkid, 75);
            assert_eq!(unsuback.reasons, vec![UnsubAckReason::TopicFilterInvalid]);
        }
        packet => panic!("expected UNSUBACK invalid topic, got {packet:?}"),
    }

    let empty_unsubscribe = Unsubscribe {
        pkid: 77,
        filters: Vec::new(),
        properties: Some(UnsubscribeProperties {
            user_properties: Vec::new(),
        }),
    };
    write_client_packet(&mut stream, ClientPacket::Unsubscribe(empty_unsubscribe)).await;
    match read_server_packet_labeled(&mut stream, "empty UNSUBACK").await {
        Packet::UnsubAck(unsuback) => {
            assert_eq!(unsuback.pkid, 77);
            assert_eq!(unsuback.reasons, vec![UnsubAckReason::TopicFilterInvalid]);
        }
        packet => panic!("expected UNSUBACK empty topic rejection, got {packet:?}"),
    }

    let metrics = ctx.private.metrics.snapshot();
    assert_eq!(metrics.mqtt_subscribe_success, 1);
    assert_eq!(metrics.mqtt_subscribe_failures, 3);
    assert_eq!(metrics.mqtt_unsubscribe_success, 2);
    assert_eq!(metrics.mqtt_unsubscribe_failures, 2);
}

#[tokio::test]
async fn mqtt_negative_puback_retains_durable_outbox_for_redelivery() {
    let (ctx, mut stream, device_key, channel_id, channel_password) =
        setup_connected_channel().await;
    subscribe_stream_to_channel(&mut stream, channel_id.as_str(), &channel_password, 120).await;

    send_message(
        &ctx.state,
        MessageSendCommand {
            channel_id,
            password: channel_password,
            op_id: None,
            thing_id: None,
            occurred_at: None,
            title: "MQTT rejected downlink".to_string(),
            body: Some("must remain durable".to_string()),
            severity: None,
            ttl: None,
            url: None,
            images: Vec::new(),
            ciphertext: None,
            tags: Vec::new(),
            metadata: serde_json::Map::new(),
            source: crate::delivery_core::source::IngressSource::HttpMessage,
        },
    )
    .await
    .expect("message send should succeed");

    let publish = read_publish_with_title(&mut stream, "MQTT rejected downlink").await;
    let payload: serde_json::Value =
        serde_json::from_slice(&publish.payload).expect("downlink should be JSON");
    let delivery_id = payload
        .get("delivery_id")
        .and_then(serde_json::Value::as_str)
        .expect("delivery id should be present")
        .to_string();
    let device_id = derive_private_device_id(&device_key);
    assert!(
        ctx.state
            .store
            .load_private_outbox_entry(device_id, delivery_id.as_str())
            .await
            .expect("outbox should load")
            .is_some()
    );

    let ack_non_ok_before = ctx.private.metrics.snapshot().frames_ack_non_ok;
    let mut rejected = PubAck::new(publish.pkid);
    rejected.reason = PubAckReason::NoMatchingSubscribers;
    write_client_packet(&mut stream, ClientPacket::PubAck(rejected)).await;
    wait_until(Duration::from_secs(2), || {
        let private = Arc::clone(&ctx.private);
        async move { private.metrics.snapshot().frames_ack_non_ok > ack_non_ok_before }
    })
    .await;

    assert!(
        ctx.state
            .store
            .load_private_outbox_entry(device_id, delivery_id.as_str())
            .await
            .expect("outbox should load after rejected PUBACK")
            .is_some(),
        "negative PUBACK must not delete the durable delivery"
    );
}

#[test]
fn mqtt_packet_id_wrap_skips_inflight_identifiers() {
    let mut inflight = HashMap::new();
    inflight.insert(u16::MAX, "delivery-max".to_string());
    inflight.insert(1, "delivery-one".to_string());
    let mut next_pkid = u16::MAX;

    assert_eq!(
        next_available_packet_id(&mut next_pkid, &inflight),
        2,
        "wraparound must not overwrite an in-flight packet mapping"
    );
    assert_eq!(next_pkid, 3);
}

async fn wait_until<F, Fut>(duration: Duration, mut predicate: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let started = tokio::time::Instant::now();
    loop {
        if predicate().await {
            return;
        }
        assert!(
            started.elapsed() < duration,
            "condition did not become true within {duration:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
