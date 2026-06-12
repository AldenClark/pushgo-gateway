use std::{collections::HashMap, net::SocketAddr, pin::Pin, time::Duration};

use bytes::BytesMut;
use flume::{Receiver, Sender};
use mqttbytes::{
    Protocol, QoS,
    v5::{
        self, ConnAck, ConnAckProperties, Connect, ConnectReturnCode, Disconnect,
        DisconnectProperties, DisconnectReasonCode, Packet, PubAck, PubAckProperties, PubAckReason,
        Publish, PublishProperties, RetainForwardRule, SubAck, SubAckProperties, Subscribe,
        SubscribeReasonCode, UnsubAck, UnsubAckReason, Unsubscribe,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use crate::{
    api::Error,
    app::AuthMode,
    mqtt::{MqttMessageDelivery, MqttMessagePublish, MqttMessageTopic, MqttRuntime},
    private::protocol::DeliverEnvelope,
    routing::{DeviceChannelType, derive_private_device_id},
    services::{
        ChannelSubscribeCommand, ChannelUnsubscribeCommand, DeviceRegisterCommand,
        MessageSendCommand, ensure_device_registered,
    },
    storage::DeviceId,
    storage::Platform,
    util::constant_time_eq,
    value::DeviceKeyRef,
};

const MQTT_PASSWORD_PROPERTY: &str = "pushgo-password";
const MQTT_DEVICE_TYPE_PROPERTY: &str = "device_type";
const MAX_INFLIGHT: usize = 128;
const MQTT_CONNECT_READ_TIMEOUT_SECS: u64 = 120;
const MQTT_SERVER_KEEP_ALIVE_SECS: u16 = 120;
const MQTT_MIN_READ_TIMEOUT_SECS: u64 = 2;

struct MqttStream {
    reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
    writer: Pin<Box<dyn AsyncWrite + Send + Sync>>,
}

impl MqttStream {
    fn boxed<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        }
    }
}

pub async fn serve_mqtt(runtime: MqttRuntime) -> Result<(), String> {
    let addr: SocketAddr = runtime
        .config
        .bind_addr
        .parse()
        .map_err(|err| format!("invalid mqtt bind addr: {err}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| format!("bind mqtt listener failed: {err}"))?;
    serve_mqtt_listener(runtime, listener, addr, None).await
}

pub async fn serve_mqtt_tls(runtime: MqttRuntime, tls_acceptor: TlsAcceptor) -> Result<(), String> {
    let addr: SocketAddr = runtime
        .config
        .bind_addr
        .parse()
        .map_err(|err| format!("invalid mqtt bind addr: {err}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| format!("bind mqtt listener failed: {err}"))?;
    serve_mqtt_listener(runtime, listener, addr, Some(tls_acceptor)).await
}

async fn serve_mqtt_listener(
    runtime: MqttRuntime,
    listener: TcpListener,
    addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), String> {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "mqtt.listener_started",
        listen_addr = %(addr.to_string()),
        tls_enabled = (tls_acceptor.is_some())
    );

    loop {
        let (socket, remote_addr) = listener
            .accept()
            .await
            .map_err(|err| format!("accept mqtt connection failed: {err}"))?;
        let socket = match tls_acceptor.as_ref() {
            Some(acceptor) => match acceptor.accept(socket).await {
                Ok(stream) => MqttStream::boxed(stream),
                Err(err) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "mqtt.tls_accept_failed",
                        remote_addr = %(remote_addr.to_string()),
                        error = %(err.to_string())
                    );
                    continue;
                }
            },
            None => MqttStream::boxed(socket),
        };
        let session = MqttSession::new(runtime.clone(), socket, remote_addr);
        tokio::spawn(
            async move { session.run().await }.instrument(tracing::info_span!(
                "gateway.mqtt.connection",
                remote_addr = %remote_addr
            )),
        );
    }
}

struct MqttSession {
    runtime: MqttRuntime,
    socket: MqttStream,
    remote_addr: SocketAddr,
    buffer: BytesMut,
    next_pkid: u16,
    inflight: HashMap<u16, String>,
    read_timeout: Duration,
}

struct AuthenticatedMqttClient {
    device_key: Option<String>,
    device_id: Option<DeviceId>,
    conn_id: Option<u64>,
    device_type: MqttDeviceType,
    rx: Option<Receiver<DeliverEnvelope>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttDeviceType {
    Publish,
    Subscribe,
}

struct MqttAuthSuccess {
    client: AuthenticatedMqttClient,
    assigned_client_id: Option<String>,
    server_keep_alive: Option<u16>,
    read_timeout: Duration,
}

#[derive(Debug, Clone)]
struct MqttError {
    message: &'static str,
    code: &'static str,
    kind: MqttErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttErrorKind {
    Auth,
    Topic,
    Payload,
    TopicAlias,
    Qos,
    Retain,
    NotSupported,
    Quota,
    Internal,
}

impl MqttError {
    fn new(message: &'static str, code: &'static str, kind: MqttErrorKind) -> Self {
        Self {
            message,
            code,
            kind,
        }
    }
}

impl MqttSession {
    fn new(runtime: MqttRuntime, socket: MqttStream, remote_addr: SocketAddr) -> Self {
        Self {
            runtime,
            socket,
            remote_addr,
            buffer: BytesMut::with_capacity(4096),
            next_pkid: 1,
            inflight: HashMap::new(),
            read_timeout: Duration::from_secs(MQTT_CONNECT_READ_TIMEOUT_SECS),
        }
    }

    async fn run(mut self) {
        match self.read_packet().await {
            Ok(Packet::Connect(connect)) => match self.authenticate(connect).await {
                Ok(success) => {
                    if let Err(err) = self
                        .write_connack(
                            ConnectReturnCode::Success,
                            None,
                            success.assigned_client_id.as_deref(),
                            success.server_keep_alive,
                        )
                        .await
                    {
                        self.log_failure("connack_write_failed", err.as_str());
                        return;
                    }
                    self.runtime.private.metrics.mark_mqtt_connect_success();
                    self.read_timeout = success.read_timeout;
                    self.event(
                        "mqtt.connect_accepted",
                        success
                            .client
                            .device_key
                            .as_deref()
                            .unwrap_or("temporary-publisher"),
                        None,
                    );
                    self.run_authenticated(success.client).await;
                }
                Err((code, reason)) => {
                    self.runtime.private.metrics.mark_mqtt_connect_failure();
                    self.log_failure("mqtt.connect_rejected", reason);
                    let _ = self.write_connack(code, Some(reason), None, None).await;
                }
            },
            Ok(_) => {
                let _ = self
                    .write_connack(
                        ConnectReturnCode::ProtocolError,
                        Some("first packet must be CONNECT"),
                        None,
                        None,
                    )
                    .await;
            }
            Err(err) => self.log_failure("connect_read_failed", err.as_str()),
        }
    }

    async fn authenticate(
        &self,
        connect: Connect,
    ) -> Result<MqttAuthSuccess, (ConnectReturnCode, &'static str)> {
        self.runtime.private.metrics.mark_mqtt_connect_attempt();
        if connect.protocol != Protocol::V5 {
            return Err((
                ConnectReturnCode::UnsupportedProtocolVersion,
                "mqtt5_required",
            ));
        }
        if connect.last_will.is_some() {
            return Err((
                ConnectReturnCode::ImplementationSpecificError,
                "will_not_supported",
            ));
        }
        let keep_alive = resolve_keep_alive(connect.keep_alive);
        if let AuthMode::SharedToken(required) = &self.runtime.state.auth {
            let provided = connect
                .login
                .as_ref()
                .map(|login| login.username.trim())
                .unwrap_or_default();
            if provided.is_empty() || !constant_time_eq(provided.as_bytes(), required.as_bytes()) {
                return Err((
                    ConnectReturnCode::BadUserNamePassword,
                    "gateway_token_invalid",
                ));
            }
        }
        let properties = connect
            .properties
            .as_ref()
            .map(|props| props.user_properties.as_slice())
            .unwrap_or(&[]);
        let device_type = parse_device_type(user_property(properties, MQTT_DEVICE_TYPE_PROPERTY))?;
        if device_type == MqttDeviceType::Publish {
            return Ok(MqttAuthSuccess {
                client: AuthenticatedMqttClient {
                    device_key: None,
                    device_id: None,
                    conn_id: None,
                    device_type,
                    rx: None,
                },
                assigned_client_id: None,
                server_keep_alive: keep_alive.server_property,
                read_timeout: keep_alive.read_timeout,
            });
        }

        let requested_device_key = connect
            .client_id
            .trim()
            .is_empty()
            .then_some(None)
            .unwrap_or_else(|| Some(connect.client_id.trim()));
        if let Some(raw) = requested_device_key {
            DeviceKeyRef::parse(raw).map_err(|_| {
                (
                    ConnectReturnCode::ClientIdentifierNotValid,
                    "device_key_invalid",
                )
            })?;
        }
        let device_operation_guard = requested_device_key.and_then(|device_key| {
            self.runtime
                .state
                .device_operation_guards
                .guard_for(device_key)
        });
        let _device_operation_lock = if let Some(ref guard) = device_operation_guard {
            Some(guard.lock().await)
        } else {
            None
        };
        let registered = ensure_device_registered(
            &self.runtime.state,
            DeviceRegisterCommand {
                device_key: requested_device_key,
                platform: Platform::MQTT,
            },
        )
        .await
        .map_err(|_| {
            (
                ConnectReturnCode::ServerUnavailable,
                "device_registration_failed",
            )
        })?;
        let device_key = registered.device_key;
        let route = self
            .runtime
            .state
            .device_registry
            .get(device_key.as_str())
            .ok_or((ConnectReturnCode::ServerUnavailable, "device_route_missing"))?;
        if route.channel_type != DeviceChannelType::Private {
            return Err((ConnectReturnCode::NotAuthorized, "private_route_required"));
        }
        if self
            .runtime
            .private
            .is_device_revoked(derive_private_device_id(&device_key))
        {
            return Err((ConnectReturnCode::NotAuthorized, "device_revoked"));
        }

        let device_id = derive_private_device_id(&device_key);
        let prepared = self
            .runtime
            .private
            .prepare_session_bootstrap(device_id, None, 0)
            .await
            .map_err(|_| {
                self.runtime.private.metrics.mark_mqtt_bootstrap_dropped(1);
                (
                    ConnectReturnCode::ServerUnavailable,
                    "session_bootstrap_failed",
                )
            })?;
        let (tx, rx): (Sender<DeliverEnvelope>, Receiver<DeliverEnvelope>) =
            flume::bounded(crate::private::private_connection_queue_capacity(
                self.runtime.private.config.runtime_profile,
            ));
        let conn_id = rand::random::<u64>();
        self.runtime
            .private
            .hub
            .register_mqtt_connection(device_id, conn_id, tx.clone());
        self.runtime.private.request_fallback_resync();
        let mut bootstrap_dropped = 0usize;
        for (_, envelope) in prepared.bootstrap.inflight {
            if tx.try_send(envelope).is_err() {
                bootstrap_dropped = bootstrap_dropped.saturating_add(1);
            }
        }
        for envelope in prepared.bootstrap.pending {
            if tx.try_send(envelope).is_err() {
                bootstrap_dropped = bootstrap_dropped.saturating_add(1);
            }
        }
        if bootstrap_dropped > 0 {
            self.runtime
                .private
                .metrics
                .mark_mqtt_bootstrap_dropped(bootstrap_dropped);
            self.log_failure("mqtt.bootstrap_queue_full", "bootstrap_delivery_dropped");
        }

        Ok(MqttAuthSuccess {
            assigned_client_id: (registered.issued_new_key
                || requested_device_key != Some(device_key.as_str()))
            .then(|| device_key.clone()),
            server_keep_alive: keep_alive.server_property,
            read_timeout: keep_alive.read_timeout,
            client: AuthenticatedMqttClient {
                device_key: Some(device_key),
                device_id: Some(device_id),
                conn_id: Some(conn_id),
                device_type,
                rx: Some(rx),
            },
        })
    }

    async fn run_authenticated(&mut self, client: AuthenticatedMqttClient) {
        loop {
            tokio::select! {
                packet = self.read_packet() => {
                    match packet {
                        Ok(Packet::Publish(publish)) => self.handle_publish(&client, publish).await,
                        Ok(Packet::PubAck(puback)) => self.handle_puback(&client, puback.pkid).await,
                        Ok(Packet::Subscribe(subscribe)) => self.handle_subscribe(&client, subscribe).await,
                        Ok(Packet::Unsubscribe(unsubscribe)) => self.handle_unsubscribe(&client, unsubscribe).await,
                        Ok(Packet::PingReq) => {
                            let _ = self.write_packet(Packet::PingResp).await;
                        }
                        Ok(Packet::Disconnect(_)) => break,
                        Ok(_) => {
                            self.runtime.private.metrics.mark_mqtt_protocol_error();
                            self.log_failure("mqtt.unsupported_packet", "packet_not_supported");
                            let _ = self
                                .write_disconnect(
                                    DisconnectReasonCode::ImplementationSpecificError,
                                    "packet_not_supported",
                                )
                                .await;
                            break;
                        }
                        Err(err) => {
                            self.runtime.private.metrics.mark_mqtt_protocol_error();
                            self.log_failure("mqtt.packet_read_failed", err.as_str());
                            let _ = self
                                .write_disconnect(DisconnectReasonCode::MalformedPacket, err.as_str())
                                .await;
                            break;
                        }
                    }
                }
                outbound = recv_outbound(&client), if client.rx.is_some() => {
                    match outbound {
                        Some(envelope) => {
                            if self.write_delivery(envelope).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        if let (Some(device_id), Some(conn_id)) = (client.device_id, client.conn_id) {
            self.runtime
                .private
                .hub
                .unregister_mqtt_connection(device_id, conn_id);
        }
        self.event(
            "mqtt.connection_closed",
            client
                .device_key
                .as_deref()
                .unwrap_or("temporary-publisher"),
            None,
        );
    }

    async fn handle_subscribe(&mut self, client: &AuthenticatedMqttClient, subscribe: Subscribe) {
        if subscribe.pkid == 0 {
            self.runtime.private.metrics.mark_mqtt_protocol_error();
            let _ = self
                .write_disconnect(DisconnectReasonCode::ProtocolError, "packet_id_required")
                .await;
            return;
        }
        if subscribe.filters.is_empty() {
            let mut suback = SubAck::new(
                subscribe.pkid,
                vec![SubscribeReasonCode::TopicFilterInvalid],
            );
            suback.properties = Some(SubAckProperties {
                reason_string: Some("at least one topic filter is required".to_string()),
                user_properties: vec![(
                    "pushgo-error-code".to_string(),
                    "topic_filter_required".to_string(),
                )],
            });
            let _ = self.write_packet(Packet::SubAck(suback)).await;
            return;
        }
        if subscribe.filters.len() > 1 {
            self.runtime.private.metrics.mark_mqtt_subscribe_failure();
            let mut suback = SubAck::new(
                subscribe.pkid,
                vec![SubscribeReasonCode::ImplementationSpecific; subscribe.filters.len()],
            );
            suback.properties = Some(SubAckProperties {
                reason_string: Some("subscribe one channel per packet".to_string()),
                user_properties: vec![(
                    "pushgo-error-code".to_string(),
                    "mqtt_single_subscribe_required".to_string(),
                )],
            });
            let _ = self.write_packet(Packet::SubAck(suback)).await;
            return;
        }
        if subscribe
            .properties
            .as_ref()
            .and_then(|props| props.id)
            .is_some()
        {
            self.runtime.private.metrics.mark_mqtt_subscribe_failure();
            let mut suback = SubAck::new(
                subscribe.pkid,
                vec![SubscribeReasonCode::ImplementationSpecific; subscribe.filters.len()],
            );
            suback.properties = Some(SubAckProperties {
                reason_string: Some("subscription identifiers are not supported".to_string()),
                user_properties: vec![(
                    "pushgo-error-code".to_string(),
                    "mqtt_subscription_identifier_not_supported".to_string(),
                )],
            });
            let _ = self.write_packet(Packet::SubAck(suback)).await;
            return;
        }
        let password = subscribe
            .properties
            .as_ref()
            .and_then(|props| user_property(&props.user_properties, MQTT_PASSWORD_PROPERTY));
        let mut codes = Vec::with_capacity(subscribe.filters.len());
        let mut first_error = None;
        for filter in subscribe.filters {
            let code = match self.subscribe_filter(client, &filter, password).await {
                Ok(()) => {
                    self.runtime.private.metrics.mark_mqtt_subscribe_success();
                    SubscribeReasonCode::QoS1
                }
                Err(err) => {
                    self.runtime.private.metrics.mark_mqtt_subscribe_failure();
                    if first_error.is_none() {
                        first_error = Some(err.message.to_string());
                    }
                    subscribe_reason_for_error(&err)
                }
            };
            codes.push(code);
        }
        let mut suback = SubAck::new(subscribe.pkid, codes);
        suback.properties = Some(SubAckProperties {
            reason_string: first_error,
            user_properties: vec![("pushgo-qos".to_string(), "1".to_string())],
        });
        let _ = self.write_packet(Packet::SubAck(suback)).await;
    }

    async fn subscribe_filter(
        &self,
        client: &AuthenticatedMqttClient,
        filter: &mqttbytes::v5::SubscribeFilter,
        password: Option<&str>,
    ) -> Result<(), MqttError> {
        if client.device_type != MqttDeviceType::Subscribe {
            return Err(MqttError::new(
                "publish devices cannot subscribe",
                "mqtt_device_type_publish_subscribe_forbidden",
                MqttErrorKind::Auth,
            ));
        }
        if filter.qos != QoS::AtLeastOnce {
            return Err(MqttError::new(
                "only QoS 1 is supported",
                "mqtt_qos_required",
                MqttErrorKind::Qos,
            ));
        }
        if filter.nolocal {
            return Err(MqttError::new(
                "subscription No Local option is not supported",
                "mqtt_no_local_not_supported",
                MqttErrorKind::NotSupported,
            ));
        }
        if filter.preserve_retain
            || filter.retain_forward_rule != RetainForwardRule::OnEverySubscribe
        {
            return Err(MqttError::new(
                "retained subscription options are not supported",
                "mqtt_retain_subscription_options_not_supported",
                MqttErrorKind::NotSupported,
            ));
        }
        let topic = MqttMessageTopic::parse(filter.path.as_str()).map_err(mqtt_error_from_api)?;
        let password = password.ok_or_else(|| {
            MqttError::new(
                "pushgo-password is required",
                "channel_password_required",
                MqttErrorKind::Auth,
            )
        })?;
        let device_key = client.device_key.as_deref().ok_or_else(|| {
            MqttError::new(
                "device key is required",
                "device_key_required",
                MqttErrorKind::Auth,
            )
        })?;
        crate::services::subscribe_private_device_to_channel(
            &self.runtime.state,
            ChannelSubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: Some(topic.channel_id.to_string()),
                channel_name: None,
                password: password.to_string(),
                source: "mqtt",
                allow_create_channel: false,
            },
        )
        .await
        .map_err(mqtt_error_from_api)?;
        Ok(())
    }

    async fn handle_unsubscribe(
        &mut self,
        client: &AuthenticatedMqttClient,
        unsubscribe: Unsubscribe,
    ) {
        if unsubscribe.pkid == 0 {
            self.runtime.private.metrics.mark_mqtt_protocol_error();
            let _ = self
                .write_disconnect(DisconnectReasonCode::ProtocolError, "packet_id_required")
                .await;
            return;
        }
        if unsubscribe.filters.is_empty() {
            let mut unsuback = UnsubAck::new(unsubscribe.pkid);
            unsuback.reasons = vec![UnsubAckReason::TopicFilterInvalid];
            let _ = self.write_packet(Packet::UnsubAck(unsuback)).await;
            return;
        }
        let mut reasons = Vec::with_capacity(unsubscribe.filters.len());
        for filter in unsubscribe.filters {
            let reason = match MqttMessageTopic::parse(filter.as_str()) {
                Ok(topic) => {
                    let result = self
                        .unsubscribe_filter(client, topic.channel_id.to_string().as_str())
                        .await;
                    match result {
                        Ok(()) => {
                            self.runtime.private.metrics.mark_mqtt_unsubscribe_success();
                            UnsubAckReason::Success
                        }
                        Err(_) => {
                            self.runtime.private.metrics.mark_mqtt_unsubscribe_failure();
                            UnsubAckReason::NotAuthorized
                        }
                    }
                }
                Err(_) => UnsubAckReason::TopicFilterInvalid,
            };
            reasons.push(reason);
        }
        let mut unsuback = UnsubAck::new(unsubscribe.pkid);
        unsuback.reasons = reasons;
        let _ = self.write_packet(Packet::UnsubAck(unsuback)).await;
    }

    async fn unsubscribe_filter(
        &self,
        client: &AuthenticatedMqttClient,
        channel_id: &str,
    ) -> Result<(), MqttError> {
        if client.device_type != MqttDeviceType::Subscribe {
            return Err(MqttError::new(
                "publish devices cannot unsubscribe",
                "mqtt_device_type_publish_unsubscribe_forbidden",
                MqttErrorKind::Auth,
            ));
        }
        let device_key = client.device_key.as_deref().ok_or_else(|| {
            MqttError::new(
                "device key is required",
                "device_key_required",
                MqttErrorKind::Auth,
            )
        })?;
        crate::services::unsubscribe_private_device_from_channel(
            &self.runtime.state,
            ChannelUnsubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: channel_id.to_string(),
                source: "mqtt",
            },
        )
        .await
        .map_err(mqtt_error_from_api)?;
        Ok(())
    }

    async fn handle_publish(&mut self, _client: &AuthenticatedMqttClient, publish: Publish) {
        if publish.qos != QoS::AtLeastOnce {
            self.runtime.private.metrics.mark_mqtt_publish_failure();
            let _ = self
                .write_disconnect(DisconnectReasonCode::QoSNotSupported, "mqtt_qos_required")
                .await;
            return;
        }
        if publish.pkid == 0 {
            self.runtime.private.metrics.mark_mqtt_protocol_error();
            let _ = self
                .write_disconnect(DisconnectReasonCode::ProtocolError, "packet_id_required")
                .await;
            return;
        }
        let reason = self.process_publish(publish.clone()).await;
        let mut ack = PubAck::new(publish.pkid);
        if let Err(err) = reason {
            self.runtime.private.metrics.mark_mqtt_publish_failure();
            if let Some(code) = publish_disconnect_reason(&err) {
                let _ = self.write_disconnect(code, err.message).await;
                return;
            }
            ack.reason = puback_reason_for_error(&err);
            ack.properties = Some(PubAckProperties {
                reason_string: Some(err.message.to_string()),
                user_properties: vec![("pushgo-error-code".to_string(), err.code.to_string())],
            });
        } else {
            self.runtime.private.metrics.mark_mqtt_publish_success();
            ack.properties = Some(PubAckProperties {
                reason_string: None,
                user_properties: vec![("pushgo-qos".to_string(), "1".to_string())],
            });
        }
        let _ = self.write_packet(Packet::PubAck(ack)).await;
    }

    async fn process_publish(&self, publish: Publish) -> Result<(), MqttError> {
        if publish.qos != QoS::AtLeastOnce {
            return Err(MqttError::new(
                "only QoS 1 is supported",
                "mqtt_qos_required",
                MqttErrorKind::Qos,
            ));
        }
        if publish.retain {
            return Err(MqttError::new(
                "retained messages are not supported",
                "mqtt_retain_not_supported",
                MqttErrorKind::Retain,
            ));
        }
        if publish
            .properties
            .as_ref()
            .and_then(|props| props.topic_alias)
            .is_some()
        {
            return Err(MqttError::new(
                "topic aliases are not supported",
                "mqtt_topic_alias_not_supported",
                MqttErrorKind::TopicAlias,
            ));
        }
        let topic = MqttMessageTopic::parse(publish.topic.as_str()).map_err(mqtt_error_from_api)?;
        let password = publish
            .properties
            .as_ref()
            .and_then(|props| user_property(&props.user_properties, MQTT_PASSWORD_PROPERTY))
            .ok_or_else(|| {
                MqttError::new(
                    "pushgo-password is required",
                    "channel_password_required",
                    MqttErrorKind::Auth,
                )
            })?;
        let payload: MqttMessagePublish =
            serde_json::from_slice(&publish.payload).map_err(|_| {
                MqttError::new(
                    "invalid JSON payload",
                    "payload_invalid",
                    MqttErrorKind::Payload,
                )
            })?;
        let _outcome = crate::services::send_message(
            &self.runtime.state,
            MessageSendCommand {
                channel_id: topic.channel_id.to_string(),
                password: password.to_string(),
                op_id: payload.op_id,
                thing_id: payload.thing_id,
                occurred_at: payload.occurred_at,
                title: payload.title,
                body: payload.body,
                severity: payload.severity,
                ttl: payload.ttl,
                url: payload.url,
                images: payload.images,
                ciphertext: payload.ciphertext,
                tags: payload.tags,
                metadata: payload.metadata,
                source: "mqtt",
            },
        )
        .await
        .map_err(mqtt_error_from_api)?;
        Ok(())
    }

    async fn handle_puback(&mut self, client: &AuthenticatedMqttClient, pkid: u16) {
        let Some(device_id) = client.device_id else {
            self.runtime.private.metrics.mark_ack_non_ok();
            return;
        };
        if let Some(delivery_id) = self.inflight.remove(&pkid) {
            match self
                .runtime
                .private
                .complete_terminal_delivery(device_id, delivery_id.as_str(), None)
                .await
            {
                Ok(_) => self.runtime.private.metrics.mark_ack_ok(),
                Err(_) => self.runtime.private.metrics.mark_ack_non_ok(),
            }
        } else {
            self.runtime.private.metrics.mark_ack_non_ok();
            self.log_failure("mqtt.puback_unknown_packet_id", "unknown_packet_id");
        }
    }

    async fn write_delivery(&mut self, envelope: DeliverEnvelope) -> Result<(), ()> {
        if self.inflight.len() >= MAX_INFLIGHT {
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            self.log_failure("mqtt.downlink_inflight_full", "receive_maximum_exceeded");
            return Err(());
        }
        let delivery_id = envelope.delivery_id.clone();
        let delivery =
            MqttMessageDelivery::from_private_payload(delivery_id.clone(), &envelope.payload)
                .map_err(|err| {
                    self.runtime.private.metrics.mark_mqtt_downlink_dropped();
                    self.log_failure("mqtt.downlink_payload_dropped", err.to_string().as_str());
                })?;
        let topic = MqttMessageTopic::format(delivery.channel_id.as_str());
        let mut publish = Publish::new(
            topic,
            QoS::AtLeastOnce,
            serde_json::to_vec(&delivery).map_err(|_| ())?,
        );
        publish.pkid = self.next_packet_id();
        publish.properties = Some(PublishProperties {
            payload_format_indicator: Some(1),
            message_expiry_interval: None,
            topic_alias: None,
            response_topic: None,
            correlation_data: None,
            user_properties: vec![
                (
                    "pushgo-schema".to_string(),
                    "pushgo.mqtt.message.v1".to_string(),
                ),
                ("pushgo-delivery-id".to_string(), delivery_id.clone()),
                ("pushgo-channel-id".to_string(), delivery.channel_id),
            ],
            subscription_identifiers: Vec::new(),
            content_type: Some("application/json".to_string()),
        });
        self.inflight.insert(publish.pkid, delivery_id);
        if self.write_packet(Packet::Publish(publish)).await.is_err() {
            self.inflight
                .retain(|_, value| value != &delivery.delivery_id);
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            return Err(());
        }
        self.runtime.private.metrics.mark_deliver_sent();
        self.runtime.private.metrics.mark_mqtt_downlink_sent();
        Ok(())
    }

    fn next_packet_id(&mut self) -> u16 {
        let current = self.next_pkid.max(1);
        self.next_pkid = if current == u16::MAX { 1 } else { current + 1 };
        current
    }

    async fn read_packet(&mut self) -> Result<Packet, String> {
        loop {
            match v5::read(&mut self.buffer, self.runtime.config.max_packet_bytes) {
                Ok(packet) => return Ok(packet),
                Err(mqttbytes::Error::InsufficientBytes(_)) => {
                    let mut tmp = [0u8; 4096];
                    let n = timeout(self.read_timeout, self.socket.reader.read(&mut tmp))
                        .await
                        .map_err(|_| "mqtt read timeout".to_string())?
                        .map_err(|err| err.to_string())?;
                    if n == 0 {
                        return Err("mqtt connection closed".to_string());
                    }
                    self.buffer.extend_from_slice(&tmp[..n]);
                }
                Err(err) => return Err(format!("mqtt decode failed: {err:?}")),
            }
        }
    }

    async fn write_connack(
        &mut self,
        code: ConnectReturnCode,
        reason: Option<&str>,
        assigned_client_id: Option<&str>,
        server_keep_alive: Option<u16>,
    ) -> Result<(), String> {
        let mut connack = ConnAck::new(code, false);
        let mut properties = ConnAckProperties::new();
        properties.session_expiry_interval = Some(0);
        properties.receive_max = Some(MAX_INFLIGHT as u16);
        properties.max_qos = Some(1);
        properties.retain_available = Some(0);
        properties.wildcard_subscription_available = Some(0);
        properties.subscription_identifiers_available = Some(0);
        properties.shared_subscription_available = Some(0);
        properties.max_packet_size = Some(self.runtime.config.max_packet_bytes as u32);
        properties.topic_alias_max = Some(0);
        properties.reason_string = reason.map(ToString::to_string);
        properties.assigned_client_identifier = assigned_client_id.map(ToString::to_string);
        properties.server_keep_alive = server_keep_alive;
        connack.properties = Some(properties);
        self.write_packet(Packet::ConnAck(connack)).await
    }

    async fn write_packet(&mut self, packet: Packet) -> Result<(), String> {
        let mut out = BytesMut::new();
        match packet {
            Packet::ConnAck(packet) => packet.write(&mut out),
            Packet::Publish(packet) => packet.write(&mut out),
            Packet::PubAck(packet) => packet.write(&mut out),
            Packet::SubAck(packet) => packet.write(&mut out),
            Packet::UnsubAck(packet) => packet.write(&mut out),
            Packet::PingResp => v5::PingResp.write(&mut out),
            Packet::Disconnect(packet) => packet.write(&mut out),
            _ => Err(mqttbytes::Error::MalformedPacket),
        }
        .map_err(|err| format!("mqtt encode failed: {err:?}"))?;
        self.socket
            .writer
            .write_all(&out)
            .await
            .map_err(|err| err.to_string())
    }

    async fn write_disconnect(
        &mut self,
        code: DisconnectReasonCode,
        reason: &str,
    ) -> Result<(), String> {
        let mut properties = DisconnectProperties::new();
        properties.reason_string = Some(reason.to_string());
        self.write_packet(Packet::Disconnect(Disconnect {
            reason_code: code,
            properties: Some(properties),
        }))
        .await
    }

    fn event(&self, event: &'static str, device_key: &str, reason: Option<&str>) {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = %(event),
            remote_addr = %(self.remote_addr.to_string()),
            device_key = %(crate::util::redact_text(device_key)),
            reason = %(reason.unwrap_or(""))
        );
    }

    fn log_failure(&self, event: &'static str, error: &str) {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = %(event),
            remote_addr = %(self.remote_addr.to_string()),
            error = %(error)
        );
    }
}

fn user_property<'a>(properties: &'a [(String, String)], key: &str) -> Option<&'a str> {
    properties
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

async fn recv_outbound(client: &AuthenticatedMqttClient) -> Option<DeliverEnvelope> {
    let rx = client.rx.as_ref()?;
    rx.recv_async().await.ok()
}

struct ResolvedKeepAlive {
    server_property: Option<u16>,
    read_timeout: Duration,
}

fn resolve_keep_alive(client_keep_alive: u16) -> ResolvedKeepAlive {
    let effective = if client_keep_alive == 0 || client_keep_alive > MQTT_SERVER_KEEP_ALIVE_SECS {
        MQTT_SERVER_KEEP_ALIVE_SECS
    } else {
        client_keep_alive
    };
    let read_timeout_secs = ((effective as u64) + ((effective as u64).saturating_add(1) / 2))
        .max(MQTT_MIN_READ_TIMEOUT_SECS);
    ResolvedKeepAlive {
        server_property: (client_keep_alive == 0
            || client_keep_alive > MQTT_SERVER_KEEP_ALIVE_SECS)
            .then_some(MQTT_SERVER_KEEP_ALIVE_SECS),
        read_timeout: Duration::from_secs(read_timeout_secs),
    }
}

fn parse_device_type(
    raw: Option<&str>,
) -> Result<MqttDeviceType, (ConnectReturnCode, &'static str)> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("publish") => Ok(MqttDeviceType::Publish),
        Some("subscribe") => Ok(MqttDeviceType::Subscribe),
        Some(_) => Err((
            ConnectReturnCode::PayloadFormatInvalid,
            "device_type_invalid",
        )),
        None => Err((
            ConnectReturnCode::BadUserNamePassword,
            "device_type_required",
        )),
    }
}

fn mqtt_error_from_api(err: Error) -> MqttError {
    let text = err.to_string();
    let message = Box::leak(text.into_boxed_str());
    let code = match &err {
        Error::Unauthorized => "not_authorized",
        Error::TooBusy => "too_busy",
        Error::Validation {
            code: Some(code), ..
        } => Box::leak(code.clone().into_owned().into_boxed_str()),
        Error::StoreError(crate::storage::StoreError::ChannelNotFound) => "channel_not_authorized",
        Error::StoreError(crate::storage::StoreError::ChannelPasswordMismatch) => {
            "channel_not_authorized"
        }
        _ => "implementation_specific",
    };
    let kind = match &err {
        Error::Unauthorized
        | Error::StoreError(crate::storage::StoreError::ChannelNotFound)
        | Error::StoreError(crate::storage::StoreError::ChannelPasswordMismatch) => {
            MqttErrorKind::Auth
        }
        Error::TooBusy => MqttErrorKind::Quota,
        Error::Validation {
            code: Some(code), ..
        } if code.contains("topic") || code.as_ref() == "channel_id_invalid" => {
            MqttErrorKind::Topic
        }
        Error::Validation { .. } => MqttErrorKind::Payload,
        _ => MqttErrorKind::Internal,
    };
    MqttError {
        message,
        code,
        kind,
    }
}

fn subscribe_reason_for_error(err: &MqttError) -> SubscribeReasonCode {
    match err.kind {
        MqttErrorKind::Auth => SubscribeReasonCode::NotAuthorized,
        MqttErrorKind::Topic => {
            if err.code == "mqtt_topic_filter_not_supported" {
                SubscribeReasonCode::WildcardSubscriptionsNotSupported
            } else {
                SubscribeReasonCode::TopicFilterInvalid
            }
        }
        MqttErrorKind::Qos | MqttErrorKind::NotSupported => {
            SubscribeReasonCode::ImplementationSpecific
        }
        MqttErrorKind::Quota => SubscribeReasonCode::QuotaExceeded,
        _ => SubscribeReasonCode::ImplementationSpecific,
    }
}

fn puback_reason_for_error(err: &MqttError) -> PubAckReason {
    match err.kind {
        MqttErrorKind::Auth => PubAckReason::NotAuthorized,
        MqttErrorKind::Topic => PubAckReason::TopicNameInvalid,
        MqttErrorKind::Payload => PubAckReason::PayloadFormatInvalid,
        MqttErrorKind::Quota => PubAckReason::QuotaExceeded,
        _ => PubAckReason::ImplementationSpecificError,
    }
}

fn publish_disconnect_reason(err: &MqttError) -> Option<DisconnectReasonCode> {
    match err.kind {
        MqttErrorKind::Qos => Some(DisconnectReasonCode::QoSNotSupported),
        MqttErrorKind::Retain => Some(DisconnectReasonCode::RetainNotSupported),
        MqttErrorKind::TopicAlias => Some(DisconnectReasonCode::TopicAliasInvalid),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::BytesMut;
    use mqttbytes::v5::{
        ConnectProperties, SubscribeFilter, SubscribeProperties, UnsubscribeProperties,
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
        mqtt::MqttConfig,
        private::{PrivateConfig, PrivateState},
        routing::{DeviceRegistry, DeviceRouteRecord},
        runtime_config::GatewayRuntimeProfile,
        services::{MessageSendCommand, send_message},
        stats::StatsCollector,
        storage::{DeviceRouteRecordRow, MaintenanceCleanupConfig, Platform, Storage},
    };

    struct MqttFlowTestContext {
        _dir: TempDir,
        state: Arc<AppState>,
        private: Arc<PrivateState>,
        addr: SocketAddr,
        _server: tokio::task::JoinHandle<()>,
    }

    impl MqttFlowTestContext {
        async fn new() -> Self {
            let dir = tempdir().expect("tempdir should be created");
            let db_path = dir.path().join("gateway-mqtt-flow.sqlite");
            let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
            let store = Storage::new(Some(db_url.as_str()))
                .await
                .expect("storage should initialize");
            let stats = StatsCollector::spawn(store.clone());
            let registry = Arc::new(DeviceRegistry::new());
            let private = Arc::new(PrivateState::new(
                store.clone(),
                test_private_config(),
                Arc::clone(&registry),
                Arc::clone(&stats),
            ));
            let (dispatch, _receivers) = DispatchChannels::new();
            let state = Arc::new(AppState {
                dispatch,
                auth: AuthMode::Disabled,
                private_channel_enabled: true,
                diagnostics_api_enabled: false,
                public_base_url: None,
                device_registry: registry,
                device_operation_guards: Arc::new(DeviceOperationGuards::default()),
                stats,
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
            };
            let server = tokio::spawn(async move {
                let _ = serve_mqtt_listener(runtime, listener, addr, None).await;
            });
            Self {
                _dir: dir,
                state,
                private,
                addr,
                _server: server,
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
                    source: "test",
                    allow_create_channel: true,
                },
            )
            .await
            .expect("channel should be created")
            .channel_id
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
            serde_json::to_vec(&inbound_payload).expect("JSON should encode"),
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
        wait_until(Duration::from_secs(2), || {
            let state = Arc::clone(&ctx.state);
            async move {
                state
                    .store
                    .list_private_outbox(device_id, 16)
                    .await
                    .expect("outbox should list")
                    .len()
                    > outbox_before_publish
            }
        })
        .await;
        while let Some(Packet::Publish(extra)) =
            read_server_packet_with_timeout(&mut stream, Duration::from_millis(100)).await
        {
            write_client_packet(&mut stream, ClientPacket::PubAck(PubAck::new(extra.pkid))).await;
        }
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
        match read_server_packet_labeled(&mut stream, "second SUBACK").await {
            Packet::SubAck(suback) => {
                assert_eq!(suback.pkid, 10);
                assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS1]);
            }
            packet => panic!("expected second SUBACK, got {packet:?}"),
        }

        let ack_ok_before_downlink = ctx.private.metrics.snapshot().frames_ack_ok;
        send_message(
            &ctx.state,
            MessageSendCommand {
                channel_id: channel_id.clone(),
                password: channel_password.to_string(),
                op_id: Some("mqtt-flow-downlink".to_string()),
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
                source: "test",
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
            let title = payload.get("title").and_then(|v| v.as_str());
            if title == Some("MQTT downlink") {
                downlink = Some((publish, payload));
            } else {
                write_client_packet(&mut stream, ClientPacket::PubAck(PubAck::new(publish.pkid)))
                    .await;
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
            Some("pushgo.mqtt.message.v1")
        );
        assert_eq!(
            delivery.get("title").and_then(|v| v.as_str()),
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
            "downlink should stay pending before PUBACK"
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
        wait_until(Duration::from_secs(2), || {
            let state = Arc::clone(&ctx.state);
            let delivery_id = delivery_id.clone();
            async move {
                state
                    .store
                    .load_private_outbox_entry(device_id, delivery_id.as_str())
                    .await
                    .expect("outbox should load")
                    .is_none()
            }
        })
        .await;

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
        assert_eq!(
            metrics.frames_ack_ok.saturating_sub(ack_ok_before_downlink),
            acknowledged_downlinks as u64
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

        let mut subscribe = Subscribe::new(
            "pushgo/57T3MX35F1YJ0JRNEHXW6NX544/messages",
            QoS::AtLeastOnce,
        );
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
            br#"{"title":"publish-only message"}"#.to_vec(),
        );
        publish.pkid = 41;
        publish.properties = Some(publish_properties(Some(channel_password)));
        write_client_packet(&mut stream, ClientPacket::Publish(publish)).await;

        match read_server_packet_labeled(&mut stream, "publish-only PUBACK").await {
            Packet::PubAck(puback) => {
                assert_eq!(puback.pkid, 41);
                assert_eq!(puback.reason, PubAckReason::Success);
            }
            packet => panic!("expected PUBACK success, got {packet:?}"),
        }
        assert_eq!(ctx.private.metrics.snapshot().mqtt_publish_success, 1);
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
    }

    #[tokio::test]
    async fn mqtt_rejects_publish_retain_and_bad_password_with_puback_reason() {
        let (_ctx, mut stream, _device_key, channel_id, channel_password) =
            setup_connected_channel().await;

        let mut retained = Publish::new(
            MqttMessageTopic::format(channel_id.as_str()),
            QoS::AtLeastOnce,
            br#"{"title":"retained"}"#.to_vec(),
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
            br#"{"title":"bad password"}"#.to_vec(),
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
            br#"{"title":"alias"}"#.to_vec(),
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
                br#"{"title":"bad topic"}"#.to_vec(),
                PubAckReason::TopicNameInvalid,
                "mqtt_topic_invalid",
            ),
            (
                MqttMessageTopic::format(channel_id.as_str()),
                None,
                br#"{"title":"missing password"}"#.to_vec(),
                PubAckReason::NotAuthorized,
                "channel_password_required",
            ),
            (
                MqttMessageTopic::format(channel_id.as_str()),
                Some(channel_password.as_str()),
                br#"{"body":"missing title"}"#.to_vec(),
                PubAckReason::PayloadFormatInvalid,
                "payload_invalid",
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
            br#"{"title":"wildcard publish topic"}"#.to_vec(),
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
            br#"{"title":"qos0"}"#.to_vec(),
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
}
