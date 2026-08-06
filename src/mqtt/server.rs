use std::{collections::HashMap, net::SocketAddr, time::Duration};

use bytes::BytesMut;
use flume::{Receiver, Sender};
use mqttbytes::{
    Protocol, QoS,
    v5::{
        self, ConnAck, ConnAckProperties, Connect, ConnectReturnCode, Disconnect,
        DisconnectProperties, DisconnectReasonCode, Packet, RetainForwardRule, SubAck,
        SubAckProperties, Subscribe, SubscribeReasonCode, UnsubAck, UnsubAckReason, Unsubscribe,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

mod error;
mod ingress_server;
mod listener;
mod private_receiver;

use listener::MqttStream;
pub use listener::{serve_mqtt, serve_mqtt_tls};

use error::{MqttError, MqttErrorKind, mqtt_error_from_api, subscribe_reason_for_error};

use crate::{
    app::AuthMode,
    mqtt::{MqttMessageTopic, MqttPublishCommand, MqttRuntime},
    private::protocol::DeliverEnvelope,
    routing::{DeviceChannelType, derive_private_device_id},
    services::{
        ChannelCommandSource, ChannelSubscribeCommand, ChannelUnsubscribeCommand,
        DeviceRegisterCommand, ensure_device_registered,
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
    dedupe_client_id: String,
    device_key: Option<String>,
    device_id: Option<DeviceId>,
    conn_id: Option<u64>,
    device_type: MqttDeviceType,
    rx: Option<Receiver<DeliverEnvelope>>,
    will: Option<MqttWillMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttDeviceType {
    Publish,
    Subscribe,
}

#[derive(Debug, Clone)]
struct MqttWillMessage {
    channel_id: String,
    password: String,
    payload: MqttPublishCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttCloseKind {
    Normal,
    WithWill,
}

struct MqttAuthSuccess {
    client: AuthenticatedMqttClient,
    assigned_client_id: Option<String>,
    server_keep_alive: Option<u16>,
    read_timeout: Duration,
}

impl MqttSession {
    pub(super) fn new(runtime: MqttRuntime, socket: MqttStream, remote_addr: SocketAddr) -> Self {
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

    pub(super) async fn run(mut self) {
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
                self.runtime.private.metrics.mark_mqtt_connect_attempt();
                self.runtime.private.metrics.mark_mqtt_connect_failure();
                self.runtime.private.metrics.mark_mqtt_protocol_error();
                let _ = self
                    .write_connack(
                        ConnectReturnCode::ProtocolError,
                        Some("first packet must be CONNECT"),
                        None,
                        None,
                    )
                    .await;
            }
            Err(err) => {
                self.runtime.private.metrics.mark_mqtt_connect_attempt();
                self.runtime.private.metrics.mark_mqtt_connect_failure();
                self.log_failure("connect_read_failed", err.as_str());
            }
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
        let will = self.validate_will(connect.last_will, device_type).await?;
        if device_type == MqttDeviceType::Publish {
            return Ok(MqttAuthSuccess {
                client: AuthenticatedMqttClient {
                    dedupe_client_id: mqtt_dedupe_client_id(
                        connect.client_id.as_str(),
                        None,
                        self.remote_addr,
                    ),
                    device_key: None,
                    device_id: None,
                    conn_id: None,
                    device_type,
                    rx: None,
                    will,
                },
                assigned_client_id: None,
                server_keep_alive: keep_alive.server_property,
                read_timeout: keep_alive.read_timeout,
            });
        }

        let requested_device_key = if connect.client_id.trim().is_empty() {
            None
        } else {
            Some(connect.client_id.trim())
        };
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
        self.runtime
            .state
            .store
            .record_device_activity_best_effort(
                device_id,
                chrono::Utc::now().timestamp_millis(),
                "mqtt_connect",
            )
            .await;
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
                dedupe_client_id: mqtt_dedupe_client_id(
                    connect.client_id.as_str(),
                    Some(device_key.as_str()),
                    self.remote_addr,
                ),
                device_key: Some(device_key),
                device_id: Some(device_id),
                conn_id: Some(conn_id),
                device_type,
                rx: Some(rx),
                will,
            },
        })
    }

    async fn run_authenticated(&mut self, client: AuthenticatedMqttClient) {
        let mut close_kind = MqttCloseKind::WithWill;
        loop {
            tokio::select! {
                packet = self.read_packet() => {
                    match packet {
                        Ok(Packet::Publish(publish)) => self.handle_publish(&client, publish).await,
                        Ok(Packet::PubAck(puback)) => self.handle_puback(&client, puback).await,
                        Ok(Packet::Subscribe(subscribe)) => self.handle_subscribe(&client, subscribe).await,
                        Ok(Packet::Unsubscribe(unsubscribe)) => self.handle_unsubscribe(&client, unsubscribe).await,
                        Ok(Packet::PingReq) => {
                            let _ = self.write_packet(Packet::PingResp).await;
                        }
                        Ok(Packet::Disconnect(disconnect)) => {
                            close_kind = if disconnect.reason_code == DisconnectReasonCode::DisconnectWithWillMessage {
                                MqttCloseKind::WithWill
                            } else {
                                MqttCloseKind::Normal
                            };
                            break;
                        },
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
        if close_kind == MqttCloseKind::WithWill {
            self.send_will(&client).await;
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
            self.runtime.private.metrics.mark_mqtt_subscribe_failure();
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
                source: ChannelCommandSource::Mqtt,
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
            self.runtime.private.metrics.mark_mqtt_unsubscribe_failure();
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
                Err(_) => {
                    self.runtime.private.metrics.mark_mqtt_unsubscribe_failure();
                    UnsubAckReason::TopicFilterInvalid
                }
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
                source: ChannelCommandSource::Mqtt,
            },
        )
        .await
        .map_err(mqtt_error_from_api)?;
        Ok(())
    }

    fn next_packet_id(&mut self) -> u16 {
        next_available_packet_id(&mut self.next_pkid, &self.inflight)
    }

    async fn read_packet(&mut self) -> Result<Packet, String> {
        loop {
            if self.buffer.len() >= 2 && self.buffer[0] == 0xE0 && self.buffer[1] == 0x00 {
                let _ = self.buffer.split_to(2);
                return Ok(Packet::Disconnect(Disconnect {
                    reason_code: DisconnectReasonCode::NormalDisconnection,
                    properties: None,
                }));
            }
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

fn next_available_packet_id(next_pkid: &mut u16, inflight: &HashMap<u16, String>) -> u16 {
    let mut candidate = (*next_pkid).max(1);
    loop {
        *next_pkid = if candidate == u16::MAX {
            1
        } else {
            candidate + 1
        };
        if !inflight.contains_key(&candidate) {
            return candidate;
        }
        candidate = *next_pkid;
    }
}

fn user_property<'a>(properties: &'a [(String, String)], key: &str) -> Option<&'a str> {
    properties
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn mqtt_dedupe_client_id(
    requested_client_id: &str,
    assigned_device_key: Option<&str>,
    remote_addr: SocketAddr,
) -> String {
    if let Some(device_key) = assigned_device_key {
        return device_key.to_string();
    }
    let requested = requested_client_id.trim();
    if requested.is_empty() {
        format!("anonymous@{remote_addr}")
    } else {
        requested.to_string()
    }
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

#[cfg(test)]
mod tests;
