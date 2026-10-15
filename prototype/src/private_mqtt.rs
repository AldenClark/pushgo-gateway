//! MQTT5 Private receiver only. No publish ingress, Will, Event/Thing or
//! new message model is introduced by this transport adapter. Existing-channel
//! subscribe/unsubscribe control stays in the ordinary ledger operations.
use crate::private_runtime::{PrivateRuntime, PrivateTransport};
use bytes::BytesMut;
use mqttbytes::{
    Protocol, QoS,
    v5::{
        self, ConnAck, ConnAckProperties, ConnectReturnCode, Packet, PubAckReason, Publish,
        PublishProperties, RetainForwardRule, SubAck, SubAckProperties, Subscribe,
        SubscribeReasonCode, UnsubAck, UnsubAckReason, Unsubscribe,
    },
};
use pushgo_warp_profile::PrivatePayloadEnvelope;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use warp_link::warp_link_core::{
    AckMsg, AckStatus, MAX_FRAME_BYTES, OutboundMsg, SessionControl, SessionControlOps,
    WarpLinkError,
};
// MQTT retains its independent whole-packet budget at the same shared fixed limit.
// There is no length-prefix allowance or payload-size-derived expansion here.
pub(crate) const MAX_PACKET: usize = MAX_FRAME_BYTES;
const MAX_INFLIGHT: usize = 128;
fn error(e: impl std::fmt::Display) -> WarpLinkError {
    WarpLinkError::Protocol(e.to_string())
}
// MQTT5 always requires a property-length field. mqttbytes 0.6 omits it
// when ConnAck.properties is None, including denial codes; keep the production
// receiver's Some(properties) shape on every success/failure response.
fn receiver_connack(code: ConnectReturnCode) -> ConnAck {
    let mut ack = ConnAck::new(code, false);
    let mut properties = ConnAckProperties::new();
    properties.session_expiry_interval = Some(0);
    properties.receive_max = Some(MAX_INFLIGHT as u16);
    properties.max_qos = Some(1);
    properties.retain_available = Some(0);
    properties.wildcard_subscription_available = Some(0);
    properties.subscription_identifiers_available = Some(0);
    properties.shared_subscription_available = Some(0);
    properties.max_packet_size = Some(MAX_PACKET as u32);
    properties.topic_alias_max = Some(0);
    ack.properties = Some(properties);
    ack
}
async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut BytesMut,
) -> Result<Packet, WarpLinkError> {
    loop {
        match v5::read(buffer, MAX_PACKET) {
            Ok(packet) => return Ok(packet),
            Err(mqttbytes::Error::InsufficientBytes(_)) => {}
            Err(e) => return Err(error(e)),
        }
        if buffer.len() >= MAX_PACKET {
            return Err(error("MQTT packet bound exceeded"));
        }
        let mut chunk = [0u8; 2048];
        let remaining = (MAX_PACKET - buffer.len()).min(chunk.len());
        let size = reader.read(&mut chunk[..remaining]).await.map_err(error)?;
        if size == 0 {
            return Err(error("MQTT peer closed"));
        }
        buffer.extend_from_slice(&chunk[..size]);
    }
}
async fn write_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), WarpLinkError> {
    timeout(Duration::from_secs(10), async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| error("MQTT write timeout"))?
    .map_err(error)
}
/// Same pure ordinary-message mapping as production MQTT delivery envelope.
/// The outer delivery ID is the durable ledger identity, never payload input.
pub(crate) fn delivery_json(
    delivery: &str,
    payload: &[u8],
) -> Result<(String, Vec<u8>), WarpLinkError> {
    let envelope: PrivatePayloadEnvelope = postcard::from_bytes(payload).map_err(error)?;
    if envelope.payload_version != 1 {
        return Err(error("unsupported Private payload"));
    }
    let channel = envelope
        .data
        .get("channel_id")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| error("channel_id missing"))?;
    let model = envelope
        .data
        .get("entity_type")
        .map(|s| s.trim())
        .unwrap_or("message");
    if model != "message" {
        return Err(error("only ordinary message Private receiver supported"));
    }
    let mut data = Map::new();
    for (key, value) in envelope.data {
        let mapped = match key.as_str() {
            "images" | "tags" | "metadata" | "attrs" | "external_ids" => {
                serde_json::from_str(&value).unwrap_or_else(|_| Value::String(value.clone()))
            }
            "occurred_at" | "ingested_at" | "sent_at" | "ttl" | "event_time" | "observed_at"
            | "started_at" | "ended_at" | "created_at" | "deleted_at" => value
                .parse::<i64>()
                .map(|n| Value::Number(n.into()))
                .unwrap_or_else(|_| Value::String(value.clone())),
            _ => Value::String(value),
        };
        data.insert(key, mapped);
    }
    let bytes=serde_json::to_vec(&serde_json::json!({"schema":"pushgo.mqtt.delivery.v1","type":"message","delivery_id":delivery,"channel_id":channel,"data":data})).map_err(error)?;
    Ok((channel, bytes))
}
struct Issued {
    seq: u64,
    delivery: String,
}
fn packet_id(next: &mut u16, inflight: &BTreeMap<u16, Issued>) -> Result<u16, WarpLinkError> {
    for _ in 0..=inflight.len() {
        *next = next.wrapping_add(1);
        if *next == 0 {
            *next = 1;
        }
        if !inflight.contains_key(next) {
            return Ok(*next);
        }
    }
    Err(error("bounded MQTT packet IDs exhausted"))
}
async fn publish<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: OutboundMsg,
    next: &mut u16,
    inflight: &mut BTreeMap<u16, Issued>,
    receive_max: usize,
) -> Result<(), WarpLinkError> {
    let seq = message.seq.ok_or_else(|| error("Private seq required"))?;
    let existing = inflight
        .iter()
        .find(|(_, issued)| issued.seq == seq && issued.delivery == message.id)
        .map(|(id, _)| *id);
    if existing.is_none() && inflight.len() >= receive_max {
        return Err(error("MQTT receive maximum reached"));
    }
    let id = match existing {
        Some(id) => id,
        None => packet_id(next, inflight)?,
    };
    let (channel, payload) = delivery_json(&message.id, &message.payload)?;
    let mut publish = Publish::new(channel.clone(), QoS::AtLeastOnce, payload);
    publish.pkid = id;
    publish.dup = existing.is_some();
    publish.properties = Some(PublishProperties {
        payload_format_indicator: Some(1),
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: vec![
            ("pushgo-schema".into(), "pushgo.mqtt.message.v1".into()),
            ("pushgo-delivery-id".into(), message.id.clone()),
            ("pushgo-channel-id".into(), channel),
        ],
        subscription_identifiers: Vec::new(),
        content_type: Some("application/json".into()),
    });
    let mut bytes = BytesMut::new();
    publish.write(&mut bytes).map_err(error)?;
    if bytes.len() > MAX_PACKET {
        return Err(error("MQTT delivery frame bound exceeded"));
    }
    write_bytes(writer, &bytes).await?;
    inflight.insert(
        id,
        Issued {
            seq,
            delivery: message.id,
        },
    );
    Ok(())
}
/// The listener owns this whole future, including final durable abandonment.
/// read_packet retains partial bytes across select cancellation.
pub async fn run_receiver<S: AsyncRead + AsyncWrite + Unpin + Send>(
    runtime: PrivateRuntime,
    stream: S,
    stop: watch::Receiver<bool>,
) -> Result<(), WarpLinkError> {
    let _permit = runtime.try_io_permit().map_err(error)?;
    run_receiver_owned(runtime, stream, stop).await
}
struct MqttControl(watch::Sender<bool>);
impl SessionControlOps for MqttControl {
    fn set_auth_expiry(&self, expiry: Option<i64>, _before: u16) {
        if expiry.is_some_and(|e| e <= 0) {
            let _ = self.0.send(true);
        }
    }
}
async fn run_receiver_owned<S: AsyncRead + AsyncWrite + Unpin + Send>(
    runtime: PrivateRuntime,
    stream: S,
    mut stop: watch::Receiver<bool>,
) -> Result<(), WarpLinkError> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(2048);
    if *stop.borrow() {
        return Ok(());
    }
    let first = tokio::select! {
        changed=stop.changed()=> { let _=changed;return Ok(()); },
        first=timeout(Duration::from_secs(120),read_packet(&mut reader,&mut buffer))=>first.map_err(|_|error("MQTT CONNECT timeout"))??,
    };
    let Packet::Connect(connect) = first else {
        return Err(error("MQTT CONNECT required"));
    };
    let device_type = connect
        .properties
        .as_ref()
        .and_then(|p| p.user_properties.iter().find(|(k, _)| k == "device_type"))
        .map(|(_, v)| v.trim().to_ascii_lowercase());
    let refused = if connect.protocol != Protocol::V5 {
        Some(ConnectReturnCode::UnsupportedProtocolVersion)
    } else if device_type.is_none() {
        Some(ConnectReturnCode::BadUserNamePassword)
    } else if device_type.as_deref() != Some("subscribe")
        || connect.last_will.is_some()
        || connect
            .properties
            .as_ref()
            .is_some_and(|p| p.receive_maximum == Some(0))
    {
        Some(ConnectReturnCode::PayloadFormatInvalid)
    } else {
        None
    };
    if let Some(code) = refused {
        let mut bytes = BytesMut::new();
        receiver_connack(code).write(&mut bytes).map_err(error)?;
        write_bytes(&mut writer, &bytes).await?;
        return Err(error("MQTT5 Private receiver CONNECT refused"));
    }
    let token = connect.login.as_ref().map(|login| login.username.trim());
    let requested = (!connect.client_id.trim().is_empty()).then_some(connect.client_id.trim());
    let registered = match runtime.register_mqtt(requested, token).await {
        Ok(registered) => registered,
        Err(e) => {
            let code = match e {
                crate::store::KernelError::Unauthorized => ConnectReturnCode::BadUserNamePassword,
                crate::store::KernelError::Invalid(_) => {
                    ConnectReturnCode::ClientIdentifierNotValid
                }
                _ => ConnectReturnCode::ServerUnavailable,
            };
            let mut bytes = BytesMut::new();
            receiver_connack(code).write(&mut bytes).map_err(error)?;
            write_bytes(&mut writer, &bytes).await?;
            return Err(error("MQTT registration refused before session admission"));
        }
    };
    let device = registered["device_key"]
        .as_str()
        .ok_or_else(|| error("MQTT registration missing identity"))?
        .to_owned();
    let assigned = (registered["issued_new_key"].as_bool().unwrap_or(false)
        || requested != Some(device.as_str()))
    .then_some(device.clone());
    let session = match runtime.connect(device, token, PrivateTransport::Mqtt).await {
        Ok(session) => session,
        Err(_) => {
            let mut bytes = BytesMut::new();
            receiver_connack(ConnectReturnCode::NotAuthorized)
                .write(&mut bytes)
                .map_err(error)?;
            write_bytes(&mut writer, &bytes).await?;
            return Err(error("MQTT Private authorization refused"));
        }
    };
    let (control, mut terminated) = watch::channel(false);
    runtime.control(
        &session,
        SessionControl::from_ops(Arc::new(MqttControl(control))),
    );
    let effective_keep_alive = if connect.keep_alive == 0 || connect.keep_alive > 120 {
        120
    } else {
        connect.keep_alive
    };
    let read_seconds =
        (u64::from(effective_keep_alive) + u64::from(effective_keep_alive).div_ceil(2)).max(2);
    let server_keep_alive = (connect.keep_alive == 0 || connect.keep_alive > 120).then_some(120);
    let receive_max = connect
        .properties
        .as_ref()
        .and_then(|p| p.receive_maximum)
        .unwrap_or(MAX_INFLIGHT as u16)
        .clamp(1, MAX_INFLIGHT as u16) as usize;
    let result=async {
        let mut connack=receiver_connack(ConnectReturnCode::Success);let properties=connack.properties.as_mut().expect("receiver properties always present");properties.server_keep_alive=server_keep_alive;properties.assigned_client_identifier=assigned;
        let mut bytes=BytesMut::new();connack.write(&mut bytes).map_err(error)?;write_bytes(&mut writer,&bytes).await?;
        let mut inflight=BTreeMap::<u16, Issued>::new();let mut next=0u16;let mut read_deadline=Instant::now()+Duration::from_secs(read_seconds);
        loop {
            if runtime.is_stopping() || *stop.borrow() { break; }
            tokio::select! {
                changed=terminated.changed()=> { if changed.is_err()||*terminated.borrow() { break; } },
                changed=stop.changed()=> { if changed.is_err()||*stop.borrow() { break; } },
                packet=timeout_at(read_deadline,read_packet(&mut reader,&mut buffer))=> {
                    let packet=packet.map_err(|_|error("MQTT read idle deadline"))??;read_deadline=Instant::now()+Duration::from_secs(read_seconds);
                    match packet {
                        Packet::PubAck(ack)=> { if let Some(issued)=inflight.remove(&ack.pkid) { if ack.reason==PubAckReason::Success { runtime.acknowledge(&session,AckMsg { seq:Some(issued.seq),id:issued.delivery,status:AckStatus::Ok }).await; } } },
                        Packet::Subscribe(subscribe)=>subscribe_packet(&runtime,&session,&mut writer,subscribe).await?,
                        Packet::Unsubscribe(unsubscribe)=>unsubscribe_packet(&runtime,&session,&mut writer,unsubscribe).await?,
                        Packet::PingReq=>write_bytes(&mut writer,&[0xd0,0]).await?,
                        Packet::Disconnect(_)=>break,
                        _=>return Err(error("MQTT Private receiver accepts subscribe control/PUBACK/PING/DISCONNECT only")),
                    }
                },
                message=runtime.outbound_mode(&session,15_000,inflight.len()>=receive_max)=> { if let Some(message)=message { publish(&mut writer,message,&mut next,&mut inflight,receive_max).await?; } else if runtime.is_stopping() { break; } },
            }
        }
        Ok(())
    }.await;
    runtime.disconnect(&session).await;
    result
}
fn topic(raw: &str) -> Result<String, SubscribeReasonCode> {
    if raw.contains('#') || raw.contains('+') || raw.starts_with("$share/") {
        return Err(SubscribeReasonCode::WildcardSubscriptionsNotSupported);
    }
    if raw.trim().contains('/') {
        return Err(SubscribeReasonCode::TopicFilterInvalid);
    }
    crate::sender::channel_id(raw.trim()).map_err(|_| SubscribeReasonCode::TopicFilterInvalid)
}
fn subscribe_error(error: &crate::store::KernelError) -> SubscribeReasonCode {
    use crate::store::KernelError;
    match error {
        KernelError::Unauthorized => SubscribeReasonCode::NotAuthorized,
        KernelError::Capacity => SubscribeReasonCode::QuotaExceeded,
        KernelError::Control { code, .. }
            if matches!(
                *code,
                "channel_not_found"
                    | "password_mismatch"
                    | "authentication_failed"
                    | "channel_not_authorized"
            ) =>
        {
            SubscribeReasonCode::NotAuthorized
        }
        KernelError::Control { code, .. } if *code == "invalid_channel_id" => {
            SubscribeReasonCode::TopicFilterInvalid
        }
        _ => SubscribeReasonCode::ImplementationSpecific,
    }
}
async fn subscribe_packet<W: AsyncWrite + Unpin>(
    runtime: &PrivateRuntime,
    session: &warp_link::warp_link_core::SessionCtx,
    writer: &mut W,
    subscribe: Subscribe,
) -> Result<(), WarpLinkError> {
    if subscribe.pkid == 0 {
        return Err(error("MQTT packet_id_required"));
    }
    let mut reason = None;
    let codes = if subscribe.filters.is_empty() {
        reason = Some("at least one topic filter is required".into());
        vec![SubscribeReasonCode::TopicFilterInvalid]
    } else if subscribe.filters.len() > 1 {
        reason = Some("subscribe one channel per packet".into());
        vec![SubscribeReasonCode::ImplementationSpecific; subscribe.filters.len()]
    } else if subscribe.properties.as_ref().and_then(|p| p.id).is_some() {
        reason = Some("subscription identifiers are not supported".into());
        vec![SubscribeReasonCode::ImplementationSpecific]
    } else {
        let filter = &subscribe.filters[0];
        let auth = subscribe
            .properties
            .as_ref()
            .and_then(|p| {
                p.user_properties
                    .iter()
                    .find(|(k, _)| k == "pushgo-password")
            })
            .map(|(_, v)| v.as_str());
        let code = if filter.qos != QoS::AtLeastOnce
            || filter.nolocal
            || filter.preserve_retain
            || filter.retain_forward_rule != RetainForwardRule::OnEverySubscribe
        {
            reason = Some("QoS1 without NoLocal/retained options is required".into());
            SubscribeReasonCode::ImplementationSpecific
        } else {
            match topic(&filter.path) {
                Err(code) => code,
                Ok(channel) => match auth {
                    None => SubscribeReasonCode::NotAuthorized,
                    Some(auth) => match runtime.subscribe_mqtt(session, &channel, auth).await {
                        Ok(()) => SubscribeReasonCode::QoS1,
                        Err(e) => subscribe_error(&e),
                    },
                },
            }
        };
        vec![code]
    };
    let mut ack = SubAck::new(subscribe.pkid, codes);
    ack.properties = Some(SubAckProperties {
        reason_string: reason,
        user_properties: vec![("pushgo-qos".into(), "1".into())],
    });
    let mut bytes = BytesMut::new();
    ack.write(&mut bytes).map_err(error)?;
    write_bytes(writer, &bytes).await
}
async fn unsubscribe_packet<W: AsyncWrite + Unpin>(
    runtime: &PrivateRuntime,
    session: &warp_link::warp_link_core::SessionCtx,
    writer: &mut W,
    unsubscribe: Unsubscribe,
) -> Result<(), WarpLinkError> {
    if unsubscribe.pkid == 0 {
        return Err(error("MQTT packet_id_required"));
    }
    let mut reasons = Vec::with_capacity(unsubscribe.filters.len().max(1));
    if unsubscribe.filters.is_empty() {
        reasons.push(UnsubAckReason::TopicFilterInvalid);
    }
    for raw in unsubscribe.filters {
        reasons.push(match topic(&raw) {
            Err(_) => UnsubAckReason::TopicFilterInvalid,
            Ok(channel) => match runtime.unsubscribe_mqtt(session, &channel).await {
                Ok(()) => UnsubAckReason::Success,
                Err(_) => UnsubAckReason::NotAuthorized,
            },
        });
    }
    let mut ack = UnsubAck::new(unsubscribe.pkid);
    ack.reasons = reasons;
    let mut bytes = BytesMut::new();
    ack.write(&mut bytes).map_err(error)?;
    write_bytes(writer, &bytes).await
}
pub struct MqttListener {
    pub local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    join: Option<JoinHandle<Result<(), WarpLinkError>>>,
    runtime: PrivateRuntime,
}
impl MqttListener {
    pub fn stop_accepting(&self) {
        self.stop.send_replace(true);
    }
    pub async fn shutdown(&mut self) -> Result<(), WarpLinkError> {
        self.runtime.begin_shutdown();
        self.stop_accepting();
        if let Some(join) = self.join.as_mut() {
            timeout(Duration::from_secs(30), join)
                .await
                .map_err(|_| error("MQTT sessions not joined"))?
                .map_err(error)??;
        }
        self.join.take();
        Ok(())
    }
}
impl Drop for MqttListener {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.runtime
                .fence("MQTT listener dropped without joined shutdown");
            let _ = self.stop.send(true);
        }
    }
}
pub async fn start_mqtt(
    runtime: PrivateRuntime,
    addr: SocketAddr,
) -> Result<MqttListener, WarpLinkError> {
    let listener = TcpListener::bind(addr).await.map_err(error)?;
    let local_addr = listener.local_addr().map_err(error)?;
    let (stop, mut stopped) = watch::channel(false);
    let owned = runtime.clone();
    let join = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        let mut failed = false;
        loop {
            tokio::select! {
                changed=stopped.changed()=> { if changed.is_err()||*stopped.borrow() { break; } },
                done=sessions.join_next(),if !sessions.is_empty()=> { if done.is_some_and(|result|result.is_err()) { failed=true;owned.fence("MQTT receiver task panicked"); } },
                accepted=listener.accept()=> {
                    let (stream,_)=match accepted { Ok(value)=>value,Err(_)=> { failed=true;owned.fence("MQTT accept failed");break; } };
                    // Reserve before spawning, including the CONNECT handshake. The
                    // receiver obtains its own business connection permit at auth.
                    let permit=match owned.try_io_permit() { Ok(permit)=>permit,Err(_)=>continue };let runtime=owned.clone();let stopped=stopped.clone();
                    sessions.spawn(async move { let _permit=permit;let _=run_receiver_reserved(runtime,stream,stopped).await; });
                },
            }
        }
        drop(listener);
        while let Some(result) = sessions.join_next().await {
            if result.is_err() {
                owned.fence("MQTT receiver join failed");
                failed = true;
            }
        }
        if failed {
            Err(error("MQTT receiver failure; all tasks joined"))
        } else {
            Ok(())
        }
    });
    Ok(MqttListener {
        local_addr,
        stop,
        join: Some(join),
        runtime,
    })
}
// The listener's pre-spawn permit stays owned through this future. A generic
// public caller uses run_receiver and acquires that permit itself.
async fn run_receiver_reserved<S: AsyncRead + AsyncWrite + Unpin + Send>(
    runtime: PrivateRuntime,
    stream: S,
    stop: watch::Receiver<bool>,
) -> Result<(), WarpLinkError> {
    run_receiver_owned(runtime, stream, stop).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mqtt5_denial_connacks_include_required_properties_and_round_trip() {
        for code in [
            ConnectReturnCode::BadUserNamePassword,
            ConnectReturnCode::NotAuthorized,
            ConnectReturnCode::ClientIdentifierNotValid,
            ConnectReturnCode::UnsupportedProtocolVersion,
            ConnectReturnCode::ServerUnavailable,
        ] {
            let mut bytes = BytesMut::new();
            receiver_connack(code).write(&mut bytes).unwrap();
            let Packet::ConnAck(decoded) = v5::read(&mut bytes, MAX_PACKET)
                .expect("denial is a complete MQTT5 packet, not EOF/partial properties")
            else {
                panic!("CONNACK packet required")
            };
            assert_eq!(decoded.code, code);
            let properties = decoded
                .properties
                .expect("production receiver properties retained");
            assert_eq!(properties.session_expiry_interval, Some(0));
            assert_eq!(properties.receive_max, Some(128));
            assert!(bytes.is_empty());
        }
    }
    #[test]
    fn json_mapping_matches_ordinary_production_types_and_outer_identity() {
        let payload=crate::private_runtime::encode_payload(br#"{"channel_id":"channel","entity_type":"message","ttl":"123","images":"[\"a\"]","first":"1"}"#).unwrap();
        let (topic, body) = delivery_json("durable-id", &payload).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(topic, "channel");
        assert_eq!(body["delivery_id"], "durable-id");
        assert_eq!(body["data"]["ttl"], 123);
        assert_eq!(body["data"]["images"], serde_json::json!(["a"]));
        assert_eq!(body["data"]["first"], "1");
    }
    #[test]
    fn packet_id_wrap_skips_live_ids() {
        let mut inflight = BTreeMap::new();
        inflight.insert(
            1,
            Issued {
                seq: 1,
                delivery: "a".into(),
            },
        );
        let mut next = u16::MAX;
        assert_eq!(packet_id(&mut next, &inflight).unwrap(), 2);
    }
}
