use mqttbytes::{
    QoS,
    v5::{
        ConnectReturnCode, DisconnectReasonCode, LastWill, Packet, PubAck, PubAckProperties,
        Publish,
    },
};

use crate::{
    api::handlers::delivery_core_adapter::core_error_to_api_error,
    delivery_core::source::IngressSource,
    delivery_core::{
        auth::SubmitAuth,
        submit::{
            ChannelSelector, DomainCommandInput, EventInput, ResponseMode, SubmitCommand,
            SubmitContext, ThingInput, submit_command,
        },
    },
    domain_model::message::MessageInput,
    mqtt::{
        MqttMessageTopic, MqttPublishCommand, MqttPublishDedupeDecision, MqttPublishDedupeKey,
        MqttPublishEnvelope, MqttRole,
    },
    value::ChannelId,
};

use super::{
    AuthenticatedMqttClient, MQTT_PASSWORD_PROPERTY, MqttSession, MqttWillMessage,
    error::{
        MqttError, MqttErrorKind, mqtt_error_from_api, puback_reason_for_error,
        publish_disconnect_reason,
    },
    user_property,
};

impl MqttSession {
    pub(super) async fn validate_will(
        &self,
        will: Option<LastWill>,
        device_type: super::MqttDeviceType,
    ) -> Result<Option<MqttWillMessage>, (ConnectReturnCode, &'static str)> {
        let Some(will) = will else {
            return Ok(None);
        };
        if device_type != super::MqttDeviceType::Subscribe {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            return Err((
                ConnectReturnCode::ImplementationSpecificError,
                "mqtt_will_publish_only_not_supported",
            ));
        }
        if will.qos != QoS::AtLeastOnce {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            return Err((ConnectReturnCode::QoSNotSupported, "mqtt_will_qos_required"));
        }
        if will.retain {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            return Err((
                ConnectReturnCode::RetainNotSupported,
                "mqtt_will_retain_not_supported",
            ));
        }
        let topic = MqttMessageTopic::parse(will.topic.as_str()).map_err(|_| {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            (
                ConnectReturnCode::TopicNameInvalid,
                "mqtt_will_topic_invalid",
            )
        })?;
        let password = will
            .properties
            .as_ref()
            .and_then(|props| user_property(&props.user_properties, MQTT_PASSWORD_PROPERTY))
            .ok_or_else(|| {
                self.runtime.private.metrics.mark_mqtt_will_rejected();
                (
                    ConnectReturnCode::BadUserNamePassword,
                    "mqtt_will_password_required",
                )
            })?
            .to_string();
        let payload = MqttPublishEnvelope::decode(&will.message).map_err(|_| {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            (
                ConnectReturnCode::PayloadFormatInvalid,
                "mqtt_will_payload_invalid",
            )
        })?;
        let channel_id = topic.channel_id.to_string();
        let parsed_channel_id = ChannelId::parse(channel_id.as_str()).map_err(|_| {
            self.runtime.private.metrics.mark_mqtt_will_rejected();
            (
                ConnectReturnCode::TopicNameInvalid,
                "mqtt_will_topic_invalid",
            )
        })?;
        self.runtime
            .state
            .store
            .channel_info_with_password(parsed_channel_id.into_inner(), password.as_str())
            .await
            .map_err(|_| {
                self.runtime.private.metrics.mark_mqtt_will_rejected();
                (
                    ConnectReturnCode::BadUserNamePassword,
                    "mqtt_will_channel_not_authorized",
                )
            })?
            .ok_or_else(|| {
                self.runtime.private.metrics.mark_mqtt_will_rejected();
                (
                    ConnectReturnCode::BadUserNamePassword,
                    "mqtt_will_channel_not_authorized",
                )
            })?;
        Ok(Some(MqttWillMessage {
            channel_id,
            password,
            payload,
        }))
    }

    pub(super) async fn send_will(&self, client: &AuthenticatedMqttClient) {
        let Some(will) = client.will.as_ref() else {
            return;
        };
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "mqtt.will_send_started",
            mqtt_role = %(MqttRole::IngressWill.as_str()),
            channel_id = %(crate::util::redact_text(will.channel_id.as_str()))
        );
        match self
            .submit_publish_command(
                will.channel_id.as_str(),
                will.password.as_str(),
                will.payload.clone(),
                IngressSource::MqttWill,
            )
            .await
        {
            Ok(_) => self.runtime.private.metrics.mark_mqtt_will_sent(),
            Err(err) => {
                self.runtime.private.metrics.mark_mqtt_will_failure();
                self.log_failure("mqtt.will_send_failed", err.message);
            }
        }
    }

    pub(super) async fn handle_publish(
        &mut self,
        client: &AuthenticatedMqttClient,
        publish: Publish,
    ) {
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
        let outcome = self.process_publish(client, publish.clone()).await;
        let mut ack = PubAck::new(publish.pkid);
        match outcome {
            Err(err) => {
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
            }
            Ok(op_id) => {
                self.runtime.private.metrics.mark_mqtt_publish_success();
                let mut user_properties = vec![("pushgo-qos".to_string(), "1".to_string())];
                if let Some(op_id) = op_id {
                    user_properties.push(("pushgo-op-id".to_string(), op_id));
                }
                ack.properties = Some(PubAckProperties {
                    reason_string: None,
                    user_properties,
                });
            }
        }
        let _ = self.write_packet(Packet::PubAck(ack)).await;
    }

    async fn process_publish(
        &self,
        client: &AuthenticatedMqttClient,
        publish: Publish,
    ) -> Result<Option<String>, MqttError> {
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
        let payload = MqttPublishEnvelope::decode(&publish.payload).map_err(mqtt_error_from_api)?;
        if payload.op_id().is_none()
            && self.reserve_mqtt_publish_fallback_dedupe(client, &publish)
                == MqttPublishDedupeDecision::Duplicate
        {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "mqtt.publish_duplicate_suppressed",
                mqtt_role = %(MqttRole::IngressPublish.as_str()),
                client_id = %(crate::util::redact_text(client.dedupe_client_id.as_str())),
                topic = %(crate::util::redact_text(publish.topic.as_str())),
                packet_id = (publish.pkid as u64)
            );
            return Ok(None);
        }
        let channel_id = topic.channel_id.to_string();
        let result = self
            .submit_publish_command(
                channel_id.as_str(),
                password,
                payload,
                IngressSource::MqttPublish,
            )
            .await;
        if result.is_err() {
            self.clear_mqtt_publish_fallback_dedupe(client, &publish);
        }
        result
    }

    fn reserve_mqtt_publish_fallback_dedupe(
        &self,
        client: &AuthenticatedMqttClient,
        publish: &Publish,
    ) -> MqttPublishDedupeDecision {
        self.runtime.publish_dedupe.reserve(
            mqtt_publish_fallback_dedupe_key(client, publish),
            chrono::Utc::now().timestamp_millis(),
        )
    }

    fn clear_mqtt_publish_fallback_dedupe(
        &self,
        client: &AuthenticatedMqttClient,
        publish: &Publish,
    ) {
        self.runtime
            .publish_dedupe
            .clear(mqtt_publish_fallback_dedupe_key(client, publish));
    }

    async fn submit_publish_command(
        &self,
        channel_id: &str,
        password: &str,
        payload: MqttPublishCommand,
        source: IngressSource,
    ) -> Result<Option<String>, MqttError> {
        let command = match payload {
            MqttPublishCommand::Message(payload) => {
                DomainCommandInput::Message(Box::new(MessageInput {
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
                }))
            }
            MqttPublishCommand::Event(command) => DomainCommandInput::Event(Box::new(EventInput {
                command,
                live_activity: None,
            })),
            MqttPublishCommand::Thing(command) => {
                DomainCommandInput::Thing(Box::new(ThingInput { command }))
            }
        };
        let outcome = submit_command(
            SubmitContext {
                runtime: self.runtime.state.as_ref(),
                now_millis: chrono::Utc::now().timestamp_millis(),
            },
            SubmitCommand {
                source,
                auth: SubmitAuth::ChannelPassword {
                    password: password.to_string(),
                },
                channel: ChannelSelector::ChannelId(channel_id.to_string()),
                command,
                response_mode: ResponseMode::MqttAck,
            },
        )
        .await
        .map_err(core_error_to_api_error)
        .map_err(mqtt_error_from_api)?;
        Ok(Some(outcome.summary.op_id))
    }
}

fn mqtt_publish_fallback_dedupe_key<'a>(
    client: &'a AuthenticatedMqttClient,
    publish: &'a Publish,
) -> MqttPublishDedupeKey<'a> {
    MqttPublishDedupeKey {
        client_id: client.dedupe_client_id.as_str(),
        packet_id: publish.pkid,
        topic: publish.topic.as_str(),
        payload: &publish.payload,
    }
}
