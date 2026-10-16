use mqttbytes::{
    QoS,
    v5::{Packet, PubAck, PubAckReason, Publish, PublishProperties},
};

use crate::{mqtt::MqttRole, private::protocol::DeliverEnvelope};

use super::{AuthenticatedMqttClient, MAX_INFLIGHT, MqttInflightDelivery, MqttSession};

impl MqttSession {
    pub(super) async fn handle_puback(&mut self, client: &AuthenticatedMqttClient, puback: PubAck) {
        let Some(device_id) = client.device_id else {
            self.runtime.private.metrics.mark_ack_non_ok();
            return;
        };
        if let Some(inflight) = self.inflight.remove(&puback.pkid) {
            let MqttInflightDelivery {
                delivery_id,
                ordinary,
            } = inflight;
            if puback.reason != PubAckReason::Success {
                self.runtime.private.metrics.mark_ack_non_ok();
                self.runtime.private.metrics.mark_mqtt_downlink_failure();
                self.log_failure(
                    "mqtt.puback_rejected",
                    format!("puback_rejected_{:?}", puback.reason).as_str(),
                );
                if !ordinary {
                    self.runtime.private.request_fallback_resync();
                }
                return;
            }
            let result = if ordinary {
                self.runtime
                    .private
                    .complete_ordinary_terminal_delivery(
                        device_id,
                        delivery_id.as_str(),
                        client.ordinary_route_generation,
                    )
                    .await
            } else {
                self.runtime
                    .private
                    .complete_terminal_delivery(device_id, delivery_id.as_str(), None)
                    .await
            };
            match result {
                Ok(cleared) if cleared || !ordinary => self.runtime.private.metrics.mark_ack_ok(),
                Ok(_) => self.runtime.private.metrics.mark_ack_non_ok(),
                Err(_) => self.runtime.private.metrics.mark_ack_non_ok(),
            }
        } else {
            self.runtime.private.metrics.mark_ack_non_ok();
            self.log_failure("mqtt.puback_unknown_packet_id", "unknown_packet_id");
        }
    }

    pub(super) async fn write_delivery(
        &mut self,
        device_id: Option<crate::storage::DeviceId>,
        envelope: DeliverEnvelope,
    ) -> Result<(), ()> {
        let existing_packet_id = envelope
            .ordinary
            .then(|| {
                self.inflight.iter().find_map(|(packet_id, delivery)| {
                    (delivery.delivery_id == envelope.delivery_id && delivery.ordinary)
                        .then_some(*packet_id)
                })
            })
            .flatten();
        if existing_packet_id.is_none() && self.inflight.len() >= MAX_INFLIGHT {
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            self.log_failure("mqtt.downlink_inflight_full", "receive_maximum_exceeded");
            return Err(());
        }
        let delivery_id = envelope.delivery_id.clone();
        let delivery = crate::mqtt::MqttDeliveryEnvelope::from_private_payload(
            delivery_id.clone(),
            &envelope.payload,
        )
        .map_err(|err| {
            self.runtime.private.metrics.mark_mqtt_downlink_dropped();
            self.log_failure("mqtt.downlink_payload_dropped", err.to_string().as_str());
        })?;
        let topic = crate::mqtt::MqttMessageTopic::format(delivery.channel_id.as_str());
        let mut publish = Publish::new(
            topic,
            QoS::AtLeastOnce,
            serde_json::to_vec(&delivery).map_err(|_| ())?,
        );
        publish.pkid = existing_packet_id.unwrap_or_else(|| self.next_packet_id());
        publish.dup = existing_packet_id.is_some();
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
                ("pushgo-channel-id".to_string(), delivery.channel_id.clone()),
            ],
            subscription_identifiers: Vec::new(),
            content_type: Some("application/json".to_string()),
        });
        if envelope.ordinary {
            let Some(device_id) = device_id else {
                return Err(());
            };
            match self
                .runtime
                .private
                .hub
                .authorize_ordinary_outbound(device_id, &envelope)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    if let Some(packet_id) = existing_packet_id {
                        self.inflight.remove(&packet_id);
                    }
                    return Ok(());
                }
                Err(error) => {
                    self.log_failure(
                        "mqtt.ordinary_authorization_failed",
                        error.to_string().as_str(),
                    );
                    return Err(());
                }
            }
        }
        if envelope.ordinary_expired_at(chrono::Utc::now().timestamp_millis()) {
            // Serialization, authorization or a queued retransmit can cross
            // the absolute deadline. Release the issued capability through its
            // durable authorization path; never synthesize a successful ACK.
            if let Some(device_id) = device_id {
                self.runtime
                    .private
                    .hub
                    .authorize_ordinary_outbound(device_id, &envelope)
                    .await
                    .map_err(|error| {
                        self.log_failure(
                            "mqtt.expired_ordinary_release_failed",
                            error.to_string().as_str(),
                        );
                    })?;
            }
            if let Some(packet_id) = existing_packet_id {
                self.inflight.remove(&packet_id);
            }
            return Ok(());
        }
        let ordinary = envelope.ordinary;
        if envelope.ordinary {
            self.runtime
                .private
                .hub
                .track_sent_outbound(device_id.ok_or(())?, envelope);
        }
        self.inflight.insert(
            publish.pkid,
            MqttInflightDelivery {
                delivery_id,
                ordinary,
            },
        );
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "mqtt.downlink_publish_prepared",
            mqtt_role = %(MqttRole::PrivateReceiver.as_str()),
            delivery_id = %(crate::util::redact_text(delivery.delivery_id.as_str())),
            channel_id = %(crate::util::redact_text(delivery.channel_id.as_str())),
            packet_id = (publish.pkid as u64)
        );
        if self.write_packet(Packet::Publish(publish)).await.is_err() {
            self.inflight
                .retain(|_, value| value.delivery_id != delivery.delivery_id);
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            return Err(());
        }
        self.runtime.private.metrics.mark_deliver_sent();
        self.runtime.private.metrics.mark_mqtt_downlink_sent();
        Ok(())
    }
}
