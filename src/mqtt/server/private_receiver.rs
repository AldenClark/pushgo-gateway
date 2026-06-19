use mqttbytes::{
    QoS,
    v5::{Packet, Publish, PublishProperties},
};

use crate::{mqtt::MqttRole, private::protocol::DeliverEnvelope};

use super::{AuthenticatedMqttClient, MAX_INFLIGHT, MqttSession};

impl MqttSession {
    pub(super) async fn handle_puback(&mut self, client: &AuthenticatedMqttClient, pkid: u16) {
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

    pub(super) async fn write_delivery(&mut self, envelope: DeliverEnvelope) -> Result<(), ()> {
        if self.inflight.len() >= MAX_INFLIGHT {
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
                ("pushgo-channel-id".to_string(), delivery.channel_id.clone()),
            ],
            subscription_identifiers: Vec::new(),
            content_type: Some("application/json".to_string()),
        });
        self.inflight.insert(publish.pkid, delivery_id);
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
                .retain(|_, value| value != &delivery.delivery_id);
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            return Err(());
        }
        self.runtime.private.metrics.mark_deliver_sent();
        self.runtime.private.metrics.mark_mqtt_downlink_sent();
        Ok(())
    }
}
