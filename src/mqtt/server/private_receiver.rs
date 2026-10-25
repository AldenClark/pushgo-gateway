use mqttbytes::{
    QoS,
    v5::{Packet, PubAck, PubAckReason, Publish, PublishProperties},
};

#[cfg(any(test, feature = "qa"))]
use crate::ordinary::profiling::{Path as ProfilePath, Phase as ProfilePhase};
use crate::{mqtt::MqttRole, private::protocol::DeliverEnvelope};

use super::{AuthenticatedMqttClient, MAX_INFLIGHT, MqttInflightDelivery, MqttSession};

fn fresh_source_order(ordinary_first: bool) -> [bool; 2] {
    [ordinary_first, !ordinary_first]
}

fn record_fresh_handoff(ordinary_first: &mut bool, ordinary: bool, fresh: bool) {
    if fresh {
        *ordinary_first = !ordinary;
    }
}

impl MqttSession {
    pub(super) async fn try_write_fresh_delivery(
        &mut self,
        client: &AuthenticatedMqttClient,
    ) -> Result<bool, ()> {
        // Only successful fresh handoffs rotate this connection's single bit.
        // An empty source or a full ordinary claim window falls through in the
        // same turn. The existing owned-retransmit branch keeps its order.
        for ordinary in fresh_source_order(self.ordinary_first) {
            let envelope = if ordinary {
                let Some(device_id) = client.device_id else {
                    continue;
                };
                // Keep the durable claim outside the cancellable packet select.
                self.runtime
                    .private
                    .hub
                    .ordinary_outbound(device_id, client.ordinary_route_generation)
                    .await
                    .map_err(|error| {
                        self.log_failure("mqtt.ordinary_claim_failed", error.to_string().as_str());
                    })?
            } else {
                client.rx.as_ref().and_then(|rx| rx.try_recv().ok())
            };
            if let Some(envelope) = envelope {
                self.write_delivery(client.device_id, envelope, true)
                    .await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn handle_puback(&mut self, client: &AuthenticatedMqttClient, puback: PubAck) {
        // This QA-only caller timer includes retained, unknown and non-success
        // PUBACKs too. It starts after decode, not when bytes reach the socket.
        #[cfg(any(test, feature = "qa"))]
        let profile_store = self.runtime.state.store.ordinary_handle();
        #[cfg(any(test, feature = "qa"))]
        let _caller = profile_store.as_ref().map(|store| {
            store
                .counters
                .profile
                .timer(ProfilePath::MqttAck, ProfilePhase::CallerWall)
        });
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
        fresh: bool,
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
        let write_result = {
            #[cfg(any(test, feature = "qa"))]
            let profile_store = ordinary
                .then(|| self.runtime.state.store.ordinary_handle())
                .flatten();
            #[cfg(any(test, feature = "qa"))]
            let _wire_write = profile_store.as_ref().map(|store| {
                store
                    .counters
                    .profile
                    .timer(ProfilePath::PrivateClaim, ProfilePhase::WireWrite)
            });
            self.write_packet(Packet::Publish(publish)).await
        };
        if write_result.is_err() {
            self.inflight
                .retain(|_, value| value.delivery_id != delivery.delivery_id);
            self.runtime.private.metrics.mark_deliver_send_failure();
            self.runtime.private.metrics.mark_mqtt_downlink_failure();
            return Err(());
        }
        self.runtime.private.metrics.mark_deliver_sent();
        self.runtime.private.metrics.mark_mqtt_downlink_sent();
        record_fresh_handoff(&mut self.ordinary_first, ordinary, fresh);
        Ok(())
    }
}

#[cfg(test)]
mod fresh_source_tests {
    use super::{fresh_source_order, record_fresh_handoff};

    #[test]
    fn continuously_ready_sources_alternate_successful_fresh_handoffs() {
        let mut ordinary_first = true;
        let mut handed = [0usize; 2];
        for _ in 0..128 {
            let source = fresh_source_order(ordinary_first)[0];
            handed[usize::from(source)] += 1;
            record_fresh_handoff(&mut ordinary_first, source, true);
        }
        assert_eq!(handed, [64, 64]);
    }

    #[test]
    fn empty_or_capacity_limited_preferred_source_falls_back_in_the_same_turn() {
        for preferred in [false, true] {
            let mut ordinary_first = preferred;
            let selected = fresh_source_order(ordinary_first)
                .into_iter()
                .find(|source| *source != preferred)
                .unwrap();
            assert_eq!(selected, !preferred);
            record_fresh_handoff(&mut ordinary_first, selected, true);
            assert_eq!(ordinary_first, preferred);
        }
    }

    #[test]
    fn owned_retransmit_does_not_rotate_preference() {
        for preferred in [false, true] {
            let mut ordinary_first = preferred;
            record_fresh_handoff(&mut ordinary_first, preferred, false);
            assert_eq!(ordinary_first, preferred);
            assert_eq!(fresh_source_order(ordinary_first), [preferred, !preferred]);
        }
    }
}
