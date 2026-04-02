use super::{types::TerminalDeliveryDisposition, *};

impl PrivateState {
    pub async fn enqueue_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        payload: Vec<u8>,
        sent_at: i64,
        expires_at: i64,
    ) -> Result<(), crate::Error> {
        let outcome = self
            .hub
            .enqueue_private_message(device_id, delivery_id, payload, sent_at, expires_at)
            .await?;
        if outcome.private_outbox_pruned > 0
            && let Some(engine) = &self.fallback_tasks
        {
            engine.request_resync();
        }
        if provider_wakeup_pull_enabled() && self.hub.is_online(device_id) {
            self.schedule_fallback(
                device_id,
                delivery_id.to_string(),
                sent_at + self.config.ack_timeout_secs.max(1) as i64,
            );
        }
        Ok(())
    }

    pub async fn complete_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        seq: Option<u64>,
    ) -> Result<bool, crate::Error> {
        self.settle_terminal_delivery(
            device_id,
            delivery_id,
            seq,
            TerminalDeliveryDisposition::Acked,
        )
        .await
    }

    pub async fn drop_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<bool, crate::Error> {
        self.settle_terminal_delivery(
            device_id,
            delivery_id,
            None,
            TerminalDeliveryDisposition::Dropped,
        )
        .await
    }

    async fn settle_terminal_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        seq: Option<u64>,
        disposition: TerminalDeliveryDisposition,
    ) -> Result<bool, crate::Error> {
        let resolved_delivery_id = if let Some(seq) = seq {
            self.hub
                .ack_by_seq(device_id, seq, Some(delivery_id))
                .await?
        } else {
            Some(delivery_id.to_owned())
        };
        let Some(resolved_delivery_id) = resolved_delivery_id else {
            return Ok(false);
        };
        let channel_id = self
            .resolve_channel_id_for_delivery(resolved_delivery_id.as_str())
            .await;
        self.hub
            .ack_delivery(device_id, resolved_delivery_id.as_str())
            .await?;
        let cleared = true;
        if cleared {
            self.cancel_fallback(device_id, resolved_delivery_id.as_str());
            if disposition == TerminalDeliveryDisposition::Acked {
                self.stats.record_private_ack_with_channel(
                    format!("private:{}", encode_lower_hex_128(&device_id)),
                    channel_id,
                    1,
                    chrono::Utc::now().timestamp(),
                );
            }
        }
        Ok(cleared)
    }

    async fn resolve_channel_id_for_delivery(&self, delivery_id: &str) -> Option<[u8; 16]> {
        if let Ok(Some(context)) = self
            .hub
            .store()
            .load_private_payload_context(delivery_id)
            .await
            && context.channel_id.is_some()
        {
            return context.channel_id;
        }

        let message = self
            .hub
            .load_private_message(delivery_id)
            .await
            .ok()
            .flatten()?;
        let envelope = protocol::PrivatePayloadEnvelope::decode_postcard(&message.payload)?;
        if !envelope.is_supported_version() {
            return None;
        }
        envelope.parsed_channel_id()
    }
}
