use super::*;

impl PrivateState {
    pub fn schedule_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: impl Into<String>,
        due_at_unix_millis: i64,
    ) {
        let delivery_id = delivery_id.into();
        if let Some(engine) = &self.fallback_tasks {
            if !engine.schedule(device_id, delivery_id.clone(), due_at_unix_millis) {
                self.metrics.mark_enqueue_failure();
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "private.fallback_schedule_failed",
                    device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                    delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                    due_at_unix_millis = (due_at_unix_millis)
                );
            }
            self.metrics.mark_task_queue_depth(engine.depth());
        } else {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "private.fallback_schedule_skipped",
                reason = %("fallback_tasks_disabled")
            );
        }
    }

    pub fn request_fallback_resync(&self) {
        if let Some(engine) = &self.fallback_tasks {
            engine.request_resync();
        }
    }

    pub fn cancel_fallback(&self, device_id: DeviceId, delivery_id: &str) {
        if let Some(engine) = &self.fallback_tasks {
            if !engine.cancel(device_id, delivery_id) {
                self.metrics.mark_enqueue_failure();
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "private.fallback_cancel_failed",
                    device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                    delivery_id = %(crate::util::redact_text(delivery_id))
                );
            }
            self.metrics.mark_task_queue_depth(engine.depth());
        }
    }

    pub async fn mark_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        next_attempt_at: i64,
    ) -> Result<(), crate::Error> {
        self.hub
            .mark_fallback_sent(device_id, delivery_id, next_attempt_at)
            .await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.fallback_marked_sent",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            delivery_id = %(crate::util::redact_text(delivery_id)),
            next_attempt_at = (next_attempt_at)
        );
        self.schedule_fallback(device_id, delivery_id.to_string(), next_attempt_at);
        Ok(())
    }

    pub async fn defer_fallback_retry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        retry_at: i64,
    ) -> Result<(), crate::Error> {
        self.hub
            .defer_fallback_retry(device_id, delivery_id, retry_at)
            .await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.fallback_retry_deferred",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            delivery_id = %(crate::util::redact_text(delivery_id)),
            retry_at = (retry_at)
        );
        self.schedule_fallback(device_id, delivery_id.to_string(), retry_at);
        Ok(())
    }

    pub async fn clear_device_outbox(&self, device_id: DeviceId) -> Result<usize, crate::Error> {
        let delivery_ids = self.hub.clear_device_outbox(device_id).await?;
        if delivery_ids.is_empty() {
            return Ok(0);
        }
        for delivery_id in &delivery_ids {
            self.cancel_fallback(device_id, delivery_id.as_str());
        }
        if let Some(engine) = &self.fallback_tasks {
            engine.request_resync();
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.device_outbox_cleared",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            delivery_ids = (delivery_ids.len() as u64)
        );
        Ok(delivery_ids.len())
    }
}
