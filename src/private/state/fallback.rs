use super::*;

impl PrivateState {
    pub fn schedule_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: impl Into<String>,
        due_at_unix_secs: i64,
    ) {
        if let Some(engine) = &self.fallback_tasks {
            if !engine.schedule(device_id, delivery_id.into(), due_at_unix_secs) {
                self.metrics.mark_enqueue_failure();
            }
            self.metrics.mark_task_queue_depth(engine.depth());
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
        Ok(delivery_ids.len())
    }
}
