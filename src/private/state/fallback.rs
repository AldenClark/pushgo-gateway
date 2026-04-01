use super::*;
use crate::routing::derive_private_device_id;

impl PrivateState {
    pub fn schedule_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: impl Into<String>,
        due_at_unix_secs: i64,
    ) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
        if let Some(engine) = &self.fallback_tasks {
            if !engine.schedule(device_id, delivery_id.into(), due_at_unix_secs) {
                self.metrics.mark_enqueue_failure();
            }
            self.metrics.mark_task_queue_depth(engine.depth());
        }
    }

    pub fn request_fallback_resync(&self) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
        if let Some(engine) = &self.fallback_tasks {
            engine.request_resync();
        }
    }

    pub fn cancel_fallback(&self, device_id: DeviceId, delivery_id: &str) {
        if !private_provider_wakeup_pull_enabled() {
            return;
        }
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

    pub(in crate::private) async fn resolve_system_target(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> Option<SystemTarget> {
        let devices = self.hub.list_channel_devices(channel_id).await.ok()?;
        for item in devices {
            let registry_match = self
                .device_registry
                .find_device_key_by_provider_token(item.platform, item.token_str.as_ref())
                .map(|device_key| derive_private_device_id(device_key.as_str()))
                .is_some_and(|mapped_device_id| mapped_device_id == device_id);
            if registry_match {
                return Some(SystemTarget {
                    platform: item.platform,
                    token: Arc::clone(&item.token_str),
                });
            }
            let mapped = self
                .hub
                .lookup_device_for_token(item.platform, item.token_str.as_ref())
                .await
                .ok()?;
            if mapped == Some(device_id) {
                return Some(SystemTarget {
                    platform: item.platform,
                    token: Arc::clone(&item.token_str),
                });
            }
        }
        None
    }
}
