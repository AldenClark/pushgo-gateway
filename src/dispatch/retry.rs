use super::*;
use crate::util::build_provider_wakeup_data;

pub(crate) struct ProviderPullRetryWorkerDeps {
    pub store: Storage,
    pub apns: Arc<dyn ApnsClient>,
    pub fcm: Arc<dyn FcmClient>,
    pub wns: Arc<dyn WnsClient>,
    pub audit: Arc<DispatchAuditLog>,
}

impl ProviderPullRetryWorkerDeps {
    pub(crate) fn spawn(self) {
        let worker = ProviderPullRetryWorker {
            store: self.store,
            apns: self.apns,
            fcm: self.fcm,
            wns: self.wns,
            audit: self.audit,
            config: ProviderPullRetryConfig::from_env(),
        };
        tokio::spawn(async move {
            worker.run().await;
        });
    }
}

pub(super) struct ProviderPullRetryWorker {
    pub(super) store: Storage,
    pub(super) apns: Arc<dyn ApnsClient>,
    pub(super) fcm: Arc<dyn FcmClient>,
    pub(super) wns: Arc<dyn WnsClient>,
    pub(super) audit: Arc<DispatchAuditLog>,
    pub(super) config: ProviderPullRetryConfig,
}

impl ProviderPullRetryWorker {
    pub(super) async fn run(self) {
        loop {
            let now = chrono::Utc::now().timestamp();
            let due_entries = match self
                .store
                .list_provider_pull_retry_due(now, self.config.batch_size)
                .await
            {
                Ok(entries) => entries,
                Err(err) => {
                    crate::util::diagnostics_log(format_args!(
                        "provider pull retry load due failed error={}",
                        err
                    ));
                    tokio::time::sleep(self.config.poll_interval()).await;
                    continue;
                }
            };

            for entry in due_entries {
                let dispatch = self.send_wakeup(&entry).await;
                self.audit.record(DispatchAuditRecord {
                    stage: "provider_pull_retry_send_result",
                    correlation_id: "provider_pull_retry",
                    delivery_id: Some(entry.delivery_id.as_str()),
                    channel_id: None,
                    provider: Some(entry.platform.provider_name()),
                    platform: Some(entry.platform),
                    path: Some(ProviderDeliveryPath::WakeupPull.as_str()),
                    device_token: Some(entry.provider_token.as_str()),
                    success: Some(dispatch.success),
                    status_code: Some(dispatch.status_code),
                    invalid_token: Some(dispatch.invalid_token),
                    payload_too_large: Some(dispatch.payload_too_large),
                    detail: dispatch.error.as_ref().map(|err| err.to_string().into()),
                });

                if dispatch.invalid_token || entry.expires_at <= now {
                    let _ = self
                        .store
                        .clear_provider_pull_retry(entry.delivery_id.as_str())
                        .await;
                    continue;
                }

                let next_retry_at = now.saturating_add(self.config.timeout_secs as i64);
                let _ = self
                    .store
                    .bump_provider_pull_retry(entry.delivery_id.as_str(), next_retry_at, now)
                    .await;
            }

            tokio::time::sleep(self.config.poll_interval()).await;
        }
    }

    async fn send_wakeup(&self, entry: &crate::storage::ProviderPullRetryEntry) -> DispatchResult {
        let data = Self::wakeup_data(entry.delivery_id.as_str());
        let wakeup_title = self.wakeup_title(entry.delivery_id.as_str()).await;
        match entry.platform {
            Platform::IOS | Platform::MACOS | Platform::WATCHOS => {
                let payload = Arc::new(ApnsPayload::wakeup(
                    wakeup_title,
                    None,
                    Some(entry.expires_at),
                    data,
                ));
                self.apns
                    .send_to_device(entry.provider_token.as_str(), entry.platform, payload, None)
                    .await
            }
            Platform::ANDROID => {
                let payload = Arc::new(FcmPayload::new(data, "HIGH", None));
                self.fcm
                    .send_to_device(entry.provider_token.as_str(), payload, None)
                    .await
            }
            Platform::WINDOWS => {
                let payload = Arc::new(WnsPayload::new(data, "high", None));
                self.wns
                    .send_to_device(entry.provider_token.as_str(), payload)
                    .await
            }
        }
    }

    pub(super) fn wakeup_data(delivery_id: &str) -> HashMap<String, String> {
        let mut base = HashMap::new();
        base.insert("delivery_id".to_string(), delivery_id.to_string());
        build_provider_wakeup_data(&base)
    }

    async fn wakeup_title(&self, delivery_id: &str) -> Option<String> {
        let message = self
            .store
            .load_private_message(delivery_id)
            .await
            .ok()
            .flatten()?;
        crate::api::handlers::message::wakeup_notification_title_from_private_payload(
            &message.payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderPullRetryConfig, ProviderPullRetryWorker};

    #[test]
    fn provider_retry_wakeup_data_contains_wakeup_markers() {
        let data = ProviderPullRetryWorker::wakeup_data("delivery-001");
        assert_eq!(
            data.get("delivery_id").map(String::as_str),
            Some("delivery-001")
        );
        assert_eq!(
            data.get("provider_mode").map(String::as_str),
            Some("wakeup")
        );
        assert_eq!(data.get("provider_wakeup").map(String::as_str), Some("1"));
    }

    #[test]
    fn provider_pull_retry_config_clamps_values() {
        assert_eq!(ProviderPullRetryConfig::clamp_poll_ms(10), 200);
        assert_eq!(ProviderPullRetryConfig::clamp_batch_size(10_000), 2_000);
        assert_eq!(ProviderPullRetryConfig::clamp_timeout_secs(1), 5);
    }
}
