use super::*;

#[derive(Clone)]
pub(super) struct DispatchWorkerRuntime {
    pub(super) store: Storage,
    pub(super) private: Option<Arc<PrivateState>>,
    pub(super) audit: Arc<DispatchAuditLog>,
    pub(super) retry_config: ProviderPullRetryConfig,
}

pub(super) struct ProviderDispatchFailureLog<'a> {
    pub(super) provider: &'a str,
    pub(super) correlation_id: &'a str,
    pub(super) channel_id: &'a str,
    pub(super) path: ProviderDeliveryPath,
    pub(super) platform: Option<Platform>,
    pub(super) device_token: &'a str,
}

impl DispatchWorkerRuntime {
    pub(super) async fn enqueue_provider_pull_delivery(
        &self,
        delivery: &ProviderPullDelivery,
        provider: &str,
        correlation_id: &str,
        channel_id: &str,
    ) -> bool {
        let message = PrivateMessage {
            payload: delivery.payload.as_ref().clone(),
            size: delivery.payload.len(),
            sent_at: delivery.sent_at,
            expires_at: delivery.expires_at,
        };
        match self
            .store
            .enqueue_provider_pull_item(
                delivery.delivery_id.as_ref(),
                &message,
                delivery.platform,
                delivery.provider_token.as_ref(),
                delivery
                    .sent_at
                    .saturating_add(self.retry_config.timeout_secs as i64),
            )
            .await
        {
            Ok(()) => true,
            Err(err) => {
                if let Some(private_state) = self.private.as_deref() {
                    private_state.metrics.mark_enqueue_failure();
                }
                crate::util::diagnostics_log(format_args!(
                    "provider wakeup pull cache enqueue failed provider={} correlation_id={} channel_id={} device_id={} delivery_id={} error={}",
                    provider,
                    correlation_id,
                    channel_id,
                    encode_crockford_base32_128(&delivery.device_id),
                    delivery.delivery_id,
                    err,
                ));
                false
            }
        }
    }

    pub(super) async fn cleanup_private_outbox_on_invalid_token(
        &self,
        platform: Platform,
        device_token: &str,
        provider: &str,
        correlation_id: &str,
        channel_id: &str,
    ) {
        let device_id = match self
            .store
            .lookup_private_device(platform, device_token)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                crate::util::diagnostics_log(format_args!(
                    "invalid token cleanup lookup failed provider={} correlation_id={} channel_id={} platform={} device_token={} error={}",
                    provider,
                    correlation_id,
                    channel_id,
                    platform.name(),
                    redact_device_token(device_token),
                    err,
                ));
                return;
            }
        };
        let Some(device_id) = device_id else {
            return;
        };
        let cleared_result = if let Some(private_state) = self.private.as_deref() {
            private_state.clear_device_outbox(device_id).await
        } else {
            self.store
                .clear_private_outbox_for_device(device_id)
                .await
                .map(|entries| entries.len())
                .map_err(|err| crate::Error::Internal(err.to_string()))
        };
        if let Err(err) = cleared_result {
            crate::util::diagnostics_log(format_args!(
                "invalid token cleanup outbox clear failed provider={} correlation_id={} channel_id={} platform={} device_id={} error={}",
                provider,
                correlation_id,
                channel_id,
                platform.name(),
                encode_crockford_base32_128(&device_id),
                err,
            ));
        }
    }

    pub(super) fn log_provider_dispatch_failure(
        &self,
        failure: ProviderDispatchFailureLog<'_>,
        dispatch: &DispatchResult,
    ) {
        let error = dispatch
            .error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        crate::util::diagnostics_log(format_args!(
            "provider dispatch failed provider={} correlation_id={} channel_id={} path={} platform={} device_token={} status_code={} invalid_token={} payload_too_large={} error={}",
            failure.provider,
            failure.correlation_id,
            failure.channel_id,
            failure.path.as_str(),
            failure.platform.map(Platform::name).unwrap_or("unknown"),
            redact_device_token(failure.device_token),
            dispatch.status_code,
            dispatch.invalid_token,
            dispatch.payload_too_large,
            error,
        ));
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_provider_dispatch_result(
        &self,
        provider: &'static str,
        correlation_id: &str,
        delivery_id: &str,
        channel_id: &str,
        path: ProviderDeliveryPath,
        platform: Option<Platform>,
        device_token: &str,
        dispatch: &DispatchResult,
    ) {
        self.audit.record(DispatchAuditRecord {
            stage: "provider_send_result",
            correlation_id,
            delivery_id: Some(delivery_id),
            channel_id: Some(channel_id),
            provider: Some(provider),
            platform,
            path: Some(path.as_str()),
            device_token: Some(device_token),
            success: Some(dispatch.success),
            status_code: Some(dispatch.status_code),
            invalid_token: Some(dispatch.invalid_token),
            payload_too_large: Some(dispatch.payload_too_large),
            detail: dispatch.error.as_ref().map(|err| err.to_string().into()),
        });
    }
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}
