use super::*;
use crate::stats::{
    OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED,
    OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED,
    OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED, StatsCollector,
};

#[derive(Clone)]
pub(super) struct DispatchWorkerRuntime {
    pub(super) store: Storage,
    pub(super) private: Option<Arc<PrivateState>>,
    pub(super) stats: Arc<StatsCollector>,
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
                self.stats.record_ops_counter_now(
                    OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED,
                    1,
                );
                crate::util::TraceEvent::new("dispatch.invalid_token_cleanup_lookup_failed")
                    .field_str("provider", provider)
                    .field_redacted("correlation_id", correlation_id)
                    .field_redacted("channel_id", channel_id)
                    .field_str("platform", platform.name())
                    .field_redacted("device_token", redact_device_token(device_token))
                    .field_str("error", err.to_string())
                    .emit();
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
            self.stats.record_ops_counter_now(
                OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED,
                1,
            );
            crate::util::TraceEvent::new("dispatch.invalid_token_cleanup_outbox_clear_failed")
                .field_str("provider", provider)
                .field_redacted("correlation_id", correlation_id)
                .field_redacted("channel_id", channel_id)
                .field_str("platform", platform.name())
                .field_redacted("device_id", encode_crockford_base32_128(&device_id))
                .field_str("error", err.to_string())
                .emit();
        }
    }

    pub(super) fn log_provider_dispatch_failure(
        &self,
        failure: ProviderDispatchFailureLog<'_>,
        dispatch: &DispatchResult,
    ) {
        self.stats
            .record_ops_counter_now(OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED, 1);
        let error = dispatch
            .error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        crate::util::TraceEvent::new("dispatch.provider_send_failed")
            .field_str("provider", failure.provider)
            .field_redacted("correlation_id", failure.correlation_id)
            .field_redacted("channel_id", failure.channel_id)
            .field_str("path", failure.path.as_str())
            .field_str(
                "platform",
                failure.platform.map(Platform::name).unwrap_or("unknown"),
            )
            .field_redacted("device_token", redact_device_token(failure.device_token))
            .field_u64("status_code", dispatch.status_code.into())
            .field_bool("invalid_token", dispatch.invalid_token)
            .field_bool("payload_too_large", dispatch.payload_too_large)
            .field_str("error", error)
            .emit();
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
        let error = dispatch
            .error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        crate::util::TraceEvent::new("dispatch.provider_send_result")
            .field_str("provider", provider)
            .field_redacted("correlation_id", correlation_id)
            .field_redacted("delivery_id", delivery_id)
            .field_redacted("channel_id", channel_id)
            .field_str("path", path.as_str())
            .field_str(
                "platform",
                platform.map(Platform::name).unwrap_or("unknown"),
            )
            .field_redacted("device_token", redact_device_token(device_token))
            .field_bool("success", dispatch.success)
            .field_u64("status_code", dispatch.status_code.into())
            .field_bool("invalid_token", dispatch.invalid_token)
            .field_bool("payload_too_large", dispatch.payload_too_large)
            .field_str("error", error)
            .emit();
    }
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}
