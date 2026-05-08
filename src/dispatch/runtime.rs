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
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "dispatch.invalid_token_cleanup_lookup_failed",
                    provider = %(provider),
                    correlation_id = %(crate::util::redact_text(correlation_id)),
                    channel_id = %(crate::util::redact_text(channel_id)),
                    platform = %(platform.name()),
                    device_token = %(crate::util::redact_text(redact_device_token(device_token))),
                    error = %(err.to_string())
                );
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
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "dispatch.invalid_token_cleanup_outbox_clear_failed",
                provider = %(provider),
                correlation_id = %(crate::util::redact_text(correlation_id)),
                channel_id = %(crate::util::redact_text(channel_id)),
                platform = %(platform.name()),
                device_id = %(crate::util::redact_text(encode_crockford_base32_128(&device_id))),
                error = %(err.to_string())
            );
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
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "dispatch.provider_send_failed",
            provider = %(failure.provider),
            correlation_id = %(crate::util::redact_text(failure.correlation_id)),
            channel_id = %(crate::util::redact_text(failure.channel_id)),
            path = %(failure.path.as_str()),
            platform = %(failure.platform.map(Platform::name).unwrap_or("unknown")),
            device_token = %(crate::util::redact_text(redact_device_token(failure.device_token))),
            status_code = (u64::from(dispatch.status_code)),
            failure_kind = %(dispatch.failure_kind_name()),
            invalid_token = (dispatch.is_invalid_token()),
            payload_too_large = (dispatch.is_payload_too_large()),
            error = %(error)
        );
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
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "dispatch.provider_send_result",
            provider = %(provider),
            correlation_id = %(crate::util::redact_text(correlation_id)),
            delivery_id = %(crate::util::redact_text(delivery_id)),
            channel_id = %(crate::util::redact_text(channel_id)),
            path = %(path.as_str()),
            platform = %(platform.map(Platform::name).unwrap_or("unknown")),
            device_token = %(crate::util::redact_text(redact_device_token(device_token))),
            success = (dispatch.success),
            status_code = (u64::from(dispatch.status_code)),
            failure_kind = %(dispatch.failure_kind_name()),
            invalid_token = (dispatch.is_invalid_token()),
            payload_too_large = (dispatch.is_payload_too_large()),
            error = %(error)
        );
    }
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}
