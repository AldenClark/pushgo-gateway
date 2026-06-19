use super::*;
use crate::runtime_counters::{OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED, RuntimeCounterCollector};

#[derive(Clone)]
pub(super) struct DispatchWorkerRuntime {
    pub(super) store: Storage,
    pub(super) private: Option<Arc<PrivateState>>,
    pub(super) runtime_counters: Arc<RuntimeCounterCollector>,
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
    pub(super) fn log_provider_dispatch_failure(
        &self,
        failure: ProviderDispatchFailureLog<'_>,
        dispatch: &DispatchResult,
    ) {
        self.runtime_counters
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
