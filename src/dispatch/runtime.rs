use super::*;
use crate::runtime_counters::{OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED, RuntimeCounterCollector};
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct ProviderFailureLogWindow {
    minute: u64,
    counts: HashMap<String, u64>,
}

impl ProviderFailureLogWindow {
    fn sample_count(&mut self, provider: &str, failure_kind: &str, minute: u64) -> Option<u64> {
        if self.minute != minute {
            self.minute = minute;
            self.counts.clear();
        }
        let key = format!("{provider}\0{failure_kind}");
        let count = self.counts.entry(key).or_default();
        *count = count.saturating_add(1);
        (*count <= 8 || count.is_power_of_two()).then_some(*count)
    }
}

static PROVIDER_FAILURE_LOG_WINDOW: LazyLock<Mutex<ProviderFailureLogWindow>> =
    LazyLock::new(|| Mutex::new(ProviderFailureLogWindow::default()));

fn provider_failure_log_sample_count(provider: &str, failure_kind: &str) -> Option<u64> {
    let minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 60)
        .unwrap_or_default();
    PROVIDER_FAILURE_LOG_WINDOW
        .lock()
        .ok()
        .and_then(|mut window| window.sample_count(provider, failure_kind, minute))
}

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
    pub(super) async fn finalize_provider_dispatch_outcome(
        &self,
        outcome: &ProviderDispatchOutcome,
    ) {
        let Some(success) = outcome.final_success() else {
            return;
        };
        self.store
            .finalize_provider_dispatch_outcome_durably(
                outcome.dedupe_key(),
                outcome.op_id(),
                outcome.delivery_id(),
                success,
            )
            .await;
    }

    pub(super) fn log_provider_dispatch_failure(
        &self,
        failure: ProviderDispatchFailureLog<'_>,
        dispatch: &DispatchResult,
    ) {
        self.runtime_counters
            .record_ops_counter_now(OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED, 1);
        let failure_kind = dispatch.failure_kind_name();
        let Some(sample_count) = provider_failure_log_sample_count(failure.provider, failure_kind)
        else {
            return;
        };
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
            failure_kind = %(failure_kind),
            sample_count = sample_count,
            invalid_token = (dispatch.is_invalid_token()),
            payload_too_large = (dispatch.is_payload_too_large()),
            error = %(error)
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_provider_dispatch_result(
        &self,
        provider: &'static str,
        channel_id_raw: [u8; 16],
        correlation_id: &str,
        delivery_id: &str,
        channel_id: &str,
        path: ProviderDeliveryPath,
        platform: Option<Platform>,
        device_token: &str,
        device_key: &str,
        dispatch: &DispatchResult,
    ) {
        self.runtime_counters.record_provider_send_result(
            channel_id_raw,
            device_key,
            dispatch.success,
        );
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

#[cfg(test)]
mod failure_log_tests {
    use super::ProviderFailureLogWindow;

    #[test]
    fn provider_failure_logs_are_bounded_per_kind_and_reset_each_minute() {
        let mut window = ProviderFailureLogWindow::default();
        let emitted = (1..=100)
            .filter(|_| window.sample_count("APNS", "network", 42).is_some())
            .count();
        assert_eq!(emitted, 11, "first eight plus powers of two through 64");
        assert_eq!(window.sample_count("FCM", "network", 42), Some(1));
        assert_eq!(window.sample_count("APNS", "invalid_token", 42), Some(1));
        assert_eq!(window.sample_count("APNS", "network", 43), Some(1));
    }
}
