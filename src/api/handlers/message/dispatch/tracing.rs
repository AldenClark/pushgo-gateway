use super::*;

pub(super) async fn record_provider_path_rejected(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    detail: impl Into<Cow<'static, str>>,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "dispatch.provider_path_rejected",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        provider = %(target.device.platform.provider_name()),
        platform = %(target.device.platform.name()),
        device_token = %(crate::util::redact_text(target.device.token_str())),
        detail = %(detail.into().as_ref())
    );
}

pub(super) async fn record_provider_enqueued(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
) {
    progress.record_provider_success(Arc::clone(&target.provider_stats_key));
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.provider_enqueued",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        provider = %(target.device.platform.provider_name()),
        platform = %(target.device.platform.name()),
        path = %(path.as_str()),
        device_token = %(crate::util::redact_text(target.device.token_str()))
    );
}

pub(super) async fn record_provider_enqueue_failed(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
    err: &DispatchError,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "dispatch.provider_enqueue_failed",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        provider = %(target.device.platform.provider_name()),
        platform = %(target.device.platform.name()),
        path = %(path.as_str()),
        device_token = %(crate::util::redact_text(target.device.token_str())),
        error_code = %(dispatch_error_code(err)),
        error = %(dispatch_error_detail(err))
    );
    if matches!(err, DispatchError::ChannelClosed) {
        progress.dispatch_closed = true;
    }
}

pub(super) async fn record_provider_cache_enqueue_failed(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    detail: impl Into<Cow<'static, str>>,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "dispatch.provider_cache_enqueue_failed",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        provider = %(target.device.platform.provider_name()),
        platform = %(target.device.platform.name()),
        device_token = %(crate::util::redact_text(target.device.token_str())),
        detail = %(detail.into().as_ref())
    );
}

pub(super) fn dispatch_error_detail(error: &DispatchError) -> &'static str {
    match error {
        DispatchError::QueueFull => "dispatch queue is full",
        DispatchError::ChannelClosed => "dispatch worker channel is closed",
    }
}

pub(super) fn dispatch_error_code(error: &DispatchError) -> &'static str {
    match error {
        DispatchError::QueueFull => "queue_full",
        DispatchError::ChannelClosed => "channel_closed",
    }
}
