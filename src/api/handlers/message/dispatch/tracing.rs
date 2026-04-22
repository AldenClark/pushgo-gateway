use super::*;

pub(super) async fn record_provider_path_rejected(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    detail: impl Into<Cow<'static, str>>,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    crate::util::TraceEvent::new("dispatch.provider_path_rejected")
        .field_redacted("correlation_id", prepared.correlation_id.as_ref())
        .field_redacted("delivery_id", prepared.delivery_id.as_str())
        .field_redacted("channel_id", prepared.channel_id_value.as_str())
        .field_str("provider", target.device.platform.provider_name())
        .field_str("platform", target.device.platform.name())
        .field_redacted("device_token", target.device.token_str())
        .field_str("detail", detail.into().as_ref())
        .emit();
}

pub(super) async fn record_provider_enqueued(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
) {
    progress.record_provider_success(Arc::clone(&target.provider_stats_key));
    crate::util::TraceEvent::new("dispatch.provider_enqueued")
        .field_redacted("correlation_id", prepared.correlation_id.as_ref())
        .field_redacted("delivery_id", prepared.delivery_id.as_str())
        .field_redacted("channel_id", prepared.channel_id_value.as_str())
        .field_str("provider", target.device.platform.provider_name())
        .field_str("platform", target.device.platform.name())
        .field_str("path", path.as_str())
        .field_redacted("device_token", target.device.token_str())
        .emit();
}

pub(super) async fn record_provider_enqueue_failed(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
    err: &DispatchError,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    crate::util::TraceEvent::new("dispatch.provider_enqueue_failed")
        .field_redacted("correlation_id", prepared.correlation_id.as_ref())
        .field_redacted("delivery_id", prepared.delivery_id.as_str())
        .field_redacted("channel_id", prepared.channel_id_value.as_str())
        .field_str("provider", target.device.platform.provider_name())
        .field_str("platform", target.device.platform.name())
        .field_str("path", path.as_str())
        .field_redacted("device_token", target.device.token_str())
        .field_str("error_code", dispatch_error_code(err))
        .field_str("error", dispatch_error_detail(err))
        .emit();
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
    crate::util::TraceEvent::new("dispatch.provider_cache_enqueue_failed")
        .field_redacted("correlation_id", prepared.correlation_id.as_ref())
        .field_redacted("delivery_id", prepared.delivery_id.as_str())
        .field_redacted("channel_id", prepared.channel_id_value.as_str())
        .field_str("provider", target.device.platform.provider_name())
        .field_str("platform", target.device.platform.name())
        .field_redacted("device_token", target.device.token_str())
        .field_str("detail", detail.into().as_ref())
        .emit();
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
