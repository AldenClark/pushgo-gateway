use super::*;

pub(super) async fn record_provider_path_rejected(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    detail: impl Into<Cow<'static, str>>,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    append_delivery_audit_best_effort(
        prepared.state,
        prepared.correlation_id.as_ref(),
        &DeliveryAuditWrite {
            delivery_id: prepared.delivery_id.clone(),
            channel_id: prepared.channel_id,
            device_key: target.provider_audit_key.clone(),
            entity_type: Some(prepared.entity_type.to_string()),
            entity_id: Some(prepared.entity_id.clone()),
            op_id: Some(prepared.op_id.clone()),
            path: AUDIT_PATH_PROVIDER,
            status: AUDIT_STATUS_PATH_REJECTED,
            error_code: Some("provider_path_rejected".to_string()),
            created_at: prepared.sent_at,
        },
    )
    .await;
    prepared.state.dispatch_audit.record(DispatchAuditRecord {
        stage: "provider_path_rejected",
        correlation_id: prepared.correlation_id.as_ref(),
        delivery_id: Some(prepared.delivery_id.as_str()),
        channel_id: Some(prepared.channel_id_value.as_str()),
        provider: Some(target.device.platform.provider_name()),
        platform: Some(target.device.platform),
        path: None,
        device_token: Some(target.device.token_str()),
        success: None,
        status_code: None,
        invalid_token: None,
        payload_too_large: None,
        detail: Some(detail.into()),
    });
}

pub(super) async fn record_provider_enqueued(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
) {
    progress.record_provider_success(Arc::clone(&target.provider_stats_key));
    append_delivery_audit_best_effort(
        prepared.state,
        prepared.correlation_id.as_ref(),
        &DeliveryAuditWrite {
            delivery_id: prepared.delivery_id.clone(),
            channel_id: prepared.channel_id,
            device_key: target.provider_audit_key.clone(),
            entity_type: Some(prepared.entity_type.to_string()),
            entity_id: Some(prepared.entity_id.clone()),
            op_id: Some(prepared.op_id.clone()),
            path: path.audit_path(),
            status: AUDIT_STATUS_ENQUEUED,
            error_code: None,
            created_at: prepared.sent_at,
        },
    )
    .await;
    prepared.state.dispatch_audit.record(DispatchAuditRecord {
        stage: "provider_enqueued",
        correlation_id: prepared.correlation_id.as_ref(),
        delivery_id: Some(prepared.delivery_id.as_str()),
        channel_id: Some(prepared.channel_id_value.as_str()),
        provider: Some(target.device.platform.provider_name()),
        platform: Some(target.device.platform),
        path: Some(path.as_str()),
        device_token: Some(target.device.token_str()),
        success: Some(true),
        status_code: None,
        invalid_token: None,
        payload_too_large: None,
        detail: None,
    });
}

pub(super) async fn record_provider_enqueue_failed(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
    path: ProviderDeliveryPath,
    err: &DispatchError,
) {
    progress.record_provider_failure(Arc::clone(&target.provider_stats_key));
    append_delivery_audit_best_effort(
        prepared.state,
        prepared.correlation_id.as_ref(),
        &DeliveryAuditWrite {
            delivery_id: prepared.delivery_id.clone(),
            channel_id: prepared.channel_id,
            device_key: target.provider_audit_key.clone(),
            entity_type: Some(prepared.entity_type.to_string()),
            entity_id: Some(prepared.entity_id.clone()),
            op_id: Some(prepared.op_id.clone()),
            path: path.audit_path(),
            status: AUDIT_STATUS_ENQUEUE_FAILED,
            error_code: Some(dispatch_error_code(err).to_string()),
            created_at: prepared.sent_at,
        },
    )
    .await;
    prepared.state.dispatch_audit.record(DispatchAuditRecord {
        stage: "provider_enqueue_failed",
        correlation_id: prepared.correlation_id.as_ref(),
        delivery_id: Some(prepared.delivery_id.as_str()),
        channel_id: Some(prepared.channel_id_value.as_str()),
        provider: Some(target.device.platform.provider_name()),
        platform: Some(target.device.platform),
        path: Some(path.as_str()),
        device_token: Some(target.device.token_str()),
        success: Some(false),
        status_code: None,
        invalid_token: None,
        payload_too_large: None,
        detail: Some(dispatch_error_detail(err).into()),
    });
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
    append_delivery_audit_best_effort(
        prepared.state,
        prepared.correlation_id.as_ref(),
        &DeliveryAuditWrite {
            delivery_id: prepared.delivery_id.clone(),
            channel_id: prepared.channel_id,
            device_key: target.provider_audit_key.clone(),
            entity_type: Some(prepared.entity_type.to_string()),
            entity_id: Some(prepared.entity_id.clone()),
            op_id: Some(prepared.op_id.clone()),
            path: AUDIT_PATH_PROVIDER,
            status: AUDIT_STATUS_ENQUEUE_FAILED,
            error_code: Some("provider_cache_enqueue_failed".to_string()),
            created_at: prepared.sent_at,
        },
    )
    .await;
    prepared.state.dispatch_audit.record(DispatchAuditRecord {
        stage: "provider_cache_enqueue_failed",
        correlation_id: prepared.correlation_id.as_ref(),
        delivery_id: Some(prepared.delivery_id.as_str()),
        channel_id: Some(prepared.channel_id_value.as_str()),
        provider: Some(target.device.platform.provider_name()),
        platform: Some(target.device.platform),
        path: None,
        device_token: Some(target.device.token_str()),
        success: Some(false),
        status_code: None,
        invalid_token: None,
        payload_too_large: None,
        detail: Some(detail.into()),
    });
}

pub(super) async fn append_delivery_audit_best_effort(
    state: &AppState,
    correlation_id: &str,
    entry: &DeliveryAuditWrite,
) {
    state.delivery_audit.enqueue(correlation_id, entry);
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
