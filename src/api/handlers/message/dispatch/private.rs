use super::*;

pub(super) async fn enqueue_private_deliveries(
    prepared: &PreparedDispatch<'_>,
    progress: &mut DispatchProgress,
) {
    let Some(private_dispatch) = prepared.private_dispatch.as_ref() else {
        return;
    };
    let private_expires_at = prepared
        .effective_ttl
        .unwrap_or(prepared.sent_at + prepared.private_default_ttl_secs);
    for device_id in private_dispatch.subscribers.iter().copied() {
        match private_dispatch
            .state
            .enqueue_private_delivery(
                device_id,
                prepared.delivery_id.as_str(),
                prepared.private_payload.clone(),
                prepared.sent_at,
                private_expires_at,
            )
            .await
        {
            Ok(()) => {
                progress.private_enqueue_stats.record_success();
                progress.record_private_success(device_id);
                append_delivery_audit_best_effort(
                    prepared.state,
                    prepared.correlation_id.as_ref(),
                    &DeliveryAuditWrite {
                        delivery_id: prepared.delivery_id.clone(),
                        channel_id: prepared.channel_id,
                        device_key: format!("private:{}", encode_lower_hex_128(&device_id)),
                        entity_type: Some(prepared.entity_type.to_string()),
                        entity_id: Some(prepared.entity_id.clone()),
                        op_id: Some(prepared.op_id.clone()),
                        path: AUDIT_PATH_PRIVATE_OUTBOX,
                        status: AUDIT_STATUS_ENQUEUED,
                        error_code: None,
                        created_at: prepared.sent_at,
                    },
                )
                .await;
                if private_dispatch.state.hub.is_online(device_id) {
                    let delivered = private_dispatch.state.hub.try_deliver_to_device(
                        device_id,
                        crate::private::protocol::DeliverEnvelope {
                            delivery_id: prepared.delivery_id.clone(),
                            payload: prepared.private_payload.clone(),
                        },
                    );
                    if delivered {
                        progress.private_realtime_delivered.insert(device_id);
                    } else {
                        private_dispatch.state.metrics.mark_deliver_send_failure();
                    }
                }
            }
            Err(err) => {
                progress.private_enqueue_stats.record_failure(
                    "private_subscriber",
                    device_id,
                    &err,
                );
                private_dispatch.state.metrics.mark_enqueue_failure();
                append_delivery_audit_best_effort(
                    prepared.state,
                    prepared.correlation_id.as_ref(),
                    &DeliveryAuditWrite {
                        delivery_id: prepared.delivery_id.clone(),
                        channel_id: prepared.channel_id,
                        device_key: format!("private:{}", encode_lower_hex_128(&device_id)),
                        entity_type: Some(prepared.entity_type.to_string()),
                        entity_id: Some(prepared.entity_id.clone()),
                        op_id: Some(prepared.op_id.clone()),
                        path: AUDIT_PATH_PRIVATE_OUTBOX,
                        status: AUDIT_STATUS_ENQUEUE_FAILED,
                        error_code: Some("private_enqueue_failed".to_string()),
                        created_at: prepared.sent_at,
                    },
                )
                .await;
            }
        }
    }
}
