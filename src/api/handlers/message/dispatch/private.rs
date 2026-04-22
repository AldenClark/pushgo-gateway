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
                crate::util::TraceEvent::new("dispatch.private_enqueue_failed")
                    .field_redacted("correlation_id", prepared.correlation_id.as_ref())
                    .field_redacted("delivery_id", prepared.delivery_id.as_str())
                    .field_redacted("channel_id", prepared.channel_id_value.as_str())
                    .field_redacted("device_id", encode_lower_hex_128(&device_id))
                    .field_str("error", err.to_string())
                    .emit();
            }
        }
    }
}
