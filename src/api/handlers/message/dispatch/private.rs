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
        .unwrap_or(prepared.sent_at + prepared.private_default_ttl_secs * 1000);
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
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "dispatch.private_realtime_delivery_failed",
                            correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
                            delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
                            channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
                            device_id = %(crate::util::redact_text(encode_lower_hex_128(&device_id)))
                        );
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
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "dispatch.private_enqueue_failed",
                    correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
                    delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
                    channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
                    device_id = %(crate::util::redact_text(encode_lower_hex_128(&device_id))),
                    error = %(err.to_string())
                );
            }
        }
    }
}
