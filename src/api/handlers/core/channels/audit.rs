use crate::{
    api::Error, app::AppState, routing::DeviceRouteRecord, storage::SubscriptionAuditWrite,
};

pub(super) async fn append_subscription_audit(
    state: &AppState,
    channel_id: [u8; 16],
    device_key: &str,
    action: &str,
    route: &DeviceRouteRecord,
) -> Result<(), Error> {
    let now = chrono::Utc::now().timestamp_millis();
    state
        .store
        .append_subscription_audit(&SubscriptionAuditWrite {
            channel_id,
            device_key: device_key.to_string(),
            action: action.to_string(),
            platform: route.platform.name().to_string(),
            channel_type: route.channel_type.as_str().to_string(),
            created_at: now,
        })
        .await
        .inspect_err(|err| {
                        ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.subscription_audit_failed",
                device_key = %(crate::util::redact_text(device_key)),
                channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
                action = %(action),
                error = %(err.to_string())
            );
        })?;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "channel.subscription_audit_appended",
        device_key = %(crate::util::redact_text(device_key)),
        channel_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&channel_id))),
        action = %(action),
        channel_type = %(route.channel_type.as_str())
    );
    Ok(())
}
