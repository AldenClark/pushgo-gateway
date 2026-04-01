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
    let now = chrono::Utc::now().timestamp();
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
        .await?;
    Ok(())
}
