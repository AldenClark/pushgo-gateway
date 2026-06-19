use super::*;
use crate::delivery_core::execution::provider::{
    ProviderDispatchContext, ProviderDispatchPayload, enqueue_provider_dispatch,
};

pub(super) async fn dispatch(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget,
    provider_payload: PreparedProviderPayload,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let PreparedProviderPayload::Fcm {
        direct_payload,
        direct_body,
        wakeup_payload,
        wakeup_body,
        selection,
    } = provider_payload
    else {
        return Err(Error::Internal(
            "prepared provider payload did not match FCM target".to_string(),
        ));
    };

    let path = selection.initial_path.into();
    match enqueue_provider_dispatch(
        ProviderDispatchContext {
            dispatch: prepared.runtime.dispatch_channels(),
            channel_id: prepared.channel_id,
            correlation_id: Arc::clone(&prepared.correlation_id),
            delivery_id: Arc::clone(&prepared.delivery_id_ref),
            device_key: Arc::clone(&target.device_key),
            device_token: Arc::from(target.device.token_str()),
        },
        ProviderDispatchPayload::Fcm {
            direct_payload: Arc::clone(&direct_payload),
            direct_body,
            wakeup_payload: Arc::clone(&wakeup_payload),
            wakeup_body,
            initial_path: path,
            wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
        },
    ) {
        Ok(()) => {
            record_provider_enqueued(prepared, target, progress, path).await;
        }
        Err(err) => {
            record_provider_enqueue_failed(prepared, target, progress, path, &err).await;
        }
    }

    Ok(())
}
