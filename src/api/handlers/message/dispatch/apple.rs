use super::*;
use crate::delivery_core::execution::provider::{
    ProviderDispatchContext, ProviderDispatchPayload, enqueue_provider_dispatch,
};

pub(super) async fn dispatch(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget,
    provider_payload: PreparedProviderPayload,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let PreparedProviderPayload::Apns {
        direct_payload,
        wakeup_payload,
        selection,
    } = provider_payload
    else {
        return Err(Error::Internal(
            "prepared provider payload did not match APNs target".to_string(),
        ));
    };

    let path = selection.initial_path.into();
    match enqueue_provider_dispatch(
        ProviderDispatchContext {
            dispatch: prepared.runtime.dispatch_channels(),
            store: prepared.runtime.storage(),
            channel_id: prepared.channel_id,
            correlation_id: Arc::clone(&prepared.correlation_id),
            delivery_id: Arc::clone(&prepared.delivery_id_ref),
            device_key: Arc::clone(&target.device_key),
            device_token: Arc::from(target.device.token_str()),
            route_updated_at: target.route_updated_at,
            accepted_at: prepared.sent_at,
            acceptance_order: prepared.acceptance_order,
            expires_at: prepared.provider_pull_expires_at(),
            outcome: Arc::clone(&prepared.provider_outcome),
        },
        ProviderDispatchPayload::Apns {
            platform: target.device.platform,
            direct_payload: Arc::clone(&direct_payload),
            wakeup_payload: Arc::clone(&wakeup_payload),
            initial_path: path,
            wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
            collapse_id: payloads.apns_collapse_id.clone(),
        },
    )
    .await
    {
        Ok(()) => {
            record_provider_enqueued(prepared, target, progress, path).await;
        }
        Err(err) => {
            prepared.provider_outcome.record_failure();
            record_provider_enqueue_failed(prepared, target, progress, path, &err).await;
            if !matches!(err, DispatchError::DurableEncoding(_)) {
                return Err(Error::Internal(format!(
                    "APNs durable materialization failed: {}",
                    super::tracing::dispatch_error_detail(&err)
                )));
            }
        }
    }

    Ok(())
}
