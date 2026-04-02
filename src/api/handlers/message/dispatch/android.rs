use super::*;
use crate::dispatch::FcmJob;

pub(super) async fn dispatch(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let direct_payload = payloads
        .fcm_payload
        .clone()
        .ok_or(Error::Internal("missing FCM payload".to_string()))?;
    let wakeup_payload = Arc::new(FcmPayload::new(
        SharedStringMap::from(Arc::clone(&target.wakeup_data_for_device)),
        "HIGH",
        prepared.ttl_seconds,
    ));
    let direct_body = direct_payload
        .encoded_body(target.device.token_str())
        .map_err(|err| Error::Internal(err.to_string()))?;
    let mut wakeup_body = None;
    let selection = if let Some(selection) =
        ProviderDeliverySelection::direct(target.device.platform, direct_body.len())
    {
        selection
    } else {
        let encoded_wakeup = wakeup_payload
            .encoded_body(target.device.token_str())
            .map_err(|err| Error::Internal(err.to_string()))?;
        let selection = match ProviderDeliverySelection::wakeup_pull(
            target.device.platform,
            encoded_wakeup.len(),
            target.provider_pull_delivery.is_some(),
        ) {
            Ok(selection) => selection,
            Err(err) => {
                record_provider_path_rejected(prepared, target, progress, err.to_string()).await;
                return Ok(());
            }
        };
        wakeup_body = Some(encoded_wakeup);
        selection
    };

    match prepared.state.dispatch.try_send_fcm(FcmJob {
        channel_id: prepared.channel_id,
        correlation_id: Arc::clone(&prepared.correlation_id),
        delivery_id: Arc::clone(&prepared.delivery_id_ref),
        device_token: Arc::from(target.device.token_str()),
        direct_payload: Arc::clone(&direct_payload),
        direct_body,
        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
        wakeup_body,
        initial_path: selection.initial_path,
        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
        provider_pull_delivery: target.provider_pull_delivery.clone(),
    }) {
        Ok(()) => {
            record_provider_enqueued(prepared, target, progress, selection.initial_path).await;
        }
        Err(err) => {
            record_provider_enqueue_failed(
                prepared,
                target,
                progress,
                selection.initial_path,
                &err,
            )
            .await;
        }
    }

    Ok(())
}
