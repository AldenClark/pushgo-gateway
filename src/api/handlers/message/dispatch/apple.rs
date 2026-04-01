use super::*;
use crate::dispatch::ApnsJob;

pub(super) async fn dispatch(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let direct_payload = if target.device.platform == Platform::WATCHOS {
        payloads.watchos_apns_payload.clone()
    } else {
        payloads.apns_payload.clone()
    }
    .ok_or(Error::Internal("missing APNs payload".to_string()))?;
    let wakeup_payload = Arc::new(ApnsPayload::wakeup(
        payloads.apns_wakeup_title.clone(),
        Some(prepared.channel_id_value.clone()),
        prepared.effective_ttl,
        SharedStringMap::from(Arc::clone(&target.wakeup_data_for_device)),
    ));
    let selection = match ProviderDeliverySelection::resolve(
        target.device.platform,
        direct_payload
            .encoded_len()
            .map_err(|err| Error::Internal(err.to_string()))?,
        wakeup_payload
            .encoded_len()
            .map_err(|err| Error::Internal(err.to_string()))?,
        target.private_wakeup_delivery.is_some(),
    ) {
        Ok(value) => value,
        Err(err) => {
            record_provider_path_rejected(prepared, target, progress, err.to_string()).await;
            return Ok(());
        }
    };

    match prepared.state.dispatch.try_send_apns(ApnsJob {
        channel_id: prepared.channel_id,
        correlation_id: Arc::clone(&prepared.correlation_id),
        delivery_id: Arc::clone(&prepared.delivery_id_ref),
        device_token: Arc::from(target.device.token_str()),
        platform: target.device.platform,
        direct_payload: Arc::clone(&direct_payload),
        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
        initial_path: selection.initial_path,
        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
        private_wakeup: target.private_wakeup_delivery.clone(),
        collapse_id: payloads.apns_collapse_id.clone(),
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
