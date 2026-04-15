use super::*;
use crate::{storage::PrivateMessage, util::encode_crockford_base32_128};
pub(super) async fn dispatch_provider_devices(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let total = prepared.provider_devices.len();
    for (index, device) in prepared.provider_devices.iter().enumerate() {
        let provider_route = ProviderRouteBinding::resolve(
            prepared.state,
            device.info.platform,
            device.info.token_str(),
            device.device_key.as_deref(),
        );
        let provider_audit_key = provider_route.audit_device_key.as_str().to_string();
        let provider_stats_key = Arc::<str>::from(
            provider_route
                .audit_device_key
                .as_str()
                .to_string()
                .into_boxed_str(),
        );

        let provider_pull_delivery_id = prepared.delivery_id.clone();
        let wakeup_data_for_device = Arc::new(wakeup_data_with_delivery_id(
            prepared.wakeup_data.as_ref(),
            provider_pull_delivery_id.as_str(),
        ));
        let provider_pull_delivery = ProviderPullDelivery::for_provider_target(
            provider_route.provider_device_key.as_deref(),
            device.info.platform,
            device.info.token_str(),
            &prepared.private_payload,
            provider_pull_delivery_id.as_str(),
            prepared.sent_at,
            prepared.provider_pull_expires_at(),
        );
        let target = ResolvedProviderTarget {
            device: &device.info,
            provider_audit_key,
            provider_stats_key,
            wakeup_data_for_device,
            provider_pull_delivery,
        };
        if !ensure_provider_pull_cached(prepared, &target, progress).await {
            continue;
        }

        match device.info.platform {
            Platform::ANDROID => android::dispatch(prepared, payloads, &target, progress).await?,
            Platform::WINDOWS => windows::dispatch(prepared, payloads, &target, progress).await?,
            _ => apple::dispatch(prepared, payloads, &target, progress).await?,
        }

        if progress.dispatch_closed {
            progress.rejected += total.saturating_sub(index + 1);
            break;
        }
    }
    Ok(())
}

async fn ensure_provider_pull_cached(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget<'_>,
    progress: &mut DispatchProgress,
) -> bool {
    let Some(provider_pull) = target.provider_pull_delivery.as_ref() else {
        record_provider_cache_enqueue_failed(
            prepared,
            target,
            progress,
            "provider pull cache unavailable: missing provider target identity",
        )
        .await;
        return false;
    };
    let message = PrivateMessage {
        payload: provider_pull.payload.as_ref().clone(),
        size: provider_pull.payload.len(),
        sent_at: provider_pull.sent_at,
        expires_at: provider_pull.expires_at,
    };
    match prepared
        .state
        .store
        .enqueue_provider_pull_item(
            provider_pull.device_id,
            provider_pull.delivery_id.as_ref(),
            &message,
            provider_pull.platform,
            provider_pull.provider_token.as_ref(),
        )
        .await
    {
        Ok(()) => true,
        Err(err) => {
            record_provider_cache_enqueue_failed(
                prepared,
                target,
                progress,
                format!(
                    "provider pull cache enqueue failed device_id={} delivery_id={} error={}",
                    encode_crockford_base32_128(&provider_pull.device_id),
                    provider_pull.delivery_id,
                    err,
                ),
            )
            .await;
            false
        }
    }
}
