use super::*;
use crate::api::handlers::message::ProviderPullDeliveryId;

pub(super) async fn dispatch_provider_devices(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let total = prepared.provider_devices.len();
    for (index, device) in prepared.provider_devices.iter().enumerate() {
        let private_delivery_target =
            prepared
                .private_dispatch
                .as_ref()
                .and_then(|private_dispatch| {
                    private_dispatch
                        .state
                        .device_registry
                        .find_device_key_by_provider_token(device.platform, device.token_str())
                        .map(|device_key| derive_private_device_id(device_key.as_str()))
                        .filter(|device_id| {
                            private_dispatch.subscriber_set.contains(device_id)
                                && progress.private_enqueued.contains(device_id)
                        })
                });
        let private_online = private_delivery_target
            .map(|device_id| {
                prepared
                    .private_dispatch
                    .as_ref()
                    .map(|private_dispatch| private_dispatch.state.hub.is_online(device_id))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let provider_route =
            ProviderRouteBinding::resolve(prepared.state, device.platform, device.token_str());
        let provider_audit_key = provider_route.audit_device_key.as_str().to_string();
        let provider_stats_key = Arc::<str>::from(
            provider_route
                .audit_device_key
                .as_str()
                .to_string()
                .into_boxed_str(),
        );
        if progress.should_skip_provider_delivery(private_delivery_target, private_online) {
            record_private_realtime_skip(
                prepared,
                device,
                provider_route.audit_device_key.into_inner(),
            )
            .await;
            continue;
        }

        let provider_pull_delivery_id = ProviderPullDeliveryId::derive(
            prepared.delivery_id.as_str(),
            device.platform.name(),
            device.token_str(),
        )
        .into_inner();
        let wakeup_data_for_device = Arc::new(wakeup_data_with_delivery_id(
            prepared.wakeup_data.as_ref(),
            provider_pull_delivery_id.as_str(),
        ));
        let provider_pull_delivery = ProviderPullDelivery::for_provider_target(
            provider_route.provider_device_key.as_deref(),
            device.platform,
            device.token_str(),
            &prepared.private_payload,
            provider_pull_delivery_id.as_str(),
            prepared.sent_at,
            prepared.provider_pull_expires_at(),
        );
        let target = ResolvedProviderTarget {
            device,
            provider_audit_key,
            provider_stats_key,
            wakeup_data_for_device,
            provider_pull_delivery,
        };

        match device.platform {
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
