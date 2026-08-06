use super::*;
use crate::{
    delivery_core::execution::provider::{
        ApnsPayloadPreparation, FcmPayloadPreparation, ProviderPayloadPreparationError,
        ProviderPullCacheRequest, ProviderRouteResolver, ProviderTargetPreparation,
        WnsPayloadPreparation, cache_provider_pull_delivery, direct_data_with_provider_ack_source,
        prepare_apns_payload, prepare_fcm_payload, prepare_provider_target, prepare_wns_payload,
    },
    delivery_core::payload::quantize_watch_payload,
    storage::PrivateMessage,
    util::{SharedStringMap, encode_crockford_base32_128},
};

struct AppProviderRouteResolver<'a>(&'a PreparedDispatch<'a>);

impl ProviderRouteResolver for AppProviderRouteResolver<'_> {
    fn resolve_provider_route(
        &self,
        platform: Platform,
        token: &str,
        dispatch_device_key: &str,
    ) -> String {
        self.0
            .runtime
            .device_registry()
            .resolve_provider_ingress_route(platform, token)
            .unwrap_or_else(|| {
                crate::value::DeviceKeyRef::parse(dispatch_device_key)
                    .map(crate::value::DeviceKeyRef::into_owned)
                    .unwrap_or_default()
            })
    }
}

pub(super) async fn dispatch_provider_targets(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let provider_pull_message = PrivateMessage {
        payload: prepared.private_payload.clone(),
        size: prepared.private_payload.len(),
        sent_at: prepared.sent_at,
        expires_at: prepared.provider_pull_expires_at(),
    };
    let total = prepared.provider_targets.len();
    let route_resolver = AppProviderRouteResolver(prepared);
    for (index, execution_target) in prepared.provider_targets.iter().enumerate() {
        let target = prepare_provider_target(ProviderTargetPreparation {
            resolver: &route_resolver,
            delivery_id: prepared.delivery_id.as_str(),
            wakeup_data: prepared.wakeup_data.as_ref(),
            execution_target,
        });
        let target = ResolvedProviderTarget::from(target);
        if execution_target.wakeup_pull_ref.is_some()
            && !ensure_provider_pull_cached(prepared, &target, &provider_pull_message, progress)
                .await
        {
            prepared.provider_outcome.record_failure();
            continue;
        }

        let Some(provider_payload) =
            prepare_provider_payload(prepared, payloads, &target, progress).await?
        else {
            prepared.provider_outcome.record_failure();
            continue;
        };

        match execution_target.device.info.platform {
            Platform::ANDROID => {
                android::dispatch(prepared, &target, provider_payload, progress).await?
            }
            Platform::WINDOWS => {
                windows::dispatch(prepared, &target, provider_payload, progress).await?
            }
            Platform::IOS | Platform::MACOS | Platform::WATCHOS => {
                apple::dispatch(prepared, payloads, &target, provider_payload, progress).await?
            }
            Platform::MQTT => {
                prepared.provider_outcome.record_failure();
                record_provider_path_rejected(
                    prepared,
                    &target,
                    progress,
                    "mqtt platform is private-transport only",
                )
                .await;
            }
        }

        if progress.dispatch_closed {
            let remaining = total.saturating_sub(index + 1);
            progress.rejected += remaining;
            prepared.provider_outcome.record_failures(remaining);
            break;
        }
    }
    Ok(())
}

async fn prepare_provider_payload(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget,
    progress: &mut DispatchProgress,
) -> Result<Option<PreparedProviderPayload>, Error> {
    match target.device.platform {
        Platform::ANDROID => prepare_fcm_provider_payload(prepared, target, progress).await,
        Platform::WINDOWS => {
            prepare_wns_provider_payload(prepared, payloads, target, progress).await
        }
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => {
            prepare_apns_provider_payload(prepared, payloads, target, progress).await
        }
        Platform::MQTT => Ok(None),
    }
}

async fn prepare_apns_provider_payload(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget,
    progress: &mut DispatchProgress,
) -> Result<Option<PreparedProviderPayload>, Error> {
    let direct_template = if target.device.platform == Platform::WATCHOS {
        payloads.watchos_apns_payload.clone()
    } else {
        payloads.apns_payload.clone()
    }
    .ok_or(Error::Internal("missing APNs payload".to_string()))?;
    let direct_data =
        direct_data_with_provider_ack_source(prepared.custom_data.as_ref(), &target.device_key);
    let direct_data = if target.device.platform == Platform::WATCHOS {
        SharedStringMap::from(quantize_watch_payload(direct_data.as_ref()))
    } else {
        SharedStringMap::from(direct_data)
    };
    let direct_payload = Arc::new(direct_template.with_data(direct_data));
    let wakeup_payload = Arc::new(ApnsPayload::wakeup(
        payloads.apns_wakeup_title.clone(),
        payloads.apns_wakeup_body.clone(),
        Some(prepared.channel_id_value.clone()),
        prepared
            .effective_ttl
            .map(crate::providers::apns::ApnsExpirationEpochSeconds::from_epoch_millis),
        SharedStringMap::from(Arc::clone(&target.wakeup_data_for_device)),
    ));
    prepare_core_provider_payload(
        prepared,
        target,
        progress,
        prepare_apns_payload(ApnsPayloadPreparation {
            platform: target.device.platform,
            direct_payload,
            wakeup_payload,
            inline_allowed: target.allow_inline,
            wakeup_pull_available: target.provider_pull_delivery.is_some(),
        }),
    )
    .await
}

async fn prepare_core_provider_payload(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget,
    progress: &mut DispatchProgress,
    result: Result<PreparedProviderPayload, ProviderPayloadPreparationError>,
) -> Result<Option<PreparedProviderPayload>, Error> {
    match result {
        Ok(payload) => Ok(Some(payload)),
        Err(ProviderPayloadPreparationError::EncodeFailed { event_name, error }) => {
            emit_provider_payload_encode_failed(prepared, target, event_name, error.clone());
            Err(Error::Internal(error))
        }
        Err(ProviderPayloadPreparationError::PathRejected(err)) => {
            record_provider_path_rejected(prepared, target, progress, err.to_string()).await;
            Ok(None)
        }
    }
}

async fn prepare_fcm_provider_payload(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget,
    progress: &mut DispatchProgress,
) -> Result<Option<PreparedProviderPayload>, Error> {
    let direct_payload = Arc::new(FcmPayload::new(
        SharedStringMap::from(direct_data_with_provider_ack_source(
            prepared.custom_data.as_ref(),
            &target.device_key,
        )),
        prepared.severity.fcm_priority(),
        prepared.ttl_seconds,
    ));
    let wakeup_payload = Arc::new(FcmPayload::new(
        SharedStringMap::from(Arc::clone(&target.wakeup_data_for_device)),
        "HIGH",
        prepared.ttl_seconds,
    ));
    prepare_core_provider_payload(
        prepared,
        target,
        progress,
        prepare_fcm_payload(FcmPayloadPreparation {
            platform: target.device.platform,
            device_token: target.device.token_str(),
            direct_payload,
            wakeup_payload,
            inline_allowed: target.allow_inline,
            wakeup_pull_available: target.provider_pull_delivery.is_some(),
        }),
    )
    .await
}

async fn prepare_wns_provider_payload(
    prepared: &PreparedDispatch<'_>,
    payloads: &ProviderPayloads,
    target: &ResolvedProviderTarget,
    progress: &mut DispatchProgress,
) -> Result<Option<PreparedProviderPayload>, Error> {
    let direct_template = payloads
        .wns_payload
        .clone()
        .ok_or(Error::Internal("missing WNS payload".to_string()))?;
    let direct_payload = Arc::new(direct_template.with_data(SharedStringMap::from(
        direct_data_with_provider_ack_source(prepared.custom_data.as_ref(), &target.device_key),
    )));
    let wakeup_payload = Arc::new(WnsPayload::new(
        SharedStringMap::from(Arc::clone(&target.wakeup_data_for_device)),
        "high",
        prepared.ttl_seconds,
    ));
    prepare_core_provider_payload(
        prepared,
        target,
        progress,
        prepare_wns_payload(WnsPayloadPreparation {
            platform: target.device.platform,
            direct_payload,
            wakeup_payload,
            inline_allowed: target.allow_inline,
            wakeup_pull_available: target.provider_pull_delivery.is_some(),
        }),
    )
    .await
}

fn emit_provider_payload_encode_failed(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget,
    event_name: &'static str,
    error: String,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::ERROR,
        event = event_name,
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        op_id = %(crate::util::redact_text(prepared.op_id.as_str())),
        device_key = %(crate::util::redact_text(target.device_key.as_ref())),
        device_token = %(crate::util::redact_text(target.device.token_str())),
        platform = %(target.device.platform.name()),
        error = %(error)
    );
}

async fn ensure_provider_pull_cached(
    prepared: &PreparedDispatch<'_>,
    target: &ResolvedProviderTarget,
    provider_pull_message: &PrivateMessage,
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
    match cache_provider_pull_delivery(ProviderPullCacheRequest {
        store: prepared.runtime.storage(),
        device_id: provider_pull.device_id,
        delivery_id: provider_pull.delivery_id.as_ref(),
        message: provider_pull_message,
        platform: provider_pull.platform,
        provider_token: provider_pull.provider_token.as_ref(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_source_data(device_key: &str) -> Arc<HashMap<String, String>> {
        direct_data_with_provider_ack_source(
            &HashMap::from([(
                "base_url".to_string(),
                "https://gateway.example".to_string(),
            )]),
            device_key,
        )
    }

    #[test]
    fn apns_direct_payload_contains_immutable_ack_source() {
        let payload = ApnsPayload::new(
            Some("Title".to_string()),
            Some("Body".to_string()),
            None,
            None,
            "normal".to_string(),
            None,
            SharedStringMap::from(direct_source_data("apple-device")),
        );

        let json = serde_json::to_value(payload).expect("serialize APNs payload");
        assert_eq!(
            (
                json["base_url"].as_str(),
                json["provider_device_key"].as_str()
            ),
            (Some("https://gateway.example"), Some("apple-device"))
        );
    }

    #[test]
    fn fcm_direct_payload_contains_immutable_ack_source() {
        let payload = FcmPayload::new(
            SharedStringMap::from(direct_source_data("android-device")),
            "HIGH",
            None,
        );

        assert_eq!(
            (
                payload.data().get("base_url").map(String::as_str),
                payload
                    .data()
                    .get("provider_device_key")
                    .map(String::as_str),
            ),
            (Some("https://gateway.example"), Some("android-device"))
        );
    }

    #[test]
    fn wns_direct_payload_contains_immutable_ack_source() {
        let payload = WnsPayload::new(
            SharedStringMap::from(direct_source_data("windows-device")),
            "high",
            None,
        );

        assert_eq!(
            (
                payload.data().get("base_url").map(String::as_str),
                payload
                    .data()
                    .get("provider_device_key")
                    .map(String::as_str),
            ),
            (Some("https://gateway.example"), Some("windows-device"))
        );
    }
}
