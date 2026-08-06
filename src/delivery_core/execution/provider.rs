use hashbrown::HashMap;
use std::sync::Arc;

use crate::{
    delivery_core::error::CoreError,
    dispatch::{ApnsJob, DispatchChannels, DispatchError, FcmJob, ProviderDeliveryPath, WnsJob},
    private::PrivateState,
    providers::{
        apns::{ApnsExpirationEpochSeconds, ApnsPayload},
        fcm::FcmPayload,
        wns::WnsPayload,
    },
    runtime_counters::{
        OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED,
        OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED, RuntimeCounterCollector,
    },
    storage::{DeviceId, DeviceInfo, Platform, PrivateMessage, Storage, StoreError},
    util::encode_crockford_base32_128,
};

use super::super::{
    payload::{
        NotificationSeverity, ProviderDeliverySelection, ProviderPullTarget,
        ProviderStatsDeviceKey, quantize_watch_payload,
    },
    planning::plan::{DeliveryPlan, DeliveryTargetPlan, PullRef},
    store::delivery_queue::DeliveryQueueStore,
};

pub(crate) struct ProviderDispatchDevice {
    pub(crate) info: DeviceInfo,
    pub(crate) device_key: String,
    pub(crate) route_updated_at: i64,
}

fn wakeup_data_with_delivery_id(
    wakeup_template: &HashMap<String, String>,
    delivery_id: &str,
) -> HashMap<String, String> {
    let mut data = wakeup_template.clone();
    data.insert("delivery_id".to_string(), delivery_id.to_string());
    data
}

pub(crate) fn direct_data_with_provider_ack_source(
    custom_data: &HashMap<String, String>,
    provider_device_key: &str,
) -> Arc<HashMap<String, String>> {
    let mut data = custom_data.clone();
    data.remove("provider_device_key");
    let provider_device_key = provider_device_key.trim();
    if !provider_device_key.is_empty() {
        data.insert(
            "provider_device_key".to_string(),
            provider_device_key.to_string(),
        );
    }
    Arc::new(data)
}

pub(crate) struct ProviderExecutionTarget {
    pub(crate) device: ProviderDispatchDevice,
    pub(crate) allow_inline: bool,
    pub(crate) wakeup_pull_ref: Option<PullRef>,
}

pub(crate) trait ProviderRouteResolver {
    fn resolve_provider_route(
        &self,
        platform: Platform,
        token: &str,
        dispatch_device_key: &str,
    ) -> String;
}

pub(crate) struct ResolvedProviderTarget {
    pub(crate) device: DeviceInfo,
    pub(crate) device_key: Arc<str>,
    pub(crate) route_updated_at: i64,
    pub(crate) provider_stats_key: Arc<str>,
    pub(crate) wakeup_data_for_device: Arc<HashMap<String, String>>,
    pub(crate) allow_inline: bool,
    pub(crate) provider_pull_target: Option<ProviderPullTarget>,
}

pub(crate) struct ProviderPayloadSet {
    pub(crate) apns_payload: Option<Arc<ApnsPayload>>,
    pub(crate) watchos_apns_payload: Option<Arc<ApnsPayload>>,
    pub(crate) apns_collapse_id: Option<Arc<str>>,
    pub(crate) apns_wakeup_title: Option<String>,
    pub(crate) apns_wakeup_body: Option<String>,
    pub(crate) wns_payload: Option<Arc<WnsPayload>>,
}

pub(crate) struct ProviderPayloadSetInput<'a> {
    pub(crate) targets: &'a [ProviderExecutionTarget],
    pub(crate) resolved_title: Option<String>,
    pub(crate) resolved_body: Option<String>,
    pub(crate) fallback_body: Option<String>,
    pub(crate) apple_thread_id: String,
    pub(crate) severity: NotificationSeverity,
    pub(crate) effective_ttl: Option<i64>,
    pub(crate) ttl_seconds: Option<u32>,
    pub(crate) custom_data: Arc<HashMap<String, String>>,
    pub(crate) wakeup_data: Arc<HashMap<String, String>>,
    pub(crate) delivery_id: String,
}

pub(crate) fn build_provider_payload_set(input: ProviderPayloadSetInput<'_>) -> ProviderPayloadSet {
    let mut has_apns = false;
    let mut has_wns = false;
    let mut has_watchos_apns = false;
    for target in input.targets {
        match target.device.info.platform {
            Platform::ANDROID => {}
            Platform::WINDOWS => has_wns = true,
            Platform::WATCHOS => {
                has_apns = true;
                has_watchos_apns = true;
            }
            _ => has_apns = true,
        }
    }

    let apns_expiration = input
        .effective_ttl
        .map(ApnsExpirationEpochSeconds::from_epoch_millis);
    let apns_payload = has_apns.then(|| {
        Arc::new(ApnsPayload::new(
            input.resolved_title.clone(),
            input.resolved_body.clone(),
            input.fallback_body.clone(),
            Some(input.apple_thread_id.clone()),
            input.severity.as_str().to_string(),
            apns_expiration,
            crate::util::SharedStringMap::from(Arc::clone(&input.custom_data)),
        ))
    });
    let watchos_apns_payload = has_watchos_apns.then(|| {
        Arc::new(ApnsPayload::new(
            input.resolved_title.clone(),
            input.resolved_body.clone(),
            input.fallback_body.clone(),
            Some(input.apple_thread_id.clone()),
            input.severity.as_str().to_string(),
            apns_expiration,
            quantize_watch_payload(input.custom_data.as_ref()),
        ))
    });
    let apns_collapse_id = has_apns.then(|| Arc::from(input.delivery_id.into_boxed_str()));
    let apns_wakeup_title = has_apns.then(|| input.resolved_title.clone()).flatten();
    let apns_wakeup_body = has_apns
        .then(|| input.wakeup_data.get("body").cloned())
        .flatten();
    let wns_payload = has_wns.then(|| {
        Arc::new(WnsPayload::new(
            crate::util::SharedStringMap::from(Arc::clone(&input.custom_data)),
            input.severity.as_str(),
            input.ttl_seconds,
        ))
    });

    ProviderPayloadSet {
        apns_payload,
        watchos_apns_payload,
        apns_collapse_id,
        apns_wakeup_title,
        apns_wakeup_body,
        wns_payload,
    }
}

pub(crate) struct ProviderTargetPreparation<'a> {
    pub(crate) resolver: &'a dyn ProviderRouteResolver,
    pub(crate) delivery_id: &'a str,
    pub(crate) wakeup_data: &'a HashMap<String, String>,
    pub(crate) execution_target: &'a ProviderExecutionTarget,
}

pub(crate) fn prepare_provider_target(
    input: ProviderTargetPreparation<'_>,
) -> ResolvedProviderTarget {
    let device = &input.execution_target.device;
    let provider_device_key = input.resolver.resolve_provider_route(
        device.info.platform,
        device.info.token_str(),
        device.device_key.as_str(),
    );
    let provider_stats_key = Arc::<str>::from(
        ProviderStatsDeviceKey::resolve(provider_device_key.as_str())
            .as_str()
            .to_string()
            .into_boxed_str(),
    );
    let wakeup_data_for_device = Arc::new(wakeup_data_with_delivery_id(
        input.wakeup_data,
        input.delivery_id,
    ));
    let provider_pull_target = ProviderPullTarget::for_provider_target(
        provider_device_key.as_str(),
        device.info.platform,
        device.info.token_str(),
        input.delivery_id,
    )
    .filter(|_| input.execution_target.wakeup_pull_ref.is_some());

    ResolvedProviderTarget {
        device: device.info.clone(),
        device_key: Arc::<str>::from(provider_device_key.into_boxed_str()),
        route_updated_at: device.route_updated_at,
        provider_stats_key,
        wakeup_data_for_device,
        allow_inline: input.execution_target.allow_inline,
        provider_pull_target,
    }
}

pub(crate) fn provider_targets_from_plan(
    plan: &DeliveryPlan,
    mut candidates: HashMap<(Platform, String), ProviderDispatchDevice>,
) -> Vec<ProviderExecutionTarget> {
    let mut target_specs: HashMap<(Platform, String), (bool, Option<PullRef>)> = HashMap::new();
    for target in &plan.targets {
        match target {
            DeliveryTargetPlan::ProviderInline {
                platform,
                device_key,
                ..
            } => {
                target_specs
                    .entry((*platform, device_key.clone()))
                    .or_insert((false, None))
                    .0 = true;
            }
            DeliveryTargetPlan::ProviderWakeupPull {
                platform,
                device_key,
                pull_ref,
                ..
            } => {
                target_specs
                    .entry((*platform, device_key.clone()))
                    .or_insert((false, None))
                    .1 = Some(pull_ref.clone());
            }
            DeliveryTargetPlan::PrivateRealtime { .. }
            | DeliveryTargetPlan::PrivateOutbox { .. }
            | DeliveryTargetPlan::MqttReceiver { .. } => {}
        }
    }

    let mut provider_targets = Vec::new();
    for (key, (inline_allowed, wakeup_pull_ref)) in target_specs {
        if !inline_allowed && wakeup_pull_ref.is_none() {
            continue;
        }
        if let Some(device) = candidates.remove(&key) {
            provider_targets.push(ProviderExecutionTarget {
                device,
                allow_inline: inline_allowed,
                wakeup_pull_ref,
            });
        }
    }
    provider_targets
}

pub(crate) struct ProviderDispatchContext<'a> {
    pub(crate) dispatch: &'a DispatchChannels,
    pub(crate) channel_id: [u8; 16],
    pub(crate) correlation_id: Arc<str>,
    pub(crate) delivery_id: Arc<str>,
    pub(crate) device_key: Arc<str>,
    pub(crate) device_token: Arc<str>,
    pub(crate) route_updated_at: i64,
    pub(crate) outcome: Arc<crate::dispatch::ProviderDispatchOutcome>,
}

pub(crate) enum ProviderDispatchPayload {
    Apns {
        platform: Platform,
        direct_payload: Arc<ApnsPayload>,
        wakeup_payload: Arc<ApnsPayload>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
        collapse_id: Option<Arc<str>>,
    },
    Fcm {
        direct_payload: Arc<FcmPayload>,
        direct_body: Arc<[u8]>,
        wakeup_payload: Arc<FcmPayload>,
        wakeup_body: Option<Arc<[u8]>>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
    },
    Wns {
        direct_payload: Arc<WnsPayload>,
        wakeup_payload: Arc<WnsPayload>,
        initial_path: ProviderDeliveryPath,
        wakeup_payload_within_limit: bool,
    },
}

pub(crate) enum PreparedProviderPayload {
    Apns {
        direct_payload: Arc<ApnsPayload>,
        wakeup_payload: Arc<ApnsPayload>,
        selection: ProviderDeliverySelection,
    },
    Fcm {
        direct_payload: Arc<FcmPayload>,
        direct_body: Arc<[u8]>,
        wakeup_payload: Arc<FcmPayload>,
        wakeup_body: Option<Arc<[u8]>>,
        selection: ProviderDeliverySelection,
    },
    Wns {
        direct_payload: Arc<WnsPayload>,
        wakeup_payload: Arc<WnsPayload>,
        selection: ProviderDeliverySelection,
    },
}

pub(crate) struct ApnsPayloadPreparation {
    pub(crate) platform: Platform,
    pub(crate) direct_payload: Arc<ApnsPayload>,
    pub(crate) wakeup_payload: Arc<ApnsPayload>,
    pub(crate) inline_allowed: bool,
    pub(crate) wakeup_pull_available: bool,
}

pub(crate) struct FcmPayloadPreparation<'a> {
    pub(crate) platform: Platform,
    pub(crate) device_token: &'a str,
    pub(crate) direct_payload: Arc<FcmPayload>,
    pub(crate) wakeup_payload: Arc<FcmPayload>,
    pub(crate) inline_allowed: bool,
    pub(crate) wakeup_pull_available: bool,
}

pub(crate) struct WnsPayloadPreparation {
    pub(crate) platform: Platform,
    pub(crate) direct_payload: Arc<WnsPayload>,
    pub(crate) wakeup_payload: Arc<WnsPayload>,
    pub(crate) inline_allowed: bool,
    pub(crate) wakeup_pull_available: bool,
}

pub(crate) enum ProviderPayloadPreparationError {
    EncodeFailed {
        event_name: &'static str,
        error: String,
    },
    PathRejected(CoreError),
}

pub(crate) fn prepare_apns_payload(
    input: ApnsPayloadPreparation,
) -> Result<PreparedProviderPayload, ProviderPayloadPreparationError> {
    let direct_len = input.direct_payload.encoded_len().map_err(|err| {
        ProviderPayloadPreparationError::EncodeFailed {
            event_name: "dispatch.apns_direct_payload_encode_failed",
            error: err.to_string(),
        }
    })?;
    let wakeup_len = input.wakeup_payload.encoded_len().map_err(|err| {
        ProviderPayloadPreparationError::EncodeFailed {
            event_name: "dispatch.apns_wakeup_payload_encode_failed",
            error: err.to_string(),
        }
    })?;
    let selection = if input.inline_allowed {
        ProviderDeliverySelection::resolve(
            input.platform,
            direct_len,
            wakeup_len,
            input.wakeup_pull_available,
        )
    } else {
        ProviderDeliverySelection::wakeup_pull(
            input.platform,
            wakeup_len,
            input.wakeup_pull_available,
        )
    }
    .map_err(ProviderPayloadPreparationError::PathRejected)?;
    Ok(PreparedProviderPayload::Apns {
        direct_payload: input.direct_payload,
        wakeup_payload: input.wakeup_payload,
        selection,
    })
}

pub(crate) fn prepare_fcm_payload(
    input: FcmPayloadPreparation<'_>,
) -> Result<PreparedProviderPayload, ProviderPayloadPreparationError> {
    let direct_body = input
        .direct_payload
        .encoded_body(input.device_token)
        .map_err(|err| ProviderPayloadPreparationError::EncodeFailed {
            event_name: "dispatch.fcm_direct_payload_encode_failed",
            error: err.to_string(),
        })?;
    let mut wakeup_body = None;
    let selection = if input.inline_allowed
        && let Some(selection) =
            ProviderDeliverySelection::direct(input.platform, direct_body.len())
    {
        selection
    } else {
        let encoded_wakeup = input
            .wakeup_payload
            .encoded_body(input.device_token)
            .map_err(|err| ProviderPayloadPreparationError::EncodeFailed {
                event_name: "dispatch.fcm_wakeup_payload_encode_failed",
                error: err.to_string(),
            })?;
        let selection = ProviderDeliverySelection::wakeup_pull(
            input.platform,
            encoded_wakeup.len(),
            input.wakeup_pull_available,
        )
        .map_err(ProviderPayloadPreparationError::PathRejected)?;
        wakeup_body = Some(encoded_wakeup);
        selection
    };
    Ok(PreparedProviderPayload::Fcm {
        direct_payload: input.direct_payload,
        direct_body,
        wakeup_payload: input.wakeup_payload,
        wakeup_body,
        selection,
    })
}

pub(crate) fn prepare_wns_payload(
    input: WnsPayloadPreparation,
) -> Result<PreparedProviderPayload, ProviderPayloadPreparationError> {
    let direct_len = input.direct_payload.encoded_len().map_err(|err| {
        ProviderPayloadPreparationError::EncodeFailed {
            event_name: "dispatch.wns_direct_payload_encode_failed",
            error: err.to_string(),
        }
    })?;
    let wakeup_len = input.wakeup_payload.encoded_len().map_err(|err| {
        ProviderPayloadPreparationError::EncodeFailed {
            event_name: "dispatch.wns_wakeup_payload_encode_failed",
            error: err.to_string(),
        }
    })?;
    let selection = if input.inline_allowed {
        ProviderDeliverySelection::resolve(
            input.platform,
            direct_len,
            wakeup_len,
            input.wakeup_pull_available,
        )
    } else {
        ProviderDeliverySelection::wakeup_pull(
            input.platform,
            wakeup_len,
            input.wakeup_pull_available,
        )
    }
    .map_err(ProviderPayloadPreparationError::PathRejected)?;
    Ok(PreparedProviderPayload::Wns {
        direct_payload: input.direct_payload,
        wakeup_payload: input.wakeup_payload,
        selection,
    })
}

impl ProviderDispatchPayload {
    pub(crate) fn initial_path(&self) -> ProviderDeliveryPath {
        match self {
            Self::Apns { initial_path, .. }
            | Self::Fcm { initial_path, .. }
            | Self::Wns { initial_path, .. } => *initial_path,
        }
    }
}

pub(crate) fn enqueue_provider_dispatch(
    context: ProviderDispatchContext<'_>,
    payload: ProviderDispatchPayload,
) -> Result<(), DispatchError> {
    match payload {
        ProviderDispatchPayload::Apns {
            platform,
            direct_payload,
            wakeup_payload,
            initial_path,
            wakeup_payload_within_limit,
            collapse_id,
        } => context.dispatch.try_send_apns(ApnsJob {
            channel_id: context.channel_id,
            correlation_id: Arc::clone(&context.correlation_id),
            delivery_id: Arc::clone(&context.delivery_id),
            device_key: Arc::clone(&context.device_key),
            device_token: Arc::clone(&context.device_token),
            route_updated_at: context.route_updated_at,
            platform,
            direct_payload,
            wakeup_payload: Some(wakeup_payload),
            initial_path,
            wakeup_payload_within_limit,
            outcome: Some(context.outcome),
            collapse_id,
        }),
        ProviderDispatchPayload::Fcm {
            direct_payload,
            direct_body,
            wakeup_payload,
            wakeup_body,
            initial_path,
            wakeup_payload_within_limit,
        } => context.dispatch.try_send_fcm(FcmJob {
            channel_id: context.channel_id,
            correlation_id: Arc::clone(&context.correlation_id),
            delivery_id: Arc::clone(&context.delivery_id),
            device_key: Arc::clone(&context.device_key),
            device_token: Arc::clone(&context.device_token),
            route_updated_at: context.route_updated_at,
            direct_payload,
            direct_body,
            wakeup_payload: Some(wakeup_payload),
            wakeup_body,
            initial_path,
            wakeup_payload_within_limit,
            outcome: Some(context.outcome),
        }),
        ProviderDispatchPayload::Wns {
            direct_payload,
            wakeup_payload,
            initial_path,
            wakeup_payload_within_limit,
        } => context.dispatch.try_send_wns(WnsJob {
            channel_id: context.channel_id,
            correlation_id: context.correlation_id,
            delivery_id: context.delivery_id,
            device_key: context.device_key,
            device_token: context.device_token,
            route_updated_at: context.route_updated_at,
            direct_payload,
            wakeup_payload: Some(wakeup_payload),
            initial_path,
            wakeup_payload_within_limit,
            outcome: Some(context.outcome),
        }),
    }
}

pub(crate) struct ProviderPullCacheRequest<'a> {
    pub(crate) store: &'a (dyn DeliveryQueueStore + Send + Sync),
    pub(crate) device_id: DeviceId,
    pub(crate) delivery_id: &'a str,
    pub(crate) message: &'a PrivateMessage,
    pub(crate) platform: Platform,
    pub(crate) provider_token: &'a str,
}

pub(crate) async fn cache_provider_pull_delivery(
    request: ProviderPullCacheRequest<'_>,
) -> Result<(), StoreError> {
    request
        .store
        .enqueue_provider_pull_item(
            request.device_id,
            request.delivery_id,
            request.message,
            request.platform,
            request.provider_token,
        )
        .await
}

pub(crate) struct ProviderInvalidTokenCleanup<'a> {
    pub(crate) store: &'a Storage,
    pub(crate) private: Option<&'a PrivateState>,
    pub(crate) runtime_counters: &'a RuntimeCounterCollector,
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_text: &'a str,
    pub(crate) device_key: &'a str,
    pub(crate) platform: Platform,
    pub(crate) device_token: &'a str,
    pub(crate) route_updated_at: i64,
    pub(crate) provider: &'static str,
    pub(crate) correlation_id: &'a str,
}

pub(crate) async fn cleanup_invalid_provider_token(request: ProviderInvalidTokenCleanup<'_>) {
    let invalidated = match request
        .store
        .unsubscribe_channel_if_provider_route_current(
            request.channel_id,
            request.device_key,
            request.platform,
            request.device_token,
            request.route_updated_at,
        )
        .await
    {
        Ok(invalidated) => invalidated,
        Err(err) => {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "dispatch.invalid_token_cleanup_guard_failed",
                provider = %(request.provider),
                correlation_id = %(crate::util::redact_text(request.correlation_id)),
                channel_id = %(crate::util::redact_text(request.channel_id_text)),
                platform = %(request.platform.name()),
                error = %(err.to_string())
            );
            return;
        }
    };
    if !invalidated {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "dispatch.invalid_token_cleanup_stale_ignored",
            provider = %(request.provider),
            correlation_id = %(crate::util::redact_text(request.correlation_id)),
            channel_id = %(crate::util::redact_text(request.channel_id_text)),
            platform = %(request.platform.name()),
            route_updated_at = request.route_updated_at
        );
        return;
    }

    let device_id = match request
        .store
        .lookup_private_device(request.platform, request.device_token)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            request
                .runtime_counters
                .record_ops_counter_now(OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED, 1);
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "dispatch.invalid_token_cleanup_lookup_failed",
                provider = %(request.provider),
                correlation_id = %(crate::util::redact_text(request.correlation_id)),
                channel_id = %(crate::util::redact_text(request.channel_id_text)),
                platform = %(request.platform.name()),
                device_token = %(crate::util::redact_text(redact_device_token(request.device_token))),
                error = %(err.to_string())
            );
            return;
        }
    };
    let Some(device_id) = device_id else {
        return;
    };

    let cleared_result = if let Some(private_state) = request.private {
        private_state.clear_device_outbox(device_id).await
    } else {
        request
            .store
            .clear_private_outbox_for_device(device_id)
            .await
            .map(|entries| entries.len())
            .map_err(|err| crate::Error::Internal(err.to_string()))
    };

    if let Err(err) = cleared_result {
        request.runtime_counters.record_ops_counter_now(
            OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED,
            1,
        );
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "dispatch.invalid_token_cleanup_outbox_clear_failed",
            provider = %(request.provider),
            correlation_id = %(crate::util::redact_text(request.correlation_id)),
            channel_id = %(crate::util::redact_text(request.channel_id_text)),
            platform = %(request.platform.name()),
            device_id = %(crate::util::redact_text(encode_crockford_base32_128(&device_id))),
            error = %(err.to_string())
        );
    }
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}

#[cfg(test)]
mod tests {
    use super::direct_data_with_provider_ack_source;
    use hashbrown::HashMap;

    #[test]
    fn direct_ack_source_overrides_untrusted_provider_device_key() {
        let custom_data = HashMap::from([
            (
                "base_url".to_string(),
                "https://gateway.example".to_string(),
            ),
            (
                "provider_device_key".to_string(),
                "attacker-key".to_string(),
            ),
        ]);

        let data = direct_data_with_provider_ack_source(&custom_data, " target-device-key ");

        assert_eq!(
            data.get("provider_device_key").map(String::as_str),
            Some("target-device-key")
        );
        assert_eq!(
            data.get("base_url").map(String::as_str),
            Some("https://gateway.example")
        );
    }

    #[test]
    fn direct_ack_source_omits_empty_provider_device_key() {
        let custom_data = HashMap::from([(
            "provider_device_key".to_string(),
            "attacker-key".to_string(),
        )]);

        let data = direct_data_with_provider_ack_source(&custom_data, "   ");

        assert!(!data.contains_key("provider_device_key"));
    }
}
