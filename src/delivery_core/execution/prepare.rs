use std::sync::Arc;

use hashbrown::HashMap;

use crate::{
    delivery_core::{
        execution::{
            mqtt_receiver::{MqttReceiverExecutionTarget, mqtt_receiver_targets_from_plan},
            private::{PrivateExecutionTarget, private_targets_from_plan},
            provider::{
                ProviderDispatchDevice, ProviderExecutionTarget, provider_targets_from_plan,
            },
            request::{DispatchAlert, DispatchEntityPayload},
        },
        payload::{
            CustomPayloadData, EntityKind, MAX_PROVIDER_TTL_MILLIS, MAX_PROVIDER_TTL_SECONDS,
            NotificationSeverity, OptionalText, PAYLOAD_VERSION, ProviderTtl, SCHEMA_VERSION,
            StandardFields,
        },
        planning::{
            plan::DeliveryPlan,
            planner::{DeliveryPlanCandidate, DeliveryPlanInput, DeliveryPlanner},
        },
    },
    storage::{DeviceInfo, DispatchTarget, Platform},
};

pub(crate) struct DispatchPreparationInput {
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) delivery_id: String,
    pub(crate) correlation_id: String,
    pub(crate) sent_at: i64,
    pub(crate) occurred_at: i64,
    pub(crate) alert: DispatchAlert,
    pub(crate) payload: DispatchEntityPayload,
    pub(crate) delivery_policy: crate::delivery_core::domain::projection::DomainDeliveryPolicy,
    pub(crate) dispatch_targets: Vec<DispatchTarget>,
    pub(crate) private_enabled: bool,
    pub(crate) private_default_ttl_secs: i64,
    pub(crate) public_base_url: Option<String>,
}

pub(crate) struct PreparedDispatchCore {
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) delivery_id: String,
    pub(crate) correlation_id: String,
    pub(crate) sent_at: i64,
    pub(crate) resolved_title: Option<String>,
    pub(crate) resolved_body: Option<String>,
    pub(crate) severity: NotificationSeverity,
    pub(crate) effective_ttl: Option<i64>,
    pub(crate) ttl_seconds: Option<u32>,
    pub(crate) private_default_ttl_secs: i64,
    pub(crate) private_payload: Arc<[u8]>,
    pub(crate) wakeup_data: Arc<HashMap<String, String>>,
    pub(crate) custom_data: Arc<HashMap<String, String>>,
    pub(crate) provider_targets: Vec<ProviderExecutionTarget>,
    pub(crate) provider_preparation_failed: i64,
    pub(crate) mqtt_receiver_targets: Vec<MqttReceiverExecutionTarget>,
    pub(crate) private_targets: Vec<PrivateExecutionTarget>,
    pub(crate) plan: DeliveryPlan,
    pub(crate) apple_thread_id: String,
    pub(crate) provider_fallback_body: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DispatchPreparationError {
    pub(crate) kind: DispatchPreparationErrorKind,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) enum DispatchPreparationErrorKind {
    PrivatePayloadEncodeFailed,
}

impl DispatchPreparationError {
    fn private_payload_encode_failed(message: impl Into<String>) -> Self {
        Self {
            kind: DispatchPreparationErrorKind::PrivatePayloadEncodeFailed,
            message: message.into(),
        }
    }
}

pub(crate) fn prepare_dispatch_core(
    input: DispatchPreparationInput,
) -> Result<PreparedDispatchCore, DispatchPreparationError> {
    let DispatchPreparationInput {
        channel_id,
        op_id,
        delivery_id,
        correlation_id,
        sent_at,
        occurred_at,
        alert,
        payload,
        delivery_policy,
        dispatch_targets,
        private_enabled,
        private_default_ttl_secs,
        public_base_url,
    } = input;
    let (entity_kind, entity_id, custom_data, extra_fields) = payload.into_parts();
    let entity_type = entity_kind.as_str();
    let entity_id = entity_id.trim().to_string();
    let resolved_title = OptionalText::normalize(alert.title.as_deref());
    let resolved_body = OptionalText::normalize(alert.body.as_deref());
    let severity = NotificationSeverity::normalize(alert.severity);
    let effective_ttl = alert
        .ttl
        .map(|ttl| normalize_ttl_to_expires_at(sent_at, ttl));
    let ttl_seconds =
        effective_ttl.map(|expires_at| ProviderTtl::remaining(sent_at, expires_at).into_inner());
    let private_default_ttl_secs = private_default_ttl_secs.clamp(0, MAX_PROVIDER_TTL_SECONDS);

    let mut provider_device_candidates: HashMap<(Platform, String), ProviderDispatchDevice> =
        HashMap::new();
    let mut plan_candidates = Vec::new();
    let mut provider_preparation_failed = 0_i64;
    let mqtt_private_payload_supported = mqtt_receiver_supports_payload(entity_kind, &extra_fields);
    for target in dispatch_targets {
        match target {
            DispatchTarget::Private {
                device_id,
                platform,
                device_key,
            } if private_enabled => {
                if platform == Platform::MQTT && !mqtt_private_payload_supported {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::DEBUG,
                        event = "dispatch.private_target_skipped",
                        channel_id = %(crate::util::redact_text(channel_id.as_str())),
                        op_id = %(crate::util::redact_text(op_id.as_str())),
                        correlation_id = %(crate::util::redact_text(correlation_id.as_str())),
                        delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                        device_key = %(crate::util::redact_text(device_key.as_deref().unwrap_or(""))),
                        platform = %(platform.name()),
                        entity_type = %(entity_type),
                        reason = %("mqtt_receiver_payload_unsupported")
                    );
                }
                plan_candidates.push(DeliveryPlanCandidate::Private {
                    device_id,
                    platform,
                });
            }
            DispatchTarget::Provider {
                platform,
                provider_token,
                device_key,
            } => {
                if !platform.supports_provider_push() {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "dispatch.provider_target_skipped",
                        channel_id = %(crate::util::redact_text(channel_id.as_str())),
                        op_id = %(crate::util::redact_text(op_id.as_str())),
                        correlation_id = %(crate::util::redact_text(correlation_id.as_str())),
                        delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                        device_key = %(crate::util::redact_text(device_key.as_str())),
                        platform = %(platform.name()),
                        reason = %("unsupported_provider_platform")
                    );
                    plan_candidates.push(DeliveryPlanCandidate::Provider {
                        platform,
                        device_key,
                    });
                    continue;
                }
                let info =
                    DeviceInfo::from_token(platform, provider_token.as_str()).inspect_err(|err| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "dispatch.provider_device_token_parse_failed",
                            channel_id = %(crate::util::redact_text(channel_id.as_str())),
                            op_id = %(crate::util::redact_text(op_id.as_str())),
                            correlation_id = %(crate::util::redact_text(correlation_id.as_str())),
                            delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                            device_key = %(crate::util::redact_text(device_key.as_str())),
                            platform = %(platform.name()),
                            error = %(err.to_string())
                        );
                    });
                let Ok(info) = info else {
                    provider_preparation_failed = provider_preparation_failed.saturating_add(1);
                    continue;
                };
                plan_candidates.push(DeliveryPlanCandidate::Provider {
                    platform,
                    device_key: device_key.clone(),
                });
                provider_device_candidates.insert(
                    (platform, device_key.clone()),
                    ProviderDispatchDevice { info, device_key },
                );
            }
            DispatchTarget::Private { device_id, .. } => {
                plan_candidates.push(DeliveryPlanCandidate::Private {
                    device_id,
                    platform: Platform::IOS,
                });
            }
        }
    }

    let mut custom_data = CustomPayloadData::new(custom_data);
    let embed_standard_text = should_embed_standard_notification_text(entity_kind);
    custom_data.apply_standard_fields(StandardFields {
        channel_id: &channel_id,
        title: embed_standard_text
            .then_some(resolved_title.as_deref())
            .flatten(),
        body: embed_standard_text
            .then_some(resolved_body.as_deref())
            .flatten(),
        severity: (entity_kind == EntityKind::Message).then_some(severity.as_str()),
        schema_version: SCHEMA_VERSION,
        payload_version: PAYLOAD_VERSION,
        op_id: &op_id,
        delivery_id: &delivery_id,
        ingested_at: sent_at,
        occurred_at,
        sent_at,
        ttl: effective_ttl,
        entity_type,
        entity_id: &entity_id,
    });
    custom_data.insert_extra_fields(extra_fields);
    custom_data.apply_gateway_base_url(public_base_url.as_deref());
    let derived_notification_text = custom_data.resolve_notification_text(
        entity_kind,
        resolved_title.as_deref(),
        resolved_body.as_deref(),
    );
    let title_was_gateway_generated =
        resolved_title.is_none() && derived_notification_text.title.is_some();
    let body_was_gateway_generated =
        resolved_body.is_none() && derived_notification_text.body.is_some();
    let resolved_title = resolved_title.or(derived_notification_text.title);
    let resolved_body = resolved_body.or(derived_notification_text.body);
    if title_was_gateway_generated || body_was_gateway_generated {
        custom_data.insert_extra_fields(HashMap::from([
            (
                "gateway_notification_generated".to_string(),
                "true".to_string(),
            ),
            (
                "gateway_notification_title_generated".to_string(),
                title_was_gateway_generated.to_string(),
            ),
            (
                "gateway_notification_body_generated".to_string(),
                body_was_gateway_generated.to_string(),
            ),
        ]));
    }
    if should_promote_notification_title(entity_kind) {
        custom_data.ensure_notification_title(resolved_title.as_deref());
    }
    let prepared_payload = custom_data
        .prepare_dispatch(channel_id.as_str(), entity_kind)
        .map_err(|err| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "dispatch.private_payload_encode_failed",
                channel_id = %(crate::util::redact_text(channel_id.as_str())),
                op_id = %(crate::util::redact_text(op_id.as_str())),
                correlation_id = %(crate::util::redact_text(correlation_id.as_str())),
                delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                entity_type = %(entity_type),
                entity_id = %(crate::util::redact_text(entity_id.as_str())),
                error = %(err.to_string())
            );
            DispatchPreparationError::private_payload_encode_failed(format!(
                "private payload encoding failed: {err}"
            ))
        })?;
    let plan = DeliveryPlanner::plan(DeliveryPlanInput {
        delivery_id: delivery_id.clone(),
        correlation_id: correlation_id.clone(),
        channel_id: channel_id.clone(),
        op_id: op_id.clone(),
        entity_type: entity_type.to_string(),
        entity_id: entity_id.clone(),
        created_at: sent_at,
        effective_ttl,
        private_default_ttl_secs,
        private_enabled,
        mqtt_private_payload_supported,
        delivery_policy,
        candidates: plan_candidates,
    });
    let private_targets = private_targets_from_plan(&plan);
    let mqtt_receiver_targets = mqtt_receiver_targets_from_plan(&plan);
    let provider_targets = provider_targets_from_plan(&plan, provider_device_candidates);

    Ok(PreparedDispatchCore {
        channel_id,
        op_id,
        delivery_id,
        correlation_id,
        sent_at,
        resolved_title,
        resolved_body,
        severity,
        effective_ttl,
        ttl_seconds,
        private_default_ttl_secs,
        private_payload: Arc::from(prepared_payload.private_payload.into_inner()),
        wakeup_data: prepared_payload.wakeup_data.into_inner(),
        custom_data: prepared_payload.custom_data,
        provider_targets,
        provider_preparation_failed,
        mqtt_receiver_targets,
        private_targets,
        plan,
        apple_thread_id: prepared_payload.apple_thread_id.into_inner(),
        provider_fallback_body: None,
    })
}

pub(crate) fn should_promote_notification_title(entity_kind: EntityKind) -> bool {
    entity_kind == EntityKind::Message
}

pub(crate) fn should_embed_standard_notification_text(entity_kind: EntityKind) -> bool {
    entity_kind == EntityKind::Message
}

pub(crate) fn mqtt_receiver_supports_payload(
    entity_kind: EntityKind,
    extra_fields: &HashMap<String, String>,
) -> bool {
    let _ = (entity_kind, extra_fields);
    true
}

pub(crate) fn normalize_ttl_to_expires_at(sent_at: i64, ttl: i64) -> i64 {
    ttl.min(sent_at.saturating_add(MAX_PROVIDER_TTL_MILLIS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_messages_promote_derived_notification_title_into_payload() {
        assert!(should_promote_notification_title(EntityKind::Message));
        assert!(!should_promote_notification_title(EntityKind::Thing));
        assert!(!should_promote_notification_title(EntityKind::Event));
    }

    #[test]
    fn only_messages_embed_standard_notification_text_into_payload() {
        assert!(should_embed_standard_notification_text(EntityKind::Message));
        assert!(!should_embed_standard_notification_text(EntityKind::Thing));
        assert!(!should_embed_standard_notification_text(EntityKind::Event));
    }

    #[test]
    fn mqtt_receiver_accepts_all_core_entity_payloads() {
        let empty = HashMap::new();
        assert!(mqtt_receiver_supports_payload(EntityKind::Message, &empty));
        assert!(mqtt_receiver_supports_payload(EntityKind::Thing, &empty));
        assert!(mqtt_receiver_supports_payload(EntityKind::Event, &empty));

        let mut thing_scoped = HashMap::new();
        thing_scoped.insert("thing_id".to_string(), "thing-1".to_string());
        assert!(mqtt_receiver_supports_payload(
            EntityKind::Message,
            &thing_scoped
        ));
    }

    #[test]
    fn ttl_uses_normalized_absolute_millisecond_expiry() {
        let sent_at = 1_725_000_000_000;
        assert_eq!(
            normalize_ttl_to_expires_at(sent_at, 1_725_000_060_000),
            1_725_000_060_000
        );
        assert_eq!(normalize_ttl_to_expires_at(sent_at, -1), -1);
        assert_eq!(
            normalize_ttl_to_expires_at(sent_at, sent_at + MAX_PROVIDER_TTL_MILLIS + 1),
            sent_at + MAX_PROVIDER_TTL_MILLIS
        );
    }

    #[test]
    fn provider_token_parse_failure_is_target_level_failure() {
        let prepared = prepare_dispatch_core(DispatchPreparationInput {
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            sent_at: 1_725_000_000_000,
            occurred_at: 1_725_000_000_000,
            alert: DispatchAlert::new(Some("title".to_string()), None, None, None),
            payload: DispatchEntityPayload::message(
                "message-1".to_string(),
                HashMap::new(),
                HashMap::new(),
            ),
            delivery_policy:
                crate::delivery_core::domain::projection::DomainDeliveryPolicy::fanout_default(),
            dispatch_targets: vec![DispatchTarget::Provider {
                platform: Platform::ANDROID,
                provider_token: "   ".to_string(),
                device_key: "device-key".to_string(),
            }],
            private_enabled: true,
            private_default_ttl_secs: 60,
            public_base_url: None,
        })
        .expect("bad provider token should not abort dispatch preparation");

        assert_eq!(prepared.provider_preparation_failed, 1);
        assert!(prepared.provider_targets.is_empty());
    }

    #[test]
    fn mqtt_receiver_targets_are_separate_from_private_outbox_targets() {
        let prepared = prepare_dispatch_core(DispatchPreparationInput {
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            sent_at: 1_725_000_000_000,
            occurred_at: 1_725_000_000_000,
            alert: DispatchAlert::new(Some("title".to_string()), None, None, None),
            payload: DispatchEntityPayload::message(
                "message-1".to_string(),
                HashMap::new(),
                HashMap::new(),
            ),
            delivery_policy:
                crate::delivery_core::domain::projection::DomainDeliveryPolicy::fanout_default(),
            dispatch_targets: vec![DispatchTarget::Private {
                device_id: [7; 16],
                platform: Platform::MQTT,
                device_key: Some("mqtt-device".to_string()),
            }],
            private_enabled: true,
            private_default_ttl_secs: 60,
            public_base_url: None,
        })
        .expect("mqtt receiver target should prepare");

        assert!(prepared.private_targets.is_empty());
        assert_eq!(prepared.mqtt_receiver_targets.len(), 1);
        assert_eq!(prepared.mqtt_receiver_targets[0].device_id, [7; 16]);
    }
}
