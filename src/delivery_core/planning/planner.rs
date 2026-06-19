use crate::{domain_model::projection::DomainDeliveryPolicy, storage::DeviceId, storage::Platform};

use super::plan::{
    DeliveryPlan, DeliverySkip, DeliverySkipReason, DeliveryTargetPlan, PayloadRef,
    ProviderTokenRef, PullRef,
};

pub(crate) struct DeliveryPlanner;

pub(crate) struct DeliveryPlanInput {
    pub(crate) delivery_id: String,
    pub(crate) correlation_id: String,
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) entity_type: String,
    pub(crate) entity_id: String,
    pub(crate) created_at: i64,
    pub(crate) effective_ttl: Option<i64>,
    pub(crate) private_default_ttl_secs: i64,
    pub(crate) private_enabled: bool,
    pub(crate) mqtt_private_payload_supported: bool,
    pub(crate) delivery_policy: DomainDeliveryPolicy,
    pub(crate) candidates: Vec<DeliveryPlanCandidate>,
}

pub(crate) enum DeliveryPlanCandidate {
    Private {
        device_id: DeviceId,
        platform: Platform,
    },
    Provider {
        platform: Platform,
        device_key: String,
    },
}

impl DeliveryPlanner {
    pub(crate) fn plan(input: DeliveryPlanInput) -> DeliveryPlan {
        let mut targets = Vec::new();
        let mut skips = Vec::new();
        let private_payload_ref = PayloadRef::private(input.delivery_id.as_str());
        let private_expires_at = input
            .effective_ttl
            .unwrap_or(input.created_at + input.private_default_ttl_secs * 1000);

        for candidate in input.candidates {
            match candidate {
                DeliveryPlanCandidate::Private {
                    device_id,
                    platform,
                } if input.private_enabled => {
                    if platform == Platform::MQTT && !input.delivery_policy.allow_mqtt_receiver {
                        skips.push(DeliverySkip {
                            reason: DeliverySkipReason::DomainPolicyDisabled,
                            device_id: Some(device_id),
                        });
                    } else if platform == Platform::MQTT && !input.mqtt_private_payload_supported {
                        skips.push(DeliverySkip {
                            reason: DeliverySkipReason::MqttReceiverUnsupported,
                            device_id: Some(device_id),
                        });
                    } else if platform == Platform::MQTT {
                        targets.push(DeliveryTargetPlan::MqttReceiver {
                            device_id,
                            topic: input.channel_id.clone(),
                            qos: 1,
                            payload_ref: private_payload_ref.clone(),
                        });
                    } else {
                        let mut added = false;
                        if input.delivery_policy.allow_private_realtime {
                            targets.push(DeliveryTargetPlan::PrivateRealtime {
                                device_id,
                                payload_ref: private_payload_ref.clone(),
                            });
                            added = true;
                        }
                        if input.delivery_policy.allow_private_outbox {
                            targets.push(DeliveryTargetPlan::PrivateOutbox {
                                device_id,
                                payload_ref: private_payload_ref.clone(),
                                expires_at: private_expires_at,
                            });
                            added = true;
                        }
                        if !added {
                            skips.push(DeliverySkip {
                                reason: DeliverySkipReason::DomainPolicyDisabled,
                                device_id: Some(device_id),
                            });
                        }
                    }
                }
                DeliveryPlanCandidate::Private { device_id, .. } => {
                    skips.push(DeliverySkip {
                        reason: DeliverySkipReason::PrivateRuntimeUnavailable,
                        device_id: Some(device_id),
                    });
                }
                DeliveryPlanCandidate::Provider {
                    platform,
                    device_key,
                } => {
                    if platform.supports_provider_push() {
                        let token_ref = ProviderTokenRef::new(platform, device_key.as_str());
                        let mut added = false;
                        if input.delivery_policy.allow_provider_inline {
                            targets.push(DeliveryTargetPlan::ProviderInline {
                                platform,
                                device_key: device_key.clone(),
                                token_ref: token_ref.clone(),
                                payload_ref: PayloadRef::provider_inline(
                                    input.delivery_id.as_str(),
                                    platform,
                                    device_key.as_str(),
                                ),
                            });
                            added = true;
                        }
                        if input.delivery_policy.allow_provider_wakeup_pull {
                            targets.push(DeliveryTargetPlan::ProviderWakeupPull {
                                platform,
                                device_key: device_key.clone(),
                                token_ref,
                                payload_ref: PayloadRef::provider_wakeup(
                                    input.delivery_id.as_str(),
                                    platform,
                                    device_key.as_str(),
                                ),
                                pull_ref: PullRef::new(
                                    input.delivery_id.as_str(),
                                    platform,
                                    device_key.as_str(),
                                ),
                            });
                            added = true;
                        }
                        if !added {
                            skips.push(DeliverySkip {
                                reason: DeliverySkipReason::DomainPolicyDisabled,
                                device_id: None,
                            });
                        }
                    } else {
                        skips.push(DeliverySkip {
                            reason: DeliverySkipReason::ReceiverCapabilityMissing,
                            device_id: None,
                        });
                    }
                }
            }
        }

        DeliveryPlan {
            delivery_id: input.delivery_id,
            correlation_id: input.correlation_id,
            channel_id: input.channel_id,
            op_id: input.op_id,
            entity_type: input.entity_type,
            entity_id: input.entity_id,
            created_at: input.created_at,
            targets,
            skips,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_skips_unsupported_mqtt_private_payloads() {
        let device_id = [9; 16];
        let plan = DeliveryPlanner::plan(DeliveryPlanInput {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "event".to_string(),
            entity_id: "event-id".to_string(),
            created_at: 1000,
            effective_ttl: None,
            private_default_ttl_secs: 60,
            private_enabled: true,
            mqtt_private_payload_supported: false,
            delivery_policy: DomainDeliveryPolicy::fanout_default(),
            candidates: vec![DeliveryPlanCandidate::Private {
                device_id,
                platform: Platform::MQTT,
            }],
        });

        assert!(plan.targets.is_empty());
        assert_eq!(
            plan.skips[0].reason,
            DeliverySkipReason::MqttReceiverUnsupported
        );
    }

    #[test]
    fn planner_builds_private_and_provider_targets() {
        let device_id = [3; 16];
        let plan = DeliveryPlanner::plan(DeliveryPlanInput {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message-id".to_string(),
            created_at: 1000,
            effective_ttl: Some(2000),
            private_default_ttl_secs: 60,
            private_enabled: true,
            mqtt_private_payload_supported: true,
            delivery_policy: DomainDeliveryPolicy::fanout_default(),
            candidates: vec![
                DeliveryPlanCandidate::Private {
                    device_id,
                    platform: Platform::IOS,
                },
                DeliveryPlanCandidate::Provider {
                    platform: Platform::ANDROID,
                    device_key: "provider-device".to_string(),
                },
            ],
        });

        assert_eq!(plan.targets.len(), 4);
        assert!(plan.skips.is_empty());
        let mut saw_private_payload_ref = false;
        let mut saw_provider_token_ref = false;
        let mut saw_provider_pull_ref = false;
        for target in &plan.targets {
            match target {
                DeliveryTargetPlan::PrivateRealtime { payload_ref, .. }
                | DeliveryTargetPlan::PrivateOutbox { payload_ref, .. } => {
                    assert_eq!(payload_ref.as_str(), "payload:private:delivery");
                    saw_private_payload_ref = true;
                }
                DeliveryTargetPlan::ProviderInline {
                    token_ref,
                    payload_ref,
                    ..
                } => {
                    assert_eq!(token_ref.as_str(), "token:android:provider-device");
                    assert_eq!(
                        payload_ref.as_str(),
                        "payload:provider:inline:delivery:android:provider-device"
                    );
                    saw_provider_token_ref = true;
                }
                DeliveryTargetPlan::ProviderWakeupPull {
                    token_ref,
                    payload_ref,
                    pull_ref,
                    ..
                } => {
                    assert_eq!(token_ref.as_str(), "token:android:provider-device");
                    assert_eq!(
                        payload_ref.as_str(),
                        "payload:provider:wakeup:delivery:android:provider-device"
                    );
                    assert_eq!(pull_ref.as_str(), "pull:delivery:android:provider-device");
                    saw_provider_pull_ref = true;
                }
                DeliveryTargetPlan::MqttReceiver { .. } => {}
            }
        }
        assert!(saw_private_payload_ref);
        assert!(saw_provider_token_ref);
        assert!(saw_provider_pull_ref);
    }

    #[test]
    fn planner_applies_domain_delivery_policy() {
        let private_device_id = [4; 16];
        let mqtt_device_id = [5; 16];
        let plan = DeliveryPlanner::plan(DeliveryPlanInput {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message-id".to_string(),
            created_at: 1000,
            effective_ttl: None,
            private_default_ttl_secs: 60,
            private_enabled: true,
            mqtt_private_payload_supported: true,
            delivery_policy: DomainDeliveryPolicy {
                allow_private_realtime: false,
                allow_private_outbox: true,
                allow_provider_inline: false,
                allow_provider_wakeup_pull: true,
                allow_mqtt_receiver: false,
            },
            candidates: vec![
                DeliveryPlanCandidate::Private {
                    device_id: private_device_id,
                    platform: Platform::IOS,
                },
                DeliveryPlanCandidate::Private {
                    device_id: mqtt_device_id,
                    platform: Platform::MQTT,
                },
                DeliveryPlanCandidate::Provider {
                    platform: Platform::ANDROID,
                    device_key: "provider-device".to_string(),
                },
            ],
        });

        assert!(
            plan.targets
                .iter()
                .any(|target| matches!(target, DeliveryTargetPlan::PrivateOutbox { .. }))
        );
        assert!(
            plan.targets
                .iter()
                .any(|target| matches!(target, DeliveryTargetPlan::ProviderWakeupPull { .. }))
        );
        assert!(!plan.targets.iter().any(|target| matches!(
            target,
            DeliveryTargetPlan::PrivateRealtime { .. }
                | DeliveryTargetPlan::ProviderInline { .. }
                | DeliveryTargetPlan::MqttReceiver { .. }
        )));
        assert!(plan.skips.iter().any(|skip| {
            skip.reason == DeliverySkipReason::DomainPolicyDisabled
                && skip.device_id == Some(mqtt_device_id)
        }));
    }
}
