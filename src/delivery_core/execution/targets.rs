#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use crate::{
        delivery_core::execution::mqtt_receiver::mqtt_receiver_targets_from_plan,
        delivery_core::execution::private::{
            PrivateExecutionTargetKind, private_targets_from_plan,
        },
        delivery_core::execution::provider::{ProviderDispatchDevice, provider_targets_from_plan},
        delivery_core::planning::plan::{
            DeliveryPlan, DeliverySkip, DeliverySkipReason, DeliveryTargetPlan, PayloadRef,
            ProviderTokenRef, PullRef,
        },
        storage::{DeviceInfo, Platform},
    };

    #[test]
    fn execution_targets_are_derived_from_delivery_plan_targets() {
        let private_device = [1u8; 16];
        let skipped_mqtt_device = [2u8; 16];
        let mqtt_receiver_device = [3u8; 16];
        let provider = ProviderDispatchDevice {
            info: DeviceInfo::from_token(Platform::ANDROID, "android-provider-token-0001")
                .expect("android provider token should parse"),
            device_key: "provider-device".to_string(),
        };
        let mut candidates = HashMap::new();
        candidates.insert((Platform::ANDROID, "provider-device".to_string()), provider);
        candidates.insert(
            (Platform::WINDOWS, "skipped-provider".to_string()),
            ProviderDispatchDevice {
                info: DeviceInfo::from_token(Platform::WINDOWS, "windows-provider-token-0001")
                    .expect("windows provider token should parse"),
                device_key: "skipped-provider".to_string(),
            },
        );
        let plan = DeliveryPlan {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message".to_string(),
            created_at: 1,
            targets: vec![
                DeliveryTargetPlan::PrivateRealtime {
                    device_id: private_device,
                    payload_ref: PayloadRef::private("delivery"),
                },
                DeliveryTargetPlan::PrivateOutbox {
                    device_id: private_device,
                    payload_ref: PayloadRef::private("delivery"),
                    expires_at: 2,
                },
                DeliveryTargetPlan::ProviderInline {
                    platform: Platform::ANDROID,
                    device_key: "provider-device".to_string(),
                    token_ref: ProviderTokenRef::new(Platform::ANDROID, "provider-device"),
                    payload_ref: PayloadRef::provider_inline(
                        "delivery",
                        Platform::ANDROID,
                        "provider-device",
                    ),
                },
                DeliveryTargetPlan::ProviderWakeupPull {
                    platform: Platform::ANDROID,
                    device_key: "provider-device".to_string(),
                    token_ref: ProviderTokenRef::new(Platform::ANDROID, "provider-device"),
                    payload_ref: PayloadRef::provider_wakeup(
                        "delivery",
                        Platform::ANDROID,
                        "provider-device",
                    ),
                    pull_ref: PullRef::new("delivery", Platform::ANDROID, "provider-device"),
                },
                DeliveryTargetPlan::MqttReceiver {
                    device_id: mqtt_receiver_device,
                    topic: "channel".to_string(),
                    qos: 1,
                    payload_ref: PayloadRef::private("delivery"),
                },
            ],
            skips: vec![DeliverySkip {
                reason: DeliverySkipReason::MqttReceiverUnsupported,
                device_id: Some(skipped_mqtt_device),
            }],
        };

        let private_targets = private_targets_from_plan(&plan);
        let private_target = private_targets
            .iter()
            .find(|target| target.device_id == private_device)
            .expect("private target should be derived from plan");
        assert_eq!(
            private_target.kind,
            PrivateExecutionTargetKind::Private {
                allow_realtime: true,
                allow_outbox: true,
            }
        );
        assert!(
            private_targets
                .iter()
                .all(|target| target.device_id != mqtt_receiver_device),
            "MQTT receiver must not be folded into private realtime/outbox execution"
        );

        let mqtt_targets = mqtt_receiver_targets_from_plan(&plan);
        assert_eq!(mqtt_targets.len(), 1);
        assert_eq!(mqtt_targets[0].device_id, mqtt_receiver_device);
        assert_eq!(mqtt_targets[0].topic, "channel");
        assert_eq!(mqtt_targets[0].qos, 1);

        let provider_targets = provider_targets_from_plan(&plan, candidates);
        assert_eq!(provider_targets.len(), 1);
        assert_eq!(provider_targets[0].device.device_key, "provider-device");
        assert!(provider_targets[0].allow_inline);
        assert!(provider_targets[0].wakeup_pull_ref.is_some());
    }

    #[test]
    fn provider_execution_target_respects_plan_wakeup_pull_absence() {
        let provider = ProviderDispatchDevice {
            info: DeviceInfo::from_token(Platform::ANDROID, "android-provider-token-0002")
                .expect("android provider token should parse"),
            device_key: "provider-device".to_string(),
        };
        let mut candidates = HashMap::new();
        candidates.insert((Platform::ANDROID, "provider-device".to_string()), provider);
        let plan = DeliveryPlan {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message".to_string(),
            created_at: 1,
            targets: vec![DeliveryTargetPlan::ProviderInline {
                platform: Platform::ANDROID,
                device_key: "provider-device".to_string(),
                token_ref: ProviderTokenRef::new(Platform::ANDROID, "provider-device"),
                payload_ref: PayloadRef::provider_inline(
                    "delivery",
                    Platform::ANDROID,
                    "provider-device",
                ),
            }],
            skips: Vec::new(),
        };

        let provider_targets = provider_targets_from_plan(&plan, candidates);
        assert_eq!(provider_targets.len(), 1);
        assert!(provider_targets[0].allow_inline);
        assert!(provider_targets[0].wakeup_pull_ref.is_none());
    }

    #[test]
    fn provider_execution_target_preserves_wakeup_only_plan() {
        let provider = ProviderDispatchDevice {
            info: DeviceInfo::from_token(Platform::ANDROID, "android-provider-token-0003")
                .expect("android provider token should parse"),
            device_key: "provider-device".to_string(),
        };
        let mut candidates = HashMap::new();
        candidates.insert((Platform::ANDROID, "provider-device".to_string()), provider);
        let plan = DeliveryPlan {
            delivery_id: "delivery".to_string(),
            correlation_id: "correlation".to_string(),
            channel_id: "channel".to_string(),
            op_id: "op".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message".to_string(),
            created_at: 1,
            targets: vec![DeliveryTargetPlan::ProviderWakeupPull {
                platform: Platform::ANDROID,
                device_key: "provider-device".to_string(),
                token_ref: ProviderTokenRef::new(Platform::ANDROID, "provider-device"),
                payload_ref: PayloadRef::provider_wakeup(
                    "delivery",
                    Platform::ANDROID,
                    "provider-device",
                ),
                pull_ref: PullRef::new("delivery", Platform::ANDROID, "provider-device"),
            }],
            skips: Vec::new(),
        };

        let provider_targets = provider_targets_from_plan(&plan, candidates);
        assert_eq!(provider_targets.len(), 1);
        assert!(!provider_targets[0].allow_inline);
        assert!(provider_targets[0].wakeup_pull_ref.is_some());
    }
}
