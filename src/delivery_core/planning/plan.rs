use crate::{storage::DeviceId, storage::Platform};

#[derive(Debug, Clone)]
pub(crate) struct DeliveryPlan {
    pub(crate) delivery_id: String,
    pub(crate) correlation_id: String,
    pub(crate) channel_id: String,
    pub(crate) op_id: String,
    pub(crate) entity_type: String,
    pub(crate) entity_id: String,
    pub(crate) created_at: i64,
    pub(crate) targets: Vec<DeliveryTargetPlan>,
    pub(crate) skips: Vec<DeliverySkip>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PayloadRef(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProviderTokenRef(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PullRef(String);

#[derive(Debug, Clone)]
pub(crate) enum DeliveryTargetPlan {
    PrivateRealtime {
        device_id: DeviceId,
        payload_ref: PayloadRef,
    },
    PrivateOutbox {
        device_id: DeviceId,
        payload_ref: PayloadRef,
        expires_at: i64,
    },
    ProviderInline {
        platform: Platform,
        device_key: String,
        token_ref: ProviderTokenRef,
        payload_ref: PayloadRef,
    },
    ProviderWakeupPull {
        platform: Platform,
        device_key: String,
        token_ref: ProviderTokenRef,
        payload_ref: PayloadRef,
        pull_ref: PullRef,
    },
    MqttReceiver {
        device_id: DeviceId,
        topic: String,
        qos: u8,
        payload_ref: PayloadRef,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct DeliverySkip {
    pub(crate) reason: DeliverySkipReason,
    pub(crate) device_id: Option<DeviceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliverySkipReason {
    DomainPolicyDisabled,
    ReceiverCapabilityMissing,
    PrivateRuntimeUnavailable,
    ProviderPayloadTooLarge,
    MqttReceiverUnsupported,
}

impl PayloadRef {
    pub(crate) fn private(delivery_id: &str) -> Self {
        Self(format!("payload:private:{delivery_id}"))
    }

    pub(crate) fn provider_inline(delivery_id: &str, platform: Platform, device_key: &str) -> Self {
        Self(format!(
            "payload:provider:inline:{delivery_id}:{}:{device_key}",
            platform.name()
        ))
    }

    pub(crate) fn provider_wakeup(delivery_id: &str, platform: Platform, device_key: &str) -> Self {
        Self(format!(
            "payload:provider:wakeup:{delivery_id}:{}:{device_key}",
            platform.name()
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl ProviderTokenRef {
    pub(crate) fn new(platform: Platform, device_key: &str) -> Self {
        Self(format!("token:{}:{device_key}", platform.name()))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PullRef {
    pub(crate) fn new(delivery_id: &str, platform: Platform, device_key: &str) -> Self {
        Self(format!(
            "pull:{delivery_id}:{}:{device_key}",
            platform.name()
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_plan_preserves_core_boundary_fields() {
        let device_id = [7u8; 16];
        let plan = DeliveryPlan {
            delivery_id: "delivery-1".to_string(),
            correlation_id: "trace-1".to_string(),
            channel_id: "channel-1".to_string(),
            op_id: "op-1".to_string(),
            entity_type: "message".to_string(),
            entity_id: "message-1".to_string(),
            created_at: 123,
            targets: vec![
                DeliveryTargetPlan::PrivateRealtime {
                    device_id,
                    payload_ref: PayloadRef::private("delivery-1"),
                },
                DeliveryTargetPlan::PrivateOutbox {
                    device_id,
                    payload_ref: PayloadRef::private("delivery-1"),
                    expires_at: 456,
                },
                DeliveryTargetPlan::MqttReceiver {
                    device_id,
                    topic: "channel-1".to_string(),
                    qos: 1,
                    payload_ref: PayloadRef::private("delivery-1"),
                },
                DeliveryTargetPlan::ProviderInline {
                    platform: Platform::ANDROID,
                    device_key: "device-key-1".to_string(),
                    token_ref: ProviderTokenRef::new(Platform::ANDROID, "device-key-1"),
                    payload_ref: PayloadRef::provider_inline(
                        "delivery-1",
                        Platform::ANDROID,
                        "device-key-1",
                    ),
                },
                DeliveryTargetPlan::ProviderWakeupPull {
                    platform: Platform::ANDROID,
                    device_key: "device-key-1".to_string(),
                    token_ref: ProviderTokenRef::new(Platform::ANDROID, "device-key-1"),
                    payload_ref: PayloadRef::provider_wakeup(
                        "delivery-1",
                        Platform::ANDROID,
                        "device-key-1",
                    ),
                    pull_ref: PullRef::new("delivery-1", Platform::ANDROID, "device-key-1"),
                },
            ],
            skips: vec![DeliverySkip {
                reason: DeliverySkipReason::MqttReceiverUnsupported,
                device_id: Some(device_id),
            }],
        };

        assert_eq!(plan.delivery_id, "delivery-1");
        assert_eq!(plan.targets.len(), 5);
        assert_eq!(
            plan.skips[0].reason,
            DeliverySkipReason::MqttReceiverUnsupported
        );
    }
}
