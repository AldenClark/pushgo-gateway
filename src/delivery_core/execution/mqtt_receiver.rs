use hashbrown::HashMap;
use std::sync::Arc;

use crate::{private::PrivateState, storage::DeviceId, storage::Storage};

use super::super::planning::plan::{DeliveryPlan, DeliveryTargetPlan};
use super::progress::DispatchProgress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MqttReceiverExecutionTarget {
    pub(crate) device_id: DeviceId,
    pub(crate) topic: String,
    pub(crate) qos: u8,
}

pub(crate) fn mqtt_receiver_targets_from_plan(
    plan: &DeliveryPlan,
) -> Vec<MqttReceiverExecutionTarget> {
    let mut targets: HashMap<DeviceId, MqttReceiverExecutionTarget> = HashMap::new();
    for target in &plan.targets {
        if let DeliveryTargetPlan::MqttReceiver {
            device_id,
            topic,
            qos,
            ..
        } = target
        {
            targets.insert(
                *device_id,
                MqttReceiverExecutionTarget {
                    device_id: *device_id,
                    topic: topic.clone(),
                    qos: *qos,
                },
            );
        }
    }
    targets.into_values().collect()
}

pub(crate) struct MqttReceiverDeliveryExecution<'a> {
    pub(crate) private_state: &'a PrivateState,
    pub(crate) store: &'a Storage,
    pub(crate) correlation_id: &'a str,
    pub(crate) delivery_id: &'a str,
    pub(crate) channel_id: &'a str,
    pub(crate) sent_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) targets: &'a [MqttReceiverExecutionTarget],
    pub(crate) payload: Arc<[u8]>,
}

pub(crate) async fn execute_mqtt_receiver_deliveries(
    execution: MqttReceiverDeliveryExecution<'_>,
    progress: &mut DispatchProgress,
) -> Result<(), crate::Error> {
    let device_ids = execution
        .targets
        .iter()
        .map(|target| target.device_id)
        .collect::<Vec<_>>();
    let outcomes = execution
        .private_state
        .enqueue_private_deliveries(
            &device_ids,
            execution.delivery_id,
            Arc::clone(&execution.payload),
            execution.sent_at,
            execution.expires_at,
        )
        .await;
    let mut first_failure = None;
    for (device_id, outcome) in outcomes {
        let Some(target) = execution
            .targets
            .iter()
            .find(|target| target.device_id == device_id)
        else {
            continue;
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => {
                progress.record_mqtt_failure();
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "dispatch.mqtt_receiver_outbox_enqueue_failed",
                    correlation_id = %(crate::util::redact_text(execution.correlation_id)),
                    delivery_id = %(crate::util::redact_text(execution.delivery_id)),
                    channel_id = %(crate::util::redact_text(execution.channel_id)),
                    device_id = %(crate::util::redact_text(crate::util::encode_lower_hex_128(&target.device_id))),
                    error = %(err.to_string())
                );
                if first_failure.is_none() {
                    first_failure = Some(err);
                }
                continue;
            }
        };

        let realtime_delivered = outcome.accepted_for_delivery
            && execution.private_state.hub.try_deliver_to_mqtt_device(
                target.device_id,
                crate::private::protocol::DeliverEnvelope {
                    delivery_id: execution.delivery_id.to_string(),
                    payload: Arc::clone(&outcome.canonical_payload),
                },
            );
        progress.record_mqtt_success(target.device_id);
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "dispatch.mqtt_receiver_outbox_enqueued",
            correlation_id = %(crate::util::redact_text(execution.correlation_id)),
            delivery_id = %(crate::util::redact_text(execution.delivery_id)),
            channel_id = %(crate::util::redact_text(execution.channel_id)),
            device_id = %(crate::util::redact_text(crate::util::encode_lower_hex_128(&target.device_id))),
            topic = %(crate::util::redact_text(target.topic.as_str())),
            qos = (target.qos as u64),
            realtime_delivered = (realtime_delivered)
        );
        let store = execution.store.clone();
        let device_id = target.device_id;
        tokio::spawn(async move {
            store
                .record_device_activity_best_effort(
                    device_id,
                    chrono::Utc::now().timestamp_millis(),
                    "mqtt_receiver_delivery",
                )
                .await;
        });
    }
    match first_failure {
        Some(err) => Err(err),
        None => Ok(()),
    }
}
