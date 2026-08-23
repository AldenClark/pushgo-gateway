use hashbrown::HashMap;
use std::sync::Arc;

use crate::{private::PrivateState, storage::DeviceId, util::encode_lower_hex_128};

use super::super::planning::plan::{DeliveryPlan, DeliveryTargetPlan};

pub(crate) struct PrivateExecutionTarget {
    pub(crate) device_id: DeviceId,
    pub(crate) kind: PrivateExecutionTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateExecutionTargetKind {
    Private {
        allow_realtime: bool,
        allow_outbox: bool,
    },
}

impl PrivateExecutionTargetKind {
    pub(crate) fn allow_realtime(self) -> bool {
        match self {
            Self::Private { allow_realtime, .. } => allow_realtime,
        }
    }

    pub(crate) fn allow_outbox(self) -> bool {
        match self {
            Self::Private { allow_outbox, .. } => allow_outbox,
        }
    }
}

pub(crate) fn private_targets_from_plan(plan: &DeliveryPlan) -> Vec<PrivateExecutionTarget> {
    #[derive(Default)]
    struct TargetFlags {
        allow_realtime: bool,
        allow_outbox: bool,
    }

    let mut targets: HashMap<DeviceId, TargetFlags> = HashMap::new();
    for target in &plan.targets {
        match target {
            DeliveryTargetPlan::PrivateRealtime { device_id, .. } => {
                targets.entry(*device_id).or_default().allow_realtime = true;
            }
            DeliveryTargetPlan::PrivateOutbox { device_id, .. } => {
                targets.entry(*device_id).or_default().allow_outbox = true;
            }
            DeliveryTargetPlan::ProviderInline { .. }
            | DeliveryTargetPlan::ProviderWakeupPull { .. }
            | DeliveryTargetPlan::MqttReceiver { .. } => {}
        }
    }
    targets
        .into_iter()
        .filter_map(|(device_id, flags)| {
            if flags.allow_realtime || flags.allow_outbox {
                Some(PrivateExecutionTarget {
                    device_id,
                    kind: PrivateExecutionTargetKind::Private {
                        allow_realtime: flags.allow_realtime,
                        allow_outbox: flags.allow_outbox,
                    },
                })
            } else {
                None
            }
        })
        .collect()
}
pub(crate) struct PrivateDeliveryExecution<'a> {
    pub(crate) private_state: &'a PrivateState,
    pub(crate) correlation_id: &'a str,
    pub(crate) delivery_id: &'a str,
    pub(crate) channel_id: &'a str,
    pub(crate) targets: &'a [PrivateExecutionTarget],
    pub(crate) payload: Arc<[u8]>,
    pub(crate) sent_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Debug, Default)]
pub(crate) struct PrivateDeliveryExecutionReport {
    pub(crate) attempts: Vec<PrivateDeliveryAttempt>,
}

impl PrivateDeliveryExecutionReport {
    pub(crate) fn realtime_delivered_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|attempt| attempt.realtime_delivered)
            .count()
    }
}

#[derive(Debug)]
pub(crate) struct PrivateDeliveryAttempt {
    pub(crate) device_id: DeviceId,
    pub(crate) outcome: PrivateDeliveryAttemptOutcome,
    pub(crate) realtime_delivered: bool,
}

#[derive(Debug)]
pub(crate) enum PrivateDeliveryAttemptOutcome {
    Enqueued,
    Failed(crate::Error),
}

pub(crate) async fn execute_private_deliveries(
    execution: PrivateDeliveryExecution<'_>,
) -> PrivateDeliveryExecutionReport {
    let mut report = PrivateDeliveryExecutionReport::default();
    let mut queued_devices = Vec::with_capacity(execution.targets.len());
    for target in execution.targets {
        let device_id = target.device_id;
        // Realtime delivery is only an accelerator. Every accepted private
        // target must first have a durable outbox row so process loss, socket
        // races, and a client ACK lost in flight cannot erase the delivery.
        if target.kind.allow_outbox() || target.kind.allow_realtime() {
            queued_devices.push(device_id);
        }
    }

    let enqueue_results = execution
        .private_state
        .enqueue_private_deliveries(
            &queued_devices,
            execution.delivery_id,
            Arc::clone(&execution.payload),
            execution.sent_at,
            execution.expires_at,
        )
        .await;

    for (device_id, result) in enqueue_results {
        match result {
            Ok(outcome) => {
                let realtime_delivered = outcome.accepted_for_delivery
                    && deliver_enqueued_private_realtime(
                        &execution,
                        device_id,
                        Arc::clone(&outcome.canonical_payload),
                    );
                report.attempts.push(PrivateDeliveryAttempt {
                    device_id,
                    outcome: PrivateDeliveryAttemptOutcome::Enqueued,
                    realtime_delivered,
                });
            }
            Err(err) => {
                execution.private_state.metrics.mark_enqueue_failure();
                if matches!(
                    &err,
                    crate::Error::TooBusy
                        | crate::Error::StoreError(
                            crate::storage::StoreError::PrivateOutboxCapacityExceeded { .. }
                        )
                ) {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::DEBUG,
                        event = "dispatch.private_enqueue_deferred",
                        correlation_id = %(crate::util::redact_text(execution.correlation_id)),
                        delivery_id = %(crate::util::redact_text(execution.delivery_id)),
                        channel_id = %(crate::util::redact_text(execution.channel_id)),
                        device_id = %(crate::util::redact_text(encode_lower_hex_128(&device_id))),
                        reason = "private_outbox_capacity"
                    );
                } else {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "dispatch.private_enqueue_failed",
                        correlation_id = %(crate::util::redact_text(execution.correlation_id)),
                        delivery_id = %(crate::util::redact_text(execution.delivery_id)),
                        channel_id = %(crate::util::redact_text(execution.channel_id)),
                        device_id = %(crate::util::redact_text(encode_lower_hex_128(&device_id))),
                        error = %(err.to_string())
                    );
                }
                report.attempts.push(PrivateDeliveryAttempt {
                    device_id,
                    outcome: PrivateDeliveryAttemptOutcome::Failed(err),
                    realtime_delivered: false,
                });
            }
        }
    }

    report
}

fn deliver_enqueued_private_realtime(
    execution: &PrivateDeliveryExecution<'_>,
    device_id: DeviceId,
    canonical_payload: Arc<[u8]>,
) -> bool {
    if !execution.private_state.config.online_fast_path_enabled
        || execution
            .private_state
            .hub
            .has_active_mqtt_connection(device_id)
        || !execution.private_state.hub.is_online(device_id)
    {
        return false;
    }

    let delivered = execution.private_state.hub.try_deliver_to_device(
        device_id,
        crate::private::protocol::DeliverEnvelope {
            delivery_id: execution.delivery_id.to_string(),
            payload: canonical_payload,
        },
    );
    if !delivered {
        execution.private_state.metrics.mark_deliver_send_failure();
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::WARN,
            event = "dispatch.private_realtime_delivery_failed",
            correlation_id = %(crate::util::redact_text(execution.correlation_id)),
            delivery_id = %(crate::util::redact_text(execution.delivery_id)),
            channel_id = %(crate::util::redact_text(execution.channel_id)),
            device_id = %(crate::util::redact_text(encode_lower_hex_128(&device_id)))
        );
    }
    delivered
}
