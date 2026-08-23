use super::*;
use crate::delivery_core::execution::private::{
    PrivateDeliveryAttemptOutcome, PrivateDeliveryExecution, execute_private_deliveries,
};

pub(super) async fn enqueue_private_deliveries(
    prepared: &PreparedDispatch<'_>,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    let Some(private_dispatch) = prepared.private_dispatch.as_ref() else {
        return Ok(());
    };
    let private_expires_at = prepared
        .effective_ttl
        .unwrap_or(prepared.sent_at + prepared.private_default_ttl_secs * 1000);
    let report = execute_private_deliveries(PrivateDeliveryExecution {
        private_state: private_dispatch.state,
        correlation_id: prepared.correlation_id.as_ref(),
        delivery_id: prepared.delivery_id.as_str(),
        channel_id: prepared.channel_id_value.as_str(),
        targets: &private_dispatch.targets,
        payload: prepared.private_payload.clone(),
        sent_at: prepared.sent_at,
        expires_at: private_expires_at,
    })
    .await;

    let mut first_failure = None;
    for attempt in report.attempts {
        match attempt.outcome {
            PrivateDeliveryAttemptOutcome::Enqueued => {
                progress.private_enqueue_stats.record_success();
                progress.record_private_success(attempt.device_id);
                if attempt.realtime_delivered {
                    progress
                        .private_realtime_delivered
                        .insert(attempt.device_id);
                }
            }
            PrivateDeliveryAttemptOutcome::Failed(err) => {
                progress.private_enqueue_stats.record_failure(
                    "private_subscriber",
                    attempt.device_id,
                    &err,
                );
                if first_failure.is_none() {
                    first_failure = Some(err);
                }
            }
        }
    }
    match first_failure {
        Some(err) => Err(err),
        None => Ok(()),
    }
}
