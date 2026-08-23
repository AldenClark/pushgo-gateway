use std::{borrow::Cow, future::Future, sync::Arc};

use ::tracing::Instrument;
use chrono::Utc;
use hashbrown::HashMap;

use crate::{
    api::{Error, format_channel_id, handlers::activity::dispatch_event_activity_update},
    app::AppState,
    delivery_core::execution::coordinator::{
        DispatchExecutionDelegate, DispatchExecutionError, DispatchExecutionInput,
        DispatchExecutionRuntime, PreparedDispatch, ProviderPayloads, execute_dispatch,
    },
    delivery_core::execution::mqtt_receiver::{
        MqttReceiverDeliveryExecution, execute_mqtt_receiver_deliveries,
    },
    delivery_core::execution::progress::DispatchProgress,
    delivery_core::execution::provider::PreparedProviderPayload,
    delivery_core::execution::request::DispatchRequest,
    delivery_core::payload::{
        MAX_PROVIDER_TTL_SECONDS, ProviderDeliveryPath as CoreProviderDeliveryPath,
        ProviderPullTarget,
    },
    delivery_core::store::counters::RuntimeCounterSink,
    delivery_core::submit::sender_status_from_dispatch,
    dispatch::{
        DispatchError, ProviderDeliveryPath, ProviderDispatchOutcome, ProviderDispatchOutcomeLease,
        ProviderPullDelivery,
    },
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    storage::{DeviceInfo, DispatchSubmissionRecord, DispatchTarget, Platform},
};

use super::ids::{DeliveryId, OpId, SemanticScope};
use crate::api::handlers::dispatch_lifecycle::{
    DispatchOpGuard, DispatchOpGuardStart, NotificationDispatchSummary,
};

mod android;
mod apple;
mod private;
mod provider;
mod tracing;
mod types;
mod widgets;
mod windows;

const DISPATCH_SUBMISSION_PAYLOAD_VERSION: i32 = 1;
const DISPATCH_SUBMISSION_RETENTION_MILLIS: i64 = 35 * 24 * 60 * 60 * 1_000;
const DISPATCH_SUBMISSION_MAX_BYTES: usize = 64 * 1024 * 1024;
const DISPATCH_MATERIALIZATION_LEASE_MILLIS: i64 = 15_000;
const DISPATCH_MATERIALIZATION_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);
const DISPATCH_MATERIALIZATION_RETRY_MIN_MILLIS: i64 = 5_000;
const DISPATCH_MATERIALIZATION_RETRY_MAX_MILLIS: i64 = 15_000;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct DurableDispatchSubmissionV1 {
    channel_id: [u8; 16],
    channel_id_text: String,
    sent_at: i64,
    delivery_id: String,
    op_id: String,
    dedupe_key: String,
    entity_type: String,
    entity_id: String,
    request: DispatchRequest,
    dispatch_targets: Vec<DispatchTarget>,
    private_enabled: bool,
    private_default_ttl_secs: i64,
    public_base_url: Option<String>,
    /// Optional supplemental event snapshot. Default keeps payload-v1 rows
    /// written before Live Activity durability readable during rolling repair.
    #[serde(default)]
    live_activity: Option<crate::delivery_core::execution::request::DispatchLiveActivityUpdate>,
}

impl From<CoreProviderDeliveryPath> for ProviderDeliveryPath {
    fn from(value: CoreProviderDeliveryPath) -> Self {
        match value {
            CoreProviderDeliveryPath::Direct => Self::Direct,
            CoreProviderDeliveryPath::WakeupPull => Self::WakeupPull,
        }
    }
}

impl From<ProviderPullTarget> for ProviderPullDelivery {
    fn from(value: ProviderPullTarget) -> Self {
        Self {
            device_id: value.device_id,
            platform: value.platform,
            provider_token: Arc::from(value.provider_token.into_boxed_str()),
            delivery_id: Arc::from(value.delivery_id.into_boxed_str()),
        }
    }
}

use private::enqueue_private_deliveries;
use provider::dispatch_provider_targets;
use tracing::{
    record_provider_cache_enqueue_failed, record_provider_enqueue_failed, record_provider_enqueued,
    record_provider_path_rejected,
};
use types::ResolvedProviderTarget;

struct ApiDispatchDelegate;

impl DispatchExecutionDelegate for ApiDispatchDelegate {
    type Error = Error;

    async fn execute(
        &self,
        prepared: &PreparedDispatch<'_>,
        progress: &mut DispatchProgress,
    ) -> Result<(), Self::Error> {
        // Materialization lanes are independent durability boundaries. A full
        // offline queue or a transient store error in one lane must not stop
        // healthy targets in later lanes from reaching their durable outbox.
        // The first error is still returned so the frozen submission remains
        // replayable for whichever lane did not materialize.
        let mut first_error = enqueue_private_deliveries(prepared, progress).await.err();
        if let Err(err) = dispatch_mqtt_receiver_targets(prepared, progress).await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
        if !prepared.provider_targets.is_empty() {
            let payloads = ProviderPayloads::build(prepared);
            if let Err(err) = dispatch_provider_targets(prepared, &payloads, progress).await
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        if let Err(err) = widgets::dispatch_widget_push_targets(prepared).await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn error_code(&self, err: &Self::Error) -> &'static str {
        dispatch_request_error_code(err)
    }
}

async fn dispatch_mqtt_receiver_targets(
    prepared: &PreparedDispatch<'_>,
    progress: &mut DispatchProgress,
) -> Result<(), Error> {
    if prepared.mqtt_receiver_targets.is_empty() {
        return Ok(());
    }
    let Some(private_state) = prepared.runtime.private_state() else {
        for _ in &prepared.mqtt_receiver_targets {
            progress.record_mqtt_failure();
        }
        return Err(Error::Internal(
            "frozen MQTT receiver dispatch requires the private runtime".to_string(),
        ));
    };
    execute_mqtt_receiver_deliveries(
        MqttReceiverDeliveryExecution {
            private_state,
            store: prepared.runtime.storage(),
            correlation_id: prepared.correlation_id.as_ref(),
            delivery_id: prepared.delivery_id.as_str(),
            channel_id: prepared.channel_id_value.as_str(),
            sent_at: prepared.sent_at,
            expires_at: prepared.provider_pull_expires_at(),
            targets: &prepared.mqtt_receiver_targets,
            payload: prepared.private_payload.clone(),
        },
        progress,
    )
    .await
}

impl From<DispatchExecutionError> for Error {
    fn from(value: DispatchExecutionError) -> Self {
        Error::Internal(value.message())
    }
}

impl DispatchExecutionRuntime for AppState {
    fn storage(&self) -> &crate::storage::Storage {
        &self.store
    }

    fn dispatch_channels(&self) -> &crate::dispatch::DispatchChannels {
        &self.dispatch
    }

    fn device_registry(&self) -> &crate::routing::DeviceRegistry {
        &self.device_registry
    }

    fn counter_sink(&self) -> &(dyn RuntimeCounterSink + Send + Sync) {
        self
    }

    fn private_state(&self) -> Option<&crate::private::PrivateState> {
        self.private.as_deref()
    }
}

impl RuntimeCounterSink for AppState {
    fn record(&self, _event: crate::delivery_core::store::counters::RuntimeCounterEvent) {}

    fn record_dispatch_counters(
        &self,
        channel_id: [u8; 16],
        occurred_at: i64,
        messages_routed: i64,
        deliveries_attempted: i64,
        provider_attempted: i64,
        provider_success: i64,
        provider_failed: i64,
        private_realtime_delivered: i64,
        device_stats: HashMap<Arc<str>, crate::runtime_counters::DeviceRuntimeCounterDelta>,
    ) {
        super::counters::emit_dispatch_counters(
            self,
            channel_id,
            occurred_at,
            messages_routed,
            deliveries_attempted,
            provider_attempted,
            provider_success,
            provider_failed,
            private_realtime_delivered,
            device_stats,
        );
    }
}

pub(crate) async fn dispatch_entity_notification(
    state: &AppState,
    channel_id: [u8; 16],
    mut request: DispatchRequest,
) -> Result<NotificationDispatchSummary, Error> {
    let live_activity = request.live_activity.take();
    let entity_kind = request.payload.kind();
    let entity_type = entity_kind.as_str();
    let entity_id = request.payload.entity_id().trim().to_string();
    let op_id = OpId::parse(&request.op_id)?.into_inner();
    request.op_id = op_id.clone();
    let request_fingerprint = request.request_fingerprint.clone();
    let channel_id_value = format_channel_id(&channel_id);
    let sent_at = Utc::now().timestamp_millis();
    let delivery_id = DeliveryId::reserve(state, sent_at).await?.into_inner();
    let dedupe_entity_id = if entity_kind == crate::delivery_core::payload::EntityKind::Message {
        "-"
    } else {
        entity_id.as_str()
    };
    let dedupe_key = SemanticScope::new(&channel_id_value, entity_type, dedupe_entity_id)
        .op_dedupe_key(&OpId::parse(&op_id)?);
    let dispatch_targets = state
        .store
        .list_channel_dispatch_targets(channel_id, sent_at)
        .await?;
    let private_enabled = state.private_channel_enabled && state.private.is_some();
    let private_default_ttl_secs = state
        .private
        .as_ref()
        .map(|private| private.config.default_ttl_secs)
        .unwrap_or(MAX_PROVIDER_TTL_SECONDS)
        .clamp(0, MAX_PROVIDER_TTL_SECONDS);
    let submission = DurableDispatchSubmissionV1 {
        channel_id,
        channel_id_text: channel_id_value.clone(),
        sent_at,
        delivery_id: delivery_id.clone(),
        op_id: op_id.clone(),
        dedupe_key: dedupe_key.clone(),
        entity_type: entity_type.to_string(),
        entity_id,
        request,
        dispatch_targets,
        private_enabled,
        private_default_ttl_secs,
        public_base_url: state.public_base_url.as_deref().map(ToString::to_string),
        live_activity,
    };
    let payload_blob = serde_json::to_vec(&submission)
        .map_err(|err| Error::Internal(format!("encode dispatch submission: {err}")))?;
    if payload_blob.len() > DISPATCH_SUBMISSION_MAX_BYTES {
        return Err(Error::TooBusy);
    }
    let submission_record = DispatchSubmissionRecord {
        dedupe_key: dedupe_key.clone(),
        delivery_id: delivery_id.clone(),
        op_id: op_id.clone(),
        payload_version: DISPATCH_SUBMISSION_PAYLOAD_VERSION,
        payload_blob,
        acceptance_order: 0,
        accepted_at: sent_at,
        expires_at: sent_at.saturating_add(DISPATCH_SUBMISSION_RETENTION_MILLIS),
    };
    let op_guard = match DispatchOpGuard::begin_submission(
        state,
        &submission_record,
        request_fingerprint.as_deref(),
        channel_id_value.clone(),
        op_id.clone(),
    )
    .await?
    {
        DispatchOpGuardStart::Complete(summary) => return Ok(summary),
        DispatchOpGuardStart::Proceed(guard) => guard,
    };
    let acceptance_order = op_guard.acceptance_order();
    if acceptance_order <= 0 {
        return Err(Error::Internal(
            "committed dispatch submission order is missing".into(),
        ));
    }

    let owned_state = state.clone();
    match await_owned_dispatch_lifecycle(async move {
        execute_committed_submission(&owned_state, submission, acceptance_order, op_guard).await
    })
    .await
    {
        Ok(summary) => Ok(summary),
        Err(err) => {
            // The manifest was committed atomically with the dedupe identity
            // before materialization began. Report durable acceptance and keep
            // sender status at `processing`; returning a generic failure here
            // would invite a new op_id while recovery still owns this delivery.
            if is_expected_capacity_deferral(&err) || matches!(err, Error::TooBusy) {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::DEBUG,
                    event = "dispatch.submission_materialization_deferred",
                    delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                    reason = %(dispatch_request_error_code(&err))
                );
            } else {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "dispatch.submission_materialization_deferred",
                    delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                    error = %(err.to_string())
                );
            }
            Ok(NotificationDispatchSummary::new(
                channel_id_value,
                op_id,
                delivery_id,
                crate::delivery_core::response::DeliveryDedupeStatus::New,
                crate::delivery_core::response::DeliveryDispatchStatus::MaterializationPending,
            ))
        }
    }
}

async fn execute_committed_submission(
    state: &AppState,
    submission: DurableDispatchSubmissionV1,
    acceptance_order: i64,
    op_guard: DispatchOpGuard,
) -> Result<NotificationDispatchSummary, Error> {
    let materialization_dedupe_key = submission.dedupe_key.clone();
    let materialization_delivery_id = submission.delivery_id.clone();
    let materialization_accepted_at = submission.sent_at;
    let private_capacity_epoch = state.store.private_capacity_epoch();
    let mut private_capacity_devices = submission
        .dispatch_targets
        .iter()
        .filter_map(|target| match target {
            DispatchTarget::Private { device_id, .. } => Some(*device_id),
            DispatchTarget::Provider { .. } => None,
        })
        .collect::<Vec<_>>();
    private_capacity_devices.sort_unstable();
    private_capacity_devices.dedup();
    let materialization_owner = format!(
        "gateway:{}:materializer:{}",
        std::process::id(),
        crate::util::generate_hex_id_128()
    );
    let claim_now = Utc::now().timestamp_millis();
    let claimed = state
        .store
        .claim_dispatch_submission_materialization(
            &materialization_dedupe_key,
            &materialization_delivery_id,
            &materialization_owner,
            claim_now,
            claim_now.saturating_add(DISPATCH_MATERIALIZATION_LEASE_MILLIS),
        )
        .await?;
    if !claimed {
        return Err(Error::TooBusy);
    }
    let entity_type = match submission.entity_type.as_str() {
        "message" => "message",
        "event" => "event",
        "thing" => "thing",
        _ => {
            return Err(Error::Internal(
                "unknown dispatch submission entity type".into(),
            ));
        }
    };
    let provider_outcome = Arc::new(ProviderDispatchOutcome::new(
        Arc::from(submission.op_id.clone().into_boxed_str()),
        Arc::from(submission.dedupe_key.clone().into_boxed_str()),
        Arc::from(submission.delivery_id.clone().into_boxed_str()),
    ));
    let mut provider_lease = ProviderDispatchOutcomeLease::new(Arc::clone(&provider_outcome));
    let live_activity = submission.live_activity.clone();
    let mut dispatch_future = Box::pin(async {
        let core_result = execute_dispatch(
            state,
            DispatchExecutionInput {
                channel_id: submission.channel_id,
                channel_id_text: submission.channel_id_text,
                sent_at: submission.sent_at,
                acceptance_order,
                delivery_id: submission.delivery_id,
                op_id: submission.op_id,
                entity_type,
                entity_id: submission.entity_id,
                request: submission.request,
                dispatch_targets: submission.dispatch_targets,
                private_enabled: submission.private_enabled,
                private_default_ttl_secs: submission.private_default_ttl_secs,
                public_base_url: submission.public_base_url,
                provider_outcome: Arc::clone(&provider_outcome),
            },
            ApiDispatchDelegate,
        )
        .await;
        let activity_result = match live_activity {
            Some(update) => {
                dispatch_event_activity_update(
                    state.clone(),
                    update,
                    acceptance_order,
                    materialization_delivery_id.as_str(),
                )
                .await
            }
            None => Ok(()),
        };
        match (core_result, activity_result) {
            (Ok(summary), Ok(())) => Ok(summary),
            (Err(err), Ok(())) => Err(err),
            (Ok(_), Err(err)) => Err(err),
            (Err(primary), Err(activity)) => {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "dispatch.live_activity_materialization_deferred",
                    delivery_id = %(crate::util::redact_text(materialization_delivery_id.as_str())),
                    error = %(activity.to_string())
                );
                Err(primary)
            }
        }
    });
    let mut heartbeat = tokio::time::interval(DISPATCH_MATERIALIZATION_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;
    let dispatch_result = loop {
        tokio::select! {
            result = &mut dispatch_future => break result,
            _ = heartbeat.tick() => {
                let now = Utc::now().timestamp_millis();
                match state.store.renew_dispatch_submission_materialization(
                    &materialization_dedupe_key,
                    &materialization_delivery_id,
                    &materialization_owner,
                    now,
                    now.saturating_add(DISPATCH_MATERIALIZATION_LEASE_MILLIS),
                ).await {
                    Ok(true) => {}
                    Ok(false) => break Err(Error::Internal(
                        "dispatch materialization lease was lost".to_string(),
                    )),
                    Err(err) => break Err(Error::StoreError(err)),
                }
            }
        }
    };

    // Provider jobs are independently durable and may be sent as soon as all
    // provider targets that could be reached in this pass have been written.
    // Do not hold healthy APNs/FCM/WNS work behind an unrelated private/MQTT/
    // widget materialization failure. The operation itself remains pending
    // until every lane succeeds, so replay can fill any missing durable rows.
    let activation_result = state
        .store
        .activate_provider_dispatch_jobs(
            provider_outcome.delivery_id(),
            Utc::now().timestamp_millis(),
        )
        .await;
    let dispatch_result = match (dispatch_result, activation_result) {
        (Ok(summary), Ok(_)) => Ok(summary),
        (Ok(_), Err(err)) => Err(Error::StoreError(err)),
        (Err(err), Ok(_)) => Err(err),
        (Err(primary), Err(activation)) => {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "dispatch.provider_outbox_activation_deferred",
                delivery_id = %(crate::util::redact_text(provider_outcome.delivery_id())),
                error = %(activation.to_string())
            );
            Err(primary)
        }
    };

    // SQLite keeps dispatch durability in a sidecar database, so the sender
    // projection cannot share the dedupe transaction. Advance the projection
    // first: if it fails, the frozen submission remains pending; if the process
    // dies before dedupe finalization, replay is safe and idempotent. The
    // inverse order could leave a terminal submission permanently reported as
    // `processing` because finalized manifests are not replay candidates.
    let dispatch_result = match dispatch_result {
        Ok(summary) => {
            match state
                .store
                .update_sender_submit_status(
                    summary.op_id.as_str(),
                    sender_status_from_dispatch(summary.dispatch_status),
                    Some(summary.dispatch_status.as_str()),
                    Utc::now().timestamp_millis(),
                )
                .await
            {
                Ok(()) => Ok(summary),
                Err(err) => Err(Error::StoreError(err)),
            }
        }
        Err(err) => Err(err),
    };

    let result = match op_guard.finish_submission(state, dispatch_result).await {
        Ok(summary) => {
            let volatile_terminal = provider_lease.commit();
            let terminal = match volatile_terminal {
                Some(success) => Some(success),
                None => match state
                    .store
                    .provider_dispatch_terminal_success(provider_outcome.delivery_id())
                    .await
                {
                    Ok(terminal) => terminal,
                    Err(err) => {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "dispatch.provider_terminal_reconciliation_deferred",
                            delivery_id = %(crate::util::redact_text(provider_outcome.delivery_id())),
                            error = %(err.to_string())
                        );
                        None
                    }
                },
            };
            if let Some(success) = terminal {
                state
                    .store
                    .finalize_provider_dispatch_outcome_durably(
                        provider_outcome.dedupe_key(),
                        provider_outcome.op_id(),
                        provider_outcome.delivery_id(),
                        success,
                    )
                    .await;
            }
            Ok(summary)
        }
        Err(err) => {
            // The frozen submission remains pending. Cancelling only the
            // volatile outcome releases any waiting hint workers. Provider
            // rows already activated in the independent durable lane remain
            // sendable; missing target rows are filled by replay.
            provider_lease.cancel();
            Err(err)
        }
    };
    if result.is_ok() {
        state
            .store
            .clear_private_capacity_blocked_submission(&materialization_dedupe_key);
    } else if let Err(err) = result.as_ref() {
        let now = Utc::now().timestamp_millis();
        let retry_delay = materialization_retry_delay_millis(
            &materialization_delivery_id,
            now.saturating_sub(materialization_accepted_at),
        );
        // Keep the fenced owner until a short, jittered retry deadline rather
        // than immediately making every blocked manifest eligible. At the
        // hard capacity this prevents a 10k-row retry/write/log storm while
        // preserving a sub-20-second recovery bound after space is freed.
        let renewed = state
            .store
            .renew_dispatch_submission_materialization(
                &materialization_dedupe_key,
                &materialization_delivery_id,
                &materialization_owner,
                now,
                now.saturating_add(retry_delay),
            )
            .await
            .unwrap_or(false);
        if renewed && is_private_capacity_deferral(err) && !private_capacity_devices.is_empty() {
            state.store.register_private_capacity_blocked_submission(
                &materialization_dedupe_key,
                &materialization_delivery_id,
                &materialization_owner,
                &private_capacity_devices,
            );
            // Close the narrow race where an ACK commits after the failed
            // capacity check but before this submission enters the in-memory
            // targeted index. The database lease remains the arbiter.
            if state.store.private_capacity_epoch() != private_capacity_epoch {
                let _ = state
                    .store
                    .expedite_private_capacity_recovery(
                        private_capacity_devices.first().copied(),
                        1,
                    )
                    .await;
            }
        } else {
            state
                .store
                .clear_private_capacity_blocked_submission(&materialization_dedupe_key);
        }
    }
    result
}

pub(crate) async fn recover_pending_dispatch_submissions(state: &AppState) -> Result<usize, Error> {
    recover_pending_dispatch_submissions_before(state, i64::MAX).await
}

pub(crate) async fn recover_pending_dispatch_submissions_before(
    state: &AppState,
    accepted_before: i64,
) -> Result<usize, Error> {
    let now = Utc::now().timestamp_millis();
    let records = state
        .store
        .list_pending_dispatch_submissions(10_000, now)
        .await?;
    let mut recovered = 0usize;
    for record in records {
        if record.accepted_at > accepted_before {
            continue;
        }
        if record.payload_version != DISPATCH_SUBMISSION_PAYLOAD_VERSION {
            let terminalized = state
                .store
                .terminalize_unrecoverable_dispatch_submission(
                    &record,
                    "unrecoverable_unknown_payload_version",
                    now,
                )
                .await?;
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "dispatch.submission_recovery_blocked",
                delivery_id = %(crate::util::redact_text(record.delivery_id.as_str())),
                submission_schema_version = (record.payload_version as i64),
                reason = %("unknown_payload_version"),
                terminalized = (terminalized)
            );
            state
                .store
                .clear_private_capacity_blocked_submission(record.dedupe_key.as_str());
            continue;
        }
        let submission: DurableDispatchSubmissionV1 =
            match serde_json::from_slice(record.payload_blob.as_slice()) {
                Ok(value) => value,
                Err(err) => {
                    let terminalized = state
                        .store
                        .terminalize_unrecoverable_dispatch_submission(
                            &record,
                            "unrecoverable_payload_decode_failed",
                            now,
                        )
                        .await?;
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::ERROR,
                        event = "dispatch.submission_recovery_blocked",
                        delivery_id = %(crate::util::redact_text(record.delivery_id.as_str())),
                        reason = %("decode_failed"),
                        error = %(err.to_string()),
                        terminalized = (terminalized)
                    );
                    state
                        .store
                        .clear_private_capacity_blocked_submission(record.dedupe_key.as_str());
                    continue;
                }
            };
        if submission.delivery_id != record.delivery_id
            || submission.op_id != record.op_id
            || submission.dedupe_key != record.dedupe_key
            || submission.sent_at != record.accepted_at
        {
            let terminalized = state
                .store
                .terminalize_unrecoverable_dispatch_submission(
                    &record,
                    "unrecoverable_identity_mismatch",
                    now,
                )
                .await?;
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "dispatch.submission_recovery_blocked",
                delivery_id = %(crate::util::redact_text(record.delivery_id.as_str())),
                reason = %("identity_mismatch"),
                terminalized = (terminalized)
            );
            state
                .store
                .clear_private_capacity_blocked_submission(record.dedupe_key.as_str());
            continue;
        }
        let guard = DispatchOpGuard::resume_submission(
            record.dedupe_key.clone(),
            record.delivery_id.clone(),
        );
        match execute_committed_submission(state, submission, record.acceptance_order, guard).await
        {
            Ok(_) => recovered = recovered.saturating_add(1),
            Err(err) => {
                if is_expected_capacity_deferral(&err) || matches!(err, Error::TooBusy) {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::DEBUG,
                        event = "dispatch.submission_recovery_deferred",
                        delivery_id = %(crate::util::redact_text(record.delivery_id.as_str())),
                        reason = %(dispatch_request_error_code(&err))
                    );
                } else {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "dispatch.submission_recovery_deferred",
                        delivery_id = %(crate::util::redact_text(record.delivery_id.as_str())),
                        error = %(err.to_string())
                    );
                }
            }
        }
    }
    Ok(recovered)
}

async fn await_owned_dispatch_lifecycle<T, F>(lifecycle: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: Future<Output = Result<T, Error>> + Send + 'static,
{
    let lifecycle_span = ::tracing::Span::current();
    tokio::spawn(lifecycle.instrument(lifecycle_span))
        .await
        .map_err(|err| {
            Error::Internal(format!(
                "owned dispatch lifecycle task failed before completion: {err}"
            ))
        })?
}

fn dispatch_request_error_code(err: &Error) -> &'static str {
    match err {
        Error::Validation { .. } => "validation",
        Error::Conflict { .. } => "conflict",
        Error::Unauthorized => "unauthorized",
        Error::Upstream { .. } => "upstream",
        Error::Internal(_) => "internal",
        Error::TooBusy => "too_busy",
        Error::RateLimited => "rate_limited",
        Error::StoreError(crate::storage::StoreError::PrivateOutboxCapacityExceeded { .. }) => {
            "private_outbox_capacity"
        }
        Error::StoreError(_) => "store_error",
    }
}

fn is_expected_capacity_deferral(err: &Error) -> bool {
    matches!(
        err,
        Error::StoreError(crate::storage::StoreError::PrivateOutboxCapacityExceeded { .. })
    )
}

fn is_private_capacity_deferral(err: &Error) -> bool {
    matches!(err, Error::TooBusy) || is_expected_capacity_deferral(err)
}

fn materialization_retry_delay_millis(delivery_id: &str, elapsed_millis: i64) -> i64 {
    let base = if elapsed_millis < 10_000 {
        DISPATCH_MATERIALIZATION_RETRY_MIN_MILLIS
    } else if elapsed_millis < 60_000 {
        10_000
    } else {
        DISPATCH_MATERIALIZATION_RETRY_MAX_MILLIS
    };
    let jitter = i64::from(blake3::hash(delivery_id.as_bytes()).as_bytes()[0]) * base / 1_024;
    base.saturating_add(jitter)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{
        DISPATCH_MATERIALIZATION_RETRY_MAX_MILLIS, DISPATCH_MATERIALIZATION_RETRY_MIN_MILLIS,
        DurableDispatchSubmissionV1, await_owned_dispatch_lifecycle,
        materialization_retry_delay_millis,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    #[tokio::test]
    async fn aborting_request_waiter_does_not_cancel_owned_dispatch_lifecycle() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let lifecycle_completed = Arc::clone(&completed);
        let request_waiter = tokio::spawn(async move {
            await_owned_dispatch_lifecycle(async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                lifecycle_completed.store(true, Ordering::Release);
                Ok(())
            })
            .await
        });

        started_rx
            .await
            .expect("owned lifecycle should start before request cancellation");
        request_waiter.abort();
        let _ = request_waiter.await;
        let _ = release_tx.send(());

        tokio::time::timeout(Duration::from_millis(250), async {
            while !completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned lifecycle must complete after its request waiter is aborted");
    }

    #[test]
    fn materialization_retry_is_prompt_bounded_and_deterministically_jittered() {
        let first = materialization_retry_delay_millis("delivery-a", 0);
        let repeated = materialization_retry_delay_millis("delivery-a", 0);
        let aged = materialization_retry_delay_millis("delivery-a", 120_000);
        assert_eq!(first, repeated);
        assert!(first >= DISPATCH_MATERIALIZATION_RETRY_MIN_MILLIS);
        assert!(first < DISPATCH_MATERIALIZATION_RETRY_MIN_MILLIS * 5 / 4);
        assert!(aged >= DISPATCH_MATERIALIZATION_RETRY_MAX_MILLIS);
        assert!(aged < DISPATCH_MATERIALIZATION_RETRY_MAX_MILLIS * 5 / 4);
    }

    #[test]
    fn payload_v1_without_live_activity_field_remains_readable() {
        let request = crate::delivery_core::execution::request::DispatchRequest::new(
            "op-old".to_string(),
            None,
            1_700_000_000_000,
            crate::delivery_core::execution::request::DispatchAlert::new(
                Some("old event".to_string()),
                None,
                None,
                None,
            ),
            crate::delivery_core::execution::request::DispatchEntityPayload::event(
                "event-old".to_string(),
                hashbrown::HashMap::new(),
                hashbrown::HashMap::new(),
            ),
            crate::domain_model::projection::DomainDeliveryPolicy::fanout_default(),
        );
        let submission = DurableDispatchSubmissionV1 {
            channel_id: [0; 16],
            channel_id_text: "00000000-0000-0000-0000-000000000000".to_string(),
            sent_at: 1_700_000_000_001,
            delivery_id: "delivery-old".to_string(),
            op_id: "op-old".to_string(),
            dedupe_key: "dedupe-old".to_string(),
            entity_type: "event".to_string(),
            entity_id: "event-old".to_string(),
            request,
            dispatch_targets: Vec::new(),
            private_enabled: false,
            private_default_ttl_secs: 3_600,
            public_base_url: None,
            live_activity: None,
        };
        let mut old_payload = serde_json::to_value(submission).expect("payload should encode");
        old_payload
            .as_object_mut()
            .expect("submission should be an object")
            .remove("live_activity");
        let decoded: DurableDispatchSubmissionV1 =
            serde_json::from_value(old_payload).expect("old payload-v1 should decode");
        assert!(decoded.live_activity.is_none());
    }
}
