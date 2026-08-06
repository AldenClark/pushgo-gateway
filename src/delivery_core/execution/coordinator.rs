use std::sync::Arc;

use ::tracing::Instrument;
use hashbrown::HashMap;

use crate::{
    delivery_core::{
        execution::{
            mqtt_receiver::MqttReceiverExecutionTarget,
            prepare::{
                DispatchPreparationError, DispatchPreparationErrorKind, DispatchPreparationInput,
                prepare_dispatch_core,
            },
            private::PrivateExecutionTarget,
            progress::DispatchProgress,
            provider::{
                ProviderExecutionTarget, ProviderPayloadSet, ProviderPayloadSetInput,
                build_provider_payload_set,
            },
            request::DispatchRequest,
        },
        payload::{MAX_PROVIDER_TTL_SECONDS, NotificationSeverity},
        planning::plan::DeliveryPlan,
        response::{DeliveryDedupeStatus, DeliveryDispatchStatus, DeliverySummary},
        store::{channel::ChannelStore, counters::RuntimeCounterSink},
    },
    dispatch::{DispatchChannels, ProviderDispatchOutcome},
    private::PrivateState,
    routing::DeviceRegistry,
    storage::{Storage, StoreError},
    util::generate_hex_id_128,
};

pub(crate) trait DispatchExecutionRuntime: Send + Sync {
    fn channel_store(&self) -> &(dyn ChannelStore + Send + Sync);

    fn storage(&self) -> &Storage;

    fn dispatch_channels(&self) -> &DispatchChannels;

    fn device_registry(&self) -> &DeviceRegistry;

    fn counter_sink(&self) -> &(dyn RuntimeCounterSink + Send + Sync);

    fn private_state(&self) -> Option<&PrivateState>;

    fn private_channel_enabled(&self) -> bool;

    fn public_base_url(&self) -> Option<&str>;
}

pub(crate) trait DispatchExecutionDelegate {
    type Error;

    fn execute(
        &self,
        prepared: &PreparedDispatch<'_>,
        progress: &mut DispatchProgress,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    fn error_code(&self, err: &Self::Error) -> &'static str;
}

pub(crate) struct DispatchExecutionInput {
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_text: String,
    pub(crate) sent_at: i64,
    pub(crate) delivery_id: String,
    pub(crate) op_id: String,
    pub(crate) entity_type: &'static str,
    pub(crate) entity_id: String,
    pub(crate) request: DispatchRequest,
    pub(crate) provider_outcome: Arc<ProviderDispatchOutcome>,
}

pub(crate) struct PreparedDispatch<'a> {
    pub(crate) runtime: &'a dyn DispatchExecutionRuntime,
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_value: String,
    pub(crate) entity_type: &'static str,
    pub(crate) op_id: String,
    pub(crate) delivery_id: String,
    pub(crate) delivery_id_ref: Arc<str>,
    pub(crate) correlation_id: Arc<str>,
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
    pub(crate) provider_outcome: Arc<ProviderDispatchOutcome>,
    pub(crate) mqtt_receiver_targets: Vec<MqttReceiverExecutionTarget>,
    pub(crate) private_dispatch: Option<PrivateDispatchContext<'a>>,
    pub(crate) plan: DeliveryPlan,
    pub(crate) apple_thread_id: String,
    pub(crate) provider_fallback_body: Option<String>,
}

pub(crate) struct PrivateDispatchContext<'a> {
    pub(crate) state: &'a PrivateState,
    pub(crate) targets: Vec<PrivateExecutionTarget>,
}

pub(crate) type ProviderPayloads = ProviderPayloadSet;

impl<'a> PreparedDispatch<'a> {
    async fn build(
        runtime: &'a dyn DispatchExecutionRuntime,
        request: DispatchRequest,
        context: DispatchBuildContext,
    ) -> Result<Self, DispatchExecutionError> {
        let DispatchRequest {
            op_id,
            request_fingerprint: _,
            occurred_at,
            alert,
            payload,
            delivery_policy,
        } = request;
        let DispatchBuildContext {
            channel_id,
            channel_id_value,
            sent_at,
            delivery_id,
            correlation_id,
            delivery_id_ref,
            entity_type,
            provider_outcome,
        } = context;
        let dispatch_targets = runtime
            .channel_store()
            .list_channel_dispatch_targets(channel_id, sent_at)
            .await
            .inspect_err(|err| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "dispatch.list_channel_targets_failed",
                    channel_id = %(crate::util::redact_text(channel_id_value.as_str())),
                    op_id = %(crate::util::redact_text(op_id.as_str())),
                    correlation_id = %(crate::util::redact_text(correlation_id.as_ref())),
                    delivery_id = %(crate::util::redact_text(delivery_id_ref.as_ref())),
                    error = %(err.to_string())
                );
            })?;

        let private_state = runtime.private_state();
        let private_enabled = runtime.private_channel_enabled() && private_state.is_some();
        let private_default_ttl_secs = private_state
            .map(|private| private.config.default_ttl_secs)
            .unwrap_or(MAX_PROVIDER_TTL_SECONDS)
            .clamp(0, MAX_PROVIDER_TTL_SECONDS);
        let prepared_core = prepare_dispatch_core(DispatchPreparationInput {
            channel_id: channel_id_value.clone(),
            op_id,
            delivery_id,
            correlation_id: correlation_id.to_string(),
            sent_at,
            occurred_at,
            alert,
            payload,
            delivery_policy,
            dispatch_targets,
            private_enabled,
            private_default_ttl_secs,
            public_base_url: runtime.public_base_url().map(ToString::to_string),
        })?;
        let private_dispatch =
            private_state
                .filter(|_| private_enabled)
                .map(|state| PrivateDispatchContext {
                    state,
                    targets: prepared_core.private_targets,
                });

        provider_outcome.configure(
            prepared_core
                .provider_targets
                .len()
                .saturating_add(prepared_core.provider_preparation_failed.max(0) as usize),
            prepared_core.provider_preparation_failed.max(0) as usize,
        );

        Ok(Self {
            runtime,
            channel_id,
            channel_id_value: prepared_core.channel_id,
            entity_type,
            op_id: prepared_core.op_id,
            delivery_id: prepared_core.delivery_id,
            delivery_id_ref,
            correlation_id: Arc::from(prepared_core.correlation_id.into_boxed_str()),
            sent_at: prepared_core.sent_at,
            resolved_title: prepared_core.resolved_title,
            resolved_body: prepared_core.resolved_body,
            severity: prepared_core.severity,
            effective_ttl: prepared_core.effective_ttl,
            ttl_seconds: prepared_core.ttl_seconds,
            private_default_ttl_secs: prepared_core.private_default_ttl_secs,
            private_payload: prepared_core.private_payload,
            wakeup_data: prepared_core.wakeup_data,
            custom_data: prepared_core.custom_data,
            provider_targets: prepared_core.provider_targets,
            provider_preparation_failed: prepared_core.provider_preparation_failed,
            provider_outcome,
            mqtt_receiver_targets: prepared_core.mqtt_receiver_targets,
            private_dispatch,
            plan: prepared_core.plan,
            apple_thread_id: prepared_core.apple_thread_id,
            provider_fallback_body: prepared_core.provider_fallback_body,
        })
    }

    pub(crate) fn provider_pull_expires_at(&self) -> i64 {
        self.effective_ttl
            .unwrap_or(self.sent_at + self.private_default_ttl_secs * 1000)
    }

    fn emit_counters(&self, progress: DispatchProgress) -> DeliverySummary {
        let mqtt_attempted = progress
            .mqtt_delivered
            .len()
            .saturating_add(progress.mqtt_failed) as i64;
        let provider_attempted = progress
            .provider_attempted
            .saturating_add(self.provider_preparation_failed);
        let provider_failed = progress
            .provider_failed
            .saturating_add(self.provider_preparation_failed);
        let deliveries_attempted = (progress.private_enqueue_stats.attempted as i64)
            .saturating_add(mqtt_attempted)
            .saturating_add(provider_attempted);
        self.runtime.counter_sink().record_dispatch_counters(
            self.channel_id,
            self.sent_at,
            1,
            deliveries_attempted,
            provider_attempted,
            0,
            provider_failed,
            progress.private_realtime_delivered.len() as i64,
            progress.device_stats.clone(),
        );

        let has_dispatch_attempt = !progress.private_enqueued.is_empty()
            || !progress.mqtt_delivered.is_empty()
            || progress.mqtt_failed > 0
            || progress.provider_attempted > 0
            || self.provider_preparation_failed > 0;
        let partial_failure = progress.rejected > 0
            || progress.private_enqueue_stats.has_failures()
            || progress.mqtt_failed > 0
            || self.provider_preparation_failed > 0;
        DeliverySummary::new(
            self.channel_id_value.clone(),
            self.op_id.clone(),
            self.delivery_id.clone(),
            DeliveryDedupeStatus::New,
            DeliveryDispatchStatus::from_execution(
                has_dispatch_attempt,
                progress.provider_queued > 0,
                partial_failure,
                progress.private_enqueue_stats.is_too_busy(),
            ),
        )
    }
}

struct DispatchBuildContext {
    channel_id: [u8; 16],
    channel_id_value: String,
    sent_at: i64,
    delivery_id: String,
    correlation_id: Arc<str>,
    delivery_id_ref: Arc<str>,
    entity_type: &'static str,
    provider_outcome: Arc<ProviderDispatchOutcome>,
}

impl ProviderPayloads {
    pub(crate) fn build(prepared: &PreparedDispatch<'_>) -> Self {
        build_provider_payload_set(ProviderPayloadSetInput {
            targets: &prepared.provider_targets,
            resolved_title: prepared.resolved_title.clone(),
            resolved_body: prepared.resolved_body.clone(),
            fallback_body: prepared.provider_fallback_body.clone(),
            apple_thread_id: prepared.apple_thread_id.clone(),
            severity: prepared.severity,
            effective_ttl: prepared.effective_ttl,
            ttl_seconds: prepared.ttl_seconds,
            custom_data: Arc::clone(&prepared.custom_data),
            wakeup_data: Arc::clone(&prepared.wakeup_data),
            delivery_id: prepared.delivery_id.clone(),
        })
    }
}

pub(crate) async fn execute_dispatch<D>(
    runtime: &dyn DispatchExecutionRuntime,
    input: DispatchExecutionInput,
    delegate: D,
) -> Result<DeliverySummary, D::Error>
where
    D: DispatchExecutionDelegate,
    D::Error: From<DispatchExecutionError>,
{
    let DispatchExecutionInput {
        channel_id,
        channel_id_text,
        sent_at,
        delivery_id,
        op_id,
        entity_type,
        entity_id,
        request,
        provider_outcome,
    } = input;
    let trace_id = generate_hex_id_128();
    let correlation_id = Arc::<str>::from(trace_id.into_boxed_str());
    let delivery_id_ref = Arc::<str>::from(delivery_id.clone().into_boxed_str());
    let trace_channel_id = channel_id_text.clone();
    let trace_op_id = op_id.clone();

    let dispatch_span = ::tracing::info_span!(
        "gateway.dispatch.request",
        correlation_id = %crate::util::redact_text(correlation_id.as_ref()),
        delivery_id = %crate::util::redact_text(delivery_id_ref.as_ref()),
        channel_id = %crate::util::redact_text(trace_channel_id.as_str()),
        op_id = %crate::util::redact_text(trace_op_id.as_str()),
        entity_type = %entity_type,
        entity_id = %crate::util::redact_text(entity_id.as_str())
    );
    let dispatch_result = async {
        let prepared = PreparedDispatch::build(
            runtime,
            request,
            DispatchBuildContext {
                channel_id,
                channel_id_value: channel_id_text,
                sent_at,
                delivery_id,
                correlation_id: Arc::clone(&correlation_id),
                delivery_id_ref: Arc::clone(&delivery_id_ref),
                entity_type,
                provider_outcome,
            },
        )
        .await?;
        emit_dispatch_request_started(&prepared);
        let mut progress = DispatchProgress::default();
        delegate.execute(&prepared, &mut progress).await?;
        let summary = prepared.emit_counters(progress);
        emit_dispatch_request_finished(&prepared, &summary);
        Ok(summary)
    }
    .instrument(dispatch_span)
    .await;

    if let Err(err) = dispatch_result.as_ref() {
        emit_dispatch_request_failed(
            &delegate,
            correlation_id.as_ref(),
            delivery_id_ref.as_ref(),
            trace_channel_id.as_str(),
            trace_op_id.as_str(),
            err,
        );
    }
    dispatch_result
}

fn emit_dispatch_request_started(prepared: &PreparedDispatch<'_>) {
    let private_targets = prepared
        .private_dispatch
        .as_ref()
        .map_or(0usize, |private| private.targets.len());
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.request_started",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        op_id = %(crate::util::redact_text(prepared.op_id.as_str())),
        severity = %(prepared.severity.as_str()),
        provider_targets = (prepared.provider_targets.len() as u64),
        private_targets = (private_targets as u64),
        mqtt_receiver_targets = (prepared.mqtt_receiver_targets.len() as u64),
        plan_targets = (prepared.plan.targets.len() as u64),
        plan_skips = (prepared.plan.skips.len() as u64),
        private_enabled = (private_targets > 0),
        provider_enabled = (!prepared.provider_targets.is_empty())
    );
}

fn emit_dispatch_request_finished(prepared: &PreparedDispatch<'_>, summary: &DeliverySummary) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.request_finished",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(summary.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(summary.channel_id.as_str())),
        op_id = %(crate::util::redact_text(summary.op_id.as_str())),
        partial_failure = (summary.partial_failure),
        private_enqueue_too_busy = (summary.private_enqueue_too_busy),
        has_dispatch_attempt = (summary.has_dispatch_attempt),
        dispatch_status = %(summary.dispatch_status.as_str())
    );
}

fn emit_dispatch_request_failed<D>(
    delegate: &D,
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    op_id: &str,
    err: &D::Error,
) where
    D: DispatchExecutionDelegate,
{
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "dispatch.request_failed",
        correlation_id = %(crate::util::redact_text(correlation_id)),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        channel_id = %(crate::util::redact_text(channel_id)),
        op_id = %(crate::util::redact_text(op_id)),
        error_code = %(delegate.error_code(err))
    );
}

pub(crate) struct DispatchExecutionError {
    message: String,
}

impl DispatchExecutionError {
    pub(crate) fn message(self) -> String {
        self.message
    }
}

impl From<StoreError> for DispatchExecutionError {
    fn from(value: StoreError) -> Self {
        Self {
            message: value.to_string(),
        }
    }
}

impl From<DispatchPreparationError> for DispatchExecutionError {
    fn from(value: DispatchPreparationError) -> Self {
        let _kind = match value.kind {
            DispatchPreparationErrorKind::PrivatePayloadEncodeFailed => "internal",
        };
        Self {
            message: value.message,
        }
    }
}
