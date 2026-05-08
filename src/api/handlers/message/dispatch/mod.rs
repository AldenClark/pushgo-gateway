use std::{borrow::Cow, collections::HashSet, sync::Arc};

use ::tracing::Instrument;
use chrono::Utc;
use hashbrown::HashMap;

use crate::{
    api::{Error, format_channel_id},
    app::AppState,
    dispatch::{DispatchError, ProviderDeliveryPath, ProviderPullDelivery},
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    stats::DeviceDispatchDelta,
    storage::{DeviceId, DeviceInfo, DispatchTarget, Platform},
    util::{SharedStringMap, encode_lower_hex_128, generate_hex_id_128},
};

use super::{
    ids::{DeliveryId, OpId, SemanticScope, wakeup_data_with_delivery_id},
    payload::{
        CustomPayloadData, EntityKind, MAX_PROVIDER_TTL_MILLIS, MAX_PROVIDER_TTL_SECONDS,
        NotificationSeverity, OptionalText, PAYLOAD_VERSION, ProviderDeliverySelection,
        ProviderRouteBinding, ProviderTtl, SCHEMA_VERSION, StandardFields,
    },
    stats::{PrivateEnqueueStats, emit_dispatch_stats, merge_device_dispatch_delta},
};
use crate::api::handlers::dispatch_lifecycle::{
    DispatchOpGuard, DispatchOpGuardStart, NotificationDispatchSummary,
};
use crate::api::handlers::watch_light::quantize_watch_payload;

mod android;
mod apple;
mod private;
mod provider;
mod tracing;
mod types;
mod windows;

use private::enqueue_private_deliveries;
use provider::dispatch_provider_devices;
use tracing::{
    record_provider_cache_enqueue_failed, record_provider_enqueue_failed, record_provider_enqueued,
    record_provider_path_rejected,
};
use types::{DispatchProgress, PreparedDispatch, ProviderPayloads, ResolvedProviderTarget};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_entity_notification(
    state: &AppState,
    channel_id: [u8; 16],
    op_id: String,
    occurred_at: i64,
    title: Option<String>,
    body: Option<String>,
    severity: Option<String>,
    ttl: Option<i64>,
    custom_data: HashMap<String, String>,
    entity_type: &str,
    entity_id: &str,
    extra_fields: HashMap<String, String>,
) -> Result<NotificationDispatchSummary, Error> {
    let op_id = OpId::parse(&op_id)?.into_inner();
    let trace_id = generate_hex_id_128();
    let channel_id_value = format_channel_id(&channel_id);
    let trace_channel_id = channel_id_value.clone();
    let trace_op_id = op_id.clone();
    let sent_at = Utc::now().timestamp_millis();
    let delivery_id = DeliveryId::reserve(state, sent_at).await?.into_inner();
    let correlation_id = Arc::<str>::from(trace_id.into_boxed_str());
    let delivery_id_ref = Arc::<str>::from(delivery_id.clone().into_boxed_str());
    let op_guard = match DispatchOpGuard::begin(
        state,
        SemanticScope::new(&channel_id_value, entity_type, entity_id)
            .op_dedupe_key(&OpId::parse(&op_id)?),
        delivery_id.clone(),
        sent_at,
        channel_id_value.clone(),
        op_id.clone(),
    )
    .await?
    {
        DispatchOpGuardStart::Complete(summary) => return Ok(summary),
        DispatchOpGuardStart::Proceed(guard) => guard,
    };

    let dispatch_span = ::tracing::info_span!(
        "gateway.dispatch.request",
        correlation_id = %crate::util::redact_text(correlation_id.as_ref()),
        delivery_id = %crate::util::redact_text(delivery_id_ref.as_ref()),
        channel_id = %crate::util::redact_text(trace_channel_id.as_str()),
        op_id = %crate::util::redact_text(trace_op_id.as_str()),
        entity_type = %entity_type,
        entity_id = %crate::util::redact_text(entity_id)
    );
    let dispatch_result = async {
        let prepared = PreparedDispatch::build(
            state,
            channel_id,
            channel_id_value,
            op_id,
            occurred_at,
            title,
            body,
            severity,
            ttl,
            custom_data,
            entity_type,
            entity_id,
            extra_fields,
            sent_at,
            delivery_id,
            Arc::clone(&correlation_id),
            Arc::clone(&delivery_id_ref),
        )
        .await?;
        emit_dispatch_request_started(&prepared);
        let mut progress = DispatchProgress::default();
        enqueue_private_deliveries(&prepared, &mut progress).await;
        if !prepared.provider_devices.is_empty() {
            let payloads = ProviderPayloads::build(&prepared);
            dispatch_provider_devices(&prepared, &payloads, &mut progress).await?;
        }
        let summary = prepared.emit_stats(progress);
        emit_dispatch_request_finished(&prepared, &summary);
        Ok(summary)
    }
    .instrument(dispatch_span)
    .await;
    if let Err(err) = dispatch_result.as_ref() {
        emit_dispatch_request_failed(
            correlation_id.as_ref(),
            delivery_id_ref.as_ref(),
            trace_channel_id.as_str(),
            trace_op_id.as_str(),
            err,
        );
    }

    op_guard.finish(state, dispatch_result).await
}

fn emit_dispatch_request_started(prepared: &PreparedDispatch<'_>) {
    let private_targets = prepared
        .private_dispatch
        .as_ref()
        .map_or(0usize, |private| private.subscribers.len());
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "dispatch.request_started",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        op_id = %(crate::util::redact_text(prepared.op_id.as_str())),
        severity = %(prepared.severity.as_str()),
        provider_targets = (prepared.provider_devices.len() as u64),
        private_targets = (private_targets as u64),
        private_enabled = (private_targets > 0),
        provider_enabled = (!prepared.provider_devices.is_empty())
    );
}

fn emit_dispatch_request_finished(
    prepared: &PreparedDispatch<'_>,
    summary: &NotificationDispatchSummary,
) {
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
        has_dispatch_attempt = (summary.has_dispatch_attempt)
    );
}

fn emit_dispatch_request_failed(
    correlation_id: &str,
    delivery_id: &str,
    channel_id: &str,
    op_id: &str,
    err: &Error,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "dispatch.request_failed",
        correlation_id = %(crate::util::redact_text(correlation_id)),
        delivery_id = %(crate::util::redact_text(delivery_id)),
        channel_id = %(crate::util::redact_text(channel_id)),
        op_id = %(crate::util::redact_text(op_id)),
        error_code = %(dispatch_request_error_code(err)),
        error = %(err.to_string())
    );
}

fn dispatch_request_error_code(err: &Error) -> &'static str {
    match err {
        Error::Validation { .. } => "validation",
        Error::Unauthorized => "unauthorized",
        Error::Upstream { .. } => "upstream",
        Error::Internal(_) => "internal",
        Error::TooBusy => "too_busy",
        Error::StoreError(_) => "store_error",
    }
}
