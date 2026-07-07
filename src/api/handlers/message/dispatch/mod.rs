use std::{borrow::Cow, sync::Arc};

use chrono::Utc;
use hashbrown::HashMap;

use crate::{
    api::{Error, format_channel_id},
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
        ProviderDeliveryPath as CoreProviderDeliveryPath, ProviderPullTarget,
    },
    delivery_core::store::{channel::ChannelStore, counters::RuntimeCounterSink},
    dispatch::{DispatchError, ProviderDeliveryPath, ProviderPullDelivery},
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    storage::{DeviceInfo, Platform},
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
        enqueue_private_deliveries(prepared, progress).await;
        dispatch_mqtt_receiver_targets(prepared, progress).await;
        if !prepared.provider_targets.is_empty() {
            let payloads = ProviderPayloads::build(prepared);
            dispatch_provider_targets(prepared, &payloads, progress).await?;
        }
        widgets::dispatch_widget_push_targets(prepared).await;
        Ok(())
    }

    fn error_code(&self, err: &Self::Error) -> &'static str {
        dispatch_request_error_code(err)
    }
}

async fn dispatch_mqtt_receiver_targets(
    prepared: &PreparedDispatch<'_>,
    progress: &mut DispatchProgress,
) {
    if prepared.mqtt_receiver_targets.is_empty() {
        return;
    }
    let Some(private_state) = prepared.runtime.private_state() else {
        for _ in &prepared.mqtt_receiver_targets {
            progress.record_mqtt_failure();
        }
        return;
    };
    execute_mqtt_receiver_deliveries(
        MqttReceiverDeliveryExecution {
            private_state,
            store: prepared.runtime.storage(),
            correlation_id: prepared.correlation_id.as_ref(),
            delivery_id: prepared.delivery_id.as_str(),
            channel_id: prepared.channel_id_value.as_str(),
            targets: &prepared.mqtt_receiver_targets,
            payload: prepared.private_payload.clone(),
        },
        progress,
    )
    .await;
}

impl From<DispatchExecutionError> for Error {
    fn from(value: DispatchExecutionError) -> Self {
        Error::Internal(value.message())
    }
}

impl DispatchExecutionRuntime for AppState {
    fn channel_store(&self) -> &(dyn ChannelStore + Send + Sync) {
        &self.store
    }

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

    fn private_channel_enabled(&self) -> bool {
        self.private_channel_enabled
    }

    fn public_base_url(&self) -> Option<&str> {
        self.public_base_url.as_deref()
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
    let entity_kind = request.payload.kind();
    let entity_type = entity_kind.as_str();
    let entity_id = request.payload.entity_id().trim().to_string();
    let op_id = OpId::parse(&request.op_id)?.into_inner();
    request.op_id = op_id.clone();
    let channel_id_value = format_channel_id(&channel_id);
    let sent_at = Utc::now().timestamp_millis();
    let delivery_id = DeliveryId::reserve(state, sent_at).await?.into_inner();
    let op_guard = match DispatchOpGuard::begin(
        state,
        SemanticScope::new(&channel_id_value, entity_type, &entity_id)
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

    let dispatch_result = execute_dispatch(
        state,
        DispatchExecutionInput {
            channel_id,
            channel_id_text: channel_id_value,
            sent_at,
            delivery_id,
            op_id,
            entity_type,
            entity_id,
            request,
        },
        ApiDispatchDelegate,
    )
    .await;

    op_guard.finish(state, dispatch_result).await
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
