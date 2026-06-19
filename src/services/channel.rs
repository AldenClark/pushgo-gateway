use crate::{
    api::handlers::core::channels::private_cleanup::clear_private_pending_for_channel,
    api::{ChannelAlias, ChannelId, ChannelPassword, Error},
    app::AppState,
    routing::{DeviceChannelType, derive_private_device_id},
    storage::DeviceRouteRecordRow,
    storage::PrivateDeviceId,
    value::DeviceKeyRef,
};

#[derive(Debug, Clone)]
pub(crate) struct ChannelSubscribeCommand {
    pub device_key: String,
    pub channel_id: Option<String>,
    pub channel_name: Option<String>,
    pub password: String,
    pub source: ChannelCommandSource,
    pub allow_create_channel: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelSubscribeOutcome {
    pub channel_id: String,
    pub channel_name: String,
    pub created: bool,
    pub subscribed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelUnsubscribeCommand {
    pub device_key: String,
    pub channel_id: String,
    pub source: ChannelCommandSource,
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelUnsubscribeOutcome {
    pub channel_id: String,
    pub removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelCommandSource {
    Http,
    Mqtt,
}

impl ChannelCommandSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Mqtt => "mqtt",
        }
    }
}

pub(crate) async fn subscribe_private_device_to_channel(
    state: &AppState,
    command: ChannelSubscribeCommand,
) -> Result<ChannelSubscribeOutcome, Error> {
    let device_key = DeviceKeyRef::parse(&command.device_key)?;
    let route = state
        .device_registry
        .get(device_key.as_str())
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    if route.channel_type != DeviceChannelType::Private {
        return Err(Error::validation_code(
            "device route must be private",
            "private_route_required",
        ));
    }
    if !state.private_channel_enabled {
        return Err(Error::Internal("private channel is disabled".to_string()));
    }
    state
        .store
        .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
            device_key.as_str(),
            &route,
        ))
        .await?;

    let channel_id = match command.channel_id.as_deref() {
        Some(raw) => Some(ChannelId::parse(raw)?),
        None => None,
    };
    let channel_name = match command.channel_name.as_deref() {
        Some(raw) => Some(ChannelAlias::parse(raw)?),
        None => None,
    };
    if channel_id.is_some() == channel_name.is_some() {
        return Err(Error::validation_code(
            "must provide either channel_id or channel_name",
            "channel_binding_invalid",
        ));
    }
    let password = ChannelPassword::parse(&command.password)?;
    if !command.allow_create_channel
        && let Some(id) = channel_id
    {
        state
            .store
            .channel_info_with_password(id.into_inner(), password.as_str())
            .await?
            .ok_or_else(|| Error::validation_code("channel not found", "channel_not_found"))?;
    }
    let outcome = state
        .store
        .upsert_private_channel(
            channel_id.map(ChannelId::into_inner),
            channel_name.map(ChannelAlias::as_str),
            password.as_str(),
        )
        .await?;
    let device_id = derive_private_device_id(device_key.as_str());
    state
        .store
        .private_subscribe_channel(outcome.channel_id, device_id)
        .await?;
    state
        .store
        .record_device_activity_best_effort(
            device_id,
            chrono::Utc::now().timestamp_millis(),
            "private_channel_subscribe",
        )
        .await;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "channel.subscribe_completed",
        device_key = %(crate::util::redact_text(device_key.as_str())),
        channel_id = %(crate::util::redact_text(ChannelId::from(outcome.channel_id).to_string())),
        created = (outcome.created),
        channel_type = %(route.channel_type.as_str()),
        source = %(command.source.as_str())
    );
    Ok(ChannelSubscribeOutcome {
        channel_id: ChannelId::from(outcome.channel_id).to_string(),
        channel_name: outcome.alias,
        created: outcome.created,
        subscribed: true,
    })
}

pub(crate) async fn record_route_activity_for_device_key(
    state: &AppState,
    device_key: &str,
    reason: &'static str,
) {
    if let Some(device_key) = DeviceKeyRef::optional(Some(device_key)) {
        state
            .store
            .record_device_activity_best_effort(
                PrivateDeviceId::derive(device_key.as_str()).into(),
                chrono::Utc::now().timestamp_millis(),
                reason,
            )
            .await;
    }
}

pub(crate) async fn unsubscribe_private_device_from_channel(
    state: &AppState,
    command: ChannelUnsubscribeCommand,
) -> Result<ChannelUnsubscribeOutcome, Error> {
    let device_key = DeviceKeyRef::parse(&command.device_key)?;
    let route = state
        .device_registry
        .get(device_key.as_str())
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    if route.channel_type != DeviceChannelType::Private {
        return Err(Error::validation_code(
            "device route must be private",
            "private_route_required",
        ));
    }
    if !state.private_channel_enabled {
        return Err(Error::Internal("private channel is disabled".to_string()));
    }
    let private_state = state
        .private
        .as_ref()
        .ok_or_else(|| Error::Internal("private channel runtime is unavailable".to_string()))?;
    let channel_id = ChannelId::parse(&command.channel_id)?;
    let channel_id_raw = channel_id.into_inner();
    let device_id = derive_private_device_id(device_key.as_str());
    state
        .store
        .private_unsubscribe_channel(channel_id_raw, device_id)
        .await?;
    let _cleared =
        clear_private_pending_for_channel(state, private_state, device_id, channel_id_raw).await?;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "channel.unsubscribe_completed",
        device_key = %(crate::util::redact_text(device_key.as_str())),
        channel_id = %(crate::util::redact_text(ChannelId::from(channel_id_raw).to_string())),
        removed = true,
        channel_type = %(route.channel_type.as_str()),
        source = %(command.source.as_str())
    );
    Ok(ChannelUnsubscribeOutcome {
        channel_id: ChannelId::from(channel_id_raw).to_string(),
        removed: true,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{
        app::{AuthMode, DeviceOperationGuards, PrivateTransportProfile},
        dispatch::DispatchChannels,
        private::{PrivateConfig, PrivateState, protocol::PrivatePayloadEnvelope},
        routing::{DeviceRegistry, DeviceRouteRecord},
        runtime_config::GatewayRuntimeProfile,
        runtime_counters::RuntimeCounterCollector,
        storage::{
            MaintenanceCleanupConfig, OUTBOX_STATUS_PENDING, Platform, PrivateMessage,
            PrivateOutboxEntry, Storage,
        },
    };

    struct TestContext {
        _dir: TempDir,
        state: AppState,
    }

    impl TestContext {
        async fn new() -> Self {
            let dir = tempdir().expect("tempdir should be created");
            let db_path = dir.path().join("gateway-services.sqlite");
            let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
            let store = Storage::new(Some(db_url.as_str()))
                .await
                .expect("storage should initialize");
            let runtime_counters = RuntimeCounterCollector::spawn(store.clone());
            let registry = Arc::new(DeviceRegistry::new());
            let private = Arc::new(PrivateState::new(
                store.clone(),
                test_private_config(),
                Arc::clone(&registry),
                Arc::clone(&runtime_counters),
            ));
            let (dispatch, _receivers) = DispatchChannels::new();
            let state = AppState {
                dispatch,
                auth: AuthMode::Disabled,
                private_channel_enabled: true,
                public_base_url: None,
                device_registry: registry,
                device_operation_guards: Arc::new(DeviceOperationGuards::default()),
                runtime_counters,
                private_transport_profile: PrivateTransportProfile {
                    quic_enabled: false,
                    quic_port: None,
                    tcp_enabled: false,
                    tcp_port: 5223,
                    wss_enabled: false,
                    wss_port: 443,
                    wss_path: Arc::from("/private/ws"),
                    ws_subprotocol: Arc::from("pushgo-private.v1"),
                    mqtt_enabled: true,
                    mqtt_port: Some(1883),
                    mqtt_tls_required: false,
                },
                private: Some(Arc::clone(&private)),
                store,
                mcp: None,
            };
            Self { _dir: dir, state }
        }

        async fn restore_private_route(&self, device_key: &str) {
            let route = DeviceRouteRecord {
                platform: Platform::ANDROID,
                channel_type: DeviceChannelType::Private,
                provider_token: None,
                updated_at: chrono::Utc::now().timestamp(),
            };
            self.state
                .device_registry
                .restore_route(device_key, route.clone())
                .expect("route restore should succeed");
            self.state
                .store
                .upsert_device_route(&DeviceRouteRecordRow::from_registry_record(
                    device_key, &route,
                ))
                .await
                .expect("route should persist");
        }
    }

    fn test_private_config() -> PrivateConfig {
        PrivateConfig {
            runtime_profile: GatewayRuntimeProfile::Small,
            private_quic_bind: None,
            private_tcp_bind: None,
            mqtt: None,
            tcp_tls_enabled: false,
            tcp_proxy_protocol: false,
            private_tls_cert_path: None,
            private_tls_key_path: None,
            session_ttl_secs: 60,
            grace_window_secs: 10,
            max_pending_per_device: 16,
            global_max_pending: 64,
            pull_limit: 32,
            ack_timeout_secs: 5,
            fallback_max_attempts: 3,
            fallback_max_backoff_secs: 60,
            retransmit_window_secs: 30,
            retransmit_max_per_window: 10,
            retransmit_max_per_tick: 16,
            retransmit_max_retries: 3,
            hot_cache_capacity: 64,
            default_ttl_secs: 60,
            online_fast_path_enabled: false,
            maintenance_cleanup: MaintenanceCleanupConfig::default(),
            gateway_token: None,
        }
        .normalized()
    }

    #[tokio::test]
    async fn private_subscribe_service_reuses_route_persistence() {
        let ctx = TestContext::new().await;
        let device_key = "mqtt-service-subscribe-device";
        ctx.restore_private_route(device_key).await;

        let outcome = subscribe_private_device_to_channel(
            &ctx.state,
            ChannelSubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: None,
                channel_name: Some("mqtt-service-channel".to_string()),
                password: "mqtt-pass-123".to_string(),
                source: ChannelCommandSource::Mqtt,
                allow_create_channel: true,
            },
        )
        .await
        .expect("subscribe should succeed");

        assert!(outcome.subscribed);
        assert!(outcome.created);
        let device_id = derive_private_device_id(device_key);
        let subscribed = ctx
            .state
            .store
            .list_private_subscribed_channels_for_device(device_id)
            .await
            .expect("subscription list should load");
        assert_eq!(subscribed.len(), 1);
        assert_eq!(
            ChannelId::from(subscribed[0]).to_string(),
            outcome.channel_id
        );
    }

    #[tokio::test]
    async fn private_unsubscribe_service_clears_matching_pending_outbox() {
        let ctx = TestContext::new().await;
        let device_key = "mqtt-service-unsubscribe-device";
        ctx.restore_private_route(device_key).await;
        let outcome = subscribe_private_device_to_channel(
            &ctx.state,
            ChannelSubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: None,
                channel_name: Some("mqtt-unsubscribe-channel".to_string()),
                password: "mqtt-pass-456".to_string(),
                source: ChannelCommandSource::Mqtt,
                allow_create_channel: true,
            },
        )
        .await
        .expect("subscribe should succeed");
        let channel_id = ChannelId::parse(&outcome.channel_id)
            .expect("channel id should parse")
            .into_inner();
        let device_id = derive_private_device_id(device_key);
        let delivery_id = "mqtt-unsubscribe-delivery";
        let mut data = hashbrown::HashMap::new();
        data.insert("channel_id".to_string(), outcome.channel_id.clone());
        data.insert("entity_type".to_string(), "message".to_string());
        data.insert("message_id".to_string(), "message-1".to_string());
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PrivatePayloadEnvelope::CURRENT_VERSION,
            data,
        })
        .expect("payload should encode");
        let now = chrono::Utc::now().timestamp_millis();
        ctx.state
            .store
            .insert_private_message(
                delivery_id,
                &PrivateMessage {
                    size: payload.len(),
                    payload: Arc::from(payload),
                    sent_at: now,
                    expires_at: now + 60_000,
                },
            )
            .await
            .expect("message should insert");
        ctx.state
            .store
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now,
                    created_at: now,
                    claimed_at: None,
                    claimed_by: None,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now,
                },
            )
            .await
            .expect("outbox should enqueue");

        let result = unsubscribe_private_device_from_channel(
            &ctx.state,
            ChannelUnsubscribeCommand {
                device_key: device_key.to_string(),
                channel_id: outcome.channel_id,
                source: ChannelCommandSource::Mqtt,
            },
        )
        .await
        .expect("unsubscribe should succeed");

        assert!(result.removed);
        let channels = ctx
            .state
            .store
            .list_private_subscribed_channels_for_device(device_id)
            .await
            .expect("subscription list should load");
        assert!(
            !channels.contains(&channel_id),
            "channel should be removed from private subscriptions"
        );
        assert!(
            ctx.state
                .store
                .load_private_outbox_entry(device_id, delivery_id)
                .await
                .expect("outbox entry should load")
                .is_none(),
            "matching pending delivery should be settled"
        );
    }
}
