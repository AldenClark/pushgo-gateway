use super::*;

pub(super) struct PreparedDispatch<'a> {
    pub(super) state: &'a AppState,
    pub(super) channel_id: [u8; 16],
    pub(super) channel_id_value: String,
    pub(super) op_id: String,
    pub(super) delivery_id: String,
    pub(super) delivery_id_ref: Arc<str>,
    pub(super) correlation_id: Arc<str>,
    pub(super) sent_at: i64,
    pub(super) entity_type: &'a str,
    pub(super) entity_id: String,
    pub(super) resolved_title: Option<String>,
    pub(super) resolved_body: Option<String>,
    pub(super) severity: PayloadSeverity,
    pub(super) effective_ttl: Option<i64>,
    pub(super) ttl_seconds: Option<u32>,
    pub(super) private_default_ttl_secs: i64,
    pub(super) private_payload: Vec<u8>,
    pub(super) wakeup_data: Arc<HashMap<String, String>>,
    pub(super) custom_data: Arc<HashMap<String, String>>,
    pub(super) provider_devices: Vec<DeviceInfo>,
    pub(super) private_dispatch: Option<PrivateDispatchContext<'a>>,
    pub(super) apple_thread_id: String,
    pub(super) provider_fallback_body: Option<String>,
}

pub(super) struct PrivateDispatchContext<'a> {
    pub(super) state: &'a crate::private::PrivateState,
    pub(super) subscribers: Vec<DeviceId>,
    pub(super) subscriber_set: HashSet<DeviceId>,
}

pub(super) struct ProviderPayloads {
    pub(super) apns_payload: Option<Arc<ApnsPayload>>,
    pub(super) watchos_apns_payload: Option<Arc<ApnsPayload>>,
    pub(super) apns_collapse_id: Option<Arc<str>>,
    pub(super) apns_wakeup_title: Option<String>,
    pub(super) fcm_payload: Option<Arc<FcmPayload>>,
    pub(super) wns_payload: Option<Arc<WnsPayload>>,
}

pub(super) struct ResolvedProviderTarget<'a> {
    pub(super) device: &'a DeviceInfo,
    pub(super) provider_audit_key: String,
    pub(super) provider_stats_key: Arc<str>,
    pub(super) wakeup_data_for_device: Arc<HashMap<String, String>>,
    pub(super) provider_pull_delivery: Option<ProviderPullDelivery>,
}

#[derive(Default)]
pub(super) struct DispatchProgress {
    pub(super) private_enqueued: HashSet<DeviceId>,
    pub(super) private_realtime_delivered: HashSet<DeviceId>,
    pub(super) private_enqueue_stats: PrivateEnqueueStats,
    pub(super) provider_attempted: i64,
    pub(super) provider_success: i64,
    pub(super) provider_failed: i64,
    pub(super) rejected: usize,
    pub(super) dispatch_closed: bool,
    pub(super) device_stats: HashMap<Arc<str>, DeviceDispatchDelta>,
}

impl<'a> PreparedDispatch<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build(
        state: &'a AppState,
        channel_id: [u8; 16],
        channel_id_value: String,
        op_id: String,
        occurred_at: i64,
        title: Option<String>,
        body: Option<String>,
        severity: Option<String>,
        ttl: Option<i64>,
        custom_data: HashMap<String, String>,
        entity_type: &'a str,
        entity_id: &'a str,
        extra_fields: HashMap<String, String>,
        sent_at: i64,
        delivery_id: String,
        correlation_id: Arc<str>,
        delivery_id_ref: Arc<str>,
    ) -> Result<Self, Error> {
        let entity_id = entity_id.trim().to_string();
        let entity_kind = EntityKind::new(entity_type);
        let resolved_title = title
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToString::to_string);
        let resolved_body = body
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToString::to_string);

        let severity = PayloadSeverity::normalize(severity);
        let effective_ttl =
            ttl.map(|expires_at| expires_at.min(sent_at + MAX_PROVIDER_TTL_SECONDS));
        let ttl_seconds = effective_ttl
            .map(|expires_at| ProviderTtl::remaining(sent_at, expires_at).into_inner());
        let dispatch_targets = state
            .store
            .list_channel_dispatch_targets(channel_id, sent_at)
            .await?;

        let private_state = state.private.as_deref();
        let private_enabled = state.private_channel_enabled && private_state.is_some();
        let private_default_ttl_secs = private_state
            .map(|private| private.config.default_ttl_secs)
            .unwrap_or(MAX_PROVIDER_TTL_SECONDS)
            .clamp(0, MAX_PROVIDER_TTL_SECONDS);

        let mut private_subscribers = Vec::new();
        let mut provider_devices = Vec::new();
        for target in dispatch_targets {
            match target {
                DispatchTarget::Private { device_id, .. } if private_enabled => {
                    private_subscribers.push(device_id);
                }
                DispatchTarget::Provider {
                    platform,
                    provider_token,
                    ..
                } => {
                    provider_devices
                        .push(DeviceInfo::from_token(platform, provider_token.as_str())?);
                }
                _ => {}
            }
        }

        let mut custom_data = CustomPayloadData::new(custom_data);
        custom_data.apply_standard_fields(StandardFields {
            channel_id: &channel_id_value,
            title: resolved_title.as_deref(),
            body: resolved_body.as_deref(),
            severity: (entity_type == "message").then_some(severity.as_str()),
            schema_version: SCHEMA_VERSION,
            payload_version: PAYLOAD_VERSION,
            op_id: &op_id,
            delivery_id: &delivery_id,
            ingested_at: sent_at,
            occurred_at,
            sent_at,
            ttl: effective_ttl,
            entity_type,
            entity_id: &entity_id,
        });
        custom_data.insert_extra_fields(extra_fields);
        custom_data.apply_gateway_base_url(state.public_base_url.as_deref());
        let derived_notification_text = custom_data.resolve_notification_text(
            entity_kind,
            resolved_title.as_deref(),
            resolved_body.as_deref(),
        );
        let resolved_title = resolved_title.or(derived_notification_text.title);
        let resolved_body = resolved_body.or(derived_notification_text.body);
        custom_data.ensure_notification_title(resolved_title.as_deref());
        let prepared_payload = custom_data
            .prepare_dispatch(channel_id_value.as_str(), entity_kind)
            .map_err(|err| Error::Internal(format!("private payload encoding failed: {err}")))?;
        let private_dispatch =
            private_state
                .filter(|_| private_enabled)
                .map(|state| PrivateDispatchContext {
                    state,
                    subscriber_set: private_subscribers.iter().copied().collect(),
                    subscribers: private_subscribers,
                });

        Ok(Self {
            state,
            channel_id,
            channel_id_value,
            op_id,
            delivery_id,
            delivery_id_ref,
            correlation_id,
            sent_at,
            entity_type,
            entity_id,
            resolved_title,
            resolved_body,
            severity,
            effective_ttl,
            ttl_seconds,
            private_default_ttl_secs,
            private_payload: prepared_payload.private_payload.into_inner(),
            wakeup_data: prepared_payload.wakeup_data.into_inner(),
            custom_data: prepared_payload.custom_data,
            provider_devices,
            private_dispatch,
            apple_thread_id: prepared_payload.apple_thread_id.into_inner(),
            provider_fallback_body: None,
        })
    }

    pub(super) fn provider_pull_expires_at(&self) -> i64 {
        self.effective_ttl
            .unwrap_or(self.sent_at + self.private_default_ttl_secs)
    }

    pub(super) fn emit_stats(&self, progress: DispatchProgress) -> NotificationDispatchSummary {
        emit_dispatch_stats(
            self.state,
            self.channel_id,
            self.sent_at,
            1,
            progress.private_enqueue_stats.attempted as i64 + progress.provider_attempted,
            progress.provider_attempted,
            progress.provider_success,
            progress.provider_failed,
            progress.private_realtime_delivered.len() as i64,
            progress.device_stats,
        );

        NotificationDispatchSummary {
            channel_id: self.channel_id_value.clone(),
            op_id: self.op_id.clone(),
            delivery_id: self.delivery_id.clone(),
            partial_failure: progress.rejected > 0 || progress.private_enqueue_stats.has_failures(),
            private_enqueue_too_busy: progress.private_enqueue_stats.is_too_busy(),
        }
    }
}

impl ProviderPayloads {
    pub(super) fn build(prepared: &PreparedDispatch<'_>) -> Self {
        let mut has_android = false;
        let mut has_apns = false;
        let mut has_wns = false;
        let mut has_watchos_apns = false;
        for device in &prepared.provider_devices {
            match device.platform {
                Platform::ANDROID => has_android = true,
                Platform::WINDOWS => has_wns = true,
                Platform::WATCHOS => {
                    has_apns = true;
                    has_watchos_apns = true;
                }
                _ => has_apns = true,
            }
        }

        let apns_payload = has_apns.then(|| {
            Arc::new(ApnsPayload::new(
                prepared.resolved_title.clone(),
                prepared.resolved_body.clone(),
                prepared.provider_fallback_body.clone(),
                Some(prepared.apple_thread_id.clone()),
                prepared.severity.as_str().to_string(),
                prepared.effective_ttl,
                SharedStringMap::from(Arc::clone(&prepared.custom_data)),
            ))
        });
        let watchos_apns_payload = has_watchos_apns.then(|| {
            Arc::new(ApnsPayload::new(
                prepared.resolved_title.clone(),
                prepared.resolved_body.clone(),
                prepared.provider_fallback_body.clone(),
                Some(prepared.apple_thread_id.clone()),
                prepared.severity.as_str().to_string(),
                prepared.effective_ttl,
                quantize_watch_payload(prepared.custom_data.as_ref()),
            ))
        });
        let apns_collapse_id =
            has_apns.then(|| Arc::from(prepared.delivery_id.clone().into_boxed_str()));
        let apns_wakeup_title = has_apns.then(|| prepared.resolved_title.clone()).flatten();
        let fcm_payload = has_android.then(|| {
            Arc::new(FcmPayload::new(
                SharedStringMap::from(Arc::clone(&prepared.custom_data)),
                prepared.severity.fcm_priority(),
                prepared.ttl_seconds,
            ))
        });
        let wns_payload = has_wns.then(|| {
            Arc::new(WnsPayload::new(
                SharedStringMap::from(Arc::clone(&prepared.custom_data)),
                prepared.severity.as_str(),
                prepared.ttl_seconds,
            ))
        });

        Self {
            apns_payload,
            watchos_apns_payload,
            apns_collapse_id,
            apns_wakeup_title,
            fcm_payload,
            wns_payload,
        }
    }
}

impl DispatchProgress {
    pub(super) fn record_private_success(&mut self, device_id: DeviceId) {
        self.private_enqueued.insert(device_id);
        let private_stats_key = Arc::<str>::from(
            format!("private:{}", encode_lower_hex_128(&device_id)).into_boxed_str(),
        );
        merge_device_dispatch_delta(
            &mut self.device_stats,
            private_stats_key,
            DeviceDispatchDelta {
                messages_received: 1,
                private_outbox_enqueued_count: 1,
                ..DeviceDispatchDelta::default()
            },
        );
    }

    pub(super) fn record_provider_success(&mut self, provider_stats_key: Arc<str>) {
        self.provider_attempted += 1;
        self.provider_success += 1;
        merge_device_dispatch_delta(
            &mut self.device_stats,
            provider_stats_key,
            DeviceDispatchDelta {
                messages_received: 1,
                provider_success_count: 1,
                ..DeviceDispatchDelta::default()
            },
        );
    }

    pub(super) fn record_provider_failure(&mut self, provider_stats_key: Arc<str>) {
        self.rejected += 1;
        self.provider_attempted += 1;
        self.provider_failed += 1;
        merge_device_dispatch_delta(
            &mut self.device_stats,
            provider_stats_key,
            DeviceDispatchDelta {
                provider_failure_count: 1,
                ..DeviceDispatchDelta::default()
            },
        );
    }

    pub(super) fn should_skip_provider_delivery(
        &self,
        private_delivery_target: Option<DeviceId>,
        private_online: bool,
    ) -> bool {
        ProviderDeliverySkip::should_skip(
            private_delivery_target,
            private_online,
            &self.private_realtime_delivered,
        )
    }
}
