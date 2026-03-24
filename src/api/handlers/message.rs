use std::{borrow::Cow, collections::HashSet, sync::Arc};

use axum::{extract::State, http::StatusCode};
use chrono::Utc;
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use serde_json::{Map as JsonMap, Value};

use crate::{
    api::{
        ApiJson, Error, HttpResult, format_channel_id, parse_channel_id, validate_channel_password,
    },
    app::AppState,
    device_registry::DeviceRegistry,
    dispatch::{
        ApnsJob, DispatchError, FcmJob, PrivateWakeupDelivery, ProviderDeliveryPath, WnsJob,
        audit::DispatchAuditRecord,
    },
    private::protocol::PRIVATE_PAYLOAD_VERSION_V1,
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    storage::{Platform, StoreError},
    util::{SharedStringMap, build_wakeup_data, generate_hex_id_128},
};

use super::dispatch_lifecycle::{
    DispatchOpGuard, DispatchOpGuardStart, NotificationDispatchSummary,
    dispatch_failure_error_message,
};
use super::watch_light::quantize_watch_payload;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageIntent {
    pub channel_id: String,
    pub password: String,
    pub op_id: String,
    pub thing_id: Option<String>,
    pub title: String,
    pub body: Option<String>,
    pub severity: Option<String>,
    pub ttl: Option<i64>,
    pub url: Option<String>,
    #[serde(default)]
    pub images: Vec<String>,
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_map")]
    pub metadata: JsonMap<String, Value>,
}

impl MessageIntent {
    pub fn validate_payload(&self) -> Result<(), Error> {
        if self.channel_id.trim().is_empty() {
            return Err(Error::validation("channel id must not be empty"));
        }
        validate_channel_password(&self.password)?;
        normalize_op_id(&self.op_id)?;
        if self.title.trim().is_empty() {
            return Err(Error::validation("title must not be empty"));
        }
        validate_metadata_entries(&self.metadata)?;
        Ok(())
    }
}

pub(super) fn deserialize_metadata_map<'de, D>(
    deserializer: D,
) -> Result<JsonMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<Value>::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(JsonMap::new());
    };
    parse_metadata_map_value(raw).map_err(serde::de::Error::custom)
}

fn parse_metadata_map_value(raw: Value) -> Result<JsonMap<String, Value>, String> {
    match raw {
        Value::Null => Ok(JsonMap::new()),
        Value::Object(object) => parse_metadata_object(object),
        _ => Err("metadata must be a JSON object".to_string()),
    }
}

fn parse_metadata_object(object: JsonMap<String, Value>) -> Result<JsonMap<String, Value>, String> {
    let mut out = JsonMap::new();
    for (raw_key, raw_value) in object {
        let key = raw_key.trim();
        if key.is_empty() {
            return Err("metadata key must not be empty".to_string());
        }
        if !metadata_is_scalar(&raw_value) {
            return Err(format!("metadata.{key} must be a scalar"));
        }
        if out.insert(key.to_string(), raw_value).is_some() {
            return Err("metadata key must be unique".to_string());
        }
    }
    Ok(out)
}

fn metadata_is_scalar(raw: &Value) -> bool {
    match raw {
        Value::String(value) => !value.trim().is_empty(),
        Value::Number(_) | Value::Bool(_) => true,
        _ => false,
    }
}

#[derive(Serialize)]
pub(crate) struct MessageSummary {
    channel_id: String,
    op_id: String,
    message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thing_id: Option<String>,
    accepted: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct PrivateEnqueueStats {
    attempted: usize,
    failed: usize,
}

impl PrivateEnqueueStats {
    fn record_success(&mut self) {
        self.attempted = self.attempted.saturating_add(1);
    }

    fn record_failure(&mut self, _stage: &str, _device_id: [u8; 16], _error: &crate::Error) {
        self.attempted = self.attempted.saturating_add(1);
        self.failed = self.failed.saturating_add(1);
    }

    fn has_failures(self) -> bool {
        self.failed > 0
    }

    fn is_too_busy(self) -> bool {
        if self.attempted == 0 || self.failed == 0 {
            return false;
        }
        let dynamic_min_failed = (self.attempted / 4).clamp(
            PRIVATE_ENQUEUE_TOO_BUSY_MIN_FLOOR,
            PRIVATE_ENQUEUE_TOO_BUSY_MIN_CEIL,
        );
        self.failed >= dynamic_min_failed
            && self.failed * 100 >= self.attempted * PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT
    }
}

const PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT: usize = 50;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_FLOOR: usize = 2;
const PRIVATE_ENQUEUE_TOO_BUSY_MIN_CEIL: usize = 16;
const APNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const FCM_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 4096;
const WNS_PROVIDER_PAYLOAD_LIMIT_BYTES: usize = 5120;

#[derive(Debug, Clone, Copy)]
struct ProviderDeliverySelection {
    initial_path: ProviderDeliveryPath,
    wakeup_payload_within_limit: bool,
}

pub(crate) async fn message_to_channel(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<MessageIntent>,
) -> HttpResult {
    let scoped_thing_id = payload
        .thing_id
        .as_deref()
        .map(normalize_thing_id)
        .transpose()?
        .map(ToString::to_string);
    dispatch_message_intent(&state, payload, scoped_thing_id).await
}

async fn dispatch_message_intent(
    state: &AppState,
    payload: MessageIntent,
    scoped_thing_id: Option<String>,
) -> HttpResult {
    payload.validate_payload()?;
    if !state
        .api_rate_limiter
        .allow_channel(payload.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let channel_id_value = format_channel_id(&channel_id);
    let password = validate_channel_password(&payload.password)?;
    state
        .store
        .channel_info_with_password_async(channel_id, password)
        .await?
        .ok_or(StoreError::ChannelNotFound)?;

    let MessageIntent {
        op_id,
        title,
        body,
        severity,
        ttl,
        url,
        images,
        ciphertext,
        tags,
        metadata,
        ..
    } = payload;
    let normalized_body = normalize_optional_string(body);
    let normalized_url = normalize_optional_string(url);
    let normalized_images = normalize_image_values(&images, "images")?;

    let op_id = normalize_op_id(&op_id)?;
    let message_id = resolve_create_semantic_id(
        state,
        build_semantic_create_dedupe_key(
            &channel_id_value,
            "message",
            scoped_thing_id.as_deref(),
            &op_id,
        )
        .as_str(),
    )
    .await?
    .semantic_id;
    let mut custom_data = HashMap::with_capacity(4);
    if let Some(url) = normalized_url {
        custom_data.insert("url".to_string(), url);
    }
    if !normalized_images.is_empty() {
        let encoded = serde_json::to_string(&normalized_images)
            .map_err(|_| Error::validation("images format is invalid"))?;
        custom_data.insert("images".to_string(), encoded);
    }
    if let Some(ciphertext) = normalize_optional_string(ciphertext) {
        custom_data.insert("ciphertext".to_string(), ciphertext);
    }
    let normalized_tags = normalize_tags(&tags, "tags")?;
    if !metadata.is_empty() {
        let encoded = encode_metadata(&metadata)?;
        custom_data.insert("metadata".to_string(), encoded);
    }
    let mut extra_fields = HashMap::with_capacity(3);
    extra_fields.insert("message_id".to_string(), message_id.clone());
    if !normalized_tags.is_empty() {
        let encoded = serde_json::to_string(&normalized_tags)
            .map_err(|_| Error::validation("tags format is invalid"))?;
        extra_fields.insert("tags".to_string(), encoded);
    }
    if let Some(thing_id) = scoped_thing_id.clone() {
        extra_fields.insert("thing_id".to_string(), thing_id);
    }

    let summary = dispatch_entity_notification(
        state,
        channel_id,
        op_id,
        Some(title),
        normalized_body,
        severity,
        ttl,
        custom_data,
        "message",
        &message_id,
        extra_fields,
    )
    .await?;

    let error_message = dispatch_failure_error_message(&summary);
    let mut response_data = MessageSummary {
        channel_id: summary.channel_id,
        op_id: summary.op_id,
        message_id,
        thing_id: scoped_thing_id,
        accepted: true,
    };
    if let Some(error_message) = error_message {
        response_data.accepted = false;
        return Ok(crate::api::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "success": false,
                "error": error_message,
                "data": response_data,
            }),
        ));
    }
    Ok(crate::api::ok(response_data))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_entity_notification(
    state: &AppState,
    channel_id: [u8; 16],
    op_id: String,
    title: Option<String>,
    body: Option<String>,
    severity: Option<String>,
    ttl: Option<i64>,
    mut custom_data: HashMap<String, String>,
    entity_type: &str,
    entity_id: &str,
    extra_fields: HashMap<String, String>,
) -> Result<NotificationDispatchSummary, Error> {
    let op_id = normalize_op_id(&op_id)?;
    let trace_id = generate_hex_id_128();
    let channel_id_value = format_channel_id(&channel_id);
    let op_scope = build_op_scope(&channel_id_value, entity_type, entity_id);
    let op_dedupe_key = build_op_dedupe_key(&op_scope, &op_id);
    let sent_at = Utc::now().timestamp();
    let delivery_id = reserve_new_delivery_id(state, sent_at).await?;
    let correlation_id = Arc::<str>::from(trace_id.clone().into_boxed_str());
    let delivery_id_ref = Arc::<str>::from(delivery_id.clone().into_boxed_str());
    let op_guard = match DispatchOpGuard::begin(
        state,
        op_dedupe_key,
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
    let dispatch_result = async {
        let entity_id = entity_id.trim().to_string();
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
        let provider_fallback_body = (resolved_title.is_none() && resolved_body.is_none())
            .then(|| default_notification_body(entity_type).to_string());

        let normalized_severity = normalize_severity(severity);
        let priority = FcmPayload::priority_for_level(normalized_severity.as_str());
        let effective_ttl =
            ttl.map(|expires_at| expires_at.min(sent_at + MAX_PROVIDER_TTL_SECONDS));
        let ttl_seconds =
            effective_ttl.map(|expires_at| ttl_seconds_remaining(sent_at, expires_at));
        let devices = state.store.list_channel_devices_async(channel_id).await?;

        let private_state = state.private.as_ref();
        let private_enabled = state.private_channel_enabled && private_state.is_some();
        let private_default_ttl_secs = private_state
            .map(|private| private.config.default_ttl_secs)
            .unwrap_or(MAX_PROVIDER_TTL_SECONDS)
            .clamp(0, MAX_PROVIDER_TTL_SECONDS);

        let private_subscribers = if private_enabled {
            state
                .store
                .list_private_subscribers_async(channel_id, sent_at)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let private_subscriber_set: HashSet<[u8; 16]> =
            private_subscribers.iter().copied().collect();

        sanitize_custom_data(&mut custom_data);
        add_standard_fields(
            &mut custom_data,
            StandardFields {
                channel_id: &channel_id_value,
                title: resolved_title.as_deref(),
                body: resolved_body.as_deref(),
                severity: (entity_type == "message").then_some(normalized_severity.as_str()),
                schema_version: SCHEMA_VERSION,
                payload_version: PAYLOAD_VERSION,
                op_id: &op_id,
                delivery_id: &delivery_id,
                sent_at,
                ttl: effective_ttl,
                entity_type,
                entity_id: &entity_id,
            },
        );
        for (key, value) in extra_fields {
            custom_data.insert(key, value);
        }
        let custom_data = Arc::new(custom_data);
        let wakeup_data = Arc::new(build_wakeup_data(custom_data.as_ref()));
        let private_payload = if private_state.is_some() {
            Some(encode_private_payload(custom_data.as_ref()).map_err(|err| {
                Error::Internal(format!("private payload encoding failed: {err}"))
            })?)
        } else {
            None
        };

        let mut private_enqueued = HashSet::new();
        let mut private_realtime_delivered = HashSet::new();
        let mut private_enqueue_stats = PrivateEnqueueStats::default();
        if let Some(private_state) = private_state
            && private_enabled
        {
            let Some(private_payload) = private_payload.as_ref() else {
                return Err(Error::Internal(
                    "private payload unavailable while private channel is enabled".to_string(),
                ));
            };
            let private_expires_at = effective_ttl.unwrap_or(sent_at + private_default_ttl_secs);
            for device_id in private_subscribers {
                match private_state
                    .enqueue_private_delivery(
                        device_id,
                        &delivery_id,
                        private_payload.clone(),
                        sent_at,
                        private_expires_at,
                    )
                    .await
                {
                    Ok(()) => {
                        private_enqueue_stats.record_success();
                        private_enqueued.insert(device_id);
                        if private_state.hub.is_online(device_id) {
                            let delivered = private_state.hub.try_deliver_to_device(
                                device_id,
                                crate::private::protocol::DeliverEnvelope {
                                    delivery_id: delivery_id.clone(),
                                    payload: private_payload.clone(),
                                },
                            );
                            if delivered {
                                private_realtime_delivered.insert(device_id);
                            } else {
                                private_state.metrics.mark_deliver_send_failure();
                            }
                        }
                    }
                    Err(err) => {
                        private_enqueue_stats.record_failure("private_subscriber", device_id, &err);
                        private_state.metrics.mark_enqueue_failure();
                    }
                }
            }
        }

        if devices.is_empty() {
            let private_enqueue_too_busy = private_enqueue_stats.is_too_busy();
            let partial_failure = private_enqueue_stats.has_failures();
            return Ok(NotificationDispatchSummary {
                channel_id: channel_id_value,
                op_id,
                delivery_id,
                partial_failure,
                private_enqueue_too_busy,
            });
        }

        let mut has_android = false;
        let mut has_apns = false;
        let mut has_wns = false;
        let mut has_watchos_apns = false;
        for device in &devices {
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

        let apns_payload = if has_apns {
            Some(Arc::new(ApnsPayload::new(
                resolved_title.clone(),
                resolved_body.clone(),
                provider_fallback_body.clone(),
                Some(channel_id_value.clone()),
                normalized_severity.clone(),
                effective_ttl,
                SharedStringMap::from(Arc::clone(&custom_data)),
            )))
        } else {
            None
        };
        let watchos_apns_payload = if has_watchos_apns {
            Some(Arc::new(ApnsPayload::new(
                resolved_title.clone(),
                resolved_body.clone(),
                provider_fallback_body.clone(),
                Some(channel_id_value.clone()),
                normalized_severity.clone(),
                effective_ttl,
                quantize_watch_payload(custom_data.as_ref()),
            )))
        } else {
            None
        };
        let apns_collapse_id = if has_apns {
            Some(Arc::from(delivery_id.clone().into_boxed_str()))
        } else {
            None
        };
        let fcm_payload = if has_android {
            Some(Arc::new(FcmPayload::new(
                SharedStringMap::from(Arc::clone(&custom_data)),
                priority,
                ttl_seconds,
            )))
        } else {
            None
        };
        let fcm_wakeup_payload = if has_android {
            Some(Arc::new(FcmPayload::new(
                SharedStringMap::from(Arc::clone(&wakeup_data)),
                "HIGH",
                ttl_seconds,
            )))
        } else {
            None
        };
        let wns_payload = if has_wns {
            Some(Arc::new(WnsPayload::new(
                SharedStringMap::from(Arc::clone(&custom_data)),
                normalized_severity.as_str(),
                ttl_seconds,
            )))
        } else {
            None
        };
        let wns_wakeup_payload = if has_wns {
            Some(Arc::new(WnsPayload::new(
                SharedStringMap::from(Arc::clone(&wakeup_data)),
                "high",
                ttl_seconds,
            )))
        } else {
            None
        };
        let apns_wakeup_payload = if has_apns {
            Some(Arc::new(ApnsPayload::wakeup(
                Some(channel_id_value.clone()),
                effective_ttl,
                SharedStringMap::from(Arc::clone(&wakeup_data)),
            )))
        } else {
            None
        };

        let total = devices.len();
        let mut rejected = 0usize;
        let mut dispatch_closed = false;
        let provider_private_expires_at =
            effective_ttl.unwrap_or(sent_at + private_default_ttl_secs);
        for (index, device) in devices.into_iter().enumerate() {
            let private_delivery_target = if let Some(private_state) = private_state {
                private_state
                    .device_registry
                    .find_device_key_by_provider_token(
                        platform_name(device.platform),
                        device.token_str.as_ref(),
                    )
                    .map(|device_key| DeviceRegistry::derive_private_device_id(device_key.as_str()))
                    .filter(|device_id| {
                        private_subscriber_set.contains(device_id)
                            && private_enqueued.contains(device_id)
                    })
            } else {
                None
            };
            let private_online = if let Some(device_id) = private_delivery_target {
                private_state
                    .map(|private| private.hub.is_online(device_id))
                    .unwrap_or(false)
            } else {
                false
            };
            if should_skip_provider_delivery(
                private_delivery_target,
                private_online,
                &private_realtime_delivered,
            ) {
                state.dispatch_audit.record(DispatchAuditRecord {
                    stage: "provider_skipped_private_realtime",
                    correlation_id: correlation_id.as_ref(),
                    delivery_id: Some(delivery_id.as_str()),
                    channel_id: Some(channel_id_value.as_str()),
                    provider: Some(provider_name(device.platform)),
                    platform: Some(device.platform),
                    path: None,
                    device_token: Some(device.token_str()),
                    success: None,
                    status_code: None,
                    invalid_token: None,
                    payload_too_large: None,
                    detail: Some(Cow::Borrowed(
                        "private realtime delivery already succeeded while device is online",
                    )),
                });
                continue;
            }
            let provider_device_key =
                resolve_provider_route_device_key(state, device.platform, device.token_str());
            let private_wakeup_delivery = build_private_wakeup_delivery(
                provider_device_key.as_deref(),
                private_payload.as_ref(),
                &delivery_id,
                sent_at,
                provider_private_expires_at,
            );
            let mut private_wakeup_enqueued = false;
            match device.platform {
                Platform::ANDROID => {
                    let direct_payload = fcm_payload
                        .clone()
                        .ok_or(Error::Internal("missing FCM payload".to_string()))?;
                    let wakeup_payload = fcm_wakeup_payload
                        .clone()
                        .ok_or(Error::Internal("missing FCM wakeup payload".to_string()))?;
                    let direct_body = direct_payload
                        .encoded_body(device.token_str())
                        .map_err(|err| Error::Internal(err.to_string()))?;
                    let wakeup_body = wakeup_payload
                        .encoded_body(device.token_str())
                        .map_err(|err| Error::Internal(err.to_string()))?;
                    let selection = match select_provider_delivery_path(
                        device.platform,
                        direct_body.len(),
                        wakeup_body.len(),
                        private_wakeup_delivery.is_some(),
                    ) {
                        Ok(value) => value,
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_path_rejected",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("FCM"),
                                platform: Some(device.platform),
                                path: None,
                                device_token: Some(device.token_str()),
                                success: None,
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(err.to_string().into()),
                            });
                            continue;
                        }
                    };
                    if selection.initial_path == ProviderDeliveryPath::WakeupPull
                        && let Some(private_state) = private_state
                        && let Some(private_meta) = private_wakeup_delivery.as_ref()
                    {
                        match private_state
                            .enqueue_private_delivery(
                                private_meta.device_id,
                                private_meta.delivery_id.as_ref(),
                                private_meta.payload.as_ref().clone(),
                                private_meta.sent_at,
                                private_meta.expires_at,
                            )
                            .await
                        {
                            Ok(()) => {
                                private_enqueue_stats.record_success();
                                private_wakeup_enqueued = true;
                            }
                            Err(err) => {
                                private_enqueue_stats.record_failure(
                                    "provider_wakeup",
                                    private_meta.device_id,
                                    &err,
                                );
                                private_state.metrics.mark_enqueue_failure();
                            }
                        }
                    }
                    match state.dispatch.try_send_fcm(FcmJob {
                        channel_id,
                        correlation_id: Arc::clone(&correlation_id),
                        delivery_id: Arc::clone(&delivery_id_ref),
                        device_token: Arc::from(device.token_str()),
                        direct_payload: Arc::clone(&direct_payload),
                        direct_body,
                        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
                        wakeup_body: Some(wakeup_body),
                        initial_path: selection.initial_path,
                        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
                        private_wakeup: private_wakeup_delivery.clone(),
                        private_wakeup_enqueued,
                    }) {
                        Ok(()) => {
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueued",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("FCM"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(true),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: None,
                            });
                        }
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueue_failed",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("FCM"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(false),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(dispatch_error_detail(&err).into()),
                            });
                            if matches!(err, DispatchError::ChannelClosed) {
                                dispatch_closed = true;
                            }
                        }
                    }
                }
                Platform::WINDOWS => {
                    let direct_payload = wns_payload
                        .clone()
                        .ok_or(Error::Internal("missing WNS payload".to_string()))?;
                    let wakeup_payload = wns_wakeup_payload
                        .clone()
                        .ok_or(Error::Internal("missing WNS wakeup payload".to_string()))?;
                    let selection = match select_provider_delivery_path(
                        device.platform,
                        direct_payload
                            .encoded_len()
                            .map_err(|err| Error::Internal(err.to_string()))?,
                        wakeup_payload
                            .encoded_len()
                            .map_err(|err| Error::Internal(err.to_string()))?,
                        private_wakeup_delivery.is_some(),
                    ) {
                        Ok(value) => value,
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_path_rejected",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("WNS"),
                                platform: Some(device.platform),
                                path: None,
                                device_token: Some(device.token_str()),
                                success: None,
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(err.to_string().into()),
                            });
                            continue;
                        }
                    };
                    if selection.initial_path == ProviderDeliveryPath::WakeupPull
                        && let Some(private_state) = private_state
                        && let Some(private_meta) = private_wakeup_delivery.as_ref()
                    {
                        match private_state
                            .enqueue_private_delivery(
                                private_meta.device_id,
                                private_meta.delivery_id.as_ref(),
                                private_meta.payload.as_ref().clone(),
                                private_meta.sent_at,
                                private_meta.expires_at,
                            )
                            .await
                        {
                            Ok(()) => {
                                private_enqueue_stats.record_success();
                                private_wakeup_enqueued = true;
                            }
                            Err(err) => {
                                private_enqueue_stats.record_failure(
                                    "provider_wakeup",
                                    private_meta.device_id,
                                    &err,
                                );
                                private_state.metrics.mark_enqueue_failure();
                            }
                        }
                    }
                    match state.dispatch.try_send_wns(WnsJob {
                        channel_id,
                        correlation_id: Arc::clone(&correlation_id),
                        delivery_id: Arc::clone(&delivery_id_ref),
                        device_token: Arc::from(device.token_str()),
                        direct_payload: Arc::clone(&direct_payload),
                        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
                        initial_path: selection.initial_path,
                        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
                        private_wakeup: private_wakeup_delivery.clone(),
                        private_wakeup_enqueued,
                    }) {
                        Ok(()) => {
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueued",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("WNS"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(true),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: None,
                            });
                        }
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueue_failed",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("WNS"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(false),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(dispatch_error_detail(&err).into()),
                            });
                            if matches!(err, DispatchError::ChannelClosed) {
                                dispatch_closed = true;
                            }
                        }
                    }
                }
                _ => {
                    let direct_payload = if device.platform == Platform::WATCHOS {
                        watchos_apns_payload.clone()
                    } else {
                        apns_payload.clone()
                    }
                    .ok_or(Error::Internal("missing APNs payload".to_string()))?;
                    let wakeup_payload = apns_wakeup_payload
                        .clone()
                        .ok_or(Error::Internal("missing APNs wakeup payload".to_string()))?;
                    let selection = match select_provider_delivery_path(
                        device.platform,
                        direct_payload
                            .encoded_len()
                            .map_err(|err| Error::Internal(err.to_string()))?,
                        wakeup_payload
                            .encoded_len()
                            .map_err(|err| Error::Internal(err.to_string()))?,
                        private_wakeup_delivery.is_some(),
                    ) {
                        Ok(value) => value,
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_path_rejected",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("APNS"),
                                platform: Some(device.platform),
                                path: None,
                                device_token: Some(device.token_str()),
                                success: None,
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(err.to_string().into()),
                            });
                            continue;
                        }
                    };
                    if selection.initial_path == ProviderDeliveryPath::WakeupPull
                        && let Some(private_state) = private_state
                        && let Some(private_meta) = private_wakeup_delivery.as_ref()
                    {
                        match private_state
                            .enqueue_private_delivery(
                                private_meta.device_id,
                                private_meta.delivery_id.as_ref(),
                                private_meta.payload.as_ref().clone(),
                                private_meta.sent_at,
                                private_meta.expires_at,
                            )
                            .await
                        {
                            Ok(()) => {
                                private_enqueue_stats.record_success();
                                private_wakeup_enqueued = true;
                            }
                            Err(err) => {
                                private_enqueue_stats.record_failure(
                                    "provider_wakeup",
                                    private_meta.device_id,
                                    &err,
                                );
                                private_state.metrics.mark_enqueue_failure();
                            }
                        }
                    }
                    match state.dispatch.try_send_apns(ApnsJob {
                        channel_id,
                        correlation_id: Arc::clone(&correlation_id),
                        delivery_id: Arc::clone(&delivery_id_ref),
                        device_token: Arc::from(device.token_str()),
                        platform: device.platform,
                        direct_payload: Arc::clone(&direct_payload),
                        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
                        initial_path: selection.initial_path,
                        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
                        private_wakeup: private_wakeup_delivery.clone(),
                        private_wakeup_enqueued,
                        collapse_id: apns_collapse_id.clone(),
                    }) {
                        Ok(()) => {
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueued",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("APNS"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(true),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: None,
                            });
                        }
                        Err(err) => {
                            rejected += 1;
                            state.dispatch_audit.record(DispatchAuditRecord {
                                stage: "provider_enqueue_failed",
                                correlation_id: correlation_id.as_ref(),
                                delivery_id: Some(delivery_id.as_str()),
                                channel_id: Some(channel_id_value.as_str()),
                                provider: Some("APNS"),
                                platform: Some(device.platform),
                                path: Some(provider_path_name(selection.initial_path)),
                                device_token: Some(device.token_str()),
                                success: Some(false),
                                status_code: None,
                                invalid_token: None,
                                payload_too_large: None,
                                detail: Some(dispatch_error_detail(&err).into()),
                            });
                            if matches!(err, DispatchError::ChannelClosed) {
                                dispatch_closed = true;
                            }
                        }
                    }
                }
            }
            if dispatch_closed {
                let remaining = total.saturating_sub(index + 1);
                rejected += remaining;
                break;
            }
        }

        let private_enqueue_too_busy = private_enqueue_stats.is_too_busy();
        let partial_failure = rejected > 0 || private_enqueue_stats.has_failures();

        Ok(NotificationDispatchSummary {
            channel_id: channel_id_value,
            op_id,
            delivery_id,
            partial_failure,
            private_enqueue_too_busy,
        })
    }
    .await;

    op_guard.finish(state, dispatch_result).await
}

fn encode_private_payload(data: &HashMap<String, String>) -> Result<Vec<u8>, postcard::Error> {
    #[derive(Serialize)]
    struct BorrowedPrivatePayloadEnvelope<'a> {
        payload_version: u8,
        data: &'a HashMap<String, String>,
    }

    postcard::to_allocvec(&BorrowedPrivatePayloadEnvelope {
        payload_version: PRIVATE_PAYLOAD_VERSION_V1,
        data,
    })
}

fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
    }
}

fn provider_name(platform: Platform) -> &'static str {
    match platform {
        Platform::ANDROID => "FCM",
        Platform::WINDOWS => "WNS",
        _ => "APNS",
    }
}

fn provider_path_name(path: ProviderDeliveryPath) -> &'static str {
    match path {
        ProviderDeliveryPath::Direct => "direct",
        ProviderDeliveryPath::WakeupPull => "wakeup_pull",
    }
}

fn dispatch_error_detail(error: &DispatchError) -> &'static str {
    match error {
        DispatchError::QueueFull => "dispatch queue is full",
        DispatchError::ChannelClosed => "dispatch worker channel is closed",
    }
}

struct StandardFields<'a> {
    channel_id: &'a str,
    title: Option<&'a str>,
    body: Option<&'a str>,
    severity: Option<&'a str>,
    schema_version: &'a str,
    payload_version: &'a str,
    op_id: &'a str,
    delivery_id: &'a str,
    sent_at: i64,
    ttl: Option<i64>,
    entity_type: &'a str,
    entity_id: &'a str,
}

fn add_standard_fields(data: &mut HashMap<String, String>, fields: StandardFields<'_>) {
    data.insert("channel_id".to_string(), fields.channel_id.to_string());
    if let Some(value) = fields.title.map(str::trim).filter(|text| !text.is_empty()) {
        data.insert("title".to_string(), value.to_string());
    }
    if let Some(value) = fields.body.map(str::trim).filter(|text| !text.is_empty()) {
        data.insert("body".to_string(), value.to_string());
    }
    if let Some(value) = fields
        .severity
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        data.insert("severity".to_string(), value.to_string());
    }
    data.insert(
        "schema_version".to_string(),
        fields.schema_version.to_string(),
    );
    data.insert(
        "payload_version".to_string(),
        fields.payload_version.to_string(),
    );
    data.insert("op_id".to_string(), fields.op_id.to_string());
    data.insert("delivery_id".to_string(), fields.delivery_id.to_string());
    data.insert("occurred_at".to_string(), fields.sent_at.to_string());
    data.insert("sent_at".to_string(), fields.sent_at.to_string());
    data.insert("entity_type".to_string(), fields.entity_type.to_string());
    data.insert("entity_id".to_string(), fields.entity_id.to_string());
    if let Some(ttl) = fields.ttl {
        data.insert("ttl".to_string(), ttl.to_string());
    }
}

fn sanitize_custom_data(data: &mut HashMap<String, String>) {
    // Guard reserved semantic fields so user-provided metadata cannot shadow
    // canonical entity fields in downstream clients.
    for key in [
        "title",
        "body",
        "channel_id",
        "level",
        "schema_version",
        "payload_version",
        "op_id",
        "delivery_id",
        "message_id",
        "occurred_at",
        "sent_at",
        "ttl",
        "entity_type",
        "entity_id",
        "event_id",
        "event_state",
        "event_time",
        "event_title",
        "event_description",
        "event_profile_json",
        "event_attrs_json",
        "event_unset_json",
        "severity",
        "tags",
        "attachments",
        "started_at",
        "ended_at",
        "thing_id",
        "thing_profile_json",
        "thing_attrs_json",
        "thing_unset_json",
        "image",
        "primary_image",
        "attachments",
        "created_at",
        "state",
        "deleted_at",
        "external_ids",
        "location_type",
        "location_value",
        "observed_at",
        "notify_user",
        "local_notify",
        "private_mode",
        "private_wakeup",
        "private_wakeup_handled",
        "_skip_persist",
    ] {
        data.remove(key);
    }
}

pub(super) fn validate_metadata_entries(metadata: &JsonMap<String, Value>) -> Result<(), Error> {
    let mut dedupe = std::collections::HashSet::new();
    for (raw_key, raw_value) in metadata {
        let key = raw_key.trim();
        if key.is_empty() {
            return Err(Error::validation("metadata key must not be empty"));
        }
        if key.len() > 64 {
            return Err(Error::validation("metadata key is too long"));
        }
        if !dedupe.insert(key.to_string()) {
            return Err(Error::validation("metadata key must be unique"));
        }

        if !metadata_is_scalar(raw_value) {
            return Err(Error::validation("metadata value must be scalar"));
        }
        let value = match raw_value {
            Value::String(value) => value.trim().to_string(),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            _ => unreachable!("metadata scalar validation already enforced"),
        };
        if value.is_empty() {
            return Err(Error::validation("metadata value must not be empty"));
        }
        if value.len() > 512 {
            return Err(Error::validation("metadata value is too long"));
        }
    }
    Ok(())
}

pub(super) fn encode_metadata(metadata: &JsonMap<String, Value>) -> Result<String, Error> {
    serde_json::to_string(metadata).map_err(|_| Error::validation("metadata format is invalid"))
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_tags(values: &[String], field: &str) -> Result<Vec<String>, Error> {
    const MAX_TAGS: usize = 32;
    const MAX_TAG_LEN: usize = 64;
    if values.len() > MAX_TAGS {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!("{field} contains empty tag")));
        }
        if trimmed.len() > MAX_TAG_LEN {
            return Err(Error::validation(format!("{field} contains oversized tag")));
        }
        if !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn normalize_image_values(values: &[String], field: &str) -> Result<Vec<String>, Error> {
    const MAX_IMAGES: usize = 32;
    const MAX_IMAGE_LEN: usize = 2048;
    if values.len() > MAX_IMAGES {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!("{field} contains empty url")));
        }
        if trimmed.len() > MAX_IMAGE_LEN {
            return Err(Error::validation(format!("{field} contains oversized url")));
        }
        if !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn normalize_thing_id(raw: &str) -> Result<&str, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("thing_id must not be empty"));
    }
    if trimmed.len() > 64 {
        return Err(Error::validation("thing_id is too long"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
    {
        return Err(Error::validation("thing_id format is invalid"));
    }
    Ok(trimmed)
}

const PAYLOAD_VERSION: &str = "1";
const SCHEMA_VERSION: &str = "1";
const MAX_PROVIDER_TTL_SECONDS: i64 = 2_592_000;

async fn reserve_new_delivery_id(state: &AppState, created_at: i64) -> Result<String, Error> {
    const MAX_ATTEMPTS: usize = 4;
    for _ in 0..MAX_ATTEMPTS {
        let delivery_id = generate_hex_id_128();
        let dedupe_key = build_delivery_dedupe_key(&delivery_id);
        let inserted = state
            .store
            .reserve_delivery_dedupe_async(dedupe_key.as_str(), &delivery_id, created_at)
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;
        if inserted {
            return Ok(delivery_id);
        }
    }
    Err(Error::Internal(
        "unable to reserve unique delivery id".to_string(),
    ))
}

fn build_op_scope(channel_id: &str, entity_type: &str, entity_id: &str) -> String {
    let normalized_type = normalize_scope_component(entity_type);
    let normalized_entity_id = normalize_scope_component(entity_id);
    format!("{channel_id}:{normalized_type}:{normalized_entity_id}")
}

pub(super) fn build_semantic_create_dedupe_key(
    channel_id: &str,
    entity_type: &str,
    scope_id: Option<&str>,
    op_id: &str,
) -> String {
    let scope = scope_id
        .map(normalize_scope_component)
        .unwrap_or_else(|| "-".to_string());
    format!(
        "semantic:{}:{}:{}:{}",
        normalize_scope_component(channel_id),
        normalize_scope_component(entity_type),
        scope,
        normalize_scope_component(op_id)
    )
}

pub(super) struct ResolvedSemanticId {
    pub semantic_id: String,
    pub reused: bool,
}

pub(super) async fn resolve_create_semantic_id(
    state: &AppState,
    dedupe_key: &str,
) -> Result<ResolvedSemanticId, Error> {
    const MAX_ATTEMPTS: usize = 8;
    let created_at = Utc::now().timestamp();
    for _ in 0..MAX_ATTEMPTS {
        let semantic_id = generate_hex_id_128();
        match state
            .store
            .reserve_semantic_id_async(dedupe_key, &semantic_id, created_at)
            .await
            .map_err(|err| Error::Internal(err.to_string()))?
        {
            crate::storage::SemanticIdReservation::Reserved => {
                return Ok(ResolvedSemanticId {
                    semantic_id,
                    reused: false,
                });
            }
            crate::storage::SemanticIdReservation::Existing { semantic_id } => {
                return Ok(ResolvedSemanticId {
                    semantic_id,
                    reused: true,
                });
            }
            crate::storage::SemanticIdReservation::Collision => continue,
        }
    }
    Err(Error::Internal(
        "unable to reserve unique semantic id".to_string(),
    ))
}

fn normalize_scope_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn build_op_dedupe_key(op_scope: &str, op_id: &str) -> String {
    format!("op:{op_scope}:{op_id}")
}

fn build_delivery_dedupe_key(delivery_id: &str) -> String {
    format!("delivery:{delivery_id}")
}

pub(super) fn normalize_op_id(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("op_id must not be empty"));
    }
    if trimmed.len() > 128 {
        return Err(Error::validation("op_id is too long"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
    {
        return Err(Error::validation("op_id format is invalid"));
    }
    Ok(trimmed.to_string())
}

fn normalize_severity(value: Option<String>) -> String {
    match normalize_optional_string(value)
        .map(|level| level.to_ascii_lowercase())
        .as_deref()
    {
        Some("critical") => "critical".to_string(),
        Some("high") => "high".to_string(),
        Some("low") => "low".to_string(),
        _ => "normal".to_string(),
    }
}

fn ttl_seconds_remaining(sent_at: i64, expires_at: i64) -> u32 {
    let remaining = (expires_at - sent_at).clamp(0, MAX_PROVIDER_TTL_SECONDS);
    remaining as u32
}

fn default_notification_body(entity_type: &str) -> &'static str {
    match entity_type {
        "event" => "Event updated.",
        "thing" => "Object updated.",
        _ => "You received a new message.",
    }
}

fn provider_payload_limit_bytes(platform: Platform) -> usize {
    match platform {
        Platform::ANDROID => FCM_PROVIDER_PAYLOAD_LIMIT_BYTES,
        Platform::WINDOWS => WNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
        _ => APNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
    }
}

fn select_provider_delivery_path(
    platform: Platform,
    direct_len: usize,
    wakeup_len: usize,
    wakeup_pull_available: bool,
) -> Result<ProviderDeliverySelection, Error> {
    let limit = provider_payload_limit_bytes(platform);
    let within_limit = |len: usize| match platform {
        Platform::WINDOWS => len < limit,
        _ => len <= limit,
    };
    let wakeup_payload_within_limit = within_limit(wakeup_len);
    if within_limit(direct_len) {
        return Ok(ProviderDeliverySelection {
            initial_path: ProviderDeliveryPath::Direct,
            wakeup_payload_within_limit,
        });
    }
    if !wakeup_pull_available {
        return Err(Error::validation(
            "provider payload exceeds size limit and wakeup path is unavailable",
        ));
    }
    if wakeup_payload_within_limit {
        return Ok(ProviderDeliverySelection {
            initial_path: ProviderDeliveryPath::WakeupPull,
            wakeup_payload_within_limit: true,
        });
    }
    Err(Error::validation("provider payload exceeds size limit"))
}

fn build_private_wakeup_delivery(
    provider_device_key: Option<&str>,
    private_payload: Option<&Vec<u8>>,
    delivery_id: &str,
    sent_at: i64,
    expires_at: i64,
) -> Option<PrivateWakeupDelivery> {
    let device_key = provider_device_key?;
    let payload = private_payload?;
    Some(PrivateWakeupDelivery {
        device_id: DeviceRegistry::derive_private_device_id(device_key),
        delivery_id: Arc::from(delivery_id.to_string().into_boxed_str()),
        payload: Arc::new(payload.clone()),
        sent_at,
        expires_at,
    })
}

fn resolve_provider_route_device_key(
    state: &AppState,
    platform: Platform,
    token: &str,
) -> Option<String> {
    let platform = match platform {
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
    };
    state
        .device_registry
        .resolve_provider_route_by_token(platform, token)
}

fn should_skip_provider_delivery(
    private_delivery_target: Option<[u8; 16]>,
    private_online: bool,
    private_realtime_delivered: &HashSet<[u8; 16]>,
) -> bool {
    private_delivery_target
        .is_some_and(|device_id| private_online && private_realtime_delivered.contains(&device_id))
}

#[cfg(test)]
mod tests {
    use super::{
        MessageIntent, StandardFields, add_standard_fields, select_provider_delivery_path,
        should_skip_provider_delivery,
    };
    use crate::{dispatch::ProviderDeliveryPath, storage::Platform};
    use hashbrown::HashMap;
    use serde_json::Map as JsonMap;
    use std::collections::HashSet;

    #[test]
    fn skip_provider_only_when_private_delivery_succeeds_while_online() {
        let device_id = [1u8; 16];
        let mut delivered = HashSet::new();
        delivered.insert(device_id);
        assert!(should_skip_provider_delivery(
            Some(device_id),
            true,
            &delivered
        ));
        assert!(!should_skip_provider_delivery(
            Some(device_id),
            false,
            &delivered
        ));
        assert!(!should_skip_provider_delivery(
            Some([2u8; 16]),
            true,
            &delivered
        ));
        assert!(!should_skip_provider_delivery(None, true, &delivered));
    }

    #[test]
    fn wakeup_pull_requires_available_private_wakeup_path() {
        let selection = select_provider_delivery_path(Platform::ANDROID, 5_000, 1_000, false);
        assert!(selection.is_err());
    }

    #[test]
    fn wakeup_pull_selected_when_direct_too_large_and_available() {
        let selection = select_provider_delivery_path(Platform::ANDROID, 5_000, 1_000, true)
            .expect("wakeup pull should be selected");
        assert_eq!(selection.initial_path, ProviderDeliveryPath::WakeupPull);
        assert!(selection.wakeup_payload_within_limit);
    }

    #[test]
    fn message_intent_accepts_markdown_link_body() {
        let body = "[https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV](https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV)\n\n无论可以玩玩。有上千个，\n\n\n\n[原文链接](https://www.v2ex.com/t/1200790)";
        let intent = MessageIntent {
            channel_id: "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
            password: "pass-123".to_string(),
            op_id: "op-123".to_string(),
            thing_id: None,
            title: "sample".to_string(),
            body: Some(body.to_string()),
            severity: None,
            ttl: None,
            url: None,
            images: Vec::new(),
            ciphertext: None,
            tags: Vec::new(),
            metadata: JsonMap::new(),
        };
        intent
            .validate_payload()
            .expect("markdown body should pass validation");
    }

    #[test]
    fn add_standard_fields_keeps_markdown_link_body() {
        let body = "[https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV](https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV)\n\n无论可以玩玩。有上千个，\n\n\n\n[原文链接](https://www.v2ex.com/t/1200790)";
        let mut data = HashMap::new();
        add_standard_fields(
            &mut data,
            StandardFields {
                channel_id: "06J0FZG1Y8XGG14VTQ4Y3G10MR",
                title: Some("sample"),
                body: Some(body),
                severity: None,
                schema_version: "1",
                payload_version: "1",
                op_id: "op-123",
                delivery_id: "d-123",
                sent_at: 1_710_000_000,
                ttl: None,
                entity_type: "message",
                entity_id: "m-123",
            },
        );
        assert_eq!(data.get("body"), Some(&body.to_string()));
    }
}
