use std::{borrow::Cow, collections::HashSet, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use serde_json::{Map as JsonMap, Value};

use crate::{
    api::{
        ApiJson, Error, HttpResult, deserialize_empty_as_none, deserialize_i64_lenient,
        format_channel_id, parse_channel_id, validate_channel_password,
    },
    app::AppState,
    device_registry::DeviceRegistry,
    dispatch::{
        ApnsJob, DispatchError, FcmJob, PrivateWakeupDelivery, ProviderDeliveryPath, WnsJob,
        audit::DispatchAuditRecord,
    },
    private::protocol::PRIVATE_PAYLOAD_VERSION_V1,
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    stats::{DeviceDispatchDelta, DispatchStatsEvent},
    storage::{DeliveryAuditWrite, DeviceInfo, DispatchTarget, Platform, StoreError},
    util::{SharedStringMap, build_wakeup_data, encode_lower_hex_128, generate_hex_id_128},
};

use super::dispatch_lifecycle::{
    DispatchOpGuard, DispatchOpGuardStart, NotificationDispatchSummary,
    dispatch_failure_error_message,
};
use super::watch_light::quantize_watch_payload;

mod compat;
pub(crate) use compat::{
    compat_bark_v1_body, compat_bark_v1_title_body, compat_bark_v2_push, compat_ntfy_get,
    compat_ntfy_post, compat_ntfy_put, compat_serverchan_get, compat_serverchan_post,
    message_to_channel_get,
};

fn apple_thread_id_for_payload(
    channel_id: &str,
    entity_type: &str,
    event_id: Option<&str>,
    thing_id: Option<&str>,
) -> String {
    let normalized_type = entity_type.trim().to_ascii_lowercase();
    let mut parts = vec![match normalized_type.as_str() {
        "event" => "event".to_string(),
        "thing" => "thing".to_string(),
        _ => "message".to_string(),
    }];
    let trimmed_channel = channel_id.trim();
    if !trimmed_channel.is_empty() {
        parts.push(format!("channel={trimmed_channel}"));
    }
    if (normalized_type == "event" || normalized_type == "thing")
        && let Some(event_id) = event_id.map(str::trim).filter(|value| !value.is_empty())
    {
        parts.push(format!("event={event_id}"));
    }
    if normalized_type == "thing"
        && let Some(thing_id) = thing_id.map(str::trim).filter(|value| !value.is_empty())
    {
        parts.push(format!("thing={thing_id}"));
    }
    parts.join("|")
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageIntent {
    pub channel_id: String,
    pub password: String,
    #[serde(default, deserialize_with = "deserialize_empty_as_none")]
    pub op_id: Option<String>,
    pub thing_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_i64_lenient")]
    pub occurred_at: Option<i64>,
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
        if let Some(op_id) = self.op_id.as_deref() {
            normalize_op_id(op_id)?;
        }
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

pub(super) fn parse_metadata_map_value(raw: Value) -> Result<JsonMap<String, Value>, String> {
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
const AUDIT_PATH_PRIVATE_OUTBOX: &str = "private_outbox";
const AUDIT_PATH_PROVIDER: &str = "provider";
const AUDIT_STATUS_ENQUEUED: &str = "enqueued";
const AUDIT_STATUS_ENQUEUE_FAILED: &str = "enqueue_failed";
const AUDIT_STATUS_PATH_REJECTED: &str = "path_rejected";
const AUDIT_STATUS_SKIPPED_PRIVATE_REALTIME: &str = "skipped_private_realtime";

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

pub(super) async fn dispatch_message_intent(
    state: &AppState,
    payload: MessageIntent,
    scoped_thing_id: Option<String>,
) -> HttpResult {
    payload.validate_payload()?;
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let channel_id_value = format_channel_id(&channel_id);
    let password = validate_channel_password(&payload.password)?;
    state
        .store
        .channel_info_with_password(channel_id, password)
        .await?
        .ok_or(StoreError::ChannelNotFound)?;

    let MessageIntent {
        op_id,
        occurred_at,
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
    let occurred_at = if scoped_thing_id.is_some() {
        occurred_at.ok_or_else(|| {
            Error::validation_code(
                "occurred_at is required when message is scoped to thing_id",
                "occurred_at_required_for_thing_scoped_message",
            )
        })?
    } else {
        occurred_at.unwrap_or_else(|| Utc::now().timestamp())
    };
    let normalized_body = normalize_optional_string(body);
    let normalized_url = normalize_optional_string(url);
    let normalized_images = normalize_image_values(&images, "images")?;

    let op_id = resolve_op_id(op_id.as_deref())?;
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
        occurred_at,
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
    occurred_at: i64,
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
        let dispatch_targets = state
            .store
            .list_channel_dispatch_targets(channel_id, sent_at)
            .await?;

        let private_state = state.private.as_ref();
        let private_enabled = state.private_channel_enabled && private_state.is_some();
        let private_default_ttl_secs = private_state
            .map(|private| private.config.default_ttl_secs)
            .unwrap_or(MAX_PROVIDER_TTL_SECONDS)
            .clamp(0, MAX_PROVIDER_TTL_SECONDS);

        let mut private_subscribers = Vec::new();
        let mut devices = Vec::new();
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
                    let info = DeviceInfo::from_token(platform, provider_token.as_str())?;
                    devices.push(info);
                }
                _ => {}
            }
        }
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
                ingested_at: sent_at,
                occurred_at,
                sent_at,
                ttl: effective_ttl,
                entity_type,
                entity_id: &entity_id,
            },
        );
        for (key, value) in extra_fields {
            custom_data.insert(key, value);
        }
        let apple_thread_id = apple_thread_id_for_payload(
            channel_id_value.as_str(),
            entity_type,
            custom_data.get("event_id").map(String::as_str),
            custom_data.get("thing_id").map(String::as_str),
        );
        let custom_data = Arc::new(custom_data);
        let wakeup_data = Arc::new(build_wakeup_data(custom_data.as_ref()));
        let private_payload = encode_private_payload(custom_data.as_ref())
            .map_err(|err| Error::Internal(format!("private payload encoding failed: {err}")))?;

        let mut private_enqueued = HashSet::new();
        let mut private_realtime_delivered = HashSet::new();
        let mut private_enqueue_stats = PrivateEnqueueStats::default();
        let mut provider_attempted = 0i64;
        let mut provider_success = 0i64;
        let mut provider_failed = 0i64;
        let mut device_stats = HashMap::<Arc<str>, DeviceDispatchDelta>::new();
        if let Some(private_state) = private_state
            && private_enabled
        {
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
                        let private_stats_key = Arc::<str>::from(
                            format!("private:{}", encode_lower_hex_128(&device_id))
                                .into_boxed_str(),
                        );
                        merge_device_dispatch_delta(
                            &mut device_stats,
                            private_stats_key,
                            DeviceDispatchDelta {
                                messages_received: 1,
                                private_outbox_enqueued_count: 1,
                                ..DeviceDispatchDelta::default()
                            },
                        );
                        append_delivery_audit_best_effort(
                            state,
                            correlation_id.as_ref(),
                            &DeliveryAuditWrite {
                                delivery_id: delivery_id.clone(),
                                channel_id,
                                device_key: format!("private:{}", encode_lower_hex_128(&device_id)),
                                entity_type: Some(entity_type.to_string()),
                                entity_id: Some(entity_id.clone()),
                                op_id: Some(op_id.clone()),
                                path: AUDIT_PATH_PRIVATE_OUTBOX.to_string(),
                                status: AUDIT_STATUS_ENQUEUED.to_string(),
                                error_code: None,
                                created_at: sent_at,
                            },
                        )
                        .await;
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
                        append_delivery_audit_best_effort(
                            state,
                            correlation_id.as_ref(),
                            &DeliveryAuditWrite {
                                delivery_id: delivery_id.clone(),
                                channel_id,
                                device_key: format!("private:{}", encode_lower_hex_128(&device_id)),
                                entity_type: Some(entity_type.to_string()),
                                entity_id: Some(entity_id.clone()),
                                op_id: Some(op_id.clone()),
                                path: AUDIT_PATH_PRIVATE_OUTBOX.to_string(),
                                status: AUDIT_STATUS_ENQUEUE_FAILED.to_string(),
                                error_code: Some("private_enqueue_failed".to_string()),
                                created_at: sent_at,
                            },
                        )
                        .await;
                    }
                }
            }
        }

        if devices.is_empty() {
            let private_enqueue_too_busy = private_enqueue_stats.is_too_busy();
            let partial_failure = private_enqueue_stats.has_failures();
            emit_dispatch_stats(
                state,
                channel_id,
                sent_at,
                1,
                private_enqueue_stats.attempted as i64,
                provider_attempted,
                provider_success,
                provider_failed,
                private_realtime_delivered.len() as i64,
                device_stats,
            );
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
                Some(apple_thread_id.clone()),
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
                Some(apple_thread_id.clone()),
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
        let wns_payload = if has_wns {
            Some(Arc::new(WnsPayload::new(
                SharedStringMap::from(Arc::clone(&custom_data)),
                normalized_severity.as_str(),
                ttl_seconds,
            )))
        } else {
            None
        };
        let apns_wakeup_title =
            has_apns.then(|| wakeup_fallback_title(entity_type, resolved_title.as_deref()));

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
            let provider_device_key =
                resolve_provider_route_device_key(state, device.platform, device.token_str());
            let provider_audit_key = provider_audit_device_key(
                provider_device_key.as_deref(),
                device.platform,
                device.token_str(),
            );
            let provider_stats_key = Arc::<str>::from(provider_audit_key.clone().into_boxed_str());
            if should_skip_provider_delivery(
                private_delivery_target,
                private_online,
                &private_realtime_delivered,
            ) {
                append_delivery_audit_best_effort(
                    state,
                    correlation_id.as_ref(),
                    &DeliveryAuditWrite {
                        delivery_id: delivery_id.clone(),
                        channel_id,
                        device_key: provider_audit_key.clone(),
                        entity_type: Some(entity_type.to_string()),
                        entity_id: Some(entity_id.clone()),
                        op_id: Some(op_id.clone()),
                        path: AUDIT_PATH_PROVIDER.to_string(),
                        status: AUDIT_STATUS_SKIPPED_PRIVATE_REALTIME.to_string(),
                        error_code: None,
                        created_at: sent_at,
                    },
                )
                .await;
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
            let provider_pull_delivery_id = derive_provider_pull_delivery_id(
                delivery_id.as_str(),
                device.platform,
                device.token_str(),
            );
            let wakeup_data_for_device = Arc::new(wakeup_data_with_delivery_id(
                wakeup_data.as_ref(),
                provider_pull_delivery_id.as_str(),
            ));
            let private_wakeup_delivery = build_private_wakeup_delivery(
                provider_device_key.as_deref(),
                device.platform,
                device.token_str(),
                &private_payload,
                provider_pull_delivery_id.as_str(),
                sent_at,
                provider_private_expires_at,
            );
            match device.platform {
                Platform::ANDROID => {
                    let direct_payload = fcm_payload
                        .clone()
                        .ok_or(Error::Internal("missing FCM payload".to_string()))?;
                    let wakeup_payload = Arc::new(FcmPayload::new(
                        SharedStringMap::from(Arc::clone(&wakeup_data_for_device)),
                        "HIGH",
                        ttl_seconds,
                    ));
                    let direct_body = direct_payload
                        .encoded_body(device.token_str())
                        .map_err(|err| Error::Internal(err.to_string()))?;
                    let mut wakeup_body = None;
                    let selection =
                        if provider_payload_len_within_limit(device.platform, direct_body.len()) {
                            // Keep hot path lean: skip wakeup body encoding unless direct payload already over limit.
                            ProviderDeliverySelection {
                                initial_path: ProviderDeliveryPath::Direct,
                                wakeup_payload_within_limit: false,
                            }
                        } else if private_wakeup_delivery.is_none() {
                            rejected += 1;
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: AUDIT_PATH_PROVIDER.to_string(),
                                    status: AUDIT_STATUS_PATH_REJECTED.to_string(),
                                    error_code: Some("provider_path_rejected".to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                            detail: Some(
                                "provider payload exceeds size limit and wakeup path is unavailable"
                                    .into(),
                            ),
                        });
                            continue;
                        } else {
                            let encoded_wakeup = wakeup_payload
                                .encoded_body(device.token_str())
                                .map_err(|err| Error::Internal(err.to_string()))?;
                            if !provider_payload_len_within_limit(
                                device.platform,
                                encoded_wakeup.len(),
                            ) {
                                rejected += 1;
                                provider_attempted += 1;
                                provider_failed += 1;
                                merge_device_dispatch_delta(
                                    &mut device_stats,
                                    Arc::clone(&provider_stats_key),
                                    DeviceDispatchDelta {
                                        provider_failure_count: 1,
                                        ..DeviceDispatchDelta::default()
                                    },
                                );
                                append_delivery_audit_best_effort(
                                    state,
                                    correlation_id.as_ref(),
                                    &DeliveryAuditWrite {
                                        delivery_id: delivery_id.clone(),
                                        channel_id,
                                        device_key: provider_audit_key.clone(),
                                        entity_type: Some(entity_type.to_string()),
                                        entity_id: Some(entity_id.clone()),
                                        op_id: Some(op_id.clone()),
                                        path: AUDIT_PATH_PROVIDER.to_string(),
                                        status: AUDIT_STATUS_PATH_REJECTED.to_string(),
                                        error_code: Some("provider_path_rejected".to_string()),
                                        created_at: sent_at,
                                    },
                                )
                                .await;
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
                                    detail: Some("provider payload exceeds size limit".into()),
                                });
                                continue;
                            }
                            wakeup_body = Some(encoded_wakeup);
                            ProviderDeliverySelection {
                                initial_path: ProviderDeliveryPath::WakeupPull,
                                wakeup_payload_within_limit: true,
                            }
                        };
                    match state.dispatch.try_send_fcm(FcmJob {
                        channel_id,
                        correlation_id: Arc::clone(&correlation_id),
                        delivery_id: Arc::clone(&delivery_id_ref),
                        device_token: Arc::from(device.token_str()),
                        direct_payload: Arc::clone(&direct_payload),
                        direct_body,
                        wakeup_payload: Some(Arc::clone(&wakeup_payload)),
                        wakeup_body,
                        initial_path: selection.initial_path,
                        wakeup_payload_within_limit: selection.wakeup_payload_within_limit,
                        private_wakeup: private_wakeup_delivery.clone(),
                    }) {
                        Ok(()) => {
                            provider_attempted += 1;
                            provider_success += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    messages_received: 1,
                                    provider_success_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUED.to_string(),
                                    error_code: None,
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUE_FAILED.to_string(),
                                    error_code: Some(dispatch_error_code(&err).to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                    let wakeup_payload = Arc::new(WnsPayload::new(
                        SharedStringMap::from(Arc::clone(&wakeup_data_for_device)),
                        "high",
                        ttl_seconds,
                    ));
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
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: AUDIT_PATH_PROVIDER.to_string(),
                                    status: AUDIT_STATUS_PATH_REJECTED.to_string(),
                                    error_code: Some("provider_path_rejected".to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                    }) {
                        Ok(()) => {
                            provider_attempted += 1;
                            provider_success += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    messages_received: 1,
                                    provider_success_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUED.to_string(),
                                    error_code: None,
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUE_FAILED.to_string(),
                                    error_code: Some(dispatch_error_code(&err).to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                    let wakeup_payload = Arc::new(ApnsPayload::wakeup(
                        apns_wakeup_title.clone(),
                        Some(channel_id_value.clone()),
                        effective_ttl,
                        SharedStringMap::from(Arc::clone(&wakeup_data_for_device)),
                    ));
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
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: AUDIT_PATH_PROVIDER.to_string(),
                                    status: AUDIT_STATUS_PATH_REJECTED.to_string(),
                                    error_code: Some("provider_path_rejected".to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                        collapse_id: apns_collapse_id.clone(),
                    }) {
                        Ok(()) => {
                            provider_attempted += 1;
                            provider_success += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    messages_received: 1,
                                    provider_success_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUED.to_string(),
                                    error_code: None,
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
                            provider_attempted += 1;
                            provider_failed += 1;
                            merge_device_dispatch_delta(
                                &mut device_stats,
                                Arc::clone(&provider_stats_key),
                                DeviceDispatchDelta {
                                    provider_failure_count: 1,
                                    ..DeviceDispatchDelta::default()
                                },
                            );
                            append_delivery_audit_best_effort(
                                state,
                                correlation_id.as_ref(),
                                &DeliveryAuditWrite {
                                    delivery_id: delivery_id.clone(),
                                    channel_id,
                                    device_key: provider_audit_key.clone(),
                                    entity_type: Some(entity_type.to_string()),
                                    entity_id: Some(entity_id.clone()),
                                    op_id: Some(op_id.clone()),
                                    path: provider_path_name(selection.initial_path).to_string(),
                                    status: AUDIT_STATUS_ENQUEUE_FAILED.to_string(),
                                    error_code: Some(dispatch_error_code(&err).to_string()),
                                    created_at: sent_at,
                                },
                            )
                            .await;
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
        emit_dispatch_stats(
            state,
            channel_id,
            sent_at,
            1,
            private_enqueue_stats.attempted as i64 + provider_attempted,
            provider_attempted,
            provider_success,
            provider_failed,
            private_realtime_delivered.len() as i64,
            device_stats,
        );

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

fn merge_device_dispatch_delta(
    aggregates: &mut HashMap<Arc<str>, DeviceDispatchDelta>,
    device_key: Arc<str>,
    delta: DeviceDispatchDelta,
) {
    let entry = aggregates.entry(device_key).or_default();
    entry.messages_received += delta.messages_received;
    entry.messages_acked += delta.messages_acked;
    entry.private_connected_count += delta.private_connected_count;
    entry.private_pull_count += delta.private_pull_count;
    entry.provider_success_count += delta.provider_success_count;
    entry.provider_failure_count += delta.provider_failure_count;
    entry.private_outbox_enqueued_count += delta.private_outbox_enqueued_count;
}

#[allow(clippy::too_many_arguments)]
fn emit_dispatch_stats(
    state: &AppState,
    channel_id: [u8; 16],
    occurred_at: i64,
    messages_routed: i64,
    deliveries_attempted: i64,
    provider_attempted: i64,
    provider_success: i64,
    provider_failed: i64,
    private_realtime_delivered: i64,
    device_stats: HashMap<Arc<str>, DeviceDispatchDelta>,
) {
    let active_private_sessions_max = state
        .private
        .as_ref()
        .map(|private| private.automation_stats().session_count as i64)
        .unwrap_or(0);

    state.stats.record_dispatch(DispatchStatsEvent {
        channel_id,
        occurred_at,
        messages_routed,
        deliveries_attempted,
        deliveries_acked: 0,
        private_enqueued: device_stats
            .values()
            .map(|value| value.private_outbox_enqueued_count)
            .sum(),
        provider_attempted,
        provider_failed,
        provider_success,
        private_realtime_delivered,
        active_private_sessions_max,
        device_deltas: device_stats
            .into_iter()
            .map(|(device_key, delta)| DeviceDispatchDelta {
                device_key: device_key.to_string(),
                ..delta
            })
            .collect(),
    });
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

fn dispatch_error_code(error: &DispatchError) -> &'static str {
    match error {
        DispatchError::QueueFull => "queue_full",
        DispatchError::ChannelClosed => "channel_closed",
    }
}

fn provider_audit_device_key(
    provider_device_key: Option<&str>,
    platform: Platform,
    token: &str,
) -> String {
    if let Some(device_key) = provider_device_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return device_key.to_string();
    }
    let token_hash = blake3::hash(token.as_bytes());
    let mut short = [0u8; 16];
    short.copy_from_slice(&token_hash.as_bytes()[..16]);
    format!(
        "provider:{}:{}",
        platform_name(platform),
        encode_lower_hex_128(&short)
    )
}

async fn append_delivery_audit_best_effort(
    state: &AppState,
    correlation_id: &str,
    entry: &DeliveryAuditWrite,
) {
    state.delivery_audit.enqueue(correlation_id, entry);
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
    ingested_at: i64,
    occurred_at: i64,
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
    data.insert("ingested_at".to_string(), fields.ingested_at.to_string());
    data.insert("occurred_at".to_string(), fields.occurred_at.to_string());
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
        "ingested_at",
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

pub(super) fn normalize_thing_id(raw: &str) -> Result<&str, Error> {
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
            .reserve_delivery_dedupe(dedupe_key.as_str(), &delivery_id, created_at)
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
            .reserve_semantic_id(dedupe_key, &semantic_id, created_at)
            .await
            .map_err(|err| Error::Internal(err.to_string()))?
        {
            crate::storage::SemanticIdReservation::Reserved => {
                return Ok(ResolvedSemanticId { semantic_id });
            }
            crate::storage::SemanticIdReservation::Existing { semantic_id } => {
                return Ok(ResolvedSemanticId { semantic_id });
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

pub(super) fn resolve_op_id(raw: Option<&str>) -> Result<String, Error> {
    match raw {
        Some(value) => normalize_op_id(value),
        None => Ok(generate_hex_id_128()),
    }
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

fn wakeup_fallback_title(entity_type: &str, message_title: Option<&str>) -> String {
    if entity_type == "message"
        && let Some(trimmed_title) = message_title
            .map(str::trim)
            .filter(|value| !value.is_empty())
    {
        return trimmed_title.to_string();
    }
    "You have a new notification.".to_string()
}

fn derive_provider_pull_delivery_id(
    dispatch_delivery_id: &str,
    platform: Platform,
    provider_token: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dispatch_delivery_id.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(platform_name(platform).as_bytes());
    hasher.update(b"|");
    hasher.update(provider_token.trim().as_bytes());
    let digest = hasher.finalize();
    let mut short = [0u8; 16];
    short.copy_from_slice(&digest.as_bytes()[..16]);
    encode_lower_hex_128(&short)
}

fn wakeup_data_with_delivery_id(
    wakeup_template: &HashMap<String, String>,
    delivery_id: &str,
) -> HashMap<String, String> {
    let mut data = wakeup_template.clone();
    data.insert("delivery_id".to_string(), delivery_id.to_string());
    data
}

fn provider_payload_limit_bytes(platform: Platform) -> usize {
    match platform {
        Platform::ANDROID => FCM_PROVIDER_PAYLOAD_LIMIT_BYTES,
        Platform::WINDOWS => WNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
        _ => APNS_PROVIDER_PAYLOAD_LIMIT_BYTES,
    }
}

fn provider_payload_len_within_limit(platform: Platform, len: usize) -> bool {
    let limit = provider_payload_limit_bytes(platform);
    match platform {
        Platform::WINDOWS => len < limit,
        _ => len <= limit,
    }
}

fn select_provider_delivery_path(
    platform: Platform,
    direct_len: usize,
    wakeup_len: usize,
    wakeup_pull_available: bool,
) -> Result<ProviderDeliverySelection, Error> {
    let wakeup_payload_within_limit = provider_payload_len_within_limit(platform, wakeup_len);
    if provider_payload_len_within_limit(platform, direct_len) {
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
    platform: Platform,
    provider_token: &str,
    private_payload: &[u8],
    delivery_id: &str,
    sent_at: i64,
    expires_at: i64,
) -> Option<PrivateWakeupDelivery> {
    let normalized_token = provider_token.trim();
    if normalized_token.is_empty() {
        return None;
    }
    let device_id = provider_device_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(DeviceRegistry::derive_private_device_id)
        .unwrap_or_else(|| {
            let token_hash = blake3::hash(normalized_token.as_bytes());
            let mut short = [0u8; 16];
            short.copy_from_slice(&token_hash.as_bytes()[..16]);
            short
        });
    Some(PrivateWakeupDelivery {
        device_id,
        platform,
        provider_token: Arc::from(normalized_token.to_string().into_boxed_str()),
        delivery_id: Arc::from(delivery_id.to_string().into_boxed_str()),
        payload: Arc::new(private_payload.to_owned()),
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
        MessageIntent, StandardFields, add_standard_fields, derive_provider_pull_delivery_id,
        provider_payload_len_within_limit, resolve_op_id, select_provider_delivery_path,
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
    fn wakeup_pull_requires_available_wakeup_path() {
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
            op_id: Some("op-123".to_string()),
            thing_id: None,
            occurred_at: Some(1_710_000_000),
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
                ingested_at: 1_710_000_001,
                occurred_at: 1_710_000_000,
                sent_at: 1_710_000_000,
                ttl: None,
                entity_type: "message",
                entity_id: "m-123",
            },
        );
        assert_eq!(data.get("body"), Some(&body.to_string()));
    }

    #[test]
    fn resolve_op_id_uses_provided_value() {
        let resolved = resolve_op_id(Some("provided-op-id")).expect("op_id should be accepted");
        assert_eq!(resolved, "provided-op-id");
    }

    #[test]
    fn resolve_op_id_generates_when_absent() {
        let resolved = resolve_op_id(None).expect("op_id should be generated");
        assert_eq!(resolved.len(), 32);
        assert!(resolved.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn provider_payload_limit_boundary_matches_platform_rules() {
        // Android/APNs use <= limit.
        assert!(provider_payload_len_within_limit(Platform::ANDROID, 4096));
        assert!(!provider_payload_len_within_limit(Platform::ANDROID, 4097));
        assert!(provider_payload_len_within_limit(Platform::IOS, 4096));
        assert!(!provider_payload_len_within_limit(Platform::IOS, 4097));

        // WNS uses strict < limit.
        assert!(provider_payload_len_within_limit(Platform::WINDOWS, 5119));
        assert!(!provider_payload_len_within_limit(Platform::WINDOWS, 5120));
    }

    #[test]
    fn provider_pull_delivery_id_is_stable_for_same_device() {
        let first = derive_provider_pull_delivery_id("base-delivery", Platform::IOS, "token-a");
        let second = derive_provider_pull_delivery_id("base-delivery", Platform::IOS, "token-a");
        assert_eq!(first, second);
    }

    #[test]
    fn provider_pull_delivery_id_differs_across_devices() {
        let ios = derive_provider_pull_delivery_id("base-delivery", Platform::IOS, "token-a");
        let mac = derive_provider_pull_delivery_id("base-delivery", Platform::MACOS, "token-b");
        assert_ne!(ios, mac);
    }
}
