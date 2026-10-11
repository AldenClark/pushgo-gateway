use axum::extract::State;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    api::{ApiJson, Error, HttpResult},
    app::AppState,
    routing::DeviceChannelType,
    storage::{Platform, RouteTransitionPrepareRecord, RouteTransitionRecord, StoreError},
    value::{DeviceKeyRef, ProviderTokenRef},
};

use super::device_channels::{lock_provider_route_owners, reconcile_coalesced_route_owners};
use super::shared::platform_from_str;

const ROUTE_TRANSITION_TTL_MILLIS: i64 = 10 * 60 * 1000;

#[derive(Debug, Deserialize)]
pub(crate) struct RouteTransitionPrepareRequest {
    operation_id: String,
    device_key: String,
    platform: String,
    expected_route_revision: i64,
    candidate: RouteTransitionCandidate,
}

#[derive(Debug, Deserialize)]
struct RouteTransitionCandidate {
    channel_type: String,
    provider_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RouteTransitionIdentityRequest {
    transition_id: String,
    operation_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RouteTransitionQueryRequest {
    transition_id: Option<String>,
    device_key: Option<String>,
    operation_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RouteTransitionPreparedResponse {
    transition_id: String,
    state: String,
    base_revision: i64,
    candidate_fingerprint: String,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
struct RouteTransitionCommitResponse {
    transition_id: String,
    state: String,
    previous_revision: i64,
    route_revision: i64,
    channel_type: String,
    migrated_pending_count: usize,
}

#[derive(Debug, Serialize)]
struct RouteTransitionQueryResponse {
    transition_id: String,
    state: String,
    base_revision: i64,
    candidate_fingerprint: String,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    committed_revision: Option<i64>,
    candidate_channel_type: String,
    route_revision: Option<i64>,
    channel_type: Option<String>,
    current_provider_token_sha256: Option<String>,
}

fn validated_id<'a>(value: &'a str, field: &'static str) -> Result<&'a str, Error> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(Error::validation_code(
            format!("invalid {field}"),
            format!("invalid_{field}"),
        ));
    }
    Ok(value)
}

fn map_transition_error(err: StoreError) -> Error {
    match err {
        StoreError::RouteTransitionRevisionConflict { .. } => Error::Conflict {
            message: "route revision changed before transition completed".into(),
            code: "route_transition_revision_conflict".into(),
        },
        StoreError::RouteTransitionExpired => Error::Conflict {
            message: "route transition expired".into(),
            code: "route_transition_expired".into(),
        },
        StoreError::RouteTransitionAborted => Error::Conflict {
            message: "route transition was aborted".into(),
            code: "route_transition_aborted".into(),
        },
        StoreError::RouteMigrationCapacityExceeded { .. } => Error::Conflict {
            message: "pending deliveries exceed private route capacity".into(),
            code: "route_transition_pending_capacity_exceeded".into(),
        },
        StoreError::RouteTransitionNotFound => {
            Error::validation_code("route transition not found", "route_transition_not_found")
        }
        StoreError::RouteTransitionOperationConflict => Error::Conflict {
            message: "operation_id does not match the original route transition".into(),
            code: "route_transition_operation_conflict".into(),
        },
        StoreError::RouteTransitionUnsupported => Error::Conflict {
            message: "route_transition_v2 is unavailable for this storage backend".into(),
            code: "route_transition_unsupported".into(),
        },
        other => Error::StoreError(other),
    }
}

fn prepared_response(record: RouteTransitionRecord) -> RouteTransitionPreparedResponse {
    RouteTransitionPreparedResponse {
        transition_id: record.transition_id,
        state: record.state,
        base_revision: record.base_revision,
        candidate_fingerprint: record.candidate_fingerprint,
        expires_at: record.expires_at,
    }
}

pub(crate) async fn prepare(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<RouteTransitionPrepareRequest>,
) -> HttpResult {
    if !state.store.supports_route_transition_v2() {
        return Err(map_transition_error(StoreError::RouteTransitionUnsupported));
    }
    let operation_id = validated_id(&payload.operation_id, "operation_id")?;
    let device_key = DeviceKeyRef::parse(&payload.device_key)?;
    let platform = platform_from_str(&payload.platform)?;
    let current = state
        .device_registry
        .get(device_key.as_str())
        .ok_or_else(|| Error::validation_code("device_key not found", "device_key_not_found"))?;
    if current.platform != platform {
        return Err(Error::validation_code(
            "platform does not match device identity",
            "platform_mismatch",
        ));
    }
    let channel_type = DeviceChannelType::parse(&payload.candidate.channel_type)
        .ok_or_else(|| Error::validation_code("invalid channel_type", "invalid_channel_type"))?;
    let provider_token = normalize_candidate_token(
        platform,
        channel_type,
        payload.candidate.provider_token.as_deref(),
    )?;
    let fingerprint = blake3::hash(
        format!(
            "{}\0{}\0{}\0{}\0{}",
            device_key.as_str(),
            platform.name(),
            payload.expected_route_revision,
            channel_type.as_str(),
            provider_token.as_deref().unwrap_or("")
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string();
    let now = chrono::Utc::now().timestamp_millis();
    let record = state
        .store
        .prepare_route_transition(&RouteTransitionPrepareRecord {
            transition_id: crate::util::generate_hex_id_128(),
            operation_id: operation_id.to_string(),
            device_key: device_key.into_owned(),
            platform: platform.name().to_string(),
            expected_route_revision: payload.expected_route_revision,
            candidate_channel_type: channel_type.as_str().to_string(),
            candidate_provider_token: provider_token,
            candidate_fingerprint: fingerprint,
            created_at: now,
            expires_at: now.saturating_add(ROUTE_TRANSITION_TTL_MILLIS),
        })
        .await
        .map_err(map_transition_error)?;
    Ok(crate::api::ok(prepared_response(record)))
}

pub(crate) async fn query(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<RouteTransitionQueryRequest>,
) -> HttpResult {
    let transition_id = payload
        .transition_id
        .as_deref()
        .map(|value| validated_id(value, "transition_id"))
        .transpose()?;
    let device_key = payload
        .device_key
        .as_deref()
        .map(DeviceKeyRef::parse)
        .transpose()?;
    let operation_id = payload
        .operation_id
        .as_deref()
        .map(|value| validated_id(value, "operation_id"))
        .transpose()?;
    if transition_id.is_none() && (device_key.is_none() || operation_id.is_none()) {
        return Err(Error::validation_code(
            "query requires transition_id or device_key plus operation_id",
            "route_transition_query_invalid",
        ));
    }
    for _ in 0..5 {
        let record = state
            .store
            .query_route_transition(
                transition_id,
                device_key.as_ref().map(|value| (*value).as_str()),
                operation_id,
            )
            .await
            .map_err(map_transition_error)?
            .ok_or_else(|| map_transition_error(StoreError::RouteTransitionNotFound))?;
        let active_route = state
            .store
            .active_device_route_snapshot(&record.device_key)
            .await?;
        let record_after = state
            .store
            .query_route_transition(
                transition_id,
                device_key.as_ref().map(|value| (*value).as_str()),
                operation_id,
            )
            .await
            .map_err(map_transition_error)?;
        // Route fields come from one database row snapshot. Operation changes
        // commit with the route, so stable bookends keep the receipt and route
        // from different transaction generations out of the same response.
        if record_after.as_ref() != Some(&record) {
            continue;
        }
        let current_provider_token_sha256 = active_route
            .as_ref()
            .filter(|route| route.channel_type != DeviceChannelType::Private.as_str())
            .and_then(|route| route.provider_token.as_deref())
            .map(|token| {
                let digest = Sha256::digest(token.as_bytes());
                digest.iter().map(|byte| format!("{byte:02x}")).collect()
            });
        let route_revision = active_route.as_ref().map(|route| route.route_revision);
        let channel_type = active_route.map(|route| route.channel_type);
        return Ok(crate::api::ok(RouteTransitionQueryResponse {
            transition_id: record.transition_id,
            state: record.state,
            base_revision: record.base_revision,
            candidate_fingerprint: record.candidate_fingerprint,
            expires_at: record.expires_at,
            committed_revision: record.committed_revision,
            candidate_channel_type: record.candidate_channel_type,
            route_revision,
            channel_type,
            current_provider_token_sha256,
        }));
    }
    Err(Error::Conflict {
        message: "device route changed while querying transition".into(),
        code: "route_transition_revision_conflict".into(),
    })
}

pub(crate) async fn abort(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<RouteTransitionIdentityRequest>,
) -> HttpResult {
    let transition_id = validated_id(&payload.transition_id, "transition_id")?;
    let operation_id = validated_id(&payload.operation_id, "operation_id")?;
    let record = state
        .store
        .abort_route_transition(
            transition_id,
            operation_id,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        .map_err(map_transition_error)?;
    Ok(crate::api::ok(prepared_response(record)))
}

pub(crate) async fn commit(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<RouteTransitionIdentityRequest>,
) -> HttpResult {
    let transition_id = validated_id(&payload.transition_id, "transition_id")?;
    let operation_id = validated_id(&payload.operation_id, "operation_id")?;
    let prepared = state
        .store
        .query_route_transition(Some(transition_id), None, None)
        .await
        .map_err(map_transition_error)?
        .ok_or_else(|| map_transition_error(StoreError::RouteTransitionNotFound))?;
    let _claim_lock = state.device_operation_guards.lock_provider_claim().await;
    let (locked_keys, _operation_locks) = lock_provider_route_owners(
        &state,
        &prepared.device_key,
        platform_from_str(&prepared.platform)?,
        prepared.candidate_provider_token.as_deref(),
    )
    .await?;
    let ack_timeout_secs = state
        .private
        .as_ref()
        .map(|private| private.config.ack_timeout_secs)
        .unwrap_or(30);
    let max_pending_per_device = state
        .private
        .as_ref()
        .map(|private| private.config.max_pending_per_device)
        .unwrap_or(usize::MAX);
    let committed = state
        .store
        .commit_route_transition(
            transition_id,
            operation_id,
            chrono::Utc::now().timestamp_millis(),
            ack_timeout_secs,
            max_pending_per_device,
        )
        .await
        .map_err(map_transition_error)?;
    // A committed operation can be retried after a later route change. Its
    // immutable receipt is not the current route: reconcile the registry from
    // durable state while holding the device operation guard.
    let persisted_routes = state.store.load_device_routes().await?;
    if let Some(active_route) = persisted_routes
        .iter()
        .find(|route| route.device_key == committed.record.device_key)
    {
        let channel_type = DeviceChannelType::parse(&active_route.channel_type)
            .ok_or_else(|| Error::Internal("persisted active channel type is invalid".into()))?;
        reconcile_coalesced_route_owners(
            &state,
            &locked_keys,
            &persisted_routes,
            &committed.record.device_key,
        );
        state
            .device_registry
            .update_channel(
                &committed.record.device_key,
                channel_type,
                active_route.provider_token.clone(),
            )
            .map_err(Error::Internal)?;
        if committed.migrated_pending_count > 0
            && channel_type == DeviceChannelType::Private
            && let Some(private) = state.private.as_deref()
        {
            private.request_fallback_resync();
        }
    } else {
        // A later token transfer may retire this identity. Keep the original
        // committed receipt replayable without resurrecting the retired route.
        state
            .device_registry
            .remove_device(&committed.record.device_key);
    }
    Ok(crate::api::ok(RouteTransitionCommitResponse {
        transition_id: committed.record.transition_id,
        state: committed.record.state,
        previous_revision: committed.previous_revision,
        route_revision: committed.route_revision,
        channel_type: committed.record.candidate_channel_type,
        migrated_pending_count: committed.migrated_pending_count,
    }))
}

fn normalize_candidate_token(
    platform: Platform,
    channel_type: DeviceChannelType,
    raw: Option<&str>,
) -> Result<Option<String>, Error> {
    if channel_type == DeviceChannelType::Private {
        if ProviderTokenRef::optional(raw).is_some() {
            return Err(Error::validation_code(
                "provider_token is forbidden for private route",
                "provider_token_forbidden_for_private_channel",
            ));
        }
        return Ok(None);
    }
    if !platform.supports_provider_push() {
        return Err(Error::validation_code(
            "platform does not support provider push",
            "invalid_platform",
        ));
    }
    let expected = match platform {
        Platform::ANDROID => DeviceChannelType::Fcm,
        Platform::IOS | Platform::MACOS | Platform::WATCHOS => DeviceChannelType::Apns,
        Platform::WINDOWS => DeviceChannelType::Wns,
        _ => DeviceChannelType::Private,
    };
    if channel_type != expected {
        return Err(Error::validation_code(
            "channel_type does not match platform",
            "channel_type_mismatch",
        ));
    }
    let token = ProviderTokenRef::optional(raw).ok_or_else(|| {
        Error::validation_code("provider_token required", "provider_token_required")
    })?;
    Ok(Some(ProviderTokenRef::canonicalize_for_platform(
        token.as_str(),
        platform,
    )?))
}
