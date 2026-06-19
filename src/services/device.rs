use crate::{
    api::Error,
    app::AppState,
    routing::{DeviceRouteRecord, default_route_for_platform},
    storage::{DeviceRouteRecordRow, Platform},
};

#[derive(Debug, Clone)]
pub(crate) struct DeviceRegisterCommand<'a> {
    pub device_key: Option<&'a str>,
    pub platform: Platform,
}

#[derive(Debug, Clone)]
pub(crate) struct DeviceRegisterOutcome {
    pub device_key: String,
    pub issued_new_key: bool,
    pub issue_reason: Option<&'static str>,
}

pub(crate) async fn ensure_device_registered(
    state: &AppState,
    command: DeviceRegisterCommand<'_>,
) -> Result<DeviceRegisterOutcome, Error> {
    let requested_device_key = command
        .device_key
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(device_key) = requested_device_key
        && let Some(route) = state.device_registry.get(device_key)
    {
        if route.platform != command.platform {
            return issue_new_device_key(
                state,
                command.platform,
                Some(device_key),
                Some(&route),
                "platform_mismatch",
            )
            .await;
        }
        return Ok(DeviceRegisterOutcome {
            device_key: device_key.to_string(),
            issued_new_key: false,
            issue_reason: None,
        });
    }

    if let Some(device_key) = requested_device_key
        && let Some(replacement_device_key) = state
            .device_registry
            .resolve_replaced_device_key(device_key, command.platform)
    {
        return Ok(DeviceRegisterOutcome {
            device_key: replacement_device_key,
            issued_new_key: true,
            issue_reason: Some("platform_mismatch"),
        });
    }

    issue_new_device_key(
        state,
        command.platform,
        requested_device_key,
        None,
        if requested_device_key.is_some() {
            "device_key_not_found"
        } else {
            "device_key_missing"
        },
    )
    .await
}

async fn issue_new_device_key(
    state: &AppState,
    requested_platform: Platform,
    requested_device_key: Option<&str>,
    previous_route: Option<&DeviceRouteRecord>,
    issue_reason: &'static str,
) -> Result<DeviceRegisterOutcome, Error> {
    let resolved_device_key = state.device_registry.allocate_device_key();
    let route =
        default_route_for_platform(requested_platform, chrono::Utc::now().timestamp_millis());
    let old_device_key = if issue_reason == "platform_mismatch" {
        requested_device_key
    } else {
        None
    };
    state
        .store
        .replace_device_identity(
            &DeviceRouteRecordRow::from_registry_record(resolved_device_key.as_str(), &route),
            old_device_key,
        )
        .await
        .map_err(|err| Error::Internal(format!("failed to replace device identity: {err}")))?;
    state
        .device_registry
        .restore_route(resolved_device_key.as_str(), route)
        .map_err(Error::Internal)?;
    if let Some(old_device_key) = old_device_key
        && old_device_key != resolved_device_key
    {
        state.device_registry.remove_device(old_device_key);
        state.device_registry.remember_replaced_device_key(
            old_device_key,
            resolved_device_key.as_str(),
            requested_platform,
        );
    }

    if issue_reason == "platform_mismatch" && tracing::enabled!(tracing::Level::WARN) {
        let old_key = requested_device_key.unwrap_or("");
        let old_platform = previous_route
            .map(|route| route.platform.name())
            .unwrap_or("");
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "device.route_reissued",
            reason = %(issue_reason),
            old_device_key = %(crate::util::redact_text(old_key)),
            old_platform = %(old_platform),
            requested_platform = %(requested_platform.name()),
            new_device_key = %(crate::util::redact_text(resolved_device_key.as_str()))
        );
    }

    Ok(DeviceRegisterOutcome {
        device_key: resolved_device_key,
        issued_new_key: true,
        issue_reason: Some(issue_reason),
    })
}
