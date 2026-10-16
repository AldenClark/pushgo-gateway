use std::{collections::HashSet, sync::Arc};

use crate::{
    api::handlers::widget_push::{
        WIDGET_KIND_CRITICAL_EVENTS, WIDGET_KIND_OBJECT_STATUS, WIDGET_KIND_UNREAD,
        WIDGET_KIND_WATCH_SUMMARY,
    },
    delivery_core::execution::coordinator::PreparedDispatch,
    dispatch::WidgetPushJob,
    storage::{Platform, WidgetPushSubscriptionRecord},
};

pub(super) async fn dispatch_widget_push_targets(
    prepared: &PreparedDispatch<'_>,
) -> Result<(), crate::Error> {
    let requested_kinds = requested_widget_kinds(prepared.entity_type);
    if requested_kinds.is_empty() {
        return Ok(());
    }

    let targets = match prepared
        .runtime
        .storage()
        .list_widget_push_targets_for_channel(prepared.channel_id)
        .await
    {
        Ok(targets) => targets,
        Err(err) => {
            emit_widget_push_dispatch_skipped(
                prepared,
                "store_error",
                Some(err.to_string()),
                &requested_kinds,
            );
            return Err(crate::Error::StoreError(err));
        }
    };

    let requested: HashSet<&str> = requested_kinds.iter().copied().collect();
    let mut seen_tokens = HashSet::new();
    let mut matched = 0usize;
    let mut first_error = None;
    for target in targets {
        if !requested.contains(target.widget_kind.as_str()) {
            continue;
        }
        let Ok(platform) = target.platform.parse::<Platform>() else {
            continue;
        };
        if !matches!(
            platform,
            Platform::IOS | Platform::MACOS | Platform::WATCHOS
        ) {
            continue;
        }
        if !seen_tokens.insert((platform, target.token.clone())) {
            continue;
        }
        matched += 1;
        if let Err(err) =
            enqueue_widget_push(prepared, platform, target, requested_kinds.as_slice()).await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
    }

    if matched == 0 {
        emit_widget_push_dispatch_skipped(prepared, "no_matching_widgets", None, &requested_kinds);
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

async fn enqueue_widget_push(
    prepared: &PreparedDispatch<'_>,
    platform: Platform,
    target: WidgetPushSubscriptionRecord,
    requested_kinds: &[&'static str],
) -> Result<(), crate::Error> {
    let job = widget_push_job(
        prepared.channel_id,
        prepared.entity_type,
        Arc::clone(&prepared.correlation_id),
        Arc::clone(&prepared.delivery_id_ref),
        platform,
        target.device_key,
        target.token,
    );
    let durable = crate::dispatch::DurableProviderJob::from_widget(&job);
    let mut record = match durable.to_record(
        "pending",
        prepared.sent_at,
        prepared.provider_pull_expires_at(),
    ) {
        Ok(record) => record,
        Err(err) => {
            emit_widget_push_dispatch_skipped(
                prepared,
                "widget_push_encode_failed",
                Some(err.to_string()),
                requested_kinds,
            );
            return Ok(());
        }
    };
    record.coalesce_order = prepared.acceptance_order;
    if let Err(err) = prepared
        .runtime
        .storage()
        .enqueue_provider_dispatch_job(&record)
        .await
    {
        emit_widget_push_dispatch_skipped(
            prepared,
            "widget_push_store_failed",
            Some(err.to_string()),
            requested_kinds,
        );
        return Err(crate::Error::StoreError(err));
    }
    let _ = prepared
        .runtime
        .dispatch_channels()
        .try_send_widget_push(job);
    Ok(())
}

/// Pure projection shared by retained Event/Thing dispatch and ordinary
/// invalidation. It carries no ordinary body or idempotency authority.
pub(crate) fn widget_push_job(
    channel_id: [u8; 16],
    entity_type: &'static str,
    correlation_id: Arc<str>,
    delivery_id: Arc<str>,
    platform: Platform,
    device_key: String,
    token: String,
) -> WidgetPushJob {
    WidgetPushJob {
        channel_id,
        correlation_id,
        delivery_id,
        device_key: Arc::from(device_key.into_boxed_str()),
        device_token: Arc::from(token.into_boxed_str()),
        platform,
        widget_kinds: requested_widget_kinds(entity_type)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .into(),
        collapse_id: Some(Arc::from(format!(
            "widgets:{entity_type}:{}",
            crate::value::ChannelId::from(channel_id)
        ))),
    }
}

fn requested_widget_kinds(entity_type: &str) -> Vec<&'static str> {
    match entity_type {
        "message" => vec![WIDGET_KIND_UNREAD, WIDGET_KIND_WATCH_SUMMARY],
        "event" => vec![WIDGET_KIND_CRITICAL_EVENTS, WIDGET_KIND_WATCH_SUMMARY],
        "thing" => vec![WIDGET_KIND_OBJECT_STATUS, WIDGET_KIND_WATCH_SUMMARY],
        _ => Vec::new(),
    }
}

fn emit_widget_push_dispatch_skipped(
    prepared: &PreparedDispatch<'_>,
    reason: &'static str,
    error: Option<String>,
    widget_kinds: &[&str],
) {
    if reason == "no_matching_widgets" {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::DEBUG,
            event = "widget_push.dispatch_skipped",
            correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
            delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
            channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
            reason = %(reason),
            widget_kinds = %(widget_kinds.join(",")),
            error = %(error.as_deref().unwrap_or(""))
        );
        return;
    }
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "widget_push.dispatch_skipped",
        correlation_id = %(crate::util::redact_text(prepared.correlation_id.as_ref())),
        delivery_id = %(crate::util::redact_text(prepared.delivery_id.as_str())),
        channel_id = %(crate::util::redact_text(prepared.channel_id_value.as_str())),
        reason = %(reason),
        widget_kinds = %(widget_kinds.join(",")),
        error = %(error.as_deref().unwrap_or(""))
    );
}
