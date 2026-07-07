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

pub(super) async fn dispatch_widget_push_targets(prepared: &PreparedDispatch<'_>) {
    let requested_kinds = requested_widget_kinds(prepared.entity_type);
    if requested_kinds.is_empty() {
        return;
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
            return;
        }
    };

    let requested: HashSet<&str> = requested_kinds.iter().copied().collect();
    let mut seen_tokens = HashSet::new();
    let mut matched = 0usize;
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
        enqueue_widget_push(prepared, platform, target, requested_kinds.as_slice());
    }

    if matched == 0 {
        emit_widget_push_dispatch_skipped(prepared, "no_matching_widgets", None, &requested_kinds);
    }
}

fn enqueue_widget_push(
    prepared: &PreparedDispatch<'_>,
    platform: Platform,
    target: WidgetPushSubscriptionRecord,
    requested_kinds: &[&'static str],
) {
    let job = WidgetPushJob {
        channel_id: prepared.channel_id,
        correlation_id: Arc::clone(&prepared.correlation_id),
        delivery_id: Arc::clone(&prepared.delivery_id_ref),
        device_key: Arc::from(target.device_key.into_boxed_str()),
        device_token: Arc::from(target.token.into_boxed_str()),
        platform,
        widget_kinds: requested_kinds
            .iter()
            .map(|kind| (*kind).to_string())
            .collect::<Vec<_>>()
            .into(),
        collapse_id: Some(Arc::from(format!(
            "widgets:{}:{}",
            prepared.entity_type, prepared.channel_id_value
        ))),
    };
    if let Err(err) = prepared
        .runtime
        .dispatch_channels()
        .try_send_widget_push(job)
    {
        emit_widget_push_dispatch_skipped(
            prepared,
            match err {
                crate::dispatch::DispatchError::QueueFull => "widget_push_queue_full",
                crate::dispatch::DispatchError::ChannelClosed => "widget_push_queue_closed",
            },
            None,
            requested_kinds,
        );
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
