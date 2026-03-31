pub mod channel;
pub(crate) mod channel_auth;
pub mod core;
pub(crate) mod diagnostics;
pub(crate) mod dispatch_lifecycle;
pub mod event;
pub(crate) mod health;
pub mod message;
pub mod private;
pub mod thing;
pub(crate) mod watch_light;

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};

use crate::app::AppState;

pub(crate) fn public_router(docs_html: &'static str) -> Router<AppState> {
    let docs = docs_html;
    Router::new()
        .route("/", get(move || async move { Html(docs) }))
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/private/readyz", get(health::private_readyz))
        .route(
            "/message",
            post(message::message_to_channel).get(message::message_to_channel_get),
        )
        .route(
            "/ntfy/{topic}",
            post(message::compat_ntfy_post).put(message::compat_ntfy_put),
        )
        .route(
            "/ntfy/{topic}/publish",
            get(message::compat_ntfy_get)
                .post(message::compat_ntfy_post)
                .put(message::compat_ntfy_put),
        )
        .route(
            "/ntfy/{topic}/send",
            get(message::compat_ntfy_get)
                .post(message::compat_ntfy_post)
                .put(message::compat_ntfy_put),
        )
        .route(
            "/ntfy/{topic}/trigger",
            get(message::compat_ntfy_get)
                .post(message::compat_ntfy_post)
                .put(message::compat_ntfy_put),
        )
        .route(
            "/serverchan/{sendkey}",
            get(message::compat_serverchan_get).post(message::compat_serverchan_post),
        )
        .route(
            "/bark/{device_key}/{body}",
            get(message::compat_bark_v1_body),
        )
        .route(
            "/bark/{device_key}/{title}/{body}",
            get(message::compat_bark_v1_title_body),
        )
        .route("/bark/push", post(message::compat_bark_v2_push))
        .route("/event/create", post(event::event_create_to_channel))
        .route("/event/update", post(event::event_update_to_channel))
        .route("/event/close", post(event::event_close_to_channel))
        .route("/thing/create", post(thing::thing_create_to_channel))
        .route("/thing/update", post(thing::thing_update_to_channel))
        .route("/thing/archive", post(thing::thing_archive_to_channel))
        .route("/thing/delete", post(thing::thing_delete_to_channel))
        .route("/device/register", post(core::device_channel_upsert))
        .route("/channel/device/delete", post(core::device_channel_delete))
        .route("/channel/sync", post(core::channel_sync))
        .route("/channel/subscribe", post(core::channel_subscribe))
        .route("/channel/unsubscribe", post(core::channel_unsubscribe))
        .route("/messages/pull", post(core::messages_pull))
        .route("/gateway/profile", get(private::gateway_profile))
        .route("/channel/exists", get(channel::channel_exists))
        .route("/channel/rename", post(channel::channel_rename))
}

pub(crate) fn diagnostics_router() -> Router<AppState> {
    Router::new()
        .route(
            "/diagnostics/dispatch",
            get(diagnostics::diagnostics_dispatch),
        )
        .route(
            "/diagnostics/private/metrics",
            get(private::private_metrics),
        )
        .route("/diagnostics/private/health", get(private::private_health))
        .route(
            "/diagnostics/private/network",
            get(private::private_network_diagnostics),
        )
}

pub(crate) fn private_router() -> Router<AppState> {
    Router::new().route("/private/ws", get(private::private_ws))
}
