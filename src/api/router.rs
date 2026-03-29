use crate::{
    api::handlers::{
        channel::{channel_exists, channel_rename},
        core::{
            channel_subscribe, channel_sync, channel_unsubscribe, device_channel_delete,
            device_channel_upsert, messages_pull,
        },
        diagnostics::diagnostics_dispatch,
        event::{event_close_to_channel, event_create_to_channel, event_update_to_channel},
        health::{healthz, private_readyz, readyz},
        message::{
            compat_bark_v1_body, compat_bark_v1_title_body, compat_bark_v2_push, compat_ntfy_get,
            compat_ntfy_post, compat_ntfy_put, compat_serverchan_get, compat_serverchan_post,
            message_to_channel, message_to_channel_get,
        },
        private::{
            gateway_profile, private_health, private_metrics, private_network_diagnostics,
            private_ws,
        },
        thing::{
            thing_archive_to_channel, thing_create_to_channel, thing_delete_to_channel,
            thing_update_to_channel,
        },
    },
    api::{Error, HttpResult},
    app::{AppState, AuthMode},
    util::constant_time_eq,
};
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::{
    Router,
    extract::{Request, State},
    middleware::{Next, from_fn_with_state},
    response::{Html, IntoResponse},
    routing::{get, post},
};

pub fn build_router(state: AppState, docs_html: &'static str) -> Router {
    let docs = docs_html;
    let private_channel_enabled = state.private_channel_enabled;
    let mut router = Router::new()
        .route("/", get(move || async move { Html(docs) }))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/private/readyz", get(private_readyz))
        .route(
            "/message",
            post(message_to_channel).get(message_to_channel_get),
        )
        .route("/ntfy/{topic}", post(compat_ntfy_post).put(compat_ntfy_put))
        .route(
            "/ntfy/{topic}/publish",
            get(compat_ntfy_get)
                .post(compat_ntfy_post)
                .put(compat_ntfy_put),
        )
        .route(
            "/ntfy/{topic}/send",
            get(compat_ntfy_get)
                .post(compat_ntfy_post)
                .put(compat_ntfy_put),
        )
        .route(
            "/ntfy/{topic}/trigger",
            get(compat_ntfy_get)
                .post(compat_ntfy_post)
                .put(compat_ntfy_put),
        )
        .route(
            "/serverchan/{sendkey}",
            get(compat_serverchan_get).post(compat_serverchan_post),
        )
        .route("/bark/{device_key}/{body}", get(compat_bark_v1_body))
        .route(
            "/bark/{device_key}/{title}/{body}",
            get(compat_bark_v1_title_body),
        )
        .route("/bark/push", post(compat_bark_v2_push))
        .route("/event/create", post(event_create_to_channel))
        .route("/event/update", post(event_update_to_channel))
        .route("/event/close", post(event_close_to_channel))
        .route("/thing/create", post(thing_create_to_channel))
        .route("/thing/update", post(thing_update_to_channel))
        .route("/thing/archive", post(thing_archive_to_channel))
        .route("/thing/delete", post(thing_delete_to_channel))
        .route("/device/register", post(device_channel_upsert))
        .route("/channel/device/delete", post(device_channel_delete))
        .route("/channel/sync", post(channel_sync))
        .route("/channel/subscribe", post(channel_subscribe))
        .route("/channel/unsubscribe", post(channel_unsubscribe))
        .route("/messages/pull", post(messages_pull))
        .route("/gateway/profile", get(gateway_profile))
        .route("/channel/exists", get(channel_exists))
        .route("/channel/rename", post(channel_rename));

    if state.diagnostics_api_enabled {
        router = router
            .route("/diagnostics/dispatch", get(diagnostics_dispatch))
            .route("/diagnostics/private/metrics", get(private_metrics))
            .route("/diagnostics/private/health", get(private_health))
            .route(
                "/diagnostics/private/network",
                get(private_network_diagnostics),
            );
    }

    if private_channel_enabled {
        router = router.route("/private/ws", get(private_ws));
    }

    router
        .layer(from_fn_with_state(state.clone(), middleware))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state)
        .fallback(async || (StatusCode::NOT_FOUND, "404 Not Found").into_response())
}

fn extract_bearer_token(req: &Request) -> Result<&str, Error> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Error::Unauthorized)?;

    let raw = header.to_str().map_err(|_| Error::Unauthorized)?;
    let mut it = raw.split_whitespace();

    let scheme = it.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Error::Unauthorized);
    }

    let token = it.next().ok_or(Error::Unauthorized)?;

    // Reject extra segments after the token.
    if it.next().is_some() {
        return Err(Error::Unauthorized);
    }

    // Reject empty or obviously malformed tokens.
    const MAX_TOKEN_LEN: usize = 4096;
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(Error::Unauthorized);
    }

    Ok(token)
}

async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> HttpResult {
    fn constant_time_equals(a: &str, b: &str) -> bool {
        constant_time_eq(a.as_bytes(), b.as_bytes())
    }
    if let AuthMode::SharedToken(token) = &state.auth {
        match extract_bearer_token(&req) {
            Ok(req_token) => {
                if !constant_time_equals(req_token, token) {
                    return Ok(Error::Unauthorized.into_response());
                }
            }
            Err(err) => {
                return Ok(err.into_response());
            }
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
