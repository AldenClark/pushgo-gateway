use std::net::SocketAddr;

use crate::{
    api::handlers::{
        channel::{channel_exists, channel_rename},
        event::{event_close_to_channel, event_create_to_channel, event_update_to_channel},
        message::message_to_channel,
        private::{
            private_health, private_metrics, private_network_diagnostics, private_profile,
            private_ws,
        },
        thing::{
            thing_archive_to_channel, thing_create_to_channel, thing_delete_to_channel,
            thing_update_to_channel,
        },
        v1::{
            v1_channel_subscribe, v1_channel_sync, v1_channel_unsubscribe,
            v1_device_channel_delete, v1_device_channel_upsert, v1_device_register,
            v1_messages_ack, v1_messages_ack_batch, v1_messages_pull,
        },
    },
    api::{Error, HttpResult},
    app::{AppState, AuthMode},
    util::constant_time_eq,
};
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::{
    Router,
    extract::connect_info::ConnectInfo,
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
        .route("/message", post(message_to_channel))
        .route("/event/create", post(event_create_to_channel))
        .route("/event/update", post(event_update_to_channel))
        .route("/event/close", post(event_close_to_channel))
        .route("/thing/create", post(thing_create_to_channel))
        .route("/thing/update", post(thing_update_to_channel))
        .route("/thing/archive", post(thing_archive_to_channel))
        .route("/thing/delete", post(thing_delete_to_channel))
        .route("/device/register", post(v1_device_register))
        .route("/channel/device", post(v1_device_channel_upsert))
        .route("/channel/device/delete", post(v1_device_channel_delete))
        .route("/channel/sync", post(v1_channel_sync))
        .route("/channel/subscribe", post(v1_channel_subscribe))
        .route("/channel/unsubscribe", post(v1_channel_unsubscribe))
        .route("/messages/pull", post(v1_messages_pull))
        .route("/messages/ack", post(v1_messages_ack))
        .route("/messages/ack/batch", post(v1_messages_ack_batch))
        .route("/channel/exists", get(channel_exists))
        .route("/channel/rename", post(channel_rename));

    if private_channel_enabled {
        router = router
            .route("/private/metrics", get(private_metrics))
            .route("/private/health", get(private_health))
            .route("/private/profile", get(private_profile))
            .route(
                "/private/diagnostics/network",
                get(private_network_diagnostics),
            )
            .route("/private/ws", get(private_ws));
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
    if state.ip_rate_limit_enabled {
        let peer_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let client_ip = state.client_ip_resolver.resolve(req.headers(), peer_ip);
        if !state.api_rate_limiter.allow_ip_global(client_ip.as_deref())
            || !state.api_rate_limiter.allow_ip_route(
                client_ip.as_deref(),
                req.method().as_str(),
                req.uri().path(),
            )
        {
            let mut resp = Error::TooBusy.into_response();
            resp.headers_mut()
                .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("2"));
            return Ok(resp);
        }
    }

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

    let wait_permit = match state.ingress_wait_limiter.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let mut resp = Error::TooBusy.into_response();
            resp.headers_mut()
                .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
            return Ok(resp);
        }
    };
    let _processing_permit = match state
        .ingress_processing_limiter
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => {
            drop(wait_permit);
            permit
        }
        Err(_) => {
            let mut resp = Error::TooBusy.into_response();
            resp.headers_mut()
                .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
            return Ok(resp);
        }
    };
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tokio::sync::Semaphore;
    use tower::ServiceExt;

    use crate::{
        app::{AppState, AuthMode},
        device_registry::DeviceRegistry,
        dispatch::create_dispatch_channels,
        storage::{Store, new_store},
    };

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    async fn build_test_state() -> AppState {
        let unique_id = TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_url = format!(
            "sqlite:///tmp/pushgo-router-test-{}-{}-{}.db",
            std::process::id(),
            unique_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        let store: Store = new_store(Some(db_url.as_str()))
            .await
            .expect("sqlite test store should initialize");
        let (dispatch, _apns_rx, _fcm_rx, _wns_rx) = create_dispatch_channels();
        AppState {
            dispatch,
            auth: AuthMode::Disabled,
            private_channel_enabled: false,
            ip_rate_limit_enabled: false,
            ingress_processing_limiter: Arc::new(Semaphore::new(32)),
            ingress_wait_limiter: Arc::new(Semaphore::new(32)),
            api_rate_limiter: Arc::new(crate::rate_limit::ApiRateLimiter::default()),
            client_ip_resolver: Arc::new(crate::rate_limit::ClientIpResolver),
            device_registry: Arc::new(DeviceRegistry::new()),
            private_transport_profile: crate::app::PrivateTransportProfile {
                quic_enabled: true,
                quic_port: Some(443),
                tcp_enabled: true,
                tcp_port: 5223,
                wss_enabled: true,
                wss_port: 6666,
                wss_path: Arc::from("/private/ws"),
                ws_subprotocol: Arc::from("pushgo-private.v1"),
            },
            private: None,
            store,
        }
    }

    async fn build_private_test_state() -> AppState {
        let mut state = build_test_state().await;
        state.private_channel_enabled = true;
        state
    }

    #[tokio::test]
    async fn thing_scoped_event_route_returns_not_found() {
        let state = build_test_state().await;
        let app = super::build_router(state, "<html>docs</html>");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/thing/thing-1/event/update")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("router should handle request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn thing_scoped_message_route_returns_not_found() {
        let state = build_test_state().await;
        let app = super::build_router(state, "<html>docs</html>");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/thing/thing-1/message")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("router should handle request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn event_routes_still_match_after_contract_merge() {
        let state = build_test_state().await;
        let app = super::build_router(state, "<html>docs</html>");
        for path in ["/event/create", "/event/update", "/event/close"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request should build"),
                )
                .await
                .expect("router should handle request");
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} should be routed"
            );
        }
    }

    #[tokio::test]
    async fn private_profile_route_returns_transport_config() {
        let state = build_private_test_state().await;
        let app = super::build_router(state, "<html>docs</html>");
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/private/profile")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should handle request");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
