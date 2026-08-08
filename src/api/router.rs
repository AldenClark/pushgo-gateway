use crate::{
    api::handlers,
    api::{Error, HttpResult, err_with_code, with_api_request_scope},
    app::{AppState, AuthMode},
    mcp::{is_mcp_or_oauth_path, mcp_router},
    runtime_counters::OPS_METRIC_HTTP_RESPONSE_5XX,
    util::constant_time_eq,
};
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::{
    Router,
    extract::{ConnectInfo, MatchedPath, Request, State},
    middleware::{Next, from_fn_with_state},
    response::IntoResponse,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

pub(crate) fn build_router(state: AppState, docs_html: &'static str) -> Router {
    let mut router = handlers::public_router(docs_html);

    if state.private_transport_profile.wss_enabled {
        router = router.merge(handlers::private_router());
    }

    if state.mcp.is_some() {
        router = router.merge(mcp_router());
    }

    router
        .layer(from_fn_with_state(state.clone(), middleware))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state)
        .fallback(|| async {
            let request_id = crate::util::generate_hex_id_128();
            let mut response =
                err_with_code(StatusCode::NOT_FOUND, "404 Not Found", "route_not_found");
            if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
                response.headers_mut().insert("x-request-id", value);
            }
            response
        })
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
    let headers = req.headers().clone();
    let request_id = crate::util::generate_hex_id_128();
    let method = req.method().to_string();
    let request_path = req.uri().path().to_string();
    let route_pattern = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let request_span = tracing::info_span!(
        "gateway.http.request",
        request_id = %request_id,
        method = %method,
        route = %route_pattern
    );

    with_api_request_scope(&headers, request_id.clone(), async move {
        let method = req.method().to_string();
        let bypass_auth = state.mcp.is_some() && is_mcp_or_oauth_path(req.uri().path());
        if is_password_sensitive_route(&route_pattern) || is_password_sensitive_path(&request_path)
        {
            let peer_ip = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|connect| connect.0.ip());
            if !PASSWORD_RATE_LIMITER.allow(peer_ip, current_minute()) {
                emit_auth_rejected(
                    &method,
                    &route_pattern,
                    &request_id,
                    "password_rate_limited",
                );
                return Ok(Error::RateLimited.into_response());
            }
        }

        fn constant_time_equals(a: &str, b: &str) -> bool {
            constant_time_eq(a.as_bytes(), b.as_bytes())
        }
        if !bypass_auth && let AuthMode::SharedToken(token) = &state.auth {
            match extract_bearer_token(&req) {
                Ok(req_token) => {
                    if !constant_time_equals(req_token, token) {
                        emit_auth_rejected(&method, &route_pattern, &request_id, "token_mismatch");
                        return Ok(Error::Unauthorized.into_response());
                    }
                }
                Err(err) => {
                    emit_auth_rejected(
                        &method,
                        &route_pattern,
                        &request_id,
                        "missing_or_malformed_bearer",
                    );
                    return Ok(err.into_response());
                }
            }
        }

        let mut response = next.run(req).await;
        if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
            response.headers_mut().insert("x-request-id", value);
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "http.request_completed",
            request_id = %(crate::util::redact_text(request_id.as_str())),
            method = %(method.as_str()),
            route = %(route_pattern.as_str()),
            status_code = (u64::from(response.status().as_u16()))
        );
        observe_server_error_response(&state, &method, &route_pattern, response.status());
        Ok(response)
    })
    .instrument(request_span)
    .await
}

const PASSWORD_REQUESTS_PER_IP_PER_MINUTE: u32 = 60;
const PASSWORD_REQUESTS_GLOBAL_PER_MINUTE: u32 = 1_200;
static PASSWORD_RATE_LIMITER: LazyLock<PasswordRateLimiter> =
    LazyLock::new(PasswordRateLimiter::default);

#[derive(Debug, Default)]
struct PasswordRateWindow {
    minute: u64,
    global_count: u32,
    per_ip: HashMap<IpAddr, u32>,
}

#[derive(Debug, Default)]
struct PasswordRateLimiter {
    window: Mutex<PasswordRateWindow>,
}

impl PasswordRateLimiter {
    fn allow(&self, peer_ip: Option<IpAddr>, minute: u64) -> bool {
        let Ok(mut window) = self.window.lock() else {
            return false;
        };
        if window.minute != minute {
            *window = PasswordRateWindow {
                minute,
                ..PasswordRateWindow::default()
            };
        }
        if window.global_count >= PASSWORD_REQUESTS_GLOBAL_PER_MINUTE {
            return false;
        }
        if let Some(peer_ip) = peer_ip
            && window.per_ip.get(&peer_ip).copied().unwrap_or_default()
                >= PASSWORD_REQUESTS_PER_IP_PER_MINUTE
        {
            return false;
        }
        window.global_count = window.global_count.saturating_add(1);
        if let Some(peer_ip) = peer_ip {
            let count = window.per_ip.entry(peer_ip).or_default();
            *count = count.saturating_add(1);
        }
        true
    }
}

fn current_minute() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 60)
        .unwrap_or_default()
}

fn is_password_sensitive_route(route: &str) -> bool {
    matches!(
        route,
        "/message"
            | "/ntfy/{topic}"
            | "/ntfy/{topic}/publish"
            | "/ntfy/{topic}/send"
            | "/ntfy/{topic}/trigger"
            | "/serverchan/{sendkey}"
            | "/bark/{device_key}/{body}"
            | "/bark/{device_key}/{title}/{body}"
            | "/bark/push"
            | "/event/create"
            | "/event/update"
            | "/event/close"
            | "/thing/{thing_id}/event/create"
            | "/thing/{thing_id}/event/update"
            | "/thing/{thing_id}/event/close"
            | "/thing/create"
            | "/thing/update"
            | "/thing/archive"
            | "/thing/delete"
            | "/channel/sync"
            | "/channel/subscribe"
            | "/channel/rename"
            | "/oauth/authorize"
            | "/oauth/token"
            | "/oauth/revoke"
            | "/oauth/register"
            | "/oauth/channel/validate"
            | "/mcp/bind/session"
            | "/mcp/revoke/session"
    )
}

fn is_password_sensitive_path(path: &str) -> bool {
    is_password_sensitive_route(path)
        || path.starts_with("/ntfy/")
        || path.starts_with("/serverchan/")
        || path.starts_with("/bark/")
        || (path.starts_with("/thing/") && path.contains("/event/"))
}

fn emit_auth_rejected(method: &str, route_pattern: &str, request_id: &str, reason: &'static str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "http.auth_rejected",
        request_id = %(crate::util::redact_text(request_id)),
        method = %(method),
        route = %(route_pattern),
        reason = %(reason)
    );
}

fn observe_server_error_response(
    state: &AppState,
    method: &str,
    route_pattern: &str,
    status: StatusCode,
) {
    if status.is_client_error() {
        observe_client_error_response(method, route_pattern, status);
        return;
    }
    if !status.is_server_error() {
        return;
    }
    state
        .runtime_counters
        .record_ops_counter_now(OPS_METRIC_HTTP_RESPONSE_5XX, 1);

    static HTTP_5XX_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = HTTP_5XX_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_emit_server_error_trace(count) {
        return;
    }

    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "http.response_5xx",
        count = (count),
        method = %(method),
        route = %(route_pattern),
        status_code = (u64::from(status.as_u16()))
    );
}

fn observe_client_error_response(method: &str, route_pattern: &str, status: StatusCode) {
    static HTTP_4XX_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = HTTP_4XX_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_emit_client_error_trace(count) {
        return;
    }
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "http.response_4xx",
        count = (count),
        method = %(method),
        route = %(route_pattern),
        status_code = (u64::from(status.as_u16()))
    );
}

#[inline]
fn should_emit_server_error_trace(count: u64) -> bool {
    count <= 16 || count.is_power_of_two()
}

#[inline]
fn should_emit_client_error_trace(count: u64) -> bool {
    count <= 8 || count.is_power_of_two()
}

#[cfg(test)]
#[path = "router_tests/mod.rs"]
mod tests;

#[cfg(test)]
mod trace_tests {
    use super::{
        PASSWORD_REQUESTS_PER_IP_PER_MINUTE, PasswordRateLimiter, is_password_sensitive_path,
        is_password_sensitive_route, should_emit_client_error_trace,
        should_emit_server_error_trace,
    };
    use std::net::IpAddr;

    #[test]
    fn server_error_trace_sampling_matches_expected_pattern() {
        for count in 1..=16 {
            assert!(should_emit_server_error_trace(count));
        }
        assert!(!should_emit_server_error_trace(17));
        assert!(should_emit_server_error_trace(32));
        assert!(!should_emit_server_error_trace(33));
        assert!(should_emit_server_error_trace(64));
    }

    #[test]
    fn client_error_trace_sampling_matches_expected_pattern() {
        for count in 1..=8 {
            assert!(should_emit_client_error_trace(count));
        }
        assert!(!should_emit_client_error_trace(9));
        assert!(should_emit_client_error_trace(16));
        assert!(!should_emit_client_error_trace(17));
        assert!(should_emit_client_error_trace(32));
    }

    #[test]
    fn password_rate_limiter_rejects_one_ip_without_affecting_another() {
        let limiter = PasswordRateLimiter::default();
        let first = "192.0.2.10".parse::<IpAddr>().expect("test IP");
        let second = "192.0.2.11".parse::<IpAddr>().expect("test IP");
        for _ in 0..PASSWORD_REQUESTS_PER_IP_PER_MINUTE {
            assert!(limiter.allow(Some(first), 42));
        }
        assert!(!limiter.allow(Some(first), 42));
        assert!(limiter.allow(Some(second), 42));
        assert!(limiter.allow(Some(first), 43));
    }

    #[test]
    fn password_sensitive_routes_use_matched_templates() {
        assert!(is_password_sensitive_route("/serverchan/{sendkey}"));
        assert!(is_password_sensitive_route("/oauth/channel/validate"));
        assert!(!is_password_sensitive_route("/healthz"));
    }

    #[test]
    fn password_sensitive_paths_cover_unmatched_dynamic_routes_without_logging_them() {
        assert!(is_password_sensitive_path("/serverchan/secret-key"));
        assert!(is_password_sensitive_path("/bark/private-key/body"));
        assert!(is_password_sensitive_path("/thing/123/event/create"));
        assert!(!is_password_sensitive_path("/healthz"));
    }
}
