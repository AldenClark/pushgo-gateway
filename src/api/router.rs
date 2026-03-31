use crate::{
    api::handlers,
    api::{Error, HttpResult},
    app::{AppState, AuthMode},
    mcp::{is_mcp_or_oauth_path, mcp_router},
    util::constant_time_eq,
};
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::{
    Router,
    extract::{Request, State},
    middleware::{Next, from_fn_with_state},
    response::IntoResponse,
};

pub fn build_router(state: AppState, docs_html: &'static str) -> Router {
    let mut router = handlers::public_router(docs_html);

    if state.diagnostics_api_enabled {
        router = router.merge(handlers::diagnostics_router());
    }

    if state.private_channel_enabled {
        router = router.merge(handlers::private_router());
    }

    if state.mcp.is_some() {
        router = router.merge(mcp_router());
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
    if state.mcp.is_some() && is_mcp_or_oauth_path(req.uri().path()) {
        return Ok(next.run(req).await);
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

    Ok(next.run(req).await)
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
