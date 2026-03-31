use axum::{
    Router,
    routing::{get, post},
};

pub(crate) fn mcp_router() -> Router<crate::app::AppState> {
    Router::new()
        .route("/mcp", get(mcp_get).post(mcp_post))
        .route(
            "/oauth/authorize",
            get(oauth_authorize_get).post(oauth_authorize_post),
        )
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/revoke", post(oauth_revoke))
        .route("/oauth/jwks.json", get(oauth_jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route("/mcp/bind/session", get(bind_page_get).post(bind_page_post))
        .route(
            "/mcp/revoke/session",
            get(bind_page_get).post(revoke_page_post),
        )
}
