use axum::{
    Router,
    routing::{any, get, post},
};

pub(crate) fn mcp_router() -> Router<crate::app::AppState> {
    Router::new()
        .route("/mcp", any(mcp_http))
        .route(
            "/oauth/authorize",
            get(oauth_authorize_get).post(oauth_authorize_post),
        )
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/revoke", post(oauth_revoke))
        .route("/oauth/register", post(oauth_register))
        .route("/oauth/channel/validate", post(oauth_channel_validate))
        .route("/oauth/jwks.json", get(oauth_jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/oauth",
            get(oauth_metadata),
        )
        .route(
            "/oauth/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(oauth_openid_configuration),
        )
        .route(
            "/.well-known/openid-configuration/oauth",
            get(oauth_openid_configuration),
        )
        .route(
            "/oauth/.well-known/openid-configuration",
            get(oauth_openid_configuration),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth_protected_resource_metadata),
        )
        .route("/mcp/bind/session", get(bind_page_get).post(bind_page_post))
        .route(
            "/mcp/revoke/session",
            get(bind_page_get).post(revoke_page_post),
        )
}
