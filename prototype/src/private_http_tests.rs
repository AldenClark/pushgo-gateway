//! HTTP-only profile/prefix/auth contracts; transport sessions have native oracles.
use super::*;
use crate::{
    private_http::discovery_profile,
    private_runtime::{PrivateRuntime, PrivateRuntimeConfig},
    store::{Config, DeliveryStore},
};
use axum::{body::to_bytes, http::Request};
use tower::ServiceExt;

async fn response(app: Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn disabled_profile_is_main_shape_and_shares_auth_and_base_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("http.db").display());
    let (store, owner) = DeliveryStore::open(
        &url,
        Config {
            public_base_url: "http://127.0.0.1:4400/prefix".into(),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let app = router_with_auth(
        store.clone(),
        Arc::new(|| json!({})),
        Some("synthetic-shared"),
    );
    assert_eq!(
        response(app.clone(), "/prefix/gateway/profile", None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = response(
        app.clone(),
        "/prefix/gateway/profile",
        Some("synthetic-shared"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"success":true,"data":{"private_channel_enabled":false,"private_enabled":false}})
    );
    assert_eq!(
        response(app.clone(), "/gateway/profile", Some("synthetic-shared"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        response(app, "/prefix/private/ws", Some("synthetic-shared"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    store.pool.close().await;
    owner.release();
}

#[tokio::test]
async fn private_tcp_only_profile_reports_actual_port_without_mounting_wss() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("http-private.db").display());
    let mut config = Config {
        public_base_url: "http://127.0.0.1:4400/prefix".into(),
        ..Config::default()
    };
    config.private.enabled = true;
    let (store, owner) = DeliveryStore::open(&url, config).await.unwrap();
    let runtime = PrivateRuntime::new(
        store.clone().into(),
        Some("synthetic-shared".into()),
        PrivateRuntimeConfig::default(),
    )
    .unwrap();
    let profile = discovery_profile(
        &store.config.public_base_url,
        Some("127.0.0.1:4401".parse().unwrap()),
        None,
        None,
        false,
        4400,
    );
    let private = PrivateHttp::new(
        runtime.clone(),
        crate::private_listeners::server_config(),
        profile.clone(),
    );
    let app = router_with_private(
        store.clone(),
        Arc::new(|| json!({})),
        Some("synthetic-shared"),
        Some(private.clone()),
    );
    let (status, body) = response(
        app.clone(),
        "/prefix/gateway/profile",
        Some("synthetic-shared"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"success":true,"data":profile}));
    assert_eq!(body["data"]["transport"]["tcp_port"], 4401);
    assert_eq!(
        response(app, "/prefix/private/ws", Some("synthetic-shared"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    private.shutdown().await.unwrap();
    runtime.shutdown().await.unwrap();
    store.pool.close().await;
    owner.release();
}
