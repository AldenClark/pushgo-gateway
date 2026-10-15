//! Actual ordinary router contracts, generated synthetic credentials.
use crate::{Config, DeliveryStore, router};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
const PREFIX: &str = "/mount/c3";
async fn post(app: &axum::Router, path: &str, input: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{PREFIX}{path}"))
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
#[tokio::test]
async fn native_control_paths_return_current_response_and_error_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (store, owner) = DeliveryStore::open(
        &format!("sqlite://{}/control-wire.sqlite", dir.path().display()),
        Config {
            public_base_url: format!("https://gateway.invalid{PREFIX}"),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let app = router(store.clone(), Arc::new(|| json!({})));
    let (_, register) = post(&app, "/device/register", json!({"platform":"android"})).await;
    let key = register["data"]["device_key"].as_str().unwrap();
    let synthetic_route = crate::types::generate_hex_id_128();
    let (status,route)=post(&app,"/channel/device",json!({"device_key":key,"platform":"android","channel_type":"fcm","provider_token":synthetic_route})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(route["data"]["device_key"], key);
    assert_eq!(route["data"]["channel_type"], "fcm");
    assert_eq!(route["data"]["issued_new_key"], false);
    assert!(route["data"]["route_revision"].is_i64());
    let password = crate::types::generate_hex_id_128();
    let (_, created) = post(
        &app,
        "/channel/subscribe",
        json!({"device_key":key,"channel_name":"wire control","password":password}),
    )
    .await;
    let channel = created["data"]["channel_id"].as_str().unwrap();
    let (status, renamed) = post(
        &app,
        "/channel/rename",
        json!({"channel_id":channel,"channel_name":"renamed","password":password}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["data"]["channel_name"], "renamed");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{PREFIX}/channel/exists?channel_id={channel}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["data"]["exists"], true);
    assert_eq!(body["data"]["channel_name"], "renamed");
    let wrong = crate::types::generate_hex_id_128();
    let (status, sync) = post(
        &app,
        "/channel/sync",
        json!({"device_key":key,"channels":[{"channel_id":channel,"password":wrong}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync["data"]["failed"], 1);
    assert_eq!(
        sync["data"]["channels"][0]["error_code"],
        "password_mismatch"
    );
    assert_eq!(sync["data"]["route"]["channel_type"], "fcm");
    let (status, error) = post(
        &app,
        "/channel/device/delete",
        json!({"device_key":key,"channel_type":"apns"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error_code"], "channel_type_mismatch");
    let (_, unsub) = post(
        &app,
        "/channel/unsubscribe",
        json!({"device_key":key,"channel_id":channel}),
    )
    .await;
    assert_eq!(unsub["data"]["removed"], true);
    let (status, _) = post(
        &app,
        "/channel/device/delete",
        json!({"device_key":key,"channel_type":"fcm"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, retired) = post(
        &app,
        "/channel/device/provider-token/retire",
        json!({"platform":"android","provider_token":synthetic_route}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retired["data"]["retired"], true);
    store.pool.close().await;
    owner.release();
}
