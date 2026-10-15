//! Explicit diagnostic for the existing HTTP/Private wire size contract seam.
//! A passing diagnostic reports the gap; it is not a delivery acceptance test.
use crate::{Config, OrdinaryStore};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use pushgo_warp_profile::PushgoWireProfile;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use warp_link::warp_link_core::{DeliverMsg, WireProfile};

#[tokio::test]
#[ignore = "explicit C6 HTTP/Private wire boundary diagnostic; not a capability pass"]
async fn legal_http_input_private_wire_size_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.private.enabled = true;
    let (store, owner) = OrdinaryStore::open(
        &format!("sqlite://{}", dir.path().join("size.sqlite").display()),
        config,
    )
    .await
    .unwrap();
    let device = store.register("android").await.unwrap();
    let password = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("wire boundary"), &password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut request = json!({"channel_id":channel,"password":password,"title":"x","body":"","op_id":"private-wire-boundary"});
    let empty = serde_json::to_vec(&request).unwrap().len();
    request["body"] = json!("x".repeat(32768 - empty));
    let input = serde_json::to_vec(&request).unwrap();
    assert_eq!(input.len(), 32768);
    let app = crate::router(store.clone(), Arc::new(|| json!({})));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/message")
                .header("content-type", "application/json")
                .body(Body::from(input))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let accepted: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let route = store.private_route(&device).await.unwrap();
    let ticket = store
        .private_claim(&route, "boundary-diagnostic", 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        ticket.delivery_id,
        accepted["data"]["delivery_id"].as_str().unwrap()
    );
    let payload = crate::private_runtime::encode_payload(&ticket.payload).unwrap();
    let frame = PushgoWireProfile::new()
        .encode_server_deliver(&DeliverMsg {
            seq: Some(1),
            id: ticket.delivery_id.clone(),
            payload,
        })
        .unwrap();
    println!(
        "C6_CONTRACT_BOUNDARY http_bytes=32768 canonical_bytes={} deliver_frame_bytes={} existing_transport_limit=32770",
        ticket.payload.len(),
        frame.len()
    );
    assert!(
        frame.len() > 32770,
        "diagnostic hypothesis must be observed, never assumed"
    );
    store
        .private_release(&ticket.group_id, std::slice::from_ref(&ticket.claim_token))
        .await
        .unwrap();
    store.close().await;
    owner.release();
}
