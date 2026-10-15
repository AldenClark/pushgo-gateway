//! Deterministic admission/body ownership checks; no socket or timing oracle.
use super::*;
use axum::{
    body::{Bytes, to_bytes},
    http::{Method, Request},
};
use futures_util::FutureExt;
use tower::ServiceExt;
fn app_with_budget(total: usize) -> (Router, Arc<Semaphore>, Arc<Semaphore>) {
    let requests = Arc::new(Semaphore::new(total));
    let control = Arc::new(Semaphore::new((total / 8).max(1).min(total)));
    let admission = Admission {
        requests: requests.clone(),
        control: control.clone(),
        auth_hash: None,
        health: Arc::default(),
        password_window: Arc::default(),
    };
    let app = Router::new()
        .route(
            "/v2/messages/pull",
            get(|| async {
                Json(json!({"items":[{"payload":"x".repeat(64*1024)}],"has_more":false}))
            }),
        )
        .route(
            "/message",
            post(|| async { Json(json!({"accepted":true})) }),
        )
        .route("/empty", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/error",
            get(|| async { (StatusCode::BAD_REQUEST, Json(json!({"error":"synthetic"}))) }),
        )
        .route(
            "/stream-error",
            get(|| async {
                Body::from_stream(stream::once(async {
                    Err::<Bytes, _>(std::io::Error::other("synthetic body failure"))
                }))
            }),
        )
        .layer(middleware::from_fn_with_state(admission, bound_handlers));
    (app, requests, control)
}
fn request(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}
#[tokio::test]
async fn seventeenth_control_response_waits_and_resumes_without_new_rejection() {
    let (app, requests, control) = app_with_budget(128);
    let mut held = Vec::new();
    for _ in 0..16 {
        let response = app
            .clone()
            .oneshot(request("/v2/messages/pull"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        let exact = response.headers()[axum::http::header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(exact > 64 * 1024);
        held.push((response, exact));
    }
    assert_eq!(control.available_permits(), 0);
    assert_eq!(requests.available_permits(), 112);
    let mut pending = Box::pin(app.clone().oneshot(request("/v2/messages/pull")));
    assert!(
        pending.as_mut().now_or_never().is_none(),
        "17th control request queues instead of503"
    );
    assert_eq!(
        requests.available_permits(),
        111,
        "waiting control request owns global slot"
    );
    let (response, exact) = held.pop().unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes.len(), exact);
    let replacement = pending.await.unwrap();
    assert_eq!(replacement.status(), StatusCode::OK);
    assert_eq!(control.available_permits(), 0);
    assert_eq!(requests.available_permits(), 112);
    let mut waiting = Box::pin(app.clone().oneshot(request("/v2/messages/pull")));
    assert!(waiting.as_mut().now_or_never().is_none());
    assert_eq!(requests.available_permits(), 111);
    drop(waiting);
    assert_eq!(
        requests.available_permits(),
        112,
        "cancelled waiter releases global slot"
    );
    let mut waiting = Box::pin(app.oneshot(request("/v2/messages/pull")));
    assert!(waiting.as_mut().now_or_never().is_none());
    drop(replacement);
    let replacement = waiting.await.unwrap();
    assert_eq!(replacement.status(), StatusCode::OK);
    drop(replacement);
    drop(held);
    assert_eq!(requests.available_permits(), 128);
    assert_eq!(control.available_permits(), 16);
}
#[tokio::test]
async fn only_original_global_capacity_rejects_and_sender_can_use_last_slot() {
    let (app, requests, control) = app_with_budget(128);
    let held = requests.clone().acquire_many_owned(128).await.unwrap();
    let refused = app
        .clone()
        .oneshot(request("/v2/messages/pull"))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(refused);
    drop(held);
    let held = requests.clone().acquire_many_owned(127).await.unwrap();
    let sender = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/message")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sender.status(), StatusCode::OK, "no separate112 sender cap");
    assert_eq!(requests.available_permits(), 0);
    assert_eq!(control.available_permits(), 16);
    drop(sender);
    drop(held);
    assert_eq!(requests.available_permits(), 128);
}
#[tokio::test]
async fn empty_and_error_responses_release_both_owned_permits() {
    let (app, requests, control) = app_with_budget(128);
    let empty = app.clone().oneshot(request("/empty")).await.unwrap();
    assert_eq!(empty.status(), StatusCode::NO_CONTENT);
    assert_eq!(control.available_permits(), 16);
    assert_eq!(requests.available_permits(), 128);
    assert!(
        to_bytes(empty.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
    let error = app.clone().oneshot(request("/error")).await.unwrap();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(control.available_permits(), 15);
    assert_eq!(requests.available_permits(), 127);
    to_bytes(error.into_body(), usize::MAX).await.unwrap();
    assert_eq!(control.available_permits(), 16);
    assert_eq!(requests.available_permits(), 128);
    let dropped = app.clone().oneshot(request("/error")).await.unwrap();
    drop(dropped);
    assert_eq!(control.available_permits(), 16);
    assert_eq!(requests.available_permits(), 128);
    let error = app.oneshot(request("/stream-error")).await.unwrap();
    assert!(to_bytes(error.into_body(), usize::MAX).await.is_err());
    assert_eq!(control.available_permits(), 16);
    assert_eq!(requests.available_permits(), 128);
}
#[tokio::test]
async fn single_handler_budget_uses_distinct_request_and_control_semaphores() {
    let (app, requests, control) = app_with_budget(1);
    let response = app
        .oneshot(request("/v2/messages/pull"))
        .now_or_never()
        .expect("separate semaphores must not deadlock")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(requests.available_permits(), 0);
    assert_eq!(control.available_permits(), 0);
    drop(response);
    assert_eq!(requests.available_permits(), 1);
    assert_eq!(control.available_permits(), 1);
}
