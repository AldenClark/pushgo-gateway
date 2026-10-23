//! Normal App/Router/SQLite and real APNS_WIDGETS worker coverage with synthetic
//! injected Provider clients. This is not a normal executable/HTTP socket,
//! physical Widget, credential service, or actual APNs acceptance test.
use super::transport::tests::ExistingClients;
use crate::{
    app::{AppRuntime, build_app},
    args::Args,
    dispatch::DurableProviderJob,
    providers::{
        ApnsClient, BoxFuture, DispatchResult, ProviderFailureKind, TokenInfo, apns::ApnsPayload,
    },
    storage::Platform,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use clap::Parser;
use serde_json::{Value, json};
use sqlx::{Connection, Row, SqliteConnection};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
use tower::ServiceExt;

struct WidgetClients {
    accepted: ExistingClients,
    invalid: String,
    valid: String,
    ordinary: String,
    calls: Mutex<Vec<String>>,
    widget_replies: Semaphore,
}
impl ApnsClient for WidgetClients {
    fn send_to_device<'a>(
        &'a self,
        token: &'a str,
        platform: Platform,
        payload: Arc<ApnsPayload>,
        collapse: Option<Arc<str>>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            {
                let mut calls = self.calls.lock().unwrap();
                assert!(calls.len() < 16, "unexpected repeated Provider attempts");
                calls.push(token.to_owned());
            }
            if token == self.invalid || token == self.valid {
                assert_eq!(
                    payload.encoded_body().unwrap(),
                    ApnsPayload::widgets().encoded_body().unwrap()
                );
                self.widget_replies.acquire().await.unwrap().forget();
            } else {
                assert_eq!(token, self.ordinary, "unexpected APNs target");
            }
            if token == self.invalid {
                DispatchResult {
                    success: false,
                    status_code: 410,
                    error: None,
                    failure_kind: Some(ProviderFailureKind::InvalidToken),
                    retry_after_millis: None,
                }
            } else {
                self.accepted
                    .send_to_device(token, platform, payload, collapse)
                    .await
            }
        })
    }
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
        panic!("injected Provider must not acquire real credentials")
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, crate::Error>> {
        panic!("injected Provider must not refresh real credentials")
    }
}

async fn api(router: &Router, path: &str, body: Option<Value>) -> Value {
    let method = if body.is_some() { "POST" } else { "GET" };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(body.map_or_else(Body::empty, |body| {
                    Body::from(serde_json::to_vec(&body).unwrap())
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{path}: {response:?}");
    response["data"].clone()
}

async fn stop(app: AppRuntime) {
    drop(app.router);
    let report = app.shutdown.shutdown(Duration::from_secs(10)).await;
    assert_eq!((report.failed, report.panicked, report.aborted), (0, 0, 0));
}

#[tokio::test]
async fn product_widget_worker_invalid_token_cleanup_is_token_scoped_across_replay_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("product.db").display()
    );
    let mut args = Args::parse_from([
        "pushgo-gateway",
        "--db-url",
        &url,
        "--http-addr",
        "127.0.0.1:0",
        "--private-transports",
        "none",
        "--runtime-profile",
        "small",
    ])
    .normalized();
    // Do not inherit optional process environment authentication or transports.
    args.token = None;
    args.mcp_enabled = false;
    args.public_base_url = None;
    let clients = Arc::new(WidgetClients {
        accepted: ExistingClients::default(),
        invalid: "a1".repeat(32),
        valid: "b2".repeat(32),
        ordinary: "c3".repeat(32),
        calls: Mutex::default(),
        widget_replies: Semaphore::new(0),
    });
    let unused = Arc::new(ExistingClients::default());
    let app = build_app(
        &args,
        clients.clone(),
        unused.clone(),
        unused.clone(),
        "<html>QA</html>",
    )
    .await
    .unwrap();
    let registration = api(
        &app.router,
        "/device/register",
        Some(json!({"platform":"ios"})),
    )
    .await;
    let device = registration["device_key"].as_str().unwrap().to_owned();
    api(&app.router, "/channel/device", Some(json!({
        "device_key":device, "platform":"ios", "channel_type":"apns", "provider_token":clients.ordinary,
    }))).await;
    let fixture_auth = crate::util::generate_hex_id_128();
    let channel = api(
        &app.router,
        "/channel/subscribe",
        Some(json!({
            "device_key":device, "channel_name":"ordinary-widget-worker", "password":fixture_auth,
        })),
    )
    .await["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for token in [&clients.invalid, &clients.valid] {
        let subscribed = api(
            &app.router,
            "/v1/widget-push/subscription",
            Some(json!({
                "device_key":device, "platform":"ios", "token":token, "schema_version":1,
                "widgets":[
                    {"kind":"io.ethan.pushgo.widgets.unread", "family":"systemMedium"},
                    {"kind":"io.ethan.pushgo.widgets.watch-summary", "family":"systemSmall"},
                ],
            })),
        )
        .await;
        assert_eq!(subscribed["widget_count"], 2);
    }
    let mut core = SqliteConnection::connect(&format!(
        "sqlite://{}?mode=ro",
        directory.path().join("product.db").display()
    ))
    .await
    .unwrap();
    let mut dispatch = SqliteConnection::connect(&format!(
        "sqlite://{}?mode=ro",
        directory.path().join("product.dispatch.db").display()
    ))
    .await
    .unwrap();
    assert_subscriptions(&mut core, &clients, 2).await;
    let request = json!({
        "channel_id":channel, "password":fixture_auth, "op_id":"widget-worker-original",
        "title":"ordinary Widget refresh", "body":"完整正文 remains canonical",
    });
    let accepted = api(&app.router, "/message", Some(request.clone())).await;
    let message_id = accepted["message_id"].as_str().unwrap().to_owned();
    wait_for(&mut core, &mut dispatch, false).await;
    let rows = sqlx::query("SELECT job_id,delivery_id,payload_blob,coalesce_order,op_id,dedupe_key FROM provider_dispatch_outbox WHERE provider='APNS_WIDGETS'")
        .fetch_all(&mut dispatch).await.unwrap();
    assert_eq!(
        rows.len(),
        2,
        "two kinds per token must produce two token-scoped jobs"
    );
    let mut tokens = Vec::new();
    for row in rows {
        assert!(row.get::<Option<String>, _>("op_id").is_none());
        assert!(row.get::<Option<String>, _>("dedupe_key").is_none());
        assert!(row.get::<i64, _>("coalesce_order") > 0);
        let blob: Vec<u8> = row.get("payload_blob");
        let job = serde_json::from_slice::<DurableProviderJob>(&blob)
            .unwrap()
            .into_widget()
            .unwrap();
        assert!(job.ordinary_target_scoped);
        assert_eq!(job.device_key.as_ref(), device);
        assert_eq!(
            job.widget_kinds.as_ref(),
            [
                "io.ethan.pushgo.widgets.unread",
                "io.ethan.pushgo.widgets.watch-summary"
            ]
        );
        tokens.push(job.device_token.to_string());
    }
    tokens.sort();
    assert_eq!(tokens, [clients.invalid.clone(), clients.valid.clone()]);
    clients.widget_replies.add_permits(2);
    wait_for(&mut core, &mut dispatch, true).await;
    assert_subscriptions(&mut core, &clients, 0).await;
    assert_terminal_jobs(&mut dispatch, &clients).await;
    let status = api(&app.router, "/send_status/widget-worker-original", None).await;
    assert_eq!(
        status["status"], "sent",
        "derived Widget failure cannot fail ordinary delivery"
    );
    assert_eq!(status["entity_id"], message_id);
    let original = sqlx::query("SELECT delivery_id,accepted_at,expires_at,dedupe_until,payload_bytes,provider_accepted_count,provider_failed_count FROM ordinary_messages WHERE op_id='widget-worker-original'")
        .fetch_one(&mut core).await.unwrap();
    let delivery: String = original.get("delivery_id");
    assert!(original.get::<i64, _>("payload_bytes") > 0);
    assert_eq!(original.get::<i64, _>("provider_accepted_count"), 1);
    assert_eq!(original.get::<i64, _>("provider_failed_count"), 0);
    assert_eq!(
        original.get::<i64, _>("dedupe_until") - original.get::<i64, _>("accepted_at"),
        30 * 86_400_000
    );
    let replay = api(&app.router, "/message", Some(request.clone())).await;
    assert_eq!(replay["message_id"], message_id);
    let pulled = api(
        &app.router,
        "/v2/messages/pull",
        Some(json!({"device_key":device})),
    )
    .await;
    assert_eq!(pulled["items"].as_array().unwrap().len(), 1);
    assert_eq!(pulled["items"][0]["payload"]["message_id"], message_id);
    assert_eq!(
        pulled["items"][0]["payload"]["body"],
        "完整正文 remains canonical"
    );
    for removed in [1, 0] {
        let ack = api(
            &app.router,
            "/v2/messages/ack",
            Some(json!({"device_key":device,"delivery_ids":[delivery]})),
        )
        .await;
        assert_eq!(ack["removed_count"], removed);
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT payload_bytes FROM ordinary_messages WHERE op_id='widget-worker-original'"
        )
        .fetch_one(&mut core)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ordinary_targets")
            .fetch_one(&mut core)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM provider_dispatch_outbox WHERE provider IN ('APNS','FCM','WNS')"
        )
        .fetch_one(&mut dispatch)
        .await
        .unwrap(),
        0
    );
    core.close().await.unwrap();
    dispatch.close().await.unwrap();
    stop(app).await;

    // Normal build_app startup recovery must not revive a retired token or a
    // completed derived job. A new message proves the other token still works.
    let app = build_app(
        &args,
        clients.clone(),
        unused.clone(),
        unused,
        "<html>QA</html>",
    )
    .await
    .unwrap();
    let replay = api(&app.router, "/message", Some(request.clone())).await;
    assert_eq!(replay["message_id"], message_id);
    let empty = api(
        &app.router,
        "/v2/messages/pull",
        Some(json!({"device_key":device})),
    )
    .await;
    assert!(empty["items"].as_array().unwrap().is_empty());
    let mut core = SqliteConnection::connect(&format!(
        "sqlite://{}?mode=ro",
        directory.path().join("product.db").display()
    ))
    .await
    .unwrap();
    let mut dispatch = SqliteConnection::connect(&format!(
        "sqlite://{}?mode=ro",
        directory.path().join("product.dispatch.db").display()
    ))
    .await
    .unwrap();
    assert_subscriptions(&mut core, &clients, 0).await;
    assert_terminal_jobs(&mut dispatch, &clients).await;
    let persisted = sqlx::query("SELECT accepted_at,expires_at,payload_bytes FROM ordinary_messages WHERE op_id='widget-worker-original'").fetch_one(&mut core).await.unwrap();
    assert_eq!(
        persisted.get::<i64, _>("accepted_at"),
        original.get::<i64, _>("accepted_at")
    );
    assert_eq!(
        persisted.get::<i64, _>("expires_at"),
        original.get::<i64, _>("expires_at")
    );
    assert_eq!(persisted.get::<i64, _>("payload_bytes"), 0);
    let mut next = request;
    next["op_id"] = json!("widget-worker-after-restart");
    let next = api(&app.router, "/message", Some(next)).await;
    assert_ne!(next["message_id"], message_id);
    clients.widget_replies.add_permits(1);
    wait_for(&mut core, &mut dispatch, true).await;
    assert_subscriptions(&mut core, &clients, 0).await;
    let calls = clients.calls.lock().unwrap().clone();
    assert_eq!(
        calls
            .iter()
            .filter(|token| **token == clients.invalid)
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|token| **token == clients.valid)
            .count(),
        2
    );
    assert_eq!(
        calls
            .iter()
            .filter(|token| **token == clients.ordinary)
            .count(),
        2
    );
    assert_terminal_jobs(&mut dispatch, &clients).await;
    core.close().await.unwrap();
    dispatch.close().await.unwrap();
    stop(app).await;
}

async fn assert_subscriptions(
    core: &mut SqliteConnection,
    clients: &WidgetClients,
    invalid_count: i64,
) {
    for (token, expected) in [(&clients.invalid, invalid_count), (&clients.valid, 2)] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM widget_push_subscriptions WHERE platform='ios' AND token=?",
        )
        .bind(token)
        .fetch_one(&mut *core)
        .await
        .unwrap();
        assert_eq!(
            count, expected,
            "cleanup must affect only the invalid token"
        );
    }
}

async fn wait_for(core: &mut SqliteConnection, dispatch: &mut SqliteConnection, settled: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let jobs: i64 = sqlx::query_scalar(if settled {
                "SELECT COUNT(*) FROM provider_dispatch_outbox WHERE provider='APNS_WIDGETS' AND state IN ('provider_accepted','permanent_failed')"
            } else {
                "SELECT COUNT(*) FROM provider_dispatch_outbox WHERE provider='APNS_WIDGETS'"
            }).fetch_one(&mut *dispatch).await.unwrap();
            let received: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets WHERE state <> 'provider_accepted'").fetch_one(&mut *core).await.unwrap();
            let subscriptions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM widget_push_subscriptions").fetch_one(&mut *core).await.unwrap();
            let markers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_widget_refresh").fetch_one(&mut *core).await.unwrap();
            if jobs == 2 && markers == 0 && (!settled || (received == 0 && subscriptions == 2)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("normal Provider/Widget work should establish its durable result");
}

async fn assert_terminal_jobs(dispatch: &mut SqliteConnection, clients: &WidgetClients) {
    let rows = sqlx::query("SELECT payload_blob,state,provider_status,attempt_count FROM provider_dispatch_outbox WHERE provider='APNS_WIDGETS'")
        .fetch_all(&mut *dispatch).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let blob: Vec<u8> = row.get("payload_blob");
        let job = serde_json::from_slice::<DurableProviderJob>(&blob)
            .unwrap()
            .into_widget()
            .unwrap();
        let invalid = job.device_token.as_ref() == clients.invalid;
        assert!(invalid || job.device_token.as_ref() == clients.valid);
        assert_eq!(
            row.get::<String, _>("state"),
            if invalid {
                "permanent_failed"
            } else {
                "provider_accepted"
            }
        );
        assert_eq!(
            row.get::<i64, _>("provider_status"),
            if invalid { 410 } else { 200 }
        );
        assert_eq!(row.get::<i64, _>("attempt_count"), 1);
    }
}
