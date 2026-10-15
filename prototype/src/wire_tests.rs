//! Actual router and loopback server checks; native client decoding is separate.
use crate::{
    http,
    store::{Config, DeliveryStore, OwnerLock},
};
use serde_json::{Value, json};
use std::sync::Arc;

async fn fixture() -> (
    tempfile::TempDir,
    DeliveryStore,
    OwnerLock,
    tokio::task::JoinHandle<()>,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/gateway", listener.local_addr().unwrap());
    let (store, owner) = DeliveryStore::open(
        &format!("sqlite://{}", dir.path().join("wire.sqlite").display()),
        Config {
            public_base_url: format!("{base}///"),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let app = http::router(store.clone(), Arc::new(|| json!({})));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (dir, store, owner, server, base)
}
async fn post(client: &reqwest::Client, base: &str, path: &str, body: Value) -> Value {
    let response = client
        .post(format!("{base}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    response.json().await.unwrap()
}
async fn accept(
    client: &reqwest::Client,
    base: &str,
    channel: &str,
    auth: &str,
    op: &str,
) -> Value {
    post(client, base, "/message", json!({"channel_id":channel,"password":auth,"op_id":op,"title":"wire","body":"canonical body","ttl":crate::store::now()+60_000})).await["data"].clone()
}
#[tokio::test]
async fn ordinary_router_supports_prefixed_legacy_and_v2_clients() {
    let (_dir, store, owner, server, base) = fixture().await;
    let client = reqwest::Client::new();
    let device = post(
        &client,
        &base,
        "/device/register",
        json!({"platform":"android"}),
    )
    .await["data"]["device_key"]
        .as_str()
        .unwrap()
        .to_owned();
    post(
        &client,
        &base,
        "/channel/device",
        json!({"device_key":device,"channel_type":"fcm","provider_token":crate::types::generate_hex_id_128()}),
    )
    .await;
    let auth = crate::types::generate_hex_id_128();
    let channel = post(
        &client,
        &base,
        "/channel/subscribe",
        json!({"device_key":device,"channel_name":"wire channel","password":auth}),
    )
    .await["data"]["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let accepted = accept(&client, &base, &channel, &auth, "wire-ack-op").await;
    let delivery = accepted["delivery_id"].as_str().unwrap();
    let pull_body =
        json!({"device_key":format!(" {device} "),"delivery_id":format!(" {delivery} ")});
    let first = post(&client, &base, "/v2/messages/pull", pull_body.clone()).await;
    assert_eq!(
        first,
        post(&client, &base, "/v2/messages/pull", pull_body.clone()).await
    );
    assert_eq!(first["data"]["items"][0]["delivery_id"], delivery);
    let payload = first["data"]["items"][0]["payload"].as_object().unwrap();
    assert!(payload.values().all(Value::is_string));
    assert_eq!(payload["base_url"], base);
    assert!(payload["sent_at"].as_str().unwrap().parse::<i64>().unwrap() > 1_000_000_000_000);
    assert!(payload["ttl"].as_str().unwrap().parse::<i64>().unwrap() > 1_000_000_000_000);
    assert_eq!(
        post(
            &client,
            &base,
            "/messages/ack",
            json!({"device_key":device,"delivery_id":delivery})
        )
        .await["data"]["removed"],
        true
    );
    assert_eq!(
        post(
            &client,
            &base,
            "/messages/ack",
            json!({"device_key":device,"delivery_id":delivery})
        )
        .await["data"]["removed"],
        false
    );
    assert_eq!(
        post(&client, &base, "/v2/messages/pull", pull_body).await["data"]["items"],
        json!([])
    );
    let accepted = accept(&client, &base, &channel, &auth, "wire-legacy-pull-op").await;
    let delivery = accepted["delivery_id"].as_str().unwrap();
    let legacy = post(
        &client,
        &base,
        "/messages/pull",
        json!({"device_key":device,"delivery_id":delivery}),
    )
    .await;
    assert_eq!(legacy["data"]["items"][0]["delivery_id"], delivery);
    assert!(legacy["data"].get("has_more").is_none());
    assert_eq!(
        post(
            &client,
            &base,
            "/v2/messages/pull",
            json!({"device_key":device,"delivery_id":delivery})
        )
        .await["data"]["items"],
        json!([])
    );
    let accepted = accept(&client, &base, &channel, &auth, "wire-v2-ack-op").await;
    let delivery = accepted["delivery_id"].as_str().unwrap();
    assert_eq!(
        post(
            &client,
            &base,
            "/v2/messages/ack",
            json!({"device_key":device,"delivery_ids":vec![format!(" {delivery} "); 201]})
        )
        .await["data"],
        json!({"requested_count":1,"removed_count":1})
    );
    for body in [
        json!({"device_key":" ","delivery_id":"id"}),
        json!({"device_key":device,"delivery_id":" "}),
    ] {
        let response = client
            .post(format!("{base}/messages/ack"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }
    let unknown = client
        .post(format!("{base}/messages/ack"))
        .json(&json!({"device_key":device,"delivery_id":"id","redirect":"https://bad.invalid"}))
        .send()
        .await
        .unwrap();
    assert!(unknown.status().is_success());
    assert_eq!(
        unknown.json::<Value>().await.unwrap()["data"]["removed"],
        false
    );
    let response = client.post(format!("{base}/v2/messages/ack")).json(&json!({"device_key":device,"delivery_ids":(0..201).map(|v| format!("id-{v}")).collect::<Vec<_>>()})).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let response = client
        .post(format!("{base}/v2/messages/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error_code"],
        "route_not_found"
    );
    let response = client
        .get(format!("{base}/v2/messages/pull"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    store.pool.close().await;
    owner.release();
}

#[tokio::test]
async fn sender_router_preserves_full_fields_and_generates_distinct_omitted_op_ids() {
    let (_dir, store, owner, server, base) = fixture().await;
    let client = reqwest::Client::new();
    let device = store.register("android").await.unwrap();
    store
        .route(&device, None, "FCM", "synthetic-full-fields")
        .await
        .unwrap();
    let auth = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("full fields"), &auth)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let occurred_at = crate::store::now() - 1000;
    let expiry = crate::store::now() + 60_000;
    let input = json!({"channel_id":channel,"password":auth,"title":"full",
        "ttl":expiry.to_string(),"occurred_at":occurred_at,"severity":"HIGH",
        "url":"https://fixture.invalid/message","images":["https://fixture.invalid/image"],
        "ciphertext":"synthetic-ciphertext","tags":["one","two"],
        "metadata":{"tenant":"synthetic","count":2,"enabled":true}});
    let first = post(&client, &base, "/message", input.clone()).await["data"].clone();
    let second = post(&client, &base, "/message", input).await["data"].clone();
    assert_ne!(first["op_id"], second["op_id"]);
    assert_ne!(first["delivery_id"], second["delivery_id"]);
    let pull = post(
        &client,
        &base,
        "/v2/messages/pull",
        json!({"device_key":device,"delivery_id":first["delivery_id"]}),
    )
    .await;
    let payload = &pull["data"]["items"][0]["payload"];
    assert_eq!(payload["op_id"], first["op_id"]);
    assert_eq!(payload["ttl"], expiry.to_string());
    assert_eq!(payload["occurred_at"], occurred_at.to_string());
    assert_eq!(payload["severity"], "high");
    assert_eq!(payload["url"], "https://fixture.invalid/message");
    assert_eq!(payload["ciphertext"], "synthetic-ciphertext");
    assert!(payload.get("body").is_none());
    assert_eq!(
        serde_json::from_str::<Value>(payload["images"].as_str().unwrap()).unwrap(),
        json!(["https://fixture.invalid/image"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(payload["tags"].as_str().unwrap()).unwrap(),
        json!(["one", "two"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(payload["metadata"].as_str().unwrap()).unwrap(),
        json!({"tenant":"synthetic","count":2,"enabled":true})
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    store.pool.close().await;
    owner.release();
}

#[tokio::test]
async fn repeated_register_reuses_current_ordinary_identity_and_route() {
    let (_dir, store, owner, server, base) = fixture().await;
    let client = reqwest::Client::new();
    let first = post(
        &client,
        &base,
        "/device/register",
        json!({"platform":"android"}),
    )
    .await;
    let key = first["data"]["device_key"].as_str().unwrap();
    assert_eq!(first["data"]["issued_new_key"], true);
    assert_eq!(first["data"]["issue_reason"], "device_key_missing");
    assert_eq!(
        first["data"]["route"],
        json!({"channel_type":"private","route_revision":1,"provider_token_present":false})
    );
    post(&client,&base,"/channel/device",json!({"device_key":key,"channel_type":"FCM","provider_token":"synthetic-registration-provider-token"})).await;
    let auth = crate::types::generate_hex_id_128();
    let subscribed = post(
        &client,
        &base,
        "/channel/subscribe",
        json!({"device_key":key,"channel_name":"synthetic reused registration","password":auth}),
    )
    .await;
    let channel = subscribed["data"]["channel_id"].as_str().unwrap();
    let send = json!({"channel_id":channel,"password":auth,"title":"unchanged registration message","op_id":"register-stable-op","ttl":crate::store::now()+60_000});
    let accepted = post(&client, &base, "/message", send.clone()).await;
    let before:(String,String,Vec<u8>,i64,i64)=sqlx::query_as("SELECT delivery_id,message_id,payload_blob,accepted_at,dedupe_until FROM messages WHERE op_id='register-stable-op'").fetch_one(&store.pool).await.unwrap();
    let registered = post(
        &client,
        &base,
        "/device/register",
        json!({"platform":"android","device_key":format!(" {key} ")}),
    )
    .await;
    assert_eq!(registered["data"]["device_key"], key);
    assert_eq!(registered["data"]["issued_new_key"], false);
    assert!(registered["data"].get("issue_reason").is_none());
    assert_eq!(registered["data"]["route"]["channel_type"], "fcm");
    assert_eq!(registered["data"]["route"]["provider_token_present"], true);
    assert_eq!(
        registered["data"]["route_revision"],
        registered["data"]["route"]["route_revision"]
    );
    let after:(String,String,Vec<u8>,i64,i64)=sqlx::query_as("SELECT delivery_id,message_id,payload_blob,accepted_at,dedupe_until FROM messages WHERE op_id='register-stable-op'").fetch_one(&store.pool).await.unwrap();
    assert_eq!(after, before);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
    )
    .bind(channel)
    .bind(key)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    let target: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=? AND device_key=?")
            .bind(&before.0)
            .bind(key)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(target, 1);
    let ack = post(
        &client,
        &base,
        "/v2/messages/ack",
        json!({"device_key":registered["data"]["device_key"],"delivery_ids":[before.0]}),
    )
    .await;
    assert_eq!(ack["data"]["removed_count"], 1);
    let duplicate = post(&client, &base, "/message", send).await;
    assert_eq!(
        duplicate["data"]["message_id"],
        accepted["data"]["message_id"]
    );
    let pull = post(
        &client,
        &base,
        "/v2/messages/pull",
        json!({"device_key":key}),
    )
    .await;
    assert!(pull["data"]["items"].as_array().unwrap().is_empty());
    server.abort();
    store.pool.close().await;
    owner.release();
}
#[tokio::test]
async fn blank_and_unknown_keys_get_fresh_identity_with_mainline_reason() {
    let (_dir, store, owner, server, base) = fixture().await;
    let client = reqwest::Client::new();
    for (key, reason) in [
        ("   ", "device_key_missing"),
        ("synthetic-unknown-device", "device_key_not_found"),
    ] {
        let response = post(
            &client,
            &base,
            "/device/register",
            json!({"platform":"android","device_key":key}),
        )
        .await;
        assert_eq!(response["data"]["issued_new_key"], true);
        assert_eq!(response["data"]["issue_reason"], reason);
        assert_ne!(response["data"]["device_key"], key);
        assert_eq!(response["data"]["route"]["channel_type"], "private");
        assert_eq!(response["data"]["route"]["provider_token_present"], false);
    }
    server.abort();
    store.pool.close().await;
    owner.release();
}
