//! Real normal Storage + application seam with an isolated new SQLite database.
//! These checks never start a prototype server or claim network/client coverage.
use std::sync::Arc;

use crate::{
    api::handlers::message::MessageIntent,
    domain_model::message::MessageInput,
    ordinary::{
        Config, KernelError, OrdinaryStore,
        owner::ProductOwner,
        store::{Health, now},
    },
    storage::{DeviceRouteRecordRow, PrivateDeviceId, Storage, StorageInitConfig},
};
use serde_json::{Value, json};
use sqlx::{Connection, Row, SqliteConnection};

struct Product {
    directory: tempfile::TempDir,
    storage: Storage,
    ordinary: OrdinaryStore,
    owner: ProductOwner,
}

impl Product {
    async fn open(directory: tempfile::TempDir) -> Self {
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("product.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url),
            mcp_enabled: false,
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config::default();
        config.private.enabled = true;
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
        Self {
            directory,
            storage,
            ordinary,
            owner,
        }
    }

    async fn inspect(&self) -> SqliteConnection {
        SqliteConnection::connect(&format!(
            "sqlite://{}?mode=ro",
            self.directory.path().join("product.db").display()
        ))
        .await
        .unwrap()
    }

    async fn channel_with_targets(&self) -> [u8; 16] {
        let channel = self
            .storage
            .upsert_private_channel(
                None,
                Some("ordinary expiry"),
                &crate::util::generate_hex_id_128(),
            )
            .await
            .unwrap()
            .channel_id;
        for (key, platform, kind, provider_token) in [
            (
                "expiry-provider",
                "android",
                "fcm",
                Some(crate::util::generate_hex_id_128()),
            ),
            ("expiry-private", "windows", "private", None),
            ("expiry-mqtt", "mqtt", "private", None),
        ] {
            self.storage
                .upsert_device_route(&DeviceRouteRecordRow {
                    device_key: key.into(),
                    platform: platform.into(),
                    channel_type: kind.into(),
                    provider_token,
                    updated_at: now(),
                })
                .await
                .unwrap();
            self.storage
                .private_subscribe_channel(channel, PrivateDeviceId::derive(key).into())
                .await
                .unwrap();
        }
        channel
    }

    async fn stop(self) -> tempfile::TempDir {
        self.storage.close_ordinary_storage().await.unwrap();
        self.owner.shutdown().await.unwrap();
        self.directory
    }
}

fn input(channel: [u8; 16], op: &str, raw_ttl: Option<Value>) -> MessageInput {
    let mut raw = json!({
        "channel_id": crate::value::ChannelId::from(channel).to_string(),
        "password": String::new(), "op_id": op, "title": "ordinary expiry",
        "body": "preserved input", "thing_id": "expiry-related-thing", "occurred_at": 1_725_000_000_000_i64,
    });
    if let Some(ttl) = raw_ttl {
        raw["ttl"] = ttl;
    }
    let parsed: MessageIntent = serde_json::from_value(raw).unwrap();
    MessageInput {
        op_id: parsed.op_id,
        thing_id: parsed.thing_id,
        occurred_at: parsed.occurred_at,
        title: parsed.title,
        body: parsed.body,
        severity: parsed.severity,
        ttl: parsed.ttl,
        url: parsed.url,
        images: parsed.images,
        ciphertext: parsed.ciphertext,
        tags: parsed.tags,
        metadata: parsed.metadata,
    }
}

#[tokio::test]
async fn expired_product_acceptance_preserves_identity_without_any_delivery_work() {
    let product = Product::open(tempfile::tempdir().unwrap()).await;
    let channel = product.channel_with_targets().await;
    let mut persisted = Vec::new();
    for (index, ttl) in [json!(0), json!(-1), json!(now() - 1)]
        .into_iter()
        .enumerate()
    {
        let op = format!("product-expired-{index}");
        let request = input(channel, &op, Some(ttl));
        let accepted = product
            .ordinary
            .accept_authorized(channel, request.clone(), now())
            .await
            .unwrap();
        let first_status = product.ordinary.status(&op).await.unwrap();
        assert_eq!(accepted.dispatch_status, "not_attempted");
        let duplicate = product
            .ordinary
            .accept_authorized(channel, request.clone(), now() + 1000)
            .await
            .unwrap();
        assert_eq!(duplicate.acceptance, "duplicate_completed");
        assert_eq!(duplicate.dispatch_status, "not_attempted");
        assert_eq!(accepted.message_id, duplicate.message_id);
        assert_eq!(accepted.delivery_id, duplicate.delivery_id);
        assert_eq!(
            first_status["accepted_at"],
            product.ordinary.status(&op).await.unwrap()["accepted_at"]
        );
        assert!(
            product.ordinary.target_status(&op).await.unwrap()["targets"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let mut connection = product.inspect().await;
        let row = sqlx::query("SELECT payload_bytes,accepted_at,expires_at,dedupe_until FROM ordinary_messages WHERE op_id=?")
            .bind(&op).fetch_one(&mut connection).await.unwrap();
        assert_eq!(row.get::<i64, _>("payload_bytes"), 0);
        assert!(super::super::expiry::is_expired(
            row.get("expires_at"),
            row.get("accepted_at")
        ));
        assert_eq!(
            row.get::<i64, _>("dedupe_until") - row.get::<i64, _>("accepted_at"),
            30 * 86_400_000
        );
        persisted.push((
            op,
            request,
            accepted.message_id,
            accepted.delivery_id,
            first_status,
        ));
    }
    for provider in ["FCM", "APNS", "WNS"] {
        assert!(
            product
                .ordinary
                .claim_reserved(provider, 32, false)
                .await
                .unwrap()
                .tickets
                .is_empty()
        );
    }
    assert!(
        product
            .ordinary
            .pull("expiry-provider", None)
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for device in ["expiry-private", "expiry-mqtt"] {
        let route = product.ordinary.private_route(device).await.unwrap();
        assert!(
            product
                .ordinary
                .private_claim(&route, "expiry-group", 32)
                .await
                .unwrap()
                .is_empty()
        );
    }
    let product = Product::open(product.stop().await).await;
    for (op, request, message_id, delivery_id, first_status) in persisted {
        let accepted = product
            .ordinary
            .accept_authorized(channel, request, now())
            .await
            .unwrap();
        assert_eq!(accepted.message_id, message_id);
        assert_eq!(accepted.delivery_id, delivery_id);
        assert_eq!(accepted.dispatch_status, "not_attempted");
        assert_eq!(
            product.ordinary.status(&op).await.unwrap()["accepted_at"],
            first_status["accepted_at"]
        );
    }
    product.stop().await;
}

#[tokio::test]
async fn absent_and_null_ttl_freeze_the_normal_small_default_at_first_commit() {
    let product = Product::open(tempfile::tempdir().unwrap()).await;
    let channel = product.channel_with_targets().await;
    for (index, raw_ttl) in [None, Some(Value::Null)].into_iter().enumerate() {
        let op = format!("product-default-expiry-{index}");
        let request = input(channel, &op, raw_ttl);
        let first = product
            .ordinary
            .accept_authorized(channel, request.clone(), now())
            .await
            .unwrap();
        let mut connection = product.inspect().await;
        let row = sqlx::query(
            "SELECT payload_blob,accepted_at,expires_at FROM ordinary_messages WHERE op_id=?",
        )
        .bind(&op)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(
            row.get::<i64, _>("expires_at") - row.get::<i64, _>("accepted_at"),
            7 * 86_400_000
        );
        let payload: Value =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("payload_blob")).unwrap();
        assert!(payload.get("ttl").is_none());
        let replay = product
            .ordinary
            .accept_authorized(channel, request.clone(), now() + 60_000)
            .await
            .unwrap();
        assert_eq!(replay.message_id, first.message_id);
        let after =
            sqlx::query("SELECT accepted_at,expires_at FROM ordinary_messages WHERE op_id=?")
                .bind(&op)
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(
            after.get::<i64, _>("accepted_at"),
            row.get::<i64, _>("accepted_at")
        );
        assert_eq!(
            after.get::<i64, _>("expires_at"),
            row.get::<i64, _>("expires_at")
        );
        let mut zero = request;
        zero.ttl = Some(0);
        assert!(matches!(
            product
                .ordinary
                .accept_authorized(channel, zero, now())
                .await,
            Err(KernelError::Conflict)
        ));
    }
    product.stop().await;
}

#[tokio::test]
async fn zero_recipient_acceptance_and_replay_never_report_provider_work() {
    let product = Product::open(tempfile::tempdir().unwrap()).await;
    let channel = product
        .storage
        .upsert_private_channel(
            None,
            Some("empty ordinary channel"),
            &crate::util::generate_hex_id_128(),
        )
        .await
        .unwrap()
        .channel_id;
    let request = input(channel, "ordinary-empty-channel", None);
    let accepted = product
        .ordinary
        .accept_authorized(channel, request.clone(), now())
        .await
        .unwrap();
    let replay = product
        .ordinary
        .accept_authorized(channel, request, now())
        .await
        .unwrap();
    assert_eq!(accepted.dispatch_status, "not_attempted");
    assert_eq!(replay.dispatch_status, "not_attempted");
    assert_eq!(accepted.message_id, replay.message_id);
    assert_eq!(
        product
            .ordinary
            .status("ordinary-empty-channel")
            .await
            .unwrap()["status"],
        "failed"
    );
    assert!(
        product
            .ordinary
            .target_status("ordinary-empty-channel")
            .await
            .unwrap()["targets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    product.stop().await;
}

#[tokio::test]
async fn completed_product_replay_uses_committed_status_after_body_release() {
    let product = Product::open(tempfile::tempdir().unwrap()).await;
    let channel = product.channel_with_targets().await;
    let request = input(channel, "ordinary-completed-replay", None);
    let accepted = product
        .ordinary
        .accept_authorized(channel, request.clone(), now())
        .await
        .unwrap();
    assert_eq!(accepted.dispatch_status, "provider_queued");
    let batch = product
        .ordinary
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap();
    assert_eq!(batch.tickets.len(), 1);
    product
        .ordinary
        .settle(&batch.tickets[0], "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        product
            .ordinary
            .ack("expiry-provider", vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    for device in ["expiry-private", "expiry-mqtt"] {
        let route = product.ordinary.private_route(device).await.unwrap();
        let tickets = product
            .ordinary
            .private_claim(&route, "completed-group", 1)
            .await
            .unwrap();
        assert_eq!(tickets.len(), 1);
        assert!(
            product
                .ordinary
                .private_ack(&route, &tickets[0])
                .await
                .unwrap()
        );
    }
    let mut connection = product.inspect().await;
    let retained = sqlx::query("SELECT status,payload_bytes,provider_target_count,private_enqueued_count FROM ordinary_messages WHERE op_id=?")
        .bind("ordinary-completed-replay").fetch_one(&mut connection).await.unwrap();
    assert_eq!(retained.get::<String, _>("status"), "sent");
    assert_eq!(retained.get::<i64, _>("payload_bytes"), 0);
    assert_eq!(retained.get::<i64, _>("provider_target_count"), 1);
    assert_eq!(retained.get::<i64, _>("private_enqueued_count"), 2);
    let replay = product
        .ordinary
        .accept_authorized(channel, request, now())
        .await
        .unwrap();
    assert_eq!(replay.acceptance, "duplicate_completed");
    assert_eq!(replay.dispatch_status, "attempted_accepted");
    assert_eq!(replay.message_id, accepted.message_id);
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert_eq!(
        product
            .ordinary
            .status("ordinary-completed-replay")
            .await
            .unwrap()["status"],
        "sent"
    );
    drop(connection);
    product.stop().await;
}
