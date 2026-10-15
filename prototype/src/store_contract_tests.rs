//! Synthetic ordinary Sender/store regression fixtures; no real credentials.
use crate::store::{OwnerLock, now};
use crate::{AcceptRequest, Config, DeliveryStore, KernelError};
use serde_json::json;
use sqlx::Row;
async fn fixture(
    config: Config,
) -> (
    tempfile::TempDir,
    DeliveryStore,
    OwnerLock,
    String,
    String,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("contract.sqlite").display());
    let (store, owner) = DeliveryStore::open(&url, config).await.unwrap();
    let device = store.register("android").await.unwrap();
    store
        .route(&device, None, "FCM", "synthetic-contract-provider-token")
        .await
        .unwrap();
    let auth = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("synthetic contract channel"), &auth)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (dir, store, owner, device, channel, auth)
}
fn input(channel: &str, auth: &str, id: &str) -> AcceptRequest {
    AcceptRequest {
        channel_id: channel.into(),
        password: auth.into(),
        title: " synthetic title ".into(),
        op_id: Some(id.into()),
        body: Some(" body ".into()),
        ..Default::default()
    }
}
async fn close(store: DeliveryStore, owner: OwnerLock) {
    store.pool.close().await;
    owner.release();
}
#[tokio::test]
async fn ordinary_full_fields_absolute_ttl_identity_and_auth_preserve_first_acceptance() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let mut first = input(&channel, &auth, "full-contract-op");
    first.ttl = Some(now() + 60_000);
    first.occurred_at = Some(now() - 10_000);
    first.url = Some(" https://example.invalid/target ".into());
    first.images = vec![" https://example.invalid/image ".into()];
    first.ciphertext = Some(" synthetic-ciphertext ".into());
    first.tags = vec![" tag ".into()];
    first.metadata = serde_json::from_value(json!({" scalar ":true})).unwrap();
    first.severity = Some(" HIGH ".into());
    let accepted = store.accept(first.clone()).await.unwrap();
    let status = store.status(&accepted.op_id).await.unwrap();
    let pull = store.pull(&device, None).await.unwrap();
    let payload = &pull["items"][0]["payload"];
    assert_eq!(payload["title"], "synthetic title");
    assert_eq!(payload["body"], "body");
    assert_eq!(payload["severity"], "high");
    assert_eq!(payload["url"], "https://example.invalid/target");
    assert_eq!(payload["ciphertext"], "synthetic-ciphertext");
    assert_eq!(payload["ttl"], first.ttl.unwrap().to_string());
    assert!(payload.get("delivery_id").is_none());
    let duplicate = store.accept(first.clone()).await.unwrap();
    assert_eq!(duplicate.message_id, accepted.message_id);
    assert_eq!(duplicate.delivery_id, accepted.delivery_id);
    assert_eq!(store.status(&accepted.op_id).await.unwrap(), status);
    let mut changed = first.clone();
    changed.url = Some("https://example.invalid/changed".into());
    assert!(matches!(
        store.accept(changed).await,
        Err(KernelError::Conflict)
    ));
    let mut denied = first;
    denied.password = crate::types::generate_hex_id_128();
    assert!(matches!(
        store.accept(denied).await,
        Err(KernelError::Unauthorized)
    ));
    assert_eq!(store.status(&accepted.op_id).await.unwrap(), status);
    let salt: String = sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=?")
        .bind(&channel)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(salt.starts_with("$pushgo-blake3$"));
    assert!(!salt.contains(&auth));
    close(store, owner).await;
}
#[tokio::test]
async fn omitted_operation_generates_new_identity_and_missing_ttl_stays_off_wire() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let mut req = input(&channel, &auth, "placeholder");
    req.op_id = None;
    let first = store.accept(req.clone()).await.unwrap();
    let second = store.accept(req).await.unwrap();
    assert_ne!(first.op_id, second.op_id);
    assert_ne!(first.message_id, second.message_id);
    let payload = store.pull(&device, Some(&first.delivery_id)).await.unwrap();
    assert!(payload["items"][0]["payload"].get("ttl").is_none());
    let row = sqlx::query("SELECT expires_at,accepted_at FROM messages WHERE op_id=?")
        .bind(&first.op_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        row.get::<i64, _>("expires_at") - row.get::<i64, _>("accepted_at"),
        7 * 86_400_000
    );
    close(store, owner).await;
}
#[tokio::test]
async fn provider_receipt_releases_pending_capacity_and_ack_releases_bytes_preserving_history() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config {
        max_messages: 1,
        max_targets: 1,
        ..Default::default()
    })
    .await;
    let first = store
        .accept(input(&channel, &auth, "pending-first"))
        .await
        .unwrap();
    assert!(matches!(
        store.accept(input(&channel, &auth, "pending-second")).await,
        Err(KernelError::Capacity)
    ));
    assert!(matches!(
        store.status("pending-second").await,
        Err(KernelError::NotFound)
    ));
    let mut claim = store.claim("FCM", 1, false).await.unwrap();
    let ticket = claim.tickets.pop().unwrap();
    store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        store.status("pending-first").await.unwrap()["status"],
        "sent"
    );
    let second = store
        .accept(input(&channel, &auth, "pending-second"))
        .await
        .unwrap();
    assert_ne!(first.delivery_id, second.delivery_id);
    assert_eq!(
        store
            .ack(&device, vec![first.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .ack(&device, vec![first.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    let bytes: i64 =
        sqlx::query_scalar("SELECT payload_bytes FROM messages WHERE op_id='pending-first'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(bytes, 0);
    let target: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=?")
        .bind(&first.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(target, 0);
    let replay = store
        .accept(input(&channel, &auth, "pending-first"))
        .await
        .unwrap();
    assert_eq!(replay.message_id, first.message_id);
    assert!(
        store.pull(&device, Some(&first.delivery_id)).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    close(store, owner).await;
}
#[test]
fn http_timestamp_validation_and_fields_match_ordinary_boundary() {
    let auth = crate::types::generate_hex_id_128();
    let request:AcceptRequest=serde_json::from_value(json!({"channel_id":"00000000000000000000000000","password":auth,"title":"title","ttl":"1800000000","occurred_at":1800000001,"op_id":" ","metadata":null})).unwrap();
    assert_eq!(request.ttl, Some(1_800_000_000_000));
    assert_eq!(request.occurred_at, Some(1_800_000_001_000));
    assert!(request.op_id.is_none());
    assert!(request.normalize().is_ok());
    assert!(serde_json::from_value::<AcceptRequest>(json!({"channel_id":"00000000000000000000000000","password":auth,"title":"title","message_id":null})).is_err());
}
#[tokio::test]
async fn bounded_expiry_skips_compact_history_and_maintenance_keeps_unexpired_identity() {
    let (_dir, store, owner, _device, channel, auth) = fixture(Config::default()).await;
    let accepted = store
        .accept(input(&channel, &auth, "expiry-body"))
        .await
        .unwrap();
    sqlx::query("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<300) INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) SELECT 'hist-delivery-'||n,'hist-message-'||n,'hist-op-'||n,?,'synthetic',X'',0,0,0,?,'sent',0 FROM seq").bind(&channel).bind(now()+86_400_000).execute(&store.pool).await.unwrap();
    sqlx::query("UPDATE messages SET expires_at=? WHERE op_id='expiry-body'")
        .bind(now() - 1000)
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(store.maintenance().await.unwrap(), 0);
    let row =
        sqlx::query("SELECT payload_bytes,pending_targets FROM messages WHERE op_id='expiry-body'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(row.get::<i64, _>("payload_bytes"), 0);
    assert_eq!(row.get::<i64, _>("pending_targets"), 0);
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["entity_id"],
        accepted.message_id
    );
    sqlx::query("UPDATE messages SET dedupe_until=0 WHERE op_id LIKE 'hist-op-%'")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(store.maintenance().await.unwrap(), 256);
    assert_eq!(store.maintenance().await.unwrap(), 44);
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["entity_id"],
        accepted.message_id
    );
    close(store, owner).await;
}
#[tokio::test]
async fn past_absolute_ttl_is_failed_without_jobs_and_replays_first_identity() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let mut req = input(&channel, &auth, "already-expired");
    req.ttl = Some(now() - 1000);
    let accepted = store.accept(req.clone()).await.unwrap();
    let status = store.status(&accepted.op_id).await.unwrap();
    assert_eq!(status["status"], "failed");
    assert!(
        store
            .claim("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty()
    );
    assert!(
        store.pull(&device, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let replay = store.accept(req).await.unwrap();
    assert_eq!(replay.message_id, accepted.message_id);
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert_eq!(store.status(&accepted.op_id).await.unwrap(), status);
    close(store, owner).await;
}
#[tokio::test]
async fn pending_expiry_fails_but_preserves_sent_status_and_stable_identity() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let request = input(&channel, &auth, "expire-pending");
    let pending = store.accept(request.clone()).await.unwrap();
    sqlx::query("UPDATE messages SET expires_at=? WHERE op_id=?")
        .bind(now() - 1000)
        .bind(&pending.op_id)
        .execute(&store.pool)
        .await
        .unwrap();
    store.maintenance().await.unwrap();
    let failed = store.status(&pending.op_id).await.unwrap();
    assert_eq!(failed["status"], "failed");
    let replay = store.accept(request).await.unwrap();
    assert_eq!(replay.message_id, pending.message_id);
    assert_eq!(store.status(&pending.op_id).await.unwrap(), failed);
    let sent = store
        .accept(input(&channel, &auth, "sent-then-expire"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    let sent_status = store.status(&sent.op_id).await.unwrap();
    assert_eq!(sent_status["status"], "sent");
    sqlx::query("UPDATE messages SET expires_at=? WHERE op_id=?")
        .bind(now() - 1000)
        .bind(&sent.op_id)
        .execute(&store.pool)
        .await
        .unwrap();
    store.maintenance().await.unwrap();
    assert_eq!(store.status(&sent.op_id).await.unwrap(), sent_status);
    assert!(
        store.pull(&device, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    close(store, owner).await;
}
#[tokio::test]
async fn mixed_expiry_waits_for_owned_receipt_then_reports_partial_failure() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let second = store.register("android").await.unwrap();
    store
        .route(&second, None, "FCM", "synthetic-second-provider-token")
        .await
        .unwrap();
    store
        .subscribe(&second, Some(&channel), None, &auth)
        .await
        .unwrap();
    let accepted = store
        .accept(input(&channel, &auth, "mixed-expiry"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    sqlx::query("UPDATE messages SET expires_at=? WHERE op_id=?")
        .bind(now() - 1000)
        .bind(&accepted.op_id)
        .execute(&store.pool)
        .await
        .unwrap();
    store.maintenance().await.unwrap();
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "provider_queued"
    );
    store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "partially_failed"
    );
    assert!(
        store.pull(&device, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        store.pull(&second, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    close(store, owner).await;
}
struct NoNetworkTransport;
impl crate::ProviderTransport for NoNetworkTransport {
    fn send<'a>(
        &'a self,
        _provider: &'a str,
        _platform: crate::types::Platform,
        _token: &'a str,
        _payload: serde_json::Value,
        _delivery: &'a str,
        _device: &'a str,
        _accepted: i64,
        _expiry: i64,
    ) -> crate::transport::BoxFuture<'a, crate::transport::DispatchResult> {
        Box::pin(async { panic!("ineligible runtime attempt must not call provider") })
    }
}
#[tokio::test]
async fn runtime_expired_attempt_closes_sender_failure_without_network() {
    let (_dir, store, owner, _device, channel, auth) = fixture(Config::default()).await;
    let accepted = store
        .accept(input(&channel, &auth, "runtime-expired"))
        .await
        .unwrap();
    let mut ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    ticket.expires_at = now() - 1;
    sqlx::query("UPDATE messages SET expires_at=? WHERE op_id=?")
        .bind(ticket.expires_at)
        .bind(&accepted.op_id)
        .execute(&store.pool)
        .await
        .unwrap();
    crate::runtime::attempt(
        store.clone(),
        std::sync::Arc::new(NoNetworkTransport),
        ticket,
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "failed"
    );
    assert!(
        store
            .claim("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty()
    );
    close(store, owner).await;
}
#[tokio::test]
async fn runtime_superseded_route_is_nonfailure_terminal_like_mainline() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let accepted = store
        .accept(input(&channel, &auth, "runtime-superseded"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    store
        .route(&device, None, "FCM", "synthetic-replacement-provider-token")
        .await
        .unwrap();
    crate::runtime::attempt(
        store.clone(),
        std::sync::Arc::new(NoNetworkTransport),
        ticket,
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "sent"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT provider_accepted_count FROM messages WHERE op_id=?")
            .bind(&accepted.op_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert!(
        store
            .claim("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty()
    );
    close(store, owner).await;
}
#[tokio::test]
async fn pending_client_ack_closes_queue_without_fabricating_provider_acceptance() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let req = input(&channel, &auth, "pending-client-ack");
    let accepted = store.accept(req.clone()).await.unwrap();
    assert_eq!(
        store
            .ack(&device, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .claim("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty()
    );
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "sent"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT provider_accepted_count FROM messages WHERE op_id=?")
            .bind(&accepted.op_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let replay = store.accept(req).await.unwrap();
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert!(
        store.pull(&device, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    close(store, owner).await;
}
#[tokio::test]
async fn current_invalid_token_unsubscribes_only_affected_channel_and_keeps_history() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let other_auth = crate::types::generate_hex_id_128();
    let other_channel = store
        .subscribe(&device, None, Some("other synthetic channel"), &other_auth)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let req = input(&channel, &auth, "invalid-current-token");
    let accepted = store.accept(req.clone()).await.unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let canonical: Vec<u8> =
        sqlx::query_scalar("SELECT payload_blob FROM messages WHERE delivery_id=?")
            .bind(&accepted.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(store.authorize_ticket(&ticket).await.unwrap());
    store
        .settle(
            &ticket,
            "permanent_failed",
            404,
            "invalid_token",
            now(),
            None,
        )
        .await
        .unwrap();
    let current: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
    )
    .bind(&channel)
    .bind(&device)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(current, 0);
    let other: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
    )
    .bind(&other_channel)
    .bind(&device)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(other, 1);
    let retained: Vec<u8> =
        sqlx::query_scalar("SELECT payload_blob FROM messages WHERE delivery_id=?")
            .bind(&accepted.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(retained, canonical);
    assert_eq!(
        store.accept(req).await.unwrap().message_id,
        accepted.message_id
    );
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "failed"
    );
    close(store, owner).await;
}
#[tokio::test]
async fn token_aba_generation_rejects_old_attempt_and_blocks_stale_invalid_cleanup() {
    let (_dir, store, owner, device, channel, auth) = fixture(Config::default()).await;
    let old = store
        .accept(input(&channel, &auth, "old-generation"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let original_generation = ticket.route_generation;
    let original_token = ticket.token.clone();
    // Re-registering the identical route is idempotent; actual changes advance it.
    store
        .route(&device, None, "FCM", &original_token)
        .await
        .unwrap();
    let unchanged: i64 =
        sqlx::query_scalar("SELECT route_generation FROM devices WHERE device_key=?")
            .bind(&device)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(unchanged, original_generation);
    store
        .route(&device, None, "FCM", "synthetic-middle-provider-token")
        .await
        .unwrap();
    store
        .route(&device, None, "FCM", &original_token)
        .await
        .unwrap();
    let fresh_generation: i64 =
        sqlx::query_scalar("SELECT route_generation FROM devices WHERE device_key=?")
            .bind(&device)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(fresh_generation, original_generation + 2);
    assert!(!store.authorize_ticket(&ticket).await.unwrap());
    // A late invalid-token receipt from A before B must not delete fresh A's subscription.
    store
        .settle(
            &ticket,
            "permanent_failed",
            404,
            "invalid_token",
            now(),
            None,
        )
        .await
        .unwrap();
    let subscribed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND device_key=?",
    )
    .bind(&channel)
    .bind(&device)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(subscribed, 1);
    assert_eq!(
        store.status(&old.op_id).await.unwrap()["entity_id"],
        old.message_id
    );
    // A separately frozen old-generation ticket takes the real runtime supersede path.
    let fresh = store
        .accept(input(&channel, &auth, "next-old-generation"))
        .await
        .unwrap();
    let stale = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    store
        .route(&device, None, "FCM", "synthetic-next-provider-token")
        .await
        .unwrap();
    store
        .route(&device, None, "FCM", &original_token)
        .await
        .unwrap();
    crate::runtime::attempt(
        store.clone(),
        std::sync::Arc::new(NoNetworkTransport),
        stale,
    )
    .await
    .unwrap();
    assert_eq!(store.status(&fresh.op_id).await.unwrap()["status"], "sent");
    let failure: String = sqlx::query_scalar("SELECT state FROM targets WHERE delivery_id=?")
        .bind(&fresh.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(failure, "superseded_route");
    close(store, owner).await;
}
