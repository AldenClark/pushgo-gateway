use super::{
    runtime::{DeliveryRuntime, ProviderTransport},
    store::{AcceptRequest, Config, DeliveryStore, KernelError, OwnerLock, now},
};
use crate::{
    transport::{BoxFuture, DispatchResult},
    types::Platform,
};
use serde_json::json;
use sqlx::Row;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

async fn open(config: Config) -> (tempfile::TempDir, String, DeliveryStore, OwnerLock) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("authority.sqlite").display());
    let (store, owner) = DeliveryStore::open(&url, config).await.unwrap();
    (dir, url, store, owner)
}
async fn close(store: DeliveryStore, owner: OwnerLock) {
    store.pool.close().await;
    owner.release();
}
async fn directory(store: &DeliveryStore) -> (String, String, String) {
    let device = store.register("android").await.unwrap();
    store
        .route(&device, None, "fcm", "synthetic-route-A")
        .await
        .unwrap();
    let auth = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("synthetic channel"), &auth)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (device, channel, auth)
}
fn request(channel: &str, auth: &str, op: &str) -> AcceptRequest {
    AcceptRequest {
        channel_id: channel.into(),
        password: auth.into(),
        title: "synthetic title".into(),
        body: Some("synthetic body".into()),
        op_id: Some(op.into()),
        ..AcceptRequest::default()
    }
}

#[tokio::test]
async fn complete_fanout_fixed_identity_conflict_and_ack_never_replays() {
    let (_dir, _url, store, owner) = open(Config::default()).await;
    let (device, channel, auth) = directory(&store).await;
    let other = store.register("ios").await.unwrap();
    store
        .route(&other, None, "apns", &"ab".repeat(32))
        .await
        .unwrap();
    store
        .subscribe(&other, Some(&channel), None, &auth)
        .await
        .unwrap();
    let input = request(&channel, &auth, "operation-A");
    let accepted = store.accept(input.clone()).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let payloads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(payloads, 1);
    let replay = store.accept(input.clone()).await.unwrap();
    assert_eq!(accepted.delivery_id, replay.delivery_id);
    assert_eq!(accepted.message_id, replay.message_id);
    let mut conflict = input.clone();
    conflict.body.as_mut().unwrap().push('!');
    assert!(matches!(
        store.accept(conflict).await,
        Err(KernelError::Conflict)
    ));
    let before = store.pull(&device, None).await.unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 1);
    assert_eq!(before["items"][0]["delivery_id"], accepted.delivery_id);
    assert_eq!(
        store
            .ack(&device, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    store.accept(input).await.unwrap();
    assert!(
        store.pull(&device, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.pull(&other, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    close(store, owner).await;
}
#[tokio::test]
async fn provider_receipt_and_client_ack_are_independent_in_both_orders() {
    let (_dir, _url, store, owner) = open(Config::default()).await;
    let (device, channel, auth) = directory(&store).await;
    for (index, ack_first) in [true, false].into_iter().enumerate() {
        let accepted = store
            .accept(request(&channel, &auth, &format!("receipt-{index}")))
            .await
            .unwrap();
        let ticket = store
            .claim("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .remove(0);
        if ack_first {
            store
                .ack(&device, vec![accepted.delivery_id.clone()])
                .await
                .unwrap();
        }
        store
            .settle(&ticket, "provider_accepted", 200, "none", now(), None)
            .await
            .unwrap();
        if !ack_first {
            assert_eq!(
                store
                    .pull(&device, Some(&accepted.delivery_id))
                    .await
                    .unwrap()["items"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            store
                .ack(&device, vec![accepted.delivery_id.clone()])
                .await
                .unwrap();
        }
        assert!(
            store
                .pull(&device, Some(&accepted.delivery_id))
                .await
                .unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let row = sqlx::query("SELECT status,payload_bytes,(SELECT COUNT(*) FROM targets t WHERE t.delivery_id=m.delivery_id) AS targets FROM messages m WHERE delivery_id=?")
            .bind(accepted.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("status"), "sent");
        assert_eq!(row.get::<i64, _>("targets"), 0);
        assert_eq!(row.get::<i64, _>("payload_bytes"), 0);
    }
    close(store, owner).await;
}
#[tokio::test]
async fn second_owner_cannot_reset_running_and_restart_reuses_identity() {
    let (_dir, url, store, owner) = open(Config::default()).await;
    let (_device, channel, auth) = directory(&store).await;
    let accepted = store
        .accept(request(&channel, &auth, "unknown-result"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .remove(0);
    assert!(matches!(
        DeliveryStore::open(&url, Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    let state: String = sqlx::query_scalar("SELECT state FROM targets WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(state, "running");
    close(store, owner).await;
    let (store, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let recovered = store.claim("FCM", 1, true).await.unwrap().tickets.remove(0);
    assert_eq!(recovered.delivery_id, ticket.delivery_id);
    assert_eq!(
        recovered.payload["message_id"],
        ticket.payload["message_id"]
    );
    assert_eq!(recovered.attempt_id, ticket.attempt_id + 1);
    close(store, owner).await;
}
#[tokio::test]
async fn atomic_target_cap_and_payload_cap_survive_concurrent_admission() {
    let config = Config {
        max_messages: 2,
        max_targets: 2,
        max_payload_bytes: 2048,
        ..Config::default()
    };
    let (_dir, _url, store, owner) = open(config).await;
    let (_device, channel, auth) = directory(&store).await;
    let mut set = tokio::task::JoinSet::new();
    for n in 0..16 {
        let store = store.clone();
        let input = request(&channel, &auth, &format!("cap-{n}"));
        set.spawn(async move { store.accept(input).await });
    }
    let mut accepted = 0;
    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(_) => accepted += 1,
            Err(KernelError::Capacity) => {}
            Err(error) => panic!("unexpected {error}"),
        }
    }
    assert_eq!(accepted, 2);
    let row = sqlx::query("SELECT COUNT(*) AS messages,SUM(payload_bytes) AS bytes FROM messages")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("messages"), 2);
    assert!(row.get::<i64, _>("bytes") <= 2048);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        2
    );
    close(store, owner).await;
    let config = Config {
        max_payload_bytes: 16,
        ..Config::default()
    };
    let (_dir, _url, store, owner) = open(config).await;
    let (_device, channel, auth) = directory(&store).await;
    assert!(matches!(
        store.accept(request(&channel, &auth, "oversized")).await,
        Err(KernelError::Capacity)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        0
    );
    close(store, owner).await;
}
#[tokio::test]
async fn due_retry_and_fresh_share_claim_and_cooldown_is_durable() {
    let (_dir, url, store, owner) = open(Config::default()).await;
    let (_device, channel, auth) = directory(&store).await;
    let retry = store
        .accept(request(&channel, &auth, "retry"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .remove(0);
    store
        .settle(
            &ticket,
            "retry_wait",
            503,
            "temporarily_unavailable",
            now() - 1,
            None,
        )
        .await
        .unwrap();
    let fresh = store
        .accept(request(&channel, &auth, "fresh"))
        .await
        .unwrap();
    let batch = store.claim("FCM", 2, false).await.unwrap();
    assert_eq!(batch.tickets.len(), 2);
    assert!(
        batch
            .tickets
            .iter()
            .any(|v| v.delivery_id == retry.delivery_id)
    );
    assert!(
        batch
            .tickets
            .iter()
            .any(|v| v.delivery_id == fresh.delivery_id)
    );
    let due = now() + 60_000;
    store
        .settle(
            &batch.tickets[0],
            "retry_wait",
            429,
            "rate_limited",
            due,
            Some(due),
        )
        .await
        .unwrap();
    assert!(
        store
            .claim("FCM", 8, false)
            .await
            .unwrap()
            .tickets
            .is_empty()
    );
    close(store, owner).await;
    let (store, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let empty = store.claim("FCM", 8, true).await.unwrap();
    assert!(empty.tickets.is_empty());
    assert!(empty.next_due.unwrap() >= due);
    close(store, owner).await;
}

#[derive(Default)]
struct ControlledTransport {
    started: AtomicU64,
    finished: AtomicU64,
    release: Notify,
    fcm_quiesced: AtomicU64,
}
impl ProviderTransport for ControlledTransport {
    fn quiesce(&self, provider: &str) {
        if provider == "FCM" {
            self.fcm_quiesced.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn send<'a>(
        &'a self,
        _provider: &'a str,
        _platform: Platform,
        _token: &'a str,
        _payload: serde_json::Value,
        _delivery: &'a str,
        _device: &'a str,
        _accepted: i64,
        _expiry: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::Relaxed);
            self.release.notified().await;
            self.finished.fetch_add(1, Ordering::Relaxed);
            DispatchResult::success(200)
        })
    }
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("condition deadline");
}
#[tokio::test]
async fn stale_route_is_superseded_before_any_network_send() {
    let (_dir, _url, store, owner) = open(Config::default()).await;
    let (device, channel, auth) = directory(&store).await;
    store
        .accept(request(&channel, &auth, "route-update"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .remove(0);
    store
        .route(&device, None, "fcm", "synthetic-route-B")
        .await
        .unwrap();
    let transport = Arc::new(ControlledTransport::default());
    super::runtime::attempt(store.clone(), transport.clone(), ticket)
        .await
        .unwrap();
    assert_eq!(transport.started.load(Ordering::Relaxed), 0);
    assert_eq!(
        store.target_status("route-update").await.unwrap()["targets"][0]["state"],
        json!("superseded_route")
    );
    close(store, owner).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_claim_keeps_polling_network_and_shutdown_preserves_running() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("poll.sqlite").display());
    let transport = Arc::new(ControlledTransport::default());
    let runtime = DeliveryRuntime::start(&url, Config::default(), transport.clone())
        .await
        .unwrap();
    let store = runtime.store.sqlite_store().unwrap();
    let (_device, channel, auth) = directory(&store).await;
    store
        .accept(request(&channel, &auth, "inflight"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    // Force a new claim to wait behind a persistent mutation while an existing
    // Provider future has a ready response. It must still receive polls.
    let gate = store.gate.lock().await;
    store.notify();
    transport.release.notify_one();
    until(|| transport.finished.load(Ordering::Relaxed) == 1).await;
    drop(gate);
    until(|| store.counters.receipt_commits.load(Ordering::Relaxed) >= 1).await;
    let accepted = store
        .accept(request(&channel, &auth, "shutdown-unknown"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 2).await;
    let report = runtime.shutdown().await;
    assert_eq!(report.joined, 2);
    assert_eq!(report.aborted, 0);
    assert_eq!(report.panicked, 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 0);
    let (reopened, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let ticket = reopened
        .claim("FCM", 1, true)
        .await
        .unwrap()
        .tickets
        .remove(0);
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    close(reopened, owner).await;
}

// Seed input directory before starting pumps. Then await both initial empty
// claims and their mutation gate, leaving no directory/admission wake permits.
// This makes removing AdmissionWake a meaningful negative control.
async fn idle_runtime() -> (
    tempfile::TempDir,
    String,
    DeliveryRuntime,
    Arc<ControlledTransport>,
    String,
    String,
    String,
) {
    let config = Config {
        provider_budget: 8,
        claim_quantum: 8,
        ..Config::default()
    };
    let (dir, url, store, owner) = open(config.clone()).await;
    let (device, channel, auth) = directory(&store).await;
    close(store, owner).await;
    let transport = Arc::new(ControlledTransport::default());
    let runtime = DeliveryRuntime::start(&url, config, transport.clone())
        .await
        .unwrap();
    until(|| runtime.store.counters.claim_queries.load(Ordering::Relaxed) >= 2).await;
    let sqlite = runtime.store.sqlite_store().unwrap();
    let idle_gate = sqlite.gate.lock().await;
    drop(idle_gate);
    (dir, url, runtime, transport, device, channel, auth)
}
// Use a separate SQLite connection to exercise the actual engine's writer lock,
// independently of the process-local mutation gate and its sole SQLx connection.
async fn external_writer(url: &str) -> sqlx::SqliteConnection {
    use sqlx::Connection;
    let options = url
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        .unwrap()
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_writer_contention_within_budget_keeps_claims_and_receipts_alive() {
    use sqlx::Connection;
    let (_dir, url, runtime, transport, device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let accepted = store
        .accept(request(&channel, &auth, "short-writer-lock"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    let mut blocker = external_writer(&url).await;
    let lock = blocker.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let claims = store.counters.claim_queries.load(Ordering::Relaxed);
    store.notify();
    until(|| store.counters.claim_queries.load(Ordering::Relaxed) > claims).await;
    transport.release.notify_one();
    until(|| transport.finished.load(Ordering::Relaxed) == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(store.counters.num_alive.load(Ordering::Relaxed), 2);
    assert_eq!(store.counters.db_errors.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(store.counters.receipt_commits.load(Ordering::Relaxed), 0);
    lock.rollback().await.unwrap();
    blocker.close().await.unwrap();
    until(|| store.counters.receipt_commits.load(Ordering::Relaxed) == 1).await;
    store
        .ack(&device, vec![accepted.delivery_id])
        .await
        .unwrap();
    assert_eq!(store.counters.db_errors.load(Ordering::Relaxed), 0);
    let report = runtime.shutdown().await;
    assert_eq!(report.joined, 2);
    assert_eq!(report.failed, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_writer_timeout_fails_closed_and_recovers_accepted_identity() {
    use sqlx::Connection;
    let (_dir, url, mut runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let accepted = store
        .accept(request(&channel, &auth, "long-writer-lock"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    let before = store.status("long-writer-lock").await.unwrap();
    let absolute_expiry: i64 = sqlx::query_scalar("SELECT expires_at FROM messages WHERE op_id=?")
        .bind("long-writer-lock")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let mut blocker = external_writer(&url).await;
    let lock = blocker.begin_with("BEGIN IMMEDIATE").await.unwrap();
    store.notify();
    transport.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(6), runtime.wait_failure())
        .await
        .unwrap();
    assert!(error.contains("code: 5"), "unexpected failure: {error}");
    assert_eq!(store.counters.receipt_commits.load(Ordering::Relaxed), 0);
    lock.rollback().await.unwrap();
    blocker.close().await.unwrap();
    let report = runtime.shutdown().await;
    assert!(report.failed > 0);
    let (reopened, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let after = reopened.status("long-writer-lock").await.unwrap();
    for field in ["entity_id", "accepted_at", "expires_at"] {
        assert_eq!(before[field], after[field], "changed {field}");
    }
    let ticket = reopened
        .claim("FCM", 1, true)
        .await
        .unwrap()
        .tickets
        .remove(0);
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    assert_eq!(ticket.payload["message_id"], json!(accepted.message_id));
    assert_eq!(ticket.accepted_at, before["accepted_at"].as_i64().unwrap());
    assert_eq!(ticket.expires_at, absolute_expiry);
    assert_eq!(transport.started.load(Ordering::Relaxed), 1);
    close(reopened, owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_owner_fences_cloned_and_already_waiting_admission_without_wait_failure() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use sqlx::Connection;
    use tower::ServiceExt;
    let (_dir, url, runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let app = crate::router(runtime.store.clone(), Arc::new(|| json!({})));
    let prior = store
        .accept(request(&channel, &auth, "health-prior"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    let mut blocker = external_writer(&url).await;
    let lock = blocker.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let claims = store.counters.claim_queries.load(Ordering::Relaxed);
    store.notify();
    until(|| store.counters.claim_queries.load(Ordering::Relaxed) > claims).await;
    let waiting_store = store.clone();
    let input = request(&channel, &auth, "health-waiting");
    let waiting = tokio::spawn(async move { waiting_store.accept(input).await });
    transport.release.notify_one();
    // Deliberately never call runtime.wait_failure(): public clones must fence
    // even when an embedding process fails to supervise its owner drivers.
    tokio::time::timeout(Duration::from_secs(6), async {
        while store.counters.db_errors.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    lock.rollback().await.unwrap();
    blocker.close().await.unwrap();
    assert!(matches!(
        waiting.await.unwrap(),
        Err(KernelError::Unavailable)
    ));
    assert!(matches!(
        store.accept(request(&channel, &auth, "health-after")).await,
        Err(KernelError::Unavailable)
    ));
    let response = app.oneshot(Request::builder().method("POST").uri("/message")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"channel_id":channel,"password":auth,"title":"health","op_id":"health-http"})).unwrap())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["error_code"], "internal_error");
    assert_eq!(body["message"], "temporarily unavailable");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "failed owner accepted fresh work");
    let report = runtime.shutdown().await;
    assert!(report.failed > 0);
    let (reopened, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let ticket = reopened
        .claim("FCM", 1, true)
        .await
        .unwrap()
        .tickets
        .remove(0);
    assert_eq!(ticket.delivery_id, prior.delivery_id);
    close(reopened, owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_runtime_cannot_leave_a_healthy_admission_clone() {
    let (_dir, _url, runtime, _transport, _device, channel, auth) = idle_runtime().await;
    let clone = runtime.store.clone();
    drop(runtime);
    assert!(matches!(
        clone
            .accept(request(&channel, &auth, "dropped-owner"))
            .await,
        Err(KernelError::Unavailable)
    ));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_owner_rolls_back_control_mutations_paused_after_validation() {
    for action in ["rename", "unsubscribe", "sync_omission"] {
        let (_dir, _url, runtime, _transport, device, channel, auth) = idle_runtime().await;
        let store = runtime.store.sqlite_store().unwrap();
        let barrier = Arc::new(super::store::CommitBarrier::default());
        *store.hooks.control_before_write.lock().unwrap() = Some(barrier.clone());
        let task_store = store.clone();
        let task_channel = channel.clone();
        let task = tokio::spawn(async move {
            match action {
                "rename" => {
                    task_store
                        .rename_channel(&task_channel, "must not persist", &auth)
                        .await
                }
                "unsubscribe" => task_store.unsubscribe(&device, &task_channel).await,
                _ => task_store.sync_channels(&device, vec![]).await,
            }
        });
        reached(&barrier).await;
        drop(runtime);
        barrier.resume.notify_one();
        assert!(
            matches!(task.await.unwrap(), Err(KernelError::Unavailable)),
            "{action}"
        );
        let name: String =
            sqlx::query_scalar("SELECT channel_name FROM channels WHERE channel_id=?")
                .bind(&channel)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let subscriptions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=?")
                .bind(&channel)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(name, "synthetic channel", "{action}");
        assert_eq!(subscriptions, 1, "{action}");
        store.pool.close().await;
    }
}

async fn reached(barrier: &super::store::CommitBarrier) {
    tokio::time::timeout(Duration::from_secs(3), barrier.reached.notified())
        .await
        .expect("real COMMIT boundary not reached");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postcommit_claim_is_adopted_across_wakes_while_network_and_receipt_progress() {
    let (_dir, url, runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    store
        .accept(request(&channel, &auth, "preexisting-network"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    let barrier = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(barrier.clone());
    let second = store
        .accept(request(&channel, &auth, "committed-grant"))
        .await
        .unwrap();
    reached(&barrier).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(transport.started.load(Ordering::Relaxed), 1);
    assert_eq!(
        store.counters.owned_attempts.load(Ordering::Relaxed),
        1,
        "second grant is committed but not adopted"
    );
    for _ in 0..16 {
        store.notify();
        tokio::task::yield_now().await;
    }
    transport.release.notify_one();
    until(|| transport.finished.load(Ordering::Relaxed) == 1).await;
    until(|| store.counters.receipt_commits.load(Ordering::Relaxed) == 1).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM targets WHERE delivery_id=?")
            .bind(&second.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "running"
    );
    barrier.resume.notify_one();
    until(|| transport.started.load(Ordering::Relaxed) == 2).await;
    let report = runtime.shutdown().await;
    assert_eq!(report.failed, 0);
    let (store, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let recovered = store.claim("FCM", 1, true).await.unwrap().tickets.remove(0);
    assert_eq!(recovered.delivery_id, second.delivery_id);
    close(store, owner).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_at_postcommit_preadopt_keeps_lock_then_recovers_same_identity() {
    let (_dir, url, runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let barrier = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(barrier.clone());
    let accepted = store
        .accept(request(&channel, &auth, "shutdown-committed-grant"))
        .await
        .unwrap();
    reached(&barrier).await;
    assert_eq!(transport.started.load(Ordering::Relaxed), 0);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM targets WHERE delivery_id=?")
            .bind(&accepted.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "running"
    );
    let mut stopped = runtime.stop_probe();
    let shutdown = tokio::spawn(runtime.shutdown());
    tokio::time::timeout(Duration::from_secs(3), stopped.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(*stopped.borrow());
    assert!(matches!(
        DeliveryStore::open(&url, Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    assert!(
        !shutdown.is_finished(),
        "pending committed claim is still owned"
    );
    barrier.resume.notify_one();
    let report = shutdown.await.unwrap();
    assert_eq!(report.joined, 2);
    assert_eq!(report.failed, 0);
    assert_eq!(report.aborted, 0);
    assert_eq!(
        transport.started.load(Ordering::Relaxed),
        0,
        "shutdown never dispatches unadopted grant"
    );
    let (store, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let recovered = store.claim("FCM", 1, true).await.unwrap().tickets.remove(0);
    assert_eq!(recovered.delivery_id, accepted.delivery_id);
    assert_eq!(recovered.payload["message_id"], json!(accepted.message_id));
    close(store, owner).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_admission_caller_abort_still_wakes_idle_owner_without_replay() {
    let (_dir, url, runtime, transport, device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let barrier = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.accept_after_commit.lock().unwrap() = Some(barrier.clone());
    let input = request(&channel, &auth, "caller-gone-after-commit");
    let submitted = input.clone();
    let caller_store = store.clone();
    let caller = tokio::spawn(async move { caller_store.accept(submitted).await });
    reached(&barrier).await;
    let delivery: String = sqlx::query_scalar("SELECT delivery_id FROM messages WHERE op_id=?")
        .bind(&input.op_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM targets WHERE delivery_id=?")
            .bind(&delivery)
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "pending"
    );
    assert_eq!(transport.started.load(Ordering::Relaxed), 0);
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    // No request replay or directory update supplies a replacement notification.
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    assert_eq!(
        store.pull(&device, None).await.unwrap()["items"][0]["delivery_id"],
        json!(delivery)
    );
    assert_eq!(
        store.counters.admission_commits.load(Ordering::Relaxed),
        0,
        "response-side counter was never reached; DB commitment was observed independently"
    );
    let report = runtime.shutdown().await;
    assert_eq!(report.failed, 0);
    let (store, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let replay = store.accept(input).await.unwrap();
    assert_eq!(replay.delivery_id, delivery);
    close(store, owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reservation_bounds_real_committed_grants_and_owned_work_falls_without_cancellation() {
    let (_dir, _url, runtime, transport, device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let first = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(first.clone());
    let mut ids = vec![
        store
            .accept(request(&channel, &auth, "demand-first"))
            .await
            .unwrap()
            .delivery_id,
    ];
    reached(&first).await;
    for n in 0..12 {
        ids.push(
            store
                .accept(request(&channel, &auth, &format!("demand-{n}")))
                .await
                .unwrap()
                .delivery_id,
        );
    }
    let second = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(second.clone());
    first.resume.notify_one();
    reached(&second).await;
    // This test configures ceiling8. One adopted attempt plus seven
    // committed, unadopted grants fills it; notifications cannot discard grants.
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        8
    );
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(
        store.counters.claim_reservations[0].load(Ordering::Relaxed),
        7
    );
    for _ in 0..16 {
        store.notify();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        8
    );
    second.resume.notify_one();
    until(|| transport.started.load(Ordering::Relaxed) == 8).await;
    assert_eq!(
        store.counters.provider_targets[0].load(Ordering::Relaxed),
        8
    );
    assert_eq!(
        store.counters.claim_reservations[0].load(Ordering::Relaxed),
        0
    );
    assert_eq!(store.counters.num_alive.load(Ordering::Relaxed), 2);
    assert_eq!(store.ack(&device, ids).await.unwrap(), 13);
    for finished in 1..=6 {
        transport.release.notify_one();
        until(|| transport.finished.load(Ordering::Relaxed) == finished).await;
    }
    until(|| store.counters.receipt_commits.load(Ordering::Relaxed) == 6).await;
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 2);
    // Actual work shrinks immediately; the configured logical target stays at
    // its safety ceiling until all work drains, without any warm-up timer.
    assert_eq!(
        store.counters.provider_targets[0].load(Ordering::Relaxed),
        8
    );
    assert_eq!(transport.finished.load(Ordering::Relaxed), 6);
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        2
    );
    transport.release.notify_waiters();
    until(|| {
        store.counters.owned_attempts.load(Ordering::Relaxed) == 0
            && store.counters.provider_targets[0].load(Ordering::Relaxed) == 0
    })
    .await;
    let scans = store.counters.claim_queries.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(store.counters.claim_queries.load(Ordering::Relaxed), scans);
    assert_eq!(store.pull(&device, None).await.unwrap()["items"], json!([]));
    assert_eq!(runtime.shutdown().await.failed, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_low_demand_and_blocked_receipt_have_distinct_real_ownership() {
    let (_dir, _url, runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    until(|| {
        store
            .counters
            .provider_targets
            .iter()
            .all(|a| a.load(Ordering::Relaxed) == 0)
            && store
                .counters
                .claim_reservations
                .iter()
                .all(|a| a.load(Ordering::Relaxed) == 0)
            && store.counters.num_alive.load(Ordering::Relaxed) == 2
    })
    .await;
    let scans = store.counters.claim_queries.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(store.counters.claim_queries.load(Ordering::Relaxed), scans);
    store
        .accept(request(&channel, &auth, "low-blocked-receipt"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    assert_eq!(
        store.counters.provider_targets[0].load(Ordering::Relaxed),
        store.config.provider_budget as u64
    );
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 1);
    let gate = store.gate.lock().await;
    transport.release.notify_one();
    until(|| store.counters.receipts_owned.load(Ordering::Relaxed) == 1).await;
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "running"
    );
    drop(gate);
    until(|| {
        store.counters.owned_attempts.load(Ordering::Relaxed) == 0
            && store.counters.provider_targets[0].load(Ordering::Relaxed) == 0
    })
    .await;
    assert_eq!(store.counters.receipts_owned.load(Ordering::Relaxed), 0);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "provider_accepted"
    );
    assert_eq!(runtime.shutdown().await.failed, 0);
}

struct RetryTransport;
impl ProviderTransport for RetryTransport {
    fn send<'a>(
        &'a self,
        _provider: &'a str,
        _platform: Platform,
        _token: &'a str,
        _payload: serde_json::Value,
        _delivery: &'a str,
        _device: &'a str,
        _accepted: i64,
        _expiry: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async {
            DispatchResult {
                success: false,
                status_code: 429,
                failure_kind: Some(crate::transport::FailureKind::RateLimited),
                retry_after_millis: Some(1),
            }
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_retry_wait_releases_position_and_does_not_scan_during_cooldown() {
    let (dir, url, store, owner) = open(Config::default()).await;
    let (_device, channel, auth) = directory(&store).await;
    store
        .accept(request(&channel, &auth, "retry-no-resident-position"))
        .await
        .unwrap();
    close(store, owner).await;
    let before = now();
    let runtime = DeliveryRuntime::start(&url, Config::default(), Arc::new(RetryTransport))
        .await
        .unwrap();
    let store = runtime.store.sqlite_store().unwrap();
    until(|| {
        store.counters.receipt_commits.load(Ordering::Relaxed) == 1
            && store.counters.owned_attempts.load(Ordering::Relaxed) == 0
            && store
                .counters
                .claim_reservations
                .iter()
                .all(|a| a.load(Ordering::Relaxed) == 0)
    })
    .await;
    let row = sqlx::query("SELECT state,next_attempt_at,receipt_at FROM targets")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "retry_wait");
    assert!(row.get::<i64, _>("next_attempt_at") >= before + 60_000);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT next_attempt_at FROM provider_cooldowns WHERE provider='FCM'"
        )
        .fetch_one(&store.pool)
        .await
        .unwrap(),
        row.get::<i64, _>("next_attempt_at")
    );
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.receipts_owned.load(Ordering::Relaxed), 0);
    assert_eq!(
        store.counters.provider_targets[0].load(Ordering::Relaxed),
        store.config.provider_budget as u64
    );
    let scans = store.counters.claim_queries.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(store.counters.claim_queries.load(Ordering::Relaxed), scans);
    assert_eq!(runtime.shutdown().await.failed, 0);
    drop(dir);
}

#[tokio::test]
async fn legacy_pull_atomically_acks_only_returned_items() {
    let (_dir, _url, store, owner) = open(Config::default()).await;
    let (device, channel, auth) = directory(&store).await;
    let first = store
        .accept(request(&channel, &auth, "legacy-one"))
        .await
        .unwrap();
    let second = store
        .accept(request(&channel, &auth, "legacy-two"))
        .await
        .unwrap();
    let result = store
        .pull_legacy(&device, Some(&first.delivery_id))
        .await
        .unwrap();
    assert!(result.get("has_more").is_none());
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(result["items"][0]["delivery_id"], json!(first.delivery_id));
    assert_eq!(
        store
            .pull_legacy(&device, Some(&first.delivery_id))
            .await
            .unwrap()["items"],
        json!([])
    );
    assert_eq!(
        store.pull(&device, None).await.unwrap()["items"][0]["delivery_id"],
        json!(second.delivery_id)
    );
    let a = store.clone();
    let b = store.clone();
    let (left, right) = tokio::join!(a.pull_legacy(&device, None), b.pull_legacy(&device, None));
    assert_eq!(
        left.unwrap()["items"].as_array().unwrap().len()
            + right.unwrap()["items"].as_array().unwrap().len(),
        1
    );
    assert_eq!(store.pull(&device, None).await.unwrap()["items"], json!([]));
    let replay = store
        .accept(request(&channel, &auth, "legacy-one"))
        .await
        .unwrap();
    assert_eq!(replay.delivery_id, first.delivery_id);
    assert_eq!(store.pull(&device, None).await.unwrap()["items"], json!([]));
    close(store, owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lazy_work_grows_to_configured_ceiling_32_using_bounded_grants() {
    let config = Config {
        provider_budget: 32,
        ..Config::default()
    };
    let (_dir, url, store, owner) = open(config.clone()).await;
    let (_device, channel, auth) = directory(&store).await;
    for n in 0..40 {
        store
            .accept(request(&channel, &auth, &format!("cap32-{n}")))
            .await
            .unwrap();
    }
    close(store, owner).await;
    let transport = Arc::new(ControlledTransport::default());
    let runtime = DeliveryRuntime::start(&url, config, transport.clone())
        .await
        .unwrap();
    let store = runtime.store.sqlite_store().unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 32).await;
    assert_eq!(
        store.counters.provider_targets[0].load(Ordering::Relaxed),
        32
    );
    assert_eq!(store.counters.provider_owned[0].load(Ordering::Relaxed), 32);
    assert_eq!(
        store.counters.claim_reservations[0].load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        32
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='pending'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        8
    );
    let scans = store.counters.provider_claim_queries[0].load(Ordering::Relaxed);
    for _ in 0..8 {
        store.notify();
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        store.counters.provider_claim_queries[0].load(Ordering::Relaxed),
        scans
    );
    assert_eq!(transport.started.load(Ordering::Relaxed), 32);
    assert_eq!(runtime.shutdown().await.failed, 0);
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.provider_owned[0].load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn public_base_url_preserves_prefix_and_rejects_untrusted_origins() {
    let config = Config {
        public_base_url: "  http://[::1]:12345/gateway///  ".into(),
        ..Config::default()
    };
    let (_dir, _url, store, owner) = open(config).await;
    assert_eq!(store.config.public_base_url, "http://[::1]:12345/gateway");
    close(store, owner).await;
    for bad in [
        "",
        "http://example.com",
        "https://user:pass@example.com",
        "https://example.com/?q=1",
        "https://example.com/#f",
        "file:///tmp/x",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}",
            dir.path().join("bad-origin.sqlite").display()
        );
        let config = Config {
            public_base_url: bad.into(),
            ..Config::default()
        };
        assert!(matches!(
            DeliveryStore::open(&url, config).await,
            Err(KernelError::Invalid(_))
        ));
        assert!(!dir.path().join("bad-origin.sqlite").exists());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_cancels_receipt_holding_gate_before_awaiting_pending_claim() {
    let (_dir, url, runtime, transport, _device, channel, auth) = idle_runtime().await;
    let store = runtime.store.sqlite_store().unwrap();
    let accepted = store
        .accept(request(&channel, &auth, "shutdown-receipt-gate"))
        .await
        .unwrap();
    until(|| {
        transport.started.load(Ordering::Relaxed) == 1
            && store.counters.claim_reservations[0].load(Ordering::Relaxed) == 0
    })
    .await;
    let receipt = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.receipt_with_gate.lock().unwrap() = Some(receipt.clone());
    transport.release.notify_one();
    reached(&receipt).await;
    // This is a real transaction suspended before its receipt UPDATE; the
    // contained attempt owns both the gate and the sole SQLx connection.
    assert!(store.gate.try_lock().is_err());
    assert_eq!(store.counters.receipts_owned.load(Ordering::Relaxed), 1);
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 1);
    let claim_polled = Arc::new(Notify::new());
    *store.hooks.claim_before_gate.lock().unwrap() = Some(claim_polled.clone());
    store.notify();
    tokio::time::timeout(Duration::from_secs(3), claim_polled.notified())
        .await
        .unwrap();
    assert!(store.counters.claim_reservations[0].load(Ordering::Relaxed) > 0);
    assert!(store.gate.try_lock().is_err());
    // Never resume the receipt barrier. The old stop ordering cannot release
    // its gate while awaiting this claim; the fix must finish by cancellation.
    let report = tokio::time::timeout(Duration::from_secs(3), runtime.shutdown())
        .await
        .expect("shutdown awaited claim while its unpolled receipt still owned gate");
    assert_eq!(report.joined, 2);
    assert_eq!(report.failed, 0);
    assert_eq!(report.aborted, 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(store.counters.receipts_owned.load(Ordering::Relaxed), 0);
    assert_eq!(
        store.counters.claim_reservations[0].load(Ordering::Relaxed),
        0
    );
    let (reopened, owner) = DeliveryStore::open(&url, Config::default()).await.unwrap();
    let ticket = reopened
        .claim("FCM", 1, true)
        .await
        .unwrap()
        .tickets
        .remove(0);
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    assert_eq!(ticket.payload["message_id"], json!(accepted.message_id));
    assert_eq!(transport.started.load(Ordering::Relaxed), 1);
    close(reopened, owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_32_quantum_32_is_lazy_at_idle_and_bounded_at_real_claim_commit() {
    let config = Config {
        provider_budget: 32,
        claim_quantum: 32,
        ..Config::default()
    };
    let (_dir, url, store, owner) = open(config.clone()).await;
    let (_device, channel, auth) = directory(&store).await;
    close(store, owner).await;
    let transport = Arc::new(ControlledTransport::default());
    let runtime = DeliveryRuntime::start(&url, config, transport.clone())
        .await
        .unwrap();
    let store = runtime.store.sqlite_store().unwrap();
    until(|| store.counters.num_alive.load(Ordering::Relaxed) == 2).await;
    until(|| {
        store
            .counters
            .provider_targets
            .iter()
            .all(|a| a.load(Ordering::Relaxed) == 0)
            && store
                .counters
                .claim_reservations
                .iter()
                .all(|a| a.load(Ordering::Relaxed) == 0)
    })
    .await;
    assert_eq!(store.counters.num_alive.load(Ordering::Relaxed), 2);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 0);
    let scans = store.counters.claim_queries.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(store.counters.claim_queries.load(Ordering::Relaxed), scans);
    let first = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(first.clone());
    store
        .accept(request(&channel, &auth, "fixed-first"))
        .await
        .unwrap();
    reached(&first).await;
    for n in 0..40 {
        store
            .accept(request(&channel, &auth, &format!("fixed-backlog-{n}")))
            .await
            .unwrap();
    }
    let full = Arc::new(super::store::CommitBarrier::default());
    *store.hooks.claim_after_commit.lock().unwrap() = Some(full.clone());
    first.resume.notify_one();
    reached(&full).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        32
    );
    assert_eq!(store.counters.provider_owned[0].load(Ordering::Relaxed), 1);
    assert_eq!(
        store.counters.claim_reservations[0].load(Ordering::Relaxed),
        31
    );
    assert!(
        transport.started.load(Ordering::Relaxed) <= 1,
        "unadopted committed grants must not enter transport"
    );
    full.resume.notify_one();
    until(|| transport.started.load(Ordering::Relaxed) == 32).await;
    assert_eq!(store.counters.provider_owned[0].load(Ordering::Relaxed), 32);
    assert_eq!(store.counters.network_inflight.load(Ordering::Relaxed), 32);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='pending'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        9
    );
    assert_eq!(runtime.shutdown().await.failed, 0);
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_quiesce_waits_for_owned_attempts_and_continuous_backlog_to_drain() {
    let config = Config {
        provider_budget: 1,
        claim_quantum: 1,
        ..Config::default()
    };
    let (_dir, url, store, owner) = open(config.clone()).await;
    let (_device, channel, auth) = directory(&store).await;
    close(store, owner).await;
    let transport = Arc::new(ControlledTransport::default());
    let runtime = DeliveryRuntime::start(&url, config, transport.clone())
        .await
        .unwrap();
    let store = runtime.store.sqlite_store().unwrap();
    until(|| transport.fcm_quiesced.load(Ordering::Relaxed) >= 1).await;
    let initial = transport.fcm_quiesced.load(Ordering::Relaxed);
    store
        .accept(request(&channel, &auth, "pool-first"))
        .await
        .unwrap();
    until(|| transport.started.load(Ordering::Relaxed) == 1).await;
    store
        .accept(request(&channel, &auth, "pool-continuous-next"))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='pending'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(transport.fcm_quiesced.load(Ordering::Relaxed), initial);
    transport.release.notify_one();
    until(|| transport.started.load(Ordering::Relaxed) == 2).await;
    assert_eq!(
        transport.fcm_quiesced.load(Ordering::Relaxed),
        initial,
        "next nonempty claim must retain provider pool across batches"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        1
    );
    transport.release.notify_one();
    until(|| transport.fcm_quiesced.load(Ordering::Relaxed) > initial).await;
    assert_eq!(store.counters.owned_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM targets WHERE state='provider_accepted'"
        )
        .fetch_one(&store.pool)
        .await
        .unwrap(),
        2
    );
    assert_eq!(runtime.shutdown().await.failed, 0);
}
