//! Ordinary client control lifecycle with synthetic identities only.
use crate::store::{OwnerLock, now};
use crate::{AcceptRequest, Config, DeliveryStore, KernelError};
use sqlx::Row;

async fn fixture() -> (
    tempfile::TempDir,
    DeliveryStore,
    OwnerLock,
    String,
    String,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let (store, owner) = DeliveryStore::open(
        &format!("sqlite://{}/control.sqlite", dir.path().display()),
        Config::default(),
    )
    .await
    .unwrap();
    let key = store.register("android").await.unwrap();
    store
        .route(&key, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    let password = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&key, None, Some("control"), &password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (dir, store, owner, key, channel, password)
}
fn input(channel: &str, password: &str, op: &str) -> AcceptRequest {
    AcceptRequest {
        channel_id: channel.into(),
        password: password.into(),
        title: "control lifecycle".into(),
        op_id: Some(op.into()),
        ttl: Some(now() + 60_000),
        ..Default::default()
    }
}
async fn close(store: DeliveryStore, owner: OwnerLock) {
    store.pool.close().await;
    owner.release();
}

#[tokio::test]
async fn idle_token_retirement_probes_markers_before_retained_targets() {
    let (_dir, store, owner, _key, _channel, _password) = fixture().await;
    let details = sqlx::query(&format!(
        "EXPLAIN QUERY PLAN {}",
        crate::store::RETIRE_TOKEN_TARGETS_SQL
    ))
    .fetch_all(&store.pool)
    .await
    .unwrap()
    .iter()
    .map(|row| row.get::<String, _>("detail"))
    .collect::<Vec<_>>();
    assert!(
        details.iter().any(|detail| detail.contains("SCAN r")),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("SEARCH t USING INDEX targets_token_retirement")),
        "{details:?}"
    );
    assert!(
        !details.iter().any(|detail| detail.contains("SCAN t")),
        "{details:?}"
    );
    let rows = sqlx::query(crate::store::RETIRE_TOKEN_TARGETS_SQL)
        .fetch_all(&store.pool)
        .await
        .unwrap();
    assert!(rows.is_empty());
    close(store, owner).await;
}

#[tokio::test]
async fn partial_sync_keeps_omissions_full_sync_and_unsubscribe_preserve_accepted_pull() {
    let (_dir, store, owner, key, channel, password) = fixture().await;
    let other = store
        .subscribe(&key, None, Some("omitted"), &password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = input(&other, &password, "control-sync-op");
    let accepted = store.accept(request.clone()).await.unwrap();
    let snapshot = store.status(&accepted.op_id).await.unwrap();
    let partial = store
        .sync_channels(
            &key,
            vec![
                (channel.clone(), password.clone()),
                (other.clone(), "synthetic-wrong-password".into()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(partial["success"], 1);
    assert_eq!(partial["failed"], 1);
    assert_eq!(partial["channels"][1]["error_code"], "password_mismatch");
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscriptions WHERE device_key=?")
            .bind(&key)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(count, 2);
    let full = store
        .sync_channels(&key, vec![(channel.clone(), password.clone())])
        .await
        .unwrap();
    assert_eq!(full["failed"], 0);
    assert_eq!(
        store.pull(&key, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.status(&accepted.op_id).await.unwrap(), snapshot);
    assert_eq!(
        store.unsubscribe(&key, &channel).await.unwrap()["removed"],
        true
    );
    assert_eq!(
        store.unsubscribe(&key, &channel).await.unwrap()["removed"],
        false
    );
    assert_eq!(
        store
            .ack(&key, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.accept(request).await.unwrap().delivery_id,
        accepted.delivery_id
    );
    close(store, owner).await;
}
#[tokio::test]
async fn route_delete_and_rename_preserve_frozen_payload_and_rebind_revision() {
    let (_dir, store, owner, key, channel, password) = fixture().await;
    let req = input(&channel, &password, "control-delete-op");
    let accepted = store.accept(req.clone()).await.unwrap();
    let old = store.register_device("android", Some(&key)).await.unwrap();
    assert!(matches!(
        store
            .rename_channel(&channel, "wrong", "synthetic-wrong-password")
            .await,
        Err(KernelError::Control { status: 403, .. })
    ));
    assert_eq!(
        store
            .rename_channel(&channel, "renamed", &password)
            .await
            .unwrap()["channel_name"],
        "renamed"
    );
    let deleted = store.delete_route(&key, "fcm").await.unwrap();
    assert_eq!(deleted["channel_type"], "fcm");
    assert!(deleted.get("provider_token").is_none());
    assert!(deleted["route_revision"].as_i64().unwrap() > old["route_revision"].as_i64().unwrap());
    assert_eq!(
        store.pull(&key, None).await.unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    let rebound = store
        .update_route(&key, None, "fcm", Some("synthetic-control-route-b"))
        .await
        .unwrap();
    assert!(
        rebound["route_revision"].as_i64().unwrap() > deleted["route_revision"].as_i64().unwrap()
    );
    assert_eq!(
        store.accept(req).await.unwrap().delivery_id,
        accepted.delivery_id
    );
    close(store, owner).await;
}
#[tokio::test]
async fn token_retirement_preserves_new_route_and_same_token_new_epoch() {
    let (_dir, store, owner, key, channel, password) = fixture().await;
    let old = store
        .accept(input(&channel, &password, "control-retire-old"))
        .await
        .unwrap();
    store
        .route(&key, None, "FCM", "synthetic-control-route-b")
        .await
        .unwrap();
    let newer = store
        .accept(input(&channel, &password, "control-retire-new"))
        .await
        .unwrap();
    store
        .retire_provider_token("android", "synthetic-control-route-a")
        .await
        .unwrap();
    assert_eq!(
        store.pull(&key, None).await.unwrap()["items"][0]["delivery_id"],
        newer.delivery_id
    );
    assert_eq!(
        store.pull(&key, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .ack(&key, vec![old.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    store
        .route(&key, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    let again = store
        .accept(input(&channel, &password, "control-retire-rebound"))
        .await
        .unwrap();
    store.maintenance().await.unwrap();
    assert_eq!(
        store.pull(&key, Some(&again.delivery_id)).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.register_device("android", Some(&key)).await.unwrap()["route"]["provider_token_present"],
        true
    );
    close(store, owner).await;
}
#[tokio::test]
async fn coalesced_old_capability_cannot_read_winning_owner_acks_late_receipt() {
    let (_dir, store, owner, old, channel, password) = fixture().await;
    let accepted = store
        .accept(input(&channel, &password, "control-coalesce-running"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let winner = store.register("android").await.unwrap();
    let route = store
        .update_route(&winner, None, "fcm", Some("synthetic-control-route-a"))
        .await
        .unwrap();
    assert_eq!(route["device_key"], winner);
    assert!(
        store.pull(&old, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .ack(&old, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store.pull(&winner, None).await.unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    assert!(store.authorize_ticket(&ticket).await.unwrap());
    assert_eq!(
        store
            .ack(&winner, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "sent"
    );
    let bytes: i64 = sqlx::query_scalar("SELECT payload_bytes FROM messages WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(bytes, 0);
    let row = sqlx::query(
        "SELECT message_id,dedupe_until,accepted_at,expires_at FROM messages WHERE delivery_id=?",
    )
    .bind(&accepted.delivery_id)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("message_id"), accepted.message_id);
    assert_eq!(
        row.get::<i64, _>("dedupe_until") - row.get::<i64, _>("accepted_at"),
        30 * 86_400_000
    );
    close(store, owner).await;
}

#[tokio::test]
async fn same_delivery_coalesces_to_one_pull_and_one_ack_without_losing_running_receipt() {
    let (_dir, store, owner, old, channel, password) = fixture().await;
    let winner = store.register("android").await.unwrap();
    store
        .route(&winner, None, "FCM", "synthetic-control-route-b")
        .await
        .unwrap();
    store
        .subscribe(&winner, Some(&channel), None, &password)
        .await
        .unwrap();
    let accepted = store
        .accept(input(&channel, &password, "control-coalesce-collision"))
        .await
        .unwrap();
    let mut tickets = store.claim("FCM", 2, false).await.unwrap().tickets;
    assert_eq!(tickets.len(), 2);
    store
        .route(&winner, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    assert_eq!(
        store.pull(&winner, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        store.pull(&old, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .ack(&winner, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert!(
        store.pull(&winner, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for ticket in tickets.drain(..) {
        store
            .settle(&ticket, "provider_accepted", 200, "", now(), None)
            .await
            .unwrap();
    }
    let targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(targets, 0);
    assert_eq!(
        store.status(&accepted.op_id).await.unwrap()["status"],
        "sent"
    );
    close(store, owner).await;
}

#[tokio::test]
async fn coalescing_transfers_remaining_obligation_after_winner_already_acked_its_own_target() {
    let (_dir, store, owner, old, channel, password) = fixture().await;
    let winner = store.register("android").await.unwrap();
    store
        .route(&winner, None, "FCM", "synthetic-control-route-b")
        .await
        .unwrap();
    store
        .subscribe(&winner, Some(&channel), None, &password)
        .await
        .unwrap();
    let accepted = store
        .accept(input(&channel, &password, "control-coalesce-prior-ack"))
        .await
        .unwrap();
    assert_eq!(
        store
            .ack(&winner, vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert!(
        store.pull(&winner, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    store
        .route(&winner, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    // The surviving old owner's obligation is transferred. The winner's
    // physically released target is not recreated; clients dedupe stable IDs.
    assert_eq!(
        store.pull(&winner, None).await.unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    assert!(
        store.pull(&old, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let frozen: String = sqlx::query_scalar("SELECT device_key FROM targets WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(frozen, old);
    assert_eq!(
        store
            .ack(&winner, vec![accepted.delivery_id])
            .await
            .unwrap(),
        1
    );
    close(store, owner).await;
}

#[tokio::test]
async fn coalescing_never_revives_an_aba_superseded_network_ticket() {
    let (_dir, store, owner, old, channel, password) = fixture().await;
    let accepted = store
        .accept(input(&channel, &password, "control-coalesce-aba"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert!(store.authorize_ticket(&ticket).await.unwrap());
    store
        .route(&old, None, "FCM", "synthetic-control-route-b")
        .await
        .unwrap();
    store
        .route(&old, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    assert!(!store.authorize_ticket(&ticket).await.unwrap());
    let winner = store.register("android").await.unwrap();
    store
        .route(&winner, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    assert!(!store.authorize_ticket(&ticket).await.unwrap());
    let frozen: i64 = sqlx::query_scalar(
        "SELECT owner_generation FROM targets WHERE delivery_id=? AND device_key=?",
    )
    .bind(&accepted.delivery_id)
    .bind(&old)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(frozen, -1);
    // A further transfer must preserve the negative authorization sentinel.
    let next = store.register("android").await.unwrap();
    store
        .route(&next, None, "FCM", "synthetic-control-route-a")
        .await
        .unwrap();
    assert!(!store.authorize_ticket(&ticket).await.unwrap());
    assert!(
        store.pull(&old, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        store.pull(&winner, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.pull(&next, None).await.unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    // Receipt ownership is independent of eligibility to start network work.
    store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state FROM targets WHERE delivery_id=? AND device_key=?")
            .bind(&accepted.delivery_id)
            .bind(&old)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(state, "provider_accepted");
    assert_eq!(
        store.ack(&next, vec![accepted.delivery_id]).await.unwrap(),
        1
    );
    close(store, owner).await;
}

#[tokio::test]
async fn identical_route_upsert_advances_display_revision_without_revoking_accepted_work() {
    let (_dir, store, owner, key, channel, password) = fixture().await;
    let accepted = store
        .accept(input(&channel, &password, "control-display-revision"))
        .await
        .unwrap();
    let ticket = store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let before = store.register_device("android", Some(&key)).await.unwrap();
    let revision = before["route_revision"].as_i64().unwrap();
    let first = store
        .update_route(&key, None, "fcm", Some(&ticket.token))
        .await
        .unwrap();
    assert_eq!(first["route_revision"], revision + 1);
    let second = store
        .update_route(&key, None, "fcm", Some(&ticket.token))
        .await
        .unwrap();
    assert_eq!(second["route_revision"], revision + 2);
    assert!(store.authorize_ticket(&ticket).await.unwrap());
    let generation: i64 =
        sqlx::query_scalar("SELECT route_generation FROM devices WHERE device_key=?")
            .bind(&key)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(generation, ticket.route_generation);
    let registration = store.register_device("android", Some(&key)).await.unwrap();
    assert_eq!(registration["route_revision"], revision + 2);
    assert_eq!(registration["route"]["route_revision"], revision + 2);
    let sync = store
        .sync_channels(&key, vec![(channel, password)])
        .await
        .unwrap();
    assert_eq!(sync["route"]["route_revision"], revision + 2);
    assert_eq!(
        store.pull(&key, None).await.unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    // Exhausted displayed revision rejects only the control mutation; it cannot
    // overflow into SQLite REAL or revoke a valid frozen provider attempt.
    sqlx::query("UPDATE devices SET route_revision=? WHERE device_key=?")
        .bind(i64::MAX)
        .bind(&key)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(
        store
            .update_route(&key, None, "fcm", Some(&ticket.token))
            .await
            .is_err()
    );
    assert!(store.delete_route(&key, "fcm").await.is_err());
    assert!(
        store
            .retire_provider_token("android", &ticket.token)
            .await
            .is_err()
    );
    assert!(store.authorize_ticket(&ticket).await.unwrap());
    let epoch: i64 = sqlx::query_scalar("SELECT control_epoch FROM ledger_usage WHERE singleton=1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(epoch, 0);
    close(store, owner).await;
}
