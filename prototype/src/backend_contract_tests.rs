//! Identical synthetic ordinary-message oracles exercise all three engines through
//! OrdinaryStore. Native database prerequisites are explicit; absence never passes.
use crate::store::{OwnerLock, now};
use crate::{AcceptRequest, Config, KernelError, OrdinaryStore};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use futures_util::FutureExt;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, Row};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;

const DAY: i64 = 86_400_000;
const ROUTE_A: &str = "synthetic-shared-provider-route-a";

struct Fixture {
    store: OrdinaryStore,
    owner: Option<OwnerLock>,
    url: String,
    _dir: Option<tempfile::TempDir>,
    device: String,
    channel: String,
    password: String,
}
impl Fixture {
    async fn open(url: String, config: Config, dir: Option<tempfile::TempDir>) -> Self {
        let opened = OrdinaryStore::open(&url, config).await;
        assert!(
            opened.is_ok(),
            "synthetic fixture open failed: {}",
            opened
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        let (store, owner) = opened.ok().unwrap();
        let device = store.register("android").await.unwrap();
        store.route(&device, None, "FCM", ROUTE_A).await.unwrap();
        let password = crate::types::generate_hex_id_128();
        let channel = store
            .subscribe(&device, None, Some("synthetic shared contract"), &password)
            .await
            .unwrap()["channel_id"]
            .as_str()
            .unwrap()
            .to_owned();
        Self {
            store,
            owner: Some(owner),
            url,
            _dir: dir,
            device,
            channel,
            password,
        }
    }
    async fn close(&mut self) {
        self.store.close().await;
        self.owner.take().unwrap().release();
    }
    async fn reopen(&mut self) {
        let config = self.store.config.clone();
        self.close().await;
        let opened = OrdinaryStore::open(&self.url, config).await;
        assert!(opened.is_ok(), "synthetic reopen failed");
        let (store, owner) = opened.ok().unwrap();
        self.store = store;
        self.owner = Some(owner);
    }
    fn request(&self, op: &str) -> AcceptRequest {
        AcceptRequest {
            channel_id: self.channel.clone(),
            password: self.password.clone(),
            title: " synthetic title ".into(),
            body: Some(" body ".into()),
            op_id: Some(op.into()),
            ..Default::default()
        }
    }
    async fn scalar(&self, sql: &str) -> i64 {
        if let Some(store) = self.store.sqlite_store() {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&store.pool)
                .await
                .unwrap()
        } else if let Some(store) = self.store.mysql_store() {
            let mut connection = store.acquire().await.unwrap();
            sqlx::query_scalar::<_, i64>(&sql.replace(" AS BIGINT", " AS SIGNED"))
                .fetch_one(&mut *connection)
                .await
                .unwrap()
        } else {
            let store = self.store.postgres_store().unwrap();
            let mut connection = store.acquire().await.unwrap();
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&mut *connection)
                .await
                .unwrap()
        }
    }
    async fn text(&self, sql: &str) -> String {
        if let Some(store) = self.store.sqlite_store() {
            sqlx::query_scalar::<_, String>(sql)
                .fetch_one(&store.pool)
                .await
                .unwrap()
        } else if let Some(store) = self.store.mysql_store() {
            let mut connection = store.acquire().await.unwrap();
            // Binary-collated VARCHAR carries BINARY_FLAG; decode valid UTF8
            // without SQLx's incompatible text metadata check.
            sqlx::query(sql)
                .fetch_one(&mut *connection)
                .await
                .unwrap()
                .get_unchecked::<String, _>(0)
        } else {
            let store = self.store.postgres_store().unwrap();
            let mut connection = store.acquire().await.unwrap();
            sqlx::query_scalar::<_, String>(sql)
                .fetch_one(&mut *connection)
                .await
                .unwrap()
        }
    }
    async fn exec(&self, sql: &str) {
        if let Some(store) = self.store.sqlite_store() {
            sqlx::raw_sql(sql).execute(&store.pool).await.unwrap();
        } else if let Some(store) = self.store.mysql_store() {
            let mut connection = store.acquire().await.unwrap();
            sqlx::raw_sql(sql).execute(&mut *connection).await.unwrap();
        } else {
            let store = self.store.postgres_store().unwrap();
            let mut connection = store.acquire().await.unwrap();
            sqlx::raw_sql(sql).execute(&mut *connection).await.unwrap();
        }
    }
    async fn usage(&self) {
        for (column, expression) in [
            (
                "messages",
                "(SELECT COUNT(*) FROM messages WHERE pending_targets>0)",
            ),
            (
                "targets",
                "(SELECT COUNT(*) FROM targets WHERE acked_at IS NULL AND state IN ('pending','running','retry_wait'))",
            ),
            (
                "bytes",
                "(SELECT CAST(COALESCE(SUM(payload_bytes),0) AS BIGINT) FROM messages)",
            ),
        ] {
            assert_eq!(
                self.scalar(&format!(
                    "SELECT {column} FROM ledger_usage WHERE singleton=1"
                ))
                .await,
                self.scalar(&format!("SELECT {expression}")).await,
                "usage {column}"
            );
        }
        assert_eq!(self.scalar("SELECT COUNT(*) FROM messages m WHERE pending_targets<>(SELECT COUNT(*) FROM targets t WHERE t.delivery_id=m.delivery_id AND t.acked_at IS NULL AND t.state IN ('pending','running','retry_wait'))").await, 0);
    }
}
fn lit(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn items(value: &Value) -> usize {
    value["items"].as_array().unwrap().len()
}

async fn identity_fields_ttl(f: &mut Fixture) {
    let mut request = f.request("full-fields");
    request.ttl = Some(now() + 120_000);
    request.occurred_at = Some(now() - 10_000);
    request.severity = Some(" HIGH ".into());
    request.url = Some(" https://example.invalid/synthetic ".into());
    request.images = vec![
        " https://example.invalid/a ".into(),
        "https://example.invalid/a".into(),
    ];
    request.tags = vec![" alpha ".into(), "alpha".into(), "beta".into()];
    request.ciphertext = Some(" synthetic-ciphertext ".into());
    request.metadata =
        serde_json::from_value(json!({" scalar ":true,"count":2,"label":"synthetic"})).unwrap();
    let accepted = f.store.accept(request.clone()).await.unwrap();
    let status = f.store.status(&accepted.op_id).await.unwrap();
    let payload = f
        .store
        .pull(&f.device, Some(&accepted.delivery_id))
        .await
        .unwrap()["items"][0]["payload"]
        .clone();
    assert_eq!(payload["title"], "synthetic title");
    assert_eq!(payload["body"], "body");
    assert_eq!(payload["severity"], "high");
    assert_eq!(payload["url"], "https://example.invalid/synthetic");
    assert_eq!(
        serde_json::from_str::<Value>(payload["images"].as_str().unwrap()).unwrap(),
        json!(["https://example.invalid/a"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(payload["tags"].as_str().unwrap()).unwrap(),
        json!(["alpha", "beta"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(payload["metadata"].as_str().unwrap()).unwrap(),
        json!({"scalar":true,"count":2,"label":"synthetic"})
    );
    assert_eq!(payload["ciphertext"], "synthetic-ciphertext");
    assert_eq!(payload["ttl"], request.ttl.unwrap().to_string());
    assert_eq!(
        payload["occurred_at"],
        request.occurred_at.unwrap().to_string()
    );
    assert!(payload.get("delivery_id").is_none());
    let ticket = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let mut direct = ticket.payload.clone();
    assert_eq!(direct["delivery_id"], accepted.delivery_id);
    direct.as_object_mut().unwrap().remove("delivery_id");
    assert_eq!(direct, payload);
    let fingerprint = f
        .text("SELECT fingerprint FROM messages WHERE op_id='full-fields'")
        .await;
    assert!(!fingerprint.is_empty());
    assert_eq!(
        f.scalar("SELECT dedupe_until-accepted_at FROM messages WHERE op_id='full-fields'")
            .await,
        30 * DAY
    );
    let replay = f.store.accept(request.clone()).await.unwrap();
    assert_eq!(
        (replay.message_id, replay.delivery_id),
        (accepted.message_id.clone(), accepted.delivery_id.clone())
    );
    // Every normalized content field independently participates in identity.
    let mut changed = Vec::new();
    let mut r = request.clone();
    r.title = "changed".into();
    changed.push(r);
    let mut r = request.clone();
    r.body = Some("changed".into());
    changed.push(r);
    let mut r = request.clone();
    r.severity = Some("low".into());
    changed.push(r);
    let mut r = request.clone();
    r.url = Some("https://example.invalid/changed".into());
    changed.push(r);
    let mut r = request.clone();
    r.images = vec!["changed".into()];
    changed.push(r);
    let mut r = request.clone();
    r.tags = vec!["changed".into()];
    changed.push(r);
    let mut r = request.clone();
    r.metadata.insert("count".into(), json!(3));
    changed.push(r);
    let mut r = request.clone();
    r.ciphertext = Some("changed".into());
    changed.push(r);
    let mut r = request.clone();
    r.ttl = Some(r.ttl.unwrap() + 1);
    changed.push(r);
    let mut r = request.clone();
    r.occurred_at = Some(r.occurred_at.unwrap() + 1);
    changed.push(r);
    for r in changed {
        assert!(matches!(
            f.store.accept(r).await,
            Err(KernelError::Conflict)
        ));
    }
    let mut denied = request.clone();
    denied.password = crate::types::generate_hex_id_128();
    assert!(matches!(
        f.store.accept(denied).await,
        Err(KernelError::Unauthorized)
    ));
    let other = f
        .store
        .subscribe(&f.device, None, Some("other"), &f.password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut crossed = request.clone();
    crossed.channel_id = other;
    assert!(matches!(
        f.store.accept(crossed).await,
        Err(KernelError::ScopeConflict)
    ));
    assert_eq!(f.store.status(&accepted.op_id).await.unwrap(), status);
    assert_eq!(
        f.text("SELECT fingerprint FROM messages WHERE op_id='full-fields'")
            .await,
        fingerprint
    );
    let mut omitted = f.request("unused");
    omitted.op_id = None;
    let a = f.store.accept(omitted.clone()).await.unwrap();
    let b = f.store.accept(omitted).await.unwrap();
    assert_ne!(a.op_id, b.op_id);
    assert_ne!(a.message_id, b.message_id);
    assert!(
        f.store.pull(&f.device, Some(&a.delivery_id)).await.unwrap()["items"][0]["payload"]
            .get("ttl")
            .is_none()
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT expires_at-accepted_at FROM messages WHERE delivery_id={}",
            lit(&a.delivery_id)
        ))
        .await,
        7 * DAY
    );
    let mut past = f.request("past-ttl");
    past.ttl = Some(now() - 1000);
    let failed = f.store.accept(past.clone()).await.unwrap();
    assert_eq!(
        f.store.status(&failed.op_id).await.unwrap()["status"],
        "failed"
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets WHERE delivery_id=(SELECT delivery_id FROM messages WHERE op_id='past-ttl')").await,0);
    assert_eq!(
        f.store.accept(past).await.unwrap().message_id,
        failed.message_id
    );
    let mut excessive = f.request("excessive-ttl");
    excessive.ttl = Some(now() + 31 * DAY);
    let capped = f.store.accept(excessive).await.unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT expires_at-accepted_at FROM messages WHERE delivery_id={}",
            lit(&capped.delivery_id)
        ))
        .await,
        30 * DAY
    );
    f.usage().await;
}

// These are API normalization and byte-identity oracles, shared verbatim.
// MySQL must not silently inherit a case-insensitive or PAD SPACE key contract.
async fn identity_collation_boundaries(f: &mut Fixture) {
    let lower = f.store.accept(f.request("identity-case")).await.unwrap();
    let upper = f.store.accept(f.request("IDENTITY-CASE")).await.unwrap();
    assert_ne!(lower.delivery_id, upper.delivery_id);
    let trimmed = f.store.accept(f.request(" identity-case ")).await.unwrap();
    assert_eq!(trimmed.delivery_id, lower.delivery_id);
    let max_op = "M".repeat(128);
    let accepted = f.store.accept(f.request(&max_op)).await.unwrap();
    assert_eq!(accepted.op_id, max_op);
    assert_eq!(f.store.status(&max_op).await.unwrap()["op_id"], max_op);
    assert!(matches!(
        f.store.accept(f.request(&"M".repeat(129))).await,
        Err(KernelError::Invalid(_))
    ));

    let password = "🔐".repeat(32); // exactly 128 UTF-8 bytes
    let name = "界".repeat(128); // 128 Unicode scalars, 384 UTF-8 bytes
    let device = f.store.register("android").await.unwrap();
    let token = "界".repeat(1360) + "abcdefghijklmnop"; // exactly 4096 bytes
    assert_eq!(token.len(), 4096);
    f.store.route(&device, None, "FCM", &token).await.unwrap();
    let channel = f
        .store
        .subscribe(&device, None, Some(&name), &password)
        .await
        .unwrap();
    assert_eq!(channel["channel_name"], name);
    let mut request = f.request("identity-max-unicode");
    request.channel_id = channel["channel_id"].as_str().unwrap().to_owned();
    request.password = password.clone();
    let delivery = f.store.accept(request.clone()).await.unwrap();
    assert_eq!(
        items(
            &f.store
                .pull(&device, Some(&delivery.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    request.password = "🔑".repeat(32);
    assert!(matches!(
        f.store.accept(request).await,
        Err(KernelError::Unauthorized)
    ));
    assert_eq!(
        f.text(&format!(
            "SELECT provider_token FROM devices WHERE device_key={}",
            lit(&device)
        ))
        .await,
        token
    );
    assert_eq!(
        f.text(&format!(
            "SELECT provider_token FROM targets WHERE delivery_id={}",
            lit(&delivery.delivery_id)
        ))
        .await,
        token
    );
    assert_eq!(
        f.text(&format!(
            "SELECT channel_name FROM channels WHERE channel_id={}",
            lit(channel["channel_id"].as_str().unwrap())
        ))
        .await,
        name
    );

    let long_tail_device = f.store.register("android").await.unwrap();
    let mut distinct_long_token = token.clone();
    distinct_long_token.pop();
    distinct_long_token.push('Q');
    f.store
        .route(&long_tail_device, None, "FCM", &distinct_long_token)
        .await
        .unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM devices WHERE device_key IN ({},{}) AND coalesced_to IS NULL",
            lit(&device),
            lit(&long_tail_device)
        ))
        .await,
        2,
        "token prefix indexes cannot collapse distinct full 4096-byte tokens"
    );
    let a = f.store.register("android").await.unwrap();
    let b = f.store.register("android").await.unwrap();
    let token_lower = "synthetic-Case-Sensitive-token";
    let token_upper = "synthetic-case-sensitive-token";
    f.store.route(&a, None, "FCM", token_lower).await.unwrap();
    f.store.route(&b, None, "FCM", token_upper).await.unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM devices WHERE device_key IN ({},{}) AND coalesced_to IS NULL",
            lit(&a),
            lit(&b)
        ))
        .await,
        2
    );
    // Leading/trailing whitespace is normalized before persistence and therefore
    // intentionally denotes the same route and the same current owner.
    f.store
        .route(&b, None, "FCM", &format!(" {token_lower} "))
        .await
        .unwrap();
    assert_eq!(
        f.text(&format!(
            "SELECT provider_token FROM devices WHERE device_key={}",
            lit(&b)
        ))
        .await,
        token_lower
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM devices WHERE provider_token={} AND retired_at IS NULL AND coalesced_to IS NULL",
            lit(token_lower)
        ))
        .await,
        1
    );
    assert_eq!(
        f.text(&format!(
            "SELECT coalesced_to FROM devices WHERE device_key={}",
            lit(&a)
        ))
        .await,
        b
    );
    f.usage().await;
}

async fn atomic_caps_ack_orders(f: &mut Fixture) {
    let second = f.store.register("android").await.unwrap();
    f.store
        .route(&second, None, "FCM", "synthetic-second-provider-route")
        .await
        .unwrap();
    f.store
        .subscribe(&second, Some(&f.channel), None, &f.password)
        .await
        .unwrap();
    let first = f.store.accept(f.request("cap-first")).await.unwrap();
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets").await, 2);
    assert!(matches!(
        f.store.accept(f.request("cap-rejected")).await,
        Err(KernelError::Capacity)
    ));
    assert!(matches!(
        f.store.status("cap-rejected").await,
        Err(KernelError::NotFound)
    ));
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets").await, 2);
    f.usage().await;
    let tickets = f
        .store
        .claim_reserved("FCM", 2, false)
        .await
        .unwrap()
        .tickets;
    assert_eq!(tickets.len(), 2);
    for ticket in &tickets {
        assert!(f.store.authorize_ticket(ticket).await.unwrap());
    }
    // ACK before receipt must retain the owned result obligation.
    assert_eq!(
        f.store
            .ack(&f.device, vec![first.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM targets WHERE state='running'")
            .await,
        2
    );
    assert_eq!(
        f.scalar("SELECT provider_accepted_count FROM messages WHERE op_id='cap-first'")
            .await,
        0
    );
    for t in &tickets {
        f.store
            .settle(t, "provider_accepted", 200, "", now(), None)
            .await
            .unwrap();
    }
    assert_eq!(f.store.status("cap-first").await.unwrap()["status"], "sent");
    assert_eq!(
        f.scalar("SELECT provider_accepted_count FROM messages WHERE op_id='cap-first'")
            .await,
        2
    );
    // Receipt before the other ACK releases provider budget before body bytes.
    let next = f.store.accept(f.request("cap-rejected")).await.unwrap();
    assert_ne!(next.delivery_id, first.delivery_id);
    assert_eq!(
        f.store
            .ack(&second, vec![first.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        f.store
            .ack(&second, vec![first.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.scalar("SELECT payload_bytes FROM messages WHERE op_id='cap-first'")
            .await,
        0
    );
    assert_eq!(
        f.store
            .accept(f.request("cap-first"))
            .await
            .unwrap()
            .message_id,
        first.message_id
    );
    f.usage().await;
    let third = f.store.register("android").await.unwrap();
    f.store
        .route(&third, None, "FCM", "synthetic-third-provider-route")
        .await
        .unwrap();
    f.store
        .subscribe(&third, Some(&f.channel), None, &f.password)
        .await
        .unwrap();
    for t in f
        .store
        .claim_reserved("FCM", 2, false)
        .await
        .unwrap()
        .tickets
    {
        f.store
            .settle(&t, "provider_accepted", 200, "", now(), None)
            .await
            .unwrap();
    }
    assert!(matches!(
        f.store.accept(f.request("fanout-rejected")).await,
        Err(KernelError::Capacity)
    ));
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM messages WHERE op_id='fanout-rejected'")
            .await,
        0
    );
    f.store.unsubscribe(&third, &f.channel).await.unwrap();
    let mixed = f.store.accept(f.request("mixed-expiry")).await.unwrap();
    let mut owned = f
        .store
        .claim_reserved("FCM", 2, false)
        .await
        .unwrap()
        .tickets;
    assert_eq!(owned.len(), 2);
    f.store
        .settle(
            &owned.pop().unwrap(),
            "provider_accepted",
            200,
            "",
            now(),
            None,
        )
        .await
        .unwrap();
    f.exec("UPDATE messages SET expires_at=0 WHERE op_id='mixed-expiry'")
        .await;
    f.store.maintenance().await.unwrap();
    // An in-flight outcome remains unknown even after body expiration.
    assert_eq!(
        f.store.status("mixed-expiry").await.unwrap()["status"],
        "provider_queued"
    );
    f.store
        .settle(
            &owned.pop().unwrap(),
            "permanent_failed",
            500,
            "synthetic-failure",
            now(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        f.store.status("mixed-expiry").await.unwrap()["status"],
        "partially_failed"
    );
    assert_eq!(
        f.store
            .accept(f.request("mixed-expiry"))
            .await
            .unwrap()
            .delivery_id,
        mixed.delivery_id
    );
    f.usage().await;
}

async fn pull_history_gc_restart(f: &mut Fixture) {
    let mut accepted = Vec::new();
    for n in 0..257 {
        accepted.push(
            f.store
                .accept(f.request(&format!("ordered-{n:03}")))
                .await
                .unwrap(),
        );
    }
    let early = now() - 10_000;
    for (id, at) in [
        (&accepted[0].delivery_id, early + 1),
        (&accepted[1].delivery_id, early),
    ] {
        f.exec(&format!("UPDATE messages SET accepted_at={at} WHERE delivery_id={}; UPDATE targets SET accepted_at={at} WHERE delivery_id={}",lit(id),lit(id))).await;
    }
    let batch = f.store.pull(&f.device, None).await.unwrap();
    assert_eq!(items(&batch), 200);
    assert_eq!(batch["has_more"], true);
    assert_eq!(batch["items"][0]["delivery_id"], accepted[1].delivery_id);
    assert_eq!(batch["items"][1]["delivery_id"], accepted[0].delivery_id);
    assert_eq!(f.store.pull(&f.device, None).await.unwrap(), batch);
    let exact = f
        .store
        .pull(&f.device, Some(&accepted[256].delivery_id))
        .await
        .unwrap();
    assert_eq!(items(&exact), 1);
    assert_eq!(exact["has_more"], false);
    let ids = batch["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["delivery_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(f.store.ack(&f.device, ids).await.unwrap(), 200);
    let rest = f.store.pull(&f.device, None).await.unwrap();
    assert_eq!(items(&rest), 57);
    assert_eq!(rest["has_more"], false);
    let legacy = f.store.pull_legacy(&f.device, None).await.unwrap();
    assert_eq!(items(&legacy), 57);
    assert_eq!(items(&f.store.pull(&f.device, None).await.unwrap()), 0);
    assert_eq!(
        items(&f.store.pull_legacy(&f.device, None).await.unwrap()),
        0
    );
    f.usage().await;
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 257);
    assert_eq!(
        f.scalar("SELECT CAST(COALESCE(SUM(payload_bytes),0) AS BIGINT) FROM messages")
            .await,
        0
    );
    assert_eq!(f.store.maintenance().await.unwrap(), 0);
    f.reopen().await;
    assert_eq!(
        f.store
            .accept(f.request("ordered-000"))
            .await
            .unwrap()
            .message_id,
        accepted[0].message_id
    );
    // Age fixture rows only. One GC call must leave the 257th identity intact.
    f.exec(&format!("UPDATE messages SET dedupe_until={}", now() - 1))
        .await;
    assert_eq!(f.store.maintenance().await.unwrap(), 256);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 1);
    assert_eq!(f.store.maintenance().await.unwrap(), 1);
    f.usage().await;
    // The payload-expiry batch is independently bounded, without a large
    // historical dataset or repeated unbounded maintenance loops.
    let mut expiry_ids = Vec::new();
    let equal_deadline = now() + 60_000;
    for n in 0..257 {
        let mut request = f.request(&format!("expiry-{n:03}"));
        request.ttl = Some(equal_deadline);
        expiry_ids.push(f.store.accept(request).await.unwrap().delivery_id);
    }
    expiry_ids.sort();
    f.exec("UPDATE messages SET expires_at=0").await;
    if f.store.postgres_store().is_some() {
        f.exec("SET enable_indexscan=off; SET enable_bitmapscan=off; SET enable_indexonlyscan=off")
            .await;
    }
    f.store.maintenance().await.unwrap();
    assert_expiry_keyset(f, &expiry_ids, 256).await;
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 257);
    f.usage().await;
    f.store.maintenance().await.unwrap();
    assert_expiry_keyset(f, &expiry_ids, 257).await;
    if f.store.postgres_store().is_some() {
        f.exec("RESET enable_indexscan; RESET enable_bitmapscan; RESET enable_indexonlyscan")
            .await;
    }
    assert_eq!(
        f.store.status("expiry-000").await.unwrap()["status"],
        "failed"
    );
    assert!(
        f.scalar("SELECT dedupe_until FROM messages WHERE op_id='expiry-000'")
            .await
            > now()
    );
    f.usage().await;
    let acked = f.store.accept(f.request("restart-acked")).await.unwrap();
    let pending = f.store.accept(f.request("restart-pending")).await.unwrap();
    let tickets = f
        .store
        .claim_reserved("FCM", 2, false)
        .await
        .unwrap()
        .tickets;
    f.store
        .ack(&f.device, vec![acked.delivery_id])
        .await
        .unwrap();
    f.reopen().await;
    assert_eq!(
        f.store.status("restart-acked").await.unwrap()["status"],
        "sent"
    );
    let recovered = f
        .store
        .claim_reserved("FCM", 2, false)
        .await
        .unwrap()
        .tickets;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].delivery_id, pending.delivery_id);
    assert!(
        recovered[0].attempt_id
            > tickets
                .iter()
                .find(|t| t.delivery_id == pending.delivery_id)
                .unwrap()
                .attempt_id
    );
    f.usage().await;
}

async fn control_epochs_coalescing(f: &mut Fixture) {
    let other = f
        .store
        .subscribe(&f.device, None, Some("omitted"), &f.password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut req = f.request("sync-preserved");
    req.channel_id = other.clone();
    let saved = f.store.accept(req.clone()).await.unwrap();
    let partial = f
        .store
        .sync_channels(
            &f.device,
            vec![
                (f.channel.clone(), f.password.clone()),
                (other.clone(), crate::types::generate_hex_id_128()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(partial["success"], 1);
    assert_eq!(partial["failed"], 1);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM channel_subscriptions").await,
        2
    );
    f.store
        .sync_channels(&f.device, vec![(f.channel.clone(), f.password.clone())])
        .await
        .unwrap();
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM channel_subscriptions").await,
        1
    );
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&saved.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    assert_eq!(
        f.store.unsubscribe(&f.device, &f.channel).await.unwrap()["removed"],
        true
    );
    assert_eq!(
        f.store.unsubscribe(&f.device, &f.channel).await.unwrap()["removed"],
        false
    );
    f.store.delete_route(&f.device, "fcm").await.unwrap();
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&saved.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    assert_eq!(
        f.store.accept(req).await.unwrap().message_id,
        saved.message_id
    );
    f.store
        .ack(&f.device, vec![saved.delivery_id])
        .await
        .unwrap();
    f.store
        .route(&f.device, None, "FCM", ROUTE_A)
        .await
        .unwrap();
    f.store
        .subscribe(&f.device, Some(&f.channel), None, &f.password)
        .await
        .unwrap();
    let old = f.store.accept(f.request("coalesced-frozen")).await.unwrap();
    let ticket = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert!(f.store.authorize_ticket(&ticket).await.unwrap());
    f.store
        .route(&f.device, None, "FCM", "synthetic-middle-provider-route")
        .await
        .unwrap();
    f.store
        .route(&f.device, None, "FCM", ROUTE_A)
        .await
        .unwrap();
    assert!(!f.store.authorize_ticket(&ticket).await.unwrap());
    let winner = f.store.register("android").await.unwrap();
    f.store.route(&winner, None, "FCM", ROUTE_A).await.unwrap();
    assert_eq!(
        f.text(&format!(
            "SELECT device_key FROM targets WHERE delivery_id={}",
            lit(&old.delivery_id)
        ))
        .await,
        f.device
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT owner_generation FROM targets WHERE delivery_id={}",
            lit(&old.delivery_id)
        ))
        .await,
        -1
    );
    let next = f.store.register("android").await.unwrap();
    f.store.route(&next, None, "FCM", ROUTE_A).await.unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT owner_generation FROM targets WHERE delivery_id={}",
            lit(&old.delivery_id)
        ))
        .await,
        -1
    );
    assert!(!f.store.authorize_ticket(&ticket).await.unwrap());
    assert_eq!(items(&f.store.pull(&f.device, None).await.unwrap()), 0);
    assert_eq!(items(&f.store.pull(&winner, None).await.unwrap()), 0);
    assert_eq!(items(&f.store.pull(&next, None).await.unwrap()), 1);
    assert_eq!(
        f.store
            .ack(&f.device, vec![old.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.store
            .ack(&next, vec![old.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    f.store
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
    assert_eq!(
        f.store.status("coalesced-frozen").await.unwrap()["status"],
        "failed"
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE device_key={}",
            lit(&next)
        ))
        .await,
        1
    );
    let retirement_old = f.store.accept(f.request("retire-old-route")).await.unwrap();
    f.store
        .route(&next, None, "FCM", "synthetic-new-provider-route")
        .await
        .unwrap();
    let newer = f.store.accept(f.request("retire-new-route")).await.unwrap();
    f.store
        .retire_provider_token("android", ROUTE_A)
        .await
        .unwrap();
    assert_eq!(
        items(
            &f.store
                .pull(&next, Some(&retirement_old.delivery_id))
                .await
                .unwrap()
        ),
        0
    );
    assert_eq!(
        f.store
            .ack(&next, vec![retirement_old.delivery_id])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        items(&f.store.pull(&next, Some(&newer.delivery_id)).await.unwrap()),
        1
    );
    f.store.route(&next, None, "FCM", ROUTE_A).await.unwrap();
    let rebound = f.store.accept(f.request("retire-new-epoch")).await.unwrap();
    f.store.maintenance().await.unwrap();
    assert_eq!(
        items(
            &f.store
                .pull(&next, Some(&rebound.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    assert!(f.scalar("SELECT control_epoch FROM ledger_usage").await > 0);
    assert!(f.scalar("SELECT control_epoch FROM targets WHERE delivery_id=(SELECT delivery_id FROM messages WHERE op_id='retire-new-epoch')").await>0);
    f.usage().await;
}

async fn run_oracles<F, Fut>(mut fixture: F)
where
    F: FnMut(Config) -> Fut,
    Fut: Future<Output = Fixture>,
{
    let mut f = fixture(Config {
        public_base_url: "https://gateway.invalid/mount/c4".into(),
        ..Config::default()
    })
    .await;
    identity_fields_ttl(&mut f).await;
    identity_collation_boundaries(&mut f).await;
    tokio::time::timeout(Duration::from_secs(10), shared_router_contract(&mut f))
        .await
        .expect("shared handler scenario exceeded 10 seconds");
    f.close().await;
    let mut f = fixture(Config {
        max_messages: 1,
        max_targets: 2,
        ..Default::default()
    })
    .await;
    atomic_caps_ack_orders(&mut f).await;
    f.close().await;
    let mut f = fixture(Config::default()).await;
    pull_history_gc_restart(&mut f).await;
    f.close().await;
    let mut f = fixture(Config::default()).await;
    control_epochs_coalescing(&mut f).await;
    f.close().await;
    let mut f = fixture(Config {
        max_payload_bytes: 1,
        ..Default::default()
    })
    .await;
    for n in 1..=32 {
        let key = f.store.register("android").await.unwrap();
        f.store
            .route(&key, None, "FCM", &format!("synthetic-limit-route-{n:02}"))
            .await
            .unwrap();
        let result = f
            .store
            .subscribe(&key, Some(&f.channel), None, &f.password)
            .await;
        if n < 32 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(KernelError::Control {
                    code: "channel_subscriber_limit_exceeded",
                    ..
                })
            ));
        }
    }
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM channel_subscriptions").await,
        32
    );
    assert!(matches!(
        f.store.accept(f.request("byte-cap")).await,
        Err(KernelError::Capacity)
    ));
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 0);
    f.usage().await;
    f.close().await;
}

#[tokio::test]
async fn sqlite_shared_ordinary_contract() {
    run_oracles(|config| async move {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("shared.sqlite").display());
        Fixture::open(url, config, Some(dir)).await
    })
    .await;
}

// Only this harness creates/removes databases. Cleanup names come exclusively
// from successful CREATEs in this invocation, never from the server catalog.
struct PgSandbox {
    base: reqwest::Url,
    created: std::sync::Mutex<Vec<String>>,
}
impl PgSandbox {
    fn guarded() -> Self {
        if std::env::var_os("C8_TEST_URL_FILE").is_some()
            || std::env::var_os("C7_TEST_URL_FILE").is_some()
        {
            let c8 = std::env::var_os("C8_TEST_URL_FILE").is_some();
            let raw = crate::private_contract_tests::assigned_c7_native_url(
                if c8 {
                    "C8_TEST_URL_FILE"
                } else {
                    "C7_TEST_URL_FILE"
                },
                if c8 {
                    "C8_NATIVE_DISPOSABLE"
                } else {
                    "C7_NATIVE_DISPOSABLE"
                },
                false,
                true,
            );
            return Self {
                base: reqwest::Url::parse(&raw)
                    .unwrap_or_else(|_| panic!("invalid assigned C7 native URL")),
                created: std::sync::Mutex::new(Vec::new()),
            };
        }
        assert_eq!(
            std::env::var("C4_PG_DISPOSABLE").ok().as_deref(),
            Some("YES_NEW_SYNTHETIC"),
            "explicit synthetic PostgreSQL prerequisite C4_PG_DISPOSABLE missing"
        );
        let raw =
            std::env::var("C4_PG_TEST_URL").expect("explicit C4_PG_TEST_URL prerequisite missing");
        let base = reqwest::Url::parse(&raw)
            .unwrap_or_else(|_| panic!("invalid synthetic PostgreSQL URL"));
        assert!(
            matches!(base.scheme(), "postgres" | "postgresql"),
            "PostgreSQL URL required"
        );
        assert!(
            base.host_str().is_some_and(|h| h == "localhost"
                || h.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
            "loopback PostgreSQL required"
        );
        let name = base.path().trim_start_matches('/');
        assert!(
            (name.starts_with("c4_synthetic_") || name.starts_with("c5_synthetic_"))
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "c4_synthetic or c5_synthetic database required"
        );
        assert!(
            base.query().is_none() && base.fragment().is_none(),
            "synthetic URL must not override connection host"
        );
        Self {
            base,
            created: std::sync::Mutex::new(Vec::new()),
        }
    }
    async fn admin(&self) -> PgConnection {
        PgConnection::connect(self.base.as_str())
            .await
            .unwrap_or_else(|_| panic!("synthetic PostgreSQL prerequisite unavailable"))
    }
    async fn fixture(&self, config: Config) -> Fixture {
        let name = format!("c4_synthetic_case_{}", crate::types::generate_hex_id_128());
        let mut admin = self.admin().await;
        let result = sqlx::raw_sql(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await;
        assert!(
            result.is_ok(),
            "synthetic database creation prerequisite failed"
        );
        self.created.lock().unwrap().push(name.clone());
        admin.close().await.ok();
        let mut url = self.base.clone();
        url.set_path(&format!("/{name}"));
        Fixture::open(url.to_string(), config, None).await
    }
    async fn cleanup(&self) {
        let names = self.created.lock().unwrap().clone();
        let mut admin = self.admin().await;
        for name in names {
            // FORCE targets only a database freshly created by this harness.
            let result = sqlx::raw_sql(&format!("DROP DATABASE {name} WITH (FORCE)"))
                .execute(&mut admin)
                .await;
            assert!(result.is_ok(), "synthetic database cleanup failed");
        }
        admin.close().await.ok();
    }
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback PostgreSQL C4_PG_TEST_URL and C4_PG_DISPOSABLE=YES_NEW_SYNTHETIC"]
async fn postgres_shared_ordinary_contract_and_native_failures() {
    let sandbox = PgSandbox::guarded();
    if std::env::var_os("C8_TEST_URL_FILE").is_some()
        || std::env::var_os("C7_TEST_URL_FILE").is_some()
    {
        crate::private_contract_tests::assert_empty_native_url(sandbox.base.as_str(), false).await;
    }
    let result = AssertUnwindSafe(async {
        run_oracles(|config| sandbox.fixture(config)).await;
        let mut f = sandbox.fixture(Config::default()).await;
        postgres_owner_failure_plans(&mut f).await;
        f.close().await;
        let f = sandbox.fixture(Config::default()).await;
        tokio::time::timeout(Duration::from_secs(10), postgres_runtime_backpressure(f))
            .await
            .expect("PG runtime scenario exceeded 10 seconds");
    })
    .catch_unwind()
    .await;
    sandbox.cleanup().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn postgres_owner_failure_plans(f: &mut Fixture) {
    assert!(matches!(
        OrdinaryStore::open(&f.url, Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    let mut alias = reqwest::Url::parse(&f.url).unwrap();
    let port = alias.port().unwrap_or(5432);
    alias.set_port(Some(port)).unwrap();
    let alias_host = if alias.host_str() == Some("localhost") {
        "127.0.0.1"
    } else {
        "localhost"
    };
    alias.set_host(Some(alias_host)).unwrap();
    assert!(matches!(
        OrdinaryStore::open(alias.as_str(), Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    let accepted = f
        .store
        .accept(f.request("pg-before-failure"))
        .await
        .unwrap();
    let pg = f.store.postgres_store().unwrap();
    // Native deferred constraint failure occurs at COMMIT, after the complete
    // fanout and trigger updates, and must roll all of those updates back.
    {
        let mut c = pg.acquire().await.unwrap();
        sqlx::raw_sql("CREATE TABLE commit_gate(id BIGINT PRIMARY KEY); INSERT INTO commit_gate VALUES(1); ALTER TABLE messages ADD COLUMN commit_guard BIGINT DEFAULT 1; ALTER TABLE messages ADD CONSTRAINT synthetic_deferred_commit FOREIGN KEY(commit_guard) REFERENCES commit_gate(id) DEFERRABLE INITIALLY DEFERRED; UPDATE messages SET commit_guard=NULL; DELETE FROM commit_gate").execute(&mut *c).await.unwrap();
    }
    let before = f.scalar("SELECT COUNT(*) FROM messages").await;
    assert!(
        f.store
            .accept(f.request("pg-rejected-commit"))
            .await
            .is_err()
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, before);
    assert!(matches!(
        f.store.status("pg-rejected-commit").await,
        Err(KernelError::NotFound)
    ));
    f.usage().await;
    f.exec("ALTER TABLE messages DROP CONSTRAINT synthetic_deferred_commit; ALTER TABLE messages DROP COLUMN commit_guard; DROP TABLE commit_gate").await;
    f.reopen().await;
    assert_eq!(
        f.store
            .accept(f.request("pg-before-failure"))
            .await
            .unwrap()
            .message_id,
        accepted.message_id
    );
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&accepted.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    postgres_plans(f).await;
    // Terminate the exact pinned session from an independent admin connection.
    // Repeated work must fail closed; reopening is an explicit owner action.
    let pg = f.store.postgres_store().unwrap();
    let pid: i32 = {
        let mut c = pg.acquire().await.unwrap();
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *c)
            .await
            .unwrap()
    };
    // Advisory locks are database-local. Probe on this exact case database,
    // not the sandbox's separate administrative base database.
    let mut admin = PgConnection::connect(&f.url).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut admin)
            .await
            .unwrap()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let present: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
            if !present {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("terminated pinned backend did not exit within 2 seconds");
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(1346852687,1129271876)")
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        "old backend's database advisory lock must be released"
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(1346852687,1129271876)")
            .fetch_one(&mut admin)
            .await
            .unwrap()
    );
    // The database session is gone, but the old local owner has not released
    // its persisted-dataset OS fence. Both URL spellings must still be refused.
    assert!(f.owner.is_some());
    assert!(matches!(
        OrdinaryStore::open(&f.url, Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    assert!(matches!(
        OrdinaryStore::open(alias.as_str(), Config::default()).await,
        Err(KernelError::OwnerContention)
    ));
    assert!(
        f.store
            .accept(f.request("pg-session-rejected"))
            .await
            .is_err()
    );
    assert!(
        f.store
            .accept(f.request("pg-session-rejected"))
            .await
            .is_err()
    );
    f.reopen().await;
    assert!(matches!(
        f.store.status("pg-session-rejected").await,
        Err(KernelError::NotFound)
    ));
    assert_eq!(
        f.store
            .accept(f.request("pg-before-failure"))
            .await
            .unwrap()
            .message_id,
        accepted.message_id
    );
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&accepted.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    f.usage().await;
}

async fn postgres_plans(f: &Fixture) {
    let pg = f.store.postgres_store().unwrap();
    let mut c = pg.acquire().await.unwrap();
    // Preserve actual native plans. A tiny synthetic fixture can reasonably
    // choose a sequential scan; schema readiness is a separate assertion.
    let pull: Vec<String> =
        sqlx::query_scalar(&format!("EXPLAIN {}", crate::pg_store::PULL_BATCH_SQL))
            .bind(&f.device)
            .bind(now())
            .bind(201_i64)
            .fetch_all(&mut *c)
            .await
            .unwrap();
    let exact: Vec<String> =
        sqlx::query_scalar(&format!("EXPLAIN {}", crate::pg_store::PULL_EXACT_SQL))
            .bind(&f.device)
            .bind("synthetic-plan-id")
            .bind(now())
            .fetch_all(&mut *c)
            .await
            .unwrap();
    let recovery: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT delivery_id FROM targets WHERE provider=$1 AND state='running'",
    )
    .bind("FCM")
    .fetch_all(&mut *c)
    .await
    .unwrap();
    let retirement: Vec<String> = sqlx::query_scalar(&format!(
        "EXPLAIN {}",
        crate::pg_store::RETIRE_TOKEN_TARGETS_SQL
    ))
    .fetch_all(&mut *c)
    .await
    .unwrap();
    let token_probe:Vec<String>=sqlx::query_scalar("EXPLAIN SELECT delivery_id,device_key FROM targets WHERE platform=$1 AND provider_token=$2 AND control_epoch<$3 AND acked_at IS NULL ORDER BY accepted_at,delivery_id,device_key LIMIT 256").bind("android").bind(ROUTE_A).bind(1_i64).fetch_all(&mut *c).await.unwrap();
    for plan in [&pull, &exact, &recovery, &retirement, &token_probe] {
        assert!(!plan.is_empty());
    }
    let indexes: Vec<(String,bool,String)> = sqlx::query_as("SELECT c.relname,i.indisvalid AND i.indisready,pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='pushgo_c' ORDER BY c.relname").fetch_all(&mut *c).await.unwrap();
    for (name, columns) in [
        ("targets_device", "(pull_owner, accepted_at, delivery_id)"),
        (
            "targets_owner_delivery",
            "(pull_owner, delivery_id, device_key)",
        ),
        (
            "targets_due",
            "(provider, state, next_attempt_at, delivery_id)",
        ),
        (
            "targets_token_retirement",
            "(platform, provider_token, control_epoch)",
        ),
    ] {
        let (_, ready, definition) = indexes
            .iter()
            .find(|(n, _, _)| n == name)
            .unwrap_or_else(|| panic!("missing native PG index {name}"));
        assert!(*ready, "native PG index not ready: {name}");
        assert!(
            definition.contains(columns),
            "native PG index definition {definition}"
        );
    }
    println!(
        "PG_NATIVE_PLANS {}",
        json!({"pull":pull,"exact":exact,"recovery":recovery,"retirement":retirement,"token_probe":token_probe,"indexes":indexes,"scope":"tiny synthetic fixture; actual optimizer plans and index readiness are separate evidence"})
    );
}

async fn assert_expiry_keyset(f: &Fixture, ids: &[String], expired: usize) {
    type ExpiryRow = (String, i64, i64, i64, String, i64);
    let sql = "SELECT m.delivery_id,m.provider_failed_count,m.pending_targets,m.payload_bytes,m.status,(SELECT COUNT(*) FROM targets t WHERE t.delivery_id=m.delivery_id) FROM messages m WHERE op_id LIKE 'expiry-%' ORDER BY expires_at,delivery_id";
    let rows: Vec<ExpiryRow> = if let Some(store) = f.store.sqlite_store() {
        sqlx::query_as(sql).fetch_all(&store.pool).await.unwrap()
    } else if let Some(store) = f.store.mysql_store() {
        let mut c = store.acquire().await.unwrap();
        let sql = sql
            .replace(
                "m.delivery_id,m.provider_failed_count",
                "CAST(m.delivery_id AS CHAR CHARACTER SET utf8mb4),m.provider_failed_count",
            )
            .replace("m.status,", "CAST(m.status AS CHAR CHARACTER SET utf8mb4),");
        sqlx::query_as(&sql).fetch_all(&mut *c).await.unwrap()
    } else {
        let store = f.store.postgres_store().unwrap();
        let mut c = store.acquire().await.unwrap();
        sqlx::query_as(sql).fetch_all(&mut *c).await.unwrap()
    };
    assert_eq!(rows.len(), 257);
    for (index, (id, failed, pending, bytes, status, targets)) in rows.into_iter().enumerate() {
        assert_eq!(
            id, ids[index],
            "the same ordered equal-TTL keyset must drive every expiry mutation"
        );
        if index < expired {
            assert_eq!(
                (failed, pending, bytes, status.as_str(), targets),
                (1, 0, 0, "failed", 0),
                "expired row {index}"
            );
        } else {
            assert_eq!(
                (failed, pending, status.as_str(), targets),
                (0, 1, "provider_queued", 1),
                "unselected equal-TTL row must remain intact"
            );
            assert!(bytes > 0);
        }
    }
}

async fn handler_call(
    app: &axum::Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    body: String,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(credential) = credential {
        request = request.header("authorization", format!("Bearer {credential}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn handler_post(app: &axum::Router, credential: &str, path: &str, body: Value) -> Value {
    let (status, value) = handler_call(
        app,
        "POST",
        &format!("/mount/c4{path}"),
        Some(credential),
        body.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "shared handler {path}");
    assert_eq!(value["success"], true);
    value["data"].clone()
}
async fn shared_router_contract(f: &mut Fixture) {
    let credential = crate::types::generate_hex_id_128();
    let app = crate::router_with_auth(f.store.clone(), Arc::new(|| json!({})), Some(&credential));
    let (status, _) = handler_call(
        &app,
        "POST",
        "/mount/c4/message",
        None,
        "invalid json".into(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "shared authentication precedes JSON parsing"
    );
    let (status, _) = handler_call(&app, "POST", "/message", Some(&credential), "{}".into()).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "mounted router preserves the configured prefix"
    );
    let device = handler_post(
        &app,
        &credential,
        "/device/register",
        json!({"platform":"android"}),
    )
    .await["device_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let route = crate::types::generate_hex_id_128();
    let configured = handler_post(
        &app,
        &credential,
        "/channel/device",
        json!({"device_key":device,"channel_type":"fcm","provider_token":route}),
    )
    .await;
    assert_eq!(configured["device_key"], device);
    assert_eq!(configured["channel_type"], "fcm");
    let password = crate::types::generate_hex_id_128();
    let channel = handler_post(
        &app,
        &credential,
        "/channel/subscribe",
        json!({"device_key":device,"channel_name":"shared native handlers","password":password}),
    )
    .await["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = json!({"channel_id":channel,"password":password,"op_id":"shared-http-op","title":" HTTP title ","body":"HTTP body","ttl":now()+60_000,"tags":["http"]});
    let accepted = handler_post(&app, &credential, "/message", request.clone()).await;
    let duplicate = handler_post(&app, &credential, "/message", request).await;
    assert_eq!(duplicate["message_id"], accepted["message_id"]);
    assert_eq!(duplicate["delivery_id"], accepted["delivery_id"]);
    let delivery = accepted["delivery_id"].as_str().unwrap();
    let pull_input = json!({"device_key":device,"delivery_id":delivery});
    let pulled = handler_post(&app, &credential, "/v2/messages/pull", pull_input.clone()).await;
    assert_eq!(items(&pulled), 1);
    assert_eq!(pulled["has_more"], false);
    assert_eq!(pulled["items"][0]["delivery_id"], delivery);
    assert_eq!(pulled["items"][0]["payload"]["title"], "HTTP title");
    assert_eq!(
        pulled["items"][0]["payload"]["base_url"],
        f.store.config.public_base_url
    );
    assert!(pulled["items"][0]["payload"].get("delivery_id").is_none());
    assert_eq!(
        handler_post(&app, &credential, "/v2/messages/pull", pull_input.clone()).await,
        pulled
    );
    let (status, before) = handler_call(
        &app,
        "GET",
        "/mount/c4/send_status/shared-http-op",
        Some(&credential),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["data"]["entity_id"], accepted["message_id"]);
    let ack = handler_post(
        &app,
        &credential,
        "/v2/messages/ack",
        json!({"device_key":device,"delivery_ids":[delivery]}),
    )
    .await;
    assert_eq!(ack, json!({"requested_count":1,"removed_count":1}));
    assert_eq!(
        items(&handler_post(&app, &credential, "/v2/messages/pull", pull_input).await),
        0
    );
    let (status, after) = handler_call(
        &app,
        "GET",
        "/mount/c4/send_status/shared-http-op",
        Some(&credential),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["data"]["status"], "sent");
    assert_eq!(after["data"]["entity_id"], before["data"]["entity_id"]);
    assert_eq!(after["data"]["accepted_at"], before["data"]["accepted_at"]);
    f.usage().await;
}

struct HeldResults {
    permits: tokio::sync::Semaphore,
    calls: AtomicUsize,
}
impl crate::ProviderTransport for HeldResults {
    fn send<'a>(
        &'a self,
        _provider: &'a str,
        _platform: crate::types::Platform,
        _token: &'a str,
        _payload: Value,
        _delivery: &'a str,
        _device: &'a str,
        _accepted: i64,
        _expiry: i64,
    ) -> crate::transport::BoxFuture<'a, crate::transport::DispatchResult> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.permits.acquire().await.unwrap().forget();
            crate::transport::DispatchResult::success(200)
        })
    }
}
async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("bounded runtime state did not become observable within 2 seconds");
}
async fn postgres_runtime_backpressure(mut f: Fixture) {
    let mut ids = Vec::new();
    for n in 0..40 {
        ids.push(
            f.store
                .accept(f.request(&format!("runtime-held-{n:02}")))
                .await
                .unwrap()
                .delivery_id,
        );
    }
    let config = f.store.config.clone();
    assert_eq!((config.provider_budget, config.claim_quantum), (32, 32));
    f.close().await;
    let transport = Arc::new(HeldResults {
        permits: tokio::sync::Semaphore::new(0),
        calls: AtomicUsize::new(0),
    });
    let runtime = crate::DeliveryRuntime::start(&f.url, config, transport.clone())
        .await
        .unwrap();
    f.store = runtime.store.clone();
    let counters = runtime.store.counters.clone();
    until(|| {
        transport.calls.load(Ordering::Relaxed) == 32
            && counters.network_inflight.load(Ordering::Relaxed) == 32
            && counters.owned_attempts.load(Ordering::Relaxed) == 32
    })
    .await;
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM targets WHERE state='running'")
            .await,
        32
    );
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM targets WHERE state='pending'")
            .await,
        8
    );
    // Use an independent real PostgreSQL session, never the runtime's pinned
    // session, to hold the row lock used by every ledger mutation.
    let mut locker = PgConnection::connect(&f.url)
        .await
        .unwrap_or_else(|_| panic!("synthetic runtime locker connection failed"));
    sqlx::raw_sql("SET search_path TO pushgo_c,pg_catalog; BEGIN; SELECT singleton FROM ledger_usage WHERE singleton=1 FOR UPDATE").execute(&mut locker).await.unwrap();
    transport.permits.add_permits(32);
    until(|| {
        counters.network_inflight.load(Ordering::Relaxed) == 0
            && counters.receipts_owned.load(Ordering::Relaxed) == 32
    })
    .await;
    assert_eq!(counters.owned_attempts.load(Ordering::Relaxed), 32);
    assert_eq!(transport.calls.load(Ordering::Relaxed), 32);
    assert_eq!(counters.receipt_commits.load(Ordering::Relaxed), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&mut locker)
            .await
            .unwrap(),
        32
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(counters.network_inflight.load(Ordering::Relaxed), 0);
    assert_eq!(counters.receipts_owned.load(Ordering::Relaxed), 32);
    assert_eq!(counters.owned_attempts.load(Ordering::Relaxed), 32);
    assert_eq!(
        transport.calls.load(Ordering::Relaxed),
        32,
        "result backlog must prevent claiming the other eight jobs"
    );
    assert!(counters.peak_owned_attempts.load(Ordering::Relaxed) <= 32);
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut locker)
        .await
        .unwrap();
    until(|| {
        transport.calls.load(Ordering::Relaxed) == 40
            && counters.network_inflight.load(Ordering::Relaxed) == 8
    })
    .await;
    transport.permits.add_permits(8);
    until(|| {
        counters.receipt_commits.load(Ordering::Relaxed) == 40
            && counters.owned_attempts.load(Ordering::Relaxed) == 0
            && counters.network_inflight.load(Ordering::Relaxed) == 0
            && counters.receipts_owned.load(Ordering::Relaxed) == 0
    })
    .await;
    assert_eq!(runtime.store.ack(&f.device, ids).await.unwrap(), 40);
    f.usage().await;
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages WHERE status='sent' AND provider_accepted_count=1 AND payload_bytes=0").await,40);
    until(|| counters.provider_targets[0].load(Ordering::Relaxed) == 0).await;
    let report = runtime.shutdown().await;
    assert_eq!(
        (
            report.joined,
            report.failed,
            report.panicked,
            report.aborted
        ),
        (2, 0, 0, 0)
    );
    assert_eq!(counters.num_alive.load(Ordering::Relaxed), 0);
    locker.close().await.ok();
}

#[path = "mysql_native_tests.rs"]
mod mysql_native_tests;
