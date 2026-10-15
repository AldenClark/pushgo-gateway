//! One durable Private ledger contract across SQLite, PostgreSQL and MySQL.
//! Native wrappers require an environment-owner assigned NEW EMPTY C6/C7 database;
//! they never create/drop a database or replay an external request. Trigger fault
//! prerequisites are explicit. All direct SQL is observation or synthetic fault/
//! clock control; all acceptance, claims, ACKs and ownership changes use the facade.
use crate::private_model::{PrivateRoute, PrivateTicket};
use crate::store::{OwnerLock, now};
use crate::{AcceptRequest, Config, KernelError, OrdinaryStore};
use serde_json::{Value, json};
use sqlx::{Connection, MySqlConnection, PgConnection};
use std::path::PathBuf;

const DAY: i64 = 86_400_000;
struct Subject {
    device: String,
    channel: String,
    password: String,
}
impl Subject {
    fn request(&self, op: &str) -> AcceptRequest {
        AcceptRequest {
            channel_id: self.channel.clone(),
            password: self.password.clone(),
            title: " synthetic Private title ".into(),
            body: Some(" body ".into()),
            op_id: Some(op.into()),
            ..Default::default()
        }
    }
}
struct Fixture {
    store: OrdinaryStore,
    owner: Option<OwnerLock>,
    url: String,
    _dir: Option<tempfile::TempDir>,
}
impl Fixture {
    async fn open(url: String, dir: Option<tempfile::TempDir>) -> Self {
        let mut config = Config::default();
        config.private.enabled = true;
        // A two-item bound makes admission/release observable without a load test.
        config.private.max_pending_per_device = 2;
        let (store, owner) = OrdinaryStore::open(&url, config)
            .await
            .unwrap_or_else(|error| panic!("Private fixture startup failed: {error}"));
        Self {
            store,
            owner: Some(owner),
            url,
            _dir: dir,
        }
    }
    async fn close(&mut self) {
        self.store.close().await;
        self.owner.take().unwrap().release();
    }
    async fn reopen(&mut self, config: Config) {
        self.close().await;
        let (store, owner) = OrdinaryStore::open(&self.url, config)
            .await
            .unwrap_or_else(|error| panic!("Private fixture restart failed: {error}"));
        self.store = store;
        self.owner = Some(owner);
    }
    async fn subject(&self) -> Subject {
        let device = self.store.register("android").await.unwrap();
        self.store
            .update_route(&device, None, "PRIVATE", None)
            .await
            .unwrap();
        let password = crate::types::generate_hex_id_128();
        let channel = self
            .store
            .subscribe(&device, None, Some("synthetic Private contract"), &password)
            .await
            .unwrap()["channel_id"]
            .as_str()
            .unwrap()
            .to_owned();
        Subject {
            device,
            channel,
            password,
        }
    }
    async fn route(&self, s: &Subject) -> PrivateRoute {
        self.store.private_route(&s.device).await.unwrap()
    }
    async fn claim(&self, s: &Subject, group: &str) -> Vec<PrivateTicket> {
        self.store
            .private_claim(&self.route(s).await, group, 96)
            .await
            .unwrap()
    }
    async fn scalar(&self, sql: &str) -> i64 {
        if let Some(s) = self.store.sqlite_store() {
            sqlx::query_scalar(sql).fetch_one(&s.pool).await.unwrap()
        } else if let Some(s) = self.store.postgres_store() {
            let mut c = s.acquire().await.unwrap();
            sqlx::query_scalar(sql).fetch_one(&mut *c).await.unwrap()
        } else {
            let s = self.store.mysql_store().unwrap();
            let mut c = s.acquire().await.unwrap();
            sqlx::query_scalar(sql).fetch_one(&mut *c).await.unwrap()
        }
    }
    async fn exec(&self, sql: &str) {
        if let Some(s) = self.store.sqlite_store() {
            sqlx::raw_sql(sql).execute(&s.pool).await.unwrap();
        } else if let Some(s) = self.store.postgres_store() {
            let mut c = s.acquire().await.unwrap();
            sqlx::raw_sql(sql).execute(&mut *c).await.unwrap();
        } else {
            let s = self.store.mysql_store().unwrap();
            let mut c = s.acquire().await.unwrap();
            sqlx::raw_sql(sql).execute(&mut *c).await.unwrap();
        }
    }
    async fn pending(&self, s: &Subject) -> i64 {
        self.scalar(&format!(
            "SELECT COALESCE((SELECT pending FROM private_usage WHERE device_key={}),0)",
            lit(&s.device)
        ))
        .await
    }
    async fn payload_bytes(&self, id: &str) -> i64 {
        self.scalar(&format!(
            "SELECT payload_bytes FROM messages WHERE delivery_id={}",
            lit(id)
        ))
        .await
    }
    async fn http_cannot_consume(&self, s: &Subject, id: &str) {
        assert!(
            self.store.pull(&s.device, Some(id)).await.unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            self.store.pull_legacy(&s.device, Some(id)).await.unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(self.store.ack(&s.device, vec![id.into()]).await.unwrap(), 0);
    }
    async fn counters(&self) {
        // Independent set oracle: physical fanout and logical Private obligations
        // are different quantities after identity coalescing.
        let logical = "SELECT COUNT(*) FROM (SELECT pull_owner,delivery_id FROM targets WHERE delivery_mode='private' AND acked_at IS NULL GROUP BY pull_owner,delivery_id) private_logical";
        assert_eq!(
            self.scalar("SELECT private_pending FROM ledger_usage WHERE singleton=1")
                .await,
            self.scalar(logical).await
        );
        assert_eq!(self.scalar("SELECT COUNT(*) FROM private_usage u WHERE u.pending<>(SELECT COUNT(*) FROM (SELECT pull_owner,delivery_id FROM targets WHERE delivery_mode='private' AND acked_at IS NULL GROUP BY pull_owner,delivery_id) p WHERE p.pull_owner=u.device_key)").await,0);
        assert_eq!(self.scalar("SELECT targets FROM ledger_usage WHERE singleton=1").await,self.scalar("SELECT COUNT(*) FROM targets WHERE acked_at IS NULL AND (delivery_mode='private' OR state IN ('pending','running','retry_wait'))").await);
    }
    async fn ack_fault(&self, install: bool) {
        if self.store.sqlite_store().is_some() {
            self.exec(if install {"CREATE TRIGGER c6_private_ack_fault BEFORE UPDATE OF acked_at ON targets WHEN OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'synthetic Private ACK fault'); END"} else {"DROP TRIGGER c6_private_ack_fault"}).await;
        } else if self.store.postgres_store().is_some() {
            self.exec(if install {"CREATE FUNCTION c6_private_ack_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL THEN RAISE EXCEPTION 'synthetic Private ACK fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER c6_private_ack_fault BEFORE UPDATE OF acked_at ON targets FOR EACH ROW EXECUTE FUNCTION c6_private_ack_fault_fn()"} else {"DROP TRIGGER c6_private_ack_fault ON targets; DROP FUNCTION c6_private_ack_fault_fn()"}).await;
        } else {
            self.exec(if install {"CREATE TRIGGER c6_private_ack_fault BEFORE UPDATE ON targets FOR EACH ROW BEGIN IF OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic Private ACK fault'; END IF; END"} else {"DROP TRIGGER c6_private_ack_fault"}).await;
        }
    }
}
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
fn body(t: &PrivateTicket) -> Value {
    serde_json::from_slice(&t.payload).unwrap()
}
fn same_identity(a: &crate::Accepted, b: &crate::Accepted) {
    assert_eq!(
        (&a.op_id, &a.message_id, &a.delivery_id),
        (&b.op_id, &b.message_id, &b.delivery_id)
    );
}

async fn frozen_identity_capability_capacity(f: &mut Fixture) {
    let s = f.subject().await;
    let mut req = s.request("private-frozen");
    req.ttl = Some(now() + 120_000);
    req.occurred_at = Some(now() - 10_000);
    req.tags = vec![" first ".into()];
    req.metadata = serde_json::from_value(json!({"synthetic":true})).unwrap();
    let accepted = f.store.accept(req.clone()).await.unwrap();
    let before = f.store.status(&accepted.op_id).await.unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT private_enqueued_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        1
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT provider_target_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        0
    );
    assert_eq!(
        before["expires_at"].as_i64().unwrap() - before["accepted_at"].as_i64().unwrap(),
        30 * DAY
    );
    let mut grants = f.claim(&s, "private-first-group").await;
    assert_eq!(grants.len(), 1);
    let ticket = grants.pop().unwrap();
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    assert_eq!(ticket.receipt_owner, s.device);
    assert_eq!(ticket.pull_owner, s.device);
    assert_eq!(ticket.accepted_at, before["accepted_at"].as_i64().unwrap());
    assert_eq!(ticket.expires_at, req.ttl.unwrap());
    assert_eq!(body(&ticket)["title"], "synthetic Private title");
    assert_eq!(body(&ticket)["delivery_id"], accepted.delivery_id);
    assert_eq!(body(&ticket)["ttl"], req.ttl.unwrap().to_string());
    assert_eq!(
        body(&ticket)["occurred_at"],
        req.occurred_at.unwrap().to_string()
    );
    same_identity(&accepted, &f.store.accept(req.clone()).await.unwrap());
    let mut different = req.clone();
    different.body = Some("different content".into());
    assert!(matches!(
        f.store.accept(different).await,
        Err(KernelError::Conflict)
    ));
    f.http_cannot_consume(&s, &accepted.delivery_id).await;
    assert!(f.store.private_authorize(&ticket).await.unwrap());
    assert!(
        f.store
            .claim_reserved("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty(),
        "Private enqueue must not create a Provider job"
    );
    let route = f.route(&s).await;
    let mut wrong_route = route.clone();
    wrong_route.route_generation += 1;
    assert!(!f.store.private_ack(&wrong_route, &ticket).await.unwrap());
    // A ticket's identity is not enough: every issued capability component is fenced.
    for forged in 0..5 {
        let mut bad = ticket.clone();
        match forged {
            0 => bad.claim_token = "0".repeat(32),
            1 => bad.group_id = "wrong-group".into(),
            2 => bad.delivery_epoch += 1,
            3 => bad.pull_owner = "0".repeat(32),
            _ => bad.receipt_owner = "0".repeat(32),
        }
        assert!(!f.store.private_authorize(&bad).await.unwrap());
        assert!(!f.store.private_ack(&route, &bad).await.unwrap());
    }
    assert!(
        f.claim(&s, "another-session").await.is_empty(),
        "claimed logical item cannot be granted twice"
    );
    let second = f
        .store
        .accept(s.request("private-bound-second"))
        .await
        .unwrap();
    assert_eq!(f.pending(&s).await, 2);
    assert!(matches!(
        f.store.accept(s.request("private-bound-rejected")).await,
        Err(KernelError::Capacity)
    ));
    assert!(matches!(
        f.store.status("private-bound-rejected").await,
        Err(KernelError::NotFound)
    ));
    assert!(f.store.private_ack(&route, &ticket).await.unwrap());
    assert!(!f.store.private_ack(&route, &ticket).await.unwrap());
    assert_eq!(f.pending(&s).await, 1);
    assert_eq!(f.payload_bytes(&accepted.delivery_id).await, 0);
    assert_eq!(
        f.scalar(&format!(
            "SELECT provider_accepted_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        0
    );
    let third = f
        .store
        .accept(s.request("private-bound-reused"))
        .await
        .unwrap();
    for t in f.claim(&s, "capacity-release").await {
        assert!(f.store.private_ack(&route, &t).await.unwrap());
    }
    assert_eq!(f.pending(&s).await, 0);
    assert_eq!(f.payload_bytes(&second.delivery_id).await, 0);
    assert_eq!(f.payload_bytes(&third.delivery_id).await, 0);
    f.store.maintenance().await.unwrap();
    f.reopen(f.store.config.clone()).await;
    same_identity(&accepted, &f.store.accept(req).await.unwrap());
    let after = f.store.status(&accepted.op_id).await.unwrap();
    assert_eq!(after["accepted_at"], before["accepted_at"]);
    assert_eq!(after["entity_id"], before["entity_id"]);
    assert_eq!(after["expires_at"], before["expires_at"]);
    assert!(f.claim(&s, "no-replay").await.is_empty());
    assert!(
        f.scalar(&format!(
            "SELECT dedupe_until FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await
            > now() + 29 * DAY,
        "ACK and payload collection must preserve the 30-day operation identity"
    );
    f.counters().await;
}

async fn disconnect_rollback_restart(f: &mut Fixture) {
    let s = f.subject().await;
    let request = s.request("private-restart");
    let accepted = f.store.accept(request.clone()).await.unwrap();
    let old = f.claim(&s, "disconnected-group").await.pop().unwrap();
    let original = body(&old);
    assert_eq!(
        f.store
            .private_release("wrong-group", std::slice::from_ref(&old.claim_token))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.store
            .private_release(
                &old.group_id,
                &[old.claim_token.clone(), old.claim_token.clone()]
            )
            .await
            .unwrap(),
        1
    );
    assert!(!f.store.private_authorize(&old).await.unwrap());
    assert!(!f.store.private_ack(&f.route(&s).await, &old).await.unwrap());
    let current = f.claim(&s, "reconnected-group").await.pop().unwrap();
    assert_ne!(old.claim_token, current.claim_token);
    assert_eq!(original, body(&current));
    assert_eq!(old.delivery_id, current.delivery_id);
    assert_eq!(old.expires_at, current.expires_at);
    f.ack_fault(true).await;
    assert!(
        f.store
            .private_ack(&f.route(&s).await, &current)
            .await
            .is_err(),
        "native ACK trigger must reject the transaction"
    );
    f.ack_fault(false).await;
    assert!(f.store.private_authorize(&current).await.unwrap());
    assert_eq!(f.pending(&s).await, 1);
    assert!(f.payload_bytes(&accepted.delivery_id).await > 0);
    f.counters().await;
    f.reopen(f.store.config.clone()).await;
    assert!(
        !f.store.private_authorize(&current).await.unwrap(),
        "startup must revoke the departed runtime's grant"
    );
    same_identity(&accepted, &f.store.accept(request).await.unwrap());
    let recovered = f.claim(&s, "after-restart").await.pop().unwrap();
    assert_eq!(body(&recovered), original);
    assert_ne!(recovered.claim_token, current.claim_token);
    assert_eq!(
        (recovered.accepted_at, recovered.expires_at),
        (old.accepted_at, old.expires_at)
    );
    assert!(
        f.store
            .private_ack(&f.route(&s).await, &recovered)
            .await
            .unwrap()
    );
    f.counters().await;
}

async fn modes_and_frozen_provider_receipt(f: &mut Fixture) {
    let s = f.subject().await;
    f.store
        .route(&s.device, None, "FCM", "synthetic-private-frozen-provider")
        .await
        .unwrap();
    let accepted = f
        .store
        .accept(s.request("private-old-provider-attempt"))
        .await
        .unwrap();
    let provider = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert_eq!(provider.delivery_id, accepted.delivery_id);
    f.store
        .update_route(&s.device, None, "PRIVATE", None)
        .await
        .unwrap();
    assert!(!f.store.authorize_ticket(&provider).await.unwrap());
    let t = f.claim(&s, "private-after-provider").await.pop().unwrap();
    assert!(t.delivery_epoch > 0);
    assert_eq!(t.receipt_owner, provider.device_key);
    f.http_cannot_consume(&s, &accepted.delivery_id).await;
    assert!(f.store.private_ack(&f.route(&s).await, &t).await.unwrap());
    assert_eq!(f.pending(&s).await, 0);
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM targets WHERE delivery_id={} AND state='running'",
            lit(&accepted.delivery_id)
        ))
        .await,
        1,
        "Private ACK cannot erase an owned frozen Provider receipt"
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT provider_accepted_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        0
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT private_enqueued_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        0,
        "route migration cannot rewrite frozen acceptance fanout"
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT provider_target_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        1
    );
    f.store
        .settle(&provider, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        f.scalar(&format!(
            "SELECT provider_accepted_count FROM messages WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        1
    );
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM targets WHERE delivery_id={}",
            lit(&accepted.delivery_id)
        ))
        .await,
        0
    );
    let next = f
        .store
        .accept(s.request("private-switch-back"))
        .await
        .unwrap();
    let old = f.claim(&s, "before-switch-back").await.pop().unwrap();
    let before = f.route(&s).await;
    // A no-op display revision must not invalidate a delivery capability.
    f.store
        .update_route(&s.device, None, "PRIVATE", None)
        .await
        .unwrap();
    let display = f.route(&s).await;
    assert_eq!(display.route_generation, before.route_generation);
    assert!(display.route_revision > before.route_revision);
    assert!(f.store.private_authorize(&old).await.unwrap());
    f.store
        .route(&s.device, None, "FCM", "synthetic-private-return-provider")
        .await
        .unwrap();
    assert!(!f.store.private_authorize(&old).await.unwrap());
    assert!(!f.store.private_ack(&before, &old).await.unwrap());
    assert_eq!(
        f.store
            .pull(&s.device, Some(&next.delivery_id))
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        f.store
            .claim_reserved("FCM", 1, false)
            .await
            .unwrap()
            .tickets
            .is_empty(),
        "mode switch must not fabricate another Provider push"
    );
    assert_eq!(
        f.store
            .ack(&s.device, vec![next.delivery_id])
            .await
            .unwrap(),
        1
    );
    f.counters().await;
}

async fn unsubscribe_and_coalesced_siblings(f: &mut Fixture) {
    let s = f.subject().await;
    let retained = f
        .store
        .accept(s.request("private-unsubscribe-before"))
        .await
        .unwrap();
    f.store.unsubscribe(&s.device, &s.channel).await.unwrap();
    let later = f
        .store
        .accept(s.request("private-unsubscribe-after"))
        .await
        .unwrap();
    let tickets = f.claim(&s, "after-unsubscribe").await;
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].delivery_id, retained.delivery_id);
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM targets WHERE delivery_id={}",
            lit(&later.delivery_id)
        ))
        .await,
        0
    );
    assert!(
        f.store
            .private_ack(&f.route(&s).await, &tickets[0])
            .await
            .unwrap()
    );
    let mut a = f.subject().await;
    let mut b_device = f.store.register("android").await.unwrap();
    f.store
        .subscribe(&b_device, Some(&a.channel), None, &a.password)
        .await
        .unwrap();
    // Pick the lexicographically later key as the eventual winner so the
    // canonical frozen recipient is certainly different from its current owner.
    if b_device < a.device {
        std::mem::swap(&mut b_device, &mut a.device);
    }
    f.store
        .route(&a.device, None, "FCM", "synthetic-private-coalesce-a")
        .await
        .unwrap();
    f.store
        .route(&b_device, None, "FCM", "synthetic-private-coalesce-b")
        .await
        .unwrap();
    let accepted = f
        .store
        .accept(a.request("private-coalesced-siblings"))
        .await
        .unwrap();
    f.store
        .update_route(&a.device, None, "PRIVATE", None)
        .await
        .unwrap();
    let old = f.claim(&a, "before-coalescing").await.pop().unwrap();
    let a_route = f.route(&a).await;
    f.store
        .route(&a.device, None, "FCM", "synthetic-private-coalesce-a")
        .await
        .unwrap();
    f.store
        .route(&b_device, None, "FCM", "synthetic-private-coalesce-a")
        .await
        .unwrap();
    f.store
        .update_route(&b_device, None, "PRIVATE", None)
        .await
        .unwrap();
    assert!(!f.store.private_authorize(&old).await.unwrap());
    assert!(!f.store.private_ack(&a_route, &old).await.unwrap());
    let b = Subject {
        device: b_device,
        channel: a.channel,
        password: a.password,
    };
    assert_eq!(f.scalar(&format!("SELECT COUNT(*) FROM targets WHERE delivery_id={} AND delivery_mode='private' AND acked_at IS NULL",lit(&accepted.delivery_id))).await,2);
    assert_eq!(f.pending(&b).await, 1);
    let t = f.claim(&b, "coalesced-logical").await;
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].delivery_id, accepted.delivery_id);
    assert_eq!(
        t[0].receipt_owner,
        std::cmp::min(a.device.clone(), b.device.clone())
    );
    assert_eq!(t[0].pull_owner, b.device);
    assert_ne!(
        t[0].receipt_owner, t[0].pull_owner,
        "frozen identity must survive ownership transfer"
    );
    assert!(f.claim(&b, "second-logical-session").await.is_empty());
    f.counters().await;
    assert!(
        f.store
            .private_ack(&f.route(&b).await, &t[0])
            .await
            .unwrap()
    );
    assert_eq!(f.pending(&b).await, 0);
    assert_eq!(f.payload_bytes(&accepted.delivery_id).await, 0);
    f.counters().await;
}

async fn expiry_same_timestamp_keyset(f: &mut Fixture) {
    // Four independent consumers stay below Small's 96/device limit while 260
    // messages share the same expiry. This crosses one 256-message batch without
    // increasing a product limit or allocating a capacity-test window.
    let mut config = f.store.config.clone();
    config.private.max_pending_per_device = 96;
    f.reopen(config).await;
    let ttl = now() + 120_000;
    let mut accepted = Vec::new();
    let mut requests = Vec::new();
    let mut claimed = Vec::new();
    for owner in 0..4 {
        let s = f.subject().await;
        for n in 0..65 {
            let mut req = s.request(&format!("private-expiry-{owner}-{n:02}"));
            req.ttl = Some(ttl);
            accepted.push(f.store.accept(req.clone()).await.unwrap());
            requests.push(req);
        }
        claimed.extend(f.claim(&s, &format!("expiry-owner-{owner}")).await);
        assert_eq!(f.pending(&s).await, 65);
    }
    assert_eq!(claimed.len(), 260);
    assert!(
        claimed
            .iter()
            .all(|t| t.expires_at == ttl && body(t)["ttl"] == ttl.to_string()),
        "all issued grants preserve the same absolute first TTL"
    );
    f.counters().await;
    let ids = accepted
        .iter()
        .map(|a| lit(&a.delivery_id))
        .collect::<Vec<_>>()
        .join(",");
    // Existing test convention: move the synthetic DB expiry clock, not a wall
    // clock sleep. Frozen payload and first accepted_at are left unchanged.
    f.exec(&format!(
        "UPDATE messages SET expires_at={} WHERE delivery_id IN ({ids})",
        now() - 1
    ))
    .await;
    let remaining =
        format!("SELECT COUNT(*) FROM messages WHERE delivery_id IN ({ids}) AND payload_bytes>0");
    let mut batches = Vec::new();
    for _ in 0..3 {
        let before = f.scalar(&remaining).await;
        if before == 0 {
            break;
        }
        f.store.maintenance().await.unwrap();
        let after = f.scalar(&remaining).await;
        assert!(before > after, "equal-expiry keyset must make progress");
        assert!(
            before - after <= 256,
            "one expiry batch must remain bounded"
        );
        batches.push(before - after);
    }
    assert_eq!(
        batches,
        vec![256, 4],
        "one captured keyset per call, then all equal-TTL rows must be visited"
    );
    assert_eq!(f.scalar(&remaining).await, 0);
    assert_eq!(
        f.scalar(&format!(
            "SELECT COUNT(*) FROM targets WHERE delivery_id IN ({ids})"
        ))
        .await,
        0
    );
    for t in &claimed {
        assert!(!f.store.private_authorize(t).await.unwrap());
    }
    assert_eq!(
        f.scalar("SELECT private_pending FROM ledger_usage WHERE singleton=1")
            .await,
        0
    );
    f.counters().await;
    f.reopen(f.store.config.clone()).await;
    // Replaying the identical operation cannot resurrect expired obligations or
    // replace identity, even after restart and both expiry batches.
    for (a, req) in accepted.iter().zip(requests) {
        same_identity(a, &f.store.accept(req).await.unwrap());
    }
    assert_eq!(f.scalar(&remaining).await, 0);
    f.counters().await;
    println!(
        "Private equal-TTL expiry: 260 identities, batches {batches:?}, zero retained targets, stable after restart"
    );
}
async fn migration_reserves_shared_live_budget(f: &mut Fixture) {
    let original = f.store.config.clone();
    let mut bounded = original.clone();
    bounded.max_messages = 1;
    f.reopen(bounded).await;
    let a = f.subject().await;
    f.store
        .update_route(
            &a.device,
            None,
            "FCM",
            Some("synthetic-c6-shared-budget-token"),
        )
        .await
        .unwrap();
    let accepted = f
        .store
        .accept(a.request("private-migration-budget-a"))
        .await
        .unwrap();
    let provider = f
        .store
        .claim("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    f.store
        .settle(&provider, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        f.scalar("SELECT messages FROM ledger_usage WHERE singleton=1")
            .await,
        0
    );
    assert!(f.payload_bytes(&accepted.delivery_id).await > 0);
    let before = f
        .store
        .register_device("android", Some(&a.device))
        .await
        .unwrap();
    let b = f.subject().await;
    let second = f
        .store
        .accept(b.request("private-migration-budget-b"))
        .await
        .unwrap();
    assert_eq!(
        f.scalar("SELECT messages FROM ledger_usage WHERE singleton=1")
            .await,
        1
    );
    assert!(matches!(
        f.store.update_route(&a.device, None, "PRIVATE", None).await,
        Err(KernelError::Capacity)
    ));
    assert_eq!(
        f.store
            .register_device("android", Some(&a.device))
            .await
            .unwrap(),
        before,
        "failed migration rolls back route revision and generation too"
    );
    assert_eq!(
        f.scalar("SELECT messages FROM ledger_usage WHERE singleton=1")
            .await,
        1
    );
    assert_eq!(f.scalar(&format!("SELECT COUNT(*) FROM targets WHERE delivery_id={} AND delivery_mode='provider' AND delivery_epoch=0",lit(&accepted.delivery_id))).await,1);
    assert!(
        !f.store
            .pull(&a.device, Some(&accepted.delivery_id))
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.store
            .ack(&a.device, vec![accepted.delivery_id])
            .await
            .unwrap(),
        1
    );
    let ticket = f.claim(&b, "shared-budget-release").await.pop().unwrap();
    assert_eq!(ticket.delivery_id, second.delivery_id);
    assert!(
        f.store
            .private_ack(&f.route(&b).await, &ticket)
            .await
            .unwrap()
    );
    f.counters().await;
    f.reopen(original).await;
}
/// Each backend runs the same full HTTP submission and durable replay oracle.
/// Reopening is an authority/database restart inside this test process, not an
/// operating-system client restart or a real TLS/MQTT network exchange.
async fn large_http_body_migration_replay(f: &mut Fixture) {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    use warp_link::warp_link_core::MAX_FRAME_BYTES;

    async fn submit(store: &OrdinaryStore, raw: &[u8]) -> Value {
        let app = crate::router(store.clone(), Arc::new(|| json!({})));
        let base = reqwest::Url::parse(&store.config.public_base_url).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{}/message", base.path().trim_end_matches('/')))
                    .header("content-type", "application/json")
                    .body(Body::from(raw.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let result: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        result["data"].clone()
    }

    for (index, kind) in [
        "text",
        "chinese",
        "escape",
        "numeric-metadata",
        "negative-metadata",
        "float-metadata",
    ]
    .into_iter()
    .enumerate()
    {
        let subject = f.subject().await;
        f.store
            .route(
                &subject.device,
                None,
                "FCM",
                &crate::types::generate_hex_id_128(),
            )
            .await
            .unwrap();
        let raw = crate::private_boundary_tests::legal_http_input(
            &subject.channel,
            &subject.password,
            kind,
        );
        // Distinct operations in one aggregate, preserving the exact input size
        // and the generator's raw numeric spellings before JSON normalization.
        let raw = String::from_utf8(raw)
            .unwrap()
            .replace(
                "private-wire-boundary",
                &format!("private-wire-boundar{index}"),
            )
            .into_bytes();
        assert_eq!(raw.len(), crate::MESSAGE_SUBMISSION_BODY_BYTES);
        let expected: Value = serde_json::from_slice(&raw).unwrap();
        let accepted = submit(&f.store, &raw).await;
        let id = accepted["delivery_id"].as_str().unwrap();
        let op = accepted["op_id"].as_str().unwrap();
        let status = f.store.status(op).await.unwrap();
        let pulled = f.store.pull(&subject.device, Some(id)).await.unwrap();
        assert_eq!(pulled["items"].as_array().unwrap().len(), 1);
        let provider_payload = pulled["items"][0]["payload"].clone();
        let expected_body = expected["body"].as_str().unwrap().trim();
        assert_eq!(
            provider_payload.get("body").and_then(Value::as_str),
            (!expected_body.is_empty()).then_some(expected_body)
        );
        assert!(f.payload_bytes(id).await > 0);
        let duplicate = submit(&f.store, &raw).await;
        for key in ["op_id", "message_id", "delivery_id"] {
            assert_eq!(duplicate[key], accepted[key]);
        }

        // No HTTP ACK: migration must retain this accepted Provider body and
        // frozen identity while transferring only its current consumption mode.
        f.store
            .update_route(&subject.device, None, "PRIVATE", None)
            .await
            .unwrap();
        f.http_cannot_consume(&subject, id).await;
        let first = f.claim(&subject, "large48-first").await.pop().unwrap();
        assert_eq!(first.delivery_id, id);
        assert_eq!(first.receipt_owner, subject.device);
        assert_eq!(first.pull_owner, subject.device);
        assert_eq!(first.accepted_at, status["accepted_at"].as_i64().unwrap());
        let canonical = body(&first);
        assert_eq!(canonical["delivery_id"], accepted["delivery_id"]);
        assert_eq!(canonical["message_id"], accepted["message_id"]);
        assert_eq!(
            first.expires_at,
            first.accepted_at + f.store.config.default_ttl_secs * 1000
        );
        assert!(
            canonical.get("ttl").is_none(),
            "omitted input TTL stays omitted on wire; absolute expiry remains in ledger"
        );
        for (key, value) in provider_payload.as_object().unwrap() {
            assert_eq!(&canonical[key], value, "migration changed {kind} {key}");
        }
        let payload = crate::private_runtime::encode_payload(&first.payload).unwrap();
        let frame = crate::private_boundary_tests::actual_deliver_frame(id, &payload);
        let decoded: pushgo_warp_profile::PrivatePayloadEnvelope =
            postcard::from_bytes(&payload).unwrap();
        assert_eq!(
            decoded.data.get("body").map(String::as_str),
            (!expected_body.is_empty()).then_some(expected_body)
        );
        if let Some(metadata) = expected.get("metadata") {
            assert_eq!(
                serde_json::from_str::<Value>(&decoded.data["metadata"]).unwrap(),
                *metadata
            );
        }
        assert_eq!(
            decoded.data["message_id"],
            accepted["message_id"].as_str().unwrap()
        );
        println!(
            "C8_SHARED_LARGE_FRAME {}",
            json!({"case":kind,"http_bytes":raw.len(),"input_blake3":blake3::hash(&raw).to_hex().to_string(),"canonical_bytes":first.payload.len(),"complete_frame_bytes":frame.len(),"fixed_frame_limit":MAX_FRAME_BYTES})
        );
        assert!(frame.len() <= MAX_FRAME_BYTES);
        let mqtt = crate::private_mqtt::encoded_delivery_packet_for_test(id, &payload).await;
        println!(
            "C8_SHARED_LARGE_MQTT case={kind} packet_bytes={} fixed_frame_limit={MAX_FRAME_BYTES}",
            mqtt.len()
        );
        assert!(mqtt.len() <= MAX_FRAME_BYTES);
        assert_eq!(
            f.store
                .private_release(&first.group_id, std::slice::from_ref(&first.claim_token))
                .await
                .unwrap(),
            1
        );
        assert!(!f.store.private_authorize(&first).await.unwrap());
        let abandoned = f
            .claim(&subject, "large48-before-reopen")
            .await
            .pop()
            .unwrap();
        assert_eq!(abandoned.payload, first.payload);
        f.reopen(f.store.config.clone()).await;
        assert!(!f.store.private_authorize(&abandoned).await.unwrap());
        let replay = f
            .claim(&subject, "large48-after-reopen")
            .await
            .pop()
            .unwrap();
        assert_eq!(replay.payload, first.payload);
        assert_eq!(
            (replay.accepted_at, replay.expires_at),
            (first.accepted_at, first.expires_at)
        );
        assert_eq!(
            (
                &replay.delivery_id,
                &replay.receipt_owner,
                &replay.pull_owner
            ),
            (&first.delivery_id, &first.receipt_owner, &first.pull_owner)
        );
        let after = f.store.status(op).await.unwrap();
        for key in ["accepted_at", "entity_id", "expires_at"] {
            assert_eq!(after[key], status[key]);
        }
        assert!(
            f.store
                .private_ack(&f.route(&subject).await, &replay)
                .await
                .unwrap()
        );
        assert!(
            !f.store
                .private_ack(&f.route(&subject).await, &replay)
                .await
                .unwrap()
        );
        assert_eq!(f.pending(&subject).await, 0);
        assert_eq!(f.payload_bytes(id).await, 0);
        let duplicate = submit(&f.store, &raw).await;
        for key in ["op_id", "message_id", "delivery_id"] {
            assert_eq!(duplicate[key], accepted[key]);
        }
        assert!(f.claim(&subject, "large48-after-ack").await.is_empty());
        assert!(
            f.scalar(&format!(
                "SELECT dedupe_until FROM messages WHERE delivery_id={}",
                lit(id)
            ))
            .await
                > now() + 29 * DAY
        );
        f.counters().await;
    }
}

/// Production Windows bootstraps through HTTP, without a preseeded device.
async fn windows_http_private_bootstrap(f: &mut Fixture) {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn post(store: &OrdinaryStore, path: &str, input: Value) -> (StatusCode, Value) {
        let app = crate::router(store.clone(), Arc::new(|| json!({})));
        let base = reqwest::Url::parse(&store.config.public_base_url).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{}{path}", base.path().trim_end_matches('/')))
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        (status, value)
    }
    let (status, registered) =
        post(&f.store, "/device/register", json!({"platform":"windows"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(registered["data"]["route"]["channel_type"], "private");
    let device = registered["data"]["device_key"]
        .as_str()
        .unwrap()
        .to_owned();
    // A newly registered NULL-provider route is already Private when enabled.
    let implicit = f.store.private_route(&device).await.unwrap();
    let (status, configured) = post(
        &f.store,
        "/channel/device",
        json!({"device_key":device,"platform":"windows","channel_type":"private"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(configured["data"]["channel_type"], "private");
    let route = f.store.private_route(&device).await.unwrap();
    assert_eq!(route.route_generation, implicit.route_generation);
    for provider in ["wns", "fcm", "apns"] {
        let (status, rejected) = post(&f.store, "/channel/device", json!({"device_key":device,"platform":"windows","channel_type":provider,"provider_token":"synthetic-windows-provider-token"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected["error_code"], "invalid_channel_type");
        assert_eq!(f.store.private_route(&device).await.unwrap(), route);
    }
    let (status, rejected) = post(&f.store, "/channel/device", json!({"device_key":device,"platform":"windows","channel_type":"private","provider_token":"forbidden-synthetic-token"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        rejected["error_code"],
        "provider_token_forbidden_for_private_channel"
    );
    assert_eq!(f.store.private_route(&device).await.unwrap(), route);
    let password = crate::types::generate_hex_id_128();
    let (status, subscribed) = post(
        &f.store,
        "/channel/subscribe",
        json!({"device_key":device,"channel_name":"Windows Private bootstrap","password":password}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let channel = subscribed["data"]["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let subject = Subject {
        device,
        channel,
        password,
    };
    let (status, accepted) = post(&f.store, "/message", json!({"channel_id":subject.channel,"password":subject.password,"title":"Windows Private","body":"native bootstrap retained body","op_id":"windows-private-http-bootstrap"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accepted["data"]["dispatch_status"], "attempted_accepted");
    let id = accepted["data"]["delivery_id"].as_str().unwrap();
    f.http_cannot_consume(&subject, id).await;
    let grants = f.claim(&subject, "windows-private-http").await;
    assert_eq!(grants.len(), 1);
    let ticket = &grants[0];
    assert_eq!(ticket.delivery_id, id);
    assert_eq!(body(ticket)["body"], "native bootstrap retained body");
    assert!(f.store.private_ack(&route, ticket).await.unwrap());
    assert_eq!(f.payload_bytes(id).await, 0);
    // Exit the subscription using the ordinary production control route.
    let (status, _) = post(
        &f.store,
        "/channel/unsubscribe",
        json!({"device_key":subject.device,"channel_id":subject.channel}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, deleted) = post(
        &f.store,
        "/channel/device/delete",
        json!({"device_key":subject.device,"channel_type":"private"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["data"]["channel_type"], "private");
    assert!(f.claim(&subject, "windows-after-exit").await.is_empty());
    assert_eq!(f.pending(&subject).await, 0);
    f.counters().await;
}

async fn run(mut f: Fixture) {
    windows_http_private_bootstrap(&mut f).await;
    large_http_body_migration_replay(&mut f).await;
    migration_reserves_shared_live_budget(&mut f).await;
    frozen_identity_capability_capacity(&mut f).await;
    disconnect_rollback_restart(&mut f).await;
    modes_and_frozen_provider_receipt(&mut f).await;
    unsubscribe_and_coalesced_siblings(&mut f).await;
    expiry_same_timestamp_keyset(&mut f).await;
    f.close().await;
}

#[tokio::test]
async fn sqlite_shared_private_ledger_contract() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}",
        dir.path().join("private-contract.sqlite").display()
    );
    run(Fixture::open(url, Some(dir)).await).await;
}
/// Explicit C7/C8/C9 test-only namespaces. Historical C6 receipt/path rules below are
/// unchanged. Ordinary factories retain their explicitly captured legacy base
/// names and existing per-invocation child CREATE/DROP behavior.
pub(crate) fn assigned_c7_native_url(
    key: &str,
    disposable: &str,
    mysql: bool,
    factory: bool,
) -> String {
    let c9 = key.starts_with("C9_");
    let c8 = key.starts_with("C8_");
    assert!(
        c9 || c8 || key.starts_with("C7_"),
        "explicit C7/C8/C9 key required"
    );
    if c9 {
        assert_eq!(
            key,
            if factory {
                "C9_TEST_URL_FILE"
            } else if mysql {
                "C9_PRIVATE_MYSQL_URL_FILE"
            } else {
                "C9_PRIVATE_PG_URL_FILE"
            }
        );
        assert_eq!(
            disposable,
            if factory {
                "C9_NATIVE_DISPOSABLE"
            } else {
                "C9_PRIVATE_DISPOSABLE"
            }
        );
    }
    assert_eq!(
        std::env::var(disposable).ok().as_deref(),
        Some("YES_NEW_SYNTHETIC"),
        "explicit C7 disposable prerequisite required"
    );
    let file = PathBuf::from(std::env::var(key).expect("explicit C7 assigned URL file required"))
        .canonicalize()
        .unwrap();
    let scope = PathBuf::from(if c9 {
        "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c9-idle-scaling-20261016/env"
    } else if c8 {
        "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c8-private48-20261015/env"
    } else {
        "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c7-private-frame64-20261015/env"
    })
    .canonicalize()
    .unwrap();
    assert_eq!(
        file.parent(),
        Some(scope.as_path()),
        "only the real C7 env root is supported"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600,
            "C7 URL file requires0600"
        );
    }
    let raw = std::fs::read_to_string(&file).unwrap();
    let url =
        reqwest::Url::parse(raw.trim()).unwrap_or_else(|_| panic!("invalid synthetic C7 URL"));
    assert!(if mysql {
        url.scheme() == "mysql"
    } else {
        matches!(url.scheme(), "postgres" | "postgresql")
    });
    assert!(url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }));
    assert!(url.query().is_none() && url.fragment().is_none());
    let db = url.path().trim_start_matches('/');
    assert!(
        db.starts_with(if factory {
            "c5_synthetic_"
        } else if c9 {
            "c9_synthetic_"
        } else if c8 {
            "c8_synthetic_"
        } else {
            "c7_synthetic_"
        }) && db
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let owned: Value = serde_json::from_slice(
        &std::fs::read(scope.join(if mysql {
            "mysql-owned.json"
        } else {
            "pg-owned.json"
        }))
        .unwrap(),
    )
    .unwrap();
    let case = &owned["cases"][db];
    assert_eq!(
        case["url_file"].as_str(),
        file.to_str(),
        "exact C7 captured case required"
    );
    if factory {
        assert_eq!(case["native_factory"], true);
        assert_eq!(case["legacy_fixture_name"], true);
    } else {
        assert_ne!(case["native_factory"], true);
    }
    let hex = |value: &str, length: usize| {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    assert!(
        hex(owned["id"].as_str().unwrap(), 64) && hex(owned["owner"].as_str().unwrap(), 32),
        "valid captured C7 owner identity required"
    );
    let endpoint = format!(
        "{}:{}",
        url.host_str().unwrap(),
        url.port().expect("captured explicit port required")
    );
    assert_eq!(owned["endpoint"].as_str(), Some(endpoint.as_str()));
    if c9 {
        // Formal C9 tests use a dedicated captured case role, never the
        // baseline's registry-wide role by accidental fallback.
        assert!(
            case["role"].as_str().is_some(),
            "C9 test case requires an explicit dedicated role"
        );
    }
    let role = case["role"]
        .as_str()
        .unwrap_or_else(|| owned["user"].as_str().unwrap());
    assert_eq!(
        url.username(),
        role,
        "URL role must match exact captured case role"
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(scope.join("active-case-manifest.json")).unwrap())
            .unwrap();
    let backend = if mysql { "mysql" } else { "postgres" };
    let matches = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["database"] == db && entry["backend"] == backend)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "one exact C7 allocation receipt required");
    let entry = matches[0];
    assert_eq!(entry["container_id"], owned["id"]);
    assert_eq!(entry["owner_uuid"], owned["owner"]);
    assert_eq!(entry["url_file"].as_str(), file.to_str());
    assert_eq!(entry["role"].as_str(), Some(role));
    assert_eq!(
        entry["environment_namespace"],
        if c9 {
            "C9/isolated"
        } else if c8 {
            "C8/isolated"
        } else {
            "C7/isolated"
        }
    );
    if c9 || c8 {
        assert_eq!(owned["engine_lease_only"], true);
        assert!(hex(owned["case_registry_owner"].as_str().unwrap(), 32));
        assert_eq!(entry["case_registry_owner"], owned["case_registry_owner"]);
        let parent_path = PathBuf::from(
            "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c7-private-frame64-20261015/env",
        )
        .join(if mysql { "mysql-owned.json" } else { "pg-owned.json" });
        assert_eq!(
            owned["engine_authority_source"].as_str(),
            parent_path.to_str()
        );
        assert_eq!(
            entry["engine_authority_source"].as_str(),
            parent_path.to_str()
        );
        let parent: Value = serde_json::from_slice(&std::fs::read(parent_path).unwrap()).unwrap();
        for field in ["id", "owner", "endpoint", "image"] {
            assert_eq!(
                owned[field], parent[field],
                "exact inherited engine authority required"
            );
        }
    }
    assert_eq!(entry["label"], case["label"]);
    assert_eq!(
        entry["environment_helper"].as_str(),
        scope.join("isolated_db.py").to_str()
    );
    assert_eq!(
        entry["captured_state"].as_str(),
        scope
            .join(if mysql {
                "mysql-owned.json"
            } else {
                "pg-owned.json"
            })
            .to_str()
    );
    assert_eq!(entry["native_factory"].as_bool().unwrap_or(false), factory);
    raw.trim().into()
}
fn assigned_native_url(key: &str, mysql: bool) -> String {
    let c9_key = key.replacen("C6_", "C9_", 1);
    if std::env::var_os(&c9_key).is_some() {
        return assigned_c7_native_url(&c9_key, "C9_PRIVATE_DISPOSABLE", mysql, false);
    }
    let c8_key = key.replacen("C6_", "C8_", 1);
    if std::env::var_os(&c8_key).is_some() {
        return assigned_c7_native_url(&c8_key, "C8_PRIVATE_DISPOSABLE", mysql, false);
    }
    let c7_key = key.replacen("C6_", "C7_", 1);
    if std::env::var_os(&c7_key).is_some() {
        return assigned_c7_native_url(&c7_key, "C7_PRIVATE_DISPOSABLE", mysql, false);
    }
    assert_eq!(
        std::env::var("C6_PRIVATE_DISPOSABLE").ok().as_deref(),
        Some("YES_NEW_SYNTHETIC"),
        "explicit Private native disposable prerequisite required"
    );
    let file = PathBuf::from(
        std::env::var(key).expect("environment-owner assigned NEW EMPTY C6 URL file required"),
    )
    .canonicalize()
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let scope = file.parent().unwrap();
    let env = if scope.file_name().unwrap() == "fresh2" {
        assert!(
            mysql,
            "only the explicitly rotated MySQL environment uses fresh2"
        );
        scope.parent().unwrap()
    } else {
        scope
    };
    assert_eq!(env.file_name().unwrap(), "env");
    assert!(
        env.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("c6-private-capacity-")
    );
    let raw = std::fs::read_to_string(&file).unwrap();
    let url =
        reqwest::Url::parse(raw.trim()).unwrap_or_else(|_| panic!("invalid synthetic native URL"));
    assert!(if mysql {
        url.scheme() == "mysql"
    } else {
        matches!(url.scheme(), "postgres" | "postgresql")
    });
    assert!(url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }));
    assert!(url.query().is_none() && url.fragment().is_none());
    let db = url.path().trim_start_matches('/');
    assert!(
        db.starts_with("c6_synthetic_")
            && db
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let owned: Value = serde_json::from_slice(
        &std::fs::read(scope.join(if mysql {
            "mysql-owned.json"
        } else {
            "pg-owned.json"
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        owned["cases"][db]["url_file"].as_str(),
        file.to_str(),
        "only exact environment-owner assigned C6 case allowed"
    );
    raw.trim().into()
}
pub(crate) async fn assert_empty_native_url(url: &str, mysql: bool) {
    let tables: i64 = if mysql {
        let mut c = MySqlConnection::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("synthetic MySQL unavailable"));
        let n = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE()",
        )
        .fetch_one(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
        n
    } else {
        let mut c = PgConnection::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("synthetic PostgreSQL unavailable"));
        let n=sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema')").fetch_one(&mut c).await.unwrap();
        c.close().await.unwrap();
        n
    };
    assert_eq!(
        tables, 0,
        "NEW EMPTY assigned case required; never reset previous failed evidence"
    );
}
async fn new_native_fixture(key: &str, mysql: bool) -> Fixture {
    let url = assigned_native_url(key, mysql);
    assert_empty_native_url(&url, mysql).await;
    Fixture::open(url, None).await
}
#[tokio::test]
#[ignore = "requires C6_PRIVATE_PG_URL_FILE/C6_PRIVATE_DISPOSABLE or C7_PRIVATE_PG_URL_FILE/C7_PRIVATE_DISPOSABLE or C8_PRIVATE_PG_URL_FILE/C8_PRIVATE_DISPOSABLE or C9_PRIVATE_PG_URL_FILE/C9_PRIVATE_DISPOSABLE=YES_NEW_SYNTHETIC owned NEW EMPTY case, schema/function/trigger privileges"]
async fn postgres_shared_private_ledger_contract() {
    run(new_native_fixture("C6_PRIVATE_PG_URL_FILE", false).await).await;
}
#[tokio::test]
#[ignore = "requires C6_PRIVATE_MYSQL_URL_FILE/C6_PRIVATE_DISPOSABLE or C7_PRIVATE_MYSQL_URL_FILE/C7_PRIVATE_DISPOSABLE or C8_PRIVATE_MYSQL_URL_FILE/C8_PRIVATE_DISPOSABLE or C9_PRIVATE_MYSQL_URL_FILE/C9_PRIVATE_DISPOSABLE=YES_NEW_SYNTHETIC owned NEW EMPTY case, CREATE TRIGGER and recorded trust-function prerequisite"]
async fn mysql_shared_private_ledger_contract() {
    run(new_native_fixture("C6_PRIVATE_MYSQL_URL_FILE", true).await).await;
}
