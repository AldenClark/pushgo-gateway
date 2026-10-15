//! Executed only against a newly created, explicitly opted-in synthetic MySQL DB.
use super::*;
use sqlx::{MySqlConnection, Row};

struct MySqlSandbox {
    base: reqwest::Url,
    created: std::sync::Mutex<Vec<String>>,
}
impl MySqlSandbox {
    fn guarded() -> Self {
        assert_eq!(
            std::env::var("C5_MYSQL_DISPOSABLE").ok().as_deref(),
            Some("YES_NEW_SYNTHETIC"),
            "explicit C5_MYSQL_DISPOSABLE prerequisite missing"
        );
        let raw = std::env::var("C5_MYSQL_TEST_URL")
            .expect("explicit C5_MYSQL_TEST_URL prerequisite missing");
        let base =
            reqwest::Url::parse(&raw).unwrap_or_else(|_| panic!("invalid synthetic MySQL URL"));
        assert_eq!(base.scheme(), "mysql");
        assert!(
            base.host_str().is_some_and(|h| h == "localhost"
                || h.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
            "loopback MySQL required"
        );
        let name = base.path().trim_start_matches('/');
        assert!(
            name.starts_with("c5_synthetic_")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "new c5_synthetic database prerequisite required"
        );
        assert!(
            base.query().is_none() && base.fragment().is_none(),
            "synthetic URL cannot override connection host"
        );
        Self {
            base,
            created: std::sync::Mutex::new(Vec::new()),
        }
    }
    async fn admin(&self) -> MySqlConnection {
        MySqlConnection::connect(self.base.as_str())
            .await
            .unwrap_or_else(|_| panic!("synthetic MySQL prerequisite unavailable"))
    }
    async fn fixture(&self, config: Config) -> Fixture {
        let name = format!("c5_synthetic_case_{}", crate::types::generate_hex_id_128());
        let mut admin = self.admin().await;
        sqlx::raw_sql(&format!(
            "CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
        ))
        .execute(&mut admin)
        .await
        .expect("new synthetic MySQL database CREATE prerequisite");
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
            sqlx::raw_sql(&format!("DROP DATABASE `{name}`"))
                .execute(&mut admin)
                .await
                .expect("cleanup only this invocation's successfully created synthetic database");
        }
        admin.close().await.ok();
    }
}

#[tokio::test]
#[ignore = "requires disposable loopback MySQL C5_MYSQL_TEST_URL and C5_MYSQL_DISPOSABLE=YES_NEW_SYNTHETIC; creates new c5_synthetic databases"]
async fn mysql_shared_ordinary_contract_and_native_failures() {
    let sandbox = MySqlSandbox::guarded();
    let result = AssertUnwindSafe(async {
        run_oracles(|config| sandbox.fixture(config)).await;
        let f = sandbox.fixture(Config::default()).await;
        mysql_due_index_repair_recovery(f).await;
        let mut f = sandbox.fixture(Config::default()).await;
        mysql_transaction_failures(&mut f).await;
        mysql_native_plans(&f).await;
        mysql_owner_session_loss(&mut f).await;
        f.close().await;
        for acked_running in [true, false] {
            let mut f = sandbox.fixture(Config::default()).await;
            mysql_late_reconcile_rollback(&mut f, acked_running).await;
            f.close().await;
        }
        let f = sandbox.fixture(Config::default()).await;
        tokio::time::timeout(Duration::from_secs(15), mysql_runtime_backpressure(f))
            .await
            .expect("MySQL H32 real rowlock scenario exceeded 15 seconds");
        let f = sandbox.fixture(Config::default()).await;
        tokio::time::timeout(Duration::from_secs(15), mysql_runtime_shutdown_recovery(f))
            .await
            .expect("MySQL cancellation/shutdown scenario exceeded 15 seconds");
    })
    .catch_unwind()
    .await;
    sandbox.cleanup().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

// Observe committed data through a physically independent native connection,
// rather than returning the transaction owner's own provisional values.
async fn late_reconcile_snapshot(c: &mut MySqlConnection) -> Value {
    let raw = sqlx::query("SELECT JSON_OBJECT('delivery_id',m.delivery_id,'message_id',m.message_id,'op_id',m.op_id,'accepted_at',m.accepted_at,'expires_at',m.expires_at,'dedupe_until',m.dedupe_until,'fingerprint',m.fingerprint,'payload_hex',HEX(m.payload_blob),'payload_bytes',m.payload_bytes,'usage_payload_bytes',m.usage_payload_bytes,'pending_targets',m.pending_targets,'status',m.status,'updated_at',m.updated_at,'provider_accepted_count',m.provider_accepted_count,'provider_failed_count',m.provider_failed_count,'provider_target_count',m.provider_target_count,'private_enqueued_count',m.private_enqueued_count,'device_key',t.device_key,'pull_owner',t.pull_owner,'owner_generation',t.owner_generation,'control_epoch',t.control_epoch,'route_generation',t.route_generation,'state',t.state,'attempt_id',t.attempt_id,'attempts',t.attempts,'acked_at',t.acked_at,'provider_status',t.provider_status,'provider_error',t.provider_error,'receipt_at',t.receipt_at,'next_attempt_at',t.next_attempt_at,'usage_messages',u.messages,'usage_targets',u.targets,'usage_bytes',u.bytes,'private_pending',u.private_pending) FROM messages m LEFT JOIN targets t ON t.delivery_id=m.delivery_id CROSS JOIN ledger_usage u WHERE m.op_id='c6-late-reconcile' AND u.singleton=1")
        .fetch_one(c).await.unwrap().get_unchecked::<String,_>(0);
    serde_json::from_str(&raw).unwrap()
}

async fn mysql_late_reconcile_rollback(f: &mut Fixture, acked_running: bool) {
    let mut request = f.request("c6-late-reconcile");
    request.ttl = Some(now() + 300_000);
    let accepted = f.store.accept(request.clone()).await.unwrap();
    let ticket = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    if acked_running {
        assert_eq!(
            f.store
                .ack(&f.device, vec![accepted.delivery_id.clone()])
                .await
                .unwrap(),
            1
        );
    }
    let mut observer = MySqlConnection::connect(&f.url).await.unwrap();
    sqlx::raw_sql("SET SESSION MAX_EXECUTION_TIME=2000; SET SESSION innodb_lock_wait_timeout=3; SET SESSION lock_wait_timeout=3").execute(&mut observer).await.unwrap();
    let before = late_reconcile_snapshot(&mut observer).await;
    assert_eq!(before["state"], "running");
    assert_eq!(before["provider_accepted_count"], 0);
    if acked_running {
        // Real ACK already released the last body's bytes; only its owned
        // frozen running receipt survives. Do not invent a >0 ->0 byte change.
        assert!(!before["acked_at"].is_null());
        assert_eq!(before["payload_bytes"], 0);
        assert_eq!(before["usage_bytes"], 0);
    } else {
        assert!(before["acked_at"].is_null());
        assert!(before["payload_bytes"].as_i64().unwrap() > 0);
        assert_eq!(before["usage_targets"], 1);
    }
    let predicate = if acked_running {
        // Absence of this frozen row proves release DELETE has already run.
        "NEW.bytes=0 AND NOT EXISTS(SELECT 1 FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE m.op_id='c6-late-reconcile')"
    } else {
        "OLD.targets>0 AND NEW.targets=0"
    };
    let trigger = format!(
        "CREATE TRIGGER c6_late_reconcile BEFORE UPDATE ON ledger_usage FOR EACH ROW BEGIN IF ({predicate}) AND EXISTS(SELECT 1 FROM messages WHERE op_id='c6-late-reconcile' AND provider_accepted_count=1) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic late receipt reconcile'; END IF; END"
    );
    sqlx::raw_sql(&trigger)
        .execute(&mut observer)
        .await
        .unwrap();
    let error = f
        .store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap_err();
    match error {
        KernelError::Database(error) => {
            assert_eq!(mysql_code(&error).as_deref(), Some("1644"));
            assert!(
                error
                    .to_string()
                    .contains("synthetic late receipt reconcile")
            );
        }
        other => panic!("expected native late-reconcile fault, got {other}"),
    }
    // Drain SQLx's queued whole-transaction rollback before external DDL; this
    // is not a retry of settle and cannot fabricate a Provider result.
    {
        let mysql = f.store.mysql_store().unwrap();
        drop(mysql.acquire().await.unwrap());
    }
    assert_eq!(
        late_reconcile_snapshot(&mut observer).await,
        before,
        "native late fault must roll back target DELETE/state, body, Sender counts/status, frozen history and all usage"
    );
    sqlx::raw_sql("DROP TRIGGER c6_late_reconcile")
        .execute(&mut observer)
        .await
        .unwrap();
    // Replay only the already-known database receipt, never the external send.
    f.store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    f.store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    let after = late_reconcile_snapshot(&mut observer).await;
    for key in [
        "delivery_id",
        "message_id",
        "op_id",
        "accepted_at",
        "expires_at",
        "dedupe_until",
        "fingerprint",
        "provider_target_count",
        "private_enqueued_count",
    ] {
        assert_eq!(after[key], before[key], "first acceptance {key}");
    }
    assert_eq!(
        after["provider_accepted_count"], 1,
        "same frozen receipt is counted once"
    );
    assert_eq!(after["provider_failed_count"], 0);
    assert_eq!(after["usage_messages"], 0);
    assert_eq!(after["usage_targets"], 0);
    assert_eq!(after["private_pending"], 0);
    assert_eq!(after["status"], "sent");
    if acked_running {
        assert!(after["device_key"].is_null());
        assert_eq!(after["usage_bytes"], 0);
    } else {
        assert_eq!(after["state"], "provider_accepted");
        assert!(after["acked_at"].is_null());
        assert_eq!(after["payload_hex"], before["payload_hex"]);
        assert_eq!(after["usage_bytes"], before["usage_bytes"]);
        assert_eq!(
            f.store
                .ack(&f.device, vec![accepted.delivery_id.clone()])
                .await
                .unwrap(),
            1
        );
    }
    let replay = f.store.accept(request).await.unwrap();
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert_eq!(replay.message_id, accepted.message_id);
    let final_state = late_reconcile_snapshot(&mut observer).await;
    assert_eq!(final_state["usage_bytes"], 0);
    assert_eq!(final_state["provider_accepted_count"], 1);
    assert!(final_state["device_key"].is_null());
    f.usage().await;
    observer.close().await.unwrap();
    println!(
        "MySQL late reconcile rollback: acked_running={acked_running}, native1644, full independent snapshot restored, same-ticket SQL replay counted once"
    );
}

async fn mysql_due_index_repair_recovery(mut f: Fixture) {
    f.store
        .retire_provider_token("android", "synthetic-index-epoch-unused")
        .await
        .unwrap();
    let mut request = f.request("mysql-index-repair-identity");
    request.ttl = Some(now() + 300_000);
    let accepted = f.store.accept(request.clone()).await.unwrap();
    let old_ticket = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    let first_ttl = old_ticket.expires_at;
    let first_epoch = f
        .scalar("SELECT control_epoch FROM ledger_usage WHERE singleton=1")
        .await;
    assert!(first_epoch > 0);
    let first_target_epoch = f.scalar("SELECT control_epoch FROM targets").await;
    assert_eq!(first_epoch, first_target_epoch);
    assert!(f.store.authorize_ticket(&old_ticket).await.unwrap());
    f.close().await;
    let mut admin = MySqlConnection::connect(&f.url).await.unwrap();

    // An unknown signature fails closed before running-job recovery. It must
    // not be guessed into a known index or erase an accepted capability.
    sqlx::raw_sql("ALTER TABLE targets DROP INDEX targets_due, ADD INDEX targets_due(provider,state,next_attempt_at)").execute(&mut admin).await.unwrap();
    let failed = OrdinaryStore::open(&f.url, f.store.config.clone()).await;
    assert!(
        matches!(failed,Err(KernelError::Invalid(ref message)) if message=="unsupported MySQL targets_due definition")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        1
    );

    sqlx::raw_sql("ALTER TABLE targets DROP INDEX targets_due, ADD INDEX targets_due(provider,state,next_attempt_at,delivery_id)").execute(&mut admin).await.unwrap();
    // A real metadata reader blocks startup DDL. No READY handle or
    // recovery writes may escape this failed open, and no retry is hidden.
    sqlx::raw_sql("BEGIN; SELECT delivery_id FROM targets LIMIT 1")
        .execute(&mut admin)
        .await
        .unwrap();
    let failed = tokio::time::timeout(
        Duration::from_secs(5),
        OrdinaryStore::open(&f.url, f.store.config.clone()),
    )
    .await
    .expect("metadata lock timeout must remain bounded");
    assert!(
        matches!(&failed,Err(KernelError::Database(error)) if mysql_code(error).as_deref()==Some("1205")),
        "index repair must preserve native metadata-lock failure"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE state='running'")
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE op_id='mysql-index-repair-identity'"
        )
        .fetch_one(&mut admin)
        .await
        .unwrap(),
        1
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut admin).await.unwrap();

    let (store, owner) = OrdinaryStore::open(&f.url, f.store.config.clone())
        .await
        .unwrap();
    f.store = store;
    f.owner = Some(owner);
    let signature:Vec<String>=sqlx::query_scalar("SELECT CAST(COLUMN_NAME AS CHAR CHARACTER SET utf8mb4) FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='targets' AND INDEX_NAME='targets_due' ORDER BY SEQ_IN_INDEX LIMIT 6").fetch_all(&mut admin).await.unwrap();
    assert_eq!(
        signature,
        [
            "provider",
            "state",
            "next_attempt_at",
            "delivery_id",
            "device_key"
        ]
    );
    let replay = f.store.accept(request).await.unwrap();
    assert_eq!(
        (
            replay.delivery_id.as_str(),
            replay.message_id.as_str(),
            replay.op_id.as_str()
        ),
        (
            accepted.delivery_id.as_str(),
            accepted.message_id.as_str(),
            accepted.op_id.as_str()
        )
    );
    assert_eq!(replay.acceptance, "duplicate_completed");
    assert_eq!(
        f.scalar("SELECT control_epoch FROM ledger_usage WHERE singleton=1")
            .await,
        first_epoch
    );
    assert_eq!(
        f.scalar("SELECT control_epoch FROM targets").await,
        first_target_epoch
    );
    assert_eq!(
        f.scalar("SELECT expires_at FROM messages WHERE op_id='mysql-index-repair-identity'")
            .await,
        first_ttl
    );
    assert!(!f.store.authorize_ticket(&old_ticket).await.unwrap());
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&accepted.delivery_id))
                .await
                .unwrap()
        ),
        1
    );
    let ticket = f
        .store
        .claim_reserved("FCM", 1, true)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    assert_eq!(ticket.expires_at, first_ttl);
    assert_eq!(ticket.route_generation, old_ticket.route_generation);
    assert!(ticket.attempt_id > old_ticket.attempt_id);
    assert!(f.store.authorize_ticket(&ticket).await.unwrap());
    f.store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .ack(&f.device, vec![accepted.delivery_id])
            .await
            .unwrap(),
        1
    );
    f.usage().await;
    f.close().await;
    admin.close().await.ok();
}

fn mysql_code(error: &sqlx::Error) -> Option<String> {
    // DatabaseError::code() is SQLSTATE for SQLx/MySQL, not errno 1213/1205.
    error
        .as_database_error()
        .and_then(|e| e.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .map(|e| e.number().to_string())
}

async fn mysql_transaction_failures(f: &mut Fixture) {
    // The pinned owner keeps this physical connection through every rollback.
    let owner_connection_id: u64 = {
        let mysql = f.store.mysql_store().unwrap();
        let mut c = mysql.acquire().await.unwrap();
        sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *c)
            .await
            .unwrap()
    };
    // Native 1062 rolls back a transaction that has already changed a row.
    let mut a = MySqlConnection::connect(&f.url).await.unwrap();
    sqlx::raw_sql("CREATE TABLE c5_transaction_probe(id BIGINT PRIMARY KEY,value BIGINT NOT NULL) ENGINE=InnoDB; INSERT INTO c5_transaction_probe VALUES(1,0),(2,0)").execute(&mut a).await.unwrap();
    sqlx::raw_sql("BEGIN; UPDATE c5_transaction_probe SET value=7 WHERE id=1")
        .execute(&mut a)
        .await
        .unwrap();
    let duplicate = sqlx::query("INSERT INTO c5_transaction_probe VALUES(1,9)")
        .execute(&mut a)
        .await
        .unwrap_err();
    assert_eq!(mysql_code(&duplicate).as_deref(), Some("1062"));
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT value FROM c5_transaction_probe WHERE id=1")
            .fetch_one(&mut a)
            .await
            .unwrap(),
        0
    );

    // Prove real InnoDB 1213 with a two-session lock cycle. A large undo
    // footprint makes b the victim; accept either victim rather than depending
    // on a particular engine deadlock-victim heuristic.
    let mut b = MySqlConnection::connect(&f.url).await.unwrap();
    sqlx::raw_sql("SET SESSION innodb_lock_wait_timeout=3; BEGIN; UPDATE c5_transaction_probe SET value=1 WHERE id=1").execute(&mut a).await.unwrap();
    sqlx::raw_sql("SET SESSION innodb_lock_wait_timeout=3; BEGIN; UPDATE c5_transaction_probe SET value=2 WHERE id=2").execute(&mut b).await.unwrap();
    let (ra, rb) = tokio::join!(
        sqlx::query("UPDATE c5_transaction_probe SET value=3 WHERE id=2").execute(&mut a),
        sqlx::query("UPDATE c5_transaction_probe SET value=4 WHERE id=1").execute(&mut b)
    );
    let codes: Vec<String> = [&ra, &rb]
        .into_iter()
        .filter_map(|r| r.as_ref().err())
        .filter_map(mysql_code)
        .collect();
    assert!(
        codes.iter().any(|c| c == "1213"),
        "native deadlock must emit 1213, observed {codes:?}"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();
    sqlx::raw_sql("ROLLBACK").execute(&mut b).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT CAST(SUM(value) AS SIGNED) FROM c5_transaction_probe")
            .fetch_one(&mut a)
            .await
            .unwrap(),
        0
    );

    // A native uniqueness failure after ordinary message insertion must undo
    // its identity, target fanout and usage updates as one transaction.
    sqlx::raw_sql("CREATE TRIGGER c5_accept_unique AFTER INSERT ON messages FOR EACH ROW INSERT INTO c5_transaction_probe VALUES(1,99)").execute(&mut a).await.unwrap();
    let unique = f
        .store
        .accept(f.request("mysql-unique-whole-accept"))
        .await
        .unwrap_err();
    assert!(
        matches!(&unique, KernelError::Database(error) if mysql_code(error).as_deref()==Some("1062")),
        "ordinary accept must preserve native duplicate receipt: {unique}"
    );
    // Drain the queued SQLx rollback before DDL requests a metadata lock.
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 0);
    sqlx::raw_sql("DROP TRIGGER c5_accept_unique")
        .execute(&mut a)
        .await
        .unwrap();
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 0);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets").await, 0);
    f.usage().await;

    // Deadlock after message INSERT: retain far more undo in the independent
    // blocker than the accept, making accept the engine's smaller victim.
    for id in 3..=130 {
        sqlx::query("INSERT INTO c5_transaction_probe VALUES(?,0)")
            .bind(id)
            .execute(&mut a)
            .await
            .unwrap();
    }
    sqlx::raw_sql("CREATE TRIGGER c5_accept_deadlock AFTER INSERT ON messages FOR EACH ROW BEGIN UPDATE c5_transaction_probe SET value=value+1 WHERE id=1; UPDATE c5_transaction_probe SET value=value+1 WHERE id=2; END; BEGIN; UPDATE c5_transaction_probe SET value=100 WHERE id>=2").execute(&mut a).await.unwrap();
    let store = f.store.clone();
    let request = f.request("mysql-deadlock-whole-accept");
    let mut accepting = tokio::spawn(async move { store.accept(request).await });
    wait_for_native_row_wait(&mut b, owner_connection_id, &mut accepting).await;
    sqlx::query("UPDATE c5_transaction_probe SET value=101 WHERE id=1")
        .execute(&mut a)
        .await
        .expect("larger blocker must survive native deadlock selection");
    let deadlock = accepting.await.unwrap().unwrap_err();
    assert!(
        matches!(&deadlock, KernelError::Database(error) if mysql_code(error).as_deref()==Some("1213")),
        "ordinary accept must preserve native 1213 receipt: {deadlock}"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();
    // Release row locks, then drain queued rollback before trigger DDL.
    let _ = f.scalar("SELECT COUNT(*) FROM messages").await;
    sqlx::raw_sql("DROP TRIGGER c5_accept_deadlock")
        .execute(&mut a)
        .await
        .unwrap();
    assert_eq!(f.scalar("SELECT COUNT(*) FROM messages").await, 0);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets").await, 0);
    f.usage().await;

    let rollback_on_timeout: i64 =
        sqlx::query_scalar("SELECT CAST(@@GLOBAL.innodb_rollback_on_timeout AS SIGNED)")
            .fetch_one(&mut a)
            .await
            .unwrap();
    assert_eq!(
        rollback_on_timeout, 0,
        "this oracle requires statement-only native timeout rollback"
    );
    {
        let mysql = f.store.mysql_store().unwrap();
        let mut c = mysql.acquire().await.unwrap();
        sqlx::raw_sql("SET SESSION innodb_lock_wait_timeout=1")
            .execute(&mut *c)
            .await
            .unwrap();
    }
    // Native 1205 by itself leaves earlier writes in the transaction intact.
    sqlx::raw_sql("BEGIN; UPDATE c5_transaction_probe SET value=8 WHERE id=1")
        .execute(&mut a)
        .await
        .unwrap();
    sqlx::raw_sql("SET SESSION innodb_lock_wait_timeout=1; BEGIN; UPDATE c5_transaction_probe SET value=9 WHERE id=2").execute(&mut b).await.unwrap();
    let timeout = sqlx::query("UPDATE c5_transaction_probe SET value=10 WHERE id=1")
        .execute(&mut b)
        .await
        .unwrap_err();
    assert_eq!(mysql_code(&timeout).as_deref(), Some("1205"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT value FROM c5_transaction_probe WHERE id=2")
            .fetch_one(&mut b)
            .await
            .unwrap(),
        9
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut b).await.unwrap();
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();

    // Force accept to fail after its message insert: a trigger requests a real
    // locked probe row from the pinned owner's transaction. All ordinary writes
    // and usage mutations must roll back, even with rollback_on_timeout=OFF.
    sqlx::raw_sql("CREATE TRIGGER c5_accept_timeout AFTER INSERT ON messages FOR EACH ROW UPDATE c5_transaction_probe SET value=value+1 WHERE id=1; BEGIN; UPDATE c5_transaction_probe SET value=11 WHERE id=1").execute(&mut a).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        f.store.accept(f.request("mysql-timeout-whole-accept")),
    )
    .await
    .expect("native lock timeout must remain bounded");
    let timeout = result.unwrap_err();
    assert!(
        matches!(&timeout, KernelError::Database(error) if mysql_code(error).as_deref()==Some("1205")),
        "ordinary accept must preserve native1205 receipt: {timeout}"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();
    // Release row locks, then drain queued rollback before trigger DDL.
    let _ = f.scalar("SELECT COUNT(*) FROM messages").await;
    sqlx::raw_sql("DROP TRIGGER c5_accept_timeout")
        .execute(&mut a)
        .await
        .unwrap();
    // acquire() also drains any pending explicit rollback after cancellation.
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM messages WHERE op_id='mysql-timeout-whole-accept'")
            .await,
        0
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM targets").await, 0);
    f.usage().await;
    let accepted = f
        .store
        .accept(f.request("mysql-after-timeout"))
        .await
        .unwrap();
    assert_eq!(
        items(
            &f.store
                .pull(&f.device, Some(&accepted.delivery_id))
                .await
                .unwrap()
        ),
        1
    );

    // Cancellation while real SQL is blocked must also leave no partial insert.
    sqlx::raw_sql("CREATE TRIGGER c5_accept_cancel AFTER INSERT ON messages FOR EACH ROW UPDATE c5_transaction_probe SET value=value+1 WHERE id=1; BEGIN; UPDATE c5_transaction_probe SET value=12 WHERE id=1").execute(&mut a).await.unwrap();
    let store = f.store.clone();
    let request = f.request("mysql-cancel-whole-accept");
    let mut task = tokio::spawn(async move { store.accept(request).await });
    wait_for_native_row_wait(&mut b, owner_connection_id, &mut task).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    sqlx::raw_sql("ROLLBACK").execute(&mut a).await.unwrap();
    // Release row locks, then drain queued rollback before trigger DDL.
    let _ = f.scalar("SELECT COUNT(*) FROM messages").await;
    sqlx::raw_sql("DROP TRIGGER c5_accept_cancel")
        .execute(&mut a)
        .await
        .unwrap();
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM messages WHERE op_id='mysql-cancel-whole-accept'")
            .await,
        0
    );
    f.usage().await;
    sqlx::raw_sql("DROP TABLE c5_transaction_probe")
        .execute(&mut a)
        .await
        .unwrap();
    a.close().await.ok();
    b.close().await.ok();
}

async fn wait_for_native_row_wait<T: std::fmt::Debug>(
    c: &mut MySqlConnection,
    owner_connection_id: u64,
    task: &mut tokio::task::JoinHandle<T>,
) {
    // This oracle does not depend on performance_schema instrumentation. InnoDB
    // still exposes its native lock waiter through INNODB_TRX with PROCESS.
    // Bind the exact pinned owner: another session's wait is not our oracle.
    // MySQL 8.4.11 trx0i_s.cc refreshes only after >100ms without reads;
    // each read resets last_read. A 5ms poll pins the first empty snapshot.
    // Poll every 150ms while preserving the same two-second observation bound.
    let observation = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id=? AND trx_state='LOCK WAIT' AND trx_requested_lock_id IS NOT NULL")
                .bind(owner_connection_id).fetch_one(&mut *c).await.unwrap();
            if n > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });
    tokio::select! {
        result = task => panic!("fault-injected accept completed before native wait observation: {result:?}"),
        result = observation => result.expect("exact pinned owner's real InnoDB row wait must become observable"),
    }
}

async fn mysql_owner_session_loss(f: &mut Fixture) {
    let mut alias = reqwest::Url::parse(&f.url).unwrap();
    alias.set_host(Some("localhost")).unwrap();
    let mut parameters = reqwest::Url::parse(&f.url).unwrap();
    parameters.set_query(Some("charset=utf8mb4"));
    for url in [&f.url, alias.as_str(), parameters.as_str()] {
        assert!(
            matches!(
                OrdinaryStore::open(url, Config::default()).await,
                Err(KernelError::OwnerContention)
            ),
            "same database owner exclusion must survive URL spelling"
        );
    }
    let accepted = f
        .store
        .accept(f.request("mysql-before-session-loss"))
        .await
        .unwrap();
    let mysql = f.store.mysql_store().unwrap();
    let id: u64 = {
        let mut c = mysql.acquire().await.unwrap();
        sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *c)
            .await
            .unwrap()
    };
    let mut admin = MySqlConnection::connect(&f.url).await.unwrap();
    let uuid: String =
        sqlx::query_scalar("SELECT CAST(dataset_uuid AS CHAR CHARACTER SET utf8mb4) FROM authority_metadata WHERE singleton=1")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    let lock_name = format!("pushgo-c-dataset-{uuid}");
    assert_eq!(
        sqlx::query_scalar::<_, Option<u64>>("SELECT IS_USED_LOCK(?)")
            .bind(&lock_name)
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        Some(id)
    );
    sqlx::raw_sql(&format!("KILL CONNECTION {id}"))
        .execute(&mut admin)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK(?,2)")
            .bind(&lock_name)
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>("SELECT RELEASE_LOCK(?)")
            .bind(&lock_name)
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        Some(1)
    );
    // Native owner session is gone while the local dataset UUID OS fence lives.
    assert!(f.owner.is_some());
    for url in [&f.url, alias.as_str(), parameters.as_str()] {
        assert!(matches!(
            OrdinaryStore::open(url, Config::default()).await,
            Err(KernelError::OwnerContention)
        ));
    }
    for _ in 0..2 {
        assert!(
            f.store
                .accept(f.request("mysql-session-rejected"))
                .await
                .is_err()
        );
    }
    f.reopen().await;
    assert!(matches!(
        f.store.status("mysql-session-rejected").await,
        Err(KernelError::NotFound)
    ));
    assert_eq!(
        f.store
            .accept(f.request("mysql-before-session-loss"))
            .await
            .unwrap()
            .delivery_id,
        accepted.delivery_id
    );
    f.usage().await;
    admin.close().await.ok();
}

async fn mysql_native_plans(f: &Fixture) {
    let mysql = f.store.mysql_store().unwrap();
    let mut c = mysql.acquire().await.unwrap();
    let mut plans = serde_json::Map::new();
    // EXPLAIN the exact production statements with bound values. Tiny fixture
    // optimizer choices are emitted; readiness is checked independently below.
    let at = now();
    let pull: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::PULL_BATCH_SQL
    ))
    .bind(&f.device)
    .bind(at)
    .bind(201_i64)
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let exact: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::PULL_EXACT_SQL
    ))
    .bind(&f.device)
    .bind("synthetic-plan-id")
    .bind(at)
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let claim: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::CLAIM_ONE_SQL
    ))
    .bind("FCM")
    .bind("pending")
    .bind(at)
    .bind(at)
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let recovery: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::RECOVERY_BATCH_SQL
    ))
    .bind("")
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let expiry: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::EXPIRY_BATCH_SQL
    ))
    .bind(at)
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let retirement: String = sqlx::query_scalar(&format!(
        "EXPLAIN FORMAT=JSON {}",
        crate::mysql_store::RETIRE_TOKEN_TARGETS_SQL
    ))
    .fetch_one(&mut *c)
    .await
    .unwrap();
    for (name, plan) in [
        ("pull", pull),
        ("exact", exact),
        ("claim", claim),
        ("recovery", recovery),
        ("expiry", expiry),
        ("retirement", retirement),
    ] {
        plans.insert(name.into(), serde_json::from_str(&plan).unwrap());
    }
    let indexes = sqlx::query("SELECT TABLE_NAME,INDEX_NAME,CAST(NON_UNIQUE AS UNSIGNED) AS NON_UNIQUE,CAST(SEQ_IN_INDEX AS UNSIGNED) AS SEQ_IN_INDEX,COLUMN_NAME,CAST(SUB_PART AS UNSIGNED) AS SUB_PART,IS_VISIBLE FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX").fetch_all(&mut *c).await.unwrap();
    let indexes: Vec<Value> = indexes.iter().map(|r| json!({"table":r.get_unchecked::<String,_>("TABLE_NAME"),"index":r.get_unchecked::<String,_>("INDEX_NAME"),"non_unique":r.get::<u64,_>("NON_UNIQUE"),"sequence":r.get::<u64,_>("SEQ_IN_INDEX"),"column":r.get_unchecked::<String,_>("COLUMN_NAME"),"prefix":r.get::<Option<u64>,_>("SUB_PART"),"visible":r.get_unchecked::<String,_>("IS_VISIBLE")})).collect();
    assert!(
        indexes.iter().any(|v| v["table"] == "targets"
            && v["column"] == "pull_owner"
            && v["visible"] == "YES")
    );
    assert!(
        indexes
            .iter()
            .any(|v| v["table"] == "messages" && v["column"] == "op_id" && v["non_unique"] == 0)
    );
    let expiry_columns: Vec<&str> = indexes
        .iter()
        .filter(|v| v["table"] == "messages" && v["index"] == "messages_expiry")
        .map(|v| v["column"].as_str().unwrap())
        .collect();
    assert_eq!(
        expiry_columns,
        vec!["has_payload", "expires_at", "delivery_id"]
    );
    assert!(
        indexes
            .iter()
            .filter(|v| v["table"] == "messages" && v["index"] == "messages_expiry")
            .all(|v| v["visible"] == "YES" && v["prefix"].is_null())
    );
    let generated:(String,String)=sqlx::query_as("SELECT CAST(EXTRA AS CHAR CHARACTER SET utf8mb4),CAST(GENERATION_EXPRESSION AS CHAR CHARACTER SET utf8mb4) FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='messages' AND COLUMN_NAME='has_payload'").fetch_one(&mut *c).await.unwrap();
    assert!(
        generated.0.contains("STORED GENERATED"),
        "expiry payload predicate must be STORED: {generated:?}"
    );
    let expression: String = generated
        .1
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '`' && *c != '(' && *c != ')')
        .collect();
    assert_eq!(expression, "payload_bytes>0");
    let collations: Vec<(String,String,String,String)> = sqlx::query_as("SELECT CAST(c.TABLE_NAME AS CHAR CHARACTER SET utf8mb4),CAST(c.COLUMN_NAME AS CHAR CHARACTER SET utf8mb4),CAST(c.COLLATION_NAME AS CHAR CHARACTER SET utf8mb4),CAST(k.PAD_ATTRIBUTE AS CHAR CHARACTER SET utf8mb4) FROM information_schema.columns c JOIN information_schema.collations k ON k.COLLATION_NAME=c.COLLATION_NAME WHERE c.TABLE_SCHEMA=DATABASE() AND c.COLUMN_NAME IN ('delivery_id','message_id','op_id','device_key','pull_owner','channel_id','provider_token') ORDER BY c.TABLE_NAME,c.COLUMN_NAME").fetch_all(&mut *c).await.unwrap();
    assert!(!collations.is_empty());
    for (table, column, collation, padding) in &collations {
        assert_eq!(
            collation, "utf8mb4_0900_bin",
            "case-sensitive native identity: {table}.{column}"
        );
        assert_eq!(
            padding, "NO PAD",
            "trailing-space native identity: {table}.{column}"
        );
    }
    println!(
        "MYSQL_NATIVE_PLANS {}",
        json!({"plans":plans,"indexes":indexes,"collations":collations,"has_payload":generated,"scope":"tiny synthetic fixture; no chosen-index assertion"})
    );
}

async fn mysql_runtime_backpressure(mut f: Fixture) {
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
    // Use an independent real MySQL session, never the runtime's pinned
    // session, to hold the row lock used by every ledger mutation.
    let mut locker = MySqlConnection::connect(&f.url)
        .await
        .unwrap_or_else(|_| panic!("synthetic runtime locker connection failed"));
    sqlx::raw_sql("BEGIN; SELECT singleton FROM ledger_usage WHERE singleton=1 FOR UPDATE")
        .execute(&mut locker)
        .await
        .unwrap();
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

async fn mysql_runtime_shutdown_recovery(mut f: Fixture) {
    let accepted = f
        .store
        .accept(f.request("mysql-shutdown-owned"))
        .await
        .unwrap();
    let config = f.store.config.clone();
    f.close().await;
    let transport = Arc::new(HeldResults {
        permits: tokio::sync::Semaphore::new(0),
        calls: AtomicUsize::new(0),
    });
    let runtime = crate::DeliveryRuntime::start(&f.url, config.clone(), transport.clone())
        .await
        .unwrap();
    let counters = runtime.store.counters.clone();
    until(|| {
        counters.network_inflight.load(Ordering::Relaxed) == 1
            && counters.owned_attempts.load(Ordering::Relaxed) == 1
    })
    .await;
    let first_attempt: i64 = {
        let mut admin = MySqlConnection::connect(&f.url).await.unwrap();
        sqlx::query_scalar("SELECT attempt_id FROM targets WHERE delivery_id=?")
            .bind(&accepted.delivery_id)
            .fetch_one(&mut admin)
            .await
            .unwrap()
    };
    // Graceful shutdown cancels synthetic Provider work, joins pumps, and leaves
    // the persisted running result unknown for the next explicit owner.
    let report = runtime.shutdown().await;
    assert_eq!(report.failed, 0);
    assert_eq!(report.panicked, 0);
    assert_eq!(counters.num_alive.load(Ordering::Relaxed), 0);
    assert_eq!(counters.network_inflight.load(Ordering::Relaxed), 0);
    let (store, owner) = OrdinaryStore::open(&f.url, config).await.unwrap();
    f.store = store;
    f.owner = Some(owner);
    assert_eq!(
        f.store
            .accept(f.request("mysql-shutdown-owned"))
            .await
            .unwrap()
            .delivery_id,
        accepted.delivery_id
    );
    let ticket = f
        .store
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .pop()
        .unwrap();
    assert_eq!(ticket.delivery_id, accepted.delivery_id);
    assert!(ticket.attempt_id > first_attempt);
    assert!(f.store.authorize_ticket(&ticket).await.unwrap());
    f.store
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .ack(&f.device, vec![accepted.delivery_id])
            .await
            .unwrap(),
        1
    );
    f.usage().await;
    f.close().await;
}
