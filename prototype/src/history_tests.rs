//! Fresh-database compact history costs and native SQLite failure receipts.
use crate::{AcceptRequest, Config, DeliveryStore, KernelError, store::now};
use serde_json::{Value, json};
use sqlx::{QueryBuilder, Row, Sqlite};
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Instant,
};
fn input(channel: &str, auth: &str, op: &str) -> AcceptRequest {
    AcceptRequest {
        channel_id: channel.into(),
        password: auth.into(),
        title: "history synthetic".into(),
        op_id: Some(op.into()),
        ..Default::default()
    }
}
async fn setup(
    path: &Path,
) -> (
    DeliveryStore,
    crate::store::OwnerLock,
    String,
    String,
    String,
) {
    let (store, owner) =
        DeliveryStore::open(&format!("sqlite://{}", path.display()), Config::default())
            .await
            .unwrap();
    let device = store.register("android").await.unwrap();
    store
        .route(&device, None, "FCM", "synthetic-history-route")
        .await
        .unwrap();
    let auth = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("history"), &auth)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (store, owner, device, channel, auth)
}
#[tokio::test]
async fn sqlite_full_admission_never_reports_success_or_loses_prior_accepted_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk-full.sqlite");
    let (store, owner, device, channel, auth) = setup(&path).await;
    let prior_input = input(&channel, &auth, "before-full");
    let prior = store.accept(prior_input.clone()).await.unwrap();
    let before = store.pull(&device, Some(&prior.delivery_id)).await.unwrap();
    let committed = store.counters.admission_commits.load(Ordering::Relaxed);
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let configured: i64 = sqlx::query_scalar(&format!("PRAGMA max_page_count={}", pages + 1))
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(configured, pages + 1);
    let mut request = input(&channel, &auth, "must-not-commit-full");
    request.body = Some("x".repeat(24 * 1024));
    let code = match store.accept(request).await {
        Err(KernelError::Database(sqlx::Error::Database(error))) => {
            error.code().map(|v| v.into_owned())
        }
        result => panic!("expected native SQLITE_FULL, got {result:?}"),
    };
    assert_eq!(code.as_deref(), Some("13"));
    assert_eq!(
        store.counters.admission_commits.load(Ordering::Relaxed),
        committed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE op_id='must-not-commit-full'"
        )
        .fetch_one(&store.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        store.pull(&device, Some(&prior.delivery_id)).await.unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets WHERE delivery_id=?")
            .bind(&prior.delivery_id)
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        1
    );
    store.pool.close().await;
    owner.release();
    let (reopened, owner) =
        DeliveryStore::open(&format!("sqlite://{}", path.display()), Config::default())
            .await
            .unwrap();
    let replay = reopened.accept(prior_input).await.unwrap();
    assert_eq!(replay.delivery_id, prior.delivery_id);
    assert_eq!(replay.message_id, prior.message_id);
    assert_eq!(
        reopened
            .pull(&device, Some(&prior.delivery_id))
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE op_id='must-not-commit-full'"
        )
        .fetch_one(&reopened.pool)
        .await
        .unwrap(),
        0
    );
    reopened.pool.close().await;
    owner.release();
}
fn physical(path: &Path) -> Value {
    let bytes = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    json!({"db_bytes":bytes(path),"wal_bytes":bytes(&PathBuf::from(format!("{}-wal",path.display()))),"shm_bytes":bytes(&PathBuf::from(format!("{}-shm",path.display())))})
}
async fn disk(store: &DeliveryStore, path: &Path) -> Value {
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let cache: i64 = sqlx::query_scalar("PRAGMA cache_size")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let payload: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(payload_bytes),0) FROM messages")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let dbstat = match sqlx::query(
        "SELECT name,SUM(pgsize) AS bytes FROM dbstat GROUP BY name ORDER BY name",
    )
    .fetch_all(&store.pool)
    .await
    {
        Ok(rows) => json!(
            rows.iter()
                .map(|r| json!({"name":r.get::<String,_>("name"),"bytes":r.get::<i64,_>("bytes")}))
                .collect::<Vec<_>>()
        ),
        Err(error) => json!({"unavailable":error.to_string()}),
    };
    json!({"page_size":page_size,"page_count":pages,"freelist_count":free,"allocated_db_bytes":page_size*pages,"used_pages_bytes":page_size*(pages-free),"cache_size_pragma":cache,"identity_rows":rows,"target_rows":targets,"logical_payload_bytes":payload,"physical":physical(path),"dbstat":dbstat})
}
fn vmmap(out: &Path, label: &str) -> Value {
    match std::process::Command::new("/usr/bin/vmmap")
        .args(["-summary", &std::process::id().to_string()])
        .output()
    {
        Ok(result) => {
            std::fs::write(out.join(format!("vmmap-{label}.txt")), &result.stdout).unwrap();
            std::fs::write(
                out.join(format!("vmmap-{label}.stderr.txt")),
                &result.stderr,
            )
            .unwrap();
            json!({"success":result.status.success(),"exit_code":result.status.code(),"pid":std::process::id(),"file":format!("vmmap-{label}.txt")})
        }
        Err(error) => json!({"unavailable":error.to_string()}),
    }
}
fn timing(samples: &mut [u64]) -> Value {
    samples.sort_unstable();
    json!({"n":samples.len(),"p50_us":samples[samples.len()/2],"p95_us":samples[(samples.len()*95/100).min(samples.len()-1)],"max_us":samples[samples.len()-1],"total_us":samples.iter().sum::<u64>()})
}
#[tokio::test]
#[ignore = "fresh 1m-row history/disk experiment; run explicitly with C2_HISTORY_OUT"]
async fn measure_compact_history_query_admission_gc_and_disk_space() {
    let out = PathBuf::from(
        std::env::var("C2_HISTORY_OUT").expect("new C2_HISTORY_OUT directory required"),
    );
    std::fs::create_dir(&out).expect("refuse to reuse existing experiment directory");
    let path = out.join("history.sqlite");
    let (store, owner, device, channel, auth) = setup(&path).await;
    let cold = disk(&store, &path).await;
    let cold_vmmap = vmmap(&out, "cold");
    let fingerprint = input(&channel, &auth, "seed")
        .normalize()
        .unwrap()
        .fingerprint;
    let at = now();
    let mut seeded = 0_u64;
    let mut stages = Vec::new();
    for count in [10_000_u64, 100_000, 1_000_000] {
        let start = Instant::now();
        while seeded < count {
            let end = (seeded + 500).min(count);
            let mut insert = QueryBuilder::<Sqlite>::new(
                "INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,pending_targets,provider_accepted_count,provider_failed_count) ",
            );
            insert.push_values(seeded..end, |mut row, n| {
                row.push_bind(format!("aaaa{n:028x}"))
                    .push_bind(format!("bbbb{n:028x}"))
                    .push_bind(format!("history-{n:024x}"))
                    .push_bind(&channel)
                    .push_bind(&fingerprint)
                    .push_bind(Vec::<u8>::new())
                    .push_bind(0_i64)
                    .push_bind(at)
                    .push_bind(at)
                    .push_bind(at + 30 * 86_400_000_i64)
                    .push_bind("sent")
                    .push_bind(at)
                    .push_bind(0_i64)
                    .push_bind(1_i64)
                    .push_bind(0_i64);
            });
            insert.build().execute(&store.pool).await.unwrap();
            seeded = end;
        }
        let seed_ms = start.elapsed().as_millis();
        let mut status_us = Vec::new();
        let mut duplicate_us = Vec::new();
        let mut admission_us = Vec::new();
        for n in 0..50_u64 {
            let op = format!("history-{:024x}", n * (count / 50));
            let start = Instant::now();
            let status = store.status(&op).await.unwrap();
            status_us.push(start.elapsed().as_micros() as u64);
            assert_eq!(status["status"], "sent");
            let start = Instant::now();
            let replay = store.accept(input(&channel, &auth, &op)).await.unwrap();
            duplicate_us.push(start.elapsed().as_micros() as u64);
            assert_eq!(replay.acceptance, "duplicate_completed");
            let start = Instant::now();
            let fresh = store
                .accept(input(&channel, &auth, &format!("new-{count}-{n}")))
                .await
                .unwrap();
            admission_us.push(start.elapsed().as_micros() as u64);
            store.ack(&device, vec![fresh.delivery_id]).await.unwrap();
        }
        let live = disk(&store, &path).await;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&store.pool)
            .await
            .unwrap();
        stages.push(json!({"seeded_identity_rows":count,"seed_delta_ms":seed_ms,"status":timing(&mut status_us),"duplicate":timing(&mut duplicate_us),"new_admission":timing(&mut admission_us),"disk_before_checkpoint":live,"disk_after_truncate_checkpoint":disk(&store,&path).await,"vmmap":vmmap(&out,&format!("history-{count}"))}));
    }
    // Expire only a fixed sample. All other identities retain their full30d.
    sqlx::query("UPDATE messages SET dedupe_until=? WHERE delivery_id>=? AND delivery_id<?")
        .bind(now() - 1)
        .bind("aaaa0000000000000000000000000000")
        .bind(format!("aaaa{:028x}", 10_000_u64))
        .execute(&store.pool)
        .await
        .unwrap();
    let before_gc = disk(&store, &path).await;
    let mut gc_us = Vec::new();
    let mut deleted = 0;
    for _ in 0..40 {
        let start = Instant::now();
        let chunk = store.maintenance().await.unwrap();
        gc_us.push(start.elapsed().as_micros() as u64);
        assert!(chunk <= 256);
        deleted += chunk;
    }
    assert_eq!(deleted, 10_000);
    let after_gc = disk(&store, &path).await;
    let falloff = vmmap(&out, "after-gc");
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&store.pool)
        .await
        .unwrap();
    // Separate synthetic storage-layout probe: one active business message,
    //10k frozen recipients. It is not a 10k-device network throughput claim.
    let fanout_path = out.join("active-fanout.sqlite");
    let (fanout_store, fanout_owner, _, fanout_channel, fanout_auth) = setup(&fanout_path).await;
    let fanout_cold = disk(&fanout_store, &fanout_path).await;
    let accepted = fanout_store
        .accept(input(&fanout_channel, &fanout_auth, "fanout-layout"))
        .await
        .unwrap();
    for batch in (1_u64..10_000).step_by(500) {
        let mut insert = QueryBuilder::<Sqlite>::new(
            "INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,state,next_attempt_at,accepted_at) ",
        );
        insert.push_values(batch..(batch + 500).min(10_000), |mut row, n| {
            row.push_bind(&accepted.delivery_id)
                .push_bind(format!("dddd{n:028x}"))
                .push_bind("android")
                .push_bind("FCM")
                .push_bind(format!("synthetic-{:0153x}", n))
                .push_bind("pending")
                .push_bind(now())
                .push_bind(now());
        });
        insert.build().execute(&fanout_store.pool).await.unwrap();
    }
    sqlx::query("UPDATE messages SET pending_targets=10000 WHERE delivery_id=?")
        .bind(&accepted.delivery_id)
        .execute(&fanout_store.pool)
        .await
        .unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&fanout_store.pool)
        .await
        .unwrap();
    let active_fanout = json!({"recipient_rows":10000,"synthetic_provider_token_bytes":163,"cold":fanout_cold,"active":disk(&fanout_store,&fanout_path).await,"note":"direct SQL seed measures target/index storage layout only"});
    fanout_store.pool.close().await;
    fanout_owner.release();
    let result = json!({"pid":std::process::id(),"cold":cold,"cold_vmmap":cold_vmmap,"stages":stages,"active_fanout":active_fanout,"gc":{"expired_sample":10000,"batches":40,"max_deletes_per_batch":256,"maintenance":timing(&mut gc_us),"before":before_gc,"after_logical_delete":after_gc,"after_truncate_checkpoint":disk(&store,&path).await,"falloff_vmmap":falloff},"notes":["Identity history has no quantity or byte quota; disk grows with accepted message rate for30d.","ACKed identity0payload0targets; active fanout is separate.","Freelist stays allocated; WALcheckpoint does not shrink DB; noVACUUM.","vmmap samples own process malloc/heap; RSS alone is not a leak oracle."]});
    std::fs::write(
        out.join("history-results.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "HISTORY_RESULT {}",
        out.join("history-results.json").display()
    );
    store.pool.close().await;
    owner.release();
}

#[tokio::test]
async fn deferred_sqlite_commit_failure_never_reports_success_and_preserves_prior_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commit-failure.sqlite");
    let (store, owner, device, channel, auth) = setup(&path).await;
    let prior_input = input(&channel, &auth, "prior-commit-fault");
    let prior = store.accept(prior_input.clone()).await.unwrap();
    let before = store.pull(&device, Some(&prior.delivery_id)).await.unwrap();
    let prior_status = store.status("prior-commit-fault").await.unwrap();
    let acked_input = input(&channel, &auth, "acked-before-commit-fault");
    let acked = store.accept(acked_input.clone()).await.unwrap();
    store
        .ack(&device, vec![acked.delivery_id.clone()])
        .await
        .unwrap();
    sqlx::raw_sql(
        r#"
        CREATE TABLE commit_fault_parent(id TEXT PRIMARY KEY);
        CREATE TABLE commit_fault_child(op TEXT PRIMARY KEY,parent TEXT NOT NULL,
          FOREIGN KEY(parent) REFERENCES commit_fault_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER inject_commit_failure AFTER INSERT ON messages
          WHEN NEW.op_id='commit-must-fail' BEGIN
          INSERT INTO commit_fault_child(op,parent) VALUES(NEW.op_id,'absent-parent'); END;
    "#,
    )
    .execute(&store.pool)
    .await
    .unwrap();
    // Negative control: the same constraint accepts its INSERT inside a real
    // transaction, and fails only when that transaction attempts COMMIT.
    let mut probe = store.pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO commit_fault_child(op,parent) VALUES('constraint-probe','absent-parent')",
    )
    .execute(&mut *probe)
    .await
    .unwrap();
    let probe_error = probe.commit().await.unwrap_err();
    assert_eq!(
        probe_error.as_database_error().unwrap().code().as_deref(),
        Some("787")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM commit_fault_child")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        0
    );
    let admission_successes = store.counters.admission_commits.load(Ordering::Relaxed);
    let successful_commit_samples = store
        .counters
        .admission_commit_samples
        .load(Ordering::Relaxed);
    let result = store
        .accept(input(&channel, &auth, "commit-must-fail"))
        .await;
    let error = match result {
        Err(KernelError::Database(error)) => error,
        other => panic!("expected deferred native COMMIT failure, got {other:?}"),
    };
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("787")
    );
    assert_eq!(
        store.counters.admission_commits.load(Ordering::Relaxed),
        admission_successes
    );
    assert_eq!(
        store
            .counters
            .admission_commit_samples
            .load(Ordering::Relaxed),
        successful_commit_samples
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE op_id='commit-must-fail'"
        )
        .fetch_one(&store.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM commit_fault_child")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store.pull(&device, Some(&prior.delivery_id)).await.unwrap(),
        before
    );
    assert_eq!(
        store.status("prior-commit-fault").await.unwrap(),
        prior_status
    );
    // Exercise the HTTP boundary too: a failed native COMMIT is a service
    // failure response, never a successful acceptance envelope.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/message", listener.local_addr().unwrap());
    let app = crate::http::router(store.clone(), std::sync::Arc::new(|| json!({})));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let response = reqwest::Client::new().post(endpoint).json(&json!({
        "channel_id":channel,"password":auth,"title":"history synthetic","op_id":"commit-must-fail"
    })).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json::<Value>().await.unwrap()["success"], false);
    assert_eq!(
        store.counters.admission_commits.load(Ordering::Relaxed),
        admission_successes
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    store.pool.close().await;
    owner.release();
    let (reopened, owner) =
        DeliveryStore::open(&format!("sqlite://{}", path.display()), Config::default())
            .await
            .unwrap();
    let replay = reopened.accept(prior_input).await.unwrap();
    assert_eq!(replay.delivery_id, prior.delivery_id);
    assert_eq!(replay.message_id, prior.message_id);
    assert_eq!(
        reopened
            .pull(&device, Some(&prior.delivery_id))
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        reopened.status("prior-commit-fault").await.unwrap(),
        prior_status
    );
    let acked_replay = reopened.accept(acked_input).await.unwrap();
    assert_eq!(acked_replay.delivery_id, acked.delivery_id);
    assert_eq!(acked_replay.message_id, acked.message_id);
    assert_eq!(
        reopened
            .pull(&device, Some(&acked.delivery_id))
            .await
            .unwrap()["items"],
        json!([])
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE op_id='commit-must-fail'"
        )
        .fetch_one(&reopened.pool)
        .await
        .unwrap(),
        0
    );
    // Restore normal writes after the injection and verify DB usability.
    sqlx::query("DROP TRIGGER inject_commit_failure")
        .execute(&reopened.pool)
        .await
        .unwrap();
    assert!(
        reopened
            .accept(input(&channel, &auth, "after-commit-fault"))
            .await
            .is_ok()
    );
    reopened.pool.close().await;
    owner.release();
}

fn layout_identity(n: u64, op_bytes: usize, random_ids: bool, at: i64) -> (String, String, String) {
    let digest = blake3::hash(&n.to_le_bytes()).to_hex().to_string();
    let (delivery, message) = if random_ids {
        (digest[..32].to_owned(), digest[32..].to_owned())
    } else {
        (format!("aaaa{n:028x}"), format!("bbbb{n:028x}"))
    };
    let op = match (op_bytes, random_ids) {
        (16, true) => digest[..16].to_owned(),
        (16, false) => format!("{n:016x}"),
        (46, true) => format!("{at:013x}-{}", &digest[..32]),
        (46, false) => format!("{at:013x}-{n:032x}"),
        (128, true) => digest.repeat(2),
        (128, false) => format!("{n:0128x}"),
        _ => panic!("unsupported test width"),
    };
    assert_eq!(op.len(), op_bytes);
    (delivery, message, op)
}
async fn seed_layout_range(
    store: &DeliveryStore,
    channel: &str,
    fingerprint: &str,
    range: std::ops::Range<u64>,
    op_bytes: usize,
    random_ids: bool,
    at: i64,
) {
    for start in range.clone().step_by(500) {
        let end = (start + 500).min(range.end);
        let mut insert = QueryBuilder::<Sqlite>::new(
            "INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,pending_targets,provider_accepted_count,provider_failed_count) ",
        );
        insert.push_values(start..end, |mut row, n| {
            let (delivery, message, op) = layout_identity(n, op_bytes, random_ids, at);
            row.push_bind(delivery)
                .push_bind(message)
                .push_bind(op)
                .push_bind(channel)
                .push_bind(fingerprint)
                .push_bind(Vec::<u8>::new())
                .push_bind(0_i64)
                .push_bind(at)
                .push_bind(at)
                .push_bind(at + 30 * 86_400_000_i64)
                .push_bind("sent")
                .push_bind(at)
                .push_bind(0_i64)
                .push_bind(1_i64)
                .push_bind(0_i64);
        });
        insert.build().execute(&store.pool).await.unwrap();
    }
}
#[tokio::test]
#[ignore = "fresh six-case op-width/layout and actual freepage reuse measurement; needs new C2_HISTORY_WIDTH_OUT"]
async fn measure_op_widths_16_46_128_and_actual_freepage_reuse() {
    let out = PathBuf::from(
        std::env::var("C2_HISTORY_WIDTH_OUT").expect("fresh C2_HISTORY_WIDTH_OUT required"),
    );
    std::fs::create_dir(&out).expect("refuse to reuse existing measurement directory");
    let mut cases = Vec::new();
    for random_ids in [false, true] {
        for op_bytes in [16_usize, 46, 128] {
            let order = if random_ids {
                "deterministic-random"
            } else {
                "lexical"
            };
            let path = out.join(format!("op-{op_bytes}-{order}.sqlite"));
            let (store, owner, _, channel, auth) = setup(&path).await;
            let generated = AcceptRequest {
                op_id: None,
                ..input(&channel, &auth, "unused")
            }
            .normalize()
            .unwrap()
            .op_id;
            assert_eq!(generated.len(), 46);
            let fingerprint = input(&channel, &auth, "seed")
                .normalize()
                .unwrap()
                .fingerprint;
            let cold = disk(&store, &path).await;
            let at = now();
            let seed_at = Instant::now();
            seed_layout_range(
                &store,
                &channel,
                &fingerprint,
                0..100_000,
                op_bytes,
                random_ids,
                at,
            )
            .await;
            let seed_us = seed_at.elapsed().as_micros();
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&store.pool)
                .await
                .unwrap();
            let before_delete = disk(&store, &path).await;
            assert_eq!(before_delete["identity_rows"], 100_000);
            assert_eq!(before_delete["target_rows"], 0);
            assert_eq!(before_delete["logical_payload_bytes"], 0);
            // Expire the first10k inserted rowids. Identifier keys differ by
            // order case; both cases have contiguous physical table history.
            for start in (0_u64..10_000).step_by(500) {
                let mut update = QueryBuilder::<Sqlite>::new("UPDATE messages SET dedupe_until=");
                update.push_bind(at - 1).push(" WHERE op_id IN (");
                let mut values = update.separated(",");
                for n in start..start + 500 {
                    values.push_bind(layout_identity(n, op_bytes, random_ids, at).2);
                }
                values.push_unseparated(")");
                update.build().execute(&store.pool).await.unwrap();
            }
            let mut deleted = 0;
            for _ in 0..40 {
                let chunk = store.maintenance().await.unwrap();
                assert!(chunk <= 256);
                deleted += chunk;
            }
            assert_eq!(deleted, 10_000);
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&store.pool)
                .await
                .unwrap();
            let after_delete = disk(&store, &path).await;
            assert_eq!(after_delete["identity_rows"], 90_000);
            let free_before_reinsert = after_delete["freelist_count"].as_i64().unwrap();
            assert!(
                free_before_reinsert > 0,
                "negative control requires actual free pages before reinsertion"
            );
            // Reinsert the same10k identifiers; this is native allocation reuse,
            // not an inference solely from SQLite's freelist definition.
            let reinsert_at = Instant::now();
            seed_layout_range(
                &store,
                &channel,
                &fingerprint,
                0..10_000,
                op_bytes,
                random_ids,
                at,
            )
            .await;
            let reinsert_us = reinsert_at.elapsed().as_micros();
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&store.pool)
                .await
                .unwrap();
            let after_reinsert = disk(&store, &path).await;
            assert_eq!(after_reinsert["identity_rows"], 100_000);
            assert_eq!(after_reinsert["target_rows"], 0);
            let free_after_reinsert = after_reinsert["freelist_count"].as_i64().unwrap();
            assert!(
                free_after_reinsert < free_before_reinsert,
                "reinsertion must demonstrably consume existing free pages"
            );
            let bytes_per_identity = (before_delete["allocated_db_bytes"].as_u64().unwrap()
                - cold["allocated_db_bytes"].as_u64().unwrap())
                as f64
                / 100_000.0;
            cases.push(json!({"op_id_bytes":op_bytes,"delivery_message_id_bytes":32,"channel_id_bytes":channel.len(),"fingerprint_bytes":fingerprint.len(),"identifier_order":order,"rows":100000,"seed_us":seed_us,"cold":cold,"before_delete":before_delete,"after_delete":after_delete,"after_reinsert":after_reinsert,"reinsert_us":reinsert_us,"free_pages_consumed_on_reinsert":free_before_reinsert-free_after_reinsert,"cold_subtracted_total_bytes_per_identity":bytes_per_identity}));
            store.pool.close().await;
            owner.release();
        }
    }
    let result = json!({"cases":cases,"scope":"native SQLite synthetic compact identities; batch500, no provider sends, zero targets/payload","default_generated_op_bytes":46,"max_allowed_explicit_op_bytes":128,"notes":["Lexical and deterministic random cases are controlled layout variations; production identifier distribution and insertion order can differ.","Explicit16 is one legal width, not minimumallowed; defaultgenerated46 includes13hex timestamp, dash,32hex suffix.","Recipientfanout1/16/32 contributes0 persisted targetrows once fullyACKed; activefanout cost measured separately.","Freelist reuse is verified by10k reinserts with rowcountrestored and freepagesdecreased; DBsizegrowth is recorded, not assumedzero.","No history quotas or refusalpolicy added."]});
    std::fs::write(
        out.join("history-width-results.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "HISTORY_WIDTH_RESULT {}",
        out.join("history-width-results.json").display()
    );
}

#[tokio::test]
async fn compact_history_lookup_and_bounded_gc_use_indices_without_sorting_history() {
    let dir = tempfile::tempdir().unwrap();
    let (store, owner, _, channel, auth) = setup(&dir.path().join("history-plans.sqlite")).await;
    store
        .accept(input(&channel, &auth, "plan-identity"))
        .await
        .unwrap();
    let identity=sqlx::query("EXPLAIN QUERY PLAN SELECT op_id,status,message_id,accepted_at,updated_at,dedupe_until FROM messages WHERE op_id=? AND dedupe_until>?")
        .bind("plan-identity").bind(now()).fetch_all(&store.pool).await.unwrap();
    let details: Vec<String> = identity.iter().map(|r| r.get("detail")).collect();
    assert!(
        details
            .iter()
            .any(|d| d.contains("SEARCH messages USING INDEX") && d.contains("op_id=?")),
        "{details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|d| d.contains("SCAN messages") || d.contains("TEMP B-TREE")),
        "{details:?}"
    );
    let gc=sqlx::query("EXPLAIN QUERY PLAN SELECT delivery_id FROM messages WHERE dedupe_until<=? AND payload_bytes=0 AND NOT EXISTS(SELECT 1 FROM targets WHERE targets.delivery_id=messages.delivery_id AND state='running') ORDER BY dedupe_until LIMIT 256")
        .bind(now()).fetch_all(&store.pool).await.unwrap();
    let details: Vec<String> = gc.iter().map(|r| r.get("detail")).collect();
    assert!(
        details
            .iter()
            .any(|d| d.contains("SEARCH messages USING INDEX messages_retention")),
        "{details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|d| d.contains("SCAN messages") || d.contains("TEMP B-TREE")),
        "{details:?}"
    );
    store.pool.close().await;
    owner.release();
}
