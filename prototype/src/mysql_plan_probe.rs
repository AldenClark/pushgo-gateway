//! Ignored C6 diagnostic: real SQLx/pinned MySQL prepared statements across growth.
//! Assigned fresh synthetic cases only; no Gateway, Provider, throughput or API claim.
use crate::mysql_store::{CLAIM_ONE_SQL, MySqlDeliveryStore};
use crate::store::{Config, now};
use serde_json::{Value, json};
use sqlx::{Connection, MySqlConnection, Row};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

fn assigned_url(key: &str) -> (String, PathBuf) {
    let file = PathBuf::from(std::env::var(key).expect("explicit C6 assigned URL file required"));
    let file = file.canonicalize().unwrap();
    let env = file.parent().unwrap();
    let root = env.parent().unwrap();
    assert_eq!(env.file_name().unwrap(), "env");
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("c6-private-capacity-")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let raw = std::fs::read_to_string(&file).unwrap();
    let parsed = reqwest::Url::parse(raw.trim()).unwrap();
    assert_eq!(parsed.scheme(), "mysql");
    assert!(
        parsed
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost"))
    );
    let db = parsed.path().trim_start_matches('/');
    assert!(
        db.starts_with("c6_synthetic_")
            && db
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    assert!(parsed.query().is_none() && parsed.fragment().is_none());
    let owned: Value =
        serde_json::from_slice(&std::fs::read(env.join("mysql-owned.json")).unwrap()).unwrap();
    assert_eq!(
        owned["cases"][db]["url_file"].as_str(),
        file.to_str(),
        "only environment-owner captured C6 cases"
    );
    (raw.trim().to_owned(), root.join("mysql-diagnosis"))
}
fn save(out: &Path, name: &str, receipt: &Value) {
    std::fs::create_dir_all(out).unwrap();
    std::fs::write(out.join(name), serde_json::to_vec_pretty(receipt).unwrap()).unwrap();
}

async fn seed(c: &mut MySqlConnection, previous: usize, count: usize, at: i64) {
    if previous == 0 {
        for n in 0..16 {
            sqlx::query("INSERT INTO devices(device_key,platform,provider,provider_token,route_generation) VALUES(?,?,?,?,1)")
                .bind(format!("{:032x}",n+1)).bind(if n<8{"android"}else{"ios"}).bind(if n<8{"FCM"}else{"APNS"})
                .bind(if n<8{format!("synthetic-c6-route-{n}")}else{format!("{:064x}",n+1)}).execute(&mut *c).await.unwrap();
        }
        sqlx::query("UPDATE ledger_usage SET control_epoch=1 WHERE singleton=1")
            .execute(&mut *c)
            .await
            .unwrap();
    }
    let base = at - 300_000;
    for lo in (previous..count).step_by(128) {
        let mut q = sqlx::QueryBuilder::<sqlx::MySql>::new(
            "INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,usage_payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) ",
        );
        q.push_values(lo..(lo+128).min(count),|mut row,n|{
            let id=format!("{:032x}",n+1);
            let payload=json!({"delivery_id":id,"title":"synthetic C6 SQL plan","body":"synthetic-only ".repeat(48),"channel_id":"0".repeat(26),"op_id":format!("c6:sql:{n}")}).to_string().into_bytes();
            let size=payload.len() as i64;let accepted=base+n as i64*50;
            row.push_bind(id).push_bind(format!("{:032x}",0x100000+n)).push_bind(format!("c6:sql:{n}")).push_bind("0".repeat(26)).push_bind(blake3::hash(n.to_string().as_bytes()).to_hex().to_string()).push_bind(payload).push_bind(size).push_bind(size).push_bind(accepted).push_bind(base+86_400_000).push_bind(base+30*86_400_000).push_bind("provider_queued").push_bind(accepted);
        });
        q.build().execute(&mut *c).await.unwrap();
    }
    sqlx::query("INSERT INTO targets(delivery_id,device_key,pull_owner,owner_generation,control_epoch,platform,provider,provider_token,route_generation,accepted_at,state,next_attempt_at) SELECT m.delivery_id,d.device_key,d.device_key,1,1,d.platform,d.provider,d.provider_token,1,m.accepted_at,'pending',m.accepted_at FROM messages m CROSS JOIN devices d WHERE m.delivery_id>? AND m.delivery_id<=?")
        .bind(format!("{previous:032x}")).bind(format!("{count:032x}")).execute(&mut *c).await.unwrap();
    let terminal = (7169 * count / 2560) as i64;
    let running = 55.min(count as i64 * 16 - terminal);
    sqlx::query("UPDATE targets SET state=CASE WHEN (CAST(CONV(delivery_id,16,10) AS SIGNED)-1)*16+CAST(CONV(device_key,16,10) AS SIGNED)<=? THEN 'provider_accepted' WHEN (CAST(CONV(delivery_id,16,10) AS SIGNED)-1)*16+CAST(CONV(device_key,16,10) AS SIGNED)<=? THEN 'running' ELSE 'pending' END").bind(terminal).bind(terminal+running).execute(&mut *c).await.unwrap();
    sqlx::query("UPDATE messages m JOIN (SELECT delivery_id,SUM(state IN ('pending','running','retry_wait')) AS pending,SUM(state='provider_accepted') AS accepted FROM targets GROUP BY delivery_id) t ON t.delivery_id=m.delivery_id SET m.pending_targets=t.pending,m.provider_accepted_count=t.accepted,m.status=IF(t.pending>0,'provider_queued','sent')").execute(&mut *c).await.unwrap();
    sqlx::query("UPDATE ledger_usage SET messages=(SELECT COUNT(*) FROM messages WHERE pending_targets>0),targets=(SELECT COUNT(*) FROM targets WHERE state IN ('pending','running','retry_wait')),bytes=(SELECT SUM(payload_bytes) FROM messages) WHERE singleton=1").execute(&mut *c).await.unwrap();
}

async fn observe_sql(
    c: &mut MySqlConnection,
    thread: i64,
    provider: &str,
    state: &str,
    at: i64,
    sql: &str,
    literal: bool,
) -> Value {
    let plan_sql = format!("EXPLAIN FORMAT=JSON {sql}");
    let plan = sqlx::query(&plan_sql)
        .bind(provider)
        .bind(state)
        .bind(at)
        .bind(at)
        .fetch_one(&mut *c)
        .await
        .unwrap()
        .get_unchecked::<String, _>(0);
    let before:i64=sqlx::query_scalar("SELECT CAST(COALESCE(MAX(EVENT_ID),0) AS SIGNED) FROM performance_schema.events_statements_history WHERE THREAD_ID=?").bind(thread).fetch_one(&mut *c).await.unwrap();
    let started = Instant::now();
    let row = if literal {
        // Only these internal fixed class values and integer timestamps enter
        // the literal control. No request, identity, token or secret is embedded.
        assert!(matches!(provider, "FCM" | "APNS") && matches!(state, "pending" | "retry_wait"));
        let mut text = sql.to_owned();
        for value in [
            format!("'{provider}'"),
            format!("'{state}'"),
            at.to_string(),
            at.to_string(),
        ] {
            text = text.replacen('?', &value, 1);
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            sqlx::raw_sql(&text).fetch_all(&mut *c),
        )
        .await
        .expect("literal control bounded")
        .unwrap()
        .pop()
    } else {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            sqlx::query(sql)
                .bind(provider)
                .bind(state)
                .bind(at)
                .bind(at)
                .fetch_optional(&mut *c),
        )
        .await
        .expect("prepared control bounded")
        .unwrap()
    };
    let elapsed = started.elapsed().as_secs_f64() * 1000.;
    let identity=row.map(|r|json!({"delivery_id":r.get_unchecked::<String,_>("delivery_id"),"device_key":r.get_unchecked::<String,_>("device_key")}));
    let stats=sqlx::query("SELECT CAST(EVENT_ID AS SIGNED) AS event_id,CAST(TIMER_WAIT AS SIGNED) AS timer_wait,CAST(LOCK_TIME AS SIGNED) AS lock_time,CAST(ROWS_EXAMINED AS SIGNED) AS examined,CAST(ROWS_SENT AS SIGNED) AS sent,CAST(SORT_ROWS AS SIGNED) AS sort_rows,CAST(CREATED_TMP_TABLES AS SIGNED) AS temporary,SQL_TEXT,EVENT_NAME FROM performance_schema.events_statements_history WHERE THREAD_ID=? AND EVENT_ID>? AND EVENT_NAME IN ('statement/com/Execute','statement/sql/select') ORDER BY EVENT_ID DESC LIMIT 1").bind(thread).bind(before).fetch_optional(&mut *c).await.unwrap();
    json!({"sql":sql,"literal":literal,"thread":thread,"event_after":before,"provider":provider,"state":state,"bindings":[provider,state,at,at],"client_ms":elapsed,"identity":identity,"plan":serde_json::from_str::<Value>(&plan).unwrap(),"p_s":stats.map(|r|json!({"event_id":r.get::<i64,_>("event_id"),"timer_wait_ps":r.get::<Option<i64>,_>("timer_wait"),"lock_time_ps":r.get::<Option<i64>,_>("lock_time"),"rows_examined":r.get::<i64,_>("examined"),"rows_sent":r.get::<i64,_>("sent"),"sort_rows":r.get::<i64,_>("sort_rows"),"temporary_tables":r.get::<i64,_>("temporary"),"sql_text":r.get_unchecked::<Option<String>,_>("SQL_TEXT"),"event_name":r.get_unchecked::<String,_>("EVENT_NAME")}))})
}

async fn probe(key: &str, name: &str, stages: &[usize]) {
    let (url, out) = assigned_url(key);
    let mut preflight = MySqlConnection::connect(&url).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE()",
    )
    .fetch_one(&mut preflight)
    .await
    .unwrap();
    assert_eq!(
        n, 0,
        "new empty C6 case required; never resets prior evidence"
    );
    preflight.close().await.unwrap();
    let (store, owner) = MySqlDeliveryStore::open(&url, Config::default())
        .await
        .unwrap();
    let mut receipt = json!({"mode":name,"scope":"SQLx0.8.6 true prepared VarString/LongLong bindings in pinned native owner session; no Provider/API/throughput claim","query":CLAIM_ONE_SQL,"stages":[]});
    save(&out, name, &receipt);
    let mut c = store.acquire().await.unwrap();
    sqlx::query("SET SESSION MAX_EXECUTION_TIME=2000")
        .execute(&mut *c)
        .await
        .unwrap();
    let row=sqlx::query("SELECT VERSION() AS version,@@collation_connection AS collation,@@transaction_isolation AS isolation_level,@@performance_schema AS p_s,@@optimizer_switch AS optimizer_switch").fetch_one(&mut *c).await.unwrap();
    receipt["session"] = json!({"version":row.get_unchecked::<String,_>("version"),"collation":row.get_unchecked::<String,_>("collation"),"isolation":row.get_unchecked::<String,_>("isolation_level"),"optimizer_switch":row.get_unchecked::<String,_>("optimizer_switch")});
    let thread:i64=sqlx::query_scalar("SELECT CAST(THREAD_ID AS SIGNED) FROM performance_schema.threads WHERE PROCESSLIST_ID=CONNECTION_ID()").fetch_one(&mut *c).await.unwrap();
    let at = now();
    let mut previous = 0;
    for &count in stages {
        seed(&mut c, previous, count, at).await;
        let mut stage = json!({"messages":count,"targets":count*16,"queries":[]});
        for provider in ["FCM", "APNS"] {
            for state in ["pending", "retry_wait"] {
                stage["queries"].as_array_mut().unwrap().push(
                    observe_sql(&mut c, thread, provider, state, at, CLAIM_ONE_SQL, false).await,
                );
            }
        }
        receipt["stages"].as_array_mut().unwrap().push(stage);
        save(&out, name, &receipt);
        previous = count;
    }
    drop(c);
    store.close().await;
    owner.release();
    println!("C6 SQLx prepared receipt {}", out.join(name).display());
}
#[tokio::test]
#[ignore = "requires two environment-owner captured NEW EMPTY C6 synthetic MySQL URL files; seeds synthetic plan states only"]
async fn mysql_sqlx_prepared_plan_growth_probe() {
    probe(
        "C6_MYSQL_PROBE_WARM_URL_FILE",
        "sqlx-warm-first.json",
        &[16, 64, 256, 1024, 2560],
    )
    .await;
    probe(
        "C6_MYSQL_PROBE_LARGE_URL_FILE",
        "sqlx-large-first.json",
        &[2560],
    )
    .await;
}

// Retain the unhinted negative control even after the production query is fixed.
const ORIGINAL_CLAIM: &str = "SELECT t.*,m.payload_blob,m.expires_at FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id JOIN devices d ON d.device_key=t.pull_owner WHERE d.retired_at IS NULL AND t.provider=? AND t.state=? AND t.acked_at IS NULL AND t.next_attempt_at<=? AND m.expires_at>? AND NOT EXISTS(SELECT 1 FROM retired_provider_tokens r WHERE r.platform=t.platform AND r.provider_token=t.provider_token AND t.control_epoch<r.control_epoch) ORDER BY t.next_attempt_at,t.delivery_id,t.device_key LIMIT 1";

async fn compare(
    c: &mut MySqlConnection,
    thread: i64,
    at: i64,
    candidate: &str,
    label: &str,
) -> Value {
    let mut rows = vec![];
    for provider in ["FCM", "APNS"] {
        for state in ["pending", "retry_wait"] {
            let original = observe_sql(c, thread, provider, state, at, ORIGINAL_CLAIM, false).await;
            let literal = observe_sql(c, thread, provider, state, at, ORIGINAL_CLAIM, true).await;
            let fixed = observe_sql(c, thread, provider, state, at, candidate, false).await;
            let metrics = &fixed["p_s"];
            assert!(
                !metrics.is_null(),
                "exact completed statement metrics required"
            );
            assert_eq!(metrics["sort_rows"], 0, "candidate must avoid sorting");
            assert_eq!(
                metrics["temporary_tables"], 0,
                "candidate must avoid materialization"
            );
            assert!(
                metrics["rows_examined"].as_i64().unwrap() <= 128,
                "candidate must stop before scanning the synthetic backlog"
            );
            assert_eq!(
                original["identity"], literal["identity"],
                "prepared/literal tuple {label}"
            );
            assert_eq!(
                original["identity"], fixed["identity"],
                "candidate tuple {label}"
            );
            rows.push(json!({"original":original,"literal":literal,"candidate":fixed}));
        }
    }
    json!({"label":label,"queries":rows})
}

#[tokio::test]
#[ignore = "requires environment-owner captured populated C6 synthetic SQLx large case; bounded SQL plan diagnostic only"]
async fn mysql_sqlx_plan_contrast_probe() {
    let (url, out) = assigned_url("C6_MYSQL_PROBE_LARGE_URL_FILE");
    let (store, owner) = MySqlDeliveryStore::open(&url, Config::default())
        .await
        .unwrap();
    let mut c = store.acquire().await.unwrap();
    sqlx::query("SET SESSION MAX_EXECUTION_TIME=2000")
        .execute(&mut *c)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
        .fetch_one(&mut *c)
        .await
        .unwrap();
    assert_eq!(
        count, 40960,
        "only the assigned populated synthetic fixture"
    );
    // Restore the documented synthetic distribution after ordinary recovery.
    let at = now();
    seed(&mut c, 2560, 2560, at).await;
    let thread:i64=sqlx::query_scalar("SELECT CAST(THREAD_ID AS SIGNED) FROM performance_schema.threads WHERE PROCESSLIST_ID=CONNECTION_ID()").fetch_one(&mut *c).await.unwrap();
    let candidate = ORIGINAL_CLAIM
        .replacen("SELECT t.*", "SELECT STRAIGHT_JOIN t.*", 1)
        .replacen(
            "FROM targets t JOIN",
            "FROM targets t FORCE INDEX(targets_due) JOIN",
            1,
        );
    assert_eq!(
        candidate, CLAIM_ONE_SQL,
        "probe must exercise the production query"
    );
    let mut receipt = json!({"scope":"same SQLx pinned RC connection; C6 synthetic 40960 targets; original WHERE/projection/order/limit preserved; max_execution_time=2000ms","original":ORIGINAL_CLAIM,"candidate":candidate,"checks":[]});
    for label in [
        "baseline",
        "expired",
        "retired_owner",
        "retired_token",
        "empty_pending",
    ] {
        match label {
            "expired" => {
                sqlx::query("UPDATE messages SET expires_at=? WHERE delivery_id='000000000000000000000000000001c4'").bind(at-1).execute(&mut *c).await.unwrap();
            }
            "retired_owner" => {
                sqlx::query("UPDATE devices SET retired_at=? WHERE device_key='00000000000000000000000000000001'").bind(at).execute(&mut *c).await.unwrap();
            }
            "retired_token" => {
                sqlx::query("INSERT INTO retired_provider_tokens(platform,provider_token,control_epoch) VALUES('android','synthetic-c6-route-1',2)").execute(&mut *c).await.unwrap();
            }
            "empty_pending" => {
                sqlx::query("UPDATE targets SET state='provider_accepted' WHERE state='pending'")
                    .execute(&mut *c)
                    .await
                    .unwrap();
            }
            _ => {}
        }
        receipt["checks"]
            .as_array_mut()
            .unwrap()
            .push(compare(&mut c, thread, at, &candidate, label).await);
        save(&out, "sqlx-contrast-final.json", &receipt);
    }
    // Restore only the explicit synthetic controls; no external requests replayed.
    sqlx::query(
        "UPDATE messages SET expires_at=? WHERE delivery_id='000000000000000000000000000001c4'",
    )
    .bind(at + 86_100_000)
    .execute(&mut *c)
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET retired_at=NULL")
        .execute(&mut *c)
        .await
        .unwrap();
    sqlx::query("DELETE FROM retired_provider_tokens WHERE platform='android' AND provider_token='synthetic-c6-route-1' AND control_epoch=2").execute(&mut *c).await.unwrap();
    seed(&mut c, 2560, 2560, at).await;
    drop(c);
    store.close().await;
    owner.release();
    println!(
        "C6 contrast receipt {}",
        out.join("sqlx-contrast-final.json").display()
    );
}
