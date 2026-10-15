//! Native SQLx binary-prepared next_due equivalence, in one disposable fixture.
//! P_S/plan observations are diagnostic; elapsed time is never a pass threshold.
use super::*;
use std::time::Instant;

const ORIGINAL: &str = "SELECT MIN(next_attempt_at) FROM targets WHERE provider=? AND delivery_mode='provider' AND state IN ('pending','retry_wait') AND acked_at IS NULL";
const SEED_COUNT: usize = 256;

async fn due(c: &mut MySqlConnection, replacement: bool, provider: &str) -> Option<i64> {
    let query = if replacement {
        sqlx::query_scalar::<_, Option<i64>>(crate::mysql_store::NEXT_DUE_SQL)
            .bind(provider)
            .bind(provider)
    } else {
        sqlx::query_scalar::<_, Option<i64>>(ORIGINAL).bind(provider)
    };
    tokio::time::timeout(Duration::from_secs(5), query.fetch_one(c))
        .await
        .expect("native next_due query exceeded five seconds")
        .unwrap()
}

async fn equivalent(c: &mut MySqlConnection, label: &str, expected: Option<i64>) {
    let old = due(c, false, "FCM").await;
    let new = due(c, true, "FCM").await;
    assert_eq!(old, expected, "original query: {label}");
    assert_eq!(new, expected, "production replacement: {label}");
    println!(
        "MYSQL_NEXT_DUE_EQUIVALENCE {}",
        json!({"case":label,"original":old,"replacement":new,"protocol":"SQLx bound binary prepared, not SQL PREPARE/EXECUTE"})
    );
}

async fn reset(c: &mut MySqlConnection, at: i64) {
    sqlx::query("UPDATE targets SET state='provider_accepted',delivery_mode='provider',acked_at=NULL,next_attempt_at=?")
        .bind(at).execute(c).await.unwrap();
}

async fn target(c: &mut MySqlConnection, id: &str, state: &str, at: i64) {
    let changed = sqlx::query("UPDATE targets SET state=?,next_attempt_at=? WHERE delivery_id=?")
        .bind(state)
        .bind(at)
        .bind(id)
        .execute(c)
        .await
        .unwrap();
    assert_eq!(changed.rows_affected(), 1);
}

async fn event_mark(observer: &mut MySqlConnection, thread: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT CAST(COALESCE(MAX(EVENT_ID),0) AS SIGNED) FROM performance_schema.events_statements_history_long WHERE THREAD_ID=?")
        .bind(thread).fetch_one(observer).await
}

async fn events(
    observer: &mut MySqlConnection,
    thread: i64,
    after: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query("SELECT CAST(EVENT_ID AS SIGNED) AS event_id,CAST(NESTING_EVENT_ID AS SIGNED) AS parent_event,EVENT_NAME,SQL_TEXT,CAST(TIMER_WAIT AS SIGNED) AS timer_wait,CAST(ROWS_EXAMINED AS SIGNED) AS examined,CAST(ROWS_SENT AS SIGNED) AS sent,CAST(SORT_ROWS AS SIGNED) AS sort_rows,CAST(CREATED_TMP_TABLES AS SIGNED) AS temporary,CAST(CREATED_TMP_DISK_TABLES AS SIGNED) AS disk_temporary FROM performance_schema.events_statements_history_long WHERE THREAD_ID=? AND EVENT_ID>? AND EVENT_NAME IN ('statement/com/Execute','statement/sql/select') ORDER BY EVENT_ID LIMIT 8")
        .bind(thread).bind(after).fetch_all(observer).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            json!({
                "event_id":row.get::<i64,_>("event_id"),
                "parent_event":row.get::<Option<i64>,_>("parent_event"),
                "event_name":row.get_unchecked::<String,_>("EVENT_NAME"),
                "sql_text":row.get_unchecked::<Option<String>,_>("SQL_TEXT"),
                "server_timer_ps":row.get::<Option<i64>,_>("timer_wait"),
                "rows_examined":row.get::<i64,_>("examined"),
                "rows_sent":row.get::<i64,_>("sent"),
                "sort_rows":row.get::<i64,_>("sort_rows"),
                "temporary_tables":row.get::<i64,_>("temporary"),
                "disk_temporary_tables":row.get::<i64,_>("disk_temporary")
            })
        })
        .collect())
}

async fn observe(
    c: &mut MySqlConnection,
    observer: &mut MySqlConnection,
    thread: Option<i64>,
    replacement: bool,
    expected: i64,
) {
    let sql = if replacement {
        crate::mysql_store::NEXT_DUE_SQL
    } else {
        ORIGINAL
    };
    let explain = format!("EXPLAIN FORMAT=JSON {sql}");
    let mut query = sqlx::query(&explain).bind("FCM");
    if replacement {
        query = query.bind("FCM");
    }
    let plan = tokio::time::timeout(Duration::from_secs(5), query.fetch_one(&mut *c))
        .await
        .expect("next_due bound EXPLAIN exceeded five seconds")
        .unwrap()
        .get_unchecked::<String, _>(0);
    // Observe through a different physical connection. Its own P_S queries
    // cannot be mistaken for work performed by the measured binary statement.
    let mark = match thread {
        Some(thread) => event_mark(observer, thread).await.map(Some),
        None => Ok(None),
    };
    let started = Instant::now();
    let value = due(c, replacement, "FCM").await;
    let client_ms = started.elapsed().as_secs_f64() * 1000.;
    assert_eq!(value, Some(expected));
    let evidence = match (thread, mark) {
        (Some(thread), Ok(Some(mark))) => match events(observer, thread, mark).await {
            Ok(events) if !events.is_empty() => json!({"status":"observed","events":events}),
            Ok(_) => {
                json!({"status":"unavailable","reason":"no matching instrumented event retained; no rows/time claim"})
            }
            Err(error) => json!({"status":"unavailable","reason":error.to_string()}),
        },
        (_, Err(error)) => json!({"status":"unavailable","reason":error.to_string()}),
        _ => {
            json!({"status":"unavailable","reason":"P_S thread lookup unavailable; no rows/time claim"})
        }
    };
    println!(
        "MYSQL_NEXT_DUE_NATIVE_OBSERVATION {}",
        json!({
            "replacement":replacement,"sql":sql,"bindings":if replacement {vec!["FCM","FCM"]} else {vec!["FCM"]},
            "protocol":"SQLx query_scalar bound binary prepared; no SQL PREPARE or literal-query substitute",
            "seeded_targets":SEED_COUNT,"next_due":value,"client_ms":client_ms,
            "plan":serde_json::from_str::<Value>(&plan).unwrap(),"performance_schema":evidence,
            "scope":"256 eligible pending rows in synthetic rollback transaction; no concurrent capacity, percentile, or unconditional O(1) claim"
        })
    );
}

pub(super) async fn run(mut f: Fixture) {
    let mut ids = Vec::with_capacity(SEED_COUNT);
    for index in 0..SEED_COUNT {
        let mut request = f.request(&format!("mysql-next-due-{index}"));
        request.ttl = Some(now() + 300_000);
        ids.push(f.store.accept(request).await.unwrap().delivery_id);
    }
    let mysql = f.store.mysql_store().unwrap();
    let mut c = mysql.acquire().await.unwrap();
    // Reuse this real 256-message API fixture for the exact production usage
    // read: one known message is live, while 255 unrelated targets must not
    // turn its correlated COUNT into a retained-ledger scan.
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query(crate::mysql_store::RECONCILE_READ_SQL)
            .bind(&ids[0])
            .fetch_one(&mut *c),
    )
    .await
    .expect("reconcile read exceeded five seconds")
    .unwrap();
    assert_eq!(read.get::<i64, _>("pending"), 1);
    assert_eq!(read.get::<i64, _>("pending_targets"), 1);
    assert!(read.get::<i64, _>("payload_bytes") > 0);
    assert_eq!(
        read.get::<i64, _>("usage_payload_bytes"),
        read.get::<i64, _>("payload_bytes")
    );
    let absent = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query(crate::mysql_store::RECONCILE_READ_SQL)
            .bind("not-an-accepted-delivery")
            .fetch_optional(&mut *c),
    )
    .await
    .expect("missing reconcile read exceeded five seconds")
    .unwrap();
    assert!(
        absent.is_none(),
        "missing messages remain an absent row, not a synthetic zero row"
    );
    let plan = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query(&format!(
            "EXPLAIN FORMAT=JSON {}",
            crate::mysql_store::RECONCILE_READ_SQL
        ))
        .bind(&ids[0])
        .fetch_one(&mut *c),
    )
    .await
    .expect("reconcile EXPLAIN exceeded five seconds")
    .unwrap()
    .get_unchecked::<String, _>(0);
    let plan: Value = serde_json::from_str(&plan).unwrap();
    fn table<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
        match node {
            Value::Object(fields) => {
                if fields.get("table_name").and_then(Value::as_str) == Some(name) {
                    Some(node)
                } else {
                    fields.values().find_map(|child| table(child, name))
                }
            }
            Value::Array(items) => items.iter().find_map(|child| table(child, name)),
            _ => None,
        }
    }
    let message = table(&plan, "m").expect("message primary-key plan required");
    let targets = table(&plan, "t").expect("correlated target index plan required");
    assert_eq!(message["key"], "PRIMARY");
    assert!(matches!(
        message["access_type"].as_str(),
        Some("const" | "eq_ref")
    ));
    assert_eq!(targets["key"], "PRIMARY");
    assert!(matches!(
        targets["access_type"].as_str(),
        Some("ref" | "range")
    ));
    assert_eq!(message["used_key_parts"][0], "delivery_id");
    assert_eq!(targets["used_key_parts"][0], "delivery_id");
    println!(
        "MYSQL_RECONCILE_READ_NATIVE_PLAN {}",
        json!({"seeded_messages":SEED_COUNT,"pending":1,"protocol":"SQLx bound binary prepared production constant","plan":plan,"scope":"index access proof, not measured server rows examined or a latency claim"})
    );
    let connection_id: i64 = sqlx::query_scalar("SELECT CAST(CONNECTION_ID() AS SIGNED)")
        .fetch_one(&mut *c)
        .await
        .unwrap();
    let mut observer = MySqlConnection::connect(&f.url).await.unwrap();
    let thread: Option<i64> = sqlx::query_scalar(
        "SELECT CAST(THREAD_ID AS SIGNED) FROM performance_schema.threads WHERE PROCESSLIST_ID=?",
    )
    .bind(connection_id)
    .fetch_optional(&mut observer)
    .await
    .unwrap_or(None);
    let at = now();
    // These edits construct only query-eligibility fixtures. They do not model
    // lifecycle transitions or assert counters for provisional direct SQL. One
    // RAII transaction rolls every edit back before the API usage check/close.
    let mut tx = c.begin().await.unwrap();
    sqlx::query("UPDATE targets SET next_attempt_at=?")
        .bind(at)
        .execute(&mut *tx)
        .await
        .unwrap();
    equivalent(&mut tx, "256-pending-equal-due-ties", Some(at)).await;
    observe(&mut tx, &mut observer, thread, false, at).await;
    observe(&mut tx, &mut observer, thread, true, at).await;

    reset(&mut tx, at).await;
    equivalent(&mut tx, "empty-eligible-set", None).await;
    target(&mut tx, &ids[0], "pending", at + 20).await;
    equivalent(&mut tx, "pending-only", Some(at + 20)).await;
    reset(&mut tx, at).await;
    target(&mut tx, &ids[1], "retry_wait", at + 10).await;
    equivalent(&mut tx, "retry-only", Some(at + 10)).await;
    target(&mut tx, &ids[0], "pending", at + 5).await;
    equivalent(&mut tx, "pending-before-retry", Some(at + 5)).await;
    target(&mut tx, &ids[0], "pending", at + 20).await;
    equivalent(&mut tx, "retry-before-pending", Some(at + 10)).await;
    target(&mut tx, &ids[0], "pending", at + 10).await;
    target(&mut tx, &ids[2], "retry_wait", at + 10).await;
    equivalent(&mut tx, "same-due-within-and-across-states", Some(at + 10)).await;

    reset(&mut tx, at).await;
    for state in ["pending", "retry_wait"] {
        target(&mut tx, &ids[0], state, at).await;
        sqlx::query("UPDATE targets SET delivery_mode='private' WHERE delivery_id=?")
            .bind(&ids[0])
            .execute(&mut *tx)
            .await
            .unwrap();
        target(&mut tx, &ids[1], state, at + 1).await;
        sqlx::query("UPDATE targets SET acked_at=? WHERE delivery_id=?")
            .bind(at)
            .bind(&ids[1])
            .execute(&mut *tx)
            .await
            .unwrap();
        equivalent(
            &mut tx,
            &format!("{state}-only-ineligible-mode-ack-prefix"),
            None,
        )
        .await;
        target(&mut tx, &ids[2], state, at + 2).await;
        equivalent(
            &mut tx,
            &format!("{state}-skips-mode-ack-prefix"),
            Some(at + 2),
        )
        .await;
        reset(&mut tx, at).await;
    }
    target(&mut tx, &ids[0], "pending", at).await;
    for provider in ["fcm", "FCM ", "APNS"] {
        assert_eq!(due(&mut tx, false, provider).await, None);
        assert_eq!(due(&mut tx, true, provider).await, None);
    }
    tx.rollback().await.unwrap();
    observer.close().await.unwrap();
    drop(c);
    f.usage().await;
    f.close().await;
}
