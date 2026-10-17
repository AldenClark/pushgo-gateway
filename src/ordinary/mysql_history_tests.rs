//! C16 synthetic native-MySQL runtime tests. Direct SQL creates deliberately
//! synthetic retained identities/reservations; this is not a legacy API or
//! offline migration acceptance test and does not contact any Provider.
use super::owner::ProductOwner;
use super::store::{Health, now};
use super::{AcceptRequest, Config, KernelError};
use crate::storage::{DeviceRouteRecordRow, PrivateDeviceId, Storage, StorageInitConfig};
use sqlx::{Connection, MySqlConnection};
use std::sync::Arc;

fn request(channel: [u8; 16], op: &str) -> AcceptRequest {
    AcceptRequest {
        authorized_channel: Some(channel),
        channel_id: crate::value::ChannelId::from(channel).to_string(),
        op_id: Some(op.into()),
        title: "C16 synthetic history".into(),
        body: Some("unchanged 中文 body".into()),
        occurred_at: Some(1_700_000_000_000),
        ..AcceptRequest::default()
    }
}

async fn history(connection: &mut MySqlConnection, channel: &str, op: &str, until: i64) {
    sqlx::query("INSERT INTO ordinary_messages(message_id,op_id,channel_id,thing_id,payload_blob,payload_bytes,accepted_at,dedupe_until,status,updated_at,identity_state) VALUES(?,?,?,'synthetic-thing',X'',0,?,?,'historical_unverifiable',?,'legacy_unverifiable')")
        .bind(crate::util::generate_hex_id_128()).bind(op).bind(channel)
        .bind(now()-2_000).bind(until).bind(now()-2_000).execute(connection).await.unwrap();
}

async fn reservation(connection: &mut MySqlConnection, delivery: &str) {
    sqlx::query("INSERT INTO dispatch_delivery_dedupe(dedupe_key,delivery_id,state,created_at,updated_at,expires_at) VALUES(?,?,'sent',?,?,?)")
        .bind(format!("delivery:{delivery}")).bind(delivery).bind(now()-2_000).bind(now()-2_000).bind(now()-1_000)
        .execute(connection).await.unwrap();
}

fn assert_check(error: sqlx::Error) {
    match error {
        sqlx::Error::Database(error) => assert_eq!(
            error
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .number(),
            3819
        ),
        other => panic!("expected native CHECK violation, got {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires approved fresh C16_MYSQL_TEST_URL on loopback:42773/c16_synthetic_*"]
async fn mysql_c16_synthetic_historical_runtime_contract() {
    let url =
        std::env::var("C16_MYSQL_TEST_URL").expect("explicit approved fresh C16 URL required");
    let parsed = reqwest::Url::parse(&url).unwrap();
    assert!(matches!(parsed.scheme(), "mysql"));
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1") | Some("localhost")
    ));
    assert_eq!(parsed.port(), Some(42773));
    let database = parsed.path().trim_start_matches('/');
    assert!(database.starts_with("c16_synthetic_") && database.len() > "c16_synthetic_".len());
    assert!(
        database
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    assert!(
        parsed.query().is_none(),
        "connection overrides are not allowed"
    );
    let mut inspect = MySqlConnection::connect(&url).await.unwrap();
    let tables: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.tables WHERE table_schema=DATABASE()")
        .fetch_one(&mut inspect).await.unwrap();
    assert_eq!(
        tables, 0,
        "refuse any used database, including prior test runs"
    );
    inspect.close().await.unwrap();

    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(&url), health.clone())
        .await
        .unwrap();
    let init = StorageInitConfig {
        db_url: Some(url.clone()),
        managed_upgrade: false,
        mcp_enabled: false,
        ..StorageInitConfig::default()
    };
    let storage = Storage::new_with_config(init.clone()).await.unwrap();
    let ordinary = storage
        .initialize_ordinary(
            Config {
                private: super::private_model::PrivateLedgerConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Config::default()
            },
            health.clone(),
        )
        .await
        .unwrap();
    let password = crate::util::generate_hex_id_128();
    let channel = storage
        .upsert_private_channel(None, Some("C16 synthetic"), &password)
        .await
        .unwrap()
        .channel_id;
    let other = storage
        .upsert_private_channel(None, Some("C16 other scope"), &password)
        .await
        .unwrap()
        .channel_id;
    let channel_id = crate::value::ChannelId::from(channel).to_string();
    let mut inspect = MySqlConnection::connect(&url).await.unwrap();
    history(&mut inspect, &channel_id, "C16-History", now() + 86_400_000).await;

    // Every field forbidden on historical identities must reject natively.
    for assignment in [
        "delivery_id='00112233445566778899aabbccddeeff'",
        "fingerprint='invented'",
        "expires_at=1",
        "payload_bytes=1",
        "payload_blob=X'78'",
        "status='sent'",
        "pending_targets=1",
        "provider_target_count=1",
        "private_enqueued_count=1",
        "provider_accepted_count=1",
        "provider_failed_count=1",
        "private_rejected_count=1",
        "identity_state='unknown'",
        "identity_state='live '",
        "status='historical_unverifiable '",
        "usage_payload_bytes=1",
        "identity_state='live'",
    ] {
        let result = sqlx::query(&format!(
            "UPDATE ordinary_messages SET {assignment} WHERE op_id='C16-History'"
        ))
        .execute(&mut inspect)
        .await;
        let error = result.expect_err(assignment);
        assert_check(error);
    }
    for (scope, op, thing, body) in [
        (channel, "C16-History", Some("synthetic-thing"), "same"),
        (channel, "c16-history", Some("synthetic-thing"), "changed"),
        (other, "C16-HISTORY", Some("synthetic-thing"), "same"),
        (channel, "C16-History", Some("other-thing"), "same"),
    ] {
        let mut replay = request(scope, op);
        replay.thing_id = thing.map(str::to_owned);
        replay.body = Some(body.into());
        assert!(matches!(
            ordinary.accept(replay).await,
            Err(KernelError::Control {
                status: 409,
                code: "historical_identity_unverifiable",
                ..
            })
        ));
    }
    let status = ordinary.status("C16-History").await.unwrap();
    assert_eq!(status["identity_state"], "legacy_unverifiable");
    assert_eq!(status["status"], "historical_unverifiable");
    assert_eq!(status["dispatch_status"], "not_attempted");
    assert!(status["delivery_id"].is_null() && status["delivery_expires_at"].is_null());
    assert_eq!(status["channel_id"], channel_id);
    assert_eq!(status["thing_id"], "synthetic-thing");
    let target_count: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_targets")
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(target_count, 0);

    // Generated binary keys fold ASCII case without a collation's PAD SPACE
    // equality. A historical case alias cannot become a second authority row.
    let alias_error = sqlx::query("INSERT INTO ordinary_messages(message_id,op_id,channel_id,payload_blob,payload_bytes,accepted_at,dedupe_until,status,updated_at,identity_state) VALUES(?,'c16-history',?,X'',0,?,?,'historical_unverifiable',?,'legacy_unverifiable')")
        .bind(crate::util::generate_hex_id_128()).bind(&channel_id).bind(now()).bind(now()+86_400_000).bind(now())
        .execute(&mut inspect).await.unwrap_err();
    match alias_error {
        sqlx::Error::Database(error) => assert_eq!(
            error
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .number(),
            1062
        ),
        other => panic!("expected native unique-key violation, got {other}"),
    }
    let padded: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ordinary_messages WHERE historical_op=CAST('c16-history ' AS BINARY))")
        .fetch_one(&mut inspect).await.unwrap();
    assert_eq!(
        padded, 0,
        "historical alias equality must preserve trailing bytes"
    );

    // Same expiry, >one bounded batch: NULL delivery IDs cannot strand history.
    let expired = now() - 1_000;
    for n in 0..260 {
        history(
            &mut inspect,
            &channel_id,
            &format!("c16-gc-{n:03}"),
            expired,
        )
        .await;
    }
    sqlx::query("ANALYZE TABLE ordinary_messages")
        .fetch_all(&mut inspect)
        .await
        .unwrap();
    let plan: String = sqlx::query_scalar("EXPLAIN FORMAT=JSON SELECT EXISTS(SELECT 1 FROM ordinary_messages WHERE historical_op=CAST(LOWER(CONVERT(? USING utf8mb4)) AS BINARY) AND dedupe_until>?)")
        .bind("c16-history").bind(now()).fetch_one(&mut inspect).await.unwrap();
    let plan = serde_json::from_str::<serde_json::Value>(&plan)
        .unwrap()
        .to_string();
    assert!(
        plan.contains("\"key\":\"ordinary_historical_op\"")
            && !plan.contains("\"access_type\":\"ALL\""),
        "{plan}"
    );
    assert_eq!(ordinary.maintenance().await.unwrap(), 256);
    let remaining: Vec<String> = sqlx::query_scalar(
        "SELECT CAST(op_id AS CHAR CHARACTER SET utf8mb4) FROM ordinary_messages WHERE op_id LIKE 'c16-gc-%' ORDER BY op_id",
    )
    .fetch_all(&mut inspect)
    .await
    .unwrap();
    assert_eq!(
        remaining,
        (256..260)
            .map(|n| format!("c16-gc-{n:03}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(ordinary.maintenance().await.unwrap(), 4);
    assert_eq!(ordinary.maintenance().await.unwrap(), 0);

    // Retained independent PKs still reserve IDs even past their timestamp.
    let collision = "10".repeat(16);
    let free = "20".repeat(16);
    reservation(&mut inspect, &collision).await;
    ordinary
        .mysql_test_store()
        .delivery_candidates
        .lock()
        .unwrap()
        .extend([collision.clone(), free.clone()]);
    let live_request = request(channel, "C16-Live");
    let live = ordinary.accept(live_request.clone()).await.unwrap();
    assert_eq!(live.delivery_id, free);
    let duplicate = ordinary.accept(live_request).await.unwrap();
    assert_eq!(duplicate.delivery_id, live.delivery_id);
    let lowercase = ordinary.accept(request(channel, "c16-live")).await.unwrap();
    assert_ne!(
        lowercase.delivery_id, live.delivery_id,
        "new live op IDs remain case-sensitive"
    );
    assert!(matches!(
        ordinary.accept(request(other, "C16-Live")).await,
        Err(KernelError::ScopeConflict)
    ));
    let mut changed = request(channel, "C16-Live");
    changed.body = Some("changed live body".into());
    assert!(matches!(
        ordinary.accept(changed).await,
        Err(KernelError::Conflict)
    ));
    for assignment in ["delivery_id=NULL", "fingerprint=NULL", "expires_at=NULL"] {
        let error = sqlx::query(&format!(
            "UPDATE ordinary_messages SET {assignment} WHERE op_id='C16-Live'"
        ))
        .execute(&mut inspect)
        .await
        .expect_err(assignment);
        assert_check(error);
    }
    ordinary
        .mysql_test_store()
        .delivery_candidates
        .lock()
        .unwrap()
        .extend(std::iter::repeat_n(collision.clone(), 4));
    let before: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_messages")
        .fetch_one(&mut inspect)
        .await
        .unwrap();
    assert!(matches!(
        ordinary
            .accept(request(channel, "c16-collision-exhausted"))
            .await,
        Err(KernelError::Unavailable)
    ));
    assert!(
        ordinary
            .mysql_test_store()
            .delivery_candidates
            .lock()
            .unwrap()
            .is_empty()
    );
    let after: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_messages")
        .fetch_one(&mut inspect)
        .await
        .unwrap();
    assert_eq!(before, after, "exhaustion cannot retain a partial identity");
    assert!(matches!(
        ordinary.status("c16-collision-exhausted").await,
        Err(KernelError::NotFound)
    ));
    let retained: String =
        sqlx::query_scalar("SELECT CAST(delivery_id AS CHAR CHARACTER SET utf8mb4) FROM dispatch_delivery_dedupe WHERE dedupe_key=?")
            .bind(format!("delivery:{collision}"))
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(retained, collision);
    let usage: (i64, i64, i64) = sqlx::query_as(
        "SELECT messages,targets,bytes FROM ordinary_ledger_usage WHERE singleton=1",
    )
    .fetch_one(&mut inspect)
    .await
    .unwrap();
    assert_eq!(
        usage,
        (0, 0, 0),
        "zero-target synthetic history/live rows own no delivery resources"
    );

    // Controlled native Provider flow: no network send occurs. The normal
    // ledger freezes the target, then accepts a synthetic provider receipt.
    let key = "c16-mysql-provider";
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: key.into(),
            platform: "android".into(),
            channel_type: "fcm".into(),
            provider_token: Some("c16-synthetic-provider-token".into()),
            updated_at: now(),
        })
        .await
        .unwrap();
    storage
        .private_subscribe_channel(channel, PrivateDeviceId::derive(key).into_inner())
        .await
        .unwrap();
    let delivery_request = request(channel, "c16-provider-pull-ack");
    let delivered = ordinary.accept(delivery_request.clone()).await.unwrap();
    let batch = ordinary.claim_reserved("FCM", 1, false).await.unwrap();
    assert_eq!(batch.tickets.len(), 1);
    let ticket = &batch.tickets[0];
    assert!(ordinary.authorize_ticket(ticket).await.unwrap());
    ordinary
        .settle(ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    let pulled = ordinary
        .pull(key, Some(&delivered.delivery_id))
        .await
        .unwrap();
    assert_eq!(pulled["items"][0]["delivery_id"], delivered.delivery_id);
    assert_eq!(pulled["items"][0]["payload"]["body"], "unchanged 中文 body");
    assert_eq!(
        ordinary
            .ack(key, vec![delivered.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    let released: (i64,i64,i64) = sqlx::query_as("SELECT payload_bytes,OCTET_LENGTH(payload_blob),(SELECT CAST(COUNT(*) AS SIGNED) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id) FROM ordinary_messages m WHERE delivery_id=?")
        .bind(&delivered.delivery_id).fetch_one(&mut inspect).await.unwrap();
    assert_eq!(released, (0, 0, 0));
    assert_eq!(
        ordinary.accept(delivery_request).await.unwrap().delivery_id,
        delivered.delivery_id
    );
    assert!(
        ordinary.pull(key, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // A separate Private recipient releases the same single-ledger body by
    // the normal claim/ACK path, without a transport session or fixture server.
    let private_key = "c16-mysql-private";
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: private_key.into(),
            platform: "android".into(),
            channel_type: "private".into(),
            provider_token: None,
            updated_at: now(),
        })
        .await
        .unwrap();
    storage
        .private_subscribe_channel(other, PrivateDeviceId::derive(private_key).into_inner())
        .await
        .unwrap();
    let private = ordinary
        .accept(request(other, "c16-private-ack"))
        .await
        .unwrap();
    let route = ordinary.private_route(private_key).await.unwrap();
    let grants = ordinary
        .private_claim(&route, "c16-synthetic-session", 1)
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].delivery_id, private.delivery_id);
    assert!(ordinary.private_ack(&route, &grants[0]).await.unwrap());
    assert_eq!(ordinary.private_pending_count(None).await.unwrap(), 0);

    inspect.close().await.unwrap();
    storage.close_ordinary_storage().await.unwrap();
    owner.shutdown().await.unwrap();
}
