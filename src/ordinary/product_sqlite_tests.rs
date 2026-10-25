//! Focused normal Storage/application contracts, with isolated new databases.
//! These do not claim client or network acceptance and never start the fixture.
use super::owner::ProductOwner;
use super::store::{Health, now};
use super::{AcceptRequest, Config, KernelError, OrdinaryStore};
use crate::storage::{DeviceId, DeviceRouteRecordRow, PrivateDeviceId, Storage, StorageInitConfig};
use sqlx::{Connection, Row, SqliteConnection};
use std::sync::Arc;

struct Product {
    directory: tempfile::TempDir,
    storage: Storage,
    ordinary: OrdinaryStore,
    owner: ProductOwner,
    fixture_credential: String,
}
impl Product {
    async fn open() -> Self {
        Self::reopen(tempfile::tempdir().unwrap()).await
    }
    async fn reopen(directory: tempfile::TempDir) -> Self {
        Self::reopen_with_private(directory, true).await
    }
    async fn reopen_with_private(directory: tempfile::TempDir, private_enabled: bool) -> Self {
        Self::reopen_with_private_config(
            directory,
            super::private_model::PrivateLedgerConfig {
                enabled: private_enabled,
                ..super::private_model::PrivateLedgerConfig::default()
            },
            i64::MAX,
        )
        .await
    }
    async fn reopen_with_private_config(
        directory: tempfile::TempDir,
        private_config: super::private_model::PrivateLedgerConfig,
        max_targets: i64,
    ) -> Self {
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("product.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url),
            mcp_enabled: false,
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config {
            max_messages: i64::MAX,
            max_targets,
            max_payload_bytes: i64::MAX,
            ..Config::default()
        };
        config.private = private_config;
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
        Self {
            directory,
            storage,
            ordinary,
            owner,
            fixture_credential: crate::util::generate_hex_id_128(),
        }
    }
    async fn inspect(&self) -> SqliteConnection {
        SqliteConnection::connect(&format!(
            "sqlite://{}?mode=ro",
            self.directory.path().join("product.db").display()
        ))
        .await
        .unwrap()
    }
    async fn stop(self) -> tempfile::TempDir {
        self.storage.close_ordinary_storage().await.unwrap();
        self.owner.shutdown().await.unwrap();
        self.directory
    }
    async fn channel(&self) -> [u8; 16] {
        self.storage
            .upsert_private_channel(None, Some("ordinary integration"), &self.fixture_credential)
            .await
            .unwrap()
            .channel_id
    }
    async fn route(
        &self,
        channel: [u8; 16],
        key: &str,
        platform: &str,
        kind: &str,
        token: Option<&str>,
    ) {
        self.storage
            .upsert_device_route(&route(key, platform, kind, token))
            .await
            .unwrap();
        self.storage
            .private_subscribe_channel(channel, device_id(key))
            .await
            .unwrap();
    }
    fn request(&self, channel: [u8; 16], op: &str) -> AcceptRequest {
        AcceptRequest {
            channel_id: crate::value::ChannelId::from(channel).to_string(),
            authorized_channel: Some(channel),
            op_id: Some(op.into()),
            title: "中文 ordinary".into(),
            body: Some("body \"escape\" 🛰".into()),
            thing_id: Some("thing-synthetic".into()),
            occurred_at: Some(now()),
            ..AcceptRequest::default()
        }
    }
}
fn device_id(key: &str) -> DeviceId {
    PrivateDeviceId::derive(key).into()
}
fn route(key: &str, platform: &str, kind: &str, token: Option<&str>) -> DeviceRouteRecordRow {
    DeviceRouteRecordRow {
        device_key: key.into(),
        platform: platform.into(),
        channel_type: kind.into(),
        provider_token: token.map(str::to_owned),
        updated_at: now(),
    }
}

fn maintenance_samples(profile: &serde_json::Value, statement: &str) -> u64 {
    profile["paths"]["maintenance"]["statements"][statement]["samples"]
        .as_u64()
        .unwrap_or(0)
}

fn assert_expiry_profile_delta(
    before: &serde_json::Value,
    after: &serde_json::Value,
    expiry_statements: u64,
) {
    assert_eq!(
        maintenance_samples(after, "maintenance_expiry_probe")
            - maintenance_samples(before, "maintenance_expiry_probe"),
        1
    );
    for statement in [
        "maintenance_expiry_count",
        "maintenance_expiry_ack",
        "maintenance_expiry_status",
        "maintenance_expiry_delete",
        "maintenance_expiry_payload",
    ] {
        assert_eq!(
            maintenance_samples(after, statement) - maintenance_samples(before, statement),
            expiry_statements,
            "{statement}"
        );
    }
}

#[tokio::test]
async fn sqlite_product_empty_expiry_probe_preserves_other_maintenance() {
    let product = Product::open().await;
    let channel = product.channel().await;
    product
        .route(
            channel,
            "expiry-guard-owner",
            "android",
            "fcm",
            Some("synthetic-expiry-guard"),
        )
        .await;
    let mut request = product.request(channel, "expiry-guard-fresh");
    request.ttl = Some(now() + 600_000);
    let accepted = product.ordinary.accept(request).await.unwrap();
    let before = product.ordinary.counters.profile.snapshot();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
    assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 0);
    let path = product.directory.path().join("product.db");
    let mut inspect = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let live: (bool, i64) = sqlx::query_as("SELECT payload_bytes>0,(SELECT COUNT(*) FROM ordinary_targets WHERE delivery_id=?) FROM ordinary_messages WHERE delivery_id=?")
        .bind(&accepted.delivery_id).bind(&accepted.delivery_id)
        .fetch_one(&mut inspect).await.unwrap();
    assert_eq!(live, (true, 1));

    // Explicit synthetic control/metadata injections exercise independent cleanup
    // in a no-expired-body turn; they are not migration or external-send evidence.
    let cutoff = now() - 10_000;
    sqlx::query("INSERT INTO ordinary_retired_provider_tokens(platform,provider_token,control_epoch) SELECT platform,provider_token,control_epoch+1 FROM ordinary_targets WHERE delivery_id=?")
        .bind(&accepted.delivery_id).execute(&mut inspect).await.unwrap();
    sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,coalesce_order,accepted_at,expires_at) VALUES(?,?,1,?,?)")
        .bind(&accepted.delivery_id).bind(channel.as_slice()).bind(cutoff-1).bind(cutoff)
        .execute(&mut inspect).await.unwrap();
    sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,'expiry-guard-history-id','expiry-guard-history',?,NULL,x'',0,?,NULL,?,'historical_unverifiable',?,'legacy_unverifiable')")
        .bind(crate::value::ChannelId::from(channel).to_string())
        .bind(cutoff-1).bind(cutoff).bind(cutoff-1).execute(&mut inspect).await.unwrap();
    let before = product.ordinary.counters.profile.snapshot();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 1);
    assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 0);
    let remaining: (i64, i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM ordinary_targets),(SELECT COUNT(*) FROM ordinary_widget_refresh),(SELECT COUNT(*) FROM ordinary_retired_provider_tokens),(SELECT COUNT(*) FROM ordinary_messages WHERE op_id='expiry-guard-history'),(SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?)")
        .bind(&accepted.delivery_id).fetch_one(&mut inspect).await.unwrap();
    assert_eq!(remaining, (0, 0, 0, 0, 0));
    inspect.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_expiry_probe_is_inclusive_indexed_and_keeps_bounded_batches() {
    let product = Product::open().await;
    let channel = product.channel().await;
    product
        .route(
            channel,
            "expiry-batch-owner",
            "android",
            "fcm",
            Some("synthetic-expiry-batch"),
        )
        .await;
    for index in 0..257 {
        let mut request = product.request(channel, &format!("expiry-guard-batch-{index}"));
        request.ttl = Some(now() + 600_000);
        product.ordinary.accept(request).await.unwrap();
    }
    let path = product.directory.path().join("product.db");
    let mut inspect = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let cutoff = now() - 10_000;
    sqlx::query("UPDATE ordinary_messages SET expires_at=?")
        .bind(cutoff)
        .execute(&mut inspect)
        .await
        .unwrap();
    for (at, expected) in [(cutoff - 1, false), (cutoff, true)] {
        let matches: bool = sqlx::query_scalar(super::store::MAINTENANCE_EXPIRY_PROBE_SQL)
            .bind(at)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
        assert_eq!(matches, expected);
    }
    const EXPLAIN_PROBE_SQL: &str = "EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM ordinary_messages WHERE expires_at<=? AND payload_bytes>0)";
    assert_eq!(
        EXPLAIN_PROBE_SQL
            .strip_prefix("EXPLAIN QUERY PLAN ")
            .unwrap(),
        super::store::MAINTENANCE_EXPIRY_PROBE_SQL
    );
    let plan = sqlx::query(EXPLAIN_PROBE_SQL)
        .bind(cutoff)
        .fetch_all(&mut inspect)
        .await
        .unwrap();
    assert!(plan.iter().any(|row| {
        let detail: String = row.get("detail");
        detail.contains("SEARCH ordinary_messages ")
            && detail.contains("INDEX ordinary_messages_expiry")
    }));
    assert!(!plan.iter().any(|row| {
        row.get::<String, _>("detail")
            .contains("SCAN ordinary_messages")
    }));

    for (bodies, targets, failed) in [(1, 1, 256), (0, 0, 257)] {
        let before = product.ordinary.counters.profile.snapshot();
        assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
        assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 1);
        let counts: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM ordinary_messages WHERE payload_bytes>0),(SELECT COUNT(*) FROM ordinary_targets),(SELECT SUM(provider_failed_count) FROM ordinary_messages),(SELECT COUNT(*) FROM ordinary_messages)")
            .fetch_one(&mut inspect).await.unwrap();
        assert_eq!(counts, (bodies, targets, failed, 257));
    }
    let before = product.ordinary.counters.profile.snapshot();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
    assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 0);
    inspect.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_expiry_probe_preserves_unknown_running_receipt() {
    let product = Product::open().await;
    let channel = product.channel().await;
    product
        .route(
            channel,
            "expiry-running-owner",
            "android",
            "fcm",
            Some("synthetic-expiry-running"),
        )
        .await;
    let mut request = product.request(channel, "expiry-guard-running");
    request.ttl = Some(now() + 600_000);
    let accepted = product.ordinary.accept(request).await.unwrap();
    let batch = product
        .ordinary
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap();
    assert_eq!(batch.tickets.len(), 1);
    let path = product.directory.path().join("product.db");
    let mut inspect = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let cutoff = now() - 10_000;
    sqlx::query("UPDATE ordinary_messages SET expires_at=?,dedupe_until=? WHERE delivery_id=?")
        .bind(cutoff)
        .bind(cutoff)
        .bind(&accepted.delivery_id)
        .execute(&mut inspect)
        .await
        .unwrap();
    let before = product.ordinary.counters.profile.snapshot();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
    assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 1);
    let held: (i64, String, bool, i64) = sqlx::query_as("SELECT m.payload_bytes,t.state,t.acked_at IS NOT NULL,m.provider_failed_count FROM ordinary_messages m JOIN ordinary_targets t ON t.delivery_id=m.delivery_id WHERE m.delivery_id=?")
        .bind(&accepted.delivery_id).fetch_one(&mut inspect).await.unwrap();
    assert_eq!(held, (0, "running".into(), true, 0));
    let before = product.ordinary.counters.profile.snapshot();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
    assert_expiry_profile_delta(&before, &product.ordinary.counters.profile.snapshot(), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ordinary_targets WHERE delivery_id=? AND state='running'"
        )
        .bind(&accepted.delivery_id)
        .fetch_one(&mut inspect)
        .await
        .unwrap(),
        1
    );
    product
        .ordinary
        .settle(&batch.tickets[0], "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 1);
    inspect.close().await.unwrap();
    product.stop().await;
}

// These rows are explicit unit-test injections, not old-main migration evidence.
#[tokio::test]
async fn sqlite_product_historical_identity_rejects_aliases_scopes_and_cleans_by_original_deadline()
{
    let product = Product::open().await;
    let channel = product.channel().await;
    let path = product.directory.path().join("product.db");
    let mut write = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let accepted_at = now() - 86_400_000;
    sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,thing_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,?,?,?,NULL,NULL,x'',0,?,NULL,?,'historical_unverifiable',?,'legacy_unverifiable')")
        .bind("0123456789abcdef0123456789abcdef").bind("Historic:Mixed")
        .bind(crate::value::ChannelId::from(channel).to_string())
        .bind(accepted_at).bind(now()+60_000).bind(accepted_at).execute(&mut write).await.unwrap();
    for op in ["Historic:Mixed", "historic:mixed", "HISTORIC:MIXED"] {
        let request = product.request(channel, op); // Different Thing scope is deliberately valid input.
        assert!(matches!(
            product.ordinary.accept(request).await,
            Err(KernelError::Control {
                status: 409,
                code: "historical_identity_unverifiable",
                ..
            })
        ));
    }
    let status = product.ordinary.status("Historic:Mixed").await.unwrap();
    assert_eq!(status["identity_state"], "legacy_unverifiable");
    assert_eq!(status["accepted_at"], accepted_at);
    assert!(status["delivery_id"].is_null());
    assert!(status["delivery_expires_at"].is_null());
    assert_eq!(
        product
            .ordinary
            .target_status("Historic:Mixed")
            .await
            .unwrap()["targets"],
        serde_json::json!([])
    );
    let plan=sqlx::query("EXPLAIN QUERY PLAN SELECT op_id FROM ordinary_messages WHERE (op_id=? OR (identity_state='legacy_unverifiable' AND lower(op_id)=lower(?))) AND dedupe_until>?")
        .bind("historic:mixed").bind("historic:mixed").bind(now()).fetch_all(&mut write).await.unwrap();
    assert!(plan.iter().any(|r| {
        r.get::<String, _>("detail")
            .contains("ordinary_historical_op")
    }));
    assert!(!plan.iter().any(|r| {
        r.get::<String, _>("detail")
            .contains("SCAN ordinary_messages")
    }));
    // A live identity cannot hide a missing delivery/fingerprint/TTL behind NULL.
    assert!(
        sqlx::query(
            "UPDATE ordinary_messages SET identity_state='live' WHERE op_id='Historic:Mixed'"
        )
        .execute(&mut write)
        .await
        .is_err()
    );
    sqlx::query("UPDATE ordinary_messages SET dedupe_until=? WHERE op_id='Historic:Mixed'")
        .bind(now() - 1)
        .execute(&mut write)
        .await
        .unwrap();
    product.ordinary.maintenance().await.unwrap();
    assert!(matches!(
        product.ordinary.status("Historic:Mixed").await,
        Err(KernelError::NotFound)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ordinary_messages")
            .fetch_one(&mut write)
            .await
            .unwrap(),
        0
    );
    let first = product
        .ordinary
        .accept(product.request(channel, "New:Case"))
        .await
        .unwrap();
    let second = product
        .ordinary
        .accept(product.request(channel, "new:case"))
        .await
        .unwrap();
    assert_ne!(
        first.message_id, second.message_id,
        "live op case semantics remain unchanged"
    );
    write.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_historical_retention_batches_do_not_skip_null_delivery_ids() {
    let product = Product::open().await;
    let channel = product.channel().await;
    let path = product.directory.path().join("product.db");
    let mut write = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let cutoff = now() - 1;
    let mut tx = write.begin().await.unwrap();
    for index in 0..260 {
        sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,?,?,?,NULL,x'',0,?,NULL,?,'historical_unverifiable',?,'legacy_unverifiable')")
            .bind(format!("{index:032x}")).bind(format!("same-expiry-{index}"))
            .bind(crate::value::ChannelId::from(channel).to_string())
            .bind(cutoff-7*86_400_000).bind(cutoff).bind(cutoff-1).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 256);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ordinary_messages")
            .fetch_one(&mut write)
            .await
            .unwrap(),
        4
    );
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 4);
    assert_eq!(product.ordinary.maintenance().await.unwrap(), 0);
    write.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_new_delivery_allocation_respects_independent_legacy_reservations() {
    let product = Product::open().await;
    let channel = product.channel().await;
    let reserved = "0123456789abcdef0123456789abcdef";
    let chosen = "fedcba9876543210fedcba9876543210";
    let dispatch = product.directory.path().join("product.dispatch.db");
    let mut write = SqliteConnection::connect(&format!("sqlite://{}", dispatch.display()))
        .await
        .unwrap();
    sqlx::query("INSERT INTO dispatch_delivery_dedupe(dedupe_key,delivery_id,state,created_at,updated_at) VALUES(?,?,'sent',?,?)")
        .bind(format!("delivery:{reserved}")).bind(reserved).bind(now()).bind(now()).execute(&mut write).await.unwrap();
    product
        .ordinary
        .sqlite_for_test()
        .hooks
        .delivery_candidates
        .lock()
        .unwrap()
        .extend([reserved.to_owned(), chosen.to_owned()]);
    let accepted = product
        .ordinary
        .accept(product.request(channel, "new-after-historical-collision"))
        .await
        .unwrap();
    assert_eq!(accepted.delivery_id, chosen);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT delivery_id FROM dispatch_delivery_dedupe WHERE dedupe_key=?"
        )
        .bind(format!("delivery:{reserved}"))
        .fetch_one(&mut write)
        .await
        .unwrap(),
        reserved
    );
    product
        .ordinary
        .sqlite_for_test()
        .hooks
        .delivery_candidates
        .lock()
        .unwrap()
        .extend(std::iter::repeat_n(reserved.to_owned(), 4));
    assert!(matches!(
        product
            .ordinary
            .accept(product.request(channel, "collision-budget-exhausted"))
            .await,
        Err(KernelError::Unavailable)
    ));
    assert!(matches!(
        product.ordinary.status("collision-budget-exhausted").await,
        Err(KernelError::NotFound)
    ));
    write.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_freezes_all_ordinary_targets_and_releases_one_body() {
    let product = Product::open().await;
    let channel = product.channel().await;
    let apple = "a1".repeat(32);
    let watch = "a2".repeat(32);
    let mac = "a3".repeat(32);
    product
        .route(
            channel,
            "android",
            "android",
            "fcm",
            Some("synthetic-fcm-token-ordinary"),
        )
        .await;
    product
        .route(channel, "apple", "ios", "apns", Some(&apple))
        .await;
    product
        .route(channel, "watch", "watchos", "apns", Some(&watch))
        .await;
    product
        .route(channel, "mac", "macos", "apns", Some(&mac))
        .await;
    product
        .route(
            channel,
            "windows",
            "windows",
            "wns",
            Some("https://ordinary.invalid/wns/synthetic"),
        )
        .await;
    product
        .route(channel, "private", "mqtt", "private", None)
        .await;
    let original = product.request(channel, "product-all-targets");
    let accepted = product.ordinary.accept(original.clone()).await.unwrap();
    let initial = product
        .ordinary
        .status("product-all-targets")
        .await
        .unwrap();
    assert_eq!(
        product
            .ordinary
            .target_status("product-all-targets")
            .await
            .unwrap()["targets"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    product
        .storage
        .private_unsubscribe_channel(channel, device_id("private"))
        .await
        .unwrap();
    product
        .route(
            channel,
            "later",
            "android",
            "fcm",
            Some("later-fcm-token-ordinary"),
        )
        .await;
    let duplicate = product.ordinary.accept(original.clone()).await.unwrap();
    assert_eq!(duplicate.message_id, accepted.message_id);
    assert_eq!(duplicate.delivery_id, accepted.delivery_id);
    assert_eq!(
        initial["accepted_at"],
        product
            .ordinary
            .status("product-all-targets")
            .await
            .unwrap()["accepted_at"]
    );
    let mut changed = original.clone();
    changed.thing_id = Some("another-thing".into());
    assert!(matches!(
        product.ordinary.accept(changed).await,
        Err(KernelError::ScopeConflict)
    ));
    for provider in ["FCM", "APNS", "WNS"] {
        let batch = product
            .ordinary
            .claim_reserved(provider, 8, false)
            .await
            .unwrap();
        assert_eq!(batch.tickets.len(), if provider == "APNS" { 3 } else { 1 });
        for ticket in batch.tickets {
            assert_eq!(ticket.payload["thing_id"], "thing-synthetic");
            assert_eq!(ticket.payload["message_id"], accepted.message_id);
            if ticket.platform == "watchos" {
                assert_eq!(
                    ticket.watch_alert_deadline,
                    Some(ticket.accepted_at + 30 * 60_000)
                );
            }
            assert!(product.ordinary.authorize_ticket(&ticket).await.unwrap());
            product
                .ordinary
                .settle(&ticket, "provider_accepted", 200, "", now(), None)
                .await
                .unwrap();
            assert_eq!(
                product
                    .ordinary
                    .ack(&ticket.device_key, vec![accepted.delivery_id.clone()])
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                product
                    .ordinary
                    .ack(&ticket.device_key, vec![accepted.delivery_id.clone()])
                    .await
                    .unwrap(),
                0
            );
        }
    }
    let private_route = product.ordinary.private_route("private").await.unwrap();
    let tickets = product
        .ordinary
        .private_claim(&private_route, "synthetic-session", 1)
        .await
        .unwrap();
    assert_eq!(tickets.len(), 1, "unsubscribe preserves accepted targets");
    let payload: serde_json::Value = serde_json::from_slice(&tickets[0].payload).unwrap();
    assert_eq!(payload["body"], "body \"escape\" 🛰");
    assert!(
        product
            .ordinary
            .private_ack(&private_route, &tickets[0])
            .await
            .unwrap()
    );
    assert!(
        !product
            .ordinary
            .private_ack(&private_route, &tickets[0])
            .await
            .unwrap()
    );
    let mut inspect = product.inspect().await;
    let identity=sqlx::query("SELECT payload_bytes,length(payload_blob) AS actual,thing_id,dedupe_until-accepted_at AS retained FROM ordinary_messages WHERE delivery_id=?").bind(&accepted.delivery_id).fetch_one(&mut inspect).await.unwrap();
    assert_eq!(identity.get::<i64, _>("payload_bytes"), 0);
    assert_eq!(identity.get::<i64, _>("actual"), 0);
    assert_eq!(identity.get::<String, _>("thing_id"), "thing-synthetic");
    assert_eq!(identity.get::<i64, _>("retained"), 30 * 86_400_000);
    let old:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM sender_submit_status)+(SELECT COUNT(*) FROM semantic_id_registry)").fetch_one(&mut inspect).await.unwrap();
    assert_eq!(old, 0, "ordinary identities have one owner");
    let duplicates:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('ordinary_devices','ordinary_channels','ordinary_channel_subscriptions')").fetch_one(&mut inspect).await.unwrap();
    assert_eq!(duplicates, 0);
    inspect.close().await.unwrap();
    let completed = product.ordinary.accept(original).await.unwrap();
    assert_eq!(completed.delivery_id, accepted.delivery_id);
    assert_eq!(completed.dispatch_status, "attempted_accepted");
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_private_clear_and_negative_receipt_preserve_active_route() {
    let product = Product::open().await;
    let channel = product.channel().await;
    product
        .route(channel, "private", "mqtt", "private", None)
        .await;
    let first = product
        .ordinary
        .accept(product.request(channel, "private-before-clear"))
        .await
        .unwrap();
    let old_route = product.ordinary.private_route("private").await.unwrap();
    let old = product
        .ordinary
        .private_claim(&old_route, "old-session", 1)
        .await
        .unwrap()
        .remove(0);
    product
        .storage
        .upsert_device_route(&route("private", "mqtt", "private", None))
        .await
        .unwrap();
    assert!(
        product.ordinary.private_authorize(&old).await.unwrap(),
        "same-route sync keeps generation"
    );
    product
        .storage
        .clear_ordinary_private_channel(&route("private", "mqtt", "private", None))
        .await
        .unwrap();
    assert!(!product.ordinary.private_authorize(&old).await.unwrap());
    assert!(
        !product
            .ordinary
            .private_ack(&old_route, &old)
            .await
            .unwrap()
    );
    assert_eq!(
        product
            .storage
            .list_private_subscribed_channels_for_device(device_id("private"))
            .await
            .unwrap(),
        vec![channel]
    );
    let second = product
        .ordinary
        .accept(product.request(channel, "private-after-clear"))
        .await
        .unwrap();
    let current = product.ordinary.private_route("private").await.unwrap();
    assert_eq!(current.route_generation, old_route.route_generation);
    let ticket = product
        .ordinary
        .private_claim(&current, "new-session", 1)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(ticket.delivery_id, second.delivery_id);
    assert!(
        product
            .ordinary
            .private_reject(&current, &ticket, "invalid_payload")
            .await
            .unwrap()
    );
    assert!(
        !product
            .ordinary
            .private_reject(&current, &ticket, "invalid_payload")
            .await
            .unwrap()
    );
    let mut inspect = product.inspect().await;
    let first_body: i64 =
        sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?")
            .bind(&first.delivery_id)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(first_body, 0);
    let negative = sqlx::query(
        "SELECT payload_bytes,private_rejected_count FROM ordinary_messages WHERE delivery_id=?",
    )
    .bind(&second.delivery_id)
    .fetch_one(&mut inspect)
    .await
    .unwrap();
    assert_eq!(negative.get::<i64, _>("payload_bytes"), 0);
    assert_eq!(negative.get::<i64, _>("private_rejected_count"), 1);
    inspect.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_coalescing_keeps_frozen_receipt_and_restart_replay() {
    let product = Product::open().await;
    let channel = product.channel().await;
    product
        .route(
            channel,
            "old-owner",
            "android",
            "fcm",
            Some("same-synthetic-token"),
        )
        .await;
    let original = product.request(channel, "coalescing-restart");
    let accepted = product.ordinary.accept(original.clone()).await.unwrap();
    let ticket = product
        .ordinary
        .claim_reserved("FCM", 1, false)
        .await
        .unwrap()
        .tickets
        .remove(0);
    product
        .storage
        .upsert_device_route(&route(
            "new-owner",
            "android",
            "fcm",
            Some("same-synthetic-token"),
        ))
        .await
        .unwrap();
    assert!(!product.ordinary.authorize_ticket(&ticket).await.unwrap());
    assert_eq!(
        product.ordinary.pull("new-owner", None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    product
        .ordinary
        .settle(&ticket, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        product.ordinary.status("coalescing-restart").await.unwrap()["status"],
        "sent"
    );
    let directory = product.stop().await;
    let product = Product::reopen(directory).await;
    let replay = product.ordinary.accept(original).await.unwrap();
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert_eq!(replay.message_id, accepted.message_id);
    assert_eq!(
        product
            .ordinary
            .pull("new-owner", Some(&accepted.delivery_id))
            .await
            .unwrap()["items"][0]["delivery_id"],
        accepted.delivery_id
    );
    assert_eq!(
        product
            .ordinary
            .ack("new-owner", vec![accepted.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert!(
        product.ordinary.pull("new-owner", None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_transition_attachment_is_not_reused_by_identity_coalescing() {
    use crate::storage::{RouteChannelType, StoreError};

    // Each case first borrows the one delivery writer through the real product
    // transition, then coalesces on that same pool while a core write is held.
    // A leaked attachment makes this ordinary operation wait on its own core TX.
    for exit in ["committed", "stale-return", "native-error"] {
        let product = Product::open().await;
        let channel = product.channel().await;
        product
            .route(channel, "transition-owner", "android", "private", None)
            .await;
        let request = product.request(channel, "transition-attachment");
        let accepted = product.ordinary.accept(request.clone()).await.unwrap();
        let private_route = product
            .ordinary
            .private_route("transition-owner")
            .await
            .unwrap();
        let private_ticket = product
            .ordinary
            .private_claim(&private_route, "before-transition", 1)
            .await
            .unwrap()
            .remove(0);
        let mut provider = route(
            "transition-owner",
            "android",
            "fcm",
            Some("transition-synthetic-fcm-token"),
        );
        // The normal transition deliberately ignores stale route timestamps.
        provider.updated_at = now().saturating_add(100);
        if exit == "native-error" {
            let mut invalid = provider.clone();
            invalid.provider_token = None;
            let error = product
                .storage
                .transition_device_route(&invalid, RouteChannelType::Private, 30, 1024)
                .await
                .unwrap_err();
            assert!(matches!(error, StoreError::InvalidDeviceToken));
            assert!(
                product
                    .ordinary
                    .private_authorize(&private_ticket)
                    .await
                    .unwrap()
            );
            // Exercise the next normal borrower after an in-transaction error.
            product
                .storage
                .upsert_device_route(&provider)
                .await
                .unwrap();
        } else {
            product
                .storage
                .transition_device_route(&provider, RouteChannelType::Private, 30, 1024)
                .await
                .unwrap();
            if exit == "stale-return" {
                assert_eq!(
                    product
                        .storage
                        .transition_device_route(&provider, RouteChannelType::Fcm, 30, 1024)
                        .await
                        .unwrap(),
                    0
                );
            }
        }
        assert!(
            !product
                .ordinary
                .private_authorize(&private_ticket)
                .await
                .unwrap()
        );
        let mut winner = provider.clone();
        winner.device_key = "transition-winner".into();
        winner.updated_at += 1;
        product.storage.upsert_device_route(&winner).await.unwrap();
        let items = product
            .ordinary
            .pull("transition-winner", None)
            .await
            .unwrap();
        assert_eq!(items["items"].as_array().unwrap().len(), 1, "{exit}");
        assert_eq!(items["items"][0]["delivery_id"], accepted.delivery_id);
        assert_eq!(
            items["items"][0]["payload"]["body"],
            request.body.as_deref().unwrap()
        );
        let replay = product.ordinary.accept(request).await.unwrap();
        assert_eq!(replay.delivery_id, accepted.delivery_id);
        assert_eq!(replay.message_id, accepted.message_id);
        assert_eq!(
            product
                .ordinary
                .ack("transition-winner", vec![accepted.delivery_id.clone()])
                .await
                .unwrap(),
            1
        );
        assert!(
            !product
                .ordinary
                .private_ack(&private_route, &private_ticket)
                .await
                .unwrap()
        );
        let mut inspect = product.inspect().await;
        let bytes: i64 =
            sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?")
                .bind(&accepted.delivery_id)
                .fetch_one(&mut inspect)
                .await
                .unwrap();
        assert_eq!(bytes, 0, "{exit}");
        inspect.close().await.unwrap();
        product.stop().await;
    }
}

#[tokio::test]
async fn sqlite_product_widget_marker_uses_original_clock_without_body_or_fanout_authority() {
    use crate::api::handlers::widget_push::{WIDGET_KIND_UNREAD, WIDGET_KIND_WATCH_SUMMARY};
    use crate::storage::{Platform, WidgetPushSubscriptionRecord};

    for private_enabled in [true, false] {
        let product =
            Product::reopen_with_private(tempfile::tempdir().unwrap(), private_enabled).await;
        let channel = product.channel().await;
        product
            .route(channel, "widget-owner", "ios", "private", None)
            .await;
        let token = "a4".repeat(32);
        let widgets = [WIDGET_KIND_UNREAD, WIDGET_KIND_WATCH_SUMMARY].map(|kind| {
            WidgetPushSubscriptionRecord {
                device_key: "widget-owner".into(),
                platform: "ios".into(),
                token: token.clone(),
                widget_kind: kind.into(),
                family: "systemSmall".into(),
                schema_version: 1,
                created_at: now(),
                updated_at: now(),
            }
        });
        product
            .storage
            .upsert_widget_push_subscriptions(
                "widget-owner",
                Platform::IOS,
                &token,
                &widgets,
                1,
                now(),
            )
            .await
            .unwrap();
        let request = product.request(channel, "widget-marker-first");
        let accepted = product.ordinary.accept(request.clone()).await.unwrap();
        let first = product
            .ordinary
            .next_widget_refresh()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.delivery_id, accepted.delivery_id);
        assert_eq!(first.channel_id, channel);
        assert!(first.coalesce_order > 0);
        let targets = product
            .ordinary
            .widget_refresh_targets(channel, None, 1)
            .await
            .unwrap();
        assert_eq!(targets.len(), 1, "Widget kinds share one token target");
        assert_eq!(targets[0].token, token);
        if private_enabled {
            let route = product
                .ordinary
                .private_route("widget-owner")
                .await
                .unwrap();
            let ticket = product
                .ordinary
                .private_claim(&route, "widget-body-release", 1)
                .await
                .unwrap()
                .remove(0);
            assert!(product.ordinary.private_ack(&route, &ticket).await.unwrap());
        } else {
            assert!(
                product
                    .ordinary
                    .target_status("widget-marker-first")
                    .await
                    .unwrap()["targets"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
        let mut inspect = product.inspect().await;
        let bytes: i64 =
            sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?")
                .bind(&accepted.delivery_id)
                .fetch_one(&mut inspect)
                .await
                .unwrap();
        assert_eq!(bytes, 0);
        inspect.close().await.unwrap();
        let replay = product.ordinary.accept(request).await.unwrap();
        assert_eq!(replay.delivery_id, accepted.delivery_id);
        assert_eq!(
            product
                .ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .unwrap()
                .coalesce_order,
            first.coalesce_order
        );
        let mut expired = product.request(channel, "widget-marker-expired");
        expired.ttl = Some(0);
        product.ordinary.accept(expired).await.unwrap();
        let second = product
            .ordinary
            .accept(product.request(channel, "widget-marker-second"))
            .await
            .unwrap();
        assert!(
            !product
                .ordinary
                .complete_widget_refresh(&first.delivery_id, first.coalesce_order + 1)
                .await
                .unwrap()
        );
        assert!(
            !product
                .ordinary
                .complete_widget_refresh(&first.delivery_id, first.coalesce_order)
                .await
                .unwrap()
        );
        let next = product
            .ordinary
            .next_widget_refresh()
            .await
            .unwrap()
            .unwrap();
        let mut inspect = product.inspect().await;
        let pending_markers: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_widget_refresh WHERE channel_id=?")
                .bind(channel.as_slice())
                .fetch_one(&mut inspect)
                .await
                .unwrap();
        assert_eq!(
            pending_markers, 1,
            "one latest-state obligation per channel"
        );
        inspect.close().await.unwrap();
        assert_eq!(next.delivery_id, second.delivery_id);
        assert_eq!(
            next.coalesce_order,
            first.coalesce_order + 1,
            "duplicate and expired sends do not reserve the dispatch clock"
        );
        let directory = product.stop().await;
        let product = Product::reopen_with_private(directory, private_enabled).await;
        assert_eq!(
            product
                .ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .unwrap()
                .delivery_id,
            second.delivery_id
        );
        assert!(
            product
                .ordinary
                .complete_widget_refresh(&next.delivery_id, next.coalesce_order)
                .await
                .unwrap()
        );
        assert!(
            product
                .ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .is_none()
        );
        product.stop().await;
    }
}

#[tokio::test]
async fn sqlite_product_private_waiting_does_not_block_healthy_provider() {
    use crate::storage::{
        PrivateMessage, PrivateOutboxBatchEntry, PrivateOutboxEntry, RouteChannelType,
    };
    let product = Product::reopen_with_private_config(
        tempfile::tempdir().unwrap(),
        super::private_model::PrivateLedgerConfig {
            enabled: true,
            max_pending_per_device: 1,
            max_pending: 1,
        },
        4,
    )
    .await;
    let channel = product.channel().await;
    product
        .route(channel, "congested-private", "mqtt", "private", None)
        .await;
    product
        .route(
            channel,
            "healthy-provider",
            "android",
            "fcm",
            Some("healthy-synthetic-fcm-token"),
        )
        .await;
    let at = now();
    product
        .storage
        .insert_private_message(
            "retained-event-capacity",
            &PrivateMessage {
                payload: Arc::from(&b"synthetic retained event capacity"[..]),
                size: b"synthetic retained event capacity".len(),
                sent_at: at,
                expires_at: at + 60_000,
            },
        )
        .await
        .unwrap();
    product
        .storage
        .enqueue_private_outbox_batch(
            &[PrivateOutboxBatchEntry {
                device_id: device_id("congested-private"),
                entry: PrivateOutboxEntry {
                    delivery_id: "retained-event-capacity".into(),
                    status: "pending".into(),
                    occurred_at: at,
                    created_at: at,
                    next_attempt_at: at,
                    updated_at: at,
                    ..PrivateOutboxEntry::default()
                },
            }],
            1,
            1,
            None,
        )
        .await
        .unwrap();
    let first_request = product.request(channel, "mixed-waiting-first");
    let first = product
        .ordinary
        .accept(first_request.clone())
        .await
        .unwrap();
    let second = product
        .ordinary
        .accept(product.request(channel, "mixed-waiting-second"))
        .await
        .unwrap();
    for op in ["mixed-waiting-first", "mixed-waiting-second"] {
        assert_eq!(
            product.ordinary.target_status(op).await.unwrap()["targets"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        2
    );
    // Replays do not re-run a now-full system target admission budget.
    let replay = product.ordinary.accept(first_request).await.unwrap();
    assert_eq!(replay.delivery_id, first.delivery_id);
    assert_eq!(replay.message_id, first.message_id);
    assert!(matches!(
        product
            .ordinary
            .accept(product.request(channel, "mixed-waiting-over-system"))
            .await,
        Err(KernelError::Capacity)
    ));
    assert!(matches!(
        product.ordinary.status("mixed-waiting-over-system").await,
        Err(KernelError::NotFound)
    ));
    // Already accepted waiting is not a reason to reject same-Private sync or
    // reconnect; it consumes the system target responsibility budget, not execution grants.
    let mut unchanged = route("congested-private", "mqtt", "private", None);
    unchanged.updated_at = now().saturating_add(100);
    product
        .storage
        .upsert_device_route(&unchanged)
        .await
        .unwrap();
    unchanged.updated_at += 1;
    product
        .storage
        .transition_device_route(&unchanged, RouteChannelType::Private, 30, 1)
        .await
        .unwrap();
    let private_route = product
        .ordinary
        .private_route("congested-private")
        .await
        .unwrap();
    assert!(
        product
            .ordinary
            .private_claim(&private_route, "full-legacy", 8)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        product
            .ordinary
            .private_executing_count(Some("congested-private"))
            .await
            .unwrap(),
        0
    );
    let provider = product
        .ordinary
        .claim_reserved("FCM", 8, false)
        .await
        .unwrap();
    assert_eq!(provider.tickets.len(), 2);
    for ticket in provider.tickets {
        assert!(product.ordinary.authorize_ticket(&ticket).await.unwrap());
        product
            .ordinary
            .settle(&ticket, "provider_accepted", 200, "", now(), None)
            .await
            .unwrap();
    }
    assert!(
        product
            .storage
            .ack_private_delivery(device_id("congested-private"), "retained-event-capacity")
            .await
            .unwrap()
    );
    let mut remaining = std::collections::HashMap::from([
        (first.delivery_id.clone(), first.message_id.clone()),
        (second.delivery_id.clone(), second.message_id.clone()),
    ]);
    for group in ["after-release-first", "after-release-second"] {
        let tickets = product
            .ordinary
            .private_claim(&private_route, group, 8)
            .await
            .unwrap();
        assert_eq!(tickets.len(), 1);
        let ticket = &tickets[0];
        let payload: serde_json::Value = serde_json::from_slice(&ticket.payload).unwrap();
        assert_eq!(
            payload["message_id"],
            remaining.remove(&ticket.delivery_id).unwrap()
        );
        assert_eq!(
            product
                .ordinary
                .private_executing_count(Some("congested-private"))
                .await
                .unwrap(),
            1
        );
        assert!(
            product
                .ordinary
                .private_claim(&private_route, "already-executing", 1)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            product
                .ordinary
                .private_ack(&private_route, ticket)
                .await
                .unwrap()
        );
    }
    assert!(remaining.is_empty());
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        0
    );
    assert_eq!(
        product
            .ordinary
            .private_executing_count(Some("congested-private"))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        product
            .ordinary
            .ack(
                "healthy-provider",
                vec![first.delivery_id, second.delivery_id]
            )
            .await
            .unwrap(),
        2
    );
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_private_claim_reserves_global_execution_window() {
    let product = Product::reopen_with_private_config(
        tempfile::tempdir().unwrap(),
        super::private_model::PrivateLedgerConfig {
            enabled: true,
            max_pending_per_device: 2,
            max_pending: 1,
        },
        2,
    )
    .await;
    let channel = product.channel().await;
    for device in ["first-private-executor", "second-private-executor"] {
        product
            .route(channel, device, "mqtt", "private", None)
            .await;
    }
    let accepted = product
        .ordinary
        .accept(product.request(channel, "global-private-execution"))
        .await
        .unwrap();
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        2
    );
    let first = product
        .ordinary
        .private_route("first-private-executor")
        .await
        .unwrap();
    let second = product
        .ordinary
        .private_route("second-private-executor")
        .await
        .unwrap();
    let tickets = product
        .ordinary
        .private_claim(&first, "first-global-grant", 2)
        .await
        .unwrap();
    assert_eq!(tickets.len(), 1);
    assert_eq!(
        product
            .ordinary
            .private_executing_count(None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        product
            .ordinary
            .private_executing_count(Some("second-private-executor"))
            .await
            .unwrap(),
        0
    );
    assert!(
        product
            .ordinary
            .private_claim(&second, "global-full", 2)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        product
            .ordinary
            .private_ack(&first, &tickets[0])
            .await
            .unwrap()
    );
    let tickets = product
        .ordinary
        .private_claim(&second, "second-global-grant", 2)
        .await
        .unwrap();
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].delivery_id, accepted.delivery_id);
    assert!(
        product
            .ordinary
            .private_ack(&second, &tickets[0])
            .await
            .unwrap()
    );
    assert_eq!(
        product
            .ordinary
            .private_executing_count(None)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        0
    );
    let mut inspect = product.inspect().await;
    let bytes: i64 =
        sqlx::query_scalar("SELECT payload_bytes FROM ordinary_messages WHERE delivery_id=?")
            .bind(&accepted.delivery_id)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(bytes, 0);
    inspect.close().await.unwrap();
    product.stop().await;
}

#[tokio::test]
async fn sqlite_product_empty_fanout_replay_remains_not_attempted() {
    let product = Product::open().await;
    let channel = product.channel().await;
    let original = product.request(channel, "empty-frozen-fanout");
    let accepted = product.ordinary.accept(original.clone()).await.unwrap();
    assert_eq!(accepted.dispatch_status, "not_attempted");
    let first_status = product
        .ordinary
        .status("empty-frozen-fanout")
        .await
        .unwrap();
    product
        .route(channel, "later-private", "mqtt", "private", None)
        .await;
    let replay = product.ordinary.accept(original.clone()).await.unwrap();
    assert_eq!(replay.delivery_id, accepted.delivery_id);
    assert_eq!(replay.message_id, accepted.message_id);
    assert_eq!(replay.dispatch_status, "not_attempted");
    let replay_status = product
        .ordinary
        .status("empty-frozen-fanout")
        .await
        .unwrap();
    assert_eq!(replay_status["accepted_at"], first_status["accepted_at"]);
    assert_eq!(replay_status["expires_at"], first_status["expires_at"]);
    assert!(
        product
            .ordinary
            .target_status("empty-frozen-fanout")
            .await
            .unwrap()["targets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        0
    );
    // An explicit new operation freezes the now-subscribed recipient. Retrying
    // the accepted empty operation never changes its original frozen fanout.
    let mut new_request = original;
    new_request.op_id = Some("nonempty-after-explicit-new-op".into());
    let fresh = product.ordinary.accept(new_request).await.unwrap();
    assert_ne!(fresh.message_id, accepted.message_id);
    assert_ne!(fresh.delivery_id, accepted.delivery_id);
    assert_eq!(fresh.dispatch_status, "attempted_accepted");
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        1
    );
    let route = product
        .ordinary
        .private_route("later-private")
        .await
        .unwrap();
    let tickets = product
        .ordinary
        .private_claim(&route, "new-operation-group", 1)
        .await
        .unwrap();
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].delivery_id, fresh.delivery_id);
    assert!(
        product
            .ordinary
            .private_authorize(&tickets[0])
            .await
            .unwrap()
    );
    assert!(
        product
            .ordinary
            .private_ack(&route, &tickets[0])
            .await
            .unwrap()
    );
    assert_eq!(
        product.ordinary.private_pending_count(None).await.unwrap(),
        0
    );
    product.stop().await;
}
