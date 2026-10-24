//! Native PG contracts using normal product initialization and synthetic data.
//! No HTTP, client, fixture server or external Provider acceptance is implied.
use super::owner::ProductOwner;
use super::private_model::PrivateLedgerConfig;
use super::store::{Health, now};
use super::{AcceptRequest, Config, KernelError};
use crate::storage::{DeviceRouteRecordRow, Platform, PrivateDeviceId, Storage, StorageInitConfig};
use sqlx::{Connection, PgConnection};
use std::sync::Arc;

async fn subscribe(
    storage: &Storage,
    channel: [u8; 16],
    key: &str,
    kind: &str,
    token: Option<&str>,
) -> DeviceRouteRecordRow {
    let route = DeviceRouteRecordRow {
        device_key: key.into(),
        platform: "android".into(),
        channel_type: kind.into(),
        provider_token: token.map(str::to_owned),
        updated_at: now(),
    };
    storage.upsert_device_route(&route).await.unwrap();
    storage
        .private_subscribe_channel(channel, PrivateDeviceId::derive(key).into_inner())
        .await
        .unwrap();
    route
}

fn request(channel: [u8; 16], op: &str) -> AcceptRequest {
    AcceptRequest {
        authorized_channel: Some(channel),
        channel_id: crate::value::ChannelId::from(channel).to_string(),
        op_id: Some(op.into()),
        title: "PG waiting 中文".into(),
        body: Some("unchanged body 🙂".into()),
        thing_id: Some("00112233445566778899aabbccddeeff".into()),
        occurred_at: Some(now()),
        ..AcceptRequest::default()
    }
}

async fn assert_released(connection: &mut PgConnection, delivery: &str) {
    let released: (i64, i64, i64) = sqlx::query_as(
        "SELECT payload_bytes,octet_length(payload_blob)::bigint, \
         (SELECT COUNT(*) FROM ordinary_targets t WHERE t.delivery_id=m.delivery_id) \
         FROM ordinary_messages m WHERE delivery_id=$1",
    )
    .bind(delivery)
    .fetch_one(connection)
    .await
    .unwrap();
    assert_eq!(released, (0, 0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires approved fresh isolated PostgreSQL PUSHGO_C10_PG_TEST_URL"]
async fn postgres_product_private_waiting_preserves_provider_and_global_execution() {
    let url = std::env::var("PUSHGO_C10_PG_TEST_URL").expect("approved fresh QA URL");
    let parsed = reqwest::Url::parse(&url).expect("QA URL should parse");
    assert!(matches!(parsed.scheme(), "postgres" | "postgresql"));
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1") | Some("localhost")
    ));
    assert_eq!(parsed.port_or_known_default().unwrap_or(5432), 32772);
    assert!(
        parsed
            .path()
            .trim_start_matches('/')
            .starts_with("c10_synthetic_")
    );
    let mut inspect = PgConnection::connect(&url).await.expect("QA PG probe");
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema NOT IN ('pg_catalog','information_schema')",
    )
    .fetch_one(&mut inspect)
    .await
    .unwrap();
    assert_eq!(tables, 0, "refuse any used database, including a prior run");
    inspect.close().await.unwrap();

    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(&url), health.clone())
        .await
        .unwrap();
    let storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(url.clone()),
        managed_upgrade: false,
        mcp_enabled: false,
        ..StorageInitConfig::default()
    })
    .await
    .unwrap();
    let ordinary = storage
        .initialize_ordinary(
            Config {
                max_messages: i64::MAX,
                max_targets: 4,
                max_payload_bytes: i64::MAX,
                private: PrivateLedgerConfig {
                    enabled: true,
                    max_pending_per_device: 1,
                    max_pending: 1,
                },
                ..Config::default()
            },
            health,
        )
        .await
        .unwrap();
    let password = crate::util::generate_hex_id_128();
    let channel = storage
        .upsert_private_channel(None, Some("PG mixed QA"), &password)
        .await
        .unwrap()
        .channel_id;
    let private_key = "c10-pg-waiting-private";
    let provider_key = "c10-pg-healthy-provider";
    let mut route = subscribe(&storage, channel, private_key, "private", None).await;
    subscribe(
        &storage,
        channel,
        provider_key,
        "fcm",
        Some("c10-pg-synthetic-fcm-token"),
    )
    .await;
    let first_request = request(channel, "c10-pg-waiting-first");
    let first = ordinary.accept(first_request.clone()).await.unwrap();
    let private = ordinary.private_route(private_key).await.unwrap();
    let first_grants = ordinary
        .private_claim(&private, "pg-first-window", 8)
        .await
        .unwrap();
    assert_eq!(first_grants.len(), 1);
    assert_eq!(first_grants[0].delivery_id, first.delivery_id);

    // Both the device and global execution windows are already full. The
    // second complete fanout is still accepted against the system target cap.
    let second = ordinary
        .accept(request(channel, "c10-pg-waiting-second"))
        .await
        .unwrap();
    assert_eq!(ordinary.private_pending_count(None).await.unwrap(), 2);
    let replay = ordinary.accept(first_request.clone()).await.unwrap();
    assert_eq!(
        (&replay.delivery_id, &replay.message_id),
        (&first.delivery_id, &first.message_id)
    );
    assert!(matches!(
        ordinary
            .accept(request(channel, "c10-pg-system-full"))
            .await,
        Err(KernelError::Capacity)
    ));
    assert!(matches!(
        ordinary.status("c10-pg-system-full").await,
        Err(KernelError::NotFound)
    ));
    let mut inspect = PgConnection::connect(&url).await.unwrap();
    let reserved: i64 =
        sqlx::query_scalar("SELECT targets FROM ordinary_ledger_usage WHERE singleton=1")
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(
        reserved, 4,
        "rejected admission cannot leave a partial fanout"
    );

    route.updated_at = now();
    storage.upsert_device_route(&route).await.unwrap();
    let current = ordinary.private_route(private_key).await.unwrap();
    assert_eq!(current.route_generation, private.route_generation);
    assert!(ordinary.private_authorize(&first_grants[0]).await.unwrap());
    assert!(
        ordinary
            .private_claim(&current, "pg-device-full", 8)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ordinary
            .private_executing_count(Some(private_key))
            .await
            .unwrap(),
        1
    );
    assert_eq!(ordinary.private_executing_count(None).await.unwrap(), 1);

    let provider = ordinary.claim_reserved("FCM", 8, false).await.unwrap();
    assert_eq!(
        provider.tickets.len(),
        2,
        "healthy Provider must not wait for Private"
    );
    for ticket in provider.tickets {
        assert!(ordinary.authorize_ticket(&ticket).await.unwrap());
        ordinary
            .settle(&ticket, "provider_accepted", 200, "", now(), None)
            .await
            .unwrap();
    }
    assert_eq!(
        ordinary
            .ack(
                provider_key,
                vec![first.delivery_id.clone(), second.delivery_id.clone()]
            )
            .await
            .unwrap(),
        2
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_messages WHERE payload_bytes>0")
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(
        retained, 2,
        "Private waiting/claim still owns the canonical body"
    );

    let other_channel = storage
        .upsert_private_channel(None, Some("PG global QA"), &password)
        .await
        .unwrap()
        .channel_id;
    let other_key = "c10-pg-other-private";
    subscribe(&storage, other_channel, other_key, "private", None).await;
    let other = ordinary
        .accept(request(other_channel, "c10-pg-global-waiting"))
        .await
        .unwrap();
    let other_route = ordinary.private_route(other_key).await.unwrap();
    assert_eq!(
        ordinary
            .private_executing_count(Some(other_key))
            .await
            .unwrap(),
        0
    );
    assert!(
        ordinary
            .private_claim(&other_route, "pg-global-full", 8)
            .await
            .unwrap()
            .is_empty()
    );

    // ACK is the durable execution-window release. Another device can claim
    // before this first device consumes its next waiting target.
    assert!(
        ordinary
            .private_ack(&current, &first_grants[0])
            .await
            .unwrap()
    );
    assert!(
        !ordinary
            .private_ack(&current, &first_grants[0])
            .await
            .unwrap()
    );
    assert_released(&mut inspect, &first.delivery_id).await;
    let other_grants = ordinary
        .private_claim(&other_route, "pg-other-window", 8)
        .await
        .unwrap();
    assert_eq!(other_grants.len(), 1);
    assert_eq!(other_grants[0].delivery_id, other.delivery_id);
    assert!(
        ordinary
            .private_claim(&current, "pg-global-busy-again", 8)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ordinary
            .private_ack(&other_route, &other_grants[0])
            .await
            .unwrap()
    );
    assert_released(&mut inspect, &other.delivery_id).await;
    let next = ordinary
        .private_claim(&current, "pg-next-window", 8)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].delivery_id, second.delivery_id);
    let payload: serde_json::Value = serde_json::from_slice(&next[0].payload).unwrap();
    assert_eq!(payload["message_id"], second.message_id);
    assert!(ordinary.private_ack(&current, &next[0]).await.unwrap());
    assert_released(&mut inspect, &second.delivery_id).await;
    assert_eq!(ordinary.private_pending_count(None).await.unwrap(), 0);
    assert_eq!(ordinary.private_executing_count(None).await.unwrap(), 0);

    let done = ordinary.accept(first_request).await.unwrap();
    assert_eq!(
        (&done.delivery_id, &done.message_id),
        (&first.delivery_id, &first.message_id)
    );
    assert_eq!(done.dispatch_status, "attempted_accepted");
    assert_released(&mut inspect, &first.delivery_id).await;
    let usage: (i64, i64, i64) = sqlx::query_as(
        "SELECT messages,targets,bytes FROM ordinary_ledger_usage WHERE singleton=1",
    )
    .fetch_one(&mut inspect)
    .await
    .unwrap();
    assert_eq!(usage, (0, 0, 0));

    // A normal canonical identity merge changes Pull ownership while a sent
    // external request still belongs to its original frozen receipt owner.
    let merge_channel = storage
        .upsert_private_channel(None, Some("PG merge QA"), &password)
        .await
        .unwrap()
        .channel_id;
    let old_key = "c10-pg-frozen-owner";
    let winner_key = "c10-pg-current-owner";
    let merge_token = "c10-pg-synthetic-merge-token";
    let mut winner = subscribe(&storage, merge_channel, old_key, "fcm", Some(merge_token)).await;
    let merge_request = request(merge_channel, "c10-pg-late-merged-receipt");
    let merged_message = ordinary.accept(merge_request.clone()).await.unwrap();
    let mut claimed = ordinary.claim_reserved("FCM", 1, false).await.unwrap();
    assert_eq!(claimed.tickets.len(), 1);
    let frozen = claimed.tickets.remove(0);
    assert_eq!(frozen.device_key, old_key);
    assert!(ordinary.authorize_ticket(&frozen).await.unwrap());
    winner.device_key = winner_key.into();
    winner.updated_at = now();
    storage
        .replace_device_identity(&winner, Some(old_key))
        .await
        .unwrap();
    assert!(!ordinary.authorize_ticket(&frozen).await.unwrap());
    let ownership: (String, String) =
        sqlx::query_as("SELECT device_key,pull_owner FROM ordinary_targets WHERE delivery_id=$1")
            .bind(&merged_message.delivery_id)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(ownership, (old_key.into(), winner_key.into()));
    ordinary
        .settle(&frozen, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    assert_eq!(
        ordinary.status("c10-pg-late-merged-receipt").await.unwrap()["status"],
        "sent"
    );
    let pulled = ordinary
        .pull(winner_key, Some(&merged_message.delivery_id))
        .await
        .unwrap();
    assert_eq!(
        pulled["items"][0]["delivery_id"],
        merged_message.delivery_id
    );
    assert!(
        ordinary.pull(old_key, None).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ordinary
            .ack(old_key, vec![merged_message.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        ordinary
            .ack(winner_key, vec![merged_message.delivery_id.clone()])
            .await
            .unwrap(),
        1
    );
    assert_released(&mut inspect, &merged_message.delivery_id).await;
    let merged_replay = ordinary.accept(merge_request).await.unwrap();
    assert_eq!(merged_replay.delivery_id, merged_message.delivery_id);
    assert_eq!(merged_replay.message_id, merged_message.message_id);

    // Retire then re-register the same token through normal control APIs.
    // The new canonical generation must not revive an old issued request/Pull.
    let retired_message = ordinary
        .accept(request(merge_channel, "c10-pg-retired-epoch"))
        .await
        .unwrap();
    let mut claimed = ordinary.claim_reserved("FCM", 1, false).await.unwrap();
    assert_eq!(claimed.tickets.len(), 1);
    let retired = claimed.tickets.remove(0);
    assert!(ordinary.authorize_ticket(&retired).await.unwrap());
    storage
        .retire_provider_token(Platform::ANDROID, merge_token)
        .await
        .unwrap();
    assert!(!ordinary.authorize_ticket(&retired).await.unwrap());
    winner.updated_at = now();
    storage.upsert_device_route(&winner).await.unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT ordinary_route_generation FROM devices WHERE device_key=$1")
            .bind(winner_key)
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert!(generation > retired.route_generation);
    assert!(!ordinary.authorize_ticket(&retired).await.unwrap());
    assert!(
        ordinary
            .pull(winner_key, Some(&retired_message.delivery_id))
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ordinary
            .ack(winner_key, vec![retired_message.delivery_id.clone()])
            .await
            .unwrap(),
        0
    );
    ordinary
        .settle(&retired, "provider_accepted", 200, "", now(), None)
        .await
        .unwrap();
    ordinary.maintenance().await.unwrap();
    assert_released(&mut inspect, &retired_message.delivery_id).await;
    assert!(!ordinary.authorize_ticket(&retired).await.unwrap());

    // Exercise native channel-marker UPSERT with the existing canonical owner,
    // after the retirement assertions above have completed. Waiting uses the
    // same ordinary ledger; it is not an independently accepted Widget body.
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: winner_key.into(),
            platform: "ios".into(),
            channel_type: "private".into(),
            provider_token: None,
            updated_at: now(),
        })
        .await
        .unwrap();
    let widget_token = "a6".repeat(32);
    let widgets = [
        crate::api::handlers::widget_push::WIDGET_KIND_UNREAD,
        crate::api::handlers::widget_push::WIDGET_KIND_WATCH_SUMMARY,
    ]
    .map(|kind| crate::storage::WidgetPushSubscriptionRecord {
        device_key: winner_key.into(),
        platform: "ios".into(),
        token: widget_token.clone(),
        widget_kind: kind.into(),
        family: "systemSmall".into(),
        schema_version: 1,
        created_at: now(),
        updated_at: now(),
    });
    storage
        .upsert_widget_push_subscriptions(
            winner_key,
            Platform::IOS,
            &widget_token,
            &widgets,
            1,
            now(),
        )
        .await
        .unwrap();
    let first_widget_request = request(merge_channel, "c10-pg-widget-first");
    let first_widget = ordinary.accept(first_widget_request.clone()).await.unwrap();
    let old_marker = ordinary.next_widget_refresh().await.unwrap().unwrap();
    assert_eq!(old_marker.delivery_id, first_widget.delivery_id);
    let latest_widget = ordinary
        .accept(request(merge_channel, "c10-pg-widget-latest"))
        .await
        .unwrap();
    let latest_marker = ordinary.next_widget_refresh().await.unwrap().unwrap();
    assert_eq!(latest_marker.delivery_id, latest_widget.delivery_id);
    assert!(latest_marker.coalesce_order > old_marker.coalesce_order);
    let markers: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_widget_refresh WHERE channel_id=$1")
            .bind(merge_channel.as_slice())
            .fetch_one(&mut inspect)
            .await
            .unwrap();
    assert_eq!(markers, 1);
    assert_eq!(
        ordinary
            .accept(first_widget_request)
            .await
            .unwrap()
            .delivery_id,
        first_widget.delivery_id
    );
    assert!(
        !ordinary
            .complete_widget_refresh(&old_marker.delivery_id, old_marker.coalesce_order)
            .await
            .unwrap()
    );
    assert_eq!(
        ordinary
            .next_widget_refresh()
            .await
            .unwrap()
            .unwrap()
            .delivery_id,
        latest_widget.delivery_id
    );
    assert!(
        ordinary
            .complete_widget_refresh(&latest_marker.delivery_id, latest_marker.coalesce_order)
            .await
            .unwrap()
    );

    inspect.close().await.unwrap();
    storage.close_ordinary_storage().await.unwrap();
    owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires fresh loopback c10_synthetic_scan_* DB in PUSHGO_PROVIDER_SCAN_PG_URL_FILE"]
async fn postgres_provider_scan_native_seek_ceiling_and_scope_contract() {
    let path = std::env::var_os("PUSHGO_PROVIDER_SCAN_PG_URL_FILE").expect("isolated QA URL file");
    let url = std::fs::read_to_string(path).unwrap();
    let url = url.trim();
    let parsed = reqwest::Url::parse(url).unwrap();
    assert!(matches!(parsed.scheme(), "postgres" | "postgresql"));
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1") | Some("localhost")
    ));
    assert!(
        parsed
            .path()
            .trim_start_matches('/')
            .starts_with("c10_synthetic_scan_")
    );
    let mut inspect = PgConnection::connect(url).await.expect("fresh isolated PG");
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')").fetch_one(&mut inspect).await.unwrap();
    assert_eq!(existing, 0, "refuse every existing or reused database");
    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(url), health.clone())
        .await
        .unwrap();
    let storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(url.into()),
        managed_upgrade: false,
        mcp_enabled: false,
        ..StorageInitConfig::default()
    })
    .await
    .unwrap();
    let ordinary = storage
        .initialize_ordinary(
            Config {
                max_messages: i64::MAX,
                ..Config::default()
            },
            health,
        )
        .await
        .unwrap();
    let password = crate::util::generate_hex_id_128();
    let channel = storage
        .upsert_private_channel(None, Some("PG native scan QA"), &password)
        .await
        .unwrap()
        .channel_id;
    let device = "c10-pg-provider-scan";
    let mut route = subscribe(&storage, channel, device, "fcm", Some("c10-pg-scan-token")).await;
    let epoch = ordinary.pull_route_epoch(device).await.unwrap();
    assert!(epoch.is_some());
    let mut accepted = Vec::new();
    for index in 0..5 {
        accepted.push(
            ordinary
                .accept(request(channel, &format!("native-scan-{index}")))
                .await
                .unwrap()
                .delivery_id,
        );
    }
    // Explicit equal-time fixture over normally accepted rows tests both seek keys.
    let tied = now() - 10_000;
    let changed = sqlx::query("UPDATE ordinary_targets SET accepted_at=$1")
        .bind(tied)
        .execute(&mut inspect)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(changed, 5);
    accepted.sort();
    let ceiling = ordinary.pull_scan_ceiling(device).await.unwrap().unwrap();
    assert_eq!(ceiling.at, tied);
    assert_eq!(ceiling.delivery_id, *accepted.last().unwrap());
    ordinary
        .accept(request(channel, "native-scan-appended-after-ceiling"))
        .await
        .unwrap();
    let mut cursor = None;
    let mut actual = Vec::new();
    let mut reads = 0;
    while cursor.as_ref().is_none_or(|key| key != &ceiling) {
        reads += 1;
        assert!(reads <= 3);
        let rows = ordinary
            .pull_scan_page(device, cursor.as_ref(), &ceiling, 2)
            .await
            .unwrap();
        assert!(!rows.is_empty() && rows.len() <= 2);
        for row in rows {
            cursor = Some(row.position.clone());
            actual.push(row.position.delivery_id);
        }
    }
    assert_eq!(actual, accepted);
    assert_eq!(reads, 3);
    let derived = crate::routing::derive_private_device_id(device);
    for index in 0..5 {
        let id = format!("pg-retained-scan-{index}");
        let fields = hashbrown::HashMap::from_iter([
            ("entity_type".into(), "event".into()),
            ("delivery_id".into(), id.clone()),
            ("title".into(), "retained".into()),
        ]);
        let bytes = postcard::to_allocvec(&crate::private::protocol::PrivatePayloadEnvelope {
            payload_version: 1,
            data: fields,
        })
        .unwrap();
        storage
            .enqueue_provider_pull_item(
                derived,
                &id,
                &crate::storage::PrivateMessage {
                    size: bytes.len(),
                    payload: bytes.into(),
                    sent_at: now(),
                    expires_at: now() + 300_000,
                },
                Platform::ANDROID,
                "c10-pg-scan-token",
            )
            .await
            .unwrap();
    }
    sqlx::query("UPDATE provider_pull_queue SET created_at=$1")
        .bind(tied)
        .execute(&mut inspect)
        .await
        .unwrap();
    let ceiling = storage
        .peek_provider_scan_ceiling(derived, now())
        .await
        .unwrap()
        .unwrap();
    let first = storage
        .peek_provider_scan_page(derived, now(), None, &ceiling, 2)
        .await
        .unwrap();
    let second = storage
        .peek_provider_scan_page(derived, now(), Some(&first[1].position), &ceiling, 2)
        .await
        .unwrap();
    let third = storage
        .peek_provider_scan_page(derived, now(), Some(&second[1].position), &ceiling, 2)
        .await
        .unwrap();
    assert_eq!(
        [first, second, third]
            .into_iter()
            .flatten()
            .map(|row| row.position.delivery_id)
            .collect::<Vec<_>>(),
        (0..5)
            .map(|index| format!("pg-retained-scan-{index}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        storage
            .peek_provider_candidates(derived, now(), 10)
            .await
            .unwrap()
            .len(),
        5,
        "scan never consumes a retained responsibility"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM ordinary_targets WHERE acked_at IS NULL"
        )
        .fetch_one(&mut inspect)
        .await
        .unwrap(),
        6
    );
    route.provider_token = Some("c10-pg-scan-token-rotated".into());
    storage.upsert_device_route(&route).await.unwrap();
    assert_ne!(ordinary.pull_route_epoch(device).await.unwrap(), epoch);
    inspect.close().await.unwrap();
    storage.close_ordinary_storage().await.unwrap();
    owner.shutdown().await.unwrap();
}
