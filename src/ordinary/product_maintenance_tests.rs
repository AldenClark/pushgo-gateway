//! Normal Storage maintenance must service the product ordinary ledger too.
//! All payloads and controls are synthetic. Native tests refuse a used database;
//! no runtime, HTTP fixture, external Provider, or client is started here.
use super::owner::ProductOwner;
use super::store::{Health, now};
use super::{AcceptRequest, Config, OrdinaryStore};
use crate::storage::{
    DeviceRouteRecordRow, MaintenanceCleanupConfig, PrivateDeviceId, Storage, StorageInitConfig,
};
use sqlx::{Connection, MySqlConnection, PgConnection, Row, SqliteConnection};
use std::sync::Arc;

const ROWS: i64 = 257;
const RETENTION_MS: i64 = 30 * 86_400_000;

enum Inspect {
    Sqlite(SqliteConnection),
    Postgres(PgConnection),
    MySql(MySqlConnection),
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    identities: i64,
    bodies: i64,
    targets: i64,
    markers: i64,
    full_retention: i64,
}

impl Inspect {
    async fn connect(url: &str) -> Self {
        if url.starts_with("sqlite:") {
            Self::Sqlite(
                SqliteConnection::connect(url)
                    .await
                    .expect("synthetic SQLite"),
            )
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Self::Postgres(
                PgConnection::connect(url)
                    .await
                    .expect("isolated PostgreSQL"),
            )
        } else {
            Self::MySql(MySqlConnection::connect(url).await.expect("isolated MySQL"))
        }
    }

    async fn refuse_used_database(&mut self) {
        let tables: i64 = match self {
            Self::Sqlite(connection) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .fetch_one(connection)
            .await
            .unwrap(),
            Self::Postgres(connection) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema NOT IN ('pg_catalog','information_schema')",
            )
            .fetch_one(connection)
            .await
            .unwrap(),
            Self::MySql(connection) => sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.tables \
                 WHERE table_schema=DATABASE()",
            )
            .fetch_one(connection)
            .await
            .unwrap(),
        };
        assert_eq!(tables, 0, "refuse an existing or previously used database");
    }

    async fn counts(&mut self) -> Counts {
        let row = match self {
            Self::Sqlite(connection) => {
                let row = sqlx::query(
                    "SELECT (SELECT COUNT(*) FROM ordinary_messages) AS identities,\
                     (SELECT COUNT(*) FROM ordinary_messages WHERE payload_bytes>0) AS bodies,\
                     (SELECT COUNT(*) FROM ordinary_targets) AS targets,\
                     (SELECT COUNT(*) FROM ordinary_widget_refresh) AS markers,\
                     (SELECT COUNT(*) FROM ordinary_messages WHERE dedupe_until-accepted_at=?) AS retained",
                )
                .bind(RETENTION_MS)
                .fetch_one(connection)
                .await
                .unwrap();
                return Counts {
                    identities: row.get("identities"),
                    bodies: row.get("bodies"),
                    targets: row.get("targets"),
                    markers: row.get("markers"),
                    full_retention: row.get("retained"),
                };
            }
            Self::Postgres(connection) => {
                let row = sqlx::query(
                    "SELECT (SELECT COUNT(*) FROM ordinary_messages) AS identities,\
                     (SELECT COUNT(*) FROM ordinary_messages WHERE payload_bytes>0) AS bodies,\
                     (SELECT COUNT(*) FROM ordinary_targets) AS targets,\
                     (SELECT COUNT(*) FROM ordinary_widget_refresh) AS markers,\
                     (SELECT COUNT(*) FROM ordinary_messages WHERE dedupe_until-accepted_at=$1) AS retained",
                )
                .bind(RETENTION_MS)
                .fetch_one(connection)
                .await
                .unwrap();
                return Counts {
                    identities: row.get("identities"),
                    bodies: row.get("bodies"),
                    targets: row.get("targets"),
                    markers: row.get("markers"),
                    full_retention: row.get("retained"),
                };
            }
            Self::MySql(connection) => sqlx::query(
                "SELECT CAST((SELECT COUNT(*) FROM ordinary_messages) AS SIGNED) AS identities,\
                 CAST((SELECT COUNT(*) FROM ordinary_messages WHERE payload_bytes>0) AS SIGNED) AS bodies,\
                 CAST((SELECT COUNT(*) FROM ordinary_targets) AS SIGNED) AS targets,\
                 CAST((SELECT COUNT(*) FROM ordinary_widget_refresh) AS SIGNED) AS markers,\
                 CAST((SELECT COUNT(*) FROM ordinary_messages WHERE dedupe_until-accepted_at=?) AS SIGNED) AS retained",
            )
            .bind(RETENTION_MS)
            .fetch_one(connection)
            .await
            .unwrap(),
        };
        Counts {
            identities: row.get("identities"),
            bodies: row.get("bodies"),
            targets: row.get("targets"),
            markers: row.get("markers"),
            full_retention: row.get("retained"),
        }
    }

    async fn expire_bodies(&mut self, at: i64) {
        match self {
            Self::Sqlite(connection) => {
                sqlx::query("UPDATE ordinary_messages SET expires_at=?")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
            Self::Postgres(connection) => {
                sqlx::query("UPDATE ordinary_messages SET expires_at=$1")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
            Self::MySql(connection) => {
                sqlx::query("UPDATE ordinary_messages SET expires_at=?")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
        }
    }

    async fn expire_identity_window(&mut self, at: i64) {
        match self {
            Self::Sqlite(connection) => {
                sqlx::query("UPDATE ordinary_messages SET dedupe_until=?")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
            Self::Postgres(connection) => {
                sqlx::query("UPDATE ordinary_messages SET dedupe_until=$1")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
            Self::MySql(connection) => {
                sqlx::query("UPDATE ordinary_messages SET dedupe_until=?")
                    .bind(at)
                    .execute(connection)
                    .await
                    .unwrap();
            }
        }
    }

    async fn insert_marker(&mut self, order: i64, expires_at: i64) {
        // Synthetic metadata-only obligations model a retained oldest marker
        // and an equal-expiry tail. They intentionally contain no body copy.
        let id = format!("c11-maint-marker-{order:04}");
        let channel = (order as u128).to_be_bytes();
        let accepted_at = now() - 60_000;
        match self {
            Self::Sqlite(connection) => {
                sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,coalesce_order,accepted_at,expires_at) VALUES(?,?,?,?,?)")
                    .bind(&id).bind(channel.as_slice()).bind(order).bind(accepted_at).bind(expires_at)
                    .execute(connection).await.unwrap();
            }
            Self::Postgres(connection) => {
                sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,acceptance_order,accepted_at,expires_at) VALUES($1,$2,$3,$4,$5)")
                    .bind(&id).bind(channel.as_slice()).bind(order).bind(accepted_at).bind(expires_at)
                    .execute(connection).await.unwrap();
            }
            Self::MySql(connection) => {
                sqlx::query("INSERT INTO ordinary_widget_refresh(delivery_id,channel_id,coalesce_order,accepted_at,expires_at) VALUES(?,?,?,?,?)")
                    .bind(&id).bind(channel.as_slice()).bind(order).bind(accepted_at).bind(expires_at)
                    .execute(connection).await.unwrap();
            }
        }
    }

    async fn close(self) {
        match self {
            Self::Sqlite(connection) => connection.close().await.unwrap(),
            Self::Postgres(connection) => connection.close().await.unwrap(),
            Self::MySql(connection) => connection.close().await.unwrap(),
        }
    }
}

fn native_url(name: &str, scheme: &[&str], port: u16) -> String {
    let url = std::env::var(name).expect("approved fresh isolated database URL required");
    let parsed = reqwest::Url::parse(&url).expect("isolated URL should parse");
    assert!(scheme.contains(&parsed.scheme()), "unexpected backend");
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1") | Some("localhost")
    ));
    assert_eq!(
        parsed.port(),
        Some(port),
        "use only the approved local QA port"
    );
    assert!(
        parsed
            .path()
            .trim_start_matches('/')
            .starts_with("c11_synthetic_"),
        "test must use a newly created synthetic database"
    );
    url
}

async fn maintenance_contract(url: String) {
    let mut inspect = Inspect::connect(&url).await;
    inspect.refuse_used_database().await;
    inspect.close().await;
    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(&url), health.clone())
        .await
        .unwrap();
    let storage = Storage::new_with_config(StorageInitConfig {
        db_url: Some(url.clone()),
        mcp_enabled: false,
        managed_upgrade: false,
        ..StorageInitConfig::default()
    })
    .await
    .unwrap();
    let ordinary: OrdinaryStore = storage
        .initialize_ordinary(Config::default(), health)
        .await
        .unwrap();
    let credential = crate::util::generate_hex_id_128();
    let channel = storage
        .upsert_private_channel(None, Some("C11 synthetic maintenance"), &credential)
        .await
        .unwrap()
        .channel_id;
    let key = "c11-maintenance-provider";
    storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: key.into(),
            platform: "android".into(),
            channel_type: "fcm".into(),
            provider_token: Some("c11-synthetic-no-network-token".into()),
            updated_at: now(),
        })
        .await
        .unwrap();
    storage
        .private_subscribe_channel(channel, PrivateDeviceId::derive(key).into_inner())
        .await
        .unwrap();
    for index in 0..ROWS {
        ordinary
            .accept(AcceptRequest {
                authorized_channel: Some(channel),
                channel_id: crate::value::ChannelId::from(channel).to_string(),
                op_id: Some(format!("c11-maintenance-{index:04}")),
                title: "bounded normal maintenance 中文".into(),
                body: Some("synthetic body retained until normal cleanup".into()),
                ttl: Some(now() + 600_000),
                ..AcceptRequest::default()
            })
            .await
            .unwrap();
    }
    let mut inspect = Inspect::connect(&url).await;
    let initial = Counts {
        identities: ROWS,
        bodies: ROWS,
        targets: ROWS,
        markers: 0,
        full_retention: ROWS,
    };
    assert_eq!(inspect.counts().await, initial);
    inspect.expire_bodies(now() - 60_000).await;
    storage
        .run_maintenance_cleanup(
            now(),
            MaintenanceCleanupConfig {
                dry_run: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(inspect.counts().await, initial, "dry-run cannot mutate C");

    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await,
        Counts {
            bodies: 1,
            targets: 1,
            ..initial
        },
        "one normal turn handles exactly one bounded equal-expiry batch"
    );
    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await,
        Counts {
            bodies: 0,
            targets: 0,
            ..initial
        },
        "later turn drains the equal-expiry remainder without dropping 30-day identities"
    );

    let live_expiry = now() + 600_000;
    inspect.insert_marker(1, live_expiry).await;
    let captured_ceiling = ordinary.widget_refresh_ceiling().await.unwrap().unwrap();
    assert_eq!(captured_ceiling, 1);
    let same_expiry = now() - 60_000;
    for order in 2..=ROWS + 1 {
        inspect.insert_marker(order, same_expiry).await;
    }
    assert_eq!(inspect.counts().await.markers, ROWS + 1);
    let latest_ceiling = ordinary.widget_refresh_ceiling().await.unwrap().unwrap();
    assert_eq!(latest_ceiling, ROWS + 1);
    let first = ordinary
        .widget_refresh_after(0, captured_ceiling)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.coalesce_order, 1);
    assert!(
        ordinary
            .widget_refresh_after(1, captured_ceiling)
            .await
            .unwrap()
            .is_none(),
        "new markers above the captured ceiling cannot extend or wrap an active cycle"
    );
    let second = ordinary
        .widget_refresh_after(1, latest_ceiling)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second.coalesce_order, 2,
        "a later finite cycle advances beyond the retained first marker"
    );
    let last = ordinary
        .widget_refresh_after(ROWS, latest_ceiling)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(last.coalesce_order, latest_ceiling);
    assert!(
        ordinary
            .widget_refresh_after(latest_ceiling, latest_ceiling)
            .await
            .unwrap()
            .is_none(),
        "the selector does not wrap to the blocked oldest marker"
    );
    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await.markers,
        2,
        "a retained live oldest marker cannot hide a separate bounded expiry batch"
    );
    let live = ordinary.next_widget_refresh().await.unwrap().unwrap();
    assert_eq!(live.delivery_id, "c11-maint-marker-0001");
    assert_eq!(live.coalesce_order, 1);
    assert_eq!(live.expires_at, live_expiry);
    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await.markers,
        1,
        "next turn drains the equal-expiry tail, preserving the live marker"
    );

    inspect.expire_identity_window(now() - 60_000).await;
    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await,
        Counts {
            identities: 1,
            bodies: 0,
            targets: 0,
            markers: 1,
            full_retention: 0
        },
        "identity retention cleanup is independently bounded"
    );
    storage
        .run_maintenance_cleanup(now(), MaintenanceCleanupConfig::default())
        .await
        .unwrap();
    assert_eq!(
        inspect.counts().await,
        Counts {
            identities: 0,
            bodies: 0,
            targets: 0,
            markers: 1,
            full_retention: 0
        }
    );
    inspect.close().await;
    storage.close_ordinary_storage().await.unwrap();
    owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_normal_maintenance_services_bounded_ordinary_and_widget_batches() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("c11-maintenance.db").display()
    );
    maintenance_contract(url).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an approved fresh C11_PG_TEST_URL on the isolated local PostgreSQL port"]
async fn postgres_normal_maintenance_services_bounded_ordinary_and_widget_batches() {
    maintenance_contract(native_url(
        "C11_PG_TEST_URL",
        &["postgres", "postgresql"],
        32772,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an approved fresh C11_MYSQL_TEST_URL on the isolated local MySQL port"]
async fn mysql_normal_maintenance_services_bounded_ordinary_and_widget_batches() {
    maintenance_contract(native_url("C11_MYSQL_TEST_URL", &["mysql"], 32773)).await;
}
