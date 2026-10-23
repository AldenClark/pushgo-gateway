//! Exclusive product dataset ownership, acquired before mutable Storage setup.
//!
//! A database session lock rejects concurrent owners through connection aliases.
//! A machine-wide file lock additionally prevents a second local process from
//! taking over while a disconnected first process is still finishing fail-stop.
//! The latter is deliberately retained until process exit on abnormal Drop.
//! This is a single-host rule, not a distributed lease or fencing protocol.
use super::store::{Health, KernelError, Result};
use sqlx::{Connection, MySqlConnection, PgConnection, sqlite::SqliteConnectOptions};
use std::{fs::File, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

const PG_LOCK_CLASS: i32 = 1_346_852_687;
const PG_LOCK_DATASET: i32 = 1_330_791_756;
const OWNER_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct ProductOwner {
    file: Option<File>,
    stop: Option<oneshot::Sender<()>>,
    watcher: Option<JoinHandle<RemoteOwner>>,
    health: Arc<Health>,
    released: bool,
}

enum RemoteOwner {
    Postgres(PgConnection),
    MySql {
        connection: MySqlConnection,
        lock: String,
    },
}

impl ProductOwner {
    /// Call before schema upgrades, pool creation, recovery or ingress startup.
    pub(crate) async fn acquire(db_url: Option<&str>, health: Arc<Health>) -> Result<Self> {
        let url = crate::storage::database::DatabaseDriver::normalize_db_url_public(db_url);
        let backend = owner_backend(&url)?;
        if backend == crate::storage::DatabaseKind::Sqlite {
            return Ok(Self {
                file: sqlite_owner(&url)?,
                stop: None,
                watcher: None,
                health,
                released: false,
            });
        }
        let (remote, uuid, kind) = if backend == crate::storage::DatabaseKind::Postgres {
            let connection =
                tokio::time::timeout(Duration::from_secs(5), PgConnection::connect(&url))
                    .await
                    .map_err(|_| timeout_error("PostgreSQL owner connection timed out"))??;
            let (connection, uuid) =
                tokio::time::timeout(Duration::from_secs(10), acquire_postgres(connection))
                    .await
                    .map_err(|_| timeout_error("PostgreSQL owner acquisition timed out"))??;
            (RemoteOwner::Postgres(connection), uuid, "pg")
        } else if backend == crate::storage::DatabaseKind::Mysql {
            let connection =
                tokio::time::timeout(Duration::from_secs(5), MySqlConnection::connect(&url))
                    .await
                    .map_err(|_| timeout_error("MySQL owner connection timed out"))??;
            let (connection, uuid, lock) =
                tokio::time::timeout(Duration::from_secs(10), acquire_mysql(connection))
                    .await
                    .map_err(|_| timeout_error("MySQL owner acquisition timed out"))??;
            (RemoteOwner::MySql { connection, lock }, uuid, "mysql")
        } else {
            return Err(KernelError::Invalid(
                "unsupported product database URL".into(),
            ));
        };
        // No URL, user, host alias, port spelling or query parameter appears in
        // this identity. The UUID comes from the selected database itself.
        let file = acquire_file(machine_owner_path(kind, &uuid)?)?;
        let (stop, stopped) = oneshot::channel();
        let watcher = tokio::spawn(watch(remote, stopped, health.clone()));
        Ok(Self {
            file: Some(file),
            stop: Some(stop),
            watcher: Some(watcher),
            health,
            released: false,
        })
    }

    /// Caller must first stop ingress/claiming, drain results and close *all*
    /// Storage pools. Only this explicit path releases ownership in-process.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let mut watcher = self.watcher.take();
        let close = async {
            let Some(watcher) = watcher.as_mut() else {
                return Ok(());
            };
            let remote = watcher.await.map_err(|_| KernelError::Unavailable)?;
            // The fixed physical session is closed rather than returned to a
            // pool. It can never be replaced by an automatically reconnected one.
            match remote {
                RemoteOwner::Postgres(connection) => {
                    connection.close().await?;
                }
                RemoteOwner::MySql { connection, .. } => {
                    connection.close().await?;
                }
            }
            Ok(())
        };
        let result = tokio::time::timeout(OWNER_TIMEOUT, close).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.health
                    .fail("fixed product owner shutdown failed; process restart required");
                return Err(error);
            }
            Err(_) => {
                if let Some(watcher) = watcher.take() {
                    watcher.abort();
                }
                self.health
                    .fail("fixed product owner shutdown timed out; process restart required");
                return Err(timeout_error(
                    "product owner shutdown exceeded three seconds",
                ));
            }
        }
        self.released = true;
        drop(self.file.take());
        Ok(())
    }
}

impl Drop for ProductOwner {
    fn drop(&mut self) {
        if !self.released {
            self.health.fail(
                "product dataset owner dropped before orderly release; process restart required",
            );
        }
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
        if let Some(file) = self.file.take() {
            // Cancelled SQLx work or a failed shutdown can outlive its caller.
            // Retaining the OS descriptor forbids a local replacement process
            // until this process has actually exited.
            std::mem::forget(file);
        }
    }
}

struct WatchFailureGuard {
    health: Arc<Health>,
    orderly_stop: bool,
}
impl Drop for WatchFailureGuard {
    fn drop(&mut self) {
        if !self.orderly_stop {
            self.health
                .fail("fixed product owner monitor ended unexpectedly; process restart required");
        }
    }
}

async fn watch(
    mut remote: RemoteOwner,
    mut stopped: oneshot::Receiver<()>,
    health: Arc<Health>,
) -> RemoteOwner {
    // Unwinding or aborting this task must wake main's existing failure watch;
    // waiting until a later shutdown join would silently lose lock monitoring.
    let mut failure_guard = WatchFailureGuard {
        health: health.clone(),
        orderly_stop: false,
    };
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Acquire already verified ownership; avoid an extra query at startup.
    interval.tick().await;
    loop {
        tokio::select! {
            result = &mut stopped => { failure_guard.orderly_stop=result.is_ok(); break; },
            _ = interval.tick() => {}
        }
        let verified = tokio::select! {
            result = &mut stopped => { failure_guard.orderly_stop=result.is_ok(); break; },
            result = tokio::time::timeout(OWNER_TIMEOUT, remote.verify()) => result,
        };
        if !matches!(verified, Ok(Ok(true))) {
            health.fail("fixed product database owner session lost; process restart required");
            // Keep the raw session (even a dead one) and the outer file lock
            // until the normal process failure path has stopped all components.
            failure_guard.orderly_stop = stopped.await.is_ok();
            break;
        }
    }
    remote
}

impl RemoteOwner {
    async fn verify(&mut self) -> std::result::Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(connection) => sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_catalog.pg_backend_pid() AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=2 AND granted)"
            ).bind(i64::from(PG_LOCK_CLASS)).bind(i64::from(PG_LOCK_DATASET)).fetch_one(connection).await,
            Self::MySql { connection, lock } => Ok(sqlx::query_scalar::<_, Option<i64>>(
                "SELECT IS_USED_LOCK(?)=CONNECTION_ID()"
            ).bind(lock.as_str()).fetch_one(connection).await? == Some(1)),
        }
    }
}

async fn acquire_postgres(mut connection: PgConnection) -> Result<(PgConnection, String)> {
    let owned: bool = sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_lock($1,$2)")
        .bind(PG_LOCK_CLASS)
        .bind(PG_LOCK_DATASET)
        .fetch_one(&mut connection)
        .await?;
    if !owned {
        return Err(KernelError::OwnerContention);
    }
    // Qualifying the metadata prevents a search_path connection option from
    // creating an alternative identity after the first owner's session fails.
    sqlx::query("CREATE TABLE IF NOT EXISTS public.pushgo_product_owner(singleton SMALLINT PRIMARY KEY CHECK(singleton=1),dataset_uuid VARCHAR(32) NOT NULL UNIQUE)")
        .execute(&mut connection).await?;
    sqlx::query("INSERT INTO public.pushgo_product_owner(singleton,dataset_uuid) VALUES(1,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind(crate::util::generate_hex_id_128()).execute(&mut connection).await?;
    let uuid: String = sqlx::query_scalar(
        "SELECT dataset_uuid FROM public.pushgo_product_owner WHERE singleton=1",
    )
    .fetch_one(&mut connection)
    .await?;
    validate_uuid(&uuid)?;
    Ok((connection, uuid))
}

async fn acquire_mysql(
    mut connection: MySqlConnection,
) -> Result<(MySqlConnection, String, String)> {
    let database: Option<String> = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&mut connection)
        .await?;
    let database = database
        .filter(|name| !name.is_empty())
        .ok_or_else(|| KernelError::Invalid("a dedicated MySQL database is required".into()))?;
    // DATABASE() is server-selected. Hashing on the server avoids URL aliases;
    // lowercasing safely over-serializes case-distinct catalogs during bootstrap.
    let bootstrap: String = sqlx::query_scalar("SELECT CAST(CONCAT('pushgo-owner-bootstrap-',LEFT(SHA2(LOWER(?),256),40)) AS CHAR CHARACTER SET utf8mb4)")
        .bind(database).fetch_one(&mut connection).await?;
    let owned: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
        .bind(&bootstrap)
        .fetch_one(&mut connection)
        .await?;
    if owned != Some(1) {
        return Err(KernelError::OwnerContention);
    }
    sqlx::query("CREATE TABLE IF NOT EXISTS pushgo_product_owner(singleton TINYINT PRIMARY KEY CHECK(singleton=1),dataset_uuid VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE) ENGINE=InnoDB")
        .execute(&mut connection).await?;
    sqlx::query("INSERT INTO pushgo_product_owner(singleton,dataset_uuid) VALUES(1,?) ON DUPLICATE KEY UPDATE singleton=singleton")
        .bind(crate::util::generate_hex_id_128()).execute(&mut connection).await?;
    let uuid: String = sqlx::query_scalar("SELECT CAST(dataset_uuid AS CHAR CHARACTER SET utf8mb4) FROM pushgo_product_owner WHERE singleton=1")
        .fetch_one(&mut connection).await?;
    validate_uuid(&uuid)?;
    let lock = format!("pushgo-product-{uuid}");
    let owned: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
        .bind(&lock)
        .fetch_one(&mut connection)
        .await?;
    if owned != Some(1) {
        return Err(KernelError::OwnerContention);
    }
    let _: Option<i64> = sqlx::query_scalar("SELECT RELEASE_LOCK(?)")
        .bind(bootstrap)
        .fetch_one(&mut connection)
        .await?;
    Ok((connection, uuid, lock))
}

fn validate_uuid(uuid: &str) -> Result<()> {
    if uuid.len() != 32 || !uuid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(KernelError::Invalid(
            "invalid product dataset owner identity".into(),
        ));
    }
    Ok(())
}

fn sqlite_owner(url: &str) -> Result<Option<File>> {
    let options = SqliteConnectOptions::from_str(url)?;
    let filename = options.get_filename();
    // A private in-memory SQLite database cannot be opened by another process.
    // Keep existing test-only in-memory Storage use without inventing a shared
    // owner for unrelated transient databases.
    if filename.to_string_lossy().contains(":memory:") {
        return Ok(None);
    }
    let filename = if filename.is_absolute() {
        filename.to_owned()
    } else {
        std::env::current_dir()?.join(filename)
    };
    let parent = filename
        .parent()
        .ok_or_else(|| KernelError::Invalid("database path".into()))?;
    std::fs::create_dir_all(parent)?;
    let filename = if filename.exists() {
        std::fs::canonicalize(&filename)?
    } else {
        std::fs::canonicalize(parent)?.join(
            filename
                .file_name()
                .ok_or_else(|| KernelError::Invalid("database filename".into()))?,
        )
    };
    #[cfg(unix)]
    if filename.exists() {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(&filename)?.nlink() != 1 {
            return Err(KernelError::Invalid(
                "hardlinked SQLite database is unsupported".into(),
            ));
        }
    }
    let lock = filename.with_file_name(format!(
        "{}.product-owner",
        filename.file_name().unwrap().to_string_lossy()
    ));
    Ok(Some(acquire_file(lock)?))
}

fn acquire_file(path: PathBuf) -> Result<File> {
    // Refuse a pre-existing redirected owner file. Same-host deployments must
    // also keep this directory and the database filename stable while running.
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(KernelError::Invalid(
                "owner path must be a regular file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(KernelError::Invalid(
                    "hardlinked owner file is unsupported".into(),
                ));
            }
        }
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    file.try_lock().map_err(|_| KernelError::OwnerContention)?;
    Ok(file)
}

#[cfg(unix)]
fn machine_owner_path(kind: &str, uuid: &str) -> Result<PathBuf> {
    // Intentionally machine-wide, not env::temp_dir() or a per-user directory.
    Ok(PathBuf::from("/tmp").join(format!("pushgo-product-{kind}-{uuid}.owner")))
}
#[cfg(not(unix))]
fn machine_owner_path(_: &str, _: &str) -> Result<PathBuf> {
    Err(KernelError::Invalid(
        "remote product databases currently require a Unix machine-wide owner lock".into(),
    ))
}

fn timeout_error(message: &'static str) -> KernelError {
    sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message)).into()
}

fn owner_backend(url: &str) -> Result<crate::storage::DatabaseKind> {
    // Keep the product's established pg:// alias and case-insensitive scheme
    // selection. Only the server-selected dataset UUID defines lock identity.
    crate::storage::DatabaseKind::from_url(url)
        .map_err(|error| KernelError::Invalid(error.to_string()))
}

/// The existing explicit schema-upgrade command must share product ownership.
/// A successful upgrade has completed its durable SQL before releasing the lock;
/// errors retain the abnormal-drop lock until this command process exits.
pub async fn run_exclusive_upgrade(
    config: crate::storage::StorageInitConfig,
    mode: crate::storage::database::upgrade::UpgradeMode,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner =
        ProductOwner::acquire(config.db_url.as_deref(), Arc::new(Health::default())).await?;
    crate::storage::database::upgrade::UpgradeManager::new(config)
        .run(mode)
        .await?;
    owner.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_uses_existing_product_database_scheme_aliases() {
        for url in [
            "postgres://127.0.0.1/synthetic",
            "postgresql://127.0.0.1/synthetic",
            "pg://127.0.0.1/synthetic",
            "PG://127.0.0.1/synthetic",
            "PoStGrEsQl://127.0.0.1/synthetic",
        ] {
            assert_eq!(
                owner_backend(url).unwrap(),
                crate::storage::DatabaseKind::Postgres
            );
        }
        assert_eq!(
            owner_backend("MYSQL://127.0.0.1/synthetic").unwrap(),
            crate::storage::DatabaseKind::Mysql
        );
        assert_eq!(
            owner_backend("sqlite://synthetic.db").unwrap(),
            crate::storage::DatabaseKind::Sqlite
        );
    }

    #[tokio::test]
    async fn sqlite_query_aliases_share_owner_and_explicit_shutdown_releases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary.db");
        // SQLx initialization is not required to protect an empty new dataset.
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let first = ProductOwner::acquire(Some(&url), Arc::default())
            .await
            .unwrap();
        let alias = format!("sqlite://{}?mode=rwc&cache=private", path.display());
        assert!(matches!(
            ProductOwner::acquire(Some(&alias), Arc::default()).await,
            Err(KernelError::OwnerContention)
        ));
        first.shutdown().await.unwrap();
        ProductOwner::acquire(Some(&alias), Arc::default())
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_symlink_alias_uses_canonical_database_owner() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ordinary.db");
        std::fs::write(&database, []).unwrap();
        let alias = directory.path().join("alias.db");
        std::os::unix::fs::symlink(&database, &alias).unwrap();
        let first = ProductOwner::acquire(
            Some(&format!("sqlite://{}", database.display())),
            Arc::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            ProductOwner::acquire(
                Some(&format!("sqlite://{}", alias.display())),
                Arc::default()
            )
            .await,
            Err(KernelError::OwnerContention)
        ));
        first.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_hardlinks_are_rejected_before_mutable_setup() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ordinary.db");
        std::fs::write(&database, []).unwrap();
        std::fs::hard_link(&database, directory.path().join("alias.db")).unwrap();
        assert!(matches!(
            ProductOwner::acquire(
                Some(&format!("sqlite://{}", database.display())),
                Arc::default()
            )
            .await,
            Err(KernelError::Invalid(_))
        ));
    }

    #[test]
    fn abnormal_drop_keeps_file_owner_until_process_exit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner");
        let owner = ProductOwner {
            file: Some(acquire_file(path.clone()).unwrap()),
            stop: None,
            watcher: None,
            health: Arc::default(),
            released: false,
        };
        drop(owner);
        assert!(matches!(
            acquire_file(path),
            Err(KernelError::OwnerContention)
        ));
        // The intentionally retained descriptor is closed by the test process.
    }

    #[cfg(unix)]
    #[test]
    fn redirected_owner_file_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, []).unwrap();
        let alias = directory.path().join("owner");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert!(matches!(acquire_file(alias), Err(KernelError::Invalid(_))));
    }

    #[tokio::test]
    async fn monitor_panic_fences_health_before_shutdown_join() {
        let health = Arc::new(Health::default());
        let monitor_health = health.clone();
        let result = tokio::spawn(async move {
            let _guard = WatchFailureGuard {
                health: monitor_health,
                orderly_stop: false,
            };
            panic!("synthetic owner monitor panic");
        })
        .await;
        assert!(result.unwrap_err().is_panic());
        assert!(matches!(health.ensure(), Err(KernelError::Unavailable)));
    }

    #[test]
    fn orderly_monitor_stop_does_not_publish_failure() {
        let health = Arc::new(Health::default());
        drop(WatchFailureGuard {
            health: health.clone(),
            orderly_stop: true,
        });
        assert!(health.ensure().is_ok());
    }
}
