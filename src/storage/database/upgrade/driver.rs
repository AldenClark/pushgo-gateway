use crate::runtime_config::GatewayRuntimeProfile;
use crate::storage::StoreResult;
use crate::storage::database::DatabaseDriver;
use crate::storage::database::migration::BackupPolicy;
use crate::storage::database::upgrade::backup::{BackupArtifact, UpgradeBackupAccess};
use crate::storage::database::upgrade::error::UpgradeResult;
use crate::storage::database::upgrade::lock::UpgradeLockAccess;
use crate::storage::database::upgrade::plan::UpgradePlan;
use crate::storage::database::upgrade::state::{UpgradeRunStatus, UpgradeStateAccess};
use crate::storage::database::upgrade::verify::UpgradeVerifyAccess;
use crate::storage::types::DatabaseKind;

impl DatabaseDriver {
    pub(crate) async fn open_for_upgrade(
        db_url: &str,
        kind: DatabaseKind,
        runtime_profile: GatewayRuntimeProfile,
        mcp_enabled: bool,
    ) -> StoreResult<Self> {
        match kind {
            DatabaseKind::Sqlite => Ok(Self::Sqlite(
                crate::storage::database::sqlite::SqliteDb::open_for_upgrade(
                    db_url,
                    runtime_profile,
                    mcp_enabled,
                )
                .await?,
            )),
            DatabaseKind::Postgres => Ok(Self::Postgres(
                crate::storage::database::pg::PostgresDb::open_for_upgrade(db_url, runtime_profile)
                    .await?,
            )),
            DatabaseKind::Mysql => Ok(Self::MySql(
                crate::storage::database::mysql::MySqlDb::open_for_upgrade(db_url, runtime_profile)
                    .await?,
            )),
        }
    }

    pub(crate) async fn inspect_upgrade_plan(&self) -> UpgradeResult<UpgradePlan> {
        match self {
            Self::Sqlite(inner) => inner.inspect_upgrade_plan().await,
            Self::Postgres(inner) => inner.inspect_upgrade_plan().await,
            Self::MySql(inner) => inner.inspect_upgrade_plan().await,
        }
    }
}

impl UpgradeStateAccess for DatabaseDriver {
    async fn ensure_upgrade_state_tables(&self) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => inner.ensure_upgrade_state_tables().await,
            Self::Postgres(inner) => inner.ensure_upgrade_state_tables().await,
            Self::MySql(inner) => inner.ensure_upgrade_state_tables().await,
        }
    }

    async fn unfinished_upgrade_runs(&self) -> UpgradeResult<Vec<String>> {
        match self {
            Self::Sqlite(inner) => inner.unfinished_upgrade_runs().await,
            Self::Postgres(inner) => inner.unfinished_upgrade_runs().await,
            Self::MySql(inner) => inner.unfinished_upgrade_runs().await,
        }
    }

    async fn insert_upgrade_run(
        &self,
        run_id: &str,
        driver: DatabaseKind,
        from_schema_version: Option<&str>,
        target_schema_version: &str,
    ) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => {
                inner
                    .insert_upgrade_run(run_id, driver, from_schema_version, target_schema_version)
                    .await
            }
            Self::Postgres(inner) => {
                inner
                    .insert_upgrade_run(run_id, driver, from_schema_version, target_schema_version)
                    .await
            }
            Self::MySql(inner) => {
                inner
                    .insert_upgrade_run(run_id, driver, from_schema_version, target_schema_version)
                    .await
            }
        }
    }

    async fn update_upgrade_run_status(
        &self,
        run_id: &str,
        status: UpgradeRunStatus,
        backup_uri: Option<&str>,
        backup_sha256: Option<&str>,
        error: Option<&str>,
    ) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => {
                inner
                    .update_upgrade_run_status(run_id, status, backup_uri, backup_sha256, error)
                    .await
            }
            Self::Postgres(inner) => {
                inner
                    .update_upgrade_run_status(run_id, status, backup_uri, backup_sha256, error)
                    .await
            }
            Self::MySql(inner) => {
                inner
                    .update_upgrade_run_status(run_id, status, backup_uri, backup_sha256, error)
                    .await
            }
        }
    }

    async fn insert_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        migration_id: &str,
        step_id: &str,
        description: &str,
    ) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => {
                inner
                    .insert_upgrade_step(run_id, step_order, migration_id, step_id, description)
                    .await
            }
            Self::Postgres(inner) => {
                inner
                    .insert_upgrade_step(run_id, step_order, migration_id, step_id, description)
                    .await
            }
            Self::MySql(inner) => {
                inner
                    .insert_upgrade_step(run_id, step_order, migration_id, step_id, description)
                    .await
            }
        }
    }

    async fn update_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        status: UpgradeRunStatus,
        error: Option<&str>,
    ) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => {
                inner
                    .update_upgrade_step(run_id, step_order, status, error)
                    .await
            }
            Self::Postgres(inner) => {
                inner
                    .update_upgrade_step(run_id, step_order, status, error)
                    .await
            }
            Self::MySql(inner) => {
                inner
                    .update_upgrade_step(run_id, step_order, status, error)
                    .await
            }
        }
    }
}

impl UpgradeLockAccess for DatabaseDriver {
    type Guard = Box<dyn Send>;

    async fn acquire_upgrade_lock(&self, db_url: &str) -> UpgradeResult<Self::Guard> {
        match self {
            Self::Sqlite(inner) => Ok(Box::new(inner.acquire_upgrade_lock(db_url).await?)),
            Self::Postgres(inner) => Ok(Box::new(inner.acquire_upgrade_lock(db_url).await?)),
            Self::MySql(inner) => Ok(Box::new(inner.acquire_upgrade_lock(db_url).await?)),
        }
    }
}

impl UpgradeBackupAccess for DatabaseDriver {
    async fn create_upgrade_backup(
        &self,
        db_url: &str,
        driver: DatabaseKind,
        policy: BackupPolicy,
        run_id: &str,
    ) -> UpgradeResult<Option<BackupArtifact>> {
        match self {
            Self::Sqlite(inner) => {
                inner
                    .create_upgrade_backup(db_url, driver, policy, run_id)
                    .await
            }
            Self::Postgres(inner) => {
                inner
                    .create_upgrade_backup(db_url, driver, policy, run_id)
                    .await
            }
            Self::MySql(inner) => {
                inner
                    .create_upgrade_backup(db_url, driver, policy, run_id)
                    .await
            }
        }
    }

    async fn restore_upgrade_backup(
        &self,
        db_url: &str,
        artifact: &BackupArtifact,
    ) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => inner.restore_upgrade_backup(db_url, artifact).await,
            Self::Postgres(inner) => inner.restore_upgrade_backup(db_url, artifact).await,
            Self::MySql(inner) => inner.restore_upgrade_backup(db_url, artifact).await,
        }
    }
}

impl UpgradeVerifyAccess for DatabaseDriver {
    async fn verify_upgrade(&self, target_schema_version: &str) -> UpgradeResult<()> {
        match self {
            Self::Sqlite(inner) => inner.verify_upgrade(target_schema_version).await,
            Self::Postgres(inner) => inner.verify_upgrade(target_schema_version).await,
            Self::MySql(inner) => inner.verify_upgrade(target_schema_version).await,
        }
    }
}
