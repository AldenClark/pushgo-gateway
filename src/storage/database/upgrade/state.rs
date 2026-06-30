use crate::storage::database::upgrade::error::UpgradeResult;
use crate::storage::types::DatabaseKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpgradeRunStatus {
    Planned,
    PreflightOk,
    BackupStarted,
    BackupOk,
    Migrating,
    Verifying,
    Completed,
    Failed,
    RollingBack,
    RolledBack,
    RollbackFailed,
}

impl UpgradeRunStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::PreflightOk => "preflight_ok",
            Self::BackupStarted => "backup_started",
            Self::BackupOk => "backup_ok",
            Self::Migrating => "migrating",
            Self::Verifying => "verifying",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::RollbackFailed => "rollback_failed",
        }
    }

    pub(crate) fn unfinished(raw: &str) -> bool {
        !matches!(
            raw,
            "completed" | "failed" | "rolled_back" | "rollback_failed"
        )
    }
}

pub(crate) trait UpgradeStateAccess {
    async fn ensure_upgrade_state_tables(&self) -> UpgradeResult<()>;
    async fn unfinished_upgrade_runs(&self) -> UpgradeResult<Vec<String>>;
    async fn insert_upgrade_run(
        &self,
        run_id: &str,
        driver: DatabaseKind,
        from_schema_version: Option<&str>,
        target_schema_version: &str,
    ) -> UpgradeResult<()>;
    async fn update_upgrade_run_status(
        &self,
        run_id: &str,
        status: UpgradeRunStatus,
        backup_uri: Option<&str>,
        backup_sha256: Option<&str>,
        error: Option<&str>,
    ) -> UpgradeResult<()>;
    async fn insert_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        migration_id: &str,
        step_id: &str,
        description: &str,
    ) -> UpgradeResult<()>;
    async fn update_upgrade_step(
        &self,
        run_id: &str,
        step_order: i64,
        status: UpgradeRunStatus,
        error: Option<&str>,
    ) -> UpgradeResult<()>;
}
