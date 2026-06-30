use crate::storage::database::upgrade::backup::BackupArtifact;
use crate::storage::{StoreError, types::DatabaseKind};
use thiserror::Error;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

#[derive(Debug, Clone)]
pub struct UpgradeErrorContext {
    pub driver: DatabaseKind,
    pub database_url: String,
    pub current_schema_version: Option<String>,
    pub target_schema_version: String,
    pub migration_id: Option<String>,
    pub step_id: Option<String>,
    pub backup_uri: Option<String>,
    pub rollback_attempted: bool,
    pub rollback_result: Option<String>,
    pub recovery: String,
}

#[derive(Debug, Error)]
pub enum UpgradeError {
    #[error("{message}")]
    Fatal {
        message: String,
        context: Box<UpgradeErrorContext>,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl UpgradeError {
    pub(crate) fn fatal(context: UpgradeErrorContext, error: impl std::fmt::Display) -> Self {
        let message = format!(
            "database upgrade failed: driver={} database_url={} current_schema={} target_schema={} migration={} step={} backup={} rollback_attempted={} rollback_result={} recovery={} error={}",
            context.driver.as_str(),
            context.database_url,
            context
                .current_schema_version
                .as_deref()
                .unwrap_or("unknown"),
            context.target_schema_version,
            context.migration_id.as_deref().unwrap_or("none"),
            context.step_id.as_deref().unwrap_or("none"),
            context.backup_uri.as_deref().unwrap_or("none"),
            context.rollback_attempted,
            context
                .rollback_result
                .as_deref()
                .unwrap_or("not_attempted"),
            context.recovery,
            error
        );
        Self::Fatal {
            message,
            context: Box::new(context),
        }
    }

    pub(crate) fn with_backup(
        mut context: UpgradeErrorContext,
        backup: Option<&BackupArtifact>,
    ) -> UpgradeErrorContext {
        if let Some(backup) = backup {
            context.backup_uri = Some(backup.uri.clone());
        }
        context
    }
}

impl From<std::io::Error> for UpgradeError {
    fn from(err: std::io::Error) -> Self {
        Self::Store(StoreError::Io(err))
    }
}

impl From<sqlx::Error> for UpgradeError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::Sqlx(err))
    }
}
