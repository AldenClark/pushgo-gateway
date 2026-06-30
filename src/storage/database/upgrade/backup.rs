use crate::storage::database::migration::BackupPolicy;
use crate::storage::database::upgrade::error::UpgradeResult;
use crate::storage::types::DatabaseKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupArtifact {
    pub uri: String,
    pub sha256: String,
    pub bytes: u64,
}

pub(crate) trait UpgradeBackupAccess {
    async fn create_upgrade_backup(
        &self,
        db_url: &str,
        driver: DatabaseKind,
        policy: BackupPolicy,
        run_id: &str,
    ) -> UpgradeResult<Option<BackupArtifact>>;

    async fn restore_upgrade_backup(
        &self,
        db_url: &str,
        artifact: &BackupArtifact,
    ) -> UpgradeResult<()>;
}
