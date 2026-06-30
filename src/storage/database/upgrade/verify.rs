use crate::storage::database::upgrade::error::UpgradeResult;

pub(crate) trait UpgradeVerifyAccess {
    async fn verify_upgrade(&self, target_schema_version: &str) -> UpgradeResult<()>;
}
