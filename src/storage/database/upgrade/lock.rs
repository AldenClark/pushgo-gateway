use crate::storage::database::upgrade::error::UpgradeResult;

pub(crate) trait UpgradeLockAccess {
    type Guard: Send;

    async fn acquire_upgrade_lock(&self, db_url: &str) -> UpgradeResult<Self::Guard>;
}
