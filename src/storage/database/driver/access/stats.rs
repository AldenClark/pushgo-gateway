use super::*;
use async_trait::async_trait;

#[async_trait]
impl StatsDatabaseAccess for DatabaseDriver {
    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        delegate_db_async!(self, apply_stats_batch(batch))
    }
}
