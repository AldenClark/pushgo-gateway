use super::*;
use async_trait::async_trait;

#[async_trait]
impl DeliveryAuditDatabaseAccess for DatabaseDriver {
    async fn append_delivery_audit(&self, entry: &DeliveryAuditWrite) -> StoreResult<()> {
        delegate_db_async!(self, append_delivery_audit(entry))
    }

    async fn append_delivery_audit_batch(&self, entries: &[DeliveryAuditWrite]) -> StoreResult<()> {
        delegate_db_async!(self, append_delivery_audit_batch(entries))
    }

    async fn apply_stats_batch(&self, batch: &StatsBatchWrite) -> StoreResult<()> {
        delegate_db_async!(self, apply_stats_batch(batch))
    }
}
