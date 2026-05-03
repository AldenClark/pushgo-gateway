use super::*;
use async_trait::async_trait;

#[async_trait]
impl SystemStateDatabaseAccess for DatabaseDriver {
    async fn automation_reset(&self) -> StoreResult<()> {
        delegate_db_async!(self, automation_reset())
    }

    async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        delegate_db_async!(self, automation_counts())
    }

    async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        delegate_db_async!(self, load_mcp_state_json())
    }

    async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        delegate_db_async!(self, save_mcp_state_json(state_json))
    }

    async fn cleanup_expired_provider_pull_queue(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_expired_provider_pull_queue(before_ts, limit))
    }

    async fn cleanup_stale_private_outbox(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_stale_private_outbox(before_ts, limit))
    }

    async fn cleanup_orphan_devices(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_orphan_devices(before_ts, limit))
    }

    async fn cleanup_stale_subscriptions(
        &self,
        before_ts: i64,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_stale_subscriptions(before_ts, now, limit))
    }

    async fn cleanup_soft_deleted_devices(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_soft_deleted_devices(before_ts, limit))
    }

    async fn cleanup_orphan_channels(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_orphan_channels(before_ts, limit))
    }

    async fn cleanup_audit_rows(&self, before_ts: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_audit_rows(before_ts, limit))
    }

    async fn cleanup_hourly_stats(&self, before_bucket: &str, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_hourly_stats(before_bucket, limit))
    }

    async fn cleanup_daily_stats(&self, before_bucket: &str, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_daily_stats(before_bucket, limit))
    }
}
