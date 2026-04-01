use super::*;
use async_trait::async_trait;

#[async_trait]
impl ProviderPullDatabaseAccess for DatabaseDriver {
    async fn enqueue_provider_pull_item(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            enqueue_provider_pull_item(
                delivery_id,
                message,
                platform,
                provider_token,
                next_retry_at
            )
        )
    }

    async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        delegate_db_async!(self, pull_provider_item(delivery_id, now))
    }

    async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        delegate_db_async!(self, list_provider_pull_retry_due(now, limit))
    }

    async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        delegate_db_async!(
            self,
            bump_provider_pull_retry(delivery_id, next_retry_at, now)
        )
    }

    async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        delegate_db_async!(self, clear_provider_pull_retry(delivery_id))
    }
}
