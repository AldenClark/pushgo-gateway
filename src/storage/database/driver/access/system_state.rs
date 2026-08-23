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

    async fn upsert_live_activity_token(
        &self,
        record: &LiveActivityTokenRecord,
    ) -> StoreResult<()> {
        delegate_db_async!(self, upsert_live_activity_token(record))
    }

    async fn delete_live_activity_token(
        &self,
        activity_key: &str,
        token: Option<&str>,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, delete_live_activity_token(activity_key, token))
    }

    async fn list_live_activity_tokens(
        &self,
        activity_key: &str,
    ) -> StoreResult<Vec<LiveActivityTokenRecord>> {
        delegate_db_async!(self, list_live_activity_tokens(activity_key))
    }

    async fn upsert_widget_push_subscriptions(
        &self,
        device_key: &str,
        platform: Platform,
        token: &str,
        widgets: &[WidgetPushSubscriptionRecord],
        schema_version: i32,
        now: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            upsert_widget_push_subscriptions(
                device_key,
                platform,
                token,
                widgets,
                schema_version,
                now
            )
        )
    }

    async fn delete_widget_push_token(
        &self,
        platform: Platform,
        token: &str,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, delete_widget_push_token(platform, token))
    }

    async fn list_widget_push_targets_for_channel(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Vec<WidgetPushSubscriptionRecord>> {
        delegate_db_async!(self, list_widget_push_targets_for_channel(channel_id))
    }

    async fn insert_sender_submit_status_if_absent(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<bool> {
        delegate_db_async!(self, insert_sender_submit_status_if_absent(record))
    }

    async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            update_sender_submit_status(op_id, status, dispatch_status, updated_at)
        )
    }

    async fn finalize_provider_dispatch_outcome(
        &self,
        dedupe_key: &str,
        op_id: &str,
        delivery_id: &str,
        success: bool,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            finalize_provider_dispatch_outcome(dedupe_key, op_id, delivery_id, success)
        )
    }

    async fn recover_interrupted_provider_dispatches(&self, updated_at: i64) -> StoreResult<usize> {
        delegate_db_async!(self, recover_interrupted_provider_dispatches(updated_at))
    }

    async fn load_sender_submit_status(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<SenderSubmitStatusRecord>> {
        delegate_db_async!(self, load_sender_submit_status(op_id))
    }

    async fn cleanup_sender_submit_status(&self, now: i64, limit: usize) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_sender_submit_status(now, limit))
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
        acked_before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            cleanup_stale_private_outbox(before_ts, acked_before_ts, limit)
        )
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

    async fn cleanup_inactive_subscriptions(
        &self,
        before_ts: i64,
        now: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_inactive_subscriptions(before_ts, now, limit))
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
}
