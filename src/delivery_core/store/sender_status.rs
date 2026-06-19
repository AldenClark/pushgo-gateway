use async_trait::async_trait;

use crate::storage::{SenderSubmitStatusKind, SenderSubmitStatusRecord, Storage, StoreResult};

#[async_trait]
pub(crate) trait SenderStatusStore {
    async fn upsert_sender_submit_status(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<()>;

    async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()>;
}

#[async_trait]
impl SenderStatusStore for Storage {
    async fn upsert_sender_submit_status(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<()> {
        self.upsert_sender_submit_status(record).await
    }

    async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()> {
        self.update_sender_submit_status(op_id, status, dispatch_status, updated_at)
            .await
    }
}
