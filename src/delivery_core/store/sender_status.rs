use async_trait::async_trait;

use crate::storage::{SenderSubmitStatusKind, SenderSubmitStatusRecord, Storage, StoreResult};

#[async_trait]
pub(crate) trait SenderStatusStore {
    async fn insert_sender_submit_status_if_absent(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<bool>;

    async fn update_sender_submit_status(
        &self,
        op_id: &str,
        status: SenderSubmitStatusKind,
        dispatch_status: Option<&str>,
        updated_at: i64,
    ) -> StoreResult<()>;

    async fn load_sender_submit_status(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<SenderSubmitStatusRecord>>;
}

#[async_trait]
impl SenderStatusStore for Storage {
    async fn insert_sender_submit_status_if_absent(
        &self,
        record: &SenderSubmitStatusRecord,
    ) -> StoreResult<bool> {
        self.insert_sender_submit_status_if_absent(record).await
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

    async fn load_sender_submit_status(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<SenderSubmitStatusRecord>> {
        self.load_sender_submit_status(op_id).await
    }
}
