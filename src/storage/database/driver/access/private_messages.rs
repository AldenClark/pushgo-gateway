use super::*;
use async_trait::async_trait;

#[async_trait]
impl PrivateMessageDatabaseAccess for DatabaseDriver {
    async fn load_private_outbox_entry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateOutboxEntry>> {
        delegate_db_async!(self, load_private_outbox_entry(device_id, delivery_id))
    }

    async fn delete_private_device_state(&self, device_id: DeviceId) -> StoreResult<()> {
        delegate_db_async!(self, delete_private_device_state(device_id))
    }

    async fn insert_private_message(
        &self,
        delivery_id: &str,
        message: &PrivateMessage,
    ) -> StoreResult<()> {
        delegate_db_async!(self, insert_private_message(delivery_id, message))
    }

    async fn enqueue_private_outbox(
        &self,
        device_id: DeviceId,
        entry: &PrivateOutboxEntry,
    ) -> StoreResult<()> {
        delegate_db_async!(self, enqueue_private_outbox(device_id, entry))
    }

    async fn enqueue_private_outbox_batch(
        &self,
        entries: &[PrivateOutboxBatchEntry],
        max_pending_per_device: usize,
        global_max_pending: usize,
        protected_delivery_id: Option<&str>,
    ) -> StoreResult<usize> {
        delegate_db_async!(
            self,
            enqueue_private_outbox_batch(
                entries,
                max_pending_per_device,
                global_max_pending,
                protected_delivery_id
            )
        )
    }

    async fn list_private_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        delegate_db_async!(self, list_private_outbox(device_id, limit))
    }

    async fn evict_oldest_pending_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Option<String>> {
        delegate_db_async!(
            self,
            evict_oldest_pending_private_outbox_for_device(device_id)
        )
    }

    async fn evict_oldest_pending_private_outbox_global(
        &self,
    ) -> StoreResult<Option<(DeviceId, String)>> {
        delegate_db_async!(self, evict_oldest_pending_private_outbox_global())
    }

    async fn count_private_outbox_for_device(&self, device_id: DeviceId) -> StoreResult<usize> {
        delegate_db_async!(self, count_private_outbox_for_device(device_id))
    }

    async fn cleanup_private_expired_data(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_private_expired_data(before_ts, limit))
    }

    async fn cleanup_private_sessions(&self, before_ts: i64) -> StoreResult<usize> {
        delegate_db_async!(self, cleanup_private_sessions(before_ts))
    }

    async fn bind_private_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, bind_private_token(device_id, platform, token))
    }

    async fn load_private_message(&self, delivery_id: &str) -> StoreResult<Option<PrivateMessage>> {
        delegate_db_async!(self, load_private_message(delivery_id))
    }

    async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        delegate_db_async!(self, load_private_payload_context(delivery_id))
    }

    async fn mark_private_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(
            self,
            mark_private_fallback_sent(device_id, delivery_id, at_ts)
        )
    }

    async fn defer_private_fallback(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        at_ts: i64,
    ) -> StoreResult<()> {
        delegate_db_async!(self, defer_private_fallback(device_id, delivery_id, at_ts))
    }

    async fn ack_private_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> StoreResult<()> {
        delegate_db_async!(self, ack_private_delivery(device_id, delivery_id))
    }

    async fn clear_private_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<String>> {
        delegate_db_async!(self, clear_private_outbox_for_device(device_id))
    }

    async fn list_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        delegate_db_async!(self, list_private_outbox_due(before_ts, limit))
    }

    async fn claim_private_outbox_due(
        &self,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<(DeviceId, PrivateOutboxEntry)>> {
        delegate_db_async!(
            self,
            claim_private_outbox_due(before_ts, limit, claim_until_ts)
        )
    }

    async fn claim_private_outbox_due_for_device(
        &self,
        device_id: DeviceId,
        before_ts: i64,
        limit: usize,
        claim_until_ts: i64,
    ) -> StoreResult<Vec<PrivateOutboxEntry>> {
        delegate_db_async!(
            self,
            claim_private_outbox_due_for_device(device_id, before_ts, limit, claim_until_ts)
        )
    }

    async fn count_private_outbox_total(&self) -> StoreResult<usize> {
        delegate_db_async!(self, count_private_outbox_total())
    }
}

impl DatabaseDriver {
    pub(crate) async fn insert_private_messages_batch(
        &self,
        entries: &[PrivateMessageBatchEntry],
    ) -> StoreResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        match self {
            DatabaseDriver::Sqlite(inner) => inner.insert_private_messages_batch(entries).await,
            DatabaseDriver::MySql(_) | DatabaseDriver::Postgres(_) => {
                for item in entries {
                    self.insert_private_message(item.delivery_id.as_str(), &item.message)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub(crate) async fn list_private_outbox_with_messages(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> StoreResult<Vec<PrivateOutboxMessageRow>> {
        match self {
            DatabaseDriver::Sqlite(inner) => {
                inner
                    .list_private_outbox_with_messages(device_id, limit)
                    .await
            }
            DatabaseDriver::MySql(_) | DatabaseDriver::Postgres(_) => {
                let entries = self.list_private_outbox(device_id, limit).await?;
                let mut out = Vec::with_capacity(entries.len());
                for entry in entries {
                    let message = self
                        .load_private_message(entry.delivery_id.as_str())
                        .await?;
                    out.push(PrivateOutboxMessageRow {
                        device_id,
                        entry,
                        message,
                    });
                }
                Ok(out)
            }
        }
    }

    pub(crate) async fn enqueue_private_outbox_messages_batch(
        &self,
        entries: &[PrivateOutboxMessageBatchEntry],
        max_pending_per_device: usize,
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        match self {
            DatabaseDriver::Sqlite(inner) => {
                inner
                    .enqueue_private_outbox_messages_batch(entries, max_pending_per_device)
                    .await
            }
            DatabaseDriver::MySql(_) | DatabaseDriver::Postgres(_) => {
                let payloads = entries
                    .iter()
                    .map(|item| PrivateMessageBatchEntry {
                        delivery_id: item.entry.delivery_id.clone(),
                        message: item.message.clone(),
                    })
                    .collect::<Vec<_>>();
                self.insert_private_messages_batch(&payloads).await?;
                let outbox = entries
                    .iter()
                    .map(|item| PrivateOutboxBatchEntry {
                        device_id: item.device_id,
                        entry: item.entry.clone(),
                    })
                    .collect::<Vec<_>>();
                self.enqueue_private_outbox_batch(
                    &outbox,
                    max_pending_per_device,
                    i64::MAX as usize,
                    None,
                )
                .await
            }
        }
    }

    pub(crate) async fn clear_private_outbox_entries(
        &self,
        entries: &[(DeviceId, String)],
    ) -> StoreResult<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        match self {
            DatabaseDriver::Sqlite(inner) => inner.clear_private_outbox_entries(entries).await,
            DatabaseDriver::MySql(_) | DatabaseDriver::Postgres(_) => {
                let mut removed = 0usize;
                for (device_id, delivery_id) in entries {
                    self.ack_private_delivery(*device_id, delivery_id.as_str())
                        .await?;
                    removed = removed.saturating_add(1);
                }
                Ok(removed)
            }
        }
    }
}
