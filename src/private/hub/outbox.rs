impl PrivateHub {
    pub(crate) async fn enqueue_private_message(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        payload: Vec<u8>,
        sent_at: i64,
        expires_at: i64,
    ) -> Result<EnqueuePrivateMessageOutcome, crate::Error> {
        let now = chrono::Utc::now().timestamp();
        let device_pending = self
            .store
            .count_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        if device_pending >= self.max_pending_per_device {
            return Err(crate::Error::TooBusy);
        }
        let mut total_pending = self
            .store
            .count_private_outbox_total()
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        let mut private_outbox_pruned = 0usize;
        if total_pending >= self.global_max_pending {
            private_outbox_pruned = self
                .store
                .cleanup_private_expired_data(now, 4096)
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            total_pending = self
                .store
                .count_private_outbox_total()
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            if total_pending >= self.global_max_pending {
                return Err(crate::Error::TooBusy);
            }
        }

        let should_persist_message = !self.hot_messages.contains_key(delivery_id);
        if should_persist_message {
            let size = payload.len();
            let message = PrivateMessage {
                payload,
                size,
                sent_at,
                expires_at,
            };
            self.store
                .insert_private_message(delivery_id, &message)
                .await
                .map_err(|err| crate::Error::Internal(err.to_string()))?;
            self.cache_put(delivery_id, &message);
        }

        let entry = PrivateOutboxEntry {
            delivery_id: delivery_id.to_string(),
            status: "pending".to_string(),
            attempts: 0,
            occurred_at: sent_at,
            created_at: now,
            claimed_at: None,
            first_sent_at: None,
            last_attempt_at: None,
            acked_at: None,
            fallback_sent_at: None,
            next_attempt_at: sent_at.saturating_add(self.ack_timeout_secs.max(1)),
            last_error_code: None,
            last_error_detail: None,
            updated_at: now,
        };
        self.store
            .enqueue_private_outbox(device_id, &entry)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        Ok(EnqueuePrivateMessageOutcome {
            private_outbox_pruned,
        })
    }

    pub async fn pull_outbox(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> Result<Vec<(PrivateOutboxEntry, PrivateMessage)>, crate::Error> {
        let entries = self
            .store
            .list_private_outbox(device_id, limit)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        let mut out = Vec::new();
        for entry in entries {
            if let Some(message) = self.load_message_cached(entry.delivery_id.as_str()).await? {
                out.push((entry, message));
            }
        }
        Ok(out)
    }

    pub(crate) async fn build_bootstrap_queues(
        &self,
        device_id: DeviceId,
        limit: usize,
    ) -> Result<BootstrapQueues, crate::Error> {
        let inflight_snapshot = self.snapshot_inflight(device_id);
        let mut inflight = VecDeque::new();
        let mut inflight_delivery_ids = HashSet::new();
        for (seq, item) in inflight_snapshot {
            inflight_delivery_ids.insert(item.delivery_id.clone());
            inflight.push_back((
                seq,
                protocol::DeliverEnvelope {
                    delivery_id: item.delivery_id,
                    payload: item.payload,
                },
            ));
        }

        let rows = self.pull_outbox(device_id, limit).await?;
        let mut pending = VecDeque::new();
        for (entry, msg) in rows {
            if inflight_delivery_ids.contains(entry.delivery_id.as_str()) {
                continue;
            }
            pending.push_back(protocol::DeliverEnvelope {
                delivery_id: entry.delivery_id,
                payload: msg.payload,
            });
        }

        Ok(BootstrapQueues { inflight, pending })
    }

    pub async fn count_pending_outbox_total(&self) -> Result<usize, crate::Error> {
        self.store
            .count_private_outbox_total()
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn count_pending_outbox_for_device(
        &self,
        device_id: DeviceId,
    ) -> Result<usize, crate::Error> {
        self.store
            .count_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn list_due_outbox(
        &self,
        before_ts: i64,
        limit: usize,
    ) -> Result<Vec<(DeviceId, PrivateOutboxEntry)>, crate::Error> {
        self.store
            .list_private_outbox_due(before_ts, limit)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn claim_due_outbox(
        &self,
        now: i64,
        limit: usize,
        claim_until: i64,
    ) -> Result<Vec<(DeviceId, PrivateOutboxEntry)>, crate::Error> {
        self.store
            .claim_private_outbox_due(now, limit, claim_until)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn claim_due_outbox_for_device(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
        claim_until: i64,
    ) -> Result<Vec<PrivateOutboxEntry>, crate::Error> {
        self.store
            .claim_private_outbox_due_for_device(device_id, now, limit, claim_until)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn ack_delivery(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<(), crate::Error> {
        self.store
            .ack_private_delivery(device_id, delivery_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn mark_fallback_sent(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        next_attempt_at: i64,
    ) -> Result<(), crate::Error> {
        self.store
            .mark_private_fallback_sent(device_id, delivery_id, next_attempt_at)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn defer_fallback_retry(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        retry_at: i64,
    ) -> Result<(), crate::Error> {
        self.store
            .defer_private_fallback(device_id, delivery_id, retry_at)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn clear_device_outbox(
        &self,
        device_id: DeviceId,
    ) -> Result<Vec<String>, crate::Error> {
        self.store
            .clear_private_outbox_for_device(device_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn run_maintenance_cleanup(
        &self,
        now: i64,
        dedupe_before: i64,
    ) -> Result<MaintenanceCleanupStats, crate::Error> {
        self.store
            .run_maintenance_cleanup(now, dedupe_before)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn is_delivery_pending(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
    ) -> Result<bool, crate::Error> {
        self.store
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .map(|item| item.is_some())
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn bind_token(
        &self,
        device_id: DeviceId,
        platform: Platform,
        token: &str,
    ) -> Result<(), crate::Error> {
        self.store
            .bind_private_token(device_id, platform, token)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn list_channel_devices(
        &self,
        channel_id: [u8; 16],
    ) -> Result<Vec<crate::storage::DeviceInfo>, crate::Error> {
        self.store
            .list_channel_devices(channel_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn lookup_device_for_token(
        &self,
        platform: Platform,
        token: &str,
    ) -> Result<Option<DeviceId>, crate::Error> {
        self.store
            .lookup_private_device(platform, token)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))
    }

    pub async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> Result<Option<PrivateMessage>, crate::Error> {
        self.load_message_cached(delivery_id).await
    }

    async fn load_message_cached(
        &self,
        delivery_id: &str,
    ) -> Result<Option<PrivateMessage>, crate::Error> {
        if let Some(item) = self.hot_messages.get(delivery_id) {
            return Ok(Some(item.clone()));
        }
        let message = self
            .store
            .load_private_message(delivery_id)
            .await
            .map_err(|err| crate::Error::Internal(err.to_string()))?;
        if let Some(value) = message.as_ref() {
            self.cache_put(delivery_id, value);
        }
        Ok(message)
    }
}
