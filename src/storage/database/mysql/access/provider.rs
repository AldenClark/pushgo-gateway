use super::*;
use std::sync::Arc;

impl MySqlDb {
    pub(super) async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>> {
        let row = sqlx::query(
            "SELECT payload_blob, payload_size, sent_at, expires_at \
             FROM private_payloads WHERE delivery_id = ?",
        )
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PrivateMessage {
            payload: Arc::from(r.get::<Vec<u8>, _>("payload_blob")),
            size: decode_mysql_payload_size(&r),
            sent_at: r.get("sent_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    pub(super) async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        if let Some(msg) = self.load_private_message(delivery_id).await? {
            return Ok(decode_private_payload_context(msg.payload.as_ref()));
        }
        Ok(None)
    }

    pub(super) async fn enqueue_provider_pull_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp_millis();
        self.insert_private_message(delivery_id, message).await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             payload_blob = VALUES(payload_blob), payload_size = VALUES(payload_size), sent_at = VALUES(sent_at), \
             expires_at = VALUES(expires_at), platform = VALUES(platform), provider_token = VALUES(provider_token), updated_at = VALUES(updated_at)",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(<&[u8]>::default())
        .bind(0_i64)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(platform.name())
        .bind(provider_token)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn pull_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = ? AND q.delivery_id = ? AND q.expires_at > ?",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let result = if let Some(r) = row {
            sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?")
                .bind(device_id.as_slice())
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            Some(ProviderPullItem {
                device_id,
                delivery_id: delivery_id.to_string(),
                payload: provider_payload_from_row(&r),
                sent_at: provider_sent_at_from_row(&r),
                expires_at: provider_expires_at_from_row(&r),
                platform: r.get::<String, _>("platform").parse()?,
                provider_token: r.get("provider_token"),
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(result)
    }

    pub(super) async fn pull_provider_items(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullItem>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query(
            "SELECT q.delivery_id, q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = ? AND q.expires_at > ? \
             ORDER BY q.created_at ASC LIMIT ?",
        )
        .bind(device_id.as_slice())
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        let mut delivery_ids = Vec::with_capacity(rows.len());
        for r in rows {
            let delivery_id: String = r.get("delivery_id");
            let platform_text: String = r.get("platform");
            let platform = platform_text.parse()?;
            out.push(ProviderPullItem {
                device_id,
                delivery_id: delivery_id.clone(),
                payload: provider_payload_from_row(&r),
                sent_at: provider_sent_at_from_row(&r),
                expires_at: provider_expires_at_from_row(&r),
                platform,
                provider_token: r.get("provider_token"),
            });
            delivery_ids.push(delivery_id);
        }

        for delivery_id in &delivery_ids {
            sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?")
                .bind(device_id.as_slice())
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(out)
    }

    pub(super) async fn ack_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = ? AND q.delivery_id = ?",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .fetch_optional(&mut *tx)
        .await?;

        let out = if let Some(r) = row {
            sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?")
                .bind(device_id.as_slice())
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            Some(ProviderPullItem {
                device_id,
                delivery_id: delivery_id.to_string(),
                payload: provider_payload_from_row(&r),
                sent_at: provider_sent_at_from_row(&r),
                expires_at: provider_expires_at_from_row(&r),
                platform: r.get::<String, _>("platform").parse()?,
                provider_token: r.get("provider_token"),
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(out)
    }
}

fn provider_payload_from_row(row: &sqlx::mysql::MySqlRow) -> Arc<[u8]> {
    Arc::from(
        row.get::<Option<Vec<u8>>, _>("shared_payload_blob")
            .or_else(|| row.get::<Option<Vec<u8>>, _>("queue_payload_blob"))
            .unwrap_or_default(),
    )
}

fn provider_sent_at_from_row(row: &sqlx::mysql::MySqlRow) -> i64 {
    row.get::<Option<i64>, _>("shared_sent_at")
        .or_else(|| row.get::<Option<i64>, _>("queue_sent_at"))
        .unwrap_or_default()
}

fn provider_expires_at_from_row(row: &sqlx::mysql::MySqlRow) -> i64 {
    row.get::<Option<i64>, _>("shared_expires_at")
        .or_else(|| row.get::<Option<i64>, _>("queue_expires_at"))
        .unwrap_or_default()
}
