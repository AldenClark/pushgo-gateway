use super::*;

impl SqliteDb {
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
            payload: r.get("payload_blob"),
            size: r.get::<i64, _>("payload_size") as usize,
            sent_at: r.get("sent_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    pub(super) async fn load_private_payload_context(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivatePayloadContext>> {
        if let Some(msg) = self.load_private_message(delivery_id).await? {
            return Ok(decode_private_payload_context(&msg.payload));
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
        let now = Utc::now().timestamp();
        let size = message.size as i64;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
             payload_blob = EXCLUDED.payload_blob, payload_size = EXCLUDED.payload_size, sent_at = EXCLUDED.sent_at, \
             expires_at = EXCLUDED.expires_at, platform = EXCLUDED.platform, provider_token = EXCLUDED.provider_token, updated_at = EXCLUDED.updated_at",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(&message.payload)
        .bind(size)
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT payload_blob, sent_at, expires_at, platform, provider_token \
             FROM provider_pull_queue \
             WHERE device_id = ? AND delivery_id = ? AND expires_at > ?",
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
                payload: r.get("payload_blob"),
                sent_at: r.get("sent_at"),
                expires_at: r.get("expires_at"),
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query(
            "SELECT delivery_id, payload_blob, sent_at, expires_at, platform, provider_token \
             FROM provider_pull_queue \
             WHERE device_id = ? AND expires_at > ? \
             ORDER BY created_at ASC LIMIT ?",
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
                payload: r.get("payload_blob"),
                sent_at: r.get("sent_at"),
                expires_at: r.get("expires_at"),
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = ? AND expires_at <= ?")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT payload_blob, sent_at, expires_at, platform, provider_token \
             FROM provider_pull_queue \
             WHERE device_id = ? AND delivery_id = ?",
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
                payload: r.get("payload_blob"),
                sent_at: r.get("sent_at"),
                expires_at: r.get("expires_at"),
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
