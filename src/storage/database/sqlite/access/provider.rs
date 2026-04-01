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
        delivery_id: &str,
        message: &PrivateMessage,
        platform: Platform,
        provider_token: &str,
        next_retry_at: i64,
    ) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;

        let size = message.size as i64;
        sqlx::query(
            "INSERT INTO private_payloads (delivery_id, payload_blob, payload_size, sent_at, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (delivery_id) DO UPDATE SET \
             payload_blob = EXCLUDED.payload_blob, payload_size = EXCLUDED.payload_size, updated_at = EXCLUDED.updated_at",
        )
        .bind(delivery_id)
        .bind(&message.payload)
        .bind(size)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_queue (delivery_id, status, pulled_at, acked_at, created_at, updated_at) \
             VALUES (?, 'pending', NULL, NULL, ?, ?) \
             ON CONFLICT (delivery_id) DO UPDATE SET status = 'pending', updated_at = EXCLUDED.updated_at",
        )
        .bind(delivery_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO provider_pull_retry \
             (delivery_id, platform, provider_token, attempts, next_retry_at, last_attempt_at, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, 0, ?, NULL, ?, ?, ?) \
             ON CONFLICT (delivery_id) DO UPDATE SET \
                attempts = 0, next_retry_at = EXCLUDED.next_retry_at, updated_at = EXCLUDED.updated_at",
        )
        .bind(delivery_id)
        .bind(platform.name())
        .bind(provider_token)
        .bind(next_retry_at)
        .bind(message.expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn pull_provider_item(
        &self,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = (*conn).begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT p.payload_blob, p.sent_at, p.expires_at \
             FROM provider_pull_queue q \
             INNER JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.delivery_id = ? AND q.status = 'pending' AND p.expires_at > ?",
        )
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let result = if let Some(r) = row {
            sqlx::query("UPDATE provider_pull_queue SET status = 'pulled', pulled_at = ?, updated_at = ? WHERE delivery_id = ? AND status = 'pending'")
                .bind(now)
                .bind(now)
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM private_payloads WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM provider_pull_queue WHERE delivery_id = ?")
                .bind(delivery_id)
                .execute(&mut *tx)
                .await?;
            Some(ProviderPullItem {
                delivery_id: delivery_id.to_string(),
                payload: r.get("payload_blob"),
                sent_at: r.get("sent_at"),
                expires_at: r.get("expires_at"),
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(result)
    }

    pub(super) async fn list_provider_pull_retry_due(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullRetryEntry>> {
        let rows = sqlx::query(
            "SELECT r.delivery_id, r.platform, r.provider_token, r.attempts, r.next_retry_at, r.expires_at \
             FROM provider_pull_retry r \
             INNER JOIN provider_pull_queue q ON q.delivery_id = r.delivery_id \
             WHERE q.status = 'pending' AND r.next_retry_at <= ? AND r.expires_at > ? \
             ORDER BY r.next_retry_at ASC LIMIT ?",
        )
        .bind(now)
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let platform_text: String = r.get("platform");
            let platform = platform_text.parse()?;
            out.push(ProviderPullRetryEntry {
                delivery_id: r.get("delivery_id"),
                platform,
                provider_token: r.get("provider_token"),
                attempts: r.get::<i64, _>("attempts") as i32,
                next_retry_at: r.get("next_retry_at"),
                expires_at: r.get("expires_at"),
            });
        }
        Ok(out)
    }

    pub(super) async fn bump_provider_pull_retry(
        &self,
        delivery_id: &str,
        next_retry_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE provider_pull_retry SET attempts = attempts + 1, next_retry_at = ?, last_attempt_at = ?, updated_at = ? \
             WHERE delivery_id = ? AND expires_at > ?",
        )
        .bind(next_retry_at)
        .bind(now)
        .bind(now)
        .bind(delivery_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn clear_provider_pull_retry(&self, delivery_id: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM provider_pull_retry WHERE delivery_id = ?")
            .bind(delivery_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
