use super::*;
use crate::storage::database::pg::access::maintenance::delete_orphan_private_payload_in_pg_tx;
use std::sync::Arc;

impl PostgresDb {
    pub(super) async fn load_private_message(
        &self,
        delivery_id: &str,
    ) -> StoreResult<Option<PrivateMessage>> {
        let row = sqlx::query(
            "SELECT payload_blob, payload_size, sent_at, expires_at \
             FROM private_payloads WHERE delivery_id = $1",
        )
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PrivateMessage {
            payload: Arc::from(r.get::<Vec<u8>, _>("payload_blob")),
            size: r.get::<i32, _>("payload_size") as usize,
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
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = $1 AND expires_at <= $2")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO provider_pull_queue \
             (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) \
             ON CONFLICT (device_id, delivery_id) DO UPDATE SET \
             payload_blob = EXCLUDED.payload_blob, payload_size = EXCLUDED.payload_size, sent_at = EXCLUDED.sent_at, \
             expires_at = EXCLUDED.expires_at, platform = EXCLUDED.platform, provider_token = EXCLUDED.provider_token, updated_at = EXCLUDED.updated_at",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(<&[u8]>::default())
        .bind(0_i32)
        .bind(message.sent_at)
        .bind(message.expires_at)
        .bind(platform.name())
        .bind(provider_token)
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
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = $1 AND expires_at <= $2")
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
             WHERE q.device_id = $1 AND q.delivery_id = $2 AND q.expires_at > $3",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let result = if let Some(r) = row {
            sqlx::query(
                "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(device_id.as_slice())
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
            delete_orphan_private_payload_in_pg_tx(&mut tx, delivery_id).await?;
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
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = $1 AND expires_at <= $2")
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
             WHERE q.device_id = $1 AND q.expires_at > $2 \
             ORDER BY q.created_at ASC LIMIT $3",
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
            sqlx::query(
                "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(device_id.as_slice())
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
            delete_orphan_private_payload_in_pg_tx(&mut tx, delivery_id).await?;
        }

        tx.commit().await?;
        Ok(out)
    }

    pub(super) async fn peek_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let row = sqlx::query(
            "SELECT q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = $1 AND q.delivery_id = $2 AND q.expires_at > $3",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| provider_item_from_row(device_id, delivery_id.to_string(), &row))
            .transpose()
    }

    pub(super) async fn peek_provider_items(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullItem>> {
        let rows = sqlx::query(
            "SELECT q.delivery_id, q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = $1 AND q.expires_at > $2 \
             ORDER BY q.created_at ASC, q.delivery_id ASC LIMIT $3",
        )
        .bind(device_id.as_slice())
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let delivery_id = row.get("delivery_id");
                provider_item_from_row(device_id, delivery_id, &row)
            })
            .collect()
    }

    pub(super) async fn peek_provider_candidate(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullCandidate>> {
        let row = sqlx::query(
            "SELECT q.payload_blob AS queue_payload_blob, \
                    p.payload_blob AS shared_payload_blob \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = $1 AND q.delivery_id = $2 AND q.expires_at > $3",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| ProviderPullCandidate {
            delivery_id: delivery_id.to_string(),
            payload: provider_payload_from_row(&row),
        }))
    }

    pub(super) async fn peek_provider_candidates(
        &self,
        device_id: DeviceId,
        now: i64,
        limit: usize,
    ) -> StoreResult<Vec<ProviderPullCandidate>> {
        let rows = sqlx::query(
            "SELECT q.delivery_id, q.payload_blob AS queue_payload_blob, \
                    p.payload_blob AS shared_payload_blob \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = $1 AND q.expires_at > $2 \
             ORDER BY q.created_at ASC, q.delivery_id ASC LIMIT $3",
        )
        .bind(device_id.as_slice())
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ProviderPullCandidate {
                delivery_id: row.get("delivery_id"),
                payload: provider_payload_from_row(&row),
            })
            .collect())
    }

    pub(super) async fn ack_provider_item(
        &self,
        device_id: DeviceId,
        delivery_id: &str,
        now: i64,
    ) -> StoreResult<Option<ProviderPullItem>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = $1 AND expires_at <= $2")
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
             WHERE q.device_id = $1 AND q.delivery_id = $2",
        )
        .bind(device_id.as_slice())
        .bind(delivery_id)
        .fetch_optional(&mut *tx)
        .await?;

        let out = if let Some(r) = row {
            let payload = provider_payload_from_row(&r);
            if let Some(original_delivery_id) =
                crate::storage::database::linked_private_outbox_delivery_id(payload.as_ref())
            {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2")
                    .bind(device_id.as_slice())
                    .bind(&original_delivery_id)
                    .execute(&mut *tx)
                    .await?;
                delete_orphan_private_payload_in_pg_tx(&mut tx, &original_delivery_id).await?;
            }
            sqlx::query(
                "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(device_id.as_slice())
            .bind(delivery_id)
            .execute(&mut *tx)
            .await?;
            delete_orphan_private_payload_in_pg_tx(&mut tx, delivery_id).await?;
            Some(ProviderPullItem {
                device_id,
                delivery_id: delivery_id.to_string(),
                payload,
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

    pub(super) async fn ack_provider_items(
        &self,
        device_id: DeviceId,
        delivery_ids: &[String],
        now: i64,
    ) -> StoreResult<Vec<ProviderPullItem>> {
        if delivery_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM provider_pull_queue WHERE device_id = $1 AND expires_at <= $2")
            .bind(device_id.as_slice())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT q.delivery_id, q.payload_blob AS queue_payload_blob, q.sent_at AS queue_sent_at, \
                    q.expires_at AS queue_expires_at, q.platform, q.provider_token, \
                    p.payload_blob AS shared_payload_blob, p.sent_at AS shared_sent_at, \
                    p.expires_at AS shared_expires_at \
             FROM provider_pull_queue q \
             LEFT JOIN private_payloads p ON p.delivery_id = q.delivery_id \
             WHERE q.device_id = ",
        );
        query.push_bind(device_id.as_slice());
        query.push(" AND q.delivery_id IN (");
        let mut separated = query.separated(", ");
        for delivery_id in delivery_ids {
            separated.push_bind(delivery_id);
        }
        separated.push_unseparated(") ORDER BY q.delivery_id ASC FOR UPDATE");
        let rows = query.build().fetch_all(&mut *tx).await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery_id: String = row.get("delivery_id");
            let item = provider_item_from_row(device_id, delivery_id.clone(), &row)?;
            if let Some(original_delivery_id) =
                crate::storage::database::linked_private_outbox_delivery_id(item.payload.as_ref())
            {
                sqlx::query("DELETE FROM private_outbox WHERE device_id = $1 AND delivery_id = $2")
                    .bind(device_id.as_slice())
                    .bind(&original_delivery_id)
                    .execute(&mut *tx)
                    .await?;
                delete_orphan_private_payload_in_pg_tx(&mut tx, &original_delivery_id).await?;
            }
            sqlx::query(
                "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(device_id.as_slice())
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;
            delete_orphan_private_payload_in_pg_tx(&mut tx, &delivery_id).await?;
            out.push(item);
        }
        tx.commit().await?;
        Ok(out)
    }

    pub(super) async fn discard_provider_items_by_outer_ids(
        &self,
        device_id: DeviceId,
        delivery_ids: &[String],
        now: i64,
    ) -> StoreResult<usize> {
        if delivery_ids.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await?;
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT delivery_id FROM provider_pull_queue WHERE device_id = ",
        );
        query.push_bind(device_id.as_slice());
        query.push(" AND expires_at > ");
        query.push_bind(now);
        query.push(" AND delivery_id IN (");
        let mut separated = query.separated(", ");
        for delivery_id in delivery_ids {
            separated.push_bind(delivery_id);
        }
        separated.push_unseparated(") ORDER BY delivery_id ASC FOR UPDATE");
        let rows = query.build().fetch_all(&mut *tx).await?;

        for row in &rows {
            let delivery_id: String = row.get("delivery_id");
            sqlx::query(
                "DELETE FROM provider_pull_queue WHERE device_id = $1 AND delivery_id = $2",
            )
            .bind(device_id.as_slice())
            .bind(&delivery_id)
            .execute(&mut *tx)
            .await?;
            delete_orphan_private_payload_in_pg_tx(&mut tx, &delivery_id).await?;
        }
        let removed = rows.len();
        tx.commit().await?;
        Ok(removed)
    }
}

fn provider_item_from_row(
    device_id: DeviceId,
    delivery_id: String,
    row: &sqlx::postgres::PgRow,
) -> StoreResult<ProviderPullItem> {
    Ok(ProviderPullItem {
        device_id,
        delivery_id,
        payload: provider_payload_from_row(row),
        sent_at: provider_sent_at_from_row(row),
        expires_at: provider_expires_at_from_row(row),
        platform: row.get::<String, _>("platform").parse()?,
        provider_token: row.get("provider_token"),
    })
}

fn provider_payload_from_row(row: &sqlx::postgres::PgRow) -> Arc<[u8]> {
    Arc::from(
        row.get::<Option<Vec<u8>>, _>("shared_payload_blob")
            .or_else(|| row.get::<Option<Vec<u8>>, _>("queue_payload_blob"))
            .unwrap_or_default(),
    )
}

fn provider_sent_at_from_row(row: &sqlx::postgres::PgRow) -> i64 {
    row.get::<Option<i64>, _>("shared_sent_at")
        .or_else(|| row.get::<Option<i64>, _>("queue_sent_at"))
        .unwrap_or_default()
}

fn provider_expires_at_from_row(row: &sqlx::postgres::PgRow) -> i64 {
    row.get::<Option<i64>, _>("shared_expires_at")
        .or_else(|| row.get::<Option<i64>, _>("queue_expires_at"))
        .unwrap_or_default()
}
