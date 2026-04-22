use super::*;

impl PostgresDb {
    pub(super) async fn reserve_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "INSERT INTO dispatch_delivery_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4) ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Sent.as_str())
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn reserve_semantic_id(
        &self,
        dedupe_key: &str,
        semantic_id: &str,
        created_at: i64,
    ) -> StoreResult<SemanticIdReservation> {
        let result = sqlx::query(
            "INSERT INTO semantic_id_registry (dedupe_key, semantic_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $3) ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(semantic_id)
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            Ok(SemanticIdReservation::Reserved)
        } else {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key = $1",
            )
            .bind(dedupe_key)
            .fetch_optional(&self.pool)
            .await?;
            Ok(match existing {
                Some(s) => SemanticIdReservation::Existing { semantic_id: s },
                None => SemanticIdReservation::Collision,
            })
        }
    }

    pub(super) async fn reserve_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
        created_at: i64,
    ) -> StoreResult<OpDedupeReservation> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO dispatch_op_dedupe (dedupe_key, delivery_id, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4) \
             ON CONFLICT (dedupe_key) DO NOTHING",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .bind(created_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        let outcome = if inserted {
            OpDedupeReservation::Reserved
        } else {
            let existing = sqlx::query(
                "SELECT delivery_id, state FROM dispatch_op_dedupe WHERE dedupe_key = $1 FOR UPDATE",
            )
            .bind(dedupe_key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                let existing_delivery_id: String = row.try_get("delivery_id")?;
                let state: String = row.try_get("state")?;
                match DedupeState::from_str(state.as_str())? {
                    DedupeState::Pending => OpDedupeReservation::Pending {
                        delivery_id: existing_delivery_id,
                    },
                    DedupeState::Sent => OpDedupeReservation::Sent {
                        delivery_id: existing_delivery_id,
                    },
                }
            } else {
                OpDedupeReservation::Pending {
                    delivery_id: delivery_id.to_string(),
                }
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    pub(super) async fn mark_op_dedupe_sent(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<bool> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE dispatch_op_dedupe \
             SET state = $1, sent_at = $2, updated_at = $2 \
             WHERE dedupe_key = $3 AND delivery_id = $4 AND state = $5",
        )
        .bind(DedupeState::Sent.as_str())
        .bind(now)
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn clear_op_dedupe_pending(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query(
            "DELETE FROM dispatch_op_dedupe \
             WHERE dedupe_key = $1 AND delivery_id = $2 AND state = $3",
        )
        .bind(dedupe_key)
        .bind(delivery_id)
        .bind(DedupeState::Pending.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn confirm_delivery_dedupe(
        &self,
        dedupe_key: &str,
        delivery_id: &str,
    ) -> StoreResult<()> {
        sqlx::query("UPDATE dispatch_delivery_dedupe SET state = $1, updated_at = $2 WHERE dedupe_key = $3 AND delivery_id = $4")
            .bind(DedupeState::Sent.as_str())
            .bind(Utc::now().timestamp())
            .bind(dedupe_key)
            .bind(delivery_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(super) async fn automation_reset(&self) -> StoreResult<()> {
        let tables = vec![
            "subscription_audit",
            "device_route_audit",
            "channel_stats_daily",
            "device_stats_daily",
            "gateway_stats_hourly",
            "ops_stats_hourly",
            "dispatch_op_dedupe",
            "dispatch_delivery_dedupe",
            "semantic_id_registry",
            "channel_subscriptions",
            "devices",
            "channels",
            "private_bindings",
            "private_outbox",
            "private_payloads",
            "private_sessions",
            "private_device_keys",
            "mcp_state",
        ];
        let mut tx = self.pool.begin().await?;
        for table in tables {
            sqlx::query(&format!(
                "TRUNCATE TABLE {} RESTART IDENTITY CASCADE",
                table
            ))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channels")
            .fetch_one(&self.pool)
            .await?;
        let subscription_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
                .fetch_one(&self.pool)
                .await?;
        let delivery_dedupe_pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_delivery_dedupe")
                .fetch_one(&self.pool)
                .await?;

        Ok(AutomationCounts {
            channel_count: channel_count as usize,
            subscription_count: subscription_count as usize,
            delivery_dedupe_pending_count: delivery_dedupe_pending_count as usize,
        })
    }

    pub(super) async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state_json FROM mcp_state WHERE state_key = $1",
        )
        .bind("default")
        .fetch_optional(&self.pool)
        .await?;
        Ok(state)
    }

    pub(super) async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO mcp_state (state_key, state_json, updated_at) VALUES ($1, $2, $3) \
             ON CONFLICT(state_key) DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = EXCLUDED.updated_at",
        )
        .bind("default")
        .bind(state_json)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
