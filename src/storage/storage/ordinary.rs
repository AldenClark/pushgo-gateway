use super::*;
use crate::ordinary::{
    OrdinaryStore,
    private_model::PrivateRoute,
    store::{Config, Counters, Health, KernelError},
};

impl Storage {
    /// Attach one ordinary ledger to this Storage's native pool and write gate.
    /// Dataset ownership has to be acquired before Storage itself is initialized.
    pub(crate) async fn initialize_ordinary(
        &self,
        config: Config,
        health: Arc<Health>,
    ) -> Result<OrdinaryStore, KernelError> {
        if let Some(store) = self.ordinary.get() {
            return Ok(store.clone());
        }
        let _initializing = self.ordinary_init_gate.lock().await;
        if let Some(store) = self.ordinary.get() {
            return Ok(store.clone());
        }
        health.ensure()?;
        if config.dedupe_retention_ms != 30 * 86_400_000
            || config.provider_budget == 0
            || config.claim_quantum == 0
            || config.max_provider_targets <= 0
            || config.private.max_pending_per_device == 0
            || config.private.max_pending == 0
        {
            return Err(KernelError::Invalid(
                "invalid product ordinary resource or identity-retention configuration".into(),
            ));
        }
        self.db.assert_ordinary_cutover().await?;
        let mut store = self
            .db
            .initialize_ordinary(
                config,
                health,
                self.durable_write_gate.clone(),
                Arc::new(Counters::default()),
            )
            .await?;
        let cache = self.cache.clone();
        store.set_post_control(Arc::new(move || {
            cache.clear_devices();
            cache.invalidate_all_channel_devices();
        }));
        // The separate startup mutex avoids recursively acquiring the durable
        // gate when native initialization performs bounded maintenance.
        self.ordinary
            .set(store.clone())
            .map_err(|_| KernelError::Invalid("ordinary Storage initialized twice".into()))?;
        Ok(store)
    }

    pub(crate) fn ordinary_handle(&self) -> Option<OrdinaryStore> {
        self.ordinary.get().cloned()
    }

    pub(crate) async fn clear_ordinary_private_channel(
        &self,
        route: &DeviceRouteRecordRow,
    ) -> StoreResult<()> {
        let _control = self.durable_write_gate.lock().await;
        self.ensure_ordinary_health()?;
        self.db.clear_ordinary_private_channel(route).await?;
        self.cache.clear_devices();
        self.cache.invalidate_all_channel_devices();
        self.ordinary_control_committed();
        Ok(())
    }

    /// Private transports already authenticated the existing DeviceId. Resolve
    /// only its canonical control row, then validate the current C capability.
    pub(crate) async fn ordinary_private_route(
        &self,
        device_id: DeviceId,
    ) -> Result<PrivateRoute, KernelError> {
        let store = self.ordinary_handle().ok_or(KernelError::Unavailable)?;
        store.health.ensure()?;
        let device_key = self
            .db
            .ordinary_private_device_key(device_id)
            .await?
            .ok_or(KernelError::Unauthorized)?;
        store.private_route(&device_key).await
    }

    /// Called after ingress, sessions, dispatchers and receipt commits drain.
    /// The exclusive ProductOwner is deliberately released by the caller later.
    pub(crate) async fn close_ordinary_storage(&self) -> Result<(), KernelError> {
        if let Some(ordinary) = self.ordinary_handle() {
            ordinary.close_resources().await?;
        }
        self.db.close_product_pools().await;
        Ok(())
    }

    pub(crate) fn ensure_ordinary_health(&self) -> StoreResult<()> {
        if let Some(store) = self.ordinary.get() {
            store.health.ensure().map_err(StoreError::from)?;
        }
        Ok(())
    }

    pub(crate) fn ordinary_control_committed(&self) {
        if let Some(store) = self.ordinary.get() {
            store.notify();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn isolated_storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(format!(
                "sqlite://{}?mode=rwc",
                directory.path().join("product.db").display()
            )),
            mcp_enabled: false,
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        (directory, storage)
    }

    #[tokio::test]
    async fn concurrent_initialization_shares_one_product_ledger() {
        let (_directory, storage) = isolated_storage().await;
        let health = Arc::new(Health::default());
        let (first, second) = tokio::join!(
            storage.initialize_ordinary(Config::default(), health.clone()),
            storage.initialize_ordinary(Config::default(), health),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert!(Arc::ptr_eq(&first.counters, &second.counters));
        assert!(Arc::ptr_eq(&first.health, &second.health));
        assert!(storage.ordinary_handle().is_some());
        storage.close_ordinary_storage().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_dispatch_sidecar_blocks_cutover_without_fallback() {
        let (_directory, storage) = isolated_storage().await;
        let DatabaseDriver::Sqlite(database) = storage.db.as_ref() else {
            panic!("SQLite test database");
        };
        let at = crate::ordinary::store::now();
        sqlx::query("INSERT INTO dispatch_submission(dedupe_key,delivery_id,op_id,payload_version,payload_blob,acceptance_order,accepted_at,expires_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind("op:00112233445566778899aabbccddeeff:message:00112233445566778899aabbccddeeff:legacy-op")
            .bind("legacy-delivery").bind("legacy-op").bind(1_i32).bind(b"{}".as_slice()).bind(1_i64).bind(at).bind(at+60000)
            .execute(&database.ordinary_dispatch_pool()).await.unwrap();
        let result = storage
            .initialize_ordinary(Config::default(), Arc::default())
            .await;
        assert!(
            matches!(result, Err(KernelError::Invalid(message)) if message.contains("cutover migration"))
        );
        assert!(storage.ordinary_handle().is_none());
        let retained: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dispatch_submission WHERE delivery_id='legacy-delivery'",
        )
        .fetch_one(&database.ordinary_dispatch_pool())
        .await
        .unwrap();
        assert_eq!(retained, 1);
        storage.close_ordinary_storage().await.unwrap();
    }

    #[tokio::test]
    async fn orphaned_legacy_private_body_blocks_cutover_and_is_preserved() {
        let (_directory, storage) = isolated_storage().await;
        let DatabaseDriver::Sqlite(database) = storage.db.as_ref() else {
            panic!("SQLite test database");
        };
        let at = crate::ordinary::store::now();
        let payload = postcard::to_allocvec(&crate::private::protocol::PrivatePayloadEnvelope {
            payload_version: crate::private::protocol::PrivatePayloadEnvelope::CURRENT_VERSION,
            data: hashbrown::HashMap::from_iter([
                ("entity_type".into(), "message".into()),
                ("message_id".into(), "legacy-message".into()),
            ]),
        })
        .unwrap();
        sqlx::query("INSERT INTO private_payloads(delivery_id,payload_blob,payload_size,sent_at,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind("legacy-delivery").bind(&payload).bind(payload.len() as i64).bind(at).bind(at+60000).bind(at).bind(at)
            .execute(&database.ordinary_delivery_pool()).await.unwrap();
        let result = storage
            .initialize_ordinary(Config::default(), Arc::default())
            .await;
        assert!(
            matches!(result, Err(KernelError::Invalid(message)) if message.contains("cutover migration"))
        );
        assert!(storage.ordinary_handle().is_none());
        let retained: Vec<u8> = sqlx::query_scalar(
            "SELECT payload_blob FROM private_payloads WHERE delivery_id='legacy-delivery'",
        )
        .fetch_one(&database.ordinary_delivery_pool())
        .await
        .unwrap();
        assert_eq!(retained, payload);
        storage.close_ordinary_storage().await.unwrap();
    }
}
