//! The runtime and HTTP layer select whole ledger operations, not SQL dialects.
//! Each backend retains its native connection, transactions and query plans.
use crate::mysql_store::MySqlDeliveryStore;
use crate::pg_store::PgDeliveryStore;
use crate::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, DeliveryStore, Health, KernelError,
    OwnerLock, Result, Ticket,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Clone)]
enum Backend {
    Sqlite(DeliveryStore),
    Postgres(PgDeliveryStore),
    MySql(MySqlDeliveryStore),
}
#[derive(Clone)]
pub struct OrdinaryStore {
    backend: Backend,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(super) wake: [Arc<Notify>; 2],
    pub(super) health: Arc<Health>,
    pub(super) private_wake: Arc<Notify>,
}
impl From<DeliveryStore> for OrdinaryStore {
    fn from(store: DeliveryStore) -> Self {
        Self {
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            backend: Backend::Sqlite(store),
        }
    }
}
impl From<PgDeliveryStore> for OrdinaryStore {
    fn from(store: PgDeliveryStore) -> Self {
        Self {
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            backend: Backend::Postgres(store),
        }
    }
}
impl From<MySqlDeliveryStore> for OrdinaryStore {
    fn from(store: MySqlDeliveryStore) -> Self {
        Self {
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            backend: Backend::MySql(store),
        }
    }
}
impl OrdinaryStore {
    pub(super) async fn open(url: &str, config: Config) -> Result<(Self, OwnerLock)> {
        if url.starts_with("sqlite:") {
            let (s, o) = DeliveryStore::open(url, config).await?;
            Ok((s.into(), o))
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            let (s, o) = PgDeliveryStore::open(url, config).await?;
            Ok((s.into(), o))
        } else if url.starts_with("mysql:") {
            let (s, o) = MySqlDeliveryStore::open(url, config).await?;
            Ok((s.into(), o))
        } else {
            Err(KernelError::Invalid(
                "supported ordinary backends: SQLite, PostgreSQL or MySQL".into(),
            ))
        }
    }
    pub(super) async fn close(&self) {
        match &self.backend {
            Backend::Sqlite(s) => s.pool.close().await,
            Backend::Postgres(s) => s.close().await,
            Backend::MySql(s) => s.close().await,
        }
    }
    pub(super) fn notify(&self) {
        self.private_wake.notify_one();
        for wake in &self.wake {
            wake.notify_one();
        }
    }
    fn checked<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(KernelError::Database(error)) = &result {
            let disconnected = matches!(
                error,
                sqlx::Error::Io(_)
                    | sqlx::Error::Tls(_)
                    | sqlx::Error::Protocol(_)
                    | sqlx::Error::WorkerCrashed
                    | sqlx::Error::PoolClosed
            ) || error
                .as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|c| {
                    c.starts_with("08") || matches!(c.as_ref(), "57P01" | "57P02" | "57P03")
                });
            let disconnected = disconnected
                || error
                    .as_database_error()
                    .and_then(|e| e.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
                    .is_some_and(|e| matches!(e.number(), 1053 | 2006 | 2013 | 2055 | 4031));
            if disconnected {
                self.health
                    .fail("ledger connection failed; exclusive-owner restart required");
                self.notify();
            }
        }
        result
    }
    #[cfg(test)]
    pub(super) fn sqlite_store(&self) -> Option<DeliveryStore> {
        match &self.backend {
            Backend::Sqlite(s) => Some(s.clone()),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(super) fn postgres_store(&self) -> Option<PgDeliveryStore> {
        match &self.backend {
            Backend::Postgres(s) => Some(s.clone()),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(super) fn mysql_store(&self) -> Option<MySqlDeliveryStore> {
        match &self.backend {
            Backend::MySql(s) => Some(s.clone()),
            _ => None,
        }
    }
}

impl OrdinaryStore {
    pub async fn register_device(&self, platform: &str, requested: Option<&str>) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.register_device(platform, requested).await,
            Backend::Postgres(s) => s.register_device(platform, requested).await,
            Backend::MySql(s) => s.register_device(platform, requested).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn update_route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: Option<&str>,
    ) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.update_route(device, platform, provider, raw).await,
            Backend::Postgres(s) => s.update_route(device, platform, provider, raw).await,
            Backend::MySql(s) => s.update_route(device, platform, provider, raw).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn delete_route(&self, device: &str, channel_type: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.delete_route(device, channel_type).await,
            Backend::Postgres(s) => s.delete_route(device, channel_type).await,
            Backend::MySql(s) => s.delete_route(device, channel_type).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn retire_provider_token(&self, platform: &str, raw: &str) -> Result<()> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.retire_provider_token(platform, raw).await,
            Backend::Postgres(s) => s.retire_provider_token(platform, raw).await,
            Backend::MySql(s) => s.retire_provider_token(platform, raw).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn subscribe(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.subscribe(device, channel_id, channel_name, auth).await,
            Backend::Postgres(s) => s.subscribe(device, channel_id, channel_name, auth).await,
            Backend::MySql(s) => s.subscribe(device, channel_id, channel_name, auth).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn unsubscribe(&self, device: &str, channel: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.unsubscribe(device, channel).await,
            Backend::Postgres(s) => s.unsubscribe(device, channel).await,
            Backend::MySql(s) => s.unsubscribe(device, channel).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn channel_info(&self, channel: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.channel_info(channel).await,
            Backend::Postgres(s) => s.channel_info(channel).await,
            Backend::MySql(s) => s.channel_info(channel).await,
        };
        self.checked(result)
    }
    pub async fn rename_channel(&self, channel: &str, name: &str, password: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.rename_channel(channel, name, password).await,
            Backend::Postgres(s) => s.rename_channel(channel, name, password).await,
            Backend::MySql(s) => s.rename_channel(channel, name, password).await,
        };
        self.checked(result)
    }
    pub async fn sync_channels(&self, device: &str, items: Vec<(String, String)>) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.sync_channels(device, items).await,
            Backend::Postgres(s) => s.sync_channels(device, items).await,
            Backend::MySql(s) => s.sync_channels(device, items).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn accept(&self, request: AcceptRequest) -> Result<Accepted> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.accept(request).await,
            Backend::Postgres(s) => s.accept(request).await,
            Backend::MySql(s) => s.accept(request).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn maintenance(&self) -> Result<usize> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.maintenance().await,
            Backend::Postgres(s) => s.maintenance().await,
            Backend::MySql(s) => s.maintenance().await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn pull(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.pull(device, delivery).await,
            Backend::Postgres(s) => s.pull(device, delivery).await,
            Backend::MySql(s) => s.pull(device, delivery).await,
        };
        self.checked(result)
    }
    pub async fn pull_legacy(&self, device: &str, delivery: Option<&str>) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.pull_legacy(device, delivery).await,
            Backend::Postgres(s) => s.pull_legacy(device, delivery).await,
            Backend::MySql(s) => s.pull_legacy(device, delivery).await,
        };
        self.checked(result)
    }
    pub async fn ack(&self, device: &str, ids: Vec<String>) -> Result<usize> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.ack(device, ids).await,
            Backend::Postgres(s) => s.ack(device, ids).await,
            Backend::MySql(s) => s.ack(device, ids).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub(super) async fn claim_reserved(
        &self,
        provider: &str,
        limit: usize,
        retry_first: bool,
    ) -> Result<ClaimBatch> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.claim_reserved(provider, limit, retry_first).await,
            Backend::Postgres(s) => s.claim_reserved(provider, limit, retry_first).await,
            Backend::MySql(s) => s.claim_reserved(provider, limit, retry_first).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub(super) async fn authorize_ticket(&self, ticket: &Ticket) -> Result<bool> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.authorize_ticket(ticket).await,
            Backend::Postgres(s) => s.authorize_ticket(ticket).await,
            Backend::MySql(s) => s.authorize_ticket(ticket).await,
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub(super) async fn settle(
        &self,
        ticket: &Ticket,
        state: &str,
        status: u16,
        error: &str,
        next_due: i64,
        cooldown: Option<i64>,
    ) -> Result<()> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => {
                s.settle(ticket, state, status, error, next_due, cooldown)
                    .await
            }
            Backend::Postgres(s) => {
                s.settle(ticket, state, status, error, next_due, cooldown)
                    .await
            }
            Backend::MySql(s) => {
                s.settle(ticket, state, status, error, next_due, cooldown)
                    .await
            }
        };
        if result.is_ok() && self.config.private.enabled {
            self.private_wake.notify_one();
        }
        self.checked(result)
    }
    pub async fn status(&self, op: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.status(op).await,
            Backend::Postgres(s) => s.status(op).await,
            Backend::MySql(s) => s.status(op).await,
        };
        self.checked(result)
    }
    pub async fn target_status(&self, op: &str) -> Result<Value> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.target_status(op).await,
            Backend::Postgres(s) => s.target_status(op).await,
            Backend::MySql(s) => s.target_status(op).await,
        };
        self.checked(result)
    }
    pub async fn register(&self, platform: &str) -> Result<String> {
        let value = self.register_device(platform, None).await?;
        Ok(value["device_key"]
            .as_str()
            .expect("native registration shape")
            .to_owned())
    }
    pub async fn route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: &str,
    ) -> Result<()> {
        self.update_route(device, platform, provider, Some(raw))
            .await
            .map(|_| ())
    }
    #[cfg(test)]
    pub(super) async fn claim(
        &self,
        provider: &str,
        limit: usize,
        retry_first: bool,
    ) -> Result<ClaimBatch> {
        self.claim_reserved(provider, limit, retry_first).await
    }
}

impl OrdinaryStore {
    pub(crate) async fn private_route(
        &self,
        device: &str,
    ) -> Result<crate::private_model::PrivateRoute> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_route(device).await,
            Backend::Postgres(s) => s.private_route(device).await,
            Backend::MySql(s) => s.private_route(device).await,
        };
        self.checked(result)
    }
    pub(crate) async fn private_claim(
        &self,
        route: &crate::private_model::PrivateRoute,
        group: &str,
        limit: usize,
    ) -> Result<Vec<crate::private_model::PrivateTicket>> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_claim(route, group, limit).await,
            Backend::Postgres(s) => s.private_claim(route, group, limit).await,
            Backend::MySql(s) => s.private_claim(route, group, limit).await,
        };
        self.checked(result)
    }
    pub(crate) async fn private_authorize(
        &self,
        ticket: &crate::private_model::PrivateTicket,
    ) -> Result<bool> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_authorize(ticket).await,
            Backend::Postgres(s) => s.private_authorize(ticket).await,
            Backend::MySql(s) => s.private_authorize(ticket).await,
        };
        self.checked(result)
    }
    pub(crate) async fn private_ack(
        &self,
        route: &crate::private_model::PrivateRoute,
        ticket: &crate::private_model::PrivateTicket,
    ) -> Result<bool> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_ack(route, ticket).await,
            Backend::Postgres(s) => s.private_ack(route, ticket).await,
            Backend::MySql(s) => s.private_ack(route, ticket).await,
        };
        self.checked(result)
    }
    pub(crate) async fn private_release(&self, group: &str, tokens: &[String]) -> Result<usize> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_release(group, tokens).await,
            Backend::Postgres(s) => s.private_release(group, tokens).await,
            Backend::MySql(s) => s.private_release(group, tokens).await,
        };
        self.checked(result)
    }
}
