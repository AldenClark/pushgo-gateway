//! The runtime and HTTP layer select whole ledger operations, not SQL dialects.
//! Each backend retains its native connection, transactions and query plans.
use crate::ordinary::mysql_store::MySqlDeliveryStore;
use crate::ordinary::pg_store::PgDeliveryStore;
use crate::ordinary::store::{
    AcceptRequest, Accepted, ClaimBatch, Config, Counters, DeliveryStore, Health, KernelError,
    Result, Ticket,
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
    post_control: Option<Arc<dyn Fn() + Send + Sync>>,
    pub config: Config,
    pub counters: Arc<Counters>,
    pub(crate) wake: [Arc<Notify>; 3],
    pub(crate) health: Arc<Health>,
    pub(crate) private_wake: Arc<Notify>,
    pub(crate) widget_wake: Arc<Notify>,
    pub(crate) widget_projection_gate: Arc<tokio::sync::Mutex<()>>,
}
impl From<DeliveryStore> for OrdinaryStore {
    fn from(store: DeliveryStore) -> Self {
        Self {
            post_control: None,
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            widget_wake: Arc::new(Notify::new()),
            widget_projection_gate: Arc::new(tokio::sync::Mutex::new(())),
            backend: Backend::Sqlite(store),
        }
    }
}
impl From<PgDeliveryStore> for OrdinaryStore {
    fn from(store: PgDeliveryStore) -> Self {
        Self {
            post_control: None,
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            widget_wake: Arc::new(Notify::new()),
            widget_projection_gate: Arc::new(tokio::sync::Mutex::new(())),
            backend: Backend::Postgres(store),
        }
    }
}
impl From<MySqlDeliveryStore> for OrdinaryStore {
    fn from(store: MySqlDeliveryStore) -> Self {
        Self {
            post_control: None,
            config: store.config.clone(),
            counters: store.counters.clone(),
            wake: store.wake.clone(),
            health: store.health.clone(),
            private_wake: Arc::new(Notify::new()),
            widget_wake: Arc::new(Notify::new()),
            widget_projection_gate: Arc::new(tokio::sync::Mutex::new(())),
            backend: Backend::MySql(store),
        }
    }
}
impl OrdinaryStore {
    pub(crate) fn notify(&self) {
        self.widget_wake.notify_one();
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
}

impl OrdinaryStore {
    pub(crate) async fn next_widget_refresh(
        &self,
    ) -> Result<Option<super::widget_refresh::WidgetRefresh>> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.next_widget_refresh().await,
            Backend::Postgres(s) => s.next_widget_refresh().await,
            Backend::MySql(s) => s.next_widget_refresh().await,
        };
        self.checked(result)
    }

    pub(crate) async fn complete_widget_refresh(&self, id: &str, order: i64) -> Result<bool> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.complete_widget_refresh(id, order).await,
            Backend::Postgres(s) => s.complete_widget_refresh(id, order).await,
            Backend::MySql(s) => s.complete_widget_refresh(id, order).await,
        };
        self.checked(result)
    }

    pub(crate) async fn widget_refresh_targets(
        &self,
        channel: [u8; 16],
        after: Option<&super::widget_refresh::WidgetRefreshCursor>,
        limit: usize,
    ) -> Result<Vec<super::widget_refresh::WidgetRefreshTarget>> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => {
                s.widget_refresh_targets(channel, after, limit.min(128))
                    .await
            }
            Backend::Postgres(s) => {
                s.widget_refresh_targets(channel, after, limit.min(128))
                    .await
            }
            Backend::MySql(s) => {
                s.widget_refresh_targets(channel, after, limit.min(128))
                    .await
            }
        };
        self.checked(result)
    }

    pub(crate) async fn widget_refresh_job_order(&self, job_id: &str) -> Result<Option<i64>> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.widget_refresh_job_order(job_id).await,
            Backend::Postgres(s) => s.widget_refresh_job_order(job_id).await,
            Backend::MySql(s) => s.widget_refresh_job_order(job_id).await,
        };
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
        if result.is_ok() {
            self.widget_wake.notify_one();
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
    pub(crate) async fn claim_reserved(
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
    pub(crate) async fn authorize_ticket(&self, ticket: &Ticket) -> Result<bool> {
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
    pub(crate) async fn settle(
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
        if result.is_ok() && error == "invalid_token" {
            if let Some(invalidate) = &self.post_control {
                invalidate();
            }
        }
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

    #[cfg(test)]
    pub(crate) async fn claim(
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
    ) -> Result<crate::ordinary::private_model::PrivateRoute> {
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
        route: &crate::ordinary::private_model::PrivateRoute,
        group: &str,
        limit: usize,
    ) -> Result<Vec<crate::ordinary::private_model::PrivateTicket>> {
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
        ticket: &crate::ordinary::private_model::PrivateTicket,
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
        route: &crate::ordinary::private_model::PrivateRoute,
        ticket: &crate::ordinary::private_model::PrivateTicket,
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

impl OrdinaryStore {
    pub(crate) fn fail(&self, reason: &str) {
        self.health.fail(reason);
        self.notify();
    }
    pub(crate) async fn private_changed(&self) {
        self.private_wake.notified().await;
    }
    pub(crate) fn private_notifier(&self) -> Arc<Notify> {
        self.private_wake.clone()
    }
}

impl OrdinaryStore {
    pub(crate) async fn private_reject(
        &self,
        route: &crate::ordinary::private_model::PrivateRoute,
        ticket: &crate::ordinary::private_model::PrivateTicket,
        reason: &str,
    ) -> Result<bool> {
        self.health.ensure()?;
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_reject(route, ticket, reason).await,
            Backend::Postgres(s) => s.private_reject(route, ticket, reason).await,
            Backend::MySql(s) => s.private_reject(route, ticket, reason).await,
        };
        if result.is_ok() {
            self.notify();
        }
        self.checked(result)
    }
    pub(crate) async fn active_provider_count(&self) -> Result<i64> {
        let result = match &self.backend {
            Backend::Sqlite(s) => s.active_provider_count().await,
            Backend::Postgres(s) => s.active_provider_count().await,
            Backend::MySql(s) => s.active_provider_count().await,
        };
        self.checked(result)
    }
    pub(crate) async fn private_pending_count(&self, device: Option<&str>) -> Result<i64> {
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_pending_count(device).await,
            Backend::Postgres(s) => s.private_pending_count(device).await,
            Backend::MySql(s) => s.private_pending_count(device).await,
        };
        self.checked(result)
    }
}
impl std::fmt::Debug for OrdinaryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrdinaryStore").finish_non_exhaustive()
    }
}

impl OrdinaryStore {
    pub(crate) async fn private_route_capacity(&self, device: &str) -> Result<(i64, i64)> {
        let result = match &self.backend {
            Backend::Sqlite(s) => s.private_route_capacity(device).await,
            Backend::Postgres(s) => s.private_route_capacity(device).await,
            Backend::MySql(s) => s.private_route_capacity(device).await,
        };
        self.checked(result)
    }
}

impl OrdinaryStore {
    pub(crate) fn set_post_control(&mut self, invalidate: Arc<dyn Fn() + Send + Sync>) {
        self.post_control = Some(invalidate);
    }
}

impl OrdinaryStore {
    pub(crate) async fn close_resources(&self) -> Result<()> {
        if let Backend::MySql(store) = &self.backend {
            store.close().await?;
        }
        Ok(())
    }
}
