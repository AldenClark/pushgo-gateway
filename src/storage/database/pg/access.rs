use super::*;

#[path = "access/channels.rs"]
mod channels;
#[path = "access/maintenance.rs"]
mod maintenance;
#[path = "access/outbox.rs"]
mod outbox;
#[path = "access/private_channels.rs"]
mod private_channels;
#[path = "access/provider.rs"]
mod provider;
#[path = "access/routes.rs"]
mod routes;
#[path = "access/subscriptions.rs"]
mod subscriptions;

impl_backend_database_access!(PostgresDb);
