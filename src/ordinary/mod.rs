//! Single-host ordinary message authority, owned by the product Storage lifecycle.
//! Derived from the frozen C9 candidate 86e073dec487903cb27f2e67d6e5cbdcb06a6900.
//! Control records and Private sessions remain owned by the normal product.
mod application;
pub mod metrics;
mod mysql_private;
pub(crate) mod mysql_store;
mod ordinary_store;
pub mod owner;
mod pg_private;
pub(crate) mod pg_store;
pub mod private_model;
pub mod profiling;
pub mod runtime;
mod sender;
mod sqlite_private;
pub mod store;
pub mod transport;
pub mod types;
pub use ordinary_store::OrdinaryStore;
pub use runtime::{DeliveryRuntime, ProviderTransport};
pub use store::{
    AcceptRequest, Accepted, Config, Counters, KernelError, MESSAGE_SUBMISSION_BODY_BYTES,
};

pub(crate) mod legacy;
pub mod sqlite_cutover;
pub mod pg_cutover;
pub mod cutover;

pub mod ingress;
#[cfg(test)]
mod product_pg_tests;
#[cfg(test)]
mod pg_history_tests;
#[cfg(test)]
mod product_sqlite_tests;
#[cfg(test)]
mod product_maintenance_tests;
pub mod server;
#[cfg(test)]
mod widget_provider_tests;

pub(crate) mod expiry;
pub(crate) mod widget_refresh;
