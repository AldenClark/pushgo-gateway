#![forbid(unsafe_code)]
//! Single-host delivery candidate; credential owners are reused from Gateway.
#[cfg(feature = "commit-observer")]
pub mod commit_observer;
pub mod credentials;
mod http;
mod ingress;
pub mod metrics;
mod mysql_control;
mod mysql_private;
mod mysql_store;
mod ordinary_store;
mod pg_control;
mod pg_private;
mod pg_store;
pub mod private_http;
pub mod private_listeners;
pub mod private_model;
pub mod private_mqtt;
pub mod private_runtime;
pub mod profiling;
mod runtime;
mod sender;
mod server;
mod sqlite_private;
mod store;
pub mod transport;
pub mod types;
pub use http::{router, router_with_auth, router_with_private};
pub use ingress::BoundedListener;
pub use ordinary_store::OrdinaryStore;
pub use private_http::PrivateHttp;
pub use runtime::{DeliveryRuntime, ProviderTransport, ShutdownReport};
pub use server::{HttpLimits, serve};
pub use store::{
    AcceptRequest, Accepted, Config, Counters, DeliveryStore, KernelError,
    MESSAGE_SUBMISSION_BODY_BYTES,
};
pub use transport::RealProviders;
#[cfg(test)]
mod credentials_tests;
#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod store_contract_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;

#[cfg(test)]
mod control_tests;
#[cfg(test)]
mod control_wire_tests;

#[cfg(test)]
mod backend_contract_tests;

#[cfg(test)]
mod mysql_plan_probe;

#[cfg(test)]
mod private_contract_tests;

#[cfg(test)]
mod private_runtime_tests;

#[cfg(test)]
mod private_boundary_tests;
