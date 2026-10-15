#![forbid(unsafe_code)]
//! Single-host delivery candidate; credential owners are reused from Gateway.
pub mod credentials;
mod http;
mod ingress;
pub mod metrics;
pub mod profiling;
mod runtime;
mod sender;
mod server;
mod store;
pub mod transport;
pub mod types;
pub use http::{router, router_with_auth};
pub use ingress::BoundedListener;
pub use runtime::{DeliveryRuntime, ProviderTransport, ShutdownReport};
pub use server::{HttpLimits, serve};
pub use store::{AcceptRequest, Accepted, Config, Counters, DeliveryStore, KernelError};
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
