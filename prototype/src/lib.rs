#![forbid(unsafe_code)]
//! Independent single-host delivery prototype; no production Gateway dependency.
pub mod credentials;
mod http;
mod ingress;
pub mod metrics;
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
