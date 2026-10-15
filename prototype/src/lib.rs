#![forbid(unsafe_code)]
//! Independent single-host delivery prototype; no production Gateway dependency.
mod http;
mod ingress;
mod runtime;
mod store;
pub mod transport;
pub mod types;
pub use http::router;
pub use ingress::BoundedListener;
pub use runtime::{DeliveryRuntime, ProviderTransport, ShutdownReport};
pub use store::{AcceptRequest, Accepted, Config, Counters, DeliveryStore, KernelError};
pub use transport::RealProviders;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;
