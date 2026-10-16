#![forbid(unsafe_code)]

pub mod app;
pub mod args;
pub(crate) mod delivery_core;
pub(crate) mod domain_model;
pub(crate) mod mcp;
pub(crate) mod mqtt;
pub mod private;
pub mod providers;
pub(crate) mod routing;
pub mod runtime_config;
pub mod runtime_counters;
pub(crate) mod services;
pub mod storage;
pub mod util;
pub(crate) mod value;

pub use api::Error;

pub(crate) mod api;
pub(crate) mod dispatch;

// The binary and the library share the same Remote credential owners. This
// alias preserves the owners' existing crate-qualified provider contracts.
extern crate self as pushgo_gateway;
mod token_providers;

/// Construct the existing Token Service HTTP client with its bounded policy.
pub fn token_service_http_client() -> Result<reqwest::Client, Error> {
    token_providers::remote::gateway::build_token_service_http_client()
}

/// Construct the existing FCM Remote owner; its cache and refresh lifecycle
/// stay in token_providers rather than in a delivery adapter.
pub fn remote_fcm_token_provider(
    token_service_url: &str,
    client: reqwest::Client,
) -> std::sync::Arc<dyn providers::FcmTokenProvider> {
    std::sync::Arc::new(token_providers::remote::fcm::FcmTokenProvider::new(
        token_service_url,
        client,
    ))
}

/// Construct the existing APNs Remote owner with the same injected client.
pub fn remote_apns_token_provider(
    token_service_url: &str,
    client: reqwest::Client,
) -> std::sync::Arc<dyn providers::ApnsTokenProvider> {
    std::sync::Arc::new(token_providers::remote::apns::ApnsTokenProvider::new(
        token_service_url,
        client,
    ))
}

pub mod ordinary;

/// Synthetic local Provider substitutes; not compiled into normal builds.
#[cfg(feature = "qa")]
pub mod qa;
