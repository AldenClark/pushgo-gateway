use std::{future::Future, pin::Pin, sync::Arc};

use crate::{Error, storage::Platform};

pub mod apns;
pub mod apns_client;
pub mod error;
pub mod fcm;
pub mod fcm_client;
pub mod wns;
pub mod wns_client;

pub use apns_client::ApnsService;
pub(crate) use error::ProviderFailure;
pub use error::ProviderFailureKind;
pub use fcm_client::FcmService;
pub use wns_client::WnsService;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: Arc<str>,
    pub expires_in: u64,
}

#[derive(Debug, Clone)]
pub struct FcmAccess {
    pub token: TokenInfo,
    pub project_id: Arc<str>,
}

#[derive(Debug)]
pub struct DispatchResult {
    pub success: bool,
    pub status_code: u16,
    #[allow(dead_code)]
    pub error: Option<Error>,
    pub failure_kind: Option<ProviderFailureKind>,
}

impl DispatchResult {
    pub(crate) fn success(status_code: u16) -> Self {
        Self {
            success: true,
            status_code,
            error: None,
            failure_kind: None,
        }
    }

    pub(crate) fn from_error(status_code: u16, error: Error) -> Self {
        Self {
            success: false,
            status_code,
            error: Some(error),
            failure_kind: None,
        }
    }

    pub(crate) fn transport(error: Error) -> Self {
        Self {
            success: false,
            status_code: 0,
            error: Some(error),
            failure_kind: Some(ProviderFailureKind::Transport),
        }
    }

    pub(crate) fn upstream(provider: &'static str, failure: ProviderFailure) -> Self {
        Self {
            success: false,
            status_code: failure.status_code,
            error: Some(Error::Upstream {
                provider,
                status: failure.status_code,
                message: failure.message,
            }),
            failure_kind: Some(failure.kind),
        }
    }

    pub(crate) fn should_refresh_credentials(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::should_refresh_credentials)
    }

    pub(crate) fn is_retryable(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_retryable)
    }

    pub(crate) fn is_invalid_token(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_invalid_token)
    }

    pub(crate) fn is_payload_too_large(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_payload_too_large)
    }

    pub(crate) fn failure_kind_name(&self) -> &'static str {
        self.failure_kind
            .map(ProviderFailureKind::as_str)
            .unwrap_or("none")
    }
}

pub trait ApnsTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn refresh_now<'a>(&'a self) -> BoxFuture<'a, Result<Arc<str>, Error>>;
}

pub trait FcmTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>>;
}

pub trait WnsTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait ApnsClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        platform: Platform,
        payload: Arc<apns::ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> BoxFuture<'a, DispatchResult>;

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait FcmClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<fcm::FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
    ) -> BoxFuture<'a, DispatchResult>;

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait WnsClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<wns::WnsPayload>,
    ) -> BoxFuture<'a, DispatchResult>;

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}
