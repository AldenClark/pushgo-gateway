use std::{future::Future, pin::Pin, sync::Arc};

use crate::{Error, storage::Platform};

pub mod apns;
pub mod apns_client;
pub mod fcm;
pub mod fcm_client;
pub mod wns;
pub mod wns_client;

pub use apns_client::ApnsService;
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
    pub invalid_token: bool,
    pub payload_too_large: bool,
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
