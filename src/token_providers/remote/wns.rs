use pushgo_gateway::{
    Error,
    providers::{BoxFuture, TokenInfo, WnsTokenProvider as WnsTokenProviderTrait},
};

use crate::token_providers::remote::gateway::{GatewayProvider, GatewayTokenCache};

pub struct WnsTokenProvider {
    cache: GatewayTokenCache,
}

impl WnsTokenProvider {
    pub fn new(token_service_url: &str, client: reqwest::Client) -> Result<Self, Error> {
        let cache = GatewayTokenCache::new(client, GatewayProvider::Wns, token_service_url);
        Ok(Self { cache })
    }
}

impl WnsTokenProviderTrait for WnsTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }
}
