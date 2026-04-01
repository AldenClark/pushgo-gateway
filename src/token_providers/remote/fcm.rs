use pushgo_gateway::{
    Error,
    providers::{BoxFuture, FcmAccess, FcmTokenProvider as FcmTokenProviderTrait},
};

use crate::token_providers::remote::gateway::{GatewayProvider, GatewayTokenCache};

pub(crate) struct FcmTokenProvider {
    cache: GatewayTokenCache,
}

impl FcmTokenProvider {
    pub(crate) fn new(token_service_url: &str, client: reqwest::Client) -> Result<Self, Error> {
        let cache = GatewayTokenCache::new(client, GatewayProvider::Fcm, token_service_url);
        Ok(Self { cache })
    }
}

impl FcmTokenProviderTrait for FcmTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move {
            let (token, project_id) = self.cache.token_info_with_project().await?;
            Ok(FcmAccess { token, project_id })
        })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move {
            let (token, project_id) = self.cache.token_info_with_project().await?;
            Ok(FcmAccess { token, project_id })
        })
    }
}
