use std::{sync::Arc, time::Duration};

use reqwest::Client;
use tokio::time::sleep;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, ProviderFailure, ProviderFailureKind, TokenInfo, WnsClient,
        WnsTokenProvider, error::trimmed_body_text, wns::WnsPayload,
    },
};

const WNS_TIMEOUT: Duration = Duration::from_secs(60);
const WNS_TYPE: &str = "wns/raw";
const WNS_CONTENT_TYPE: &str = "application/octet-stream";
const WNS_MAX_RETRY: usize = 3;
const WNS_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

pub struct WnsService {
    client: Client,
    token_provider: Arc<dyn WnsTokenProvider>,
}

impl WnsService {
    pub fn new(token_provider: Arc<dyn WnsTokenProvider>) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .timeout(WNS_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;

        Ok(Self {
            client,
            token_provider,
        })
    }

    pub async fn send_to_device(
        &self,
        device_token: &str,
        payload: Arc<WnsPayload>,
    ) -> DispatchResult {
        let body = match payload.encoded_body() {
            Ok(body) => body,
            Err(err) => return DispatchResult::from_error(0, Error::Internal(err.to_string())),
        };

        let priority = payload.priority();
        let ttl_seconds = payload.ttl_seconds();
        let mut attempt = 0usize;
        let mut backoff = WNS_INITIAL_BACKOFF;
        let mut force_fresh_token = false;

        loop {
            attempt += 1;
            let token = match if force_fresh_token {
                self.token_provider.token_info_fresh().await
            } else {
                self.token_provider.token_info().await
            } {
                Ok(info) => info,
                Err(err) => return DispatchResult::from_error(0, err),
            };

            let dispatch = self
                .send_request(
                    device_token,
                    token.token.as_ref(),
                    body.clone(),
                    priority,
                    ttl_seconds,
                )
                .await;
            if dispatch.success {
                return dispatch;
            }

            if dispatch.should_refresh_credentials()
                && !force_fresh_token
                && attempt < WNS_MAX_RETRY
            {
                force_fresh_token = true;
                continue;
            }

            let retryable = dispatch.is_retryable() && attempt < WNS_MAX_RETRY;
            if !retryable {
                return dispatch;
            }

            force_fresh_token = false;
            sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }

    async fn send_request(
        &self,
        device_token: &str,
        bearer: &str,
        body: Arc<[u8]>,
        priority: Option<u8>,
        ttl_seconds: Option<u32>,
    ) -> DispatchResult {
        let mut request = self
            .client
            .post(device_token)
            .bearer_auth(bearer)
            .header("x-wns-type", WNS_TYPE)
            .header("content-type", WNS_CONTENT_TYPE)
            .body(body.as_ref().to_vec());
        if let Some(priority) = priority {
            request = request.header("x-wns-priority", priority.to_string());
        }
        if let Some(ttl) = ttl_seconds {
            request = request.header("x-wns-ttl", ttl.to_string());
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => return DispatchResult::transport(Error::Internal(err.to_string())),
        };

        let status = response.status();
        let status_code = status.as_u16();
        let body = response.bytes().await.unwrap_or_default();

        if !status.is_success() {
            return DispatchResult::upstream("WNS", classify_wns_failure(status_code, &body));
        }

        DispatchResult::success(status_code)
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        self.token_provider.token_info().await
    }

    pub async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        self.token_provider.token_info_fresh().await
    }
}

impl WnsClient for WnsService {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<WnsPayload>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move { self.send_to_device(device_token, payload).await })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info_fresh().await })
    }
}

fn classify_wns_failure(status_code: u16, body: &[u8]) -> ProviderFailure {
    let message =
        trimmed_body_text(body).unwrap_or_else(|| format!("WNS error, status {status_code}"));
    let kind = match status_code {
        401 => ProviderFailureKind::CredentialsExpired,
        404 | 410 => ProviderFailureKind::InvalidToken,
        413 => ProviderFailureKind::PayloadTooLarge,
        429 => ProviderFailureKind::RateLimited,
        500 | 503 | 504 => ProviderFailureKind::TemporarilyUnavailable,
        403 => ProviderFailureKind::Unauthorized,
        _ => ProviderFailureKind::Rejected,
    };
    ProviderFailure::new(status_code, kind, message)
}

#[cfg(test)]
mod tests {
    use super::{ProviderFailureKind, classify_wns_failure};

    #[test]
    fn wns_classifies_expired_credentials() {
        let failure = classify_wns_failure(401, b"");
        assert_eq!(failure.kind, ProviderFailureKind::CredentialsExpired);
    }

    #[test]
    fn wns_classifies_invalid_token() {
        let failure = classify_wns_failure(410, b"gone");
        assert_eq!(failure.kind, ProviderFailureKind::InvalidToken);
    }

    #[test]
    fn wns_classifies_payload_too_large() {
        let failure = classify_wns_failure(413, b"too large");
        assert_eq!(failure.kind, ProviderFailureKind::PayloadTooLarge);
    }
}
