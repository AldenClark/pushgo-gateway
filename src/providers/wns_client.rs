use std::sync::Arc;

use reqwest::Client;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, PROVIDER_CONNECT_TIMEOUT, PROVIDER_REQUEST_TIMEOUT,
        ProviderFailure, ProviderFailureKind, TokenInfo, WnsClient, WnsTokenProvider,
        error::{parse_retry_after_millis, trimmed_body_text},
        wns::WnsPayload,
    },
    runtime_config::GatewayRuntimeProfile,
};

const WNS_TYPE: &str = "wns/raw";
// WNS requires this media type for raw notifications even when the app payload is UTF-8 JSON.
const WNS_CONTENT_TYPE: &str = "application/octet-stream";

pub struct WnsService {
    client: Client,
    token_provider: Arc<dyn WnsTokenProvider>,
}

impl WnsService {
    pub fn new(token_provider: Arc<dyn WnsTokenProvider>) -> Result<Self, Error> {
        Self::new_with_profile(token_provider, GatewayRuntimeProfile::Small)
    }

    pub fn new_with_profile(
        token_provider: Arc<dyn WnsTokenProvider>,
        _runtime_profile: GatewayRuntimeProfile,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .timeout(PROVIDER_REQUEST_TIMEOUT)
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
        let token = match self.token_provider.token_info().await {
            Ok(info) => info,
            Err(err) => return DispatchResult::provider_access_failure(err),
        };
        let dispatch = self
            .send_request(
                device_token,
                token.token.as_ref(),
                body,
                priority,
                ttl_seconds,
            )
            .await;
        if dispatch.should_refresh_credentials() {
            let _ = self.token_provider.token_info_fresh().await;
        }
        dispatch
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
        let retry_after_millis = normalize_wns_retry_after(
            status_code,
            parse_retry_after_millis(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
            ),
        );
        let body = response.bytes().await.unwrap_or_default();

        if !status.is_success() {
            return DispatchResult::upstream(
                "WNS",
                classify_wns_failure(status_code, &body)
                    .with_retry_after_millis(retry_after_millis),
            );
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

fn normalize_wns_retry_after(status_code: u16, retry_after_millis: Option<i64>) -> Option<i64> {
    if matches!(status_code, 406 | 429) {
        // 406 is WNS per-sender throttling; 429 is monthly quota pressure.
        // Retry-After is authoritative. Use a conservative default when the
        // response omits it instead of creating a tight retry loop.
        Some(retry_after_millis.unwrap_or_default().max(60_000))
    } else if status_code == 408 || (500..=599).contains(&status_code) {
        Some(retry_after_millis.unwrap_or_default().max(10_000))
    } else {
        retry_after_millis
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
        406 | 429 => ProviderFailureKind::RateLimited,
        408 | 500..=599 => ProviderFailureKind::TemporarilyUnavailable,
        403 => ProviderFailureKind::Unauthorized,
        _ => ProviderFailureKind::Rejected,
    };
    ProviderFailure::new(status_code, kind, message)
}

#[cfg(test)]
mod tests {
    use super::{ProviderFailureKind, classify_wns_failure, normalize_wns_retry_after};

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

    #[test]
    fn wns_retries_gateway_and_timeout_responses() {
        for status in [408, 502, 503] {
            let failure = classify_wns_failure(status, b"");
            assert_eq!(failure.kind, ProviderFailureKind::TemporarilyUnavailable);
        }
    }

    #[test]
    fn wns_throttling_is_retryable_and_respects_retry_after() {
        let failure = classify_wns_failure(406, b"throttled");
        assert_eq!(failure.kind, ProviderFailureKind::RateLimited);
        assert_eq!(normalize_wns_retry_after(406, None), Some(60_000));
        assert_eq!(normalize_wns_retry_after(503, None), Some(10_000));
        assert_eq!(normalize_wns_retry_after(503, Some(30_000)), Some(30_000));
    }
}
