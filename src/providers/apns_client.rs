use std::{sync::Arc, time::Duration};

use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tokio::{sync::Semaphore, time::sleep};

use crate::{
    Error,
    providers::{
        ApnsClient, ApnsTokenProvider, BoxFuture, DispatchResult, ProviderFailure,
        ProviderFailureKind, TokenInfo, apns::ApnsPayload, error::trimmed_body_text,
    },
    storage::Platform,
};

const IOS_TOPIC: &str = "io.ethan.pushgo";
const MACOS_TOPIC: &str = "io.ethan.pushgo";
const WATCHOS_TOPIC: &str = "io.ethan.pushgo.watchkitapp";

const APNS_TIMEOUT: Duration = Duration::from_secs(60);
const APNS_MAX_RETRY: usize = 3;
const APNS_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

// In-process APNs concurrency cap; tune based on latency and throughput.
const APNS_MAX_IN_FLIGHT_DEFAULT: usize = 100;
const APNS_MAX_IN_FLIGHT_ENV: &str = "PUSHGO_APNS_MAX_IN_FLIGHT";

/// APNs client with token caching and bounded retries.
pub struct ApnsService {
    token_provider: Arc<dyn ApnsTokenProvider>,
    client: Client,
    limiter: Arc<Semaphore>,
    endpoint: Arc<str>,
}

impl ApnsService {
    pub fn new(token_provider: Arc<dyn ApnsTokenProvider>, endpoint: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent(concat!("pushgo-gateway/", env!("CARGO_PKG_VERSION")))
            .timeout(APNS_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;

        let max_in_flight = std::env::var(APNS_MAX_IN_FLIGHT_ENV)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(APNS_MAX_IN_FLIGHT_DEFAULT);

        Ok(Self {
            token_provider,
            client,
            limiter: Arc::new(Semaphore::new(max_in_flight)),
            endpoint: Arc::from(endpoint.trim_end_matches('/')),
        })
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        self.token_provider.token_info().await
    }

    pub async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        self.token_provider.token_info_fresh().await
    }

    pub async fn send_to_device(
        &self,
        device_token: &str,
        platform: Platform,
        payload: Arc<ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> DispatchResult {
        let default_topic = match platform {
            Platform::IOS => IOS_TOPIC,
            Platform::MACOS => MACOS_TOPIC,
            Platform::WATCHOS => WATCHOS_TOPIC,
            Platform::ANDROID => {
                return DispatchResult::from_error(
                    0,
                    Error::validation("android platform must be delivered via FCM"),
                );
            }
            Platform::WINDOWS => {
                return DispatchResult::from_error(
                    0,
                    Error::validation("windows platform must be delivered via WNS"),
                );
            }
        };
        let topic = match payload.topic_override() {
            Some(topic) => topic.to_string(),
            None => default_topic.to_string(),
        };

        self.send_with_retry(device_token, &topic, payload, collapse_id)
            .await
    }

    async fn send_with_retry(
        &self,
        device_token: &str,
        topic: &str,
        payload: Arc<ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> DispatchResult {
        let mut attempt = 0;
        let mut backoff = APNS_INITIAL_BACKOFF;

        loop {
            attempt += 1;
            let dispatch = self
                .send_once(device_token, topic, payload.clone(), collapse_id.clone())
                .await;

            let retryable =
                dispatch.is_retryable() && attempt < APNS_MAX_RETRY && !dispatch.success;

            if retryable {
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }

            return dispatch;
        }
    }

    async fn send_once(
        &self,
        device_token: &str,
        topic: &str,
        payload: Arc<ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> DispatchResult {
        let request_uri = format!("{}/3/device/{device_token}", self.endpoint.as_ref());
        // Bound APNs calls to avoid unbounded fan-out.
        let _permit = match self.limiter.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                return DispatchResult::from_error(
                    0,
                    Error::Internal("APNs concurrency limiter closed".to_string()),
                );
            }
        };
        let mut auth_token = match self.current_token().await {
            Ok(token) => token,
            Err(err) => return DispatchResult::from_error(0, err),
        };

        let body = match payload.encoded_body() {
            Ok(body) => body,
            Err(err) => return DispatchResult::from_error(0, Error::Internal(err.to_string())),
        };

        let mut request = self
            .client
            .post(&request_uri)
            .header("authorization", format!("bearer {auth_token}"))
            .header("apns-topic", topic)
            .header("content-type", "application/json")
            .header("apns-push-type", payload.push_type_header())
            .header("apns-priority", payload.priority().to_string());
        if let Some(ref id) = collapse_id {
            request = request.header("apns-collapse-id", id.as_ref());
        }
        if let Some(expiration) = payload.expiration {
            request = request.header("apns-expiration", expiration.to_string());
        }

        let mut response = match request.body(body.as_ref().to_vec()).send().await {
            Ok(resp) => resp,
            Err(err) => return DispatchResult::transport(Error::Internal(err.to_string())),
        };

        let mut status = response.status();
        let mut status_code = status.as_u16();
        let mut response_body = response.bytes().await.unwrap_or_default();
        let mut reason = parse_apns_reason(&response_body);

        // Retry once if APNs reports an expired provider token.
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            && matches!(reason.as_deref(), Some("ExpiredProviderToken"))
        {
            match self.refresh_token_now().await {
                Ok(new_token) => {
                    auth_token = new_token;
                    let mut request = self
                        .client
                        .post(&request_uri)
                        .header("authorization", format!("bearer {auth_token}"))
                        .header("apns-topic", topic)
                        .header("content-type", "application/json")
                        .header("apns-push-type", payload.push_type_header())
                        .header("apns-priority", payload.priority().to_string());
                    if let Some(ref id) = collapse_id {
                        request = request.header("apns-collapse-id", id.as_ref());
                    }
                    if let Some(expiration) = payload.expiration {
                        request = request.header("apns-expiration", expiration.to_string());
                    }

                    response = match request.body(body.as_ref().to_vec()).send().await {
                        Ok(resp) => resp,
                        Err(err) => {
                            return DispatchResult::transport(Error::Internal(err.to_string()));
                        }
                    };

                    status = response.status();
                    status_code = status.as_u16();
                    response_body = response.bytes().await.unwrap_or_default();
                    reason = parse_apns_reason(&response_body);
                }
                Err(err) => return DispatchResult::from_error(status_code, err),
            }
        }

        if status == StatusCode::OK {
            DispatchResult::success(status_code)
        } else {
            DispatchResult::upstream(
                "APNs",
                classify_apns_failure(status, reason.as_deref(), &response_body),
            )
        }
    }

    async fn current_token(&self) -> Result<Arc<str>, Error> {
        Ok(self.token_info().await?.token)
    }

    async fn refresh_token_now(&self) -> Result<Arc<str>, Error> {
        self.token_provider.refresh_now().await
    }
}

fn classify_apns_failure(
    status: StatusCode,
    reason: Option<&str>,
    response_body: &[u8],
) -> ProviderFailure {
    let status_code = status.as_u16();
    let message = if let Some(reason) = reason {
        reason.to_string()
    } else if let Some(body_text) = trimmed_body_text(response_body) {
        body_text
    } else {
        format!("APNs error, status {status_code}")
    };
    let kind = if matches!(
        reason,
        Some("BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered" | "InvalidToken")
    ) || status == StatusCode::GONE
    {
        ProviderFailureKind::InvalidToken
    } else if status == StatusCode::PAYLOAD_TOO_LARGE && matches!(reason, Some("PayloadTooLarge")) {
        ProviderFailureKind::PayloadTooLarge
    } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        && matches!(reason, Some("ExpiredProviderToken"))
    {
        ProviderFailureKind::CredentialsExpired
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        ProviderFailureKind::RateLimited
    } else if matches!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::SERVICE_UNAVAILABLE
    ) {
        ProviderFailureKind::TemporarilyUnavailable
    } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        ProviderFailureKind::Unauthorized
    } else {
        ProviderFailureKind::Rejected
    };
    ProviderFailure::new(status_code, kind, message)
}
impl ApnsClient for ApnsService {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        platform: Platform,
        payload: Arc<ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            self.send_to_device(device_token, platform, payload, collapse_id)
                .await
        })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info_fresh().await })
    }
}

#[derive(Deserialize)]
struct ReasonBody {
    reason: Option<String>,
}

fn parse_apns_reason(body: &[u8]) -> Option<String> {
    let parsed = serde_json::from_slice::<ReasonBody>(body).ok()?;
    parsed.reason
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::{ProviderFailureKind, classify_apns_failure};

    #[test]
    fn apns_classifies_expired_provider_token() {
        let failure = classify_apns_failure(
            StatusCode::UNAUTHORIZED,
            Some("ExpiredProviderToken"),
            br#"{"reason":"ExpiredProviderToken"}"#,
        );
        assert_eq!(failure.kind, ProviderFailureKind::CredentialsExpired);
    }

    #[test]
    fn apns_classifies_invalid_device_token() {
        let failure = classify_apns_failure(
            StatusCode::BAD_REQUEST,
            Some("BadDeviceToken"),
            br#"{"reason":"BadDeviceToken"}"#,
        );
        assert_eq!(failure.kind, ProviderFailureKind::InvalidToken);
    }

    #[test]
    fn apns_classifies_payload_too_large() {
        let failure = classify_apns_failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            Some("PayloadTooLarge"),
            br#"{"reason":"PayloadTooLarge"}"#,
        );
        assert_eq!(failure.kind, ProviderFailureKind::PayloadTooLarge);
    }
}
