use std::sync::Arc;

use reqwest::{Client, StatusCode};
use serde::Deserialize;

use crate::{
    Error,
    providers::{
        ApnsClient, ApnsTokenProvider, BoxFuture, DispatchResult, PROVIDER_CONNECT_TIMEOUT,
        PROVIDER_REQUEST_TIMEOUT, ProviderFailure, ProviderFailureKind, TokenInfo,
        apns::{ApnsPayload, ApnsPushType},
        error::{parse_retry_after_millis, trimmed_body_text},
    },
    runtime_config::GatewayRuntimeProfile,
    storage::Platform,
};

const IOS_TOPIC: &str = "io.ethan.pushgo";
const MACOS_TOPIC: &str = "io.ethan.pushgo";
const WATCHOS_TOPIC: &str = "io.ethan.pushgo.watchkitapp";

/// APNs transport adapter. Durable scheduling owns retries and concurrency.
pub struct ApnsService {
    token_provider: Arc<dyn ApnsTokenProvider>,
    client: Client,
    endpoint: Arc<str>,
}

impl ApnsService {
    pub fn new(token_provider: Arc<dyn ApnsTokenProvider>, endpoint: &str) -> Result<Self, Error> {
        Self::new_with_profile(token_provider, endpoint, GatewayRuntimeProfile::Small)
    }

    pub fn new_with_profile(
        token_provider: Arc<dyn ApnsTokenProvider>,
        endpoint: &str,
        _runtime_profile: GatewayRuntimeProfile,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent(concat!("pushgo-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .timeout(PROVIDER_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;

        Ok(Self {
            token_provider,
            client,
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
                    Error::validation_code(
                        "android platform must be delivered via FCM",
                        "android_platform_requires_fcm",
                    ),
                );
            }
            Platform::WINDOWS => {
                return DispatchResult::from_error(
                    0,
                    Error::validation_code(
                        "windows platform must be delivered via WNS",
                        "windows_platform_requires_wns",
                    ),
                );
            }
            Platform::MQTT => {
                return DispatchResult::from_error(
                    0,
                    Error::validation_code(
                        "mqtt platform must be delivered via private MQTT transport",
                        "mqtt_platform_requires_private_transport",
                    ),
                );
            }
        };
        let topic = match payload.topic_override() {
            Some(topic) => topic.to_string(),
            None if payload.push_type() == ApnsPushType::Widgets => {
                format!("{default_topic}.push-type.widgets")
            }
            None => default_topic.to_string(),
        };

        self.send_once(device_token, &topic, payload, collapse_id)
            .await
    }

    async fn send_once(
        &self,
        device_token: &str,
        topic: &str,
        payload: Arc<ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> DispatchResult {
        let request_uri = format!("{}/3/device/{device_token}", self.endpoint.as_ref());
        let auth_token = match self.current_token().await {
            Ok(token) => token,
            Err(err) => return DispatchResult::provider_access_failure(err),
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

        let response = match request.body(body.as_ref().to_vec()).send().await {
            Ok(resp) => resp,
            Err(err) => return DispatchResult::transport(Error::Internal(err.to_string())),
        };

        let status = response.status();
        let status_code = status.as_u16();
        let retry_after_millis = normalize_apns_retry_after(
            status,
            parse_retry_after_millis(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
            ),
        );
        let response_body = response.bytes().await.unwrap_or_default();
        let reason = parse_apns_reason(&response_body);

        // Refresh cached credentials for the scheduler's next durable attempt;
        // this adapter never performs a second provider send inline.
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            && matches!(reason.as_deref(), Some("ExpiredProviderToken"))
        {
            let _ = self.refresh_token_now().await;
        }

        if status == StatusCode::OK {
            DispatchResult::success(status_code)
        } else {
            DispatchResult::upstream(
                "APNs",
                classify_apns_failure(status, reason.as_deref(), &response_body)
                    .with_retry_after_millis(retry_after_millis),
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

fn normalize_apns_retry_after(status: StatusCode, retry_after_millis: Option<i64>) -> Option<i64> {
    // Apple asks providers to wait 15 minutes before retrying 5xx responses.
    // Enforce that floor even when APNs omits Retry-After so a local worker
    // scale-up cannot amplify an APNs incident.
    const APNS_SERVER_ERROR_RETRY_MILLIS: i64 = 15 * 60 * 1_000;
    if status.is_server_error() {
        Some(
            retry_after_millis
                .unwrap_or_default()
                .max(APNS_SERVER_ERROR_RETRY_MILLIS),
        )
    } else {
        retry_after_millis
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
    } else if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
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

    use super::{ProviderFailureKind, classify_apns_failure, normalize_apns_retry_after};

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

    #[test]
    fn apns_retries_gateway_and_timeout_responses() {
        for status in [StatusCode::REQUEST_TIMEOUT, StatusCode::BAD_GATEWAY] {
            let failure = classify_apns_failure(status, None, b"");
            assert_eq!(failure.kind, ProviderFailureKind::TemporarilyUnavailable);
        }
    }

    #[test]
    fn apns_server_failures_wait_at_least_fifteen_minutes() {
        assert_eq!(
            normalize_apns_retry_after(StatusCode::SERVICE_UNAVAILABLE, None),
            Some(15 * 60 * 1_000)
        );
        assert_eq!(
            normalize_apns_retry_after(StatusCode::SERVICE_UNAVAILABLE, Some(20 * 60 * 1_000)),
            Some(20 * 60 * 1_000)
        );
        assert_eq!(
            normalize_apns_retry_after(StatusCode::TOO_MANY_REQUESTS, None),
            None
        );
    }
}
