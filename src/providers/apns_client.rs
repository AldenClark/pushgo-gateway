use std::{sync::Arc, time::Duration};

use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tokio::{sync::Semaphore, time::sleep};

use crate::{
    Error,
    providers::{
        ApnsClient, ApnsTokenProvider, BoxFuture, DispatchResult, TokenInfo, apns::ApnsPayload,
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
            .user_agent("pushgo-gateway/0.1.0")
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
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::validation(
                        "android platform must be delivered via FCM",
                    )),
                    invalid_token: false,
                    payload_too_large: false,
                };
            }
            Platform::WINDOWS => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::validation(
                        "windows platform must be delivered via WNS",
                    )),
                    invalid_token: false,
                    payload_too_large: false,
                };
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

            let retryable = (dispatch.status_code == 0
                || matches!(dispatch.status_code, 429 | 500 | 503))
                && attempt < APNS_MAX_RETRY
                && !dispatch.success;

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
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::Internal(
                        "APNs concurrency limiter closed".to_string(),
                    )),
                    invalid_token: false,
                    payload_too_large: false,
                };
            }
        };
        let mut auth_token = match self.current_token().await {
            Ok(token) => token,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(err),
                    invalid_token: false,
                    payload_too_large: false,
                };
            }
        };

        let body = match payload.encoded_body() {
            Ok(body) => body,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::Internal(err.to_string())),
                    invalid_token: false,
                    payload_too_large: false,
                };
            }
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

        let mut response = match request.body(body.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::Internal(err.to_string())),
                    invalid_token: false,
                    payload_too_large: false,
                };
            }
        };

        let mut status = response.status();
        let mut status_code = status.as_u16();
        let mut body_text = response.text().await.unwrap_or_default();
        let mut reason = parse_apns_reason(&body_text);

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

                    response = match request.body(body.clone()).send().await {
                        Ok(resp) => resp,
                        Err(err) => {
                            return DispatchResult {
                                success: false,
                                status_code: 0,
                                error: Some(Error::Internal(err.to_string())),
                                invalid_token: false,
                                payload_too_large: false,
                            };
                        }
                    };

                    status = response.status();
                    status_code = status.as_u16();
                    body_text = response.text().await.unwrap_or_default();
                    reason = parse_apns_reason(&body_text);
                }
                Err(err) => {
                    return DispatchResult {
                        success: false,
                        status_code,
                        error: Some(err),
                        invalid_token: false,
                        payload_too_large: false,
                    };
                }
            }
        }

        if status == StatusCode::OK {
            DispatchResult {
                success: true,
                status_code,
                error: None,
                invalid_token: false,
                payload_too_large: false,
            }
        } else {
            // Prefer APNs reason, then fall back to the raw body or status.
            let message = if let Some(r) = reason.as_deref() {
                r.to_string()
            } else if !body_text.is_empty() {
                body_text.clone()
            } else {
                format!("APNs error, status {status_code}")
            };

            DispatchResult {
                success: false,
                status_code,
                error: Some(Error::Upstream {
                    provider: "APNs",
                    status: status_code,
                    message,
                }),
                invalid_token: is_apns_token_invalid(status, reason.as_deref()),
                payload_too_large: is_apns_payload_too_large(status, reason.as_deref()),
            }
        }
    }

    async fn current_token(&self) -> Result<Arc<str>, Error> {
        Ok(self.token_info().await?.token)
    }

    async fn refresh_token_now(&self) -> Result<Arc<str>, Error> {
        self.token_provider.refresh_now().await
    }
}

fn is_apns_payload_too_large(status: StatusCode, reason: Option<&str>) -> bool {
    status == StatusCode::PAYLOAD_TOO_LARGE && matches!(reason, Some("PayloadTooLarge"))
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

fn parse_apns_reason(body: &str) -> Option<String> {
    let parsed = serde_json::from_str::<ReasonBody>(body).ok()?;
    parsed.reason
}

fn is_apns_token_invalid(status: StatusCode, reason: Option<&str>) -> bool {
    if status == StatusCode::GONE {
        return true;
    }
    if let Some(reason) = reason {
        return matches!(
            reason,
            "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered" | "InvalidToken"
        );
    }
    false
}
