use std::sync::Arc;

use reqwest::Client;
use serde::Deserialize;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, FcmClient, FcmTokenProvider, PROVIDER_CONNECT_TIMEOUT,
        PROVIDER_REQUEST_TIMEOUT, ProviderFailure, ProviderFailureKind, TokenInfo,
        error::{parse_retry_after_millis, trimmed_body_text},
        fcm::FcmPayload,
    },
    runtime_config::GatewayRuntimeProfile,
};

pub struct FcmService {
    client: Client,
    token_provider: Arc<dyn FcmTokenProvider>,
    base_url: Arc<str>,
}

impl FcmService {
    pub fn new(token_provider: Arc<dyn FcmTokenProvider>, base_url: &str) -> Result<Self, Error> {
        Self::new_with_profile(token_provider, base_url, GatewayRuntimeProfile::Small)
    }

    pub fn new_with_profile(
        token_provider: Arc<dyn FcmTokenProvider>,
        base_url: &str,
        _runtime_profile: GatewayRuntimeProfile,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .timeout(PROVIDER_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;
        let normalized_base_url = normalize_base_url(base_url)?;
        Ok(Self {
            client,
            token_provider,
            base_url: Arc::from(normalized_base_url),
        })
    }

    pub async fn send_to_device(
        &self,
        device_token: &str,
        payload: Arc<FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
    ) -> DispatchResult {
        let body = match prepared_body {
            Some(body) => body,
            None => match payload.encoded_body(device_token) {
                Ok(body) => body,
                Err(err) => {
                    return DispatchResult::from_error(0, Error::Internal(err.to_string()));
                }
            },
        };

        let access = match self.token_provider.token_info().await {
            Ok(access) => access,
            Err(err) => return DispatchResult::provider_access_failure(err),
        };
        let dispatch = self.send_once(&access, body.as_ref()).await;
        if dispatch.should_refresh_credentials() {
            let _ = self.token_provider.token_info_fresh().await;
        }
        dispatch
    }

    async fn send_once(&self, access: &crate::providers::FcmAccess, body: &[u8]) -> DispatchResult {
        let endpoint = format!(
            "{}/v1/projects/{}/messages:send",
            self.base_url, access.project_id
        );
        let response = match self
            .client
            .post(&endpoint)
            .bearer_auth(access.token.token.as_ref())
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => return DispatchResult::transport(Error::Internal(err.to_string())),
        };

        let status = response.status();
        let status_code = status.as_u16();
        let retry_after_millis = parse_retry_after_millis(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
        );
        let response_body = response.bytes().await.unwrap_or_default();

        if status.is_success() {
            return DispatchResult::success(status_code);
        }

        let retry_after_millis = normalize_fcm_retry_after(status_code, retry_after_millis);
        DispatchResult::upstream(
            "FCM",
            classify_fcm_failure(status_code, &response_body)
                .with_retry_after_millis(retry_after_millis),
        )
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        let access = self.token_provider.token_info().await?;
        Ok(access.token)
    }

    pub async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        let access = self.token_provider.token_info_fresh().await?;
        Ok(access.token)
    }
}

fn normalize_fcm_retry_after(status_code: u16, retry_after_millis: Option<i64>) -> Option<i64> {
    if status_code == 429 {
        // FCM explicitly specifies a one-minute default for quota responses.
        Some(retry_after_millis.unwrap_or_default().max(60_000))
    } else if status_code == 408 || (500..=599).contains(&status_code) {
        // FCM recommends waiting at least ten seconds before retrying a failed
        // request. The durable scheduler adds exponential backoff and jitter.
        Some(retry_after_millis.unwrap_or_default().max(10_000))
    } else {
        retry_after_millis
    }
}

fn classify_fcm_failure(status_code: u16, body: &[u8]) -> ProviderFailure {
    let message =
        trimmed_body_text(body).unwrap_or_else(|| format!("FCM error, status {status_code}"));
    let kind = if is_fcm_token_invalid(body) {
        ProviderFailureKind::InvalidToken
    } else if is_fcm_payload_too_large(status_code, body) {
        ProviderFailureKind::PayloadTooLarge
    } else if matches!(status_code, 401 | 403) {
        ProviderFailureKind::CredentialsExpired
    } else if status_code == 429 {
        ProviderFailureKind::RateLimited
    } else if status_code == 408 || (500..=599).contains(&status_code) {
        ProviderFailureKind::TemporarilyUnavailable
    } else {
        ProviderFailureKind::Rejected
    };
    ProviderFailure::new(status_code, kind, message)
}

fn is_fcm_payload_too_large(status_code: u16, body: &[u8]) -> bool {
    status_code == 400
        && parse_fcm_error(body)
            .and_then(|value| value.error)
            .is_some_and(|error| {
                error
                    .status
                    .as_deref()
                    .is_some_and(|status| status.eq_ignore_ascii_case("INVALID_ARGUMENT"))
                    && error
                        .message
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains("message too big")
            })
}
impl FcmClient for FcmService {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            self.send_to_device(device_token, payload, prepared_body)
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

fn is_fcm_token_invalid(body: &[u8]) -> bool {
    let Some(error) = parse_fcm_error(body).and_then(|value| value.error) else {
        let haystack = String::from_utf8_lossy(body).to_ascii_lowercase();
        return haystack.contains("unregistered")
            || haystack.contains("not registered")
            || haystack.contains("invalid registration token")
            || (haystack.contains("registration token") && haystack.contains("invalid"));
    };
    if error
        .status
        .as_deref()
        .map(|status| status.eq_ignore_ascii_case("NOT_FOUND"))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(details) = error.details.as_deref() {
        for detail in details {
            if detail
                .error_code
                .as_deref()
                .map(|code| code.eq_ignore_ascii_case("UNREGISTERED"))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    if let Some(message) = error.message.as_deref() {
        let haystack = message.to_ascii_lowercase();
        return haystack.contains("unregistered")
            || haystack.contains("not registered")
            || haystack.contains("invalid registration token")
            || (haystack.contains("registration token") && haystack.contains("invalid"));
    }
    false
}

fn normalize_base_url(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::validation_code(
            "fcm-base-url must not be empty",
            "fcm_base_url_required",
        ));
    }
    Ok(trimmed.to_string())
}

fn parse_fcm_error(body: &[u8]) -> Option<FcmErrorEnvelope> {
    serde_json::from_slice(body).ok()
}

#[derive(Deserialize)]
struct FcmErrorEnvelope {
    error: Option<FcmErrorBody>,
}

#[derive(Deserialize)]
struct FcmErrorBody {
    status: Option<String>,
    message: Option<String>,
    #[serde(default)]
    details: Option<Vec<FcmErrorDetail>>,
}

#[derive(Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ProviderFailureKind, classify_fcm_failure, normalize_fcm_retry_after};

    #[test]
    fn fcm_classifies_unregistered_token() {
        let body = br#"{
            "error":{
                "status":"NOT_FOUND",
                "message":"Requested entity was not found.",
                "details":[{"errorCode":"UNREGISTERED"}]
            }
        }"#;
        let failure = classify_fcm_failure(404, body);
        assert_eq!(failure.kind, ProviderFailureKind::InvalidToken);
    }

    #[test]
    fn fcm_does_not_delete_a_token_for_an_unstructured_not_found_response() {
        let failure = classify_fcm_failure(404, b"");
        assert_eq!(failure.kind, ProviderFailureKind::Rejected);
    }

    #[test]
    fn fcm_classifies_payload_too_large() {
        let body = br#"{
            "error":{
                "status":"INVALID_ARGUMENT",
                "message":"Message too big"
            }
        }"#;
        let failure = classify_fcm_failure(400, body);
        assert_eq!(failure.kind, ProviderFailureKind::PayloadTooLarge);
    }

    #[test]
    fn fcm_classifies_retryable_server_failure() {
        for status in [408, 502, 503] {
            let failure = classify_fcm_failure(status, b"");
            assert_eq!(failure.kind, ProviderFailureKind::TemporarilyUnavailable);
        }
    }

    #[test]
    fn fcm_retry_delays_respect_provider_minimums() {
        assert_eq!(normalize_fcm_retry_after(429, None), Some(60_000));
        assert_eq!(normalize_fcm_retry_after(503, None), Some(10_000));
        assert_eq!(normalize_fcm_retry_after(503, Some(30_000)), Some(30_000));
        assert_eq!(normalize_fcm_retry_after(400, None), None);
    }
}
