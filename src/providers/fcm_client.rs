use std::{sync::Arc, time::Duration};

use reqwest::Client;
use serde::Deserialize;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, FcmClient, FcmTokenProvider, TokenInfo, fcm::FcmPayload,
    },
};

const FCM_TIMEOUT: Duration = Duration::from_secs(60);

pub struct FcmService {
    client: Client,
    token_provider: Arc<dyn FcmTokenProvider>,
    base_url: Arc<str>,
}

impl FcmService {
    pub fn new(token_provider: Arc<dyn FcmTokenProvider>, base_url: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .timeout(FCM_TIMEOUT)
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
        let access = match self.token_provider.token_info().await {
            Ok(access) => access,
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

        let body = match prepared_body {
            Some(body) => body,
            None => match payload.encoded_body(device_token) {
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
            },
        };

        let endpoint = format!(
            "{}/v1/projects/{}/messages:send",
            self.base_url, access.project_id
        );

        let response = match self
            .client
            .post(&endpoint)
            .bearer_auth(access.token.token.as_ref())
            .header("content-type", "application/json")
            .body(body.as_ref().to_vec())
            .send()
            .await
        {
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

        let status = response.status();
        let status_code = status.as_u16();
        let body = response.bytes().await.unwrap_or_default();

        if !status.is_success() {
            let message =
                body_message(&body).unwrap_or_else(|| format!("FCM error, status {status_code}"));
            return DispatchResult {
                success: false,
                status_code,
                error: Some(Error::Upstream {
                    provider: "FCM",
                    status: status_code,
                    message,
                }),
                invalid_token: is_fcm_token_invalid(status_code, &body),
                payload_too_large: is_fcm_payload_too_large(status_code, &body),
            };
        }

        DispatchResult {
            success: true,
            status_code,
            error: None,
            invalid_token: false,
            payload_too_large: false,
        }
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

fn is_fcm_payload_too_large(status_code: u16, body: &[u8]) -> bool {
    if status_code != 400 {
        return false;
    }
    let Some(error) = parse_fcm_error(body).and_then(|value| value.error) else {
        return false;
    };
    let invalid_argument = error
        .status
        .as_deref()
        .map(|status| status.eq_ignore_ascii_case("INVALID_ARGUMENT"))
        .unwrap_or(false);
    if !invalid_argument {
        return false;
    }
    let message = error
        .message
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    message.contains("message too big")
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

fn is_fcm_token_invalid(status_code: u16, body: &[u8]) -> bool {
    if status_code == 404 {
        return true;
    }
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
        return Err(Error::validation("fcm-base-url must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn body_message(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
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
