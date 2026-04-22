use std::{sync::Arc, time::Duration};

use reqwest::Client;
use tokio::time::sleep;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, TokenInfo, WnsClient, WnsTokenProvider, wns::WnsPayload,
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

            let dispatch = self
                .send_request(
                    device_token,
                    token.token.as_ref(),
                    body.clone(),
                    priority,
                    ttl_seconds,
                )
                .await
                .unwrap_or_else(|err| DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(err),
                    invalid_token: false,
                    payload_too_large: false,
                });
            if dispatch.success {
                return dispatch;
            }

            let status_code = dispatch.status_code;
            if status_code == 401 && !force_fresh_token && attempt < WNS_MAX_RETRY {
                force_fresh_token = true;
                continue;
            }

            let retryable = is_wns_retryable_status(status_code) && attempt < WNS_MAX_RETRY;
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
    ) -> Result<DispatchResult, Error> {
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
        let response = request
            .send()
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;

        let status = response.status();
        let status_code = status.as_u16();
        let body = response.bytes().await.unwrap_or_default();

        if !status.is_success() {
            let message = if let Some(body_text) = response_body_text(&body) {
                body_text
            } else {
                format!("WNS error, status {status_code}")
            };
            return Ok(DispatchResult {
                success: false,
                status_code,
                error: Some(Error::Upstream {
                    provider: "WNS",
                    status: status_code,
                    message,
                }),
                invalid_token: is_wns_token_invalid(status_code),
                payload_too_large: is_wns_payload_too_large(status_code),
            });
        }

        Ok(DispatchResult {
            success: true,
            status_code,
            error: None,
            invalid_token: false,
            payload_too_large: false,
        })
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

fn is_wns_token_invalid(status_code: u16) -> bool {
    matches!(status_code, 404 | 410)
}

fn is_wns_payload_too_large(status_code: u16) -> bool {
    status_code == 413
}

fn is_wns_retryable_status(status_code: u16) -> bool {
    status_code == 0 || matches!(status_code, 429 | 500 | 503 | 504)
}

fn response_body_text(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
