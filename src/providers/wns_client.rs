use std::{sync::Arc, time::Duration};

use reqwest::Client;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, TokenInfo, WnsClient, WnsTokenProvider, wns::WnsPayload,
    },
};

const WNS_TIMEOUT: Duration = Duration::from_secs(60);
const WNS_TYPE: &str = "wns/raw";
const WNS_CONTENT_TYPE: &str = "application/octet-stream";

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
        let token = match self.token_provider.token_info().await {
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
        match self
            .send_request(
                device_token,
                token.token.as_ref(),
                body.clone(),
                priority,
                ttl_seconds,
            )
            .await
        {
            Ok(result) if result.status_code == 401 => {
                self.retry_with_fresh_token(device_token, body, priority, ttl_seconds)
                    .await
            }
            Ok(result) => result,
            Err(err) => DispatchResult {
                success: false,
                status_code: 0,
                error: Some(err),
                invalid_token: false,
                payload_too_large: false,
            },
        }
    }

    async fn retry_with_fresh_token(
        &self,
        device_token: &str,
        body: Vec<u8>,
        priority: Option<u8>,
        ttl_seconds: Option<u32>,
    ) -> DispatchResult {
        let token = match self.token_provider.token_info_fresh().await {
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

        match self
            .send_request(
                device_token,
                token.token.as_ref(),
                body,
                priority,
                ttl_seconds,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => DispatchResult {
                success: false,
                status_code: 0,
                error: Some(err),
                invalid_token: false,
                payload_too_large: false,
            },
        }
    }

    async fn send_request(
        &self,
        device_token: &str,
        bearer: &str,
        body: Vec<u8>,
        priority: Option<u8>,
        ttl_seconds: Option<u32>,
    ) -> Result<DispatchResult, Error> {
        let mut request = self
            .client
            .post(device_token)
            .bearer_auth(bearer)
            .header("x-wns-type", WNS_TYPE)
            .header("content-type", WNS_CONTENT_TYPE)
            .body(body);
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
        let body_text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let message = if body_text.is_empty() {
                format!("WNS error, status {status_code}")
            } else {
                body_text.clone()
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
