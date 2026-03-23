use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;
use tokio::time::sleep;

use pushgo_gateway::{
    Error,
    providers::{BoxFuture, TokenInfo, WnsTokenProvider as WnsTokenProviderTrait},
    util::is_sandbox_mode,
};

use crate::provider_config::WnsConfig;

const WNS_TIMEOUT: Duration = Duration::from_secs(60);
const WNS_TOKEN_REFRESH_BUFFER_SECS: u64 = 300;
const WNS_TOKEN_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct WnsTokenState {
    token: Arc<str>,
    expires_at: std::time::Instant,
}

impl WnsTokenState {
    fn empty() -> Self {
        Self {
            token: Arc::from(""),
            expires_at: std::time::Instant::now() - Duration::from_secs(1),
        }
    }
}

struct WnsAuth {
    oauth_base_url: Arc<str>,
    tenant_id: Arc<str>,
    client_id: Arc<str>,
    client_secret: Arc<str>,
    scope: Arc<str>,
}

pub struct WnsTokenProvider {
    client: Client,
    access_token: Arc<ArcSwap<WnsTokenState>>,
    auth: Arc<WnsAuth>,
}

impl WnsTokenProvider {
    pub fn new(config: &WnsConfig, oauth_base_url: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .timeout(WNS_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;
        let normalized_oauth_base_url = normalize_base_url(oauth_base_url)?;

        let access_token = Arc::new(ArcSwap::from_pointee(WnsTokenState::empty()));
        let auth = Arc::new(WnsAuth {
            oauth_base_url: Arc::from(normalized_oauth_base_url),
            tenant_id: Arc::from(config.tenant_id.as_str()),
            client_id: Arc::from(config.client_id.as_str()),
            client_secret: Arc::from(config.client_secret.as_str()),
            scope: Arc::from(normalize_scope(config.scope.as_str())),
        });

        let token_client = client.clone();
        let token_store = Arc::clone(&access_token);
        let token_auth = Arc::clone(&auth);

        tokio::spawn(async move {
            loop {
                match get_wns_access_token(&token_client, &token_auth).await {
                    Ok(token) => {
                        let sleep_for = token
                            .expires_in
                            .saturating_sub(WNS_TOKEN_REFRESH_BUFFER_SECS)
                            .max(60);
                        let token_arc = Arc::from(token.value.into_boxed_str());
                        let expires_at =
                            std::time::Instant::now() + Duration::from_secs(token.expires_in);
                        token_store.store(Arc::new(WnsTokenState {
                            token: token_arc,
                            expires_at,
                        }));
                        sleep(Duration::from_secs(sleep_for)).await;
                    }
                    Err(err) => {
                        sleep(WNS_TOKEN_RETRY_DELAY).await;
                    }
                }
            }
        });

        Ok(Self {
            client,
            access_token,
            auth,
        })
    }

    async fn token_info(&self) -> Result<TokenInfo, Error> {
        let cached = self.access_token.load();
        let now = std::time::Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid && remaining > Duration::from_secs(WNS_TOKEN_REFRESH_BUFFER_SECS) {
            return Ok(TokenInfo {
                token: Arc::clone(&cached.token),
                expires_in: remaining.as_secs(),
            });
        }

        match get_wns_access_token(&self.client, &self.auth).await {
            Ok(token) => {
                let expires_in = token.expires_in;
                let token_arc = Arc::from(token.value.into_boxed_str());
                let expires_at = std::time::Instant::now() + Duration::from_secs(expires_in);
                self.access_token.store(Arc::new(WnsTokenState {
                    token: Arc::clone(&token_arc),
                    expires_at,
                }));
                Ok(TokenInfo {
                    token: token_arc,
                    expires_in,
                })
            }
            Err(err) => {
                if cached_valid {
                    Ok(TokenInfo {
                        token: Arc::clone(&cached.token),
                        expires_in: remaining.as_secs(),
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        let token = get_wns_access_token(&self.client, &self.auth).await?;
        Ok(TokenInfo {
            token: Arc::from(token.value.into_boxed_str()),
            expires_in: token.expires_in,
        })
    }
}

impl WnsTokenProviderTrait for WnsTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info_fresh().await })
    }
}

struct AccessToken {
    value: String,
    expires_in: u64,
}

async fn get_wns_access_token(client: &Client, auth: &WnsAuth) -> Result<AccessToken, Error> {
    let token_url = format!(
        "{}/{}/oauth2/v2.0/token",
        auth.oauth_base_url, auth.tenant_id
    );
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", auth.client_id.as_ref()),
        ("client_secret", auth.client_secret.as_ref()),
        ("scope", auth.scope.as_ref()),
    ];

    let response = match client.post(&token_url).form(&params).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Err(Error::Internal(err.to_string()));
        }
    };

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        let body = response.bytes().await.unwrap_or_default();
        let message = parse_error_body(&body).unwrap_or_else(|| {
            format!("Azure AD OAuth error, status {status_code}")
        });
        return Err(Error::Upstream {
            provider: "Azure AD",
            status: status_code,
            message,
        });
    }

    let body = response
        .bytes()
        .await
        .map_err(|err| Error::Internal(err.to_string()))?;
    let token: AccessTokenResponse =
        serde_json::from_slice(&body).map_err(|err| Error::Internal(err.to_string()))?;
    let value = token.access_token.ok_or_else(|| Error::Upstream {
        provider: "Azure AD",
        status: status.as_u16(),
        message: "missing access_token".to_string(),
    })?;
    let expires_in = token.expires_in.unwrap_or(3600);

    Ok(AccessToken { value, expires_in })
}

fn normalize_base_url(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::validation("wns-base-url must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn normalize_scope(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return "https://wns.windows.com/.default".to_string();
    }
    trimmed.to_string()
}

fn parse_error_body(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
}
