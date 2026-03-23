use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use pushgo_gateway::{
    Error,
    providers::{BoxFuture, FcmAccess, FcmTokenProvider as FcmTokenProviderTrait, TokenInfo},
    util::is_sandbox_mode,
};

use crate::provider_config::FcmConfig;

const FCM_TOKEN_PATH: &str = "/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_TIMEOUT: Duration = Duration::from_secs(60);
const FCM_TOKEN_REFRESH_BUFFER_SECS: u64 = 300;
const FCM_TOKEN_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct FcmTokenState {
    token: Arc<str>,
    expires_at: std::time::Instant,
}

impl FcmTokenState {
    fn empty() -> Self {
        Self {
            token: Arc::from(""),
            expires_at: std::time::Instant::now() - Duration::from_secs(1),
        }
    }
}

struct FcmAuth {
    client_email: Arc<str>,
    encoding_key: EncodingKey,
    oauth_token_url: Arc<str>,
}

pub struct FcmTokenProvider {
    client: Client,
    access_token: Arc<ArcSwap<FcmTokenState>>,
    auth: Arc<FcmAuth>,
    project_id: Arc<str>,
}

impl FcmTokenProvider {
    pub fn new(config: &FcmConfig, oauth_base_url: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .timeout(FCM_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;
        let normalized_oauth_base_url = normalize_base_url(oauth_base_url)?;
        let oauth_token_url = format!("{normalized_oauth_base_url}{FCM_TOKEN_PATH}");

        let project_id = Arc::from(config.project_id.as_str());
        let access_token = Arc::new(ArcSwap::from_pointee(FcmTokenState::empty()));
        let auth = Arc::new(build_fcm_auth(config, &oauth_token_url)?);
        let token_client = client.clone();
        let token_store = Arc::clone(&access_token);
        let token_auth = Arc::clone(&auth);

        tokio::spawn(async move {
            loop {
                match get_google_access_token(&token_client, &token_auth).await {
                    Ok(token) => {
                        let sleep_for = token
                            .expires_in
                            .saturating_sub(FCM_TOKEN_REFRESH_BUFFER_SECS)
                            .max(60);
                        let token_arc = Arc::from(token.value.into_boxed_str());
                        let expires_at =
                            std::time::Instant::now() + Duration::from_secs(token.expires_in);
                        token_store.store(Arc::new(FcmTokenState {
                            token: token_arc,
                            expires_at,
                        }));
                        sleep(Duration::from_secs(sleep_for)).await;
                    }
                    Err(err) => {
                        sleep(FCM_TOKEN_RETRY_DELAY).await;
                    }
                }
            }
        });

        Ok(Self {
            client,
            access_token,
            auth,
            project_id,
        })
    }

    async fn token_info(&self) -> Result<FcmAccess, Error> {
        let cached = self.access_token.load();
        let now = std::time::Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid && remaining > Duration::from_secs(FCM_TOKEN_REFRESH_BUFFER_SECS) {
            return Ok(FcmAccess {
                token: TokenInfo {
                    token: Arc::clone(&cached.token),
                    expires_in: remaining.as_secs(),
                },
                project_id: Arc::clone(&self.project_id),
            });
        }

        match get_google_access_token(&self.client, &self.auth).await {
            Ok(token) => {
                let expires_in = token.expires_in;
                let token_arc = Arc::from(token.value.into_boxed_str());
                let expires_at = std::time::Instant::now() + Duration::from_secs(expires_in);
                self.access_token.store(Arc::new(FcmTokenState {
                    token: Arc::clone(&token_arc),
                    expires_at,
                }));
                Ok(FcmAccess {
                    token: TokenInfo {
                        token: token_arc,
                        expires_in,
                    },
                    project_id: Arc::clone(&self.project_id),
                })
            }
            Err(err) => {
                if cached_valid {
                    Ok(FcmAccess {
                        token: TokenInfo {
                            token: Arc::clone(&cached.token),
                            expires_in: remaining.as_secs(),
                        },
                        project_id: Arc::clone(&self.project_id),
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn token_info_fresh(&self) -> Result<FcmAccess, Error> {
        let token = get_google_access_token(&self.client, &self.auth).await?;
        let expires_in = token.expires_in;
        let token_arc = Arc::from(token.value.into_boxed_str());
        Ok(FcmAccess {
            token: TokenInfo {
                token: token_arc,
                expires_in,
            },
            project_id: Arc::clone(&self.project_id),
        })
    }
}

impl FcmTokenProviderTrait for FcmTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move { self.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move { self.token_info_fresh().await })
    }
}

struct AccessToken {
    value: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: usize,
    iat: usize,
}

async fn get_google_access_token(client: &Client, auth: &FcmAuth) -> Result<AccessToken, Error> {
    let now = Utc::now();
    let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
    let iat = now.timestamp() as usize;
    let claims = Claims {
        iss: auth.client_email.to_string(),
        scope: FCM_SCOPE.to_string(),
        aud: auth.oauth_token_url.to_string(),
        exp,
        iat,
    };
    let header = Header::new(Algorithm::RS256);
    let jwt_token = encode(&header, &claims, &auth.encoding_key)
        .map_err(|err| Error::Internal(format!("failed to sign FCM JWT: {err}")))?;

    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt_token.as_str()),
    ];

    let response = match client
        .post(auth.oauth_token_url.as_ref())
        .form(&params)
        .send()
        .await
    {
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
            format!("Google OAuth error, status {status_code}")
        });
        return Err(Error::Upstream {
            provider: "Google OAuth",
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
        provider: "Google OAuth",
        status: status.as_u16(),
        message: "missing access_token".to_string(),
    })?;
    let expires_in = token.expires_in.unwrap_or(3600);

    Ok(AccessToken { value, expires_in })
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

fn build_fcm_auth(config: &FcmConfig, oauth_token_url: &str) -> Result<FcmAuth, Error> {
    let encoding_key = EncodingKey::from_rsa_pem(config.private_key.as_bytes())
        .map_err(|err| Error::Internal(format!("invalid FCM private_key: {err}")))?;
    Ok(FcmAuth {
        client_email: Arc::from(config.client_email.as_str()),
        encoding_key,
        oauth_token_url: Arc::from(oauth_token_url),
    })
}

fn normalize_base_url(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::validation("fcm-oauth-base-url must not be empty"));
    }
    Ok(trimmed.to_string())
}
