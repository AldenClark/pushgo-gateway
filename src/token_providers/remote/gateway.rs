use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;

use pushgo_gateway::{Error, providers::TokenInfo};

const TOKEN_SERVICE_TOKEN_ENV: &str = "PUSHGO_TOKEN_SERVICE_TOKEN";
const TOKEN_ENDPOINT_PATH: &str = "/provider/token";
const TOKEN_SANDBOX_ENDPOINT_PATH: &str = "/provider/token/sandbox";
const TOKEN_PRODUCTION_ENDPOINT_PATH: &str = "/provider/token/production";
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub enum GatewayProvider {
    Apns,
    Fcm,
    Wns,
}

impl GatewayProvider {
    fn as_str(self) -> &'static str {
        match self {
            GatewayProvider::Apns => "apns",
            GatewayProvider::Fcm => "fcm",
            GatewayProvider::Wns => "wns",
        }
    }
}

#[derive(Debug)]
struct GatewayTokenState {
    token: Arc<str>,
    expires_at: Instant,
    project_id: Option<Arc<str>>,
}

pub struct GatewayTokenCache {
    client: Client,
    provider: GatewayProvider,
    base_url: Arc<str>,
    token: Option<Arc<str>>,
    state: Arc<ArcSwap<GatewayTokenState>>,
}

impl GatewayTokenCache {
    pub fn new(client: Client, provider: GatewayProvider, base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let token = read_token_env();

        let initial = GatewayTokenState {
            token: Arc::from(""),
            expires_at: Instant::now() - Duration::from_secs(1),
            project_id: None,
        };
        Self {
            client,
            provider,
            base_url: Arc::from(base_url.into_boxed_str()),
            token,
            state: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        let cached = self.state.load();
        let now = Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid && remaining > TOKEN_REFRESH_BUFFER {
            return Ok(TokenInfo {
                token: Arc::clone(&cached.token),
                expires_in: remaining.as_secs(),
            });
        }

        match self.fetch_and_store().await {
            Ok(info) => Ok(info),
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

    pub async fn token_info_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
        let cached = self.state.load();
        let now = Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid
            && remaining > TOKEN_REFRESH_BUFFER
            && let Some(project_id) = &cached.project_id
        {
            return Ok((
                TokenInfo {
                    token: Arc::clone(&cached.token),
                    expires_in: remaining.as_secs(),
                },
                Arc::clone(project_id),
            ));
        }

        match self.fetch_and_store_with_project().await {
            Ok((info, project_id)) => Ok((info, project_id)),
            Err(err) => {
                if cached_valid {
                    if let Some(project_id) = &cached.project_id {
                        Ok((
                            TokenInfo {
                                token: Arc::clone(&cached.token),
                                expires_in: remaining.as_secs(),
                            },
                            Arc::clone(project_id),
                        ))
                    } else {
                        Err(err)
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    pub async fn refresh_now(&self) -> Result<Arc<str>, Error> {
        let info = self.fetch_and_store().await?;
        Ok(info.token)
    }

    async fn fetch_and_store(&self) -> Result<TokenInfo, Error> {
        let (info, project_id) = self.fetch_token().await?;
        let expires_at = Instant::now() + Duration::from_secs(info.expires_in);
        let state = GatewayTokenState {
            token: Arc::clone(&info.token),
            expires_at,
            project_id,
        };
        self.state.store(Arc::new(state));
        Ok(info)
    }

    async fn fetch_and_store_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
        let (info, project_id) = self.fetch_token().await?;
        let project_id = if let Some(project_id) = project_id {
            project_id
        } else {
            let cached = self.state.load();
            if let Some(cached_project_id) = &cached.project_id {
                Arc::clone(cached_project_id)
            } else {
                Arc::from("")
            }
        };
        let expires_at = Instant::now() + Duration::from_secs(info.expires_in);
        let state = GatewayTokenState {
            token: Arc::clone(&info.token),
            expires_at,
            project_id: Some(Arc::clone(&project_id)),
        };
        self.state.store(Arc::new(state));
        Ok((info, project_id))
    }

    async fn fetch_token(&self) -> Result<(TokenInfo, Option<Arc<str>>), Error> {
        let mut paths = Vec::with_capacity(2);
        match self.provider {
            GatewayProvider::Apns => {
                if pushgo_gateway::util::is_sandbox_mode() {
                    paths.push(TOKEN_SANDBOX_ENDPOINT_PATH);
                } else {
                    paths.push(TOKEN_PRODUCTION_ENDPOINT_PATH);
                }
                // Backward-compatible fallback for older token-service deployments.
                paths.push(TOKEN_ENDPOINT_PATH);
            }
            GatewayProvider::Fcm | GatewayProvider::Wns => paths.push(TOKEN_ENDPOINT_PATH),
        }

        let mut last_error: Option<Error> = None;
        for path in paths {
            match self.fetch_token_from_path(path).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    let should_try_fallback = path != TOKEN_ENDPOINT_PATH
                        && matches!(
                            &err,
                            Error::Upstream { status, .. } if *status == 400 || *status == 404 || *status == 405
                        );
                    if should_try_fallback {
                        last_error = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| Error::Internal("token service request failed".to_string())))
    }

    async fn fetch_token_from_path(
        &self,
        token_path: &str,
    ) -> Result<(TokenInfo, Option<Arc<str>>), Error> {
        let url = format!(
            "{}{}?provider={}",
            self.base_url,
            token_path,
            self.provider.as_str()
        );
        let mut request = self.client.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_ref());
        }

        let response = request
            .send()
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;

        if !status.is_success() {
            let message = parse_error_body(&body)
                .unwrap_or_else(|| format!("token service error, status {}", status.as_u16()));
            return Err(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message,
            });
        }

        let parsed: GatewayResponse<GatewayTokenData> =
            serde_json::from_slice(&body).map_err(|err| Error::Internal(err.to_string()))?;
        if !parsed.success {
            return Err(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: parsed
                    .error
                    .unwrap_or_else(|| "token service returned error".to_string()),
            });
        }
        let data = parsed
            .data
            .ok_or_else(|| Error::Internal("token service response missing data".to_string()))?;
        let token = data
            .token
            .ok_or_else(|| Error::Internal("token service response missing token".to_string()))?;

        Ok((
            TokenInfo {
                token: Arc::from(token.into_boxed_str()),
                expires_in: data.expires_in,
            },
            data.project_id
                .map(|value| Arc::from(value.into_boxed_str())),
        ))
    }
}

fn parse_error_body(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn read_token_env() -> Option<Arc<str>> {
    if let Ok(value) = std::env::var(TOKEN_SERVICE_TOKEN_ENV) {
        let value = value.trim();
        if !value.is_empty() {
            return Some(Arc::from(value.to_string().into_boxed_str()));
        }
    }
    None
}

#[derive(Deserialize)]
struct GatewayResponse<T> {
    success: bool,
    error: Option<String>,
    data: Option<T>,
}

#[derive(Deserialize)]
struct GatewayTokenData {
    #[serde(default, deserialize_with = "deserialize_empty_string_as_none")]
    token: Option<String>,
    expires_in: u64,
    #[serde(default, deserialize_with = "deserialize_empty_string_as_none")]
    project_id: Option<String>,
}

fn deserialize_empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<Cow<'de, str>> = Option::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
    }
}
