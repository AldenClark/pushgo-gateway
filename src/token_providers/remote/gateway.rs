use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;

use pushgo_gateway::{Error, providers::TokenInfo};

const TOKEN_ENDPOINT_PATH: &str = "/provider/token";
const TOKEN_SANDBOX_ENDPOINT_PATH: &str = "/provider/token/sandbox";
const TOKEN_PRODUCTION_ENDPOINT_PATH: &str = "/provider/token/production";
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub(crate) enum GatewayProvider {
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

pub(crate) struct GatewayTokenCache {
    client: Client,
    provider: GatewayProvider,
    base_url: Arc<str>,
    state: Arc<ArcSwap<GatewayTokenState>>,
}

impl GatewayTokenCache {
    pub(crate) fn new(client: Client, provider: GatewayProvider, base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let expired_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        let initial = GatewayTokenState {
            token: Arc::from(""),
            expires_at: expired_at,
            project_id: None,
        };
        Self {
            client,
            provider,
            base_url: Arc::from(base_url.into_boxed_str()),
            state: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub(crate) async fn token_info(&self) -> Result<TokenInfo, Error> {
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

    pub(crate) async fn token_info_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
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

    pub(crate) async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        self.fetch_and_store().await
    }

    pub(crate) async fn token_info_with_project_fresh(
        &self,
    ) -> Result<(TokenInfo, Arc<str>), Error> {
        self.fetch_and_store_with_project().await
    }

    pub(crate) async fn refresh_now(&self) -> Result<Arc<str>, Error> {
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
                return Err(Error::Internal(
                    "token service response missing project_id for fcm provider".to_string(),
                ));
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
        let mut paths = Vec::with_capacity(1);
        match self.provider {
            GatewayProvider::Apns => {
                if pushgo_gateway::util::is_sandbox_mode() {
                    paths.push(TOKEN_SANDBOX_ENDPOINT_PATH);
                } else {
                    paths.push(TOKEN_PRODUCTION_ENDPOINT_PATH);
                }
            }
            GatewayProvider::Fcm | GatewayProvider::Wns => paths.push(TOKEN_ENDPOINT_PATH),
        }

        if let Some(path) = paths.into_iter().next() {
            return self.fetch_token_from_path(path).await;
        }
        Err(Error::Internal("token service request failed".to_string()))
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
        let response = self
            .client
            .get(&url)
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{GatewayProvider, GatewayTokenCache};

    #[tokio::test]
    async fn fresh_token_info_with_project_bypasses_cached_token() {
        let (base_url, request_count) = spawn_token_service(2).await;
        let cache = GatewayTokenCache::new(reqwest::Client::new(), GatewayProvider::Fcm, &base_url);

        let (first, first_project) = cache
            .token_info_with_project()
            .await
            .expect("initial token should fetch");
        assert_eq!(&*first.token, "token-1");
        assert_eq!(&*first_project, "project-1");

        let (cached, cached_project) = cache
            .token_info_with_project()
            .await
            .expect("cached token should return");
        assert_eq!(&*cached.token, "token-1");
        assert_eq!(&*cached_project, "project-1");

        let (fresh, fresh_project) = cache
            .token_info_with_project_fresh()
            .await
            .expect("fresh token should refetch");
        assert_eq!(&*fresh.token, "token-2");
        assert_eq!(&*fresh_project, "project-2");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    async fn spawn_token_service(max_requests: usize) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let request_count = Arc::new(AtomicUsize::new(0));
        let served_count = Arc::clone(&request_count);
        tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut socket, _) = listener.accept().await.expect("request should accept");
                let mut buffer = [0u8; 1024];
                let _ = socket.read(&mut buffer).await;
                let next = served_count.fetch_add(1, Ordering::SeqCst) + 1;
                let body = format!(
                    r#"{{"success":true,"data":{{"token":"token-{next}","expires_in":3600,"project_id":"project-{next}"}}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("response should write");
            }
        });
        (format!("http://{addr}"), request_count)
    }
}
